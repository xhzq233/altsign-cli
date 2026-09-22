#import "diagnostics.h"
#include <unistd.h>

static FILE *diagnosticFile;
static NSString *diagnosticPath;

static void WriteEvent(NSDictionary *fields) {
    @synchronized (NSProcessInfo.processInfo) {
        if (!diagnosticFile) return;
        NSMutableDictionary *event = [fields mutableCopy];
        event[@"time"] = @([NSDate.date timeIntervalSince1970]);
        NSData *json = [NSJSONSerialization dataWithJSONObject:event options:0 error:nil];
        if (json) {
            fwrite(json.bytes, 1, json.length, diagnosticFile);
            fputc('\n', diagnosticFile);
            fflush(diagnosticFile);
        }
    }
}

NSString *ALTDiagnosticsPath(void) { return diagnosticPath; }

void ALTDiagnosticsStart(NSString *command) {
    NSString *directory = NSProcessInfo.processInfo.environment[@"TMPDIR"] ?: NSTemporaryDirectory();
    NSString *pattern = [directory stringByAppendingPathComponent:@"altsign-XXXXXX.log"];
    char *path = strdup(pattern.fileSystemRepresentation);
    int fd = mkstemps(path, 4); // Creates an owner-only file, independent of session storage.
    if (fd >= 0) {
        diagnosticFile = fdopen(fd, "w");
        if (diagnosticFile) diagnosticPath = [NSFileManager.defaultManager stringWithFileSystemRepresentation:path length:strlen(path)];
        else { close(fd); unlink(path); }
    }
    free(path);
    if (!diagnosticFile) {
        fprintf(stderr, "Warning: unable to create diagnostic log.\n");
        return;
    }
    WriteEvent(@{@"stage": @"start", @"command": command,
                 @"os": NSProcessInfo.processInfo.operatingSystemVersionString,
                 @"client_info": @"akd/1.0", @"gsa_ua": @"AuthKit/1-Xcode/26.0"});
    fprintf(stderr, "Diagnostic log: %s\n", diagnosticPath.fileSystemRepresentation);
}

void ALTDiagnosticsEvent(NSString *stage, NSInteger code) {
    WriteEvent(@{@"stage": stage, @"code": @(code)});
}

void ALTDiagnosticsHTTP(NSString *stage, NSURLResponse *response, NSError *error) {
    NSMutableDictionary *event = [@{@"stage": stage, @"network_error": @(error.code)} mutableCopy];
    if ([response isKindOfClass:NSHTTPURLResponse.class]) {
        NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
        event[@"http"] = @(http.statusCode);
        NSString *retry = [http valueForHTTPHeaderField:@"Retry-After"];
        // Persist only a parsed delay/date, never arbitrary headers or response bodies.
        if (retry.length) {
            NSScanner *scanner = [NSScanner scannerWithString:retry];
            long long seconds;
            if ([scanner scanLongLong:&seconds] && scanner.isAtEnd && seconds >= 0) {
                event[@"retry_after_seconds"] = @(seconds);
            } else {
                NSDateFormatter *format = [NSDateFormatter new];
                format.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
                format.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
                format.dateFormat = @"EEE',' dd MMM yyyy HH':'mm':'ss z";
                NSDate *date = [format dateFromString:retry];
                if (date) event[@"retry_after_unix"] = @(date.timeIntervalSince1970);
                else event[@"retry_after_unparsed"] = @YES;
            }
        } else event[@"retry_after_absent"] = @YES;
    }
    WriteEvent(event);
}

void ALTDiagnosticsFinish(int exitCode) {
    @synchronized (NSProcessInfo.processInfo) {
        if (!diagnosticFile) return;
        ALTDiagnosticsEvent(@"exit", exitCode);
        fclose(diagnosticFile);
        diagnosticFile = NULL;
        fprintf(stderr, "Diagnostics (exit code %d): %s\n", exitCode, diagnosticPath.fileSystemRepresentation);
    }
}
