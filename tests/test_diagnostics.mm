#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <sys/stat.h>
#import "../srp_auth.mm"
#include <assert.h>

static NSInteger scenario;
@interface TestProtocol : NSURLProtocol
@end
@implementation TestProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)stopLoading {}
- (void)startLoading {
    if (scenario == 3) {
        [self.client URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorTimedOut userInfo:nil]];
        return;
    }
    NSInteger status = scenario == 0 ? 429 : (scenario == 1 ? 401 : 200);
    NSData *data = scenario == 0 ? [@"<html>Too Many Requests</html>" dataUsingEncoding:NSUTF8StringEncoding]
        : [NSPropertyListSerialization dataWithPropertyList:@{@"Response": @{@"Status": @{@"ec": scenario == 1 ? @(-21669) : @0}}} format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:status HTTPVersion:@"HTTP/1.1" headerFields:@{@"Retry-After": @"120", @"Set-Cookie": @"private-test-cookie"}];
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:data];
    [self.client URLProtocolDidFinishLoading:self];
}
@end

@interface NSURLSessionConfiguration (DiagnosticTest)
+ (instancetype)testConfiguration;
@end
@implementation NSURLSessionConfiguration (DiagnosticTest)
+ (instancetype)testConfiguration {
    NSURLSessionConfiguration *configuration = [self defaultSessionConfiguration];
    configuration.protocolClasses = @[TestProtocol.class];
    return configuration;
}
@end

int main(void) {
    @autoreleasepool {
        ALTDiagnosticsStart(@"list");
        NSString *path = ALTDiagnosticsPath();
        assert(path != nil);
        struct stat info;
        assert(stat(path.fileSystemRepresentation, &info) == 0);
        assert((info.st_mode & 0777) == 0600);
        Method original = class_getClassMethod(NSURLSessionConfiguration.class, @selector(ephemeralSessionConfiguration));
        Method fake = class_getClassMethod(NSURLSessionConfiguration.class, @selector(testConfiguration));
        method_exchangeImplementations(original, fake);
        for (scenario = 0; scenario < 4; scenario++) {
            dispatch_semaphore_t done = dispatch_semaphore_create(0);
            SendGSARequest(@{@"o": @"init"}, nil, nil, ^(NSDictionary *response, NSError *error) {
                if (scenario == 0) assert(error.code == 429 && response == nil);
                if (scenario == 1) assert(error.code == -21669 && response == nil);
                if (scenario == 2) assert(error == nil && response != nil);
                if (scenario == 3) assert(error.code == NSURLErrorTimedOut && response == nil);
                dispatch_semaphore_signal(done);
            });
            assert(dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);
        }
        method_exchangeImplementations(original, fake);
        NSHTTPURLResponse *dated = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"https://example.invalid"] statusCode:429 HTTPVersion:@"HTTP/1.1" headerFields:@{@"Retry-After": @"Wed, 21 Oct 2015 07:28:00 GMT"}];
        ALTDiagnosticsHTTP(@"test.date", dated, nil);
        dispatch_apply(50, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(size_t i) {
            ALTDiagnosticsEvent(@"test.concurrent", i);
        });
        ALTDiagnosticsFinish(1);
        NSArray *lines = [[NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil] componentsSeparatedByString:@"\n"];
        NSUInteger httpCount = 0, concurrentCount = 0, dates = 0, timeouts = 0;
        NSSet *allowed = [NSSet setWithArray:@[@"time", @"stage", @"code", @"command", @"os", @"client_info", @"gsa_ua", @"network_error", @"http", @"retry_after_seconds", @"retry_after_unix", @"retry_after_absent", @"retry_after_unparsed"]];
        for (NSString *line in lines) {
            if (!line.length) continue;
            NSDictionary *event = [NSJSONSerialization JSONObjectWithData:[line dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
            assert(event != nil);
            assert([[NSSet setWithArray:event.allKeys] isSubsetOfSet:allowed]);
            if (event[@"retry_after_seconds"]) { assert([event[@"retry_after_seconds"] integerValue] == 120); httpCount++; }
            if (event[@"retry_after_unix"]) { assert([event[@"retry_after_unix"] longLongValue] == 1445412480); dates++; }
            if ([event[@"network_error"] integerValue] == NSURLErrorTimedOut) timeouts++;
            if ([event[@"stage"] isEqual:@"test.concurrent"]) concurrentCount++;
        }
        assert(httpCount == 3 && concurrentCount == 50 && dates == 1 && timeouts == 1);
        puts("[altsign-test] HTTP errors, Retry-After, concurrent diagnostics and permissions passed");
    }
}
