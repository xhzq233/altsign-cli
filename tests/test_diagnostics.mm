#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <sys/stat.h>
#import "../srp_auth.mm"
#include <assert.h>

static NSInteger scenario;
static NSUInteger requestCount;

@interface TestAnisette : ALTAnisetteData
@property NSUInteger refreshes;
@property NSUInteger resyncs;
@end
@implementation TestAnisette
- (NSString *)oneTimePassword { return self.refreshes || self.resyncs ? @"fresh-otp" : @"initial-otp"; }
- (void)refreshWithCompletion:(void (^)(NSError *))completion { self.refreshes++; completion(nil); }
- (void)resynchronize:(NSString *)sim completion:(void (^)(NSError *))completion {
    assert([sim isEqual:@"dGVzdC1zeW5j"]);
    self.resyncs++; completion(nil);
}
@end

static TestAnisette *makeAnisette(void) {
    TestAnisette *data = [[TestAnisette alloc] initWithMachineID:@"test-mid" oneTimePassword:@"initial-otp"
        localUserID:@"test-lu" routingInfo:84215040 deviceUniqueIdentifier:@"test-device"
        deviceSerialNumber:@"test-serial" deviceDescription:@"test-provider-info" date:NSDate.date
        locale:@"en_US" timeZone:@"UTC"];
    data.userAgent = @"test-provider-agent";
    return data;
}
@interface TestProtocol : NSURLProtocol
@end
@implementation TestProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)stopLoading {}
- (void)startLoading {
    requestCount++;
    assert([[self.request valueForHTTPHeaderField:@"User-Agent"] isEqual:@"test-provider-agent"]);
    assert([[self.request valueForHTTPHeaderField:@"X-MMe-Client-Info"] isEqual:@"test-provider-info"]);
    assert([[self.request valueForHTTPHeaderField:@"X-Apple-App-Info"] isEqual:@"com.apple.gs.xcode.auth"]);
    if (scenario >= 4) {
        assert([[self.request valueForHTTPHeaderField:@"X-Apple-I-MD"] isEqual:scenario == 4 && requestCount == 1 ? @"initial-otp" : @"fresh-otp"]);
        NSData *body = self.request.HTTPBody;
        if (!body && self.request.HTTPBodyStream) {
            NSInputStream *stream = self.request.HTTPBodyStream;
            [stream open];
            NSMutableData *buffer = [NSMutableData data];
            uint8_t bytes[4096];
            NSInteger count;
            while ((count = [stream read:bytes maxLength:sizeof(bytes)]) > 0) [buffer appendBytes:bytes length:(NSUInteger)count];
            [stream close];
            body = buffer;
        }
        if (body.length) {
            NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:body options:0 format:nil error:nil];
            assert([plist[@"Request"][@"cpd"][@"X-Apple-I-MD"] isEqual:[self.request valueForHTTPHeaderField:@"X-Apple-I-MD"]]);
        }
    }
    if (scenario == 3) {
        [self.client URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorTimedOut userInfo:nil]];
        return;
    }
    NSInteger status = scenario == 0 ? 429 : (scenario == 1 ? 401 : 200);
    BOOL resync = scenario == 5 || (scenario == 4 && requestCount == 1);
    NSDictionary *statusFields = resync ? @{@"ec": @0, @"hsc": @434, @"X-Apple-I-MD-DATA": [@"test-sync" dataUsingEncoding:NSUTF8StringEncoding]}
        : @{@"ec": scenario == 1 ? @(-21669) : @0};
    NSData *data = scenario == 0 ? [@"<html>Too Many Requests</html>" dataUsingEncoding:NSUTF8StringEncoding]
        : [NSPropertyListSerialization dataWithPropertyList:@{@"Response": @{@"Status": statusFields}} format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
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
            SendGSARequest(@{@"o": @"init"}, makeAnisette(), nil, ^(NSDictionary *response, NSError *error) {
                if (scenario == 0) assert(error.code == 429 && response == nil);
                if (scenario == 1) assert(error.code == -21669 && response == nil);
                if (scenario == 2) assert(error == nil && response != nil);
                if (scenario == 3) assert(error.code == NSURLErrorTimedOut && response == nil);
                dispatch_semaphore_signal(done);
            });
            assert(dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);
        }
        NSUInteger originalRequests = requestCount;
        NSUInteger extraRequests = 0;
        for (scenario = 4; scenario < 7; scenario++) {
            requestCount = 0;
            TestAnisette *anisette = makeAnisette();
            if (scenario == 5) anisette.resyncs = 1;
            dispatch_semaphore_t done = dispatch_semaphore_create(0);
            NSDictionary *request = @{@"o": scenario == 6 ? @"apptokens" : @"init", @"cpd": @{@"X-Apple-I-MD": @"stale-otp"}};
            SendGSARequest(request, anisette, nil, ^(NSDictionary *response, NSError *error) {
                if (scenario == 5) assert(error.code == 434 && response == nil && anisette.resyncs == 2);
                else assert(error == nil && response != nil);
                if (scenario == 4) assert(anisette.resyncs == 1 && requestCount == 2);
                if (scenario == 6) assert(anisette.refreshes == 1 && requestCount == 1);
                dispatch_semaphore_signal(done);
            });
            assert(dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);
            extraRequests += requestCount;
        }
        TestAnisette *anisette = makeAnisette();
        __block BOOL called = NO;
        NSUInteger before = requestCount;
        [ALTSRPAuthenticator _requestTwoFactorCodeForDSID:@"test" idmsToken:@"fake-token" anisetteData:anisette codeAlreadySent:YES completionHandler:^(NSError *error) {
            assert(error == nil); called = YES;
        }];
        assert(called && requestCount == before);
        scenario = 7;
        dispatch_semaphore_t verified = dispatch_semaphore_create(0);
        [ALTSRPAuthenticator submitTwoFactorCode:@"000000" dsid:@"test" idmsToken:@"fake-token" anisetteData:anisette completionHandler:^(BOOL success, NSError *error) {
            assert(success && error == nil && anisette.refreshes == 1);
            dispatch_semaphore_signal(verified);
        }];
        assert(dispatch_semaphore_wait(verified, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);
        extraRequests++;
        before = requestCount;
        called = NO;
        [ALTSRPAuthenticator authenticateWithAppleID:@"test@example.invalid" password:@"unused-fixture" anisetteData:[ALTAnisetteData new] completionHandler:^(ALTAccount *account, ALTAppleAPISession *session, NSError *error) {
            assert(account == nil && session == nil && error != nil); called = YES;
        }];
        assert(called && requestCount == before);
        ALTAppleAPISession *saved = [[ALTAppleAPISession alloc] initWithDSID:@"test" authToken:@"fake-token" anisetteData:anisette];
        saved.expirationDate = [NSDate dateWithTimeIntervalSinceNow:3600];
        assert([saved saveForAppleID:@"test@example.invalid"]);
        assert([[ALTAppleAPISession loadSession:NULL].anisetteData.userAgent isEqual:anisette.userAgent]);
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
        assert(originalRequests == 4 && httpCount == 3 + extraRequests && concurrentCount == 50 && dates == 1 && timeouts == 1);
        puts("[altsign-test] HTTP errors, diagnostics, provider headers, OTP refresh, bounded resync and 2FA passed");
    }
}
