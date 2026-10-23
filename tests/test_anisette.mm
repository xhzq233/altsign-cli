#import "../remote_anisette.mm"
#include <assert.h>

@interface TestSocket : NSObject
@property BOOL closed;
- (void)resume;
- (void)cancelWithCloseCode:(NSURLSessionWebSocketCloseCode)code reason:(NSData *)reason;
@end
@implementation TestSocket
- (void)resume {}
- (void)cancelWithCloseCode:(NSURLSessionWebSocketCloseCode)code reason:(NSData *)reason { self.closed = YES; }
@end

@interface TestSession : NSObject
@property TestSocket *socket;
- (NSURLSessionWebSocketTask *)webSocketTaskWithURL:(NSURL *)url;
@end
@implementation TestSession
- (NSURLSessionWebSocketTask *)webSocketTaskWithURL:(NSURL *)url {
    assert([url.scheme isEqual:@"wss"] && [url.host isEqual:@"example.invalid"]);
    self.socket = [TestSocket new];
    return (id)self.socket;
}
@end

@interface TestClient : ALTAnisetteV3Client
@property NSMutableArray<NSURLRequest *> *requests;
@property NSMutableArray<NSDictionary *> *replies;
@property NSMutableArray<NSDictionary *> *messages;
@property NSDictionary *info;
@property NSDictionary *headers;
@property BOOL expireOnce;
@property BOOL badLookup;
@property BOOL badStep;
@property NSUInteger provisions;
@end
@implementation TestClient
- (instancetype)init {
    if ((self = [super init])) {
        self.server = [NSURL URLWithString:@"https://example.invalid"];
        self.statePath = [NSHomeDirectory() stringByAppendingPathComponent:@"state/anisette.plist"];
        self.session = (id)[TestSession new];
        self.requests = [NSMutableArray array];
        self.replies = [NSMutableArray array];
        self.info = @{@"client_info": @"<Mac> <macOS;test;test> <com.apple.AuthKit/1 (com.apple.akd/1.0)>", @"user_agent": @"test-agent"};
        self.headers = @{@"X-Apple-I-MD-M": @"test-mid", @"X-Apple-I-MD": @"test-otp", @"X-Apple-I-MD-RINFO": @"84215040"};
    }
    return self;
}
- (NSDictionary *)send:(NSURLRequest *)request plist:(BOOL)plist error:(NSError **)error {
    [self.requests addObject:request];
    if ([request.URL.path hasSuffix:@"/client_info"]) return self.info;
    if ([request.URL.path hasSuffix:@"/get_headers"]) {
        if (self.expireOnce) {
            self.expireOnce = NO;
            return @{@"result": @"GetHeadersError", @"message": @"ADI -45061"};
        }
        return self.headers;
    }
    assert([request.URL.host isEqual:@"gsa.apple.com"] && plist);
    assert([[request valueForHTTPHeaderField:@"User-Agent"] isEqual:self.info[@"user_agent"]]);
    assert([[request valueForHTTPHeaderField:@"X-Mme-Client-Info"] isEqual:self.info[@"client_info"]]);
    assert([request valueForHTTPHeaderField:@"X-Apple-I-MD-LU"].length == 64);
    assert([request valueForHTTPHeaderField:@"Authorization"] == nil);
    if ([request.URL.path hasSuffix:@"/lookup"]) {
        return @{@"urls": @{@"midStartProvisioning": self.badLookup ? @"https://example.invalid/steal" : @"https://gsa.apple.com/start",
                           @"midFinishProvisioning": @"https://gsa.apple.com/finish"}};
    }
    NSDictionary *body = [NSPropertyListSerialization propertyListWithData:request.HTTPBody options:0 format:nil error:nil];
    assert([body[@"Header"] count] == 0);
    if ([request.URL.path isEqual:@"/start"]) {
        assert([body[@"Request"] count] == 0);
        return @{@"Response": @{@"spim": @"test-spim"}};
    }
    assert([body[@"Request"] isEqual:@{@"cpim": @"test-cpim"}]);
    return @{@"Response": @{@"ptm": @"test-ptm", @"tk": @"test-tk"}};
}
- (NSString *)provision:(NSData *)identity clientInfo:(NSDictionary *)info error:(NSError **)error {
    self.provisions++;
    self.messages = [@[@{@"result": self.badStep ? @"Unknown" : @"GiveIdentifier"},
                      @{@"result": @"GiveStartProvisioningData"},
                      @{@"result": @"GiveEndProvisioningData", @"cpim": @"test-cpim"},
                      @{@"result": @"ProvisioningSuccess", @"adi_pb": @"dGVzdC1hZGk="}] mutableCopy];
    return [super provision:identity clientInfo:info error:error];
}
- (NSDictionary *)receive:(NSURLSessionWebSocketTask *)socket error:(NSError **)error {
    assert(self.messages.count);
    NSDictionary *message = self.messages.firstObject;
    [self.messages removeObjectAtIndex:0];
    return message;
}
- (BOOL)sendMessage:(NSDictionary *)value socket:(NSURLSessionWebSocketTask *)socket error:(NSError **)error {
    [self.replies addObject:value];
    return YES;
}
@end

static void liveCheck(void) {
    __block ALTAnisetteData *previous;
    for (int i = 0; i < 2; i++) {
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block BOOL success = NO;
        // Exercise the production entry point, including macOS 27 provider selection.
        [ALTAnisetteData fetchAnisetteDataWithCompletion:^(ALTAnisetteData *data, NSError *error) {
            if (error) fprintf(stderr, "Live anisette failed: %s\n", error.localizedDescription.UTF8String);
            success = data.isValid && data.userAgent.length > 0;
            if (success && previous) {
                assert([previous.deviceUniqueIdentifier isEqual:data.deviceUniqueIdentifier]);
                assert([previous.localUserID isEqual:data.localUserID]);
                assert([previous.machineID isEqual:data.machineID]);
            }
            previous = data;
            dispatch_semaphore_signal(done);
        }];
        assert(dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_SEC)) == 0);
        assert(success);
    }
    dispatch_semaphore_t refreshed = dispatch_semaphore_create(0);
    [previous refreshWithCompletion:^(NSError *error) {
        assert(error == nil && previous.isValid);
        dispatch_semaphore_signal(refreshed);
    }];
    assert(dispatch_semaphore_wait(refreshed, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_SEC)) == 0);
    puts("[altsign-test] Live v3 provisioning and persistent identity reuse passed (no account credentials)");
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc == 2 && strcmp(argv[1], "--live") == 0) { liveCheck(); return 0; }
        TestClient *client = [TestClient new];
        NSError *error = nil;
        ALTAnisetteData *first = [client fetchWithError:&error];
        assert(first.isValid && error == nil && first.routingInfo == 84215040);
        assert([first.userAgent isEqual:@"test-agent"] && first.localUserID.length == 64);
        assert(client.provisions == 1 && client.replies.count == 3);
        assert([(TestSession *)(id)client.session socket].closed);
        assert([client.replies[1] isEqual:@{@"spim": @"test-spim"}]);
        assert(([client.replies[2] isEqual:@{@"ptm": @"test-ptm", @"tk": @"test-tk"}]));
        struct stat info;
        assert(stat(client.statePath.fileSystemRepresentation, &info) == 0 && (info.st_mode & 0777) == 0600);
        assert(stat(client.statePath.stringByDeletingLastPathComponent.fileSystemRepresentation, &info) == 0 && (info.st_mode & 0777) == 0700);

        ALTAnisetteData *second = [client fetchWithError:&error];
        assert(client.provisions == 1 && [first.deviceUniqueIdentifier isEqual:second.deviceUniqueIdentifier]);
        assert([first.localUserID isEqual:second.localUserID]);
        client.sim = @"test-sync";
        second = [client fetchWithError:&error];
        assert(second.isValid && client.provisions == 1);
        NSDictionary *syncRequest = [NSJSONSerialization JSONObjectWithData:client.requests.lastObject.HTTPBody options:0 error:nil];
        assert([syncRequest[@"sim"] isEqual:@"test-sync"]);
        assert([syncRequest[@"device_id"] isEqual:first.deviceUniqueIdentifier]);
        assert([syncRequest[@"md_lu"] isEqual:first.localUserID]);
        client.sim = nil;
        client.expireOnce = YES;
        second = [client fetchWithError:&error];
        assert(second.isValid && client.provisions == 2 && ![first.deviceUniqueIdentifier isEqual:second.deviceUniqueIdentifier]);

        // A provider change must not reuse provisioning from the previous provider.
        client.info = @{@"client_info": @"another-provider", @"user_agent": @"another-agent"};
        assert([client fetchWithError:&error].isValid && client.provisions == 3);
        for (NSString *routing in @[@"-1", @"1x", @"18446744073709551616", @"", @" 1"]) {
            client.headers = @{@"X-Apple-I-MD-M": @"mid", @"X-Apple-I-MD": @"otp", @"X-Apple-I-MD-RINFO": routing};
            error = nil;
            assert([client fetchWithError:&error] == nil && error != nil);
        }
        client.headers = @{@"X-Apple-I-MD-M": @"mid", @"X-Apple-I-MD": @"", @"X-Apple-I-MD-RINFO": @"1"};
        error = nil;
        assert([client fetchWithError:&error] == nil && error != nil);
        client.info = @{@"client_info": @"bad\r\nheader", @"user_agent": @"test"};
        error = nil;
        assert([client fetchWithError:&error] == nil && error != nil);

        TestClient *missingSync = [TestClient new];
        missingSync.statePath = [NSHomeDirectory() stringByAppendingPathComponent:@"missing-sync/state.plist"];
        missingSync.sim = @"test-sync";
        error = nil;
        assert([missingSync fetchWithError:&error] == nil && error != nil && missingSync.provisions == 0);

        for (int scenario = 0; scenario < 2; scenario++) {
            TestClient *bad = [TestClient new];
            bad.statePath = [NSHomeDirectory() stringByAppendingFormat:@"/bad-%d/state.plist", scenario];
            bad.badLookup = scenario == 0; bad.badStep = scenario == 1;
            error = nil;
            assert([bad fetchWithError:&error] == nil && error != nil);
            assert(![NSFileManager.defaultManager fileExistsAtPath:bad.statePath]);
            if (bad.badStep) assert([(TestSession *)(id)bad.session socket].closed);
        }
        NSURLRequest *redirect = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://example.invalid/redirect"]];
        NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:redirect.URL statusCode:302 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
        [client URLSession:client.session task:(id)[NSObject new] willPerformHTTPRedirection:response newRequest:redirect completionHandler:^(NSURLRequest *request) { assert(request == nil); }];
        client.deadline = [NSDate dateWithTimeIntervalSinceNow:-1];
        error = nil;
        assert(![client wait:dispatch_semaphore_create(0) error:&error] && error.code == NSURLErrorTimedOut);
        puts("[altsign-test] V3 handshake, identity reuse/recovery, permissions and invalid response boundaries passed");
    }
}
