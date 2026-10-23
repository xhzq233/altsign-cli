#import "remote_anisette.h"
#import "diagnostics.h"
#import <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

NS_ASSUME_NONNULL_BEGIN

static NSError *AnisetteError(NSString *message, NSInteger code = -1) {
    return [NSError errorWithDomain:@"com.altsign.anisette" code:code
                          userInfo:@{NSLocalizedDescriptionKey: message}];
}

static BOOL HeaderString(id value) {
    return [value isKindOfClass:NSString.class] && [value length] > 0 &&
        [value rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location == NSNotFound;
}

static BOOL AppleProvisioningURL(NSURL *url) {
    return [url.scheme isEqualToString:@"https"] && [url.host isEqualToString:@"gsa.apple.com"] &&
        (!url.port || url.port.integerValue == 443) && !url.user && !url.password;
}

static BOOL ParseRoutingInfo(id value, unsigned long long *result) {
    if (!HeaderString(value)) return NO;
    const char *text = [value UTF8String];
    if (strspn(text, "0123456789") != strlen(text)) return NO;
    errno = 0;
    *result = strtoull(text, NULL, 10);
    return errno != ERANGE;
}

// Provisioning material must stay on its original endpoint, including on redirects.
@interface ALTAnisetteV3Client : NSObject <NSURLSessionTaskDelegate>
@property (nonatomic, strong) NSURL *server;
@property (nonatomic, copy) NSString *statePath;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, strong) NSDate *deadline;
@property (nonatomic, copy, nullable) NSString *sim;
- (nullable ALTAnisetteData *)fetchWithError:(NSError **)error;
@end

@implementation ALTAnisetteV3Client

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request
    completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler {
    completionHandler(nil);
}

- (BOOL)wait:(dispatch_semaphore_t)done error:(NSError **)error {
    NSTimeInterval seconds = MIN(30, self.deadline.timeIntervalSinceNow);
    if (seconds <= 0 || dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC)))) {
        *error = AnisetteError(@"Anisette v3 request timed out. Check the network or ALTSIGN_ANISETTE_SERVER.", NSURLErrorTimedOut);
        return NO;
    }
    return YES;
}

- (nullable NSDictionary *)send:(NSURLRequest *)request plist:(BOOL)plist error:(NSError **)error {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block NSData *body;
    __block NSURLResponse *response;
    __block NSError *failure;
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *reply, NSError *err) {
        body = data; response = reply; failure = err;
        dispatch_semaphore_signal(done);
    }];
    [task resume];
    if (![self wait:done error:error]) { [task cancel]; return nil; }
    ALTDiagnosticsHTTP(plist ? @"anisette.provision.apple" : @"anisette.remote.http", response, failure);
    if (failure) {
        *error = AnisetteError(@"Anisette v3 network request failed. Check the network or ALTSIGN_ANISETTE_SERVER.", failure.code);
        return nil;
    }
    NSInteger status = [(NSHTTPURLResponse *)response statusCode];
    if (status != 200) {
        *error = AnisetteError([NSString stringWithFormat:@"Anisette %@ request returned HTTP %ld.", plist ? @"Apple provisioning" : @"server", (long)status], status);
        return nil;
    }
    if (body.length == 0) { *error = AnisetteError(@"Anisette v3 returned an empty response."); return nil; }
    id value = plist ? [NSPropertyListSerialization propertyListWithData:body options:NSPropertyListImmutable format:nil error:nil]
        : [NSJSONSerialization JSONObjectWithData:body options:0 error:nil];
    if (![value isKindOfClass:NSDictionary.class]) {
        *error = AnisetteError(@"Anisette v3 returned an invalid response.");
        return nil;
    }
    return value;
}

- (NSMutableURLRequest *)appleRequest:(NSURL *)url identity:(NSData *)identity clientInfo:(NSDictionary *)info {
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(identity.bytes, (CC_LONG)identity.length, digest);
    NSMutableString *localUserID = [NSMutableString string];
    for (unsigned char byte : digest) [localUserID appendFormat:@"%02x", byte];
    uuid_t bytes;
    [identity getBytes:bytes length:sizeof(bytes)];
    NSDictionary *headers = @{
        @"User-Agent": info[@"user_agent"], @"X-Mme-Client-Info": info[@"client_info"],
        @"Content-Type": @"text/x-xml-plist", @"Accept": @"text/x-xml-plist",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth", @"X-Xcode-Version": @"26.0 (17A324)",
        @"X-Apple-I-MD-LU": localUserID,
        @"X-Mme-Device-Id": [[[NSUUID alloc] initWithUUIDBytes:bytes] UUIDString].lowercaseString,
        @"X-Apple-Locale": NSLocale.currentLocale.localeIdentifier,
        @"X-Apple-I-TimeZone": NSTimeZone.localTimeZone.abbreviation ?: @"UTC",
        @"X-Apple-I-Client-Time": [[NSISO8601DateFormatter new] stringFromDate:NSDate.date]
    };
    request.allHTTPHeaderFields = headers;
    return request;
}

- (nullable NSDictionary *)receive:(NSURLSessionWebSocketTask *)socket error:(NSError **)error {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block NSURLSessionWebSocketMessage *message;
    __block NSError *failure;
    [socket receiveMessageWithCompletionHandler:^(NSURLSessionWebSocketMessage *reply, NSError *err) {
        message = reply; failure = err; dispatch_semaphore_signal(done);
    }];
    if (![self wait:done error:error]) return nil;
    if (failure || message.type != NSURLSessionWebSocketMessageTypeString || !message.string) {
        *error = AnisetteError(@"Anisette v3 provisioning connection failed.", failure ? failure.code : -1);
        return nil;
    }
    id value = [NSJSONSerialization JSONObjectWithData:[message.string dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (![value isKindOfClass:NSDictionary.class]) {
        *error = AnisetteError(@"Anisette v3 returned an invalid provisioning message.");
        return nil;
    }
    return value;
}

- (BOOL)sendMessage:(NSDictionary *)value socket:(NSURLSessionWebSocketTask *)socket error:(NSError **)error {
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block NSError *failure;
    [socket sendMessage:[[NSURLSessionWebSocketMessage alloc] initWithString:text] completionHandler:^(NSError *err) {
        failure = err; dispatch_semaphore_signal(done);
    }];
    if (![self wait:done error:error]) return NO;
    if (failure) { *error = AnisetteError(@"Could not send anisette provisioning data.", failure.code); return NO; }
    return YES;
}

- (nullable NSString *)provision:(NSData *)identity clientInfo:(NSDictionary *)info error:(NSError **)error {
    NSURL *lookupURL = [NSURL URLWithString:@"https://gsa.apple.com/grandslam/GsService2/lookup"];
    NSDictionary *lookup = [self send:[self appleRequest:lookupURL identity:identity clientInfo:info] plist:YES error:error];
    if (!lookup) return nil;
    NSDictionary *urls = lookup[@"urls"];
    if (![urls isKindOfClass:NSDictionary.class] || !HeaderString(urls[@"midStartProvisioning"]) || !HeaderString(urls[@"midFinishProvisioning"])) {
        *error = AnisetteError(@"Apple's anisette provisioning lookup is missing URLs."); return nil;
    }
    NSURL *start = [NSURL URLWithString:urls[@"midStartProvisioning"]];
    NSURL *finish = [NSURL URLWithString:urls[@"midFinishProvisioning"]];
    if (!AppleProvisioningURL(start) || !AppleProvisioningURL(finish)) {
        *error = AnisetteError(@"Apple's anisette provisioning lookup returned an unexpected URL."); return nil;
    }

    NSURLComponents *components = [NSURLComponents componentsWithURL:[self.server URLByAppendingPathComponent:@"v3/provisioning_session"] resolvingAgainstBaseURL:NO];
    components.scheme = @"wss";
    NSURLSessionWebSocketTask *socket = [self.session webSocketTaskWithURL:components.URL];
    [socket resume];
    // The v3 handshake has four ordered prompts; reject repeats and unknown messages.
    NSArray *steps = @[@"GiveIdentifier", @"GiveStartProvisioningData", @"GiveEndProvisioningData", @"ProvisioningSuccess"];
    @try {
        for (NSString *step in steps) {
            NSDictionary *message = [self receive:socket error:error];
            if (!message) return nil;
            if (![message[@"result"] isEqual:step]) {
                *error = AnisetteError(@"Anisette v3 returned an unexpected provisioning step."); return nil;
            }
            NSDictionary *reply;
            if ([step isEqualToString:@"GiveIdentifier"]) {
                reply = @{@"identifier": [identity base64EncodedStringWithOptions:0]};
            } else if ([step isEqualToString:@"ProvisioningSuccess"]) {
                NSString *adiPB = message[@"adi_pb"];
                if (!HeaderString(adiPB) || ![[NSData alloc] initWithBase64EncodedString:adiPB options:0].length) {
                    *error = AnisetteError(@"Anisette v3 provisioning did not return a valid adi_pb."); return nil;
                }
                ALTDiagnosticsEvent(@"anisette.remote.provisioned", 0);
                return adiPB;
            } else {
                BOOL isStart = [step isEqualToString:@"GiveStartProvisioningData"];
                if (!isStart && !HeaderString(message[@"cpim"])) {
                    *error = AnisetteError(@"Anisette v3 provisioning is missing cpim."); return nil;
                }
                NSMutableURLRequest *request = [self appleRequest:isStart ? start : finish identity:identity clientInfo:info];
                request.HTTPMethod = @"POST";
                request.HTTPBody = [NSPropertyListSerialization dataWithPropertyList:@{
                    @"Header": @{}, @"Request": isStart ? @{} : @{@"cpim": message[@"cpim"]}
                } format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
                NSDictionary *response = [self send:request plist:YES error:error];
                if (!response) return nil;
                NSDictionary *payload = response[@"Response"];
                if (![payload isKindOfClass:NSDictionary.class] ||
                    (isStart ? !HeaderString(payload[@"spim"]) : (!HeaderString(payload[@"ptm"]) || !HeaderString(payload[@"tk"])))) {
                    *error = AnisetteError(@"Apple returned incomplete anisette provisioning data."); return nil;
                }
                reply = isStart ? @{@"spim": payload[@"spim"]} : @{@"ptm": payload[@"ptm"], @"tk": payload[@"tk"]};
            }
            if (![self sendMessage:reply socket:socket error:error]) return nil;
        }
    } @finally {
        [socket cancelWithCloseCode:NSURLSessionWebSocketCloseCodeNormalClosure reason:nil];
    }
    return nil;
}

- (BOOL)saveIdentity:(NSDictionary *)identity error:(NSError **)error {
    NSString *directory = self.statePath.stringByDeletingLastPathComponent;
    NSFileManager *fm = NSFileManager.defaultManager;
    if (![fm createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0700} error:error] ||
        ![fm setAttributes:@{NSFilePosixPermissions: @0700} ofItemAtPath:directory error:error]) return NO;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:identity format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    if (!data) return NO;
    char *path = strdup([[directory stringByAppendingPathComponent:@".anisette-XXXXXX"] fileSystemRepresentation]);
    int fd = mkstemp(path); // 0600 from creation, including during the atomic replacement.
    BOOL ok = fd >= 0;
    NSUInteger offset = 0;
    while (ok && offset < data.length) {
        ssize_t count = write(fd, (const char *)data.bytes + offset, data.length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) ok = NO;
        else offset += count;
    }
    if (fd >= 0 && close(fd) != 0) ok = NO;
    if (ok) ok = rename(path, self.statePath.fileSystemRepresentation) == 0;
    if (!ok) {
        unlink(path);
        *error = AnisetteError(@"Could not save the anisette identity in Application Support/altsign.");
    }
    free(path);
    return ok;
}

- (nullable ALTAnisetteData *)fetchWithError:(NSError **)error {
    self.deadline = [NSDate dateWithTimeIntervalSinceNow:90];
    NSDictionary *info = [self send:[NSURLRequest requestWithURL:[self.server URLByAppendingPathComponent:@"v3/client_info"]] plist:NO error:error];
    if (!info) return nil;
    if (!HeaderString(info[@"client_info"]) || !HeaderString(info[@"user_agent"])) {
        *error = AnisetteError(@"Anisette v3 server must supply client_info and user_agent."); return nil;
    }
    NSDictionary *cached = [NSDictionary dictionaryWithContentsOfFile:self.statePath];
    NSData *identity = cached[@"identity"];
    NSString *adiPB = cached[@"adi_pb"];
    if (![identity isKindOfClass:NSData.class] || identity.length != 16 || !HeaderString(adiPB) ||
        ![[NSData alloc] initWithBase64EncodedString:adiPB options:0].length ||
        ![cached[@"server"] isEqual:self.server.absoluteString] || ![cached[@"client_info"] isEqual:info[@"client_info"]]) {
        identity = nil; adiPB = nil;
    }
    if (self.sim && !identity) {
        *error = AnisetteError(@"The anisette identity to resynchronize is missing or belongs to a different provider."); return nil;
    }

    for (NSUInteger attempt = 0; attempt < 2; attempt++) {
        if (!identity) {
            uuid_t bytes;
            [NSUUID.UUID getUUIDBytes:bytes];
            identity = [NSData dataWithBytes:bytes length:sizeof(bytes)];
            NSLog(@"[Anisette] Provisioning a v3 identity...");
            adiPB = [self provision:identity clientInfo:info error:error];
            if (!adiPB || ![self saveIdentity:@{@"server": self.server.absoluteString, @"client_info": info[@"client_info"],
                                              @"identity": identity, @"adi_pb": adiPB} error:error]) return nil;
        }
        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[self.server URLByAppendingPathComponent:@"v3/get_headers"]];
        request.HTTPMethod = @"POST";
        [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        NSMutableDictionary *body = [@{@"identifier": [identity base64EncodedStringWithOptions:0], @"adi_pb": adiPB} mutableCopy];
        if (self.sim) {
            NSURLRequest *apple = [self appleRequest:[NSURL URLWithString:@"https://gsa.apple.com"] identity:identity clientInfo:info];
            body[@"sim"] = self.sim;
            body[@"device_id"] = [apple valueForHTTPHeaderField:@"X-Mme-Device-Id"];
            body[@"md_lu"] = [apple valueForHTTPHeaderField:@"X-Apple-I-MD-LU"];
        }
        request.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
        NSDictionary *headers = [self send:request plist:NO error:error];
        if (!headers) return nil;
        if ([headers[@"result"] isEqual:@"GetHeadersError"]) {
            if (!self.sim && attempt == 0 && [headers[@"message"] isKindOfClass:NSString.class] && [headers[@"message"] containsString:@"-45061"]) {
                identity = nil; adiPB = nil;
                continue;
            }
            *error = AnisetteError(@"Anisette v3 server rejected the provisioned identity."); return nil;
        }
        NSString *routing = headers[@"X-Apple-I-MD-RINFO"];
        unsigned long long routingInfo;
        if (!HeaderString(headers[@"X-Apple-I-MD-M"]) || !HeaderString(headers[@"X-Apple-I-MD"]) ||
            !ParseRoutingInfo(routing, &routingInfo)) {
            *error = AnisetteError(@"Anisette v3 response is missing valid MID, OTP or routing info."); return nil;
        }
        NSMutableURLRequest *apple = [self appleRequest:[NSURL URLWithString:@"https://gsa.apple.com"] identity:identity clientInfo:info];
        ALTAnisetteData *data = [[ALTAnisetteData alloc] initWithMachineID:headers[@"X-Apple-I-MD-M"]
            oneTimePassword:headers[@"X-Apple-I-MD"] localUserID:[apple valueForHTTPHeaderField:@"X-Apple-I-MD-LU"]
            routingInfo:(NSUInteger)routingInfo deviceUniqueIdentifier:[apple valueForHTTPHeaderField:@"X-Mme-Device-Id"]
            deviceSerialNumber:@"C02LKHBBFD57" deviceDescription:info[@"client_info"] date:NSDate.date
            locale:NSLocale.currentLocale.localeIdentifier timeZone:NSTimeZone.localTimeZone.abbreviation ?: @"UTC"];
        data.userAgent = info[@"user_agent"];
        ALTDiagnosticsEvent(@"anisette.remote.ready", 0);
        NSLog(@"[Anisette] V3 OK machineID=%lu otp=%lu", (unsigned long)data.machineID.length, (unsigned long)data.oneTimePassword.length);
        return data;
    }
    return nil;
}
@end

static void FetchRemoteAnisetteData(NSString * _Nullable sim, void (^completion)(ALTAnisetteData * _Nullable, NSError * _Nullable)) {
    // Serialize identity reads, provisioning and replacement within one CLI process.
    static dispatch_queue_t queue;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ queue = dispatch_queue_create("com.altsign.anisette.v3", DISPATCH_QUEUE_SERIAL); });
    dispatch_async(queue, ^{
        NSString *address = NSProcessInfo.processInfo.environment[@"ALTSIGN_ANISETTE_SERVER"] ?: @"https://mac-ani.jkcoxson.com";
        NSURL *url = [NSURL URLWithString:address];
        if (![url.scheme isEqual:@"https"] || !url.host.length || url.user || url.password || url.query || url.fragment) {
            completion(nil, AnisetteError(@"ALTSIGN_ANISETTE_SERVER must be an HTTPS URL without credentials, query or fragment."));
            return;
        }
        ALTAnisetteV3Client *client = [ALTAnisetteV3Client new];
        client.server = url;
        client.sim = sim;
        NSString *support = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES).firstObject;
        client.statePath = [support stringByAppendingPathComponent:@"altsign/anisette-v3.plist"];
        NSURLSessionConfiguration *config = NSURLSessionConfiguration.ephemeralSessionConfiguration;
        config.timeoutIntervalForRequest = 30;
        config.timeoutIntervalForResource = 90;
        client.session = [NSURLSession sessionWithConfiguration:config delegate:client delegateQueue:nil];
        NSError *error = nil;
        ALTAnisetteData *data;
        @try {
            data = [client fetchWithError:&error];
        } @finally {
            [client.session invalidateAndCancel];
        }
        ALTDiagnosticsEvent(@"anisette.remote.finished", error.code);
        completion(data, error);
    });
}

void ALTFetchRemoteAnisetteData(void (^completion)(ALTAnisetteData * _Nullable, NSError * _Nullable)) {
    FetchRemoteAnisetteData(nil, completion);
}

void ALTResynchronizeRemoteAnisetteData(NSString *sim, void (^completion)(ALTAnisetteData * _Nullable, NSError * _Nullable)) {
    FetchRemoteAnisetteData(sim, completion);
}

NS_ASSUME_NONNULL_END
