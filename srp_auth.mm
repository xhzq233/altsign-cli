#import "srp_auth.h"
#import <CommonCrypto/CommonCrypto.h>

extern "C" {
#include <corecrypto/cc.h>
#include <corecrypto/ccsrp.h>
#include <corecrypto/ccsrp_gp.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccpad.h>
#include <corecrypto/ccrng.h>
}

static NSString *const kGSAEndpoint = @"https://gsa.apple.com/grandslam/GsService2";
static NSString *const kGSA2FARequest = @"https://gsa.apple.com/auth/verify/trusteddevice";
static NSString *const kGSA2FAValidate = @"https://gsa.apple.com/grandslam/GsService2/validate";

static NSString *const kGSAUserAgent = @"akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
static NSString *const kGSA2FAUserAgent = @"Xcode";
static NSString *const kGSAXcodeVersion = @"26.0 (17A324)";

static NSURLSession *ALTSharedSession(void) {
    static NSURLSession *session;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]];
    });
    return session;
}

BOOL ALTVerboseLogging = NO;

static NSInteger const kAltSignErrorCodeGeneric = -1;
static NSInteger const kAltSignErrorCode2FARequired = -21600;
static NSInteger const kAltSignErrorCodeInvalid2FA = -21669;

static const char ALTHexCharacters[] = "0123456789abcdef";

static NSDateFormatter *GSAClientTimeFormatter(void) {
    static NSDateFormatter *formatter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSDateFormatter alloc] init];
        formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
        formatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];
    });
    return formatter;
}

static void ALTDigestUpdateString(const struct ccdigest_info *diInfo, struct ccdigest_ctx *diCtx, NSString *string) {
    ccdigest_update(diInfo, diCtx, string.length, string.UTF8String);
}

static void ALTDigestUpdateData(const struct ccdigest_info *diInfo, struct ccdigest_ctx *diCtx, NSData *data) {
    uint32_t dataLen = (uint32_t)data.length;
    ccdigest_update(diInfo, diCtx, sizeof(dataLen), &dataLen);
    ccdigest_update(diInfo, diCtx, dataLen, data.bytes);
}

static NSData * _Nullable ALTPBKDF2SRP(const struct ccdigest_info *diInfo, BOOL isS2K, NSString *password, NSData *salt, int iterations) {
    const struct ccdigest_info *passwordDiInfo = ccsha256_di();
    const char *passwordUTF8 = password.UTF8String;

    char *digestRaw = (char *)malloc(passwordDiInfo->output_size);
    ccdigest(passwordDiInfo, strlen(passwordUTF8), passwordUTF8, digestRaw);

    size_t finalDigestLen = passwordDiInfo->output_size * (isS2K ? 1 : 2);
    char *digest = (char *)malloc(finalDigestLen);

    if (isS2K) {
        memcpy(digest, digestRaw, finalDigestLen);
    } else {
        for (int i = 0; i < passwordDiInfo->output_size; i++) {
            char byte = digestRaw[i];
            digest[i * 2 + 0] = ALTHexCharacters[(byte >> 4) & 0x0F];
            digest[i * 2 + 1] = ALTHexCharacters[(byte >> 0) & 0x0F];
        }
    }

    NSMutableData *data = [NSMutableData dataWithLength:diInfo->output_size];
    int result = ccpbkdf2_hmac(diInfo,
                               finalDigestLen,
                               digest,
                               salt.length,
                               salt.bytes,
                               iterations,
                               diInfo->output_size,
                               data.mutableBytes);

    free(digestRaw);
    free(digest);

    if (result != 0) {
        return nil;
    }

    return data;
}

static NSData * _Nullable ALTCreateSessionKey(ccsrp_ctx_t srpCtx, const char *keyName) {
    size_t keyLen = 0;
    const void *sessionKey = ccsrp_get_session_key(srpCtx, &keyLen);
    if (sessionKey == NULL || keyLen == 0) {
        return nil;
    }

    const struct ccdigest_info *diInfo = ccsha256_di();
    size_t hmacLen = diInfo->output_size;
    unsigned char *hmacBytes = (unsigned char *)malloc(hmacLen);
    cchmac(diInfo, keyLen, sessionKey, strlen(keyName), keyName, hmacBytes);

    NSData *derivedKey = [NSData dataWithBytes:hmacBytes length:hmacLen];
    free(hmacBytes);
    return derivedKey;
}

static NSData * _Nullable ALTDecryptDataCBC(ccsrp_ctx_t srpCtx, NSData *spd) {
    NSData *extraDataKey = ALTCreateSessionKey(srpCtx, "extra data key:");
    NSData *extraDataIV = ALTCreateSessionKey(srpCtx, "extra data iv:");
    if (extraDataKey == nil || extraDataIV == nil) {
        return nil;
    }

    NSMutableData *decryptedData = [NSMutableData dataWithLength:spd.length];
    const struct ccmode_cbc *decryptMode = ccaes_cbc_decrypt_mode();

    cccbc_iv *iv = (cccbc_iv *)malloc(decryptMode->block_size);
    if (extraDataIV.bytes) {
        memcpy(iv, extraDataIV.bytes, decryptMode->block_size);
    } else {
        memset(iv, 0, decryptMode->block_size);
    }

    cccbc_ctx *ctxBuffer = (cccbc_ctx *)malloc(decryptMode->size);
    decryptMode->init(decryptMode, ctxBuffer, extraDataKey.length, extraDataKey.bytes);

    size_t length = ccpad_pkcs7_decrypt(decryptMode,
                                        ctxBuffer,
                                        iv,
                                        spd.length,
                                        spd.bytes,
                                        decryptedData.mutableBytes);

    free(iv);
    free(ctxBuffer);

    if (length > spd.length) {
        return nil;
    }

    decryptedData.length = length;
    return decryptedData;
}

static NSData * _Nullable ALTDecryptDataGCM(NSData *sk, NSData *encryptedData) {
    if (encryptedData.length < 35) {
        return nil;
    }

    if (cc_cmp_safe(3, encryptedData.bytes, "XYZ")) {
        return nil;
    }

    const struct ccmode_gcm *decryptMode = ccaes_gcm_decrypt_mode();
    ccgcm_ctx *gcmCtx = (ccgcm_ctx *)malloc(decryptMode->size);
    decryptMode->init(decryptMode, gcmCtx, sk.length, sk.bytes);

    decryptMode->set_iv(gcmCtx, 16, (const unsigned char *)encryptedData.bytes + 3);
    decryptMode->gmac(gcmCtx, 3, encryptedData.bytes);

    size_t decryptedLen = encryptedData.length - 35;
    NSMutableData *decryptedData = [NSMutableData dataWithLength:decryptedLen];
    decryptMode->gcm(gcmCtx,
                     decryptedLen,
                     (const unsigned char *)encryptedData.bytes + 19,
                     decryptedData.mutableBytes);

    char tag[16];
    decryptMode->finalize(gcmCtx, 16, tag);
    free(gcmCtx);

    if (cc_cmp_safe(16, (const unsigned char *)encryptedData.bytes + decryptedLen + 19, tag)) {
        return nil;
    }

    return decryptedData;
}

static NSData *ALTCreateAppTokensChecksum(NSData *sk, NSString *adsid, NSArray<NSString *> *apps) {
    const struct ccdigest_info *diInfo = ccsha256_di();
    size_t hmacSize = cchmac_di_size(diInfo);
    struct cchmac_ctx *hmacCtx = (struct cchmac_ctx *)malloc(hmacSize);

    cchmac_init(diInfo, hmacCtx, sk.length, sk.bytes);

    const char *key = "apptokens";
    cchmac_update(diInfo, hmacCtx, strlen(key), key);

    const char *adsidUTF8 = adsid.UTF8String;
    cchmac_update(diInfo, hmacCtx, strlen(adsidUTF8), adsidUTF8);

    for (NSString *app in apps) {
        cchmac_update(diInfo, hmacCtx, app.length, app.UTF8String);
    }

    NSMutableData *checksum = [NSMutableData dataWithLength:diInfo->output_size];
    cchmac_final(diInfo, hmacCtx, (unsigned char *)checksum.mutableBytes);
    free(hmacCtx);

    return checksum;
}

static NSData * _Nullable PlistSerialize(NSDictionary *dict) {
    return [NSPropertyListSerialization dataWithPropertyList:dict
                                                      format:NSPropertyListXMLFormat_v1_0
                                                     options:0
                                                       error:nil];
}

static NSDictionary * _Nullable PlistDeserialize(NSData *data, NSError **error) {
    if (!data) {
        return nil;
    }
    return [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:error];
}

static NSError *SRPError(NSInteger code, NSString *description) {
    return [NSError errorWithDomain:@"com.altsign.srp"
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: description ?: @"SRP error"}];
}

static void SendGSARequest(NSDictionary *requestDict,
                           ALTAnisetteData *anisetteData,
                           NSDictionary * _Nullable extraHeaders,
                           void (^completion)(NSDictionary * _Nullable response, NSError * _Nullable error))
{
    NSDictionary *body = @{
        @"Header": @{@"Version": @"1.0.1"},
        @"Request": requestDict
    };

    NSData *bodyData = PlistSerialize(body);
    if (!bodyData) {
        completion(nil, SRPError(kAltSignErrorCodeGeneric, @"Failed to serialize plist request"));
        return;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kGSAEndpoint]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = bodyData;

    [request setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"*/*" forHTTPHeaderField:@"Accept"];
    [request setValue:anisetteData.deviceDescription forHTTPHeaderField:@"X-MMe-Client-Info"];

    if (extraHeaders) {
        for (NSString *key in extraHeaders) {
            [request setValue:extraHeaders[key] forHTTPHeaderField:key];
        }
    }

    NSURLSessionDataTask *task = [ALTSharedSession()
        dataTaskWithRequest:request
          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            completion(nil, error);
            return;
        }

        NSInteger httpStatus = 0;
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            httpStatus = ((NSHTTPURLResponse *)response).statusCode;
        }

        if (error || httpStatus < 200 || httpStatus >= 300) {
            NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (raw) {
                if (ALTVerboseLogging) {
                    NSLog(@"[SRP] Error response: %@", raw);
                } else {
                    NSLog(@"[SRP] Error response (first 512 chars): %@", [raw substringToIndex:MIN(512, raw.length)]);
                }
            } else if (data) {
                NSLog(@"[SRP] Error response (binary, %lu bytes)", (unsigned long)data.length);
            }
        }

        if (httpStatus >= 500) {
            completion(nil, SRPError((NSInteger)httpStatus, [NSString stringWithFormat:@"HTTP %ld from Apple", (long)httpStatus]));
            return;
        }

        NSError *parseError = nil;
        NSDictionary *responseDict = PlistDeserialize(data, &parseError);
        if (!responseDict) {
            completion(nil, SRPError(kAltSignErrorCodeGeneric, @"Invalid plist response"));
            return;
        }

        NSDictionary *dictionary = responseDict[@"Response"];
        if (![dictionary isKindOfClass:[NSDictionary class]]) {
            completion(nil, SRPError(kAltSignErrorCodeGeneric, @"Missing Response in plist"));
            return;
        }

        NSDictionary *status = dictionary[@"Status"];
        NSInteger hsc = [status[@"hsc"] integerValue];
        NSInteger errorCode = [status[@"ec"] integerValue];
        if (errorCode != 0 || hsc >= 500) {
            NSString *errorDescription = status[@"em"] ?: [NSString stringWithFormat:@"GSA error (hsc=%ld, ec=%ld)", (long)hsc, (long)errorCode];
            NSLog(@"[SRP] GSA status: %@", status);
            completion(nil, SRPError(errorCode ?: hsc, errorDescription));
            return;
        }
        if (ALTVerboseLogging) {
            NSLog(@"[SRP] GSA response: %@", dictionary);
        }

        completion(dictionary, nil);
    }];

    [task resume];
}

static NSString *SessionStorePath(void) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *base = paths.firstObject ?: NSHomeDirectory();
    NSString *dir = [base stringByAppendingPathComponent:@"altsign"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return [dir stringByAppendingPathComponent:@"session.plist"];
}

static NSString *Pending2FAStorePath(void) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *base = paths.firstObject ?: NSHomeDirectory();
    NSString *dir = [base stringByAppendingPathComponent:@"altsign"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return [dir stringByAppendingPathComponent:@"2fa_pending.plist"];
}

@implementation ALTAppleAPISession

- (instancetype)initWithDSID:(NSString *)dsid
                   authToken:(NSString *)authToken
                anisetteData:(ALTAnisetteData *)anisetteData
{
    self = [super init];
    if (self) {
        _dsid = [dsid copy];
        _authToken = [authToken copy];
        _anisetteData = anisetteData;
    }
    return self;
}

- (BOOL)saveForAppleID:(NSString *)appleID {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"appleID"] = appleID;
    dict[@"dsid"] = self.dsid;
    dict[@"authToken"] = self.authToken;
    if (self.expirationDate) {
        dict[@"expirationDate"] = self.expirationDate;
    }

    NSMutableDictionary *anisette = [NSMutableDictionary dictionary];
    anisette[@"machineID"] = self.anisetteData.machineID ?: @"";
    anisette[@"oneTimePassword"] = self.anisetteData.oneTimePassword ?: @"";
    anisette[@"localUserID"] = self.anisetteData.localUserID ?: @"";
    anisette[@"routingInfo"] = [@(self.anisetteData.routingInfo) description];
    anisette[@"deviceUniqueIdentifier"] = self.anisetteData.deviceUniqueIdentifier ?: @"";
    anisette[@"deviceSerialNumber"] = self.anisetteData.deviceSerialNumber ?: @"";
    anisette[@"deviceDescription"] = self.anisetteData.deviceDescription ?: @"";
    anisette[@"date"] = self.anisetteData.date ?: [NSDate date];
    anisette[@"locale"] = self.anisetteData.locale ?: @"";
    anisette[@"timeZone"] = self.anisetteData.timeZone ?: @"";
    dict[@"anisetteData"] = anisette;

    return [dict writeToFile:SessionStorePath() atomically:YES];
}

+ (nullable instancetype)loadSessionForAppleID:(NSString *)appleID {
    NSString *path = SessionStorePath();
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!dict) return nil;

    NSString *storedAppleID = dict[@"appleID"];
    if (appleID && ![storedAppleID isEqualToString:appleID]) return nil;

    return [self sessionFromDict:dict];
}

+ (nullable instancetype)loadAnySession:(NSString *_Nullable *_Nullable)outAppleID {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:SessionStorePath()];
    if (!dict) return nil;
    if (outAppleID) *outAppleID = dict[@"appleID"];
    return [self sessionFromDict:dict];
}

+ (nullable instancetype)sessionFromDict:(NSDictionary *)dict {
    NSDictionary *ad = dict[@"anisetteData"];
    ALTAnisetteData *anisette = [[ALTAnisetteData alloc]
        initWithMachineID:ad[@"machineID"] ?: @""
          oneTimePassword:ad[@"oneTimePassword"] ?: @""
              localUserID:ad[@"localUserID"] ?: @""
              routingInfo:[ad[@"routingInfo"] integerValue]
   deviceUniqueIdentifier:ad[@"deviceUniqueIdentifier"] ?: @""
       deviceSerialNumber:ad[@"deviceSerialNumber"] ?: @""
        deviceDescription:ad[@"deviceDescription"] ?: @""
                     date:ad[@"date"] ?: [NSDate date]
                   locale:ad[@"locale"] ?: @""
                 timeZone:ad[@"timeZone"] ?: @""];

    ALTAppleAPISession *session = [[ALTAppleAPISession alloc]
        initWithDSID:dict[@"dsid"] ?: @""
           authToken:dict[@"authToken"] ?: @""
        anisetteData:anisette];
    session.expirationDate = dict[@"expirationDate"];
    return session;
}

+ (void)deleteSession {
    [[NSFileManager defaultManager] removeItemAtPath:SessionStorePath() error:nil];
}

- (BOOL)isExpired {
    if (!self.expirationDate) return YES;
    NSDate *buffer = [self.expirationDate dateByAddingTimeInterval:-300];
    return [buffer compare:[NSDate date]] == NSOrderedAscending;
}

@end

@implementation ALTAccount
@end

@interface ALTSRPContext : NSObject
@property (nonatomic, assign) struct ccsrp_ctx *srpCtx;
@property (nonatomic, assign) struct ccdigest_ctx *diCtx;
@end

@implementation ALTSRPContext
- (void)dealloc {
    if (_srpCtx) { free(_srpCtx); _srpCtx = NULL; }
    if (_diCtx) { free(_diCtx); _diCtx = NULL; }
}
@end

@interface ALTSRPAuthenticator ()
+ (void)fetchXcodeAuthTokenWithAdsid:(NSString *)adsid
                           idmsToken:(NSString *)idmsToken
                          sessionKey:(NSData *)sessionKey
                            requestC:(id)requestC
                                 cpd:(NSDictionary *)cpd
                        anisetteData:(ALTAnisetteData *)anisetteData
                   completionHandler:(void (^)(NSString * _Nullable authToken,
                                               NSDate * _Nullable expirationDate,
                                               NSError * _Nullable error))completion;
@end

@implementation ALTSRPAuthenticator

+ (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
              completionHandler:(void (^)(ALTAccount * _Nullable, ALTAppleAPISession * _Nullable, NSError * _Nullable))completion
{
    [self authenticateWithAppleID:appleID password:password anisetteData:anisetteData
              verificationHandler:nil completionHandler:completion];
}

+ (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
              verificationHandler:(nullable ALTVerificationHandler)verificationHandler
              completionHandler:(void (^)(ALTAccount * _Nullable, ALTAppleAPISession * _Nullable, NSError * _Nullable))completion
{
    NSLog(@"[SRP] Starting authentication for %@", appleID);

    NSString *clientTime = [GSAClientTimeFormatter() stringFromDate:anisetteData.date ?: [NSDate date]];
    NSString *locale = [NSLocale currentLocale].localeIdentifier ?: anisetteData.locale ?: @"en_US";
    NSString *timeZone = [NSTimeZone localTimeZone].abbreviation ?: anisetteData.timeZone ?: @"UTC";

    NSMutableDictionary *clientDictionary = [@{
        @"bootstrap": @YES,
        @"icscrec": @YES,
        @"loc": locale,
        @"pbe": @NO,
        @"prkgen": @YES,
        @"svct": @"iCloud",
        @"X-Apple-I-Client-Time": clientTime,
        @"X-Apple-Locale": locale,
        @"X-Apple-I-TimeZone": timeZone,
        @"X-Apple-I-MD": anisetteData.oneTimePassword ?: @"",
        @"X-Apple-I-MD-LU": anisetteData.localUserID ?: @"",
        @"X-Apple-I-MD-M": anisetteData.machineID ?: @"",
        @"X-Apple-I-MD-RINFO": @(anisetteData.routingInfo),
        @"X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier ?: @"",
        @"X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber ?: @"",
    } mutableCopy];

    ccsrp_const_gp_t gp = ccsrp_gp_rfc5054_2048();
    const struct ccdigest_info *diInfo = ccsha256_di();

    ALTSRPContext *ctx = [[ALTSRPContext alloc] init];
    ctx.diCtx = (struct ccdigest_ctx *)malloc(ccdigest_di_size(diInfo));
    ccdigest_init(diInfo, ctx.diCtx);

    ctx.srpCtx = (struct ccsrp_ctx *)malloc(ccsrp_sizeof_srp(diInfo, gp));
    ccsrp_ctx_init(ctx.srpCtx, diInfo, gp);
    ccsrp_client_set_noUsernameInX(ctx.srpCtx, true);
    SRP_RNG(ctx.srpCtx) = ccrng(NULL);

    __block ALTSRPContext *srpContext = ctx;

    NSArray<NSString *> *ps = @[@"s2k", @"s2k_fo"];
    ALTDigestUpdateString(diInfo, srpContext.diCtx, ps[0]);
    ALTDigestUpdateString(diInfo, srpContext.diCtx, @",");
    ALTDigestUpdateString(diInfo, srpContext.diCtx, ps[1]);

    size_t ASize = ccsrp_exchange_size(srpContext.srpCtx);
    char *ABytes = (char *)malloc(ASize);
    int startResult = ccsrp_client_start_authentication(srpContext.srpCtx, ccrng(NULL), ABytes);
    if (startResult != 0) {
        free(ABytes);
        completion(nil, nil, SRPError(startResult, @"Failed to start SRP authentication"));
        return;
    }

    NSData *AData = [NSData dataWithBytes:ABytes length:ASize];
    free(ABytes);

    ALTDigestUpdateString(diInfo, srpContext.diCtx, @"|");

    NSDictionary *initRequest = @{
        @"A2k": AData,
        @"ps": ps,
        @"cpd": clientDictionary,
        @"u": appleID,
        @"o": @"init"
    };

    SendGSARequest(initRequest, anisetteData, nil, ^(NSDictionary *initResponse, NSError *error) {
        if (error || !initResponse) {
            completion(nil, nil, error ?: SRPError(kAltSignErrorCodeGeneric, @"Empty init response"));
            return;
        }

        NSString *sp = initResponse[@"sp"];
        BOOL isS2K = [sp isEqualToString:@"s2k"];

        ALTDigestUpdateString(diInfo, srpContext.diCtx, @"|");
        if (sp) {
            ALTDigestUpdateString(diInfo, srpContext.diCtx, sp);
        }

        id cValue = initResponse[@"c"];
        NSData *salt = initResponse[@"s"];
        NSNumber *iterations = initResponse[@"i"];
        NSData *BData = initResponse[@"B"];

        if (!cValue || !salt || !iterations || !BData) {
            completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Invalid init challenge"));
            return;
        }

        NSData *passwordKey = ALTPBKDF2SRP(diInfo, isS2K, password, salt, iterations.intValue);
        if (!passwordKey) {
            completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Failed to derive SRP password key"));
            return;
        }

        size_t MSize = ccsrp_session_size(srpContext.srpCtx);
        NSMutableData *MData = [NSMutableData dataWithLength:MSize];

        int challengeResult = ccsrp_client_process_challenge(srpContext.srpCtx,
                                                             appleID.UTF8String,
                                                             passwordKey.length,
                                                             passwordKey.bytes,
                                                             salt.length,
                                                             salt.bytes,
                                                             BData.bytes,
                                                             MData.mutableBytes);
        if (challengeResult != 0) {
            completion(nil, nil, SRPError(challengeResult, @"SRP challenge failed"));
            return;
        }

        NSDictionary *completeRequest = @{
            @"c": cValue,
            @"M1": MData,
            @"cpd": clientDictionary,
            @"u": appleID,
            @"o": @"complete"
        };

        SendGSARequest(completeRequest, anisetteData, nil, ^(NSDictionary *completeResponse, NSError *error) {
            if (error || !completeResponse) {
                completion(nil, nil, error ?: SRPError(kAltSignErrorCodeGeneric, @"Empty complete response"));
                return;
            }

            NSData *M2Data = completeResponse[@"M2"];
            if (!M2Data || !ccsrp_client_verify_session(srpContext.srpCtx, (const uint8_t *)M2Data.bytes)) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Failed to verify SRP session"));
                return;
            }

            ALTDigestUpdateString(diInfo, srpContext.diCtx, @"|");
            NSData *spd = completeResponse[@"spd"];
            if (spd) {
                ALTDigestUpdateData(diInfo, srpContext.diCtx, spd);
            }

            ALTDigestUpdateString(diInfo, srpContext.diCtx, @"|");
            NSData *sc = completeResponse[@"sc"];
            if (sc) {
                ALTDigestUpdateData(diInfo, srpContext.diCtx, sc);
            }

            ALTDigestUpdateString(diInfo, srpContext.diCtx, @"|");
            NSData *np = completeResponse[@"np"];
            if (!np) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing negotiation proof"));
                return;
            }

            size_t digestLen = diInfo->output_size;
            if (np.length != digestLen) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Invalid negotiation proof length"));
                return;
            }

            unsigned char *digest = (unsigned char *)malloc(digestLen);
            diInfo->final(diInfo, srpContext.diCtx, digest);

            NSData *hmacKey = ALTCreateSessionKey(srpContext.srpCtx, "HMAC key:");
            if (!hmacKey) {
                free(digest);
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing SRP session key"));
                return;
            }

            unsigned char *hmacOut = (unsigned char *)malloc(digestLen);
            cchmac(diInfo, hmacKey.length, hmacKey.bytes, digestLen, digest, hmacOut);
            int proofMismatch = cc_cmp_safe(digestLen, hmacOut, np.bytes);
            free(digest);
            free(hmacOut);

            if (proofMismatch) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Invalid negotiation proof"));
                return;
            }

            NSData *decryptedData = ALTDecryptDataCBC(srpContext.srpCtx, spd);
            if (!decryptedData) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Failed to decrypt SRP payload"));
                return;
            }

            NSError *parseError = nil;
            NSDictionary *decryptedDictionary = PlistDeserialize(decryptedData, &parseError);
            if (!decryptedDictionary) {
                completion(nil, nil, parseError ?: SRPError(kAltSignErrorCodeGeneric, @"Failed to parse SRP payload"));
                return;
            }

            NSString *adsid = decryptedDictionary[@"adsid"];
            NSString *idmsToken = decryptedDictionary[@"GsIdmsToken"];
            if (adsid.length == 0 || idmsToken.length == 0) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing adsid or idmsToken"));
                return;
            }

            NSDictionary *statusDictionary = completeResponse[@"Status"];
            NSString *authType = statusDictionary[@"au"];
            if ([authType isEqualToString:@"trustedDeviceSecondaryAuth"] || [authType isEqualToString:@"secondaryAuth"]) {
                [self _requestTwoFactorCodeForDSID:adsid idmsToken:idmsToken anisetteData:anisetteData
                                 completionHandler:^(NSError * _Nullable requestError) {
                    if (requestError) {
                        completion(nil, nil, requestError);
                        return;
                    }

                    if (!verificationHandler) {
                        completion(nil, nil, SRPError(kAltSignErrorCode2FARequired, @"Two-factor authentication required."));
                        return;
                    }

                    verificationHandler(^(NSString * _Nullable code) {
                        if (!code || code.length == 0) {
                            completion(nil, nil, SRPError(kAltSignErrorCode2FARequired, @"2FA code not provided"));
                            return;
                        }

                        [self submitTwoFactorCode:code dsid:adsid idmsToken:idmsToken anisetteData:anisetteData
                                completionHandler:^(BOOL success, NSError * _Nullable verifyError) {
                            if (!success) {
                                completion(nil, nil, verifyError ?: SRPError(kAltSignErrorCodeInvalid2FA, @"Incorrect verification code"));
                                return;
                            }

                            // Validate 成功后直接用第一次 SRP 的 session data 取 token，不再 re-SRP
                            NSData *sk = decryptedDictionary[@"sk"];
                            id requestC = decryptedDictionary[@"c"];
                            if (!sk || !requestC) {
                                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing session key material"));
                                return;
                            }

                            [self fetchXcodeAuthTokenWithAdsid:adsid
                                                     idmsToken:idmsToken
                                                    sessionKey:sk
                                                      requestC:requestC
                                                           cpd:clientDictionary
                                                  anisetteData:anisetteData
                                             completionHandler:^(NSString *authToken, NSDate *expirationDate, NSError *tokenError) {
                                if (tokenError || authToken.length == 0) {
                                    completion(nil, nil, tokenError ?: SRPError(kAltSignErrorCodeGeneric, @"Empty auth token"));
                                    return;
                                }

                                ALTAccount *account = [[ALTAccount alloc] init];
                                account.appleID = appleID;
                                account.identifier = adsid;

                                ALTAppleAPISession *session = [[ALTAppleAPISession alloc] initWithDSID:adsid
                                                                                            authToken:authToken
                                                                                         anisetteData:anisetteData];
                                session.expirationDate = expirationDate;
                                [session saveForAppleID:appleID];

                                NSLog(@"[SRP] Authentication successful, session saved (expires: %@)", expirationDate);
                                completion(account, session, nil);
                            }];
                        }];
                    });
                }];
                return;
            }

            NSData *sk = decryptedDictionary[@"sk"];
            id requestC = decryptedDictionary[@"c"];
            if (!sk || !requestC) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing app token key material"));
                return;
            }

            [self fetchXcodeAuthTokenWithAdsid:adsid
                                     idmsToken:idmsToken
                                    sessionKey:sk
                                      requestC:requestC
                                           cpd:clientDictionary
                                  anisetteData:anisetteData
                             completionHandler:^(NSString *authToken, NSDate *expirationDate, NSError *tokenError) {
                if (tokenError || authToken.length == 0) {
                    completion(nil, nil, tokenError ?: SRPError(kAltSignErrorCodeGeneric, @"Empty auth token"));
                    return;
                }

                ALTAccount *account = [[ALTAccount alloc] init];
                account.appleID = appleID;
                account.identifier = adsid;

                ALTAppleAPISession *session = [[ALTAppleAPISession alloc] initWithDSID:adsid
                                                                              authToken:authToken
                                                                           anisetteData:anisetteData];
                session.expirationDate = expirationDate;
                [session saveForAppleID:appleID];

                NSLog(@"[SRP] Authentication successful, session saved (expires: %@)", expirationDate);
                completion(account, session, nil);
            }];
        });
    });
}

+ (void)_requestTwoFactorCodeForDSID:(NSString *)dsid
                           idmsToken:(NSString *)idmsToken
                        anisetteData:(ALTAnisetteData *)anisetteData
                   completionHandler:(void (^)(NSError * _Nullable error))completion
{
    NSString *identityToken = [NSString stringWithFormat:@"%@:%@", dsid, idmsToken];
    NSData *tokenData = [identityToken dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64Token = [tokenData base64EncodedStringWithOptions:0];

    NSDictionary<NSString *, NSString *> *headers = @{
        @"Content-Type": @"text/x-xml-plist",
        @"Accept": @"text/x-xml-plist",
        @"User-Agent": kGSA2FAUserAgent,
        @"Accept-Language": @"en-us",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Xcode-Version": kGSAXcodeVersion,
        @"X-Apple-Identity-Token": base64Token,
        @"X-Apple-I-MD-M": anisetteData.machineID ?: @"",
        @"X-Apple-I-MD": anisetteData.oneTimePassword ?: @"",
        @"X-Apple-I-MD-LU": anisetteData.localUserID ?: @"",
        @"X-Apple-I-MD-RINFO": [@(anisetteData.routingInfo) description],
        @"X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier ?: @"",
        @"X-MMe-Client-Info": anisetteData.deviceDescription ?: @"",
        @"X-Apple-I-Client-Time": [GSAClientTimeFormatter() stringFromDate:anisetteData.date ?: [NSDate date]],
        @"X-Apple-Locale": anisetteData.locale ?: [NSLocale currentLocale].localeIdentifier ?: @"en_US",
        @"X-Apple-I-TimeZone": anisetteData.timeZone ?: [NSTimeZone localTimeZone].abbreviation ?: @"UTC",
    };

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kGSA2FARequest]];
    request.HTTPMethod = @"GET";
    for (NSString *key in headers) {
        [request setValue:headers[key] forHTTPHeaderField:key];
    }

    NSLog(@"[2FA] Requesting trusted device code for DSID %@...", dsid);
    NSURLSessionDataTask *task = [ALTSharedSession()
        dataTaskWithRequest:request
          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            NSLog(@"[2FA] Request failed: %@", error);
            completion(error);
            return;
        }
        NSInteger httpStatus = 0;
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            httpStatus = ((NSHTTPURLResponse *)response).statusCode;
        }
        NSString *bodyPreview = @"";
        if (data.length > 0) {
            NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (raw) {
                bodyPreview = (ALTVerboseLogging || raw.length <= 200) ? raw : [raw substringToIndex:200];
            } else {
                bodyPreview = [NSString stringWithFormat:@"(binary, %lu bytes)", (unsigned long)data.length];
            }
        }
        NSLog(@"[2FA] Trusted device request HTTP %ld, bodyPreview: %@", (long)httpStatus, bodyPreview);
        if (httpStatus < 200 || httpStatus >= 300) {
            completion(SRPError(httpStatus, [NSString stringWithFormat:@"HTTP %ld from 2FA request", (long)httpStatus]));
            return;
        }
        completion(nil);
    }];

    [task resume];
}

+ (void)fetchXcodeAuthTokenWithAdsid:(NSString *)adsid
                           idmsToken:(NSString *)idmsToken
                          sessionKey:(NSData *)sessionKey
                            requestC:(id)requestC
                                 cpd:(NSDictionary *)cpd
                        anisetteData:(ALTAnisetteData *)anisetteData
                   completionHandler:(void (^)(NSString * _Nullable authToken,
                                               NSDate * _Nullable expirationDate,
                                               NSError * _Nullable error))completion
{
    NSArray<NSString *> *apps = @[@"com.apple.gs.xcode.auth"];
    NSData *checksum = ALTCreateAppTokensChecksum(sessionKey, adsid, apps);

    NSDictionary *appTokenRequest = @{
        @"u": adsid,
        @"app": apps,
        @"c": requestC,
        @"t": idmsToken,
        @"checksum": checksum,
        @"cpd": cpd,
        @"o": @"apptokens"
    };

    SendGSARequest(appTokenRequest, anisetteData, nil, ^(NSDictionary *response, NSError *error) {
        if (error || !response) {
            completion(nil, nil, error ?: SRPError(kAltSignErrorCodeGeneric, @"Empty app token response"));
            return;
        }

        NSData *encryptedToken = response[@"et"];
        if (!encryptedToken) {
            completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing encrypted app token"));
            return;
        }

        NSData *decryptedToken = ALTDecryptDataGCM(sessionKey, encryptedToken);
        if (!decryptedToken) {
            completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Failed to decrypt app token"));
            return;
        }

        NSError *parseError = nil;
        NSDictionary *tokenPlist = PlistDeserialize(decryptedToken, &parseError);
        if (!tokenPlist) {
            completion(nil, nil, parseError ?: SRPError(kAltSignErrorCodeGeneric, @"Failed to parse app token plist"));
            return;
        }

        NSString *app = apps.firstObject;
        NSDictionary *tokenDictionary = tokenPlist[@"t"][app];
        NSString *token = tokenDictionary[@"token"];
        if (token.length == 0) {
            completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing Xcode auth token"));
            return;
        }

        NSNumber *expiryMS = tokenDictionary[@"expiry"];
        NSDate *expirationDate = nil;
        if (expiryMS) {
            expirationDate = [NSDate dateWithTimeIntervalSince1970:(double)expiryMS.integerValue / 1000.0];
        }

        completion(token, expirationDate, nil);
    });
}

+ (void)submitTwoFactorCode:(NSString *)code
                       dsid:(NSString *)dsid
                  idmsToken:(NSString *)idmsToken
               anisetteData:(ALTAnisetteData *)anisetteData
          completionHandler:(void (^)(BOOL success, NSError * _Nullable error))completion
{
    NSString *identityToken = [NSString stringWithFormat:@"%@:%@", dsid, idmsToken];
    NSData *tokenData = [identityToken dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64Token = [tokenData base64EncodedStringWithOptions:0];

    NSDictionary<NSString *, NSString *> *headers = @{
        @"Content-Type": @"text/x-xml-plist",
        @"Accept": @"text/x-xml-plist",
        @"User-Agent": kGSA2FAUserAgent,
        @"Accept-Language": @"en-us",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Xcode-Version": kGSAXcodeVersion,
        @"X-Apple-Identity-Token": base64Token,
        @"X-Apple-I-MD-M": anisetteData.machineID ?: @"",
        @"X-Apple-I-MD": anisetteData.oneTimePassword ?: @"",
        @"X-Apple-I-MD-LU": anisetteData.localUserID ?: @"",
        @"X-Apple-I-MD-RINFO": [@(anisetteData.routingInfo) description],
        @"X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier ?: @"",
        @"X-MMe-Client-Info": anisetteData.deviceDescription ?: @"",
        @"X-Apple-I-Client-Time": [GSAClientTimeFormatter() stringFromDate:anisetteData.date ?: [NSDate date]],
        @"X-Apple-Locale": anisetteData.locale ?: [NSLocale currentLocale].localeIdentifier ?: @"en_US",
        @"X-Apple-I-TimeZone": anisetteData.timeZone ?: [NSTimeZone localTimeZone].abbreviation ?: @"UTC",
        @"security-code": code ?: @"",
    };

    NSMutableURLRequest *validateRequest = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kGSA2FAValidate]];
    validateRequest.HTTPMethod = @"GET";
    for (NSString *key in headers) {
        [validateRequest setValue:headers[key] forHTTPHeaderField:key];
    }

    NSLog(@"[2FA] Validating code for DSID %@...", dsid);
    NSURLSessionDataTask *validateTask = [ALTSharedSession()
        dataTaskWithRequest:validateRequest
          completionHandler:^(NSData *validateData, NSURLResponse *validateResponse, NSError *validateError) {
        if (validateError) {
            NSLog(@"[2FA] Validate network error: %@", validateError);
            completion(NO, validateError);
            return;
        }

        NSInteger httpStatus = [(NSHTTPURLResponse *)validateResponse statusCode];
        NSLog(@"[2FA] Validate HTTP status: %ld", (long)httpStatus);

        if (!validateData || validateData.length == 0) {
            if (httpStatus >= 200 && httpStatus < 300) {
                NSLog(@"[2FA] Validation successful (empty body, HTTP %ld)", (long)httpStatus);
                completion(YES, nil);
            } else {
                completion(NO, SRPError(kAltSignErrorCodeGeneric, [NSString stringWithFormat:@"2FA validation failed (HTTP %ld, empty body)", (long)httpStatus]));
            }
            return;
        }

        NSString *raw = [[NSString alloc] initWithData:validateData encoding:NSUTF8StringEncoding];
        if (raw) {
            NSString *preview = (ALTVerboseLogging || raw.length <= 300) ? raw : [raw substringToIndex:300];
            NSLog(@"[2FA] Validate response: %@", preview);
        }

        NSError *parseError = nil;
        NSDictionary *responseDictionary = PlistDeserialize(validateData, &parseError);
        if (!responseDictionary) {
            completion(NO, parseError ?: SRPError(kAltSignErrorCodeGeneric, @"Invalid 2FA response plist"));
            return;
        }

        // validate endpoint returns flat plist (ec, em, atxid, idmsdata) not nested Response/Status
        NSInteger errorCode = [responseDictionary[@"ec"] integerValue];
        if (errorCode != 0) {
            NSString *errorDescription = responseDictionary[@"em"] ?: @"2FA verification failed";
            NSLog(@"[2FA] Validation failed: ec=%ld, em=%@", (long)errorCode, errorDescription);
            completion(NO, SRPError(errorCode, errorDescription));
            return;
        }

        NSLog(@"[2FA] Validation successful");
        completion(YES, nil);
    }];

    [validateTask resume];
}

+ (BOOL)hasPendingTwoFactorAuthentication {
    NSString *path = Pending2FAStorePath();
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!dict) return NO;
    NSDate *date = dict[@"date"];
    if (!date || -[date timeIntervalSinceNow] > 300) return NO;
    return YES;
}

+ (void)submitPendingTwoFactorCode:(NSString *)code
                          password:(NSString *)password
                 completionHandler:(void (^)(ALTAccount * _Nullable account,
                                            ALTAppleAPISession * _Nullable session,
                                            NSError * _Nullable error))completion
{
    NSString *path = Pending2FAStorePath();
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!dict) {
        completion(nil, nil, SRPError(kAltSignErrorCode2FARequired, @"No pending two-factor authentication"));
        return;
    }
    NSDate *date = dict[@"date"];
    if (!date || -[date timeIntervalSinceNow] > 300) {
        [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
        completion(nil, nil, SRPError(kAltSignErrorCode2FARequired, @"Pending 2FA expired"));
        return;
    }

    NSString *adsid = dict[@"adsid"];
    NSString *idmsToken = dict[@"idmsToken"];
    NSString *appleID = dict[@"appleID"];
    NSDictionary *ad = dict[@"anisetteData"];
    ALTAnisetteData *anisetteData = [[ALTAnisetteData alloc]
        initWithMachineID:ad[@"machineID"] ?: @""
          oneTimePassword:ad[@"oneTimePassword"] ?: @""
              localUserID:ad[@"localUserID"] ?: @""
              routingInfo:[ad[@"routingInfo"] integerValue]
   deviceUniqueIdentifier:ad[@"deviceUniqueIdentifier"] ?: @""
       deviceSerialNumber:ad[@"deviceSerialNumber"] ?: @""
        deviceDescription:ad[@"deviceDescription"] ?: @""
                     date:ad[@"date"] ?: [NSDate date]
                   locale:ad[@"locale"] ?: @""
                 timeZone:ad[@"timeZone"] ?: @""];

    [self submitTwoFactorCode:code dsid:adsid idmsToken:idmsToken anisetteData:anisetteData
            completionHandler:^(BOOL success, NSError * _Nullable error) {
        if (!success) {
            // Remove pending state on failure so user can trigger a new code
            [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
            completion(nil, nil, error ?: SRPError(kAltSignErrorCodeInvalid2FA, @"Incorrect verification code"));
            return;
        }

        [[NSFileManager defaultManager] removeItemAtPath:path error:nil];

        NSData *sk = dict[@"sk"];
        id requestC = dict[@"requestC"];
        NSDictionary *cpd = dict[@"cpd"];
        if (!sk || !requestC || !cpd) {
            completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing session data. Please re-run without --2fa-code first."));
            return;
        }

        NSLog(@"[SRP] 2FA validated, fetching auth token...");

        [self fetchXcodeAuthTokenWithAdsid:adsid
                                 idmsToken:idmsToken
                                sessionKey:sk
                                  requestC:requestC
                                       cpd:cpd
                              anisetteData:anisetteData
                         completionHandler:^(NSString *authToken, NSDate *expirationDate, NSError *tokenError) {
            if (tokenError || authToken.length == 0) {
                completion(nil, nil, tokenError ?: SRPError(kAltSignErrorCodeGeneric, @"Empty auth token"));
                return;
            }

            ALTAccount *account = [[ALTAccount alloc] init];
            account.appleID = appleID;
            account.identifier = adsid;

            ALTAppleAPISession *session = [[ALTAppleAPISession alloc] initWithDSID:adsid
                                                                        authToken:authToken
                                                                     anisetteData:anisetteData];
            session.expirationDate = expirationDate;
            [session saveForAppleID:appleID];

            NSLog(@"[SRP] Auth successful (expires: %@)", expirationDate);
            completion(account, session, nil);
        }];
    }];
}

@end
