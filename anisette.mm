//
//  anisette.mm
//  AltSign CLI
//
//  Anisette 数据获取 — 优先 AOSKit，fallback AuthKit
//  参照 AltStore AnisetteDataManager 实现
//

#import "anisette.h"
#import <dlfcn.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/sysctl.h>

static NSString *MachineModel(void) {
    char model[256];
    size_t size = sizeof(model);
    if (sysctlbyname("hw.model", model, &size, NULL, 0) == 0) {
        return [NSString stringWithUTF8String:model];
    }
    return @"MacBookPro18,3";
}

static NSString *OSBuildVersion(void) {
    char build[256];
    size_t size = sizeof(build);
    if (sysctlbyname("kern.osproductversion", build, &size, NULL, 0) == 0) {
        return [NSString stringWithUTF8String:build];
    }
    return @"22F66";
}

static NSString *DeviceDescription(NSString *deviceModel, NSString *osVersion, NSString *buildVersion) {
    NSString *osName = @"macOS";
    return [NSString stringWithFormat:@"<%@> <%@;%@;%@> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
            deviceModel, osName, osVersion, buildVersion];
}

static NSString *Base64LocalUserID(NSString *udid) {
    if (!udid) return @"";
    return [[udid dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
}

@implementation ALTAnisetteData

- (instancetype)initWithMachineID:(NSString *)machineID
                  oneTimePassword:(NSString *)oneTimePassword
                      localUserID:(NSString *)localUserID
                      routingInfo:(NSUInteger)routingInfo
           deviceUniqueIdentifier:(NSString *)deviceUniqueIdentifier
               deviceSerialNumber:(NSString *)deviceSerialNumber
                deviceDescription:(NSString *)deviceDescription
                             date:(NSDate *)date
                           locale:(NSString *)locale
                         timeZone:(NSString *)timeZone
{
    self = [super init];
    if (self) {
        _machineID = [machineID copy];
        _oneTimePassword = [oneTimePassword copy];
        _localUserID = [localUserID copy];
        _routingInfo = routingInfo;
        _deviceUniqueIdentifier = [deviceUniqueIdentifier copy];
        _deviceSerialNumber = [deviceSerialNumber copy];
        _deviceDescription = [deviceDescription copy];
        _date = date;
        _locale = [locale copy];
        _timeZone = [timeZone copy];
    }
    return self;
}

+ (void)fetchAnisetteDataWithCompletion:(void (^)(ALTAnisetteData * _Nullable, NSError * _Nullable))completion
{
    // 主路径：AOSKit
    ALTAnisetteData * _Nullable (^fetchFromAOSKit)(void) = ^ALTAnisetteData * _Nullable {
        NSBundle *aosKit = [NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AOSKit.framework"];
        if (!aosKit || ![aosKit load]) {
            NSLog(@"[Anisette] AOSKit load failed");
            return nil;
        }

        Class AOSUtilitiesClass = NSClassFromString(@"AOSUtilities");
        if (!AOSUtilitiesClass) {
            NSLog(@"[Anisette] AOSUtilities not found");
            return nil;
        }

        SEL otpSel = NSSelectorFromString(@"retrieveOTPHeadersForDSID:");
        if (![AOSUtilitiesClass respondsToSelector:otpSel]) {
            NSLog(@"[Anisette] AOSUtilities does not respond to retrieveOTPHeadersForDSID:");
            return nil;
        }

        NSDictionary *requestHeaders = ((id (*)(id, SEL, id))objc_msgSend)(
            AOSUtilitiesClass, otpSel, @"-2"
        );
        if (!requestHeaders || requestHeaders.count == 0) {
            NSLog(@"[Anisette] retrieveOTPHeadersForDSID returned empty");
            return nil;
        }
        NSLog(@"[Anisette] AOSKit headers keys: %@", [requestHeaders.allKeys componentsJoinedByString:@", "]);

        NSString *machineID = requestHeaders[@"X-Apple-MD-M"];
        NSString *oneTimePassword = requestHeaders[@"X-Apple-MD"];
        if (!machineID || machineID.length == 0 || !oneTimePassword || oneTimePassword.length == 0) {
            NSLog(@"[Anisette] AOSKit missing MID/OTP in headers");
            return nil;
        }

        SEL udidSel = NSSelectorFromString(@"machineUDID");
        NSString *deviceID = nil;
        if ([AOSUtilitiesClass respondsToSelector:udidSel]) {
            deviceID = ((id (*)(id, SEL))objc_msgSend)(AOSUtilitiesClass, udidSel);
        }
        if (!deviceID) deviceID = @"Unknown";

        SEL serialSel = NSSelectorFromString(@"machineSerialNumber");
        NSString *serialNumber = nil;
        if ([AOSUtilitiesClass respondsToSelector:serialSel]) {
            serialNumber = ((id (*)(id, SEL))objc_msgSend)(AOSUtilitiesClass, serialSel);
        }
        if (!serialNumber) serialNumber = @"C0FFFFFFFFFFFF";

        NSString *localUserID = Base64LocalUserID(deviceID);
        NSUInteger routingInfo = 84215040;

        NSString *deviceModel = MachineModel();
        NSString *osVersion = OSBuildVersion();
        NSString *buildVersion = @"22F66"; // fallback
        NSString *deviceDescription = DeviceDescription(deviceModel, osVersion, buildVersion);

        NSLog(@"[Anisette] AOSKit OK machineID=%lu otp=%lu", (unsigned long)machineID.length, (unsigned long)oneTimePassword.length);

        return [[ALTAnisetteData alloc]
            initWithMachineID:machineID
              oneTimePassword:oneTimePassword
                  localUserID:localUserID
                  routingInfo:routingInfo
       deviceUniqueIdentifier:deviceID
           deviceSerialNumber:serialNumber
            deviceDescription:deviceDescription
                         date:[NSDate date]
                       locale:[[NSLocale currentLocale] localeIdentifier]
                     timeZone:[[NSTimeZone localTimeZone] abbreviation]];
    };

    ALTAnisetteData *data = fetchFromAOSKit();
    if (data) {
        completion(data, nil);
        return;
    }

    // Fallback：AuthKit AKAppleIDSession
    NSLog(@"[Anisette] Falling back to AuthKit...");

    static Class AKAppleIDSessionClass = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        dlopen("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit", RTLD_LAZY);
        AKAppleIDSessionClass = NSClassFromString(@"AKAppleIDSession");
    });

    if (!AKAppleIDSessionClass) {
        completion(nil, [NSError errorWithDomain:@"com.altsign.anisette" code:-1
                                        userInfo:@{NSLocalizedDescriptionKey: @"AuthKit not available"}]);
        return;
    }

    @try {
        id session = ((id (*)(id, SEL, id))objc_msgSend)(
            [AKAppleIDSessionClass alloc],
            NSSelectorFromString(@"initWithIdentifier:"),
            @"com.apple.gs.xcode.auth"
        );

        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://gsa.apple.com"]];
        NSDictionary *headers = ((id (*)(id, SEL, id))objc_msgSend)(
            session, NSSelectorFromString(@"appleIDHeadersForRequest:"), request
        );

        if (!headers) {
            completion(nil, [NSError errorWithDomain:@"com.altsign.anisette" code:-2
                                            userInfo:@{NSLocalizedDescriptionKey: @"AuthKit returned empty headers"}]);
            return;
        }

        NSString *machineID = headers[@"X-Apple-I-MD-M"] ?: headers[@"X-Apple-I-MD-MachineId"] ?: @"";
        NSString *otp = headers[@"X-Apple-I-MD"] ?: headers[@"X-Apple-I-MD-OTP"] ?: @"";
        NSString *localUserID = headers[@"X-Apple-I-MD-LU"] ?: @"";
        NSString *rinfoStr = headers[@"X-Apple-I-MD-RINFO"];
        NSUInteger routingInfo = (NSUInteger)[rinfoStr longLongValue];

        NSLog(@"[Anisette] AuthKit fallback machineID=%lu otp=%lu", (unsigned long)machineID.length, (unsigned long)otp.length);

        ALTAnisetteData *fallbackData = [[ALTAnisetteData alloc]
            initWithMachineID:machineID
              oneTimePassword:otp
                  localUserID:localUserID
                  routingInfo:routingInfo
       deviceUniqueIdentifier:[[NSUUID UUID] UUIDString]
           deviceSerialNumber:@"C0FFFFFFFFFFFF"
            deviceDescription:DeviceDescription(MachineModel(), OSBuildVersion(), @"22F66")
                         date:[NSDate date]
                       locale:[[NSLocale currentLocale] localeIdentifier]
                     timeZone:[[NSTimeZone localTimeZone] abbreviation]];

        completion(fallbackData, nil);
    } @catch (NSException *exception) {
        completion(nil, [NSError errorWithDomain:@"com.altsign.anisette" code:-3
                                        userInfo:@{NSLocalizedDescriptionKey: exception.reason ?: @"AuthKit exception"}]);
    }
}

- (NSDictionary<NSString *, NSString *> *)httpHeaders
{
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
    formatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];

    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    headers[@"X-Apple-I-MD"]       = self.oneTimePassword ?: @"";
    headers[@"X-Apple-I-MD-M"]     = self.machineID ?: @"";
    headers[@"X-Apple-I-MD-LU"]    = self.localUserID ?: @"";
    headers[@"X-Apple-I-MD-RINFO"] = [NSString stringWithFormat:@"%lu", (unsigned long)self.routingInfo];
    headers[@"X-Mme-Device-Id"]    = self.deviceUniqueIdentifier ?: @"";
    headers[@"X-Apple-I-SRL-NO"]   = self.deviceSerialNumber ?: @"";
    headers[@"X-Apple-I-Client-Time"] = [formatter stringFromDate:self.date];
    headers[@"X-Apple-I-TimeZone"] = self.timeZone ?: @"UTC";
    headers[@"X-Apple-Locale"]     = self.locale ?: @"en_US";
    headers[@"X-MMe-Client-Info"]  = self.deviceDescription ?: @"";
    return headers;
}

@end
