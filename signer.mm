//
//  signer.mm
//  AltSign CLI
//
//  IPA re-signing via codesign (targeted signing, preserves Apple frameworks)
//

#import "signer.h"
#import <Foundation/Foundation.h>

@interface ALTSigner ()
@property (nonatomic, strong) ALTCertificate *certificate;
@end

@implementation ALTSigner

- (instancetype)initWithCertificate:(ALTCertificate *)certificate {
    self = [super init];
    if (self) {
        _certificate = certificate;
    }
    return self;
}

#pragma mark - Main Signing Flow

- (void)signIPAAtURL:(NSURL *)ipaURL
provisioningProfiles:(NSArray<ALTProvisioningProfile *> *)profiles
           outputURL:(NSURL *)outputURL
   completionHandler:(void (^)(BOOL, NSError *))completion
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error = nil;

    // Step 1: 解压 IPA
    NSURL *tempDir = [fm.temporaryDirectory URLByAppendingPathComponent:
                      [[NSUUID UUID] UUIDString]];
    [fm createDirectoryAtURL:tempDir withIntermediateDirectories:YES attributes:nil error:nil];

    NSURL *payloadDir = [tempDir URLByAppendingPathComponent:@"Payload"];

    NSLog(@"[Signer] Extracting IPA: %@", ipaURL.path);

    NSTask *unzipTask = [[NSTask alloc] init];
    unzipTask.launchPath = @"/usr/bin/ditto";
    unzipTask.arguments = @[@"-xk", ipaURL.path, tempDir.path];
    [unzipTask launch];
    [unzipTask waitUntilExit];

    if (unzipTask.terminationStatus != 0) {
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-1
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to extract IPA"}]);
        return;
    }

    // 找到 .app bundle
    NSURL *appURL = nil;
    for (NSURL *url in [fm contentsOfDirectoryAtURL:payloadDir
                            includingPropertiesForKeys:nil options:0 error:nil]) {
        if ([url.pathExtension isEqualToString:@"app"]) {
            appURL = url;
            break;
        }
    }
    if (!appURL) {
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-2
                                       userInfo:@{NSLocalizedDescriptionKey: @"No .app found in IPA"}]);
        return;
    }
    NSLog(@"[Signer] Found app bundle: %@", appURL.lastPathComponent);

    // Step 2: 嵌入 Provisioning Profile + 提取 Entitlements
    NSMutableDictionary<NSString *, NSString *> *entitlementsByPath = [NSMutableDictionary dictionary];

    [self prepareAppAtURL:appURL provisioningProfiles:profiles entitlementsByPath:entitlementsByPath];

    NSURL *plugInsURL = [appURL URLByAppendingPathComponent:@"PlugIns"];
    if ([fm fileExistsAtPath:plugInsURL.path]) {
        for (NSURL *extURL in [fm contentsOfDirectoryAtURL:plugInsURL
                                includingPropertiesForKeys:nil options:0 error:nil]) {
            if ([extURL.pathExtension isEqualToString:@"appex"] ||
                [extURL.pathExtension isEqualToString:@"xctest"]) {
                [self prepareAppAtURL:extURL provisioningProfiles:profiles entitlementsByPath:entitlementsByPath];
            }
        }
    }

    if (entitlementsByPath.count == 0) {
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-5
                                       userInfo:@{NSLocalizedDescriptionKey: @"No entitlements extracted"}]);
        return;
    }

    // Step 3: 生成 P12
    NSData *p12Data = [self.certificate p12Data];
    if (!p12Data) {
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-3
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to generate P12"}]);
        return;
    }
    NSLog(@"[Signer] P12 generated: %lu bytes", (unsigned long)p12Data.length);

    // Step 4: 创建临时 Keychain + 导入 P12
    NSString *kcPass = @"altsign";
    NSURL *keychainURL = [tempDir URLByAppendingPathComponent:@"sign.keychain-db"];

    [self runTask:@"/usr/bin/security" args:@[@"create-keychain", @"-p", kcPass, keychainURL.path]];
    [self runTask:@"/usr/bin/security" args:@[@"set-keychain-settings", keychainURL.path]];
    [self runTask:@"/usr/bin/security" args:@[@"unlock-keychain", @"-p", kcPass, keychainURL.path]];

    NSURL *p12URL = [tempDir URLByAppendingPathComponent:@"cert.p12"];
    [p12Data writeToURL:p12URL atomically:YES];
    [self runTask:@"/usr/bin/security" args:@[@"import", p12URL.path, @"-k", keychainURL.path, @"-P", @"altsign",
                                                @"-T", @"/usr/bin/codesign", @"-T", @"/usr/bin/security"]];
    [self runTask:@"/usr/bin/security" args:@[@"list-keychains", @"-d", @"user", @"-s",
                                                keychainURL.path, @"login.keychain-db"]];
    [self runTask:@"/usr/bin/security" args:@[@"set-key-partition-list", @"-S",
                                                @"apple-tool:,apple:,codesign:", @"-s", @"-k", kcPass, keychainURL.path]];

    // 获取签名身份
    NSString *identity = [self findSigningIdentity:keychainURL];
    if (!identity) {
        [self runTask:@"/usr/bin/security" args:@[@"delete-keychain", keychainURL.path]];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-6
                                       userInfo:@{NSLocalizedDescriptionKey: @"No signing identity found"}]);
        return;
    }
    NSLog(@"[Signer] Identity: %@", identity);

    // Step 5: 从内到外签名——先签嵌套的非 Apple 代码，再签主 app
    NSLog(@"[Signer] Signing binaries...");

    // 5a: 签名 PlugIns 中的 .appex/.xctest bundle
    for (NSString *path in entitlementsByPath) {
        NSString *bundlePath = [path stringByDeletingLastPathComponent];
        if ([bundlePath hasSuffix:@".appex"] || [bundlePath hasSuffix:@".xctest"]) {
            NSURL *entURL = [tempDir URLByAppendingPathComponent:
                [NSString stringWithFormat:@"ent_%@.plist", [[NSUUID UUID] UUIDString]]];
            [entitlementsByPath[path] writeToURL:entURL atomically:YES encoding:NSUTF8StringEncoding error:nil];
            [self runTask:@"/usr/bin/codesign" args:@[@"--force", @"--sign", identity,
                @"--keychain", keychainURL.path, @"--entitlements", entURL.path,
                @"--generate-entitlement-der", bundlePath]];
            NSLog(@"[Signer] Signed nested: %@", [bundlePath lastPathComponent]);
        }
    }

    // 5b: 签名 Frameworks 中所有 dylib/framework（不区分 Apple/非 Apple）
    NSURL *frameworksURL = [appURL URLByAppendingPathComponent:@"Frameworks"];
    if ([fm fileExistsAtPath:frameworksURL.path]) {
        // 从内到外：先签 framework 内部的子 framework
        for (NSURL *fwURL in [fm contentsOfDirectoryAtURL:frameworksURL
                                includingPropertiesForKeys:nil options:0 error:nil]) {
            NSString *ext = fwURL.pathExtension;
            if ([ext isEqualToString:@"framework"]) {
                // 检查 framework 内部是否有子 Frameworks
                NSURL *subFW = [fwURL URLByAppendingPathComponent:@"Frameworks"];
                if ([fm fileExistsAtPath:subFW.path]) {
                    for (NSURL *subURL in [fm contentsOfDirectoryAtURL:subFW
                                            includingPropertiesForKeys:nil options:0 error:nil]) {
                        [self runTask:@"/usr/bin/codesign" args:@[@"--force", @"--sign", identity,
                            @"--keychain", keychainURL.path, @"--generate-entitlement-der", subURL.path]];
                        NSLog(@"[Signer] Signed sub-framework: %@", [subURL lastPathComponent]);
                    }
                }
                [self runTask:@"/usr/bin/codesign" args:@[@"--force", @"--sign", identity,
                    @"--keychain", keychainURL.path, @"--generate-entitlement-der", fwURL.path]];
                NSLog(@"[Signer] Signed framework: %@", [fwURL lastPathComponent]);
            } else if ([ext isEqualToString:@"dylib"]) {
                [self runTask:@"/usr/bin/codesign" args:@[@"--force", @"--sign", identity,
                    @"--keychain", keychainURL.path, fwURL.path]];
                NSLog(@"[Signer] Signed dylib: %@", [fwURL lastPathComponent]);
            }
        }
    }

    // 5c: 签名主 app bundle
    NSString *mainPath = appURL.path;
    NSURL *mainEntURL = [tempDir URLByAppendingPathComponent:@"ent_main.plist"];
    // 用第一个 entitlements（主 app 的）
    NSString *mainEnt = entitlementsByPath.allValues.firstObject;
    [mainEnt writeToURL:mainEntURL atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [self runTask:@"/usr/bin/codesign" args:@[@"--force", @"--sign", identity,
        @"--keychain", keychainURL.path, @"--entitlements", mainEntURL.path,
        @"--generate-entitlement-der", mainPath]];

    NSLog(@"[Signer] Signed app bundle");

    // 清理 keychain
    [self runTask:@"/usr/bin/security" args:@[@"delete-keychain", keychainURL.path]];

    // Step 6: 重新打包
    NSLog(@"[Signer] Repacking IPA...");
    [fm removeItemAtURL:outputURL error:nil];

    NSTask *zipTask = [[NSTask alloc] init];
    zipTask.launchPath = @"/usr/bin/zip";
    zipTask.arguments = @[@"-rq", outputURL.path, @"Payload"];
    zipTask.currentDirectoryURL = tempDir;
    [zipTask launch];
    [zipTask waitUntilExit];

    [fm removeItemAtURL:tempDir error:nil];

    if (zipTask.terminationStatus == 0) {
        NSLog(@"[Signer] Successfully signed IPA: %@", outputURL.path);
        completion(YES, nil);
    } else {
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-4
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to repack IPA"}]);
    }
}

#pragma mark - Helpers

- (BOOL)isAppleCode:(NSURL *)url {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/codesign";
    task.arguments = @[@"-dvvv", url.path];
    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;
    [task launch];
    [task waitUntilExit];
    NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
    NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    // Apple 签名的 Authority 包含 "Apple Root CA"
    return [output containsString:@"Authority=Apple Root CA"];
}

- (NSString *)findSigningIdentity:(NSURL *)keychainURL {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/security";
    task.arguments = @[@"find-identity", @"-v", @"-p", @"codesigning", keychainURL.path];
    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    [task launch];
    [task waitUntilExit];
    NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
    NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

    NSRegularExpression *regex = [NSRegularExpression
        regularExpressionWithPattern:@"([A-F0-9]{40})" options:0 error:nil];
    NSTextCheckingResult *match = [regex firstMatchInString:output options:0
        range:NSMakeRange(0, output.length)];
    return match ? [output substringWithRange:[match rangeAtIndex:1]] : nil;
}

- (int)runTask:(NSString *)launchPath args:(NSArray *)args {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = launchPath;
    task.arguments = args;
    [task launch];
    [task waitUntilExit];
    return task.terminationStatus;
}

#pragma mark - Prepare App

- (void)prepareAppAtURL:(NSURL *)appURL
   provisioningProfiles:(NSArray<ALTProvisioningProfile *> *)profiles
    entitlementsByPath:(NSMutableDictionary *)entitlementsByPath
{
    NSURL *infoPlistURL = [appURL URLByAppendingPathComponent:@"Info.plist"];
    NSMutableDictionary *infoPlist = [[NSDictionary dictionaryWithContentsOfURL:infoPlistURL] mutableCopy];
    NSString *originalBundleID = infoPlist[@"CFBundleIdentifier"] ?: @"";
    NSString *bundleID = originalBundleID;

    if (self.bundleIDOverride) {
        bundleID = self.bundleIDOverride;
        infoPlist[@"CFBundleIdentifier"] = bundleID;
        [infoPlist writeToURL:infoPlistURL atomically:YES];
        NSLog(@"[Signer] Overrode bundle ID: %@ → %@", originalBundleID, bundleID);
    }

    NSString *executable = infoPlist[@"CFBundleExecutable"] ?: @"";

    ALTProvisioningProfile *matchedProfile = nil;
    for (ALTProvisioningProfile *profile in profiles) {
        if ([profile.bundleIdentifier isEqualToString:bundleID]) {
            matchedProfile = profile;
            break;
        }
    }
    if (!matchedProfile && profiles.count > 0) {
        for (ALTProvisioningProfile *profile in profiles) {
            if ([profile.bundleIdentifier hasSuffix:@"*"]) {
                matchedProfile = profile;
                break;
            }
        }
    }
    if (!matchedProfile) {
        NSLog(@"[Signer] Warning: No profile found for %@", bundleID);
        return;
    }

    NSURL *profileURL = [appURL URLByAppendingPathComponent:@"embedded.mobileprovision"];
    [matchedProfile.data writeToURL:profileURL atomically:YES];

    NSDictionary *entitlements = matchedProfile.entitlements;
    if (!entitlements && matchedProfile.data) {
        NSString *profileStr = [[NSString alloc] initWithData:matchedProfile.data
                                                     encoding:NSASCIIStringEncoding];
        NSRange plistStart = [profileStr rangeOfString:@"<?xml"];
        NSRange plistEnd = [profileStr rangeOfString:@"</plist>"];
        if (plistStart.location != NSNotFound && plistEnd.location != NSNotFound) {
            NSRange range = NSMakeRange(plistStart.location,
                plistEnd.location + plistEnd.length - plistStart.location);
            NSDictionary *plist = [NSPropertyListSerialization
                propertyListWithData:[[profileStr substringWithRange:range]
                                    dataUsingEncoding:NSUTF8StringEncoding]
                options:0 format:nil error:nil];
            entitlements = plist[@"Entitlements"];
        }
    }

    if (entitlements) {
        NSData *entData = [NSPropertyListSerialization
            dataWithPropertyList:entitlements format:NSPropertyListXMLFormat_v1_0
                        options:0 error:nil];
        NSString *entString = [[NSString alloc] initWithData:entData encoding:NSUTF8StringEncoding];
        NSURL *binaryURL = [appURL URLByAppendingPathComponent:executable];
        entitlementsByPath[binaryURL.path] = entString;
    } else {
        NSLog(@"[Signer] Warning: No entitlements found for %@", bundleID);
    }
}

@end
