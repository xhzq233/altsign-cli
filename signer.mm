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
        [fm removeItemAtURL:tempDir error:nil];
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
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-2
                                       userInfo:@{NSLocalizedDescriptionKey: @"No .app found in IPA"}]);
        return;
    }
    NSLog(@"[Signer] Found app bundle: %@", appURL.lastPathComponent);

    // Step 2: 读取主 app 的 Bundle ID 作为 default
    NSDictionary *mainInfo = [NSDictionary dictionaryWithContentsOfURL:[appURL URLByAppendingPathComponent:@"Info.plist"]];
    NSString *defaultBundleID = mainInfo[@"CFBundleIdentifier"];
    if (!defaultBundleID || defaultBundleID.length == 0) {
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-10
                                       userInfo:@{NSLocalizedDescriptionKey: @"Main app missing CFBundleIdentifier"}]);
        return;
    }

    // 嵌入 Provisioning Profile + 提取 Entitlements
    NSMutableDictionary<NSString *, NSString *> *entitlementsByPath = [NSMutableDictionary dictionary];

    if (![self prepareAppAtURL:appURL provisioningProfiles:profiles entitlementsByPath:entitlementsByPath defaultBundleID:defaultBundleID]) {
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-10
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to prepare app bundle"}]);
        return;
    }

    if (entitlementsByPath.count == 0) {
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-5
                                       userInfo:@{NSLocalizedDescriptionKey: @"No entitlements extracted"}]);
        return;
    }

    // Step 3: 生成 P12
    NSData *p12Data = [self.certificate p12Data];
    if (!p12Data) {
        [fm removeItemAtURL:tempDir error:nil];
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
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-6
                                       userInfo:@{NSLocalizedDescriptionKey: @"No signing identity found"}]);
        return;
    }
    NSLog(@"[Signer] Identity: %@", identity);

    // Step 5: 从内到外签名
    NSLog(@"[Signer] Signing binaries...");

    // 递归收集 .app 内所有 .framework / .dylib，按路径深度降序（最深的先签）
    NSMutableArray<NSString *> *signablePaths = [NSMutableArray array];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:appURL
                                  includingPropertiesForKeys:nil
                                                     options:NSDirectoryEnumerationSkipsHiddenFiles
                                                errorHandler:nil];
    for (NSURL *url in enumerator) {
        NSString *ext = url.pathExtension;
        if ([ext isEqualToString:@"framework"] || [ext isEqualToString:@"dylib"]) {
            [signablePaths addObject:url.path];
        }
    }
    [signablePaths sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        NSUInteger da = [a componentsSeparatedByString:@"/"].count;
        NSUInteger db = [b componentsSeparatedByString:@"/"].count;
        return (da > db) ? NSOrderedAscending : ((da < db) ? NSOrderedDescending : NSOrderedSame);
    }];

    for (NSString *itemPath in signablePaths) {
        int status = [self runTask:@"/usr/bin/codesign" args:@[@"--force", @"--sign", identity,
            @"--keychain", keychainURL.path, @"--generate-entitlement-der", itemPath]];
        if (status != 0) {
            NSLog(@"[Signer] Failed to sign: %@ (exit %d)", [itemPath lastPathComponent], status);
            [self runTask:@"/usr/bin/security" args:@[@"delete-keychain", keychainURL.path]];
            [fm removeItemAtURL:tempDir error:nil];
            completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-7
                                           userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"Failed to sign: %@", itemPath.lastPathComponent]}]);
            return;
        }
        NSLog(@"[Signer] Signed: %@", [itemPath lastPathComponent]);
    }

    // 签名 PlugIns 中的 .appex/.xctest bundle（按路径深度降序，内层先签）
    NSMutableArray<NSString *> *extBinaryPaths = [NSMutableArray array];
    for (NSString *path in entitlementsByPath) {
        NSString *bundlePath = [path stringByDeletingLastPathComponent];
        if ([bundlePath hasSuffix:@".appex"] || [bundlePath hasSuffix:@".xctest"]) {
            [extBinaryPaths addObject:path];
        }
    }
    [extBinaryPaths sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        NSUInteger da = [a componentsSeparatedByString:@"/"].count;
        NSUInteger db = [b componentsSeparatedByString:@"/"].count;
        return (da > db) ? NSOrderedAscending : ((da < db) ? NSOrderedDescending : NSOrderedSame);
    }];

    for (NSString *path in extBinaryPaths) {
        NSString *bundlePath = [path stringByDeletingLastPathComponent];
        NSURL *entURL = [tempDir URLByAppendingPathComponent:
            [NSString stringWithFormat:@"ent_%@.plist", [[NSUUID UUID] UUIDString]]];
        [entitlementsByPath[path] writeToURL:entURL atomically:YES encoding:NSUTF8StringEncoding error:nil];
        int status = [self runTask:@"/usr/bin/codesign" args:@[@"--force", @"--sign", identity,
            @"--keychain", keychainURL.path, @"--entitlements", entURL.path,
            @"--generate-entitlement-der", bundlePath]];
        if (status != 0) {
            NSLog(@"[Signer] Failed to sign extension: %@ (exit %d)", [bundlePath lastPathComponent], status);
            [self runTask:@"/usr/bin/security" args:@[@"delete-keychain", keychainURL.path]];
            [fm removeItemAtURL:tempDir error:nil];
            completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-8
                                           userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"Failed to sign extension: %@", bundlePath.lastPathComponent]}]);
            return;
        }
        NSLog(@"[Signer] Signed nested: %@", [bundlePath lastPathComponent]);
    }

    // 签名主 app bundle — 从 entitlementsByPath 中找到主 app 二进制对应的 entitlements
    NSString *mainPath = appURL.path;
    NSString *mainExe = mainInfo[@"CFBundleExecutable"] ?: @"";
    NSString *mainEnt = entitlementsByPath[[mainPath stringByAppendingPathComponent:mainExe]];
    if (!mainEnt) {
        // fallback: 单一 profile 场景（CLI 默认流程），取唯一条目
        mainEnt = entitlementsByPath.allValues.firstObject;
    }
    NSURL *mainEntURL = [tempDir URLByAppendingPathComponent:@"ent_main.plist"];
    [mainEnt writeToURL:mainEntURL atomically:YES encoding:NSUTF8StringEncoding error:nil];
    int status = [self runTask:@"/usr/bin/codesign" args:@[@"--force", @"--sign", identity,
        @"--keychain", keychainURL.path, @"--entitlements", mainEntURL.path,
        @"--generate-entitlement-der", mainPath]];
    if (status != 0) {
        NSLog(@"[Signer] Failed to sign main app bundle (exit %d)", status);
        [self runTask:@"/usr/bin/security" args:@[@"delete-keychain", keychainURL.path]];
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-9
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to sign main app bundle"}]);
        return;
    }
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

- (NSString *)findSigningIdentity:(NSURL *)keychainURL {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/security";
    task.arguments = @[@"find-identity", @"-v", @"-p", @"codesigning", keychainURL.path];
    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    [task launch];
    NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
    [task waitUntilExit];
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

- (BOOL)prepareAppAtURL:(NSURL *)appURL
   provisioningProfiles:(NSArray<ALTProvisioningProfile *> *)profiles
    entitlementsByPath:(NSMutableDictionary *)entitlementsByPath
         defaultBundleID:(NSString *)defaultBundleID
{
    NSURL *infoPlistURL = [appURL URLByAppendingPathComponent:@"Info.plist"];
    NSMutableDictionary *infoPlist = [[NSDictionary dictionaryWithContentsOfURL:infoPlistURL] mutableCopy];
    NSString *originalBundleID = infoPlist[@"CFBundleIdentifier"];
    if (!originalBundleID || originalBundleID.length == 0) {
        NSLog(@"[Signer] Error: Missing CFBundleIdentifier in %@", appURL.lastPathComponent);
        return NO;
    }

    NSString *bundleID = originalBundleID;
    // xctest 的 Bundle ID 必须和主 app 一致；appex 保持自己的
    if ([appURL.pathExtension isEqualToString:@"xctest"]) {
        bundleID = defaultBundleID;
        infoPlist[@"CFBundleIdentifier"] = bundleID;
        [infoPlist writeToURL:infoPlistURL atomically:YES];
        NSLog(@"[Signer] Overrode xctest bundle ID: %@ → %@", originalBundleID, bundleID);
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
        NSLog(@"[Signer] Error: No profile found for %@", bundleID);
        return NO;
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

    NSURL *nestedPlugInsURL = [appURL URLByAppendingPathComponent:@"PlugIns"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:nestedPlugInsURL.path]) {
        for (NSURL *extURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:nestedPlugInsURL
                                includingPropertiesForKeys:nil options:0 error:nil]) {
            if ([extURL.pathExtension isEqualToString:@"appex"] ||
                [extURL.pathExtension isEqualToString:@"xctest"]) {
                if (![self prepareAppAtURL:extURL provisioningProfiles:profiles entitlementsByPath:entitlementsByPath defaultBundleID:defaultBundleID]) {
                    return NO;
                }
            }
        }
    }
    return YES;
}

@end
