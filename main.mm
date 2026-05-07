//
//  main.mm
//  AltSign CLI
//
//  macOS 命令行自签名工具
//  Usage:
//    altsign-cli sign   --apple-id <email> --password <pwd> --udid <udid> --ipa <path> [--output <path>]
//    altsign-cli cert   --apple-id <email> --password <pwd>
//
//  如需 2FA，会自动提示输入验证码（stdin），无需额外参数。

#import <Foundation/Foundation.h>
#import "anisette.h"
#import "srp_auth.h"
#import "apple_api.h"
#import "certificate_request.h"
#import "signer.h"

// ============================================================
// 辅助函数
// ============================================================

static NSURL * _Nullable keysDirectory(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *supportDir = [fm URLsForDirectory:NSApplicationSupportDirectory
                                   inDomains:NSUserDomainMask].firstObject;
    NSURL *dir = [supportDir URLByAppendingPathComponent:@"altsign/keys"];
    [fm createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

static void saveCertKey(NSString *certID, NSData *privateKey) {
    NSURL *dir = keysDirectory();
    if (!dir || !privateKey) return;
    NSString *filename = [NSString stringWithFormat:@"%@.pem", certID];
    [privateKey writeToURL:[dir URLByAppendingPathComponent:filename] atomically:YES];
}

static NSData * _Nullable loadCertKey(NSString *certID) {
    NSURL *dir = keysDirectory();
    if (!dir) return nil;
    NSString *filename = [NSString stringWithFormat:@"%@.pem", certID];
    return [NSData dataWithContentsOfURL:[dir URLByAppendingPathComponent:filename]];
}

// ============================================================
// Capability 名称 → Feature ID 映射
// ============================================================

static NSDictionary<NSString *, NSString *> *capabilityFeatureMap(void) {
    return @{
        @"app-groups":         @"APG3427HIY",
        @"healthkit":          @"HK421J6T7P",
        @"push":               @"IAD53UNK2F",
        @"sign-in-with-apple": @"LPLF93JG7M",
        @"associated-domains": @"SKC3T5S89Y",
        @"vpn":                @"V66P55NK2I",
        @"external-accessory": @"WC421J6T7P",
        @"gamecenter":         @"gameCenter",
    };
}

static void printCapabilities(void) {
    fprintf(stderr,
        "可用的 --entitlement 名称:\n"
        "  app-groups           应用组 (com.apple.security.application-groups)\n"
        "  healthkit            HealthKit\n"
        "  push                 远程推送\n"
        "  sign-in-with-apple   Apple 登录\n"
        "  associated-domains   关联域名\n"
        "  external-accessory   无线配件配置\n"
        "  gamecenter           游戏中心\n"
        "\n"
        "需要付费开发者账号 ($99/年):\n"
        "  vpn                  网络扩展 / VPN (Network Extension)\n"
        "\n"
    );
}

static void printUsage(void) {
    fprintf(stderr,
        "AltSign CLI — macOS IPA 自签名工具\n"
        "\n"
        "用法:\n"
        "  altsign-cli sign   --apple-id <email> --password <pwd> --udid <udid> --ipa <file> [--output <file>] [--entitlement <list>]\n"
        "  altsign-cli list   --apple-id <email> --password <pwd>\n"
        "\n"
        "命令:\n"
        "  sign   完整签名流程: 登录 → 拉证书 → 注册设备 → 创建PP → 重签IPA\n"
        "  list   登录后拉取开发证书 + App ID 列表（只读）\n"
        "\n"
        "选项:\n"
        "  --apple-id      Apple ID 邮箱\n"
        "  --password      Apple ID 密码\n"
        "  --udid          iOS 设备 UDID\n"
        "  --ipa           待签名的 IPA 文件路径\n"
        "  --output        输出签名后的 IPA 路径 (默认在原文件名加 _signed)\n"
        "  --entitlement   启用的 capabilities，逗号分隔 (如 healthkit,app-groups)\n"
        "  --verbose       打印完整日志（默认截断大响应）\n"
        "\n"
    );
    printCapabilities();
}

static NSString * _Nullable getArg(NSArray *args, NSString *flag) {
    NSUInteger idx = NSNotFound;
    for (NSUInteger i = 0; i < args.count; i++) {
        if ([args[i] isEqualToString:flag]) {
            idx = i;
        }
    }
    if (idx != NSNotFound && idx + 1 < args.count) {
        return args[idx + 1];
    }
    return nil;
}

static NSArray<NSString *> * _Nullable extractBundleIDsFromIPA(NSString *ipaPath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *tempDir = [fm.temporaryDirectory URLByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    [fm createDirectoryAtURL:tempDir withIntermediateDirectories:YES attributes:nil error:nil];

    NSTask *unzipTask = [[NSTask alloc] init];
    unzipTask.launchPath = @"/usr/bin/ditto";
    unzipTask.arguments = @[@"-xk", ipaPath, tempDir.path];
    [unzipTask launch];
    [unzipTask waitUntilExit];

    if (unzipTask.terminationStatus != 0) {
        [fm removeItemAtURL:tempDir error:nil];
        return nil;
    }

    NSURL *payloadDir = [tempDir URLByAppendingPathComponent:@"Payload"];
    NSMutableArray<NSString *> *bundleIDs = [NSMutableArray array];

    void (^collectBundleIDs)(NSURL *) = ^(NSURL *dir) {
        NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:dir
                                     includingPropertiesForKeys:nil
                                                        options:NSDirectoryEnumerationSkipsHiddenFiles
                                                   errorHandler:nil];
        for (NSURL *url in enumerator) {
            NSString *ext = url.pathExtension;
            // xctest 的 Bundle ID 会被覆盖成主 app 的，不需要单独提取；appex 保持自己的
            if ([ext isEqualToString:@"app"] || [ext isEqualToString:@"appex"]) {
                NSURL *infoPlistURL = [url URLByAppendingPathComponent:@"Info.plist"];
                NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfURL:infoPlistURL];
                NSString *bundleID = infoPlist[@"CFBundleIdentifier"];
                if (bundleID && bundleID.length > 0) {
                    [bundleIDs addObject:bundleID];
                }
            }
        }
    };
    collectBundleIDs(payloadDir);

    [fm removeItemAtURL:tempDir error:nil];
    return bundleIDs.count > 0 ? bundleIDs : nil;
}

// ============================================================
// 认证（含 session 复用 + 2FA）
// ============================================================

static void authenticateWithAppleID(NSString *appleID, NSString *password,
                                    void (^completion)(ALTAccount * _Nullable, ALTAppleAPISession * _Nullable, NSError * _Nullable))
{
    [ALTAnisetteData fetchAnisetteDataWithCompletion:^(ALTAnisetteData *anisetteData, NSError *error) {
        if (error || !anisetteData) {
            completion(nil, nil, error ?: [NSError errorWithDomain:@"com.altsign" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Failed to fetch Anisette data"}]);
            return;
        }

        ALTAppleAPISession *cachedSession = [ALTAppleAPISession loadSessionForAppleID:appleID];
        if (cachedSession && !cachedSession.isExpired) {
            NSLog(@"[Auth] Reusing cached session (expires: %@)", cachedSession.expirationDate);
            cachedSession.anisetteData = anisetteData;
            ALTAccount *account = [[ALTAccount alloc] init];
            account.appleID = appleID;
            account.identifier = cachedSession.dsid;
            completion(account, cachedSession, nil);
            return;
        }

        NSLog(@"[Auth] Cached session missing or expired, performing SRP login...");

        ALTVerificationHandler verificationHandler = ^(void (^callback)(NSString * _Nullable code)) {
            fprintf(stdout, "\n2FA verification required. Enter code: ");
            fflush(stdout);
            char buf[32];
            if (fgets(buf, sizeof(buf), stdin)) {
                NSString *code = [[NSString alloc] initWithUTF8String:buf];
                code = [code stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                callback(code);
            } else {
                callback(nil);
            }
        };

        [ALTSRPAuthenticator authenticateWithAppleID:appleID
                                            password:password
                                        anisetteData:anisetteData
                                   verificationHandler:verificationHandler
                                   completionHandler:completion];
    }];
}

// ============================================================
// 核心流程
// ============================================================

static void performSign(NSString *appleID, NSString *password,
                        NSString *udid, NSString *ipaPath, NSString *outputPath,
                        NSArray<NSString *> *entitlementNames)
{
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    NSLog(@"========================================");
    NSLog(@" AltSign CLI — IPA 自签名工具");
    NSLog(@"========================================");
    NSLog(@" Apple ID:  %@", appleID);
    NSLog(@" UDID:      %@", udid);
    NSLog(@" IPA:       %@", ipaPath);
    NSLog(@" Output:    %@", outputPath);
    NSLog(@"========================================");

    authenticateWithAppleID(appleID, password, ^(ALTAccount *account, ALTAppleAPISession *session, NSError *error) {
        if (error || !session) {
            NSLog(@"[Error] Authentication failed: %@", error);
            dispatch_semaphore_signal(sem);
            return;
        }
        NSLog(@"[Step 1] Login successful! DSID: %@", account.identifier);

        ALTAppleAPI *api = [ALTAppleAPI sharedAPI];

        // Step 2: 获取团队
        NSLog(@"[Step 2] Fetching teams...");
        [api fetchTeamsForAccount:account session:session completionHandler:^(NSArray<ALTTeam *> *teams, NSError *error) {
            if (error || teams.count == 0) {
                NSLog(@"[Error] No teams found: %@", error);
                dispatch_semaphore_signal(sem);
                return;
            }

            ALTTeam *team = teams.firstObject;
            NSLog(@"[Step 2] Using team: %@ (%@) type=%@", team.name, team.identifier, team.type);

            // Step 3: 获取证书
            NSLog(@"[Step 3] Fetching certificates...");
            [api fetchCertificatesForTeam:team session:session completionHandler:^(NSArray<ALTCertificate *> *certs, NSError *error) {

                void (^continueWithCert)(ALTCertificate *) = ^(ALTCertificate *cert) {
                    // Step 4: 注册设备
                    NSLog(@"[Step 4] Registering device: %@", udid);
                    [api registerDeviceWithName:@"AltSign Device" identifier:udid team:team session:session completionHandler:^(ALTDevice *device, NSError *error) {
                        NSLog(@"[Step 4] Device registered or already exists");

                        // Step 5: 提取 IPA 中所有需要签名的 bundle ID
                        NSArray<NSString *> *bundleIDs = extractBundleIDsFromIPA(ipaPath);
                        if (!bundleIDs || bundleIDs.count == 0) {
                            NSLog(@"[Error] Failed to read bundle IDs from IPA");
                            dispatch_semaphore_signal(sem);
                            return;
                        }
                        NSLog(@"[Step 5] Bundle IDs to resolve: %@", [bundleIDs componentsJoinedByString:@", "]);

                        // Step 6: 获取已有 App ID 列表，然后串行创建缺失的 App ID 并下载 Profile
                        [api fetchAppIDsForTeam:team session:session completionHandler:^(NSArray<ALTAppID *> *appIDs, NSError *error) {
                            if (error) {
                                NSLog(@"[Error] fetchAppIDs failed: %@", error);
                                dispatch_semaphore_signal(sem);
                                return;
                            }

                            NSMutableArray<ALTProvisioningProfile *> *profiles = [NSMutableArray array];
                            dispatch_queue_t serialQueue = dispatch_queue_create("com.altsign.profile", DISPATCH_QUEUE_SERIAL);

                            void (^finishWithError)(NSString *) = ^(NSString *reason) {
                                NSLog(@"[Error] %@", reason);
                                dispatch_semaphore_signal(sem);
                            };

                            void (^startSigning)(void) = ^{
                                NSLog(@"[Step 7] Signing IPA...");
                                ALTSigner *signer = [[ALTSigner alloc] initWithCertificate:cert];
                                [signer signIPAAtURL:[NSURL fileURLWithPath:ipaPath]
                                    provisioningProfiles:profiles
                                               outputURL:[NSURL fileURLWithPath:outputPath]
                                       completionHandler:^(BOOL success, NSError *error) {
                                    if (success) {
                                        NSLog(@"✅ [Done] IPA signed successfully!");
                                        NSLog(@"   Output: %@", outputPath);
                                    } else {
                                        NSLog(@"❌ [Error] Signing failed: %@", error);
                                    }
                                    dispatch_semaphore_signal(sem);
                                }];
                            };

                            // 串行处理每个 Bundle ID 的 App ID + Profile（避免主线程死锁）
                            NSMutableArray<NSString *> *remainingBundleIDs = [bundleIDs mutableCopy];
                            __block void (^processNext)(void) = nil;
                            processNext = ^{
                                if (remainingBundleIDs.count == 0) {
                                    if (profiles.count != bundleIDs.count) {
                                        finishWithError(@"Failed to resolve all provisioning profiles");
                                    } else {
                                        startSigning();
                                    }
                                    processNext = nil; // 打破 retain cycle
                                    return;
                                }

                                NSString *bundleID = remainingBundleIDs.firstObject;
                                [remainingBundleIDs removeObjectAtIndex:0];

                                ALTAppID *appID = nil;
                                for (ALTAppID *aid in appIDs) {
                                    if ([aid.bundleIdentifier isEqualToString:bundleID]) { appID = aid; break; }
                                }

                                void (^afterAppID)(ALTAppID *) = ^(ALTAppID *resolvedAppID) {
                                    // 如果指定了 --entitlement，先启用对应的 capabilities
                                    void (^fetchProfile)(ALTAppID *) = ^(ALTAppID *finalAppID) {
                                        [api fetchProvisioningProfileForAppID:finalAppID team:team session:session completionHandler:^(ALTProvisioningProfile *profile, NSError *error) {
                                            if (error || !profile) {
                                                finishWithError([NSString stringWithFormat:@"Failed to fetch profile for %@: %@", bundleID, error]);
                                                processNext = nil;
                                                return;
                                            }
                                            NSLog(@"[Step 6] Profile acquired for %@: %@ (expires: %@)", bundleID, profile.identifier, profile.expirationDate);
                                            [profiles addObject:profile];
                                            dispatch_async(serialQueue, processNext);
                                        }];
                                    };

                                    if (entitlementNames.count > 0) {
                                        // 构建 features 字典
                                        NSDictionary *map = capabilityFeatureMap();
                                        NSMutableDictionary *features = [NSMutableDictionary dictionary];
                                        for (NSString *name in entitlementNames) {
                                            NSString *featureID = map[name.lowercaseString];
                                            if (featureID) {
                                                features[featureID] = @"1";
                                            }
                                        }
                                        if (features.count > 0) {
                                            NSLog(@"[Step 5] Enabling capabilities: %@", entitlementNames);
                                            [api updateAppID:resolvedAppID features:features team:team session:session completionHandler:^(ALTAppID *updated, NSError *error) {
                                                if (error) {
                                                    NSLog(@"[Warning] Failed to enable capabilities: %@", error.localizedDescription);
                                                }
                                                fetchProfile(updated ?: resolvedAppID);
                                            }];
                                        } else {
                                            fetchProfile(resolvedAppID);
                                        }
                                    } else {
                                        fetchProfile(resolvedAppID);
                                    }
                                };

                                if (appID) {
                                    NSLog(@"[Step 5] Reusing existing App ID: %@", appID.bundleIdentifier);
                                    afterAppID(appID);
                                } else {
                                    NSLog(@"[Step 5] Creating App ID: %@", bundleID);
                                    [api addAppIDWithName:@"AltSign App" bundleIdentifier:bundleID team:team session:session completionHandler:^(ALTAppID *newAppID, NSError *error) {
                                        if (error || !newAppID) {
                                            finishWithError([NSString stringWithFormat:@"Failed to create App ID %@: %@", bundleID, error]);
                                            processNext = nil;
                                            return;
                                        }
                                        afterAppID(newAppID);
                                    }];
                                }
                            };

                            dispatch_async(serialQueue, processNext);
                        }];
                    }];
                };

                // 证书处理：尝试加载已有证书的私钥，无私钥则撤销重建
                void (^createNewCert)(void) = ^{
                    NSLog(@"[Step 3] Creating new certificate...");
                    ALTCertificateRequest *certReq = [[ALTCertificateRequest alloc] init];
                    if (!certReq) {
                        NSLog(@"[Error] Failed to generate certificate request");
                        dispatch_semaphore_signal(sem);
                        return;
                    }
                    [api submitCertificateRequest:certReq.data team:team session:session completionHandler:^(ALTCertificate *cert, NSError *error) {
                        if (error || !cert) {
                            NSLog(@"[Error] Failed to create certificate: %@", error);
                            dispatch_semaphore_signal(sem);
                            return;
                        }
                        cert.privateKey = certReq.privateKey;
                        saveCertKey(cert.identifier, cert.privateKey);
                        NSLog(@"[Step 3] Certificate created: %@", cert.identifier);
                        continueWithCert(cert);
                    }];
                };

                if (certs.count > 0) {
                    ALTCertificate *cert = certs.firstObject;
                    NSLog(@"[Step 3] Found existing certificate: %@", cert.identifier);
                    NSData *savedKey = loadCertKey(cert.identifier);
                    if (savedKey) {
                        cert.privateKey = savedKey;
                        NSLog(@"[Step 3] Loaded saved private key");
                        continueWithCert(cert);
                    } else {
                        NSLog(@"[Step 3] No saved private key, revoking and recreating...");
                        [api revokeCertificate:cert team:team session:session completionHandler:^(BOOL ok, NSError *revokeErr) {
                            if (!ok) {
                                NSLog(@"[Warning] Revoke failed: %@, attempting create anyway...", revokeErr);
                            }
                            createNewCert();
                        }];
                    }
                } else {
                    createNewCert();
                }
            }];
        }];
    });

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
}

static void performList(NSString *appleID, NSString *password)
{
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    authenticateWithAppleID(appleID, password, ^(ALTAccount *account, ALTAppleAPISession *session, NSError *error) {
        if (error || !session) {
            NSLog(@"[Error] Authentication failed: %@", error);
            dispatch_semaphore_signal(sem);
            return;
        }
        NSLog(@"✅ Login successful! DSID: %@", account.identifier);

        ALTAppleAPI *api = [ALTAppleAPI sharedAPI];
        [api fetchTeamsForAccount:account session:session
                completionHandler:^(NSArray<ALTTeam *> *teams, NSError *error) {
            if (teams.count == 0) {
                NSLog(@"No teams found");
                dispatch_semaphore_signal(sem);
                return;
            }
            ALTTeam *team = teams.firstObject;
            NSLog(@"Team: %@ (%@)", team.name, team.identifier);

            [api fetchCertificatesForTeam:team session:session
                completionHandler:^(NSArray<ALTCertificate *> *certs, NSError *error) {
                if (certs.count > 0) {
                    NSLog(@"");
                    NSLog(@"📜 Certificates (%lu):", (unsigned long)certs.count);
                    for (ALTCertificate *cert in certs) {
                        NSLog(@"   %@ (%@)", cert.name, cert.identifier);
                    }
                } else {
                    NSLog(@"📜 No certificates found.");
                }

                [api fetchAppIDsForTeam:team session:session
                    completionHandler:^(NSArray<ALTAppID *> *appIDs, NSError *error) {
                    if (appIDs.count > 0) {
                        NSLog(@"");
                        NSLog(@"📦 App IDs (%lu):", (unsigned long)appIDs.count);
                        for (ALTAppID *appID in appIDs) {
                            NSLog(@"   %@ (%@) name=%@", appID.bundleIdentifier, appID.identifier, appID.name);
                        }
                    } else {
                        NSLog(@"📦 No App IDs found.");
                    }
                    dispatch_semaphore_signal(sem);
                }];
            }];
        }];
    });

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
}

// ============================================================
// main
// ============================================================

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSArray *args = [[NSProcessInfo processInfo] arguments];

        if (args.count < 2) {
            printUsage();
            return 1;
        }

        NSString *command = args[1];
        NSString *appleID = getArg(args, @"--apple-id");
        NSString *password = getArg(args, @"--password");
        NSString *udid = getArg(args, @"--udid");
        NSString *ipaPath = getArg(args, @"--ipa");
        NSString *outputPath = getArg(args, @"--output");
        NSString *entitlementArg = getArg(args, @"--entitlement");
        ALTVerboseLogging = (getArg(args, @"--verbose") != nil);

        NSArray<NSString *> *entitlementNames = @[];
        if (entitlementArg.length > 0) {
            NSMutableArray *names = [NSMutableArray array];
            for (NSString *part in [entitlementArg componentsSeparatedByString:@","]) {
                NSString *trimmed = [part stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                if (trimmed.length > 0) {
                    NSString *lower = trimmed.lowercaseString;
                    if (capabilityFeatureMap()[lower]) {
                        [names addObject:lower];
                    } else {
                        fprintf(stderr, "Warning: unknown entitlement '%s', skipping\n", trimmed.UTF8String);
                    }
                }
            }
            entitlementNames = names;
        }

        // 如果没提供 apple-id/password，尝试从已存 session 获取
        if (!appleID || !password) {
            NSString *storedAppleID = nil;
            ALTAppleAPISession *existing = [ALTAppleAPISession loadAnySession:&storedAppleID];
            if (existing && !existing.isExpired) {
                if (!appleID) appleID = storedAppleID;
                NSLog(@"[Auth] Using cached session for %@ (no credentials needed)", appleID);
            } else if (!appleID || !password) {
                fprintf(stderr, "Error: No cached session found. --apple-id and --password are required for first-time login.\n\n");
                printUsage();
                return 1;
            }
        }

        if ([command isEqualToString:@"sign"]) {
            if (!udid || !ipaPath) {
                fprintf(stderr, "Error: --udid and --ipa are required for sign command\n\n");
                printUsage();
                return 1;
            }
            if (!outputPath) {
                NSString *base = [ipaPath stringByDeletingPathExtension];
                outputPath = [base stringByAppendingString:@"_signed.ipa"];
            }
            performSign(appleID, password, udid, ipaPath, outputPath, entitlementNames);

        } else if ([command isEqualToString:@"list"]) {
            performList(appleID, password);

        } else {
            fprintf(stderr, "Unknown command: %s\n\n", command.UTF8String);
            printUsage();
            return 1;
        }

        return 0;
    }
}
