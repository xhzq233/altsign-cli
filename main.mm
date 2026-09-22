//
//  main.mm
//  AltSign CLI
//
//  macOS 命令行自签名工具
//  Usage:
//    altsign-cli list   --apple-id <email>
//    altsign-cli sign   --udid <udid> --ipa <path.ipa|path.app> [--output <path.ipa>]
//    altsign-cli sign   --udid <udid> --app <path.app> [--output <path.ipa>]
//
//  首次认证的密码与 2FA 都从标准输入读取。

#import "diagnostics.h"
#import <Foundation/Foundation.h>
#import "anisette.h"
#import "srp_auth.h"
#import "apple_api.h"
#import "certificate_request.h"
#import "signer.h"

#include <readpassphrase.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
        "Capabilities (--entitlement, comma-separated):\n"
        "  app-groups, healthkit, push, sign-in-with-apple, associated-domains,\n"
        "  external-accessory, gamecenter, vpn\n"
        "  Availability depends on the selected team's membership and Apple policy.\n"
        "\n");
}

static void printCommandHelp(NSString *command) {
    BOOL showList = !command || [command isEqualToString:@"list"];
    BOOL showSign = !command || [command isEqualToString:@"sign"];
    fprintf(stderr, "AltSign CLI - sign iOS IPA and .app bundles on macOS\n\n");
    if (showList) {
        fprintf(stderr,
            "List teams and inspect a team's certificates and App IDs:\n"
            "  altsign-cli list [--apple-id <email>] [--team-id <id>] [--verbose]\n"
            "\n"
            "  --apple-id <email>  Log in, or reuse this account's valid cached session.\n"
            "                     Omit to use the single cached account.\n"
            "  --team-id <id>      Inspect this team's certificates and App IDs.\n"
            "                     Omit to show all teams and inspect resources for\n"
            "                     the first team returned by Apple.\n"
            "\n"
            "Examples:\n"
            "  altsign-cli list --apple-id 'you@example.com'\n"
            "  altsign-cli list\n"
            "  altsign-cli list --team-id ABCDE12345\n\n");
    }
    if (showSign) {
        fprintf(stderr,
            "Sign with the cached account (authenticate with list first):\n"
            "  altsign-cli sign --udid <id> (--ipa <path> | --app <path>)\n"
            "                   [--team-id <id>] [--output <path.ipa>]\n"
            "                   [--entitlement <names>] [--verbose]\n"
            "\n"
            "  --udid <id>         Target device UDID.\n"
            "  --ipa <path>        Input IPA (.app also accepted for compatibility).\n"
            "  --app <path>        Input .app bundle; mutually exclusive with --ipa.\n"
            "  --team-id <id>      Select a team; defaults to the first team returned\n"
            "                     by Apple, including accounts with multiple teams.\n"
            "  --output <path>     Signed IPA; default: <input>_signed.ipa.\n"
            "  --entitlement <names>  Enable comma-separated capabilities.\n"
            "\n"
            "The selected team is shown before certificate/device changes.\n"
            "Signing can create or revoke certificates and register devices/App IDs.\n"
            "Team selection is per invocation, never saved or inferred from membership.\n"
            "\n"
            "Examples:\n"
            "  altsign-cli sign --team-id ABCDE12345 --udid DEVICE_ID --ipa MyApp.ipa\n"
            "  altsign-cli sign --udid DEVICE_ID --app MyApp.app --output Signed.ipa\n"
            "  altsign-cli sign --udid DEVICE_ID --ipa MyApp.ipa --entitlement healthkit\n\n");
        printCapabilities();
    }
    fprintf(stderr,
        "Common options:\n"
        "  --verbose          Print full API responses to the terminal (sensitive).\n"
        "  -h, --help         Show help without authentication or state changes.\n"
        "  altsign-cli help [list|sign]\n"
        "\n"
        "Authentication and state:\n"
        "  Passwords and 2FA codes are read from stdin; terminal passwords are hidden.\n"
        "  --password is not supported; sign does not accept --apple-id.\n"
        "  A successful login replaces the single cached account.\n"
        "  Session and keys: ~/Library/Application Support/altsign/.\n"
        "\n"
        "Diagnostics:\n"
        "  Validated commands print a private, shareable JSON log path at startup\n"
        "  and completion: $TMPDIR/altsign-XXXXXX.log (macOS temp dir fallback).\n"
        "  Logs contain stages and numeric status, not credentials or raw responses.\n"
        "  Terminal output and session files are separate; do not share them unredacted.\n"
        "  HTTP 429 preserves its error code; no automatic retries are performed.\n"
        "\n"
        "Exit codes: 0 success/help; 1 operation or missing sign input failure;\n"
        "            2 missing/expired session or password input failure;\n"
        "            64 unknown command or invalid option.\n"
        "  Apple/HTTP error codes appear separately from process exit codes.\n");
}

static void printUsage(void) { printCommandHelp(nil); }

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

static BOOL hasFlag(NSArray *args, NSString *flag) {
    return [args containsObject:flag];
}

static BOOL validateCommandOptions(NSArray<NSString *> *args,
                                   NSString *command,
                                   NSString **errorMessage) {
    NSSet<NSString *> *valueOptions = [command isEqualToString:@"list"]
        ? [NSSet setWithArray:@[@"--apple-id", @"--team-id"]]
        : [NSSet setWithArray:@[
            @"--udid", @"--ipa", @"--app", @"--output", @"--entitlement", @"--team-id"
        ]];
    NSSet<NSString *> *flagOptions = [NSSet setWithArray:@[@"--verbose"]];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    for (NSUInteger index = 2; index < args.count; index += 1) {
        NSString *argument = args[index];
        BOOL takesValue = [valueOptions containsObject:argument];
        if (!takesValue && ![flagOptions containsObject:argument]) {
            if (errorMessage != NULL) {
                *errorMessage = [NSString stringWithFormat:
                    @"unknown option for %@: %@", command, argument];
            }
            return NO;
        }
        if ([seen containsObject:argument]) {
            if (errorMessage != NULL) {
                *errorMessage = [NSString stringWithFormat:
                    @"duplicate option: %@", argument];
            }
            return NO;
        }
        [seen addObject:argument];
        if (takesValue) {
            if (index + 1 >= args.count ||
                [args[index + 1] hasPrefix:@"--"] ||
                [args[index + 1] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length == 0) {
                if (errorMessage != NULL) {
                    *errorMessage = [NSString stringWithFormat:
                        @"%@ requires a value", argument];
                }
                return NO;
            }
            index += 1;
        }
    }
    return YES;
}

static BOOL isAppBundlePath(NSString *path) {
    return [path.pathExtension.lowercaseString isEqualToString:@"app"];
}

static BOOL isIPAPath(NSString *path) {
    return [path.pathExtension.lowercaseString isEqualToString:@"ipa"];
}

static NSArray<NSString *> * _Nullable extractBundleIDsFromAppBundle(NSString *appPath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:appPath isDirectory:&isDir] || !isDir || !isAppBundlePath(appPath)) {
        return nil;
    }

    NSMutableArray<NSString *> *bundleIDs = [NSMutableArray array];
    void (^appendBundleID)(NSURL *) = ^(NSURL *url) {
        NSURL *infoPlistURL = [url URLByAppendingPathComponent:@"Info.plist"];
        NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfURL:infoPlistURL];
        NSString *bundleID = infoPlist[@"CFBundleIdentifier"];
        if (bundleID.length > 0) [bundleIDs addObject:bundleID];
    };

    NSURL *appURL = [NSURL fileURLWithPath:appPath];
    appendBundleID(appURL);

    NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:appURL
                                 includingPropertiesForKeys:nil
                                                    options:NSDirectoryEnumerationSkipsHiddenFiles
                                               errorHandler:nil];
    for (NSURL *url in enumerator) {
        NSString *ext = url.pathExtension;
        if ([ext isEqualToString:@"appex"] || [ext isEqualToString:@"xctest"]) {
            appendBundleID(url);
        }
    }

    return bundleIDs.count > 0 ? bundleIDs : nil;
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
            if ([ext isEqualToString:@"app"] || [ext isEqualToString:@"appex"] || [ext isEqualToString:@"xctest"]) {
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

static NSError *AltSignCLIError(NSString *message) {
    return [NSError errorWithDomain:@"com.altsign.cli"
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

static void clearSensitiveBuffer(char *buffer, size_t length) {
    volatile char *cursor = buffer;
    while (length-- > 0) {
        *cursor++ = 0;
    }
}

static NSString * _Nullable readPasswordFromStandardInput(
    NSString *appleID,
    NSError **error
) {
    char password[4096] = {0};
    NSString *prompt = [NSString stringWithFormat:
        @"Apple ID password for %@: ", appleID];
    int flags = isatty(STDIN_FILENO) ? RPP_REQUIRE_TTY : RPP_STDIN;
    errno = 0;
    char *result = readpassphrase(
        prompt.UTF8String,
        password,
        sizeof(password),
        flags
    );
    if (result == NULL) {
        if (error != NULL) {
            NSString *reason = errno == 0
                ? @"password was not provided"
                : [NSString stringWithFormat:
                    @"could not read the password from standard input: %s",
                    strerror(errno)];
            *error = AltSignCLIError(reason);
        }
        clearSensitiveBuffer(password, sizeof(password));
        return nil;
    }
    NSString *value = [[NSString alloc] initWithUTF8String:password];
    clearSensitiveBuffer(password, sizeof(password));
    if (value.length == 0 && error != NULL) {
        *error = AltSignCLIError(@"password was not provided");
    }
    return value.length > 0 ? value : nil;
}

static NSString * _Nullable readVerificationCodeFromStandardInput(void) {
    fprintf(stderr, "2FA verification required. Enter code: ");
    fflush(stderr);
    char buffer[64] = {0};
    char *result = fgets(buffer, sizeof(buffer), stdin);
    if (result == NULL) return nil;
    NSString *code = [[NSString alloc] initWithUTF8String:buffer];
    NSString *trimmed = [code stringByTrimmingCharactersInSet:
        NSCharacterSet.whitespaceAndNewlineCharacterSet];
    clearSensitiveBuffer(buffer, sizeof(buffer));
    return trimmed.length > 0 ? trimmed : nil;
}

static void authenticateWithAppleID(NSString *appleID, NSString *password,
                                    void (^completion)(ALTAccount * _Nullable, ALTAppleAPISession * _Nullable, NSError * _Nullable))
{
    [ALTAnisetteData fetchAnisetteDataWithCompletion:^(ALTAnisetteData *anisetteData, NSError *error) {
        if (error || !anisetteData) {
            completion(nil, nil, error ?: [NSError errorWithDomain:@"com.altsign" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Failed to fetch Anisette data"}]);
            return;
        }

        NSString *cachedAppleID = nil;
        ALTAppleAPISession *cachedSession =
            [ALTAppleAPISession loadSession:&cachedAppleID];
        if ([cachedAppleID isEqualToString:appleID] &&
            cachedSession && !cachedSession.isExpired) {
            ALTDiagnosticsEvent(@"auth.cache_reused", 0);
            NSLog(@"[Auth] Reusing cached session (expires: %@)", cachedSession.expirationDate);
            cachedSession.anisetteData = anisetteData;
            ALTAccount *account = [[ALTAccount alloc] init];
            account.appleID = appleID;
            account.identifier = cachedSession.dsid;
            completion(account, cachedSession, nil);
            return;
        }

        ALTDiagnosticsEvent(@"auth.fresh_login", 0);
        NSLog(@"[Auth] Cached session missing or expired, performing SRP login...");

        ALTVerificationHandler verificationHandler = ^(void (^callback)(NSString * _Nullable code)) {
            callback(readVerificationCodeFromStandardInput());
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

static void printTeams(NSArray<ALTTeam *> *teams) {
    fprintf(stdout, "Teams (%lu):\n", (unsigned long)teams.count);
    for (ALTTeam *team in teams) {
        fprintf(stdout, "  %s  %s  [%s]\n", team.identifier.UTF8String,
                team.name.UTF8String, team.type.UTF8String);
    }
    fflush(stdout);
}

static ALTTeam *selectTeam(NSArray<ALTTeam *> *teams, NSString *teamID) {
    if (teamID) {
        for (ALTTeam *team in teams) {
            if ([team.identifier isEqualToString:teamID]) {
                ALTDiagnosticsEvent(@"team.explicit", 0);
                return team;
            }
        }
        fprintf(stderr, "Error: team '%s' is not available to this account.\n", teamID.UTF8String);
        ALTDiagnosticsEvent(@"team.not_found", 1);
    } else if (teams.count > 0) {
        ALTDiagnosticsEvent(@"team.automatic", 0);
        return teams.firstObject;
    } else {
        fprintf(stderr, "Error: no teams are available.\n");
        ALTDiagnosticsEvent(@"team.none", 1);
    }
    printTeams(teams);
    return nil;
}

static BOOL performSign(NSString *appleID, NSString *password,
                        NSString *udid, NSString *inputPath, NSString *outputPath,
                        NSArray<NSString *> *entitlementNames, NSString *teamID)
{
    BOOL inputIsApp = isAppBundlePath(inputPath);
    if (!inputIsApp && !isIPAPath(inputPath)) {
        NSLog(@"[Error] Input must be an .ipa file or .app bundle: %@", inputPath);
        return NO;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block BOOL succeeded = NO;

    NSLog(@"========================================");
    NSLog(@" AltSign CLI - IPA/.app signing tool");
    NSLog(@"========================================");
    NSLog(@" Apple ID:  %@", appleID);
    NSLog(@" UDID:      %@", udid);
    NSLog(@" Input:     %@", inputPath);
    NSLog(@" Output:    %@", outputPath);
    NSLog(@"========================================");

    authenticateWithAppleID(appleID, password, ^(ALTAccount *account, ALTAppleAPISession *session, NSError *error) {
        if (error || !session) {
            ALTDiagnosticsEvent(@"auth.failed", error.code);
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
                ALTDiagnosticsEvent(@"teams.failed_or_empty", error.code);
                NSLog(@"[Error] No teams found: %@", error);
                dispatch_semaphore_signal(sem);
                return;
            }

            ALTTeam *team = selectTeam(teams, teamID);
            if (!team) {
                dispatch_semaphore_signal(sem);
                return;
            }
            NSLog(@"[Step 2] Using team: %@ (%@) type=%@", team.name, team.identifier, team.type);

            // Step 3: 获取证书
            NSLog(@"[Step 3] Fetching certificates...");
            [api fetchCertificatesForTeam:team session:session completionHandler:^(NSArray<ALTCertificate *> *certs, NSError *error) {
                if (error) {
                    ALTDiagnosticsEvent(@"certificates.failed", error.code);
                    NSLog(@"[Error] Failed to fetch certificates: %@", error);
                    dispatch_semaphore_signal(sem);
                    return;
                }

                void (^continueWithCert)(ALTCertificate *) = ^(ALTCertificate *cert) {
                    // Step 4: 注册设备
                    NSLog(@"[Step 4] Registering device: %@", udid);
                    [api registerDeviceWithName:@"AltSign Device" identifier:udid team:team session:session completionHandler:^(ALTDevice *device, NSError *error) {
                        if (error || device == nil) {
                            NSLog(@"[Error] Failed to register device: %@", error);
                            dispatch_semaphore_signal(sem);
                            return;
                        }
                        NSLog(@"[Step 4] Device registered or already exists");

                        // Step 5: 提取所有需要签名的 bundle ID
                        NSArray<NSString *> *bundleIDs = inputIsApp ? extractBundleIDsFromAppBundle(inputPath) : extractBundleIDsFromIPA(inputPath);
                        if (!bundleIDs || bundleIDs.count == 0) {
                            NSLog(@"[Error] Failed to read bundle IDs from input");
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
                                NSLog(@"[Step 7] Signing %@...", inputIsApp ? @".app" : @"IPA");
                                ALTSigner *signer = [[ALTSigner alloc] initWithCertificate:cert];
                                void (^completion)(BOOL, NSError *) = ^(BOOL success, NSError *error) {
                                    if (success) {
                                        ALTDiagnosticsEvent(@"sign.succeeded", 0);
                                        NSLog(@"[Done] IPA signed successfully!");
                                        NSLog(@"   Output: %@", outputPath);
                                        succeeded = YES;
                                    } else {
                                        ALTDiagnosticsEvent(@"sign.failed", error.code);
                                        NSLog(@"[Error] Signing failed: %@", error);
                                    }
                                    dispatch_semaphore_signal(sem);
                                };
                                if (inputIsApp) {
                                    [signer signAppAtURL:[NSURL fileURLWithPath:inputPath]
                                     provisioningProfiles:profiles
                                                outputURL:[NSURL fileURLWithPath:outputPath]
                                        completionHandler:completion];
                                } else {
                                    [signer signIPAAtURL:[NSURL fileURLWithPath:inputPath]
                                     provisioningProfiles:profiles
                                                outputURL:[NSURL fileURLWithPath:outputPath]
                                        completionHandler:completion];
                                }
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
    return succeeded;
}

static BOOL performList(NSString *appleID, NSString *password, NSString *teamID)
{
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block BOOL succeeded = NO;

    authenticateWithAppleID(appleID, password, ^(ALTAccount *account, ALTAppleAPISession *session, NSError *error) {
        if (error || !session) {
            ALTDiagnosticsEvent(@"auth.failed", error.code);
            NSLog(@"[Error] Authentication failed: %@", error);
            dispatch_semaphore_signal(sem);
            return;
        }
        NSLog(@"Login successful! DSID: %@", account.identifier);

        ALTAppleAPI *api = [ALTAppleAPI sharedAPI];
        [api fetchTeamsForAccount:account session:session
                completionHandler:^(NSArray<ALTTeam *> *teams, NSError *error) {
            if (error || teams.count == 0) {
                ALTDiagnosticsEvent(@"teams.failed_or_empty", error.code);
                NSLog(@"[Error] No teams found: %@", error);
                dispatch_semaphore_signal(sem);
                return;
            }
            if (!teamID) {
                printTeams(teams);
            }
            ALTTeam *team = selectTeam(teams, teamID);
            if (!team) {
                dispatch_semaphore_signal(sem);
                return;
            }
            NSLog(@"Team: %@ (%@) type=%@", team.name, team.identifier, team.type);

            [api fetchCertificatesForTeam:team session:session
                completionHandler:^(NSArray<ALTCertificate *> *certs, NSError *error) {
                if (error) {
                    ALTDiagnosticsEvent(@"certificates.failed", error.code);
                    NSLog(@"[Error] Failed to fetch certificates: %@", error);
                    dispatch_semaphore_signal(sem);
                    return;
                }
                if (certs.count > 0) {
                    NSLog(@"");
                    NSLog(@"Certificates (%lu):", (unsigned long)certs.count);
                    for (ALTCertificate *cert in certs) {
                        NSLog(@"   %@ (%@)", cert.name, cert.identifier);
                    }
                } else {
                    NSLog(@"No certificates found.");
                }

                [api fetchAppIDsForTeam:team session:session
                    completionHandler:^(NSArray<ALTAppID *> *appIDs, NSError *error) {
                    if (error) {
                        ALTDiagnosticsEvent(@"app_ids.failed", error.code);
                        NSLog(@"[Error] Failed to fetch App IDs: %@", error);
                        dispatch_semaphore_signal(sem);
                        return;
                    }
                    if (appIDs.count > 0) {
                        NSLog(@"");
                        NSLog(@"App IDs (%lu):", (unsigned long)appIDs.count);
                        for (ALTAppID *appID in appIDs) {
                            NSLog(@"   %@ (%@) name=%@", appID.bundleIdentifier, appID.identifier, appID.name);
                        }
                    } else {
                        NSLog(@"No App IDs found.");
                    }
                    succeeded = YES;
                    dispatch_semaphore_signal(sem);
                }];
            }];
        }];
    });

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    return succeeded;
}

// ============================================================
// main
// ============================================================

static int RunCLI(int argc, const char * argv[]) {
    @autoreleasepool {
        umask(0077);
        NSArray *args = [[NSProcessInfo processInfo] arguments];

        if (args.count < 2) {
            printUsage();
            return 1;
        }

        NSString *command = args[1];
        if ([command isEqualToString:@"--help"] || [command isEqualToString:@"-h"] ||
            [command isEqualToString:@"help"]) {
            if (args.count == 2) { printUsage(); return 0; }
            if ([command isEqualToString:@"help"] && args.count == 3 &&
                ([args[2] isEqualToString:@"list"] || [args[2] isEqualToString:@"sign"])) {
                printCommandHelp(args[2]); return 0;
            }
            fprintf(stderr, "Error: use altsign-cli help [list|sign].\n");
            return 64;
        }
        if (([command isEqualToString:@"list"] || [command isEqualToString:@"sign"]) &&
            (hasFlag(args, @"--help") || hasFlag(args, @"-h"))) {
            printCommandHelp(command);
            return 0;
        }
        if (hasFlag(args, @"--password")) {
            fprintf(stderr,
                "Error: --password is not supported. `list --apple-id` reads the password from standard input.\n");
            return 64;
        }

        if (![command isEqualToString:@"sign"] &&
            ![command isEqualToString:@"list"]) {
            fprintf(stderr, "Unknown command: %s\n\n", command.UTF8String);
            printUsage();
            return 64;
        }

        if ([command isEqualToString:@"sign"] &&
            hasFlag(args, @"--apple-id")) {
            fprintf(stderr,
                "Error: sign uses the cached session. Authenticate separately with `altsign-cli list --apple-id '<Apple ID>'`.\n");
            return 64;
        }

        NSString *optionError = nil;
        if (!validateCommandOptions(args, command, &optionError)) {
            fprintf(stderr, "Error: %s.\n", optionError.UTF8String);
            return 64;
        }

        NSString *appleID = getArg(args, @"--apple-id");
        NSString *teamID = getArg(args, @"--team-id");
        NSString *udid = getArg(args, @"--udid");
        NSString *ipaPath = getArg(args, @"--ipa");
        NSString *appPath = getArg(args, @"--app");
        NSString *outputPath = getArg(args, @"--output");
        NSString *entitlementArg = getArg(args, @"--entitlement");
        ALTVerboseLogging = hasFlag(args, @"--verbose");
        ALTDiagnosticsStart(command);

        if (hasFlag(args, @"--apple-id") && appleID.length == 0) {
            fprintf(stderr, "Error: --apple-id requires a value.\n");
            return 64;
        }
        NSString *password = nil;
        if ([command isEqualToString:@"list"] && appleID.length > 0) {
            NSString *cachedAppleID = nil;
            ALTAppleAPISession *cached =
                [ALTAppleAPISession loadSession:&cachedAppleID];
            if (![cachedAppleID isEqualToString:appleID] ||
                cached == nil || cached.isExpired) {
                NSError *passwordError = nil;
                password = readPasswordFromStandardInput(
                    appleID,
                    &passwordError
                );
                if (password.length == 0) {
                    ALTDiagnosticsEvent(@"auth.input_failed", passwordError.code);
                    fprintf(stderr, "Error: %s\n",
                        (passwordError.localizedDescription ?:
                            @"password was not provided").UTF8String);
                    return 2;
                }
            }
        } else {
            NSString *cachedAppleID = nil;
            ALTAppleAPISession *cached =
                [ALTAppleAPISession loadSession:&cachedAppleID];
            if (cached == nil || cached.isExpired || cachedAppleID.length == 0) {
                ALTDiagnosticsEvent(@"auth.cache_missing_or_expired", 2);
                fprintf(stderr,
                    "Error: no valid cached session. Run `altsign-cli list --apple-id '<Apple ID>'` first.\n");
                return 2;
            }
            appleID = cachedAppleID;
        }

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

        if ([command isEqualToString:@"sign"]) {
            if (ipaPath && appPath) {
                fprintf(stderr, "Error: use either --ipa or --app, not both\n\n");
                printUsage();
                return 1;
            }
            NSString *inputPath = ipaPath ?: appPath;
            if (!udid || !inputPath) {
                fprintf(stderr, "Error: --udid and one of --ipa/--app are required for sign command\n\n");
                printUsage();
                return 1;
            }
            if (!outputPath) {
                NSString *base = [inputPath stringByDeletingPathExtension];
                outputPath = [base stringByAppendingString:@"_signed.ipa"];
            }
            return performSign(
                appleID,
                nil,
                udid,
                inputPath,
                outputPath,
                entitlementNames,
                teamID
            ) ? 0 : 1;

        } else if ([command isEqualToString:@"list"]) {
            return performList(appleID, password, teamID) ? 0 : 1;
        }

        return 64;
    }
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        int code = RunCLI(argc, argv);
        ALTDiagnosticsFinish(code);
        return code;
    }
}
