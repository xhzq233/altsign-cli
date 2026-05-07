//
//  apple_api.h
//  AltSign CLI
//
//  Apple Developer Services API 封装
//

#import <Foundation/Foundation.h>
#import "srp_auth.h"

NS_ASSUME_NONNULL_BEGIN

// ============================================================
// 数据模型
// ============================================================

@interface ALTTeam : NSObject
@property (nonatomic, copy) NSString *identifier;  // teamId
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *type;         // Individual / Company
@end

@interface ALTCertificate : NSObject
@property (nonatomic, copy) NSString *identifier;   // serialNumber
@property (nonatomic, copy, nullable) NSString *name;
@property (nonatomic, copy, nullable) NSData *data;       // DER 证书数据
@property (nonatomic, copy, nullable) NSData *privateKey;  // RSA 私钥
@property (nonatomic, copy, nullable) NSData *machineIdentifier;

/// 生成 P12 (PKCS#12) 数据，签名时需要
- (nullable NSData *)p12Data;
@end

@interface ALTDevice : NSObject
@property (nonatomic, copy) NSString *identifier;  // UDID
@property (nonatomic, copy) NSString *name;
@end

@interface ALTAppID : NSObject
@property (nonatomic, copy) NSString *identifier;       // appIdId
@property (nonatomic, copy) NSString *bundleIdentifier; // com.xxx.xxx
@property (nonatomic, copy) NSString *name;
@end

@interface ALTProvisioningProfile : NSObject
@property (nonatomic, copy) NSString *identifier;       // UUID
@property (nonatomic, copy) NSString *bundleIdentifier;
@property (nonatomic, copy) NSData *data;               // mobileprovision 数据
@property (nonatomic, strong) NSDictionary *entitlements;
@property (nonatomic, strong) NSDate *expirationDate;
@end

// ============================================================
// Apple Developer Services API
// ============================================================

@interface ALTAppleAPI : NSObject

+ (instancetype)sharedAPI;

/// 获取团队列表
- (void)fetchTeamsForAccount:(ALTAccount *)account
                     session:(ALTAppleAPISession *)session
           completionHandler:(void (^)(NSArray<ALTTeam *> * _Nullable teams,
                                       NSError * _Nullable error))completion;

/// 获取开发证书列表
- (void)fetchCertificatesForTeam:(ALTTeam *)team
                         session:(ALTAppleAPISession *)session
               completionHandler:(void (^)(NSArray<ALTCertificate *> * _Nullable certs,
                                           NSError * _Nullable error))completion;

/// 提交 CSR，创建新证书
- (void)submitCertificateRequest:(NSData *)csrData
                            team:(ALTTeam *)team
                         session:(ALTAppleAPISession *)session
               completionHandler:(void (^)(ALTCertificate * _Nullable cert,
                                           NSError * _Nullable error))completion;

/// 撤销证书
- (void)revokeCertificate:(ALTCertificate *)certificate
                      team:(ALTTeam *)team
                   session:(ALTAppleAPISession *)session
         completionHandler:(void (^)(BOOL success, NSError * _Nullable error))completion;

/// 注册设备
- (void)registerDeviceWithName:(NSString *)name
                    identifier:(NSString *)udid
                          team:(ALTTeam *)team
                       session:(ALTAppleAPISession *)session
             completionHandler:(void (^)(ALTDevice * _Nullable device,
                                         NSError * _Nullable error))completion;

/// 获取已有 App ID 列表
- (void)fetchAppIDsForTeam:(ALTTeam *)team
                   session:(ALTAppleAPISession *)session
         completionHandler:(void (^)(NSArray<ALTAppID *> * _Nullable appIDs,
                                     NSError * _Nullable error))completion;

/// 创建 App ID
- (void)addAppIDWithName:(NSString *)name
        bundleIdentifier:(NSString *)bundleIdentifier
                    team:(ALTTeam *)team
                 session:(ALTAppleAPISession *)session
       completionHandler:(void (^)(ALTAppID * _Nullable appID,
                                   NSError * _Nullable error))completion;

/// 更新 App ID（启用/禁用 capabilities）
- (void)updateAppID:(ALTAppID *)appID
            features:(NSDictionary<NSString *, id> *)features
                team:(ALTTeam *)team
             session:(ALTAppleAPISession *)session
   completionHandler:(void (^)(ALTAppID * _Nullable appID,
                               NSError * _Nullable error))completion;

/// 下载 Provisioning Profile
- (void)fetchProvisioningProfileForAppID:(ALTAppID *)appID
                                    team:(ALTTeam *)team
                                 session:(ALTAppleAPISession *)session
                       completionHandler:(void (^)(ALTProvisioningProfile * _Nullable profile,
                                                   NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
