//
//  srp_auth.h
//  AltSign CLI
//
//  Apple SRP (Secure Remote Password) 认证协议实现
//

#import <Foundation/Foundation.h>
#import "anisette.h"

NS_ASSUME_NONNULL_BEGIN

/// Apple API 会话（认证后获得）
@interface ALTAppleAPISession : NSObject
@property (nonatomic, copy) NSString *dsid;          // Directory Services ID
@property (nonatomic, copy) NSString *authToken;     // Xcode Auth Token
@property (nonatomic, strong) ALTAnisetteData *anisetteData;
@property (nonatomic, strong, nullable) NSDate *expirationDate; // Token 过期时间

- (instancetype)initWithDSID:(NSString *)dsid
                   authToken:(NSString *)authToken
                anisetteData:(ALTAnisetteData *)anisetteData;

/// 保存 session 到本地 plist
- (BOOL)saveForAppleID:(NSString *)appleID;

/// 从本地 plist 加载 session（需匹配 appleID）
+ (nullable instancetype)loadSessionForAppleID:(NSString *)appleID;

/// 加载任意可用的已存 session，通过 outAppleID 返回对应的 Apple ID
+ (nullable instancetype)loadAnySession:(NSString *_Nullable *_Nullable)outAppleID;

/// 删除本地保存的 session
+ (void)deleteSession;

/// 判断 session 是否已过期（预留 5 分钟缓冲）
- (BOOL)isExpired;
@end

/// Apple 帐号信息
@interface ALTAccount : NSObject
@property (nonatomic, copy) NSString *appleID;
@property (nonatomic, copy) NSString *identifier;  // dsid
@property (nonatomic, copy) NSString *firstName;
@property (nonatomic, copy) NSString *lastName;
@end

/// 全局 verbose 日志开关
extern BOOL ALTVerboseLogging;

/// 2FA 验证码处理器
typedef void (^ALTVerificationHandler)(void (^ _Nonnull)(NSString * _Nullable verificationCode));

/// SRP 认证器
@interface ALTSRPAuthenticator : NSObject

/// 使用 Apple ID + 密码 + Anisette 数据进行 SRP 登录
/// 完成后返回 ALTAccount + ALTAppleAPISession
+ (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
              completionHandler:(void (^)(ALTAccount * _Nullable account,
                                         ALTAppleAPISession * _Nullable session,
                                         NSError * _Nullable error))completion;

/// 带 2FA 验证码回调的 SRP 登录
/// verificationHandler 被调用时，需要向用户索取 6 位验证码，然后调用回调传入
+ (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
              verificationHandler:(nullable ALTVerificationHandler)verificationHandler
              completionHandler:(void (^)(ALTAccount * _Nullable account,
                                         ALTAppleAPISession * _Nullable session,
                                         NSError * _Nullable error))completion;

/// 提交 2FA 验证码（独立步骤）
+ (void)submitTwoFactorCode:(NSString *)code
                       dsid:(NSString *)dsid
                  idmsToken:(NSString *)idmsToken
               anisetteData:(ALTAnisetteData *)anisetteData
          completionHandler:(void (^)(BOOL success, NSError * _Nullable error))completion;

/// 检查是否存在待处理的 2FA 状态（5 分钟内有效）
+ (BOOL)hasPendingTwoFactorAuthentication;

/// 提交待处理 2FA 的验证码，验证成功后自动完成登录
+ (void)submitPendingTwoFactorCode:(NSString *)code
                          password:(NSString *)password
                 completionHandler:(void (^)(ALTAccount * _Nullable account,
                                            ALTAppleAPISession * _Nullable session,
                                            NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
