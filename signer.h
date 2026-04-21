//
//  signer.h
//  AltSign CLI
//

#import <Foundation/Foundation.h>
#import "apple_api.h"

NS_ASSUME_NONNULL_BEGIN

@interface ALTSigner : NSObject

@property (nonatomic, copy, nullable) NSString *bundleIDOverride;

- (instancetype)initWithCertificate:(ALTCertificate *)certificate;

/// 对 IPA 进行重签名
/// @param ipaURL IPA 文件路径
/// @param profiles 按 bundleID 匹配的 Provisioning Profile 列表
/// @param outputURL 输出 IPA 路径
/// @param completion 完成回调
- (void)signIPAAtURL:(NSURL *)ipaURL
provisioningProfiles:(NSArray<ALTProvisioningProfile *> *)profiles
           outputURL:(NSURL *)outputURL
   completionHandler:(void (^)(BOOL success, NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
