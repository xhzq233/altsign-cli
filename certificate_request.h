//
//  certificate_request.h
//  AltSign CLI
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// CSR 生成器（使用 OpenSSL）
@interface ALTCertificateRequest : NSObject

/// CSR PEM 数据
@property (nonatomic, copy, readonly) NSData *data;

/// RSA 私钥 PEM 数据
@property (nonatomic, copy, readonly) NSData *privateKey;

/// 初始化时自动生成 2048-bit RSA 密钥对 + X509 CSR
- (nullable instancetype)init;

@end

NS_ASSUME_NONNULL_END
