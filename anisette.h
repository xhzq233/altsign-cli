//
//  anisette.h
//  AltSign CLI
//
//  Anisette 数据获取 — 通过 macOS 私有框架 AuthKit/AOSKit
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Anisette 设备认证数据
@interface ALTAnisetteData : NSObject

@property (nonatomic, copy, readonly) NSString *machineID;           // X-Apple-I-MD-M
@property (nonatomic, copy, readonly) NSString *oneTimePassword;     // X-Apple-I-MD
@property (nonatomic, copy, readonly) NSString *localUserID;         // X-Apple-I-MD-LU
@property (nonatomic, assign, readonly) NSUInteger routingInfo;      // X-Apple-I-MD-RINFO
@property (nonatomic, copy, readonly) NSString *deviceUniqueIdentifier; // X-Mme-Device-Id
@property (nonatomic, copy, readonly) NSString *deviceSerialNumber;  // X-Apple-I-SRL-NO
@property (nonatomic, copy, readonly) NSString *deviceDescription;
@property (nonatomic, strong, readonly) NSDate *date;
@property (nonatomic, copy, readonly) NSString *locale;
@property (nonatomic, copy, readonly) NSString *timeZone;

- (instancetype)initWithMachineID:(NSString *)machineID
                  oneTimePassword:(NSString *)oneTimePassword
                      localUserID:(NSString *)localUserID
                      routingInfo:(NSUInteger)routingInfo
           deviceUniqueIdentifier:(NSString *)deviceUniqueIdentifier
               deviceSerialNumber:(NSString *)deviceSerialNumber
                deviceDescription:(NSString *)deviceDescription
                             date:(NSDate *)date
                           locale:(NSString *)locale
                         timeZone:(NSString *)timeZone;

/// 从 macOS 系统获取当前 Anisette 数据
+ (void)fetchAnisetteDataWithCompletion:(void (^)(ALTAnisetteData * _Nullable data, NSError * _Nullable error))completion;

/// 将 Anisette 数据转为 HTTP Header 字典
- (NSDictionary<NSString *, NSString *> *)httpHeaders;

@end

NS_ASSUME_NONNULL_END
