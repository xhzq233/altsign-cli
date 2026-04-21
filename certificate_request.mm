//
//  certificate_request.mm
//  AltSign CLI
//
//  使用 OpenSSL 3.0+ EVP API 生成 CSR（证书签名请求）
//  功能等价于 AltSign/AltSign/Model/ALTCertificateRequest.m
//  已迁移至 EVP_PKEY API，消除全部 deprecation warnings
//

#import "certificate_request.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>

@implementation ALTCertificateRequest

- (nullable instancetype)init
{
    self = [super init];
    NSLog(@"[CSR] init called, self=%@", self);
    if (self)
    {
        NSData *data = nil;
        NSData *privateKey = nil;
        [self generateRequest:&data privateKey:&privateKey];
        
        if (data == nil || privateKey == nil) {
            return nil;
        }
        
        _data = [data copy];
        _privateKey = [privateKey copy];
    }
    return self;
}

// ============================================================
// 生成 RSA 2048 密钥对 + X509 CSR (OpenSSL 3.0 EVP API)
// ============================================================
- (void)generateRequest:(NSData **)outputRequest privateKey:(NSData **)outputPrivateKey
{
    NSLog(@"[CSR] generateRequest entered");
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    X509_REQ *request = NULL;
    BIO *csr = NULL;
    BIO *privKeyBIO = NULL;
    
    void (^finish)(void) = ^{
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        X509_REQ_free(request);
        BIO_free_all(csr);
        BIO_free_all(privKeyBIO);
    };
    
    /* ========== Generate RSA 2048 Key (EVP API) ========== */
    
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!pctx) {
        NSLog(@"[CSR] EVP_PKEY_CTX_new_from_name failed");
        finish();
        return;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        NSLog(@"[CSR] EVP_PKEY_keygen_init failed");
        finish();
        return;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
        NSLog(@"[CSR] set_rsa_keygen_bits failed");
        finish();
        return;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        NSLog(@"[CSR] EVP_PKEY_keygen failed");
        finish();
        return;
    }
    
    /* ========== Generate X509 CSR ========== */
    
    const char *country = "US";
    const char *state = "CA";
    const char *city = "Los Angeles";
    const char *organization = "AltSign";
    const char *commonName = "AltSign";
    
    request = X509_REQ_new();
    if (!request) {
        NSLog(@"[CSR] X509_REQ_new failed");
        finish();
        return;
    }
    X509_REQ_set_version(request, 0); // version 0 = PKCS#10 v1, OpenSSL 3.x compatible

    // Subject
    X509_NAME *subject = X509_REQ_get_subject_name(request);
    X509_NAME_add_entry_by_txt(subject, "C",  MBSTRING_ASC, (const unsigned char *)country, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "ST", MBSTRING_ASC, (const unsigned char *)state, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "L",  MBSTRING_ASC, (const unsigned char *)city, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "O",  MBSTRING_ASC, (const unsigned char *)organization, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char *)commonName, -1, -1, 0);

    // Set public key
    if (X509_REQ_set_pubkey(request, pkey) != 1) {
        NSLog(@"[CSR] X509_REQ_set_pubkey failed");
        finish();
        return;
    }

    // Sign CSR with SHA-256 (upgraded from SHA-1)
    if (X509_REQ_sign(request, pkey, EVP_sha256()) <= 0) {
        NSLog(@"[CSR] X509_REQ_sign failed");
        finish();
        return;
    }

    /* ========== Output CSR (PEM) ========== */

    csr = BIO_new(BIO_s_mem());
    if (!csr || PEM_write_bio_X509_REQ(csr, request) != 1) {
        NSLog(@"[CSR] PEM_write_bio_X509_REQ failed");
        finish();
        return;
    }

    /* ========== Output Private Key (PEM, via EVP) ========== */

    privKeyBIO = BIO_new(BIO_s_mem());
    if (!privKeyBIO || PEM_write_bio_PrivateKey(privKeyBIO, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        NSLog(@"[CSR] PEM_write_bio_PrivateKey failed");
        finish();
        return;
    }
    
    /* ========== Return values ========== */

    NSLog(@"[CSR] Reached output section, csr=%p privKeyBIO=%p", csr, privKeyBIO);

    char *csrData = NULL;
    long csrLength = BIO_get_mem_data(csr, &csrData);
    *outputRequest = [NSData dataWithBytes:csrData length:csrLength];
    
    char *privateKeyData = NULL;
    long privateKeyLength = BIO_get_mem_data(privKeyBIO, &privateKeyData);
    *outputPrivateKey = [NSData dataWithBytes:privateKeyData length:privateKeyLength];

    NSLog(@"[CSR] csrLen=%ld privKeyLen=%ld", csrLength, privateKeyLength);
    NSLog(@"[CSR] outputRequest=%@ outputPrivateKey=%@", *outputRequest, *outputPrivateKey);

    finish();
}

@end
