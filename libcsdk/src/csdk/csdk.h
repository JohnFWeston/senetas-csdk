/*
 * Engine declarations shared by the cipher methods and the self-test.
 *
 * csdk_ciphers() is the ENGINE cipher callback. csdk_destroy_ciphers()
 * frees the EVP methods created on the first lookup.
 */

#ifndef __CSDK_H__
#define __CSDK_H__

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

/*
 * Call counts for init, cipher, and AEAD control. The self-test stores
 * this on the EVP context with EVP_CIPHER_CTX_set_app_data.
 */
typedef struct csdk_stats_s {
    unsigned long long csdk_128_cfb_init_key;
    unsigned long long csdk_256_cfb_init_key;
    unsigned long long csdk_128_ctr_init_key;
    unsigned long long csdk_256_ctr_init_key;
    unsigned long long csdk_128_aead_init_key;
    unsigned long long csdk_256_aead_init_key;
    unsigned long long csdk_128_cfb_cipher;
    unsigned long long csdk_256_cfb_cipher;
    unsigned long long csdk_128_ctr_cipher;
    unsigned long long csdk_256_ctr_cipher;
    unsigned long long csdk_128_aead_cipher;
    unsigned long long csdk_256_aead_cipher;
    unsigned long long csdk_128_aead_ctrl;
    unsigned long long csdk_256_aead_ctrl;
} csdk_stats_t;

int csdk_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
void csdk_destroy_ciphers(void);

#endif /* __CSDK_H__ */
