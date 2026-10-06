/*
 * Camellia cipher hook over the OpenSSL Camellia sources.
 *
 * Included from csdk_ciphers.c for CSDK_CIPHER_TARGET_camellia_ossl.
 * The block encrypt and key schedule are _Camellia_* from camellia_ossl/.
 * The license for that code is below.
 *
 * csdk_key_st holds the key size in bits (ks), the block size in bytes (bs),
 * and the Camellia key table. The GCM context follows the OpenSSL layout so
 * the mode layer can run GHASH over it. Do not reorder those fields.
 */

/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdlib.h>

/* Assembly and C entry points from camellia_ossl/. */
void _Camellia_EncryptBlock(int keyBitLength, const u8 plaintext[],
                            const KEY_TABLE_TYPE keyTable, u8 ciphertext[]);
void _Camellia_DecryptBlock(int keyBitLength, const u8 plaintext[],
                            const KEY_TABLE_TYPE keyTable, u8 ciphertext[]);
int _Camellia_Ekeygen(int keyBitLength, const u8 *rawKey, KEY_TABLE_TYPE k);
void _x86_64_Camellia_ctr32_encrypt_blocks(const unsigned char *in,
                                           unsigned char *out,
                                           size_t blocks,
                                           const KEY_TABLE_TYPE *keyTable,
                                           int ks,
                                           const unsigned char ivec[16]);

/* Key schedule. ks is bits, bs is bytes. */
struct csdk_key_st {
    int ks; /* key size in bits */
    int bs; /* cipher block size in bytes */
    KEY_TABLE_TYPE keyTable;
};
typedef struct csdk_key_st CSDK_KEY;

/*
 * Mirror of the OpenSSL GCM context. Field order is part of the GHASH
 * assembly contract.
 */
typedef struct {
    unsigned long hi, lo;
} u128;

typedef struct _gcm128_context_s {
    /* Names follow the GCM specification. */
    union {
        unsigned long u[2];
        unsigned int d[4];
        unsigned char c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
     * Xi, H, and Htable stay in this order. Assembler uses the offsets.
     */
    u128 Htable[16];
    void (*gmult)(unsigned long Xi[2], const u128 Htable[16]);
    void (*ghash)(unsigned long Xi[2], const u128 Htable[16],
                  const unsigned char *inp, size_t len);
    unsigned int mres, ares;
    block128_f block;
    void *key;
    unsigned char Xn[48];
} _gcm128_context_t;

typedef struct csdk_gcm_st_s {
    union {
        double align;
        CSDK_KEY ks;
    } ks;
    int key_set;       /* Set if key initialised */
    int iv_set;        /* Set if an iv is set */
    _gcm128_context_t gcm;
    unsigned char *iv; /* Temporary IV store */
    int ivlen;         /* IV length */
    int taglen;
    int iv_gen;        /* It is OK to generate IVs */
    ctr128_f ctr;
} csdk_gcm_st_t;
typedef struct csdk_gcm_st_s CSDK_GCM_CTX;

/* Expand the Camellia key into key->keyTable. */
static void camellia_set_key(const unsigned char *userKey, EVP_CIPHER_CTX *ctx,
                             CSDK_KEY *key)
{
    key->ks = EVP_CIPHER_CTX_key_length(ctx) * 8;
    key->bs = 16;
    _Camellia_Ekeygen(key->ks, userKey, key->keyTable);
}

/* Decrypt key setup for CFB, CTR, and GCM. */
static inline __attribute__((always_inline))
int _csdk_set_decrypt_key(const unsigned char *userKey,
                          const unsigned char *iv,
                          EVP_CIPHER_CTX *ctx)
{
    (void)iv;

    switch (EVP_CIPHER_CTX_nid(ctx)) {
    case NID_aes_128_cfb128:
    case NID_aes_256_cfb128:
    case NID_aes_128_ctr:
    case NID_aes_256_ctr: {
        camellia_set_key(userKey, ctx, EVP_CIPHER_CTX_get_cipher_data(ctx));
        break;
    }
    case NID_aes_128_gcm:
    case NID_aes_256_gcm: {
        CSDK_GCM_CTX *gctx = EVP_CIPHER_CTX_get_cipher_data(ctx);

        camellia_set_key(userKey, ctx, &gctx->ks.ks);
        break;
    }
    default:
        break;
    }
    return 0;
}

/* Encrypt key setup for CFB, CTR, and GCM. */
static inline __attribute__((always_inline))
int _csdk_set_encrypt_key(const unsigned char *userKey,
                          const unsigned char *iv,
                          EVP_CIPHER_CTX *ctx)
{
    (void)iv;

    switch (EVP_CIPHER_CTX_nid(ctx)) {
    case NID_aes_128_cfb128:
    case NID_aes_256_cfb128:
    case NID_aes_128_ctr:
    case NID_aes_256_ctr: {
        camellia_set_key(userKey, ctx, EVP_CIPHER_CTX_get_cipher_data(ctx));
        break;
    }
    case NID_aes_128_gcm:
    case NID_aes_256_gcm: {
        CSDK_GCM_CTX *gctx = EVP_CIPHER_CTX_get_cipher_data(ctx);

        camellia_set_key(userKey, ctx, &gctx->ks.ks);
        break;
    }
    default:
        break;
    }
    return 0;
}

/* Encrypt one block. */
static inline __attribute__((always_inline))
void _csdk_encrypt(const unsigned char *in, unsigned char *out,
                   const CSDK_KEY *key)
{
    _Camellia_EncryptBlock(key->ks, in, key->keyTable, out);
}

/* CTR encrypt, in the Camellia assembly. */
static inline __attribute__((always_inline))
void _csdk_encrypt_ctr32(const unsigned char *in, unsigned char *out,
                         size_t blocks, const CSDK_KEY *key,
                         const unsigned char ivec[16])
{
    _x86_64_Camellia_ctr32_encrypt_blocks(in, out, blocks, &key->keyTable,
                                          key->ks, ivec);
}
