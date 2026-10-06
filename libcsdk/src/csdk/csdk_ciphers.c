/*
 * EVP cipher methods for the libcsdk engine.
 *
 * One cipher target is compiled in. Block-cipher targets register the
 * AES-128 and AES-256 names for CFB-128, CTR, and GCM. ChaCha20-Poly1305
 * registers that AEAD instead. Mode code in this file calls the hooks in
 * the selected cipher source.
 */

#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/rand_drbg.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <emmintrin.h>
#include <tmmintrin.h>

#include "csdk.h"
#include "csdk_err.h"
#include "csdk_utils.h"
#if !defined(CSDK_CIPHER_TARGET_custom) && !defined(CSDK_CIPHER_TARGET_aesni) && !defined(CSDK_CIPHER_TARGET_aessbox)
#include <openssl/aes.h>
#endif
#include <openssl/modes.h>

uint64_t  _OPENSSL_ia32_cpuid(unsigned int *);
unsigned int _OPENSSL_ia32cap_P[4];

#define BSWAP8(x) ({ uint64_t ret_=(x); asm ("bswapq %0" : "+r"(ret_));   ret_; })
#define BSWAP4(x) ({ uint32_t ret_=(x); asm ("bswapl %0" : "+r"(ret_));   ret_; })
# define GETU32(p)       BSWAP4(*(const uint32_t*)(p))
# define PUTU32(p,v)     *(uint32_t *)(p) = BSWAP4(v)

typedef struct csdk_gcm_st_s CSDK_GCM_CTX;

/* increment upper 96 bits of 128-bit counter by 1 */
static void ctr96_inc(unsigned char *counter)
{
    uint32_t n = 12, c = 1;

    do {
        --n;
        c += counter[n];
        counter[n] = (uint8_t)c;
        c >>= 8;
    } while (n);
}

#ifdef CSDK_CIPHER_TARGET_custom
#include "cipher/custom.c"
#endif

#ifdef CSDK_CIPHER_TARGET_aesni
#include "cipher/aesni.c"
#endif

#ifdef CSDK_CIPHER_TARGET_aessbox
#include "cipher/aessbox.c"
#endif

#ifdef CSDK_CIPHER_TARGET_camellia
#include "cipher/camellia.c"
#endif
#ifdef CSDK_CIPHER_TARGET_twofish
#include "cipher/twofish.c"
#endif
#ifdef CSDK_CIPHER_TARGET_twofish_intrinsics
#include "cipher/twofish_intrinsics.c"
#endif
#ifdef CSDK_CIPHER_TARGET_xor
#include "cipher/xor.c"
#endif
#ifdef CSDK_CIPHER_TARGET_chacha20_poly1305
#include "cipher/chacha/chacha.h"
#include "cipher/chacha/poly1305.h"
#include "cipher/chacha20_poly1305.c"
#include "cipher/chacha/poly1305.c"
#endif
#ifdef CSDK_CIPHER_TARGET_camellia_ossl
#include "cipher/camellia_ossl/cmll_local.h"
#include "cipher/camellia_ossl.c"
#endif

#if defined( CSDK_CIPHER_TARGET_aes ) ||  \
    defined (CSDK_CIPHER_TARGET_aria)
#define CSDK_MODE_EXTERNAL
#endif


#ifndef CSDK_CIPHER_TARGET_chacha20_poly1305

#ifndef CSDK_MODE_EXTERNAL
static void ctr64_inc(unsigned char *counter)
{
    unsigned int n = 8;
    unsigned char c;

    counter += 8;
    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}
#endif

/* CFB-128. The block cipher is the selected target's _csdk_encrypt hook. */

#ifndef CSDK_MODE_EXTERNAL
void _csdk_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], int *num,
                           int enc, block128_f block)
{
    unsigned int n;
    size_t l = 0;

    n = *num;

    if (enc) {
        if (16 % sizeof(size_t) == 0) { /* always true actually */
            do {
                while (n && len) {
                    *(out++) = ivec[n] ^= *(in++);
                    --len;
                    n = (n + 1) % 16;
                }
# if defined(STRICT_ALIGNMENT)
                if (((size_t)in | (size_t)out | (size_t)ivec) %
                    sizeof(size_t) != 0)
                    break;
# endif
                while (len >= 16) {
                    (*block) (ivec, ivec, key);
                    {
                        __m128i _a = _mm_loadu_si128((__m128i*) &ivec[0]);
                        __m128i _b = _mm_loadu_si128((__m128i*) &in[0]);
                        _a = _mm_xor_si128(_a, _b);
                        _mm_storeu_si128((__m128i*) &out[0], _a);
                        _mm_storeu_si128((__m128i*) &ivec[0], _a);
                    }
                    len -= 16;
                    out += 16;
                    in += 16;
                    n = 0;
                }
                if (len) {
                    (*block) (ivec, ivec, key);
                    while (len--) {
                        out[n] = ivec[n] ^= in[n];
                        ++n;
                    }
                }
                *num = n;
                return;
            } while (0);
        }
        /* the rest would be commonly eliminated by x86* compiler */
        while (l < len) {
            if (n == 0) {
                (*block) (ivec, ivec, key);
            }
            out[l] = ivec[n] ^= in[l];
            ++l;
            n = (n + 1) % 16;
        }
        *num = n;
    } else {
        if (16 % sizeof(size_t) == 0) { /* always true actually */
            do {
                while (n && len) {
                    unsigned char c;
                    *(out++) = ivec[n] ^ (c = *(in++));
                    ivec[n] = c;
                    --len;
                    n = (n + 1) % 16;
                }
# if defined(STRICT_ALIGNMENT)
                if (((size_t)in | (size_t)out | (size_t)ivec) %
                    sizeof(size_t) != 0)
                    break;
# endif
                while (len >= 16) {
                    (*block) (ivec, ivec, key);
                    {
                        __m128i _iv = _mm_loadu_si128((__m128i*) &ivec[0]);
                        __m128i _t = _mm_loadu_si128((__m128i*) &in[0]);
                        _iv = _mm_xor_si128(_t, _iv);
                        _mm_storeu_si128((__m128i*) &out[0], _iv);
                        _mm_storeu_si128((__m128i*) &ivec[0], _t);
                    }
                    len -= 16;
                    out += 16;
                    in += 16;
                    n = 0;
                }
                if (len) {
                    (*block) (ivec, ivec, key);
                    while (len--) {
                        unsigned char c;
                        out[n] = ivec[n] ^ (c = in[n]);
                        ivec[n] = c;
                        ++n;
                    }
                }
                *num = n;
                return;
            } while (0);
        }
        /* the rest would be commonly eliminated by x86* compiler */
        while (l < len) {
            unsigned char c;
            if (n == 0) {
                (*block) (ivec, ivec, key);
            }
            out[l] = ivec[n] ^ (c = in[l]);
            ivec[n] = c;
            ++l;
            n = (n + 1) % 16;
        }
        *num = n;
    }
}
#endif

static int csdk_128_cfb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_128_cfb_init_key++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_init(EVP_aes_128_cfb())(ctx, key, iv, enc);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_init(EVP_aria_128_cfb())(ctx, key, iv, enc);
#else
    int ret;
    if (enc)
        ret = _csdk_set_encrypt_key(key, iv, ctx);
    else
        ret = _csdk_set_decrypt_key(key, iv, ctx);
    if (ret < 0) {
        return 0;
    }
    return 1;
#endif
}


static int csdk_128_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_128_cfb_cipher++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_do_cipher(EVP_aes_128_cfb())(ctx, out, in , inl);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_do_cipher(EVP_aria_128_cfb())(ctx, out, in , inl);
#else
    CSDK_KEY *key = (CSDK_KEY*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    int num = EVP_CIPHER_CTX_num(ctx);

    _csdk_cfb128_encrypt(in, out, inl, key,
                          EVP_CIPHER_CTX_iv_noconst(ctx),
                          &num,
                          EVP_CIPHER_CTX_encrypting(ctx),
                          (block128_f) _csdk_encrypt);
    EVP_CIPHER_CTX_set_num(ctx, num);
#endif
    return 1;
}

#ifdef CSDK_CIPHER_TARGET_aes
#define CSDK_CFB_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CFB_MODE)
#elif CSDK_CIPHER_TARGET_aria
#define CSDK_CFB_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CFB_MODE)
#else
#define CSDK_CFB_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CFB_MODE)
#endif
static EVP_CIPHER *_hidden_128_cfb = NULL;
static const EVP_CIPHER *csdk_cipher_128_cfb(void)
{
#ifdef CSDK_CIPHER_TARGET_aes
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aes_128_cfb());
#elif CSDK_CIPHER_TARGET_aria
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aria_128_cfb());
#else
    size_t s = sizeof(CSDK_KEY);
#endif

    if (_hidden_128_cfb == NULL
        && ((_hidden_128_cfb = EVP_CIPHER_meth_new(NID_aes_128_cfb128,
                                                       1  /* block size - streaming */,
                                                       16 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_128_cfb,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_128_cfb, CSDK_CFB_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_128_cfb, csdk_128_cfb_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_128_cfb, csdk_128_cfb_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_128_cfb, s)))
    {
        EVP_CIPHER_meth_free(_hidden_128_cfb);
        _hidden_128_cfb = NULL;
    }
    return _hidden_128_cfb;
}


static int csdk_256_cfb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_256_cfb_init_key++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_init(EVP_aes_256_cfb())(ctx, key, iv, enc);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_init(EVP_aria_256_cfb())(ctx, key, iv, enc);
#else
    int ret;
    (void)iv;

    if (enc)
        ret = _csdk_set_encrypt_key(key, iv, ctx);
    else
        ret = _csdk_set_decrypt_key(key, iv, ctx);
    if (ret < 0) {
        return 0;
    }
    return 1;
#endif
}

static int csdk_256_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_256_cfb_cipher++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_do_cipher(EVP_aes_256_cfb())(ctx, out, in , inl);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_do_cipher(EVP_aria_256_cfb())(ctx, out, in , inl);
#else
    CSDK_KEY *key = (CSDK_KEY*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    int num = EVP_CIPHER_CTX_num(ctx);

    _csdk_cfb128_encrypt(in, out, inl, key,
                          EVP_CIPHER_CTX_iv_noconst(ctx),
                          &num,
                          EVP_CIPHER_CTX_encrypting(ctx),
                          (block128_f) _csdk_encrypt);
    EVP_CIPHER_CTX_set_num(ctx, num);
#endif
    return 1;
}

static EVP_CIPHER *_hidden_256_cfb = NULL;
static const EVP_CIPHER *csdk_cipher_256_cfb(void)
{
#ifdef CSDK_CIPHER_TARGET_aes
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aes_256_cfb());
#elif CSDK_CIPHER_TARGET_aria
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aria_256_cfb());
#else
    size_t s = sizeof(CSDK_KEY);
#endif

    if (_hidden_256_cfb == NULL
        && ((_hidden_256_cfb = EVP_CIPHER_meth_new(NID_aes_256_cfb128,
                                                       1  /* block size - streaming */,
                                                       32 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_256_cfb,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_256_cfb, CSDK_CFB_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_256_cfb, csdk_256_cfb_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_256_cfb, csdk_256_cfb_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_256_cfb, s)))
    {
        EVP_CIPHER_meth_free(_hidden_256_cfb);
        _hidden_256_cfb = NULL;
    }
    return _hidden_256_cfb;
}



/* CTR. The counter encrypt is _csdk_encrypt_ctr32 when the target provides it. */
#ifndef CSDK_MODE_EXTERNAL
#if 1

void _csdk_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16],
                           unsigned char ecount_buf[16], unsigned int *num,
                           ctr128_f func)
{
    unsigned int n, ctr32;

    n = *num;

    while (n && len) {
        *(out++) = *(in++) ^ ecount_buf[n];
        --len;
        n = (n + 1) % 16;
    }

    ctr32 = GETU32(ivec + 12);
    while (len >= 16) {
        size_t blocks = len / 16;
        /*
         * 1<<28 is just a not-so-small yet not-so-large number...
         * Below condition is practically never met, but it has to
         * be checked for code correctness.
         */
        if (sizeof(size_t) > sizeof(unsigned int) && blocks > (1U << 28))
            blocks = (1U << 28);
        /*
         * As (*func) operates on 32-bit counter, caller
         * has to handle overflow. 'if' below detects the
         * overflow, which is then handled by limiting the
         * amount of blocks to the exact overflow point...
         */
        ctr32 += (uint32_t)blocks;
        if (ctr32 < blocks) {
            blocks -= ctr32;
            ctr32 = 0;
        }
        (*func) (in, out, blocks, key, ivec);
        /* (*ctr) does not update ivec, caller does: */
        PUTU32(ivec + 12, ctr32);
        /* ... overflow was detected, propagate carry. */
        if (ctr32 == 0)
            ctr96_inc(ivec);
        blocks *= 16;
        len -= blocks;
        out += blocks;
        in += blocks;
    }
    if (len) {
        memset(ecount_buf, 0, 16);
        (*func) (ecount_buf, ecount_buf, 1, key, ivec);
        ++ctr32;
        PUTU32(ivec + 12, ctr32);
        if (ctr32 == 0)
            ctr96_inc(ivec);
        while (len--) {
            out[n] = in[n] ^ ecount_buf[n];
            ++n;
        }
    }

    *num = n;
}

#else
inline __m128i _mm_inc_epi32(__m128i a)
{
    return _mm_add_epi32(a, _mm_set1_epi32(1));
}

static void ctr128_inc_aligned(unsigned char *counter)
{
    __m128i mask = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    __m128i one = _mm_set_epi32(0,0,0,1);
    _mm_storeu_si128((__m128i*)counter,
        _mm_shuffle_epi8(_mm_add_epi32(one, _mm_shuffle_epi8(
                _mm_loadu_si128((__m128i*)counter), mask)), mask));
}

void _csdk_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16],
                           unsigned char ecount_buf[16], unsigned int *num,
                           block128_f block)
{
    unsigned int n;
    size_t l = 0;

    n = *num;

    if (16 % sizeof(size_t) == 0) { /* always true actually */
        do {
            while (n && len) {
                *(out++) = *(in++) ^ ecount_buf[n];
                --len;
                n = (n + 1) % 16;
            }

# if defined(STRICT_ALIGNMENT)
            if (((size_t)in | (size_t)out | (size_t)ecount_buf)
                % sizeof(size_t) != 0)
                break;
# endif
            while (len >= 16) {
                (*block) (ivec, ecount_buf, key);
                ctr128_inc_aligned(ivec);
           {
               __m128i _eb = _mm_loadu_si128((__m128i*) &ecount_buf[0]);
               __m128i _i = _mm_loadu_si128((__m128i*) &in[0]);
               _eb = _mm_xor_si128(_eb, _i);
               _mm_storeu_si128((__m128i*) &out[0], _eb);
           }
                len -= 16;
                out += 16;
                in += 16;
                n = 0;
            }
            if (len) {
                (*block) (ivec, ecount_buf, key);
                ctr128_inc_aligned(ivec);
                while (len--) {
                    out[n] = in[n] ^ ecount_buf[n];
                    ++n;
                }
            }
            *num = n;
            return;
        } while (0);
    }
    /* the rest would be commonly eliminated by x86* compiler */
    while (l < len) {
        if (n == 0) {
            (*block) (ivec, ecount_buf, key);
        ctr128_inc_aligned(ivec);
           // ctr128_inc(ivec);
        }
        out[l] = in[l] ^ ecount_buf[n];
        ++l;
        n = (n + 1) % 16;
    }

    *num = n;
}
#endif
#endif

static int csdk_128_ctr_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_128_ctr_init_key++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_init(EVP_aes_128_ctr())(ctx, key, iv, enc);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_init(EVP_aria_128_ctr())(ctx, key, iv, enc);
#else
    int ret;
    if (enc)
        ret = _csdk_set_encrypt_key(key, iv, ctx);
    else
        ret = _csdk_set_decrypt_key(key, iv, ctx);
    if (ret < 0) {
        return 0;
    }
    return 1;
#endif
}

static int csdk_128_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_128_ctr_cipher++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_do_cipher(EVP_aes_128_ctr())(ctx, out, in , inl);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_do_cipher(EVP_aria_128_ctr())(ctx, out, in , inl);
#else
    CSDK_KEY *key = (CSDK_KEY*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned int num = EVP_CIPHER_CTX_num(ctx);

#if 1
    _csdk_ctr128_encrypt_ctr32(in, out, inl, key,
                          EVP_CIPHER_CTX_iv_noconst(ctx),
                          EVP_CIPHER_CTX_buf_noconst(ctx),
                          &num,
                          (ctr128_f) _csdk_encrypt_ctr32);
#else
    _csdk_ctr128_encrypt(in, out, inl, key,
                          EVP_CIPHER_CTX_iv_noconst(ctx),
                          EVP_CIPHER_CTX_buf_noconst(ctx),
                          &num,
                          (block128_f) _csdk_encrypt);
#endif
    EVP_CIPHER_CTX_set_num(ctx, num);
#endif
    return 1;
}

#ifdef CSDK_CIPHER_TARGET_aes
#define CSDK_CTR_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CTR_MODE)
#elif CSDK_CIPHER_TARGET_aria
#define CSDK_CTR_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CTR_MODE)
#else
#define CSDK_CTR_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CTR_MODE)
#endif

static EVP_CIPHER *_hidden_128_ctr = NULL;
static const EVP_CIPHER *csdk_cipher_128_ctr(void)
{
#ifdef CSDK_CIPHER_TARGET_aes
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aes_128_ctr());
#elif CSDK_CIPHER_TARGET_aria
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aria_128_ctr());
#else
    size_t s = sizeof(CSDK_KEY);
#endif
    if (_hidden_128_ctr == NULL
        && ((_hidden_128_ctr = EVP_CIPHER_meth_new(NID_aes_128_ctr,
                                                       1  /* block size - streaming */,
                                                       16 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_128_ctr,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_128_ctr, CSDK_CTR_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_128_ctr, csdk_128_ctr_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_128_ctr, csdk_128_ctr_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_128_ctr, s)))
    {
        EVP_CIPHER_meth_free(_hidden_128_ctr);
        _hidden_128_ctr = NULL;
    }
    return _hidden_128_ctr;
}


static int csdk_256_ctr_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_256_ctr_init_key++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_init(EVP_aes_256_ctr())(ctx, key, iv, enc);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_init(EVP_aria_256_ctr())(ctx, key, iv, enc);
#else
    int ret;
    (void)iv;
    EVP_CipherInit_ex( ctx,NULL, NULL, NULL, iv, EVP_CIPHER_CTX_encrypting(ctx));

    if (enc)
        ret = _csdk_set_encrypt_key(key, iv, ctx);
    else
        ret = _csdk_set_decrypt_key(key, iv, ctx);
    EVP_CIPHER_CTX_set_num(ctx, 0);
    if (ret < 0) {
        return 0;
    }
    return 1;
#endif
}

static int csdk_256_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_256_ctr_cipher++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_do_cipher(EVP_aes_256_ctr())(ctx, out, in , inl);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_do_cipher(EVP_aria_256_ctr())(ctx, out, in , inl);
#else
    CSDK_KEY *key = (CSDK_KEY*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned int num = EVP_CIPHER_CTX_num(ctx);
    unsigned char iv[16] = {0};
    memcpy(iv, EVP_CIPHER_CTX_iv_noconst(ctx), sizeof(iv));

    _csdk_ctr128_encrypt_ctr32(in, out, inl, key,
                          EVP_CIPHER_CTX_iv_noconst(ctx),
                          EVP_CIPHER_CTX_buf_noconst(ctx),
                          &num,
                          (ctr128_f) _csdk_encrypt_ctr32);
#if 0
    _csdk_ctr128_encrypt(in, out, inl, key,
                          iv,
                          EVP_CIPHER_CTX_buf_noconst(ctx),
                          &num,
                          (block128_f) _csdk_encrypt);
#endif
    EVP_CIPHER_CTX_set_num(ctx, num);
    EVP_CipherInit_ex( ctx,NULL, NULL, NULL, iv, EVP_CIPHER_CTX_encrypting(ctx));
#endif
    return 1;
}

static EVP_CIPHER *_hidden_256_ctr = NULL;
static const EVP_CIPHER *csdk_cipher_256_ctr(void)
{
#ifdef CSDK_CIPHER_TARGET_aes
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aes_256_ctr());
#elif CSDK_CIPHER_TARGET_aria
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aria_256_ctr());
#else
    size_t s = sizeof(CSDK_KEY);
#endif
    if (_hidden_256_ctr == NULL
        && ((_hidden_256_ctr = EVP_CIPHER_meth_new(NID_aes_256_ctr,
                                                       1  /* block size - streaming */,
                                                       32 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_256_ctr,16)
            || !EVP_CIPHER_meth_set_flags(_hidden_256_ctr, CSDK_CTR_FLAGS )
            || !EVP_CIPHER_meth_set_init(_hidden_256_ctr, csdk_256_ctr_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_256_ctr, csdk_256_ctr_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_256_ctr, s)))
    {
        EVP_CIPHER_meth_free(_hidden_256_ctr);
        _hidden_256_ctr = NULL;
    }
    return _hidden_256_ctr;
}


/* GCM. The context layout matches OpenSSL so the GHASH assembly can run. */
#ifndef CSDK_MODE_EXTERNAL
/*
 * gcm implementation taken from core openssl - restating licence here
 *
 * Copyright 2010-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

typedef size_t size_t_aX __attribute((__aligned__(1)));


#define PACK(s)         ((size_t)(s)<<(sizeof(size_t)*8-16))
#define REDUCE1BIT(V)   do { \
        if (sizeof(size_t)==8) { \
                uint64_t T = U64(0xe100000000000000) & (0-(V.lo&1)); \
                V.lo  = (V.hi<<63)|(V.lo>>1); \
                V.hi  = (V.hi>>1 )^T; \
        } \
        else { \
                uint32_t T = 0xe1000000U & (0-(uint32_t)(V.lo&1)); \
                V.lo  = (V.hi<<63)|(V.lo>>1); \
                V.hi  = (V.hi>>1 )^((uint64_t)T<<32); \
        } \
} while(0)

static void _gcm_init_4bit(u128 Htable[16], uint64_t H[2])
{
    u128 V;

    Htable[0].hi = 0;
    Htable[0].lo = 0;
    V.hi = H[0];
    V.lo = H[1];

    Htable[8] = V;
    REDUCE1BIT(V);
    Htable[4] = V;
    REDUCE1BIT(V);
    Htable[2] = V;
    REDUCE1BIT(V);
    Htable[1] = V;
    Htable[3].hi = V.hi ^ Htable[2].hi, Htable[3].lo = V.lo ^ Htable[2].lo;
    V = Htable[4];
    Htable[5].hi = V.hi ^ Htable[1].hi, Htable[5].lo = V.lo ^ Htable[1].lo;
    Htable[6].hi = V.hi ^ Htable[2].hi, Htable[6].lo = V.lo ^ Htable[2].lo;
    Htable[7].hi = V.hi ^ Htable[3].hi, Htable[7].lo = V.lo ^ Htable[3].lo;
    V = Htable[8];
    Htable[9].hi = V.hi ^ Htable[1].hi, Htable[9].lo = V.lo ^ Htable[1].lo;
    Htable[10].hi = V.hi ^ Htable[2].hi, Htable[10].lo = V.lo ^ Htable[2].lo;
    Htable[11].hi = V.hi ^ Htable[3].hi, Htable[11].lo = V.lo ^ Htable[3].lo;
    Htable[12].hi = V.hi ^ Htable[4].hi, Htable[12].lo = V.lo ^ Htable[4].lo;
    Htable[13].hi = V.hi ^ Htable[5].hi, Htable[13].lo = V.lo ^ Htable[5].lo;
    Htable[14].hi = V.hi ^ Htable[6].hi, Htable[14].lo = V.lo ^ Htable[6].lo;
    Htable[15].hi = V.hi ^ Htable[7].hi, Htable[15].lo = V.lo ^ Htable[7].lo;
}

/* GHASH assembly entry points. */
void _gcm_gmult_4bit(uint64_t Xi[2], const u128 Htable[16]);
void _gcm_ghash_4bit(uint64_t Xi[2], const u128 Htable[16], const uint8_t *inp,
                    size_t len);

# define GCM_MUL(ctx)      _gcm_gmult_4bit(ctx->Xi.u,ctx->Htable)
#  define GHASH(ctx,in,len) _gcm_ghash_4bit((ctx)->Xi.u,(ctx)->Htable,in,len)
/*
 * GHASH_CHUNK is "stride parameter" missioned to mitigate cache trashing
 * effect. In other words idea is to hash data while it's still in L1 cache
 * after encryption pass...
 */
#  define GHASH_CHUNK       (3*1024)
#  define GHASH_ASM_X86_OR_64

/* CLMUL and AVX GHASH assembly entry points. */
void _gcm_init_clmul(u128 Htable[16], const uint64_t Xi[2]);
void _gcm_gmult_clmul(uint64_t Xi[2], const u128 Htable[16]);
void _gcm_ghash_clmul(uint64_t Xi[2], const u128 Htable[16], const uint8_t *inp,
                     size_t len);

void _gcm_init_avx(u128 Htable[16], const uint64_t Xi[2]);
void _gcm_gmult_avx(uint64_t Xi[2], const u128 Htable[16]);
void _gcm_ghash_avx(uint64_t Xi[2], const u128 Htable[16], const uint8_t *inp,
                   size_t len);
# undef  GCM_MUL
# define GCM_MUL(ctx)           (*_gcm_gmult_p)(ctx->Xi.u,ctx->Htable)
#  undef  GHASH
#  define GHASH(ctx,in,len)     (*_gcm_ghash_p)(ctx->Xi.u,ctx->Htable,in,len)

void _crypto_gcm128_init(_gcm128_context_t *ctx, void *key, block128_f block)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };

    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->key = key;
    (*block) (ctx->H.c, ctx->H.c, key);

    if (is_endian.little) {
        /* H is stored in host byte order */
        ctx->H.u[0] = BSWAP8(ctx->H.u[0]);
        ctx->H.u[1] = BSWAP8(ctx->H.u[1]);
    }
#  define CTX__GHASH(f) (ctx->ghash = (f))
    if (_OPENSSL_ia32cap_P[1] & (1 << 1)) { /* check PCLMULQDQ bit */
        if (((_OPENSSL_ia32cap_P[1] >> 22) & 0x41) == 0x41) { /* AVX+MOVBE */
            _gcm_init_avx(ctx->Htable, ctx->H.u);
            ctx->gmult = _gcm_gmult_avx;
            CTX__GHASH(_gcm_ghash_avx);
        } else {
            _gcm_init_clmul(ctx->Htable, ctx->H.u);
            ctx->gmult = _gcm_gmult_clmul;
            CTX__GHASH(_gcm_ghash_clmul);
        }
        return;
    }
    else // ghash_4bit worst case - slow
    {
        _gcm_init_4bit(ctx->Htable, ctx->H.u);
        ctx->gmult = _gcm_gmult_4bit;
        CTX__GHASH(_gcm_ghash_4bit);
    }
# undef CTX__GHASH
}

void _crypto_gcm128_setiv(_gcm128_context_t *ctx, const unsigned char *iv,
                         size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int ctr;
    void (*_gcm_gmult_p) (uint64_t Xi[2], const u128 Htable[16]) = ctx->gmult;

    ctx->len.u[0] = 0;          /* AAD length */
    ctx->len.u[1] = 0;          /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    if (len == 12) {
        memcpy(ctx->Yi.c, iv, 12);
        ctx->Yi.c[12] = 0;
        ctx->Yi.c[13] = 0;
        ctx->Yi.c[14] = 0;
        ctx->Yi.c[15] = 1;
        ctr = 1;
    } else {
        size_t i;
        uint64_t len0 = len;

        /* Borrow ctx->Xi to calculate initial Yi */
        ctx->Xi.u[0] = 0;
        ctx->Xi.u[1] = 0;

        while (len >= 16) {
            for (i = 0; i < 16; ++i)
                ctx->Xi.c[i] ^= iv[i];
            GCM_MUL(ctx);
            iv += 16;
            len -= 16;
        }
        if (len) {
            for (i = 0; i < len; ++i)
                ctx->Xi.c[i] ^= iv[i];
            GCM_MUL(ctx);
        }
        len0 <<= 3;
        if (is_endian.little) {
            ctx->Xi.u[1] ^= BSWAP8(len0);
        } else {
            ctx->Xi.u[1] ^= len0;
        }

        GCM_MUL(ctx);

        if (is_endian.little)
            ctr = BSWAP4(ctx->Xi.d[3]);
        else
            ctr = ctx->Xi.d[3];

        /* Copy borrowed Xi to Yi */
        ctx->Yi.u[0] = ctx->Xi.u[0];
        ctx->Yi.u[1] = ctx->Xi.u[1];
    }

    ctx->Xi.u[0] = 0;
    ctx->Xi.u[1] = 0;

    (*ctx->block) (ctx->Yi.c, ctx->EK0.c, ctx->key);
    ++ctr;
    if (is_endian.little)
        ctx->Yi.d[3] = BSWAP4(ctr);
    else
        ctx->Yi.d[3] = ctr;
}

int _crypto_gcm128_aad(_gcm128_context_t *ctx, const unsigned char *aad,
                      size_t len)
{
    size_t i;
    unsigned int n;
    uint64_t alen = ctx->len.u[0];
    void (*_gcm_gmult_p) (uint64_t Xi[2], const u128 Htable[16]) = ctx->gmult;
    void (*_gcm_ghash_p) (uint64_t Xi[2], const u128 Htable[16],
                         const uint8_t *inp, size_t len) = ctx->ghash;

    if (ctx->len.u[1])
        return -2;

    alen += len;
    if (alen > (U64(1) << 61) || (sizeof(len) == 8 && alen < len))
        return -1;
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if (n) {
        while (n && len) {
            ctx->Xi.c[n] ^= *(aad++);
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0)
            GCM_MUL(ctx);
        else {
            ctx->ares = n;
            return 0;
        }
    }
    if ((i = (len & (size_t)-16))) {
        GHASH(ctx, aad, i);
        aad += i;
        len -= i;
    }
    if (len) {
        n = (unsigned int)len;
        for (i = 0; i < len; ++i)
            ctx->Xi.c[i] ^= aad[i];
    }

    ctx->ares = n;
    return 0;
}

int _crypto_gcm128_encrypt_ctr32(_gcm128_context_t *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ctr128_f stream)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr, mres;
    size_t i;
    uint64_t mlen = ctx->len.u[1];
    void *key = ctx->key;
    void (*_gcm_gmult_p) (uint64_t Xi[2], const u128 Htable[16]) = ctx->gmult;
    void (*_gcm_ghash_p) (uint64_t Xi[2], const u128 Htable[16],
                         const uint8_t *inp, size_t len) = ctx->ghash;

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    mres = ctx->mres;

    if (ctx->ares) {
        /* First call to encrypt finalizes GHASH(AAD) */
        if (len == 0) {
            GCM_MUL(ctx);
            ctx->ares = 0;
            return 0;
        }
        memcpy(ctx->Xn, ctx->Xi.c, sizeof(ctx->Xi));
        ctx->Xi.u[0] = 0;
        ctx->Xi.u[1] = 0;
        mres = sizeof(ctx->Xi);
        ctx->ares = 0;
    }

    if (is_endian.little)
        ctr = BSWAP4(ctx->Yi.d[3]);
    else
        ctr = ctx->Yi.d[3];

    n = mres % 16;
    if (n) {
        while (n && len) {
            ctx->Xn[mres++] = *(out++) = *(in++) ^ ctx->EKi.c[n];
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0) {
            GHASH(ctx, ctx->Xn, mres);
            mres = 0;
        } else {
            ctx->mres = mres;
            return 0;
        }
    }
        if (len >= 16 && mres) {
            GHASH(ctx, ctx->Xn, mres);
            mres = 0;
        }
    while (len >= GHASH_CHUNK) {
        (*stream) (in, out, GHASH_CHUNK / 16, key, ctx->Yi.c);
        ctr += GHASH_CHUNK / 16;
        if (is_endian.little)
            ctx->Yi.d[3] = BSWAP4(ctr);
        else
            ctx->Yi.d[3] = ctr;
        GHASH(ctx, out, GHASH_CHUNK);
        out += GHASH_CHUNK;
        in += GHASH_CHUNK;
        len -= GHASH_CHUNK;
    }
    if ((i = (len & (size_t)-16))) {
        size_t j = i / 16;

        (*stream) (in, out, j, key, ctx->Yi.c);
        ctr += (unsigned int)j;
        if (is_endian.little)
            ctx->Yi.d[3] = BSWAP4(ctr);
        else
            ctx->Yi.d[3] = ctr;
        in += i;
        len -= i;
        GHASH(ctx, out, i);
        out += i;
    }
    if (len) {
        (*ctx->block) (ctx->Yi.c, ctx->EKi.c, key);
        ++ctr;
        if (is_endian.little)
            ctx->Yi.d[3] = BSWAP4(ctr);
        else
            ctx->Yi.d[3] = ctr;
        while (len--) {
            ctx->Xn[mres++] = out[n] = in[n] ^ ctx->EKi.c[n];
            ++n;
        }
    }

    ctx->mres = mres;
    return 0;
}

int _crypto_gcm128_decrypt_ctr32(_gcm128_context_t *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ctr128_f stream)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr, mres;
    size_t i;
    uint64_t mlen = ctx->len.u[1];
    void *key = ctx->key;
    void (*_gcm_gmult_p) (uint64_t Xi[2], const u128 Htable[16]) = ctx->gmult;
    void (*_gcm_ghash_p) (uint64_t Xi[2], const u128 Htable[16],
                         const uint8_t *inp, size_t len) = ctx->ghash;

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    mres = ctx->mres;

    if (ctx->ares) {
        /* First call to decrypt finalizes GHASH(AAD) */
        if (len == 0) {
            GCM_MUL(ctx);
            ctx->ares = 0;
            return 0;
        }
        memcpy(ctx->Xn, ctx->Xi.c, sizeof(ctx->Xi));
        ctx->Xi.u[0] = 0;
        ctx->Xi.u[1] = 0;
        mres = sizeof(ctx->Xi);
        ctx->ares = 0;
    }

    if (is_endian.little)
        ctr = BSWAP4(ctx->Yi.d[3]);
    else
        ctr = ctx->Yi.d[3];

    n = mres % 16;
    if (n) {
        while (n && len) {
            *(out++) = (ctx->Xn[mres++] = *(in++)) ^ ctx->EKi.c[n];
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0) {
            GHASH(ctx, ctx->Xn, mres);
            mres = 0;
        } else {
            ctx->mres = mres;
            return 0;
        }
    }
    if (len >= 16 && mres) {
        GHASH(ctx, ctx->Xn, mres);
        mres = 0;
    }
    while (len >= GHASH_CHUNK) {
        GHASH(ctx, in, GHASH_CHUNK);
        (*stream) (in, out, GHASH_CHUNK / 16, key, ctx->Yi.c);
        ctr += GHASH_CHUNK / 16;
        if (is_endian.little)
            ctx->Yi.d[3] = BSWAP4(ctr);
        else
            ctx->Yi.d[3] = ctr;
        out += GHASH_CHUNK;
        in += GHASH_CHUNK;
        len -= GHASH_CHUNK;
    }
    if ((i = (len & (size_t)-16))) {
        size_t j = i / 16;

        GHASH(ctx, in, i);
        (*stream) (in, out, j, key, ctx->Yi.c);
        ctr += (unsigned int)j;
        if (is_endian.little)
            ctx->Yi.d[3] = BSWAP4(ctr);
        else
            ctx->Yi.d[3] = ctr;
        out += i;
        in += i;
        len -= i;
    }
    if (len) {
        (*ctx->block) (ctx->Yi.c, ctx->EKi.c, key);
        ++ctr;
        if (is_endian.little)
            ctx->Yi.d[3] = BSWAP4(ctr);
        else
            ctx->Yi.d[3] = ctr;
        while (len--) {
            out[n] = (ctx->Xn[mres++] = in[n]) ^ ctx->EKi.c[n];
            ++n;
        }
    }

    ctx->mres = mres;
    return 0;
}

int _crypto_gcm128_finish(_gcm128_context_t *ctx, const unsigned char *tag,
                         size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    uint64_t alen = ctx->len.u[0] << 3;
    uint64_t clen = ctx->len.u[1] << 3;
    void (*_gcm_gmult_p) (uint64_t Xi[2], const u128 Htable[16]) = ctx->gmult;
    void (*_gcm_ghash_p) (uint64_t Xi[2], const u128 Htable[16],
                         const uint8_t *inp, size_t len) = ctx->ghash;

    u128 bitlen;
    unsigned int mres = ctx->mres;

    if (mres) {
        unsigned blocks = (mres + 15) & -16;

        memset(ctx->Xn + mres, 0, blocks - mres);
        mres = blocks;
        if (mres == sizeof(ctx->Xn)) {
            GHASH(ctx, ctx->Xn, mres);
            mres = 0;
        }
    } else if (ctx->ares) {
        GCM_MUL(ctx);
    }

    if (is_endian.little) {
        alen = BSWAP8(alen);
        clen = BSWAP8(clen);
    }

    bitlen.hi = alen;
    bitlen.lo = clen;
    memcpy(ctx->Xn + mres, &bitlen, sizeof(bitlen));
    mres += sizeof(bitlen);
    GHASH(ctx, ctx->Xn, mres);

    ctx->Xi.u[0] ^= ctx->EK0.u[0];
    ctx->Xi.u[1] ^= ctx->EK0.u[1];

    if (tag && len <= sizeof(ctx->Xi))
        return CRYPTO_memcmp(ctx->Xi.c, tag, len);
    else
        return -1;
}

void _crypto_gcm128_tag(_gcm128_context_t *ctx, unsigned char *tag, size_t len)
{
    _crypto_gcm128_finish(ctx, NULL, 0);
    memcpy(tag, ctx->Xi.c,
           len <= sizeof(ctx->Xi.c) ? len : sizeof(ctx->Xi.c));
}

_gcm128_context_t *_crypto_gcm128_new(void *key, block128_f block)
{
    _gcm128_context_t *ret;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) != NULL)
        _crypto_gcm128_init(ret, key, block);

    return ret;
}

void _crypto_gcm128_release(_gcm128_context_t *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}
#endif

static int csdk_128_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_128_aead_init_key++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_init(EVP_aes_128_gcm())(ctx, key, iv, enc);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_init(EVP_aria_128_gcm())(ctx, key, iv, enc);
#else
    CSDK_GCM_CTX *gctx = (CSDK_GCM_CTX*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    (void) enc;
    if (!iv && !key)
        return 1;
    if (key) {

        _csdk_set_encrypt_key(key, iv, ctx);

        _crypto_gcm128_init((void*) &gctx->gcm, &gctx->ks, (block128_f) _csdk_encrypt);
        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            _crypto_gcm128_setiv((void*) &gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    }
    else
    {
        /* If key set use IV, otherwise copy */
        if (gctx->key_set)
            _crypto_gcm128_setiv((void*) &gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
#endif
}


static int csdk_128_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_128_aead_ctrl++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_ctrl(EVP_aes_128_gcm())(ctx, type, arg, ptr);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_ctrl(EVP_aria_128_gcm())(ctx, type, arg, ptr);
#else

    CSDK_GCM_CTX *gctx = (CSDK_GCM_CTX*) EVP_CIPHER_CTX_get_cipher_data(ctx);

    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_CTX_iv_length(ctx);
        gctx->iv = EVP_CIPHER_CTX_iv_noconst(ctx);
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;
        /* Allocate memory for IV if needed */
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(ctx))
                OPENSSL_free(gctx->iv);
            if ((gctx->iv = OPENSSL_malloc(arg)) == NULL) {
                return 0;
            }
        }
        gctx->ivlen = arg;
        return 1;

    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = gctx->ivlen;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(ctx))
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, arg);
        gctx->taglen = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(ctx)
            || gctx->taglen < 0)
            return 0;
        memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(ctx), arg);
        return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
        /* Special case: -1 length restores whole IV */
        if (arg == -1) {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
        }
        /*
         * Fixed field must be at least 4 bytes and invocation field at least
         * 8.
         */
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (EVP_CIPHER_CTX_encrypting(ctx)
            && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;

    case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        _crypto_gcm128_setiv((void*) &gctx->gcm, gctx->iv, gctx->ivlen);
        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        /*
         * Invocation field will be at least 8 bytes in size and so no need
         * to check wrap around or increment more than last 8 bytes.
         */
        ctr64_inc(gctx->iv + gctx->ivlen - 8);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0
            || EVP_CIPHER_CTX_encrypting(ctx))
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        _crypto_gcm128_setiv((void*) &gctx->gcm, gctx->iv, gctx->ivlen);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            CSDK_GCM_CTX *gctx_out = (CSDK_GCM_CTX*) EVP_CIPHER_CTX_get_cipher_data(out);
            if (gctx->gcm.key) {
                if (gctx->gcm.key != &gctx->ks)
                    return 0;
                gctx_out->gcm.key = &gctx_out->ks;
            }
            if (gctx->iv == EVP_CIPHER_CTX_iv_noconst(ctx))
                gctx_out->iv = EVP_CIPHER_CTX_iv_noconst(out);
            else {
                if ((gctx_out->iv = OPENSSL_malloc(gctx->ivlen)) == NULL) {
                    return 0;
                }
                memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
            }
            return 1;
        }

    default:
        return -1;

    }

#endif
}

static int csdk_128_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_128_aead_cipher++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_do_cipher(EVP_aes_128_gcm())(ctx, out, in, len);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_do_cipher(EVP_aria_128_gcm())(ctx, out, in, len);
#else
    CSDK_GCM_CTX *gctx = (CSDK_GCM_CTX*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    /* If not set up, return error */
    if (!gctx->key_set)
        return -1;
    if (!gctx->iv_set)
        return -1;
    if (in) {
        if (out == NULL) {
            if (_crypto_gcm128_aad((void*) &gctx->gcm, in, len))
                return -1;
        } else if (EVP_CIPHER_CTX_encrypting(ctx)) {
            if (_crypto_gcm128_encrypt_ctr32((void*) &gctx->gcm, in, out, len, (ctr128_f) _csdk_encrypt_ctr32))
                return -1;
        } else {
            if (_crypto_gcm128_decrypt_ctr32((void*) &gctx->gcm, in, out, len, (ctr128_f) _csdk_encrypt_ctr32))
                return -1;
        }
        return len;
    }
    if (!EVP_CIPHER_CTX_encrypting(ctx)) {
        if (gctx->taglen < 0)
            return -1;
        if (_crypto_gcm128_finish((void*) &gctx->gcm,
                                 EVP_CIPHER_CTX_buf_noconst(ctx),
                                 gctx->taglen) != 0)
            return -1;
        gctx->iv_set = 0;
        return 0;
    }
    _crypto_gcm128_tag((void*) &gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx), 16);
    gctx->taglen = 16;
    /* Don't reuse the IV */
    gctx->iv_set = 0;
    return 0;
#endif
}

static int csdk_128_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_cleanup(EVP_aes_128_gcm())(ctx);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_cleanup(EVP_aria_128_gcm())(ctx);
#else
    CSDK_GCM_CTX *gctx = (CSDK_GCM_CTX*) EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(ctx))
        OPENSSL_free(gctx->iv);

    return 1;
#endif
}

static EVP_CIPHER *_hidden_128_gcm = NULL;

#define CSDK_GCM_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY |EVP_CIPH_FLAG_AEAD_CIPHER \
                | EVP_CIPH_GCM_MODE)

static const EVP_CIPHER *csdk_cipher_128_gcm(void)
{
#ifdef CSDK_CIPHER_TARGET_aes
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aes_128_gcm());
#elif CSDK_CIPHER_TARGET_aria
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aria_128_gcm());
#else
    size_t s = sizeof(CSDK_GCM_CTX);
#endif
    if (_hidden_128_gcm == NULL
        && ((_hidden_128_gcm = EVP_CIPHER_meth_new(NID_aes_128_gcm,
                                                       1  /* block size */,
                                                       16 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_128_gcm,12)
            || !EVP_CIPHER_meth_set_flags(_hidden_128_gcm, CSDK_GCM_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_128_gcm, csdk_128_gcm_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_128_gcm, csdk_128_gcm_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_128_gcm, csdk_128_gcm_ctrl)
            || !EVP_CIPHER_meth_set_cleanup(_hidden_128_gcm, csdk_128_gcm_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_128_gcm, s)))
    {
        EVP_CIPHER_meth_free(_hidden_128_gcm);
        _hidden_128_gcm = NULL;
    }
    return _hidden_128_gcm;
}

static int csdk_256_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_256_aead_init_key++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_init(EVP_aes_256_gcm())(ctx, key, iv, enc);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_init(EVP_aria_256_gcm())(ctx, key, iv, enc);
#else
    CSDK_GCM_CTX *gctx = (CSDK_GCM_CTX*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    (void) enc;
    if (!iv && !key)
        return 1;
    if (key) {
        _csdk_set_encrypt_key(key, iv, ctx);
        _crypto_gcm128_init((void*) &gctx->gcm, &gctx->ks, (block128_f) _csdk_encrypt);
        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            _crypto_gcm128_setiv((void*) &gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    }
    else
    {
        /* If key set use IV, otherwise copy */
        if (gctx->key_set)
            _crypto_gcm128_setiv((void*) &gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
#endif
}


static int csdk_256_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_256_aead_ctrl++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_ctrl(EVP_aes_256_gcm())(ctx, type, arg, ptr);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_ctrl(EVP_aria_256_gcm())(ctx, type, arg, ptr);
#else
    CSDK_GCM_CTX *gctx = (CSDK_GCM_CTX*) EVP_CIPHER_CTX_get_cipher_data(ctx);

    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_CTX_iv_length(ctx);
        gctx->iv = EVP_CIPHER_CTX_iv_noconst(ctx);
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;
        /* Allocate memory for IV if needed */
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(ctx))
                OPENSSL_free(gctx->iv);
            if ((gctx->iv = OPENSSL_malloc(arg)) == NULL) {
                return 0;
            }
        }
        gctx->ivlen = arg;
        return 1;

    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = gctx->ivlen;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(ctx))
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, arg);
        gctx->taglen = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(ctx)
            || gctx->taglen < 0)
            return 0;
        memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(ctx), arg);
        return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
        /* Special case: -1 length restores whole IV */
        if (arg == -1) {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
        }
        /*
         * Fixed field must be at least 4 bytes and invocation field at least
         * 8.
         */
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (EVP_CIPHER_CTX_encrypting(ctx)
            && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;

    case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        _crypto_gcm128_setiv((void*) &gctx->gcm, gctx->iv, gctx->ivlen);
        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        /*
         * Invocation field will be at least 8 bytes in size and so no need
         * to check wrap around or increment more than last 8 bytes.
         */
        ctr64_inc(gctx->iv + gctx->ivlen - 8);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0
            || EVP_CIPHER_CTX_encrypting(ctx))
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        _crypto_gcm128_setiv((void*) &gctx->gcm, gctx->iv, gctx->ivlen);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            CSDK_GCM_CTX *gctx_out = (CSDK_GCM_CTX*) EVP_CIPHER_CTX_get_cipher_data(out);
            if (gctx->gcm.key) {
                if (gctx->gcm.key != &gctx->ks)
                    return 0;
                gctx_out->gcm.key = &gctx_out->ks;
            }
            if (gctx->iv == EVP_CIPHER_CTX_iv_noconst(ctx))
                gctx_out->iv = EVP_CIPHER_CTX_iv_noconst(out);
            else {
                if ((gctx_out->iv = OPENSSL_malloc(gctx->ivlen)) == NULL) {
                    return 0;
                }
                memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
            }
            return 1;
        }

    default:
        return -1;

    }
#endif
}

static int csdk_256_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    csdk_stats_t * d = (csdk_stats_t*) EVP_CIPHER_CTX_get_app_data(ctx);
    if (d) (d)->csdk_256_aead_cipher++;
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_do_cipher(EVP_aes_256_gcm())(ctx, out, in , len);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_do_cipher(EVP_aria_256_gcm())(ctx, out, in , len);
#else
    CSDK_GCM_CTX *gctx = (CSDK_GCM_CTX*) EVP_CIPHER_CTX_get_cipher_data(ctx);

    /* If not set up, return error */
    if (!gctx->key_set)
        return -1;
    if (!gctx->iv_set)
        return -1;
    if (in) {
        if (out == NULL) {
            if (_crypto_gcm128_aad((void*) &gctx->gcm, in, len))
                return -1;
        } else if (EVP_CIPHER_CTX_encrypting(ctx)) {
            if (_crypto_gcm128_encrypt_ctr32((void*) &gctx->gcm, in, out, len, (ctr128_f) _csdk_encrypt_ctr32))
                return -1;
        } else {
            if (_crypto_gcm128_decrypt_ctr32((void*) &gctx->gcm, in, out, len, (ctr128_f) _csdk_encrypt_ctr32))
                return -1;
        }
        return len;
    }
    if (!EVP_CIPHER_CTX_encrypting(ctx)) {
        if (gctx->taglen < 0)
            return -1;
        if (_crypto_gcm128_finish((void*) &gctx->gcm,
                                 EVP_CIPHER_CTX_buf_noconst(ctx),
                                 gctx->taglen) != 0)
            return -1;
        gctx->iv_set = 0;
        return 0;
    }
    _crypto_gcm128_tag((void*) &gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx), 16);
    gctx->taglen = 16;
    /* Don't reuse the IV */
    gctx->iv_set = 0;
    return 0;
#endif
}

static int csdk_256_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
#ifdef CSDK_CIPHER_TARGET_aes
    return EVP_CIPHER_meth_get_cleanup(EVP_aes_256_gcm())(ctx);
#elif CSDK_CIPHER_TARGET_aria
    return EVP_CIPHER_meth_get_cleanup(EVP_aria_256_gcm())(ctx);
#else
    CSDK_GCM_CTX *gctx = (CSDK_GCM_CTX*) EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(ctx))
        OPENSSL_free(gctx->iv);

    return 1;
#endif
}

static EVP_CIPHER *_hidden_256_gcm = NULL;

#define CSDK_GCM_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY |EVP_CIPH_FLAG_AEAD_CIPHER \
                | EVP_CIPH_GCM_MODE)

static const EVP_CIPHER *csdk_cipher_256_gcm(void)
{
#ifdef CSDK_CIPHER_TARGET_aes
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aes_256_gcm());
#elif CSDK_CIPHER_TARGET_aria
    size_t s = EVP_CIPHER_impl_ctx_size(EVP_aria_256_gcm());
#else
    size_t s = sizeof(CSDK_GCM_CTX);
#endif
    if (_hidden_256_gcm == NULL
        && ((_hidden_256_gcm = EVP_CIPHER_meth_new(NID_aes_256_gcm,
                                                       1  /* block size */,
                                                       32 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_256_gcm,12)
            || !EVP_CIPHER_meth_set_flags(_hidden_256_gcm, CSDK_GCM_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_256_gcm, csdk_256_gcm_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_256_gcm, csdk_256_gcm_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_256_gcm, csdk_256_gcm_ctrl)
            || !EVP_CIPHER_meth_set_cleanup(_hidden_256_gcm, csdk_256_gcm_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_256_gcm, s)))
    {
        EVP_CIPHER_meth_free(_hidden_256_gcm);
        _hidden_256_gcm = NULL;
    }
    return _hidden_256_gcm;
}

#endif

#ifdef CSDK_CIPHER_TARGET_chacha20_poly1305

static EVP_CIPHER *_hidden_chacha20_poly1305 = NULL;

#define CSDK_CHACHA20_POLY1305_FLAGS   ( \
        EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_CUSTOM_IV | \
    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT |  \
        EVP_CIPH_CUSTOM_COPY | EVP_CIPH_FLAG_CUSTOM_CIPHER | \
        EVP_CIPH_CUSTOM_IV_LENGTH )

static const EVP_CIPHER *csdk_cipher_chacha20_poly1305(void)
{
    if (_hidden_chacha20_poly1305 == NULL
        && ((_hidden_chacha20_poly1305 = EVP_CIPHER_meth_new(NID_chacha20_poly1305,
                                            1               /* block size */,
                                            CHACHA_KEY_SIZE /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_chacha20_poly1305,12)
            || !EVP_CIPHER_meth_set_flags(_hidden_chacha20_poly1305, CSDK_CHACHA20_POLY1305_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_chacha20_poly1305, csdk_chacha20_poly1305_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_chacha20_poly1305, csdk_chacha20_poly1305_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_chacha20_poly1305, csdk_chacha20_poly1305_ctrl)
            || !EVP_CIPHER_meth_set_cleanup(_hidden_chacha20_poly1305, csdk_chacha20_poly1305_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_chacha20_poly1305, 0) /* 0 moves context-specific structure allocation to ctrl */
        ))
    {
        EVP_CIPHER_meth_free(_hidden_chacha20_poly1305);
        _hidden_chacha20_poly1305 = NULL;
    }
    return _hidden_chacha20_poly1305;
}

#endif

void csdk_destroy_ciphers(void)
{
#ifdef CSDK_CIPHER_TARGET_chacha20_poly1305
    EVP_CIPHER_meth_free(_hidden_chacha20_poly1305); _hidden_chacha20_poly1305 = NULL;
#else
    EVP_CIPHER_meth_free(_hidden_128_cfb); _hidden_128_cfb = NULL;
    EVP_CIPHER_meth_free(_hidden_256_cfb); _hidden_256_cfb = NULL;
    EVP_CIPHER_meth_free(_hidden_128_ctr); _hidden_128_ctr = NULL;
    EVP_CIPHER_meth_free(_hidden_256_ctr); _hidden_256_ctr = NULL;
    EVP_CIPHER_meth_free(_hidden_128_gcm); _hidden_128_gcm = NULL;
    EVP_CIPHER_meth_free(_hidden_256_gcm); _hidden_256_gcm = NULL;
#endif
}


static int csdk_cipher_nids[] = {
#ifdef CSDK_CIPHER_TARGET_chacha20_poly1305
    NID_chacha20_poly1305,
#else
    NID_aes_128_cfb128,
    NID_aes_256_cfb128,
    NID_aes_128_ctr,
    NID_aes_256_ctr,
    NID_aes_128_gcm,
    NID_aes_256_gcm,
#endif
    0
};
#if CHECK_REGS
static void print_leaf7_features(uint32_t ebx, uint32_t ecx) {
    struct { uint32_t mask; const char *name; } ebx_feats[] = {
        {1u << 5,  "AVX2"},
        {1u << 3,  "BMI1"},
        {1u << 8,  "BMI2"},
        {1u << 19, "ADX"},
        {1u << 29, "SHA"},
        {1u << 16, "AVX512F"},
        {1u << 17, "AVX512DQ"},
        {1u << 21, "AVX512IFMA"},
        {1u << 26, "AVX512PF"},
        {1u << 27, "AVX512ER"},
        {1u << 28, "AVX512CD"},
        {1u << 30, "AVX512BW"},
        {1u << 31, "AVX512VL"},
        {1u << 23, "CLFLUSHOPT"},
        {1u << 24, "CLWB"},
        {1u << 25, "INTEL_PT"},
    };
    struct { uint32_t mask; const char *name; } ecx_feats[] = {
        {1u << 9,  "VAES"},
        {1u << 10, "VPCLMULQDQ"},
        {1u << 11, "AVX512VNNI"},
        {1u << 12, "AVX512BITALG"},
        {1u << 14, "AVX512VPOPCNTDQ"},
        {1u << 1,  "AVX512VBMI"},
        {1u << 6,  "AVX512VBMI2"},
        {1u << 8,  "GFNI"},
        {1u << 22, "AVX512VP2INTERSECT"},
        {1u << 0,  "PREFETCHWT1"},
        {1u << 3,  "PKU"},
        {1u << 4,  "OSPKE"},
        {1u << 16, "RDPID"},
    };

    int first = 1;
    printf("Leaf7 EBX features:");
    for (size_t i = 0; i < sizeof(ebx_feats)/sizeof(ebx_feats[0]); i++) {
        if (ebx & ebx_feats[i].mask) {
            printf("%s%s", first ? " " : " | ", ebx_feats[i].name);
            first = 0;
        }
    }
    if (first) printf(" none");
    printf("\n");

    first = 1;
    printf("Leaf7 ECX features:");
    for (size_t i = 0; i < sizeof(ecx_feats)/sizeof(ecx_feats[0]); i++) {
        if (ecx & ecx_feats[i].mask) {
            printf("%s%s", first ? " " : " | ", ecx_feats[i].name);
            first = 0;
        }
    }
    if (first) printf(" none");
    printf("\n");
}
#endif

int csdk_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                          const int **nids, int nid)
{
    uint64_t caps = _OPENSSL_ia32_cpuid(_OPENSSL_ia32cap_P);
    int ok = 1;
    (void) e;

    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = csdk_cipher_nids;
        return (sizeof(csdk_cipher_nids) - 1)/sizeof(csdk_cipher_nids[0]);
    }
    _OPENSSL_ia32cap_P[0] = (uint32_t) (caps & 0xffffffff); // convert to legacy EDX
    _OPENSSL_ia32cap_P[1] = (uint32_t) (caps >> 32);        // and ECX registers
#ifdef CHECK_REGS
    print_leaf7_features(_OPENSSL_ia32cap_P[0], _OPENSSL_ia32cap_P[1]);
#endif
    /* We are being asked for a specific cipher */
    switch (nid) {
#ifdef CSDK_CIPHER_TARGET_chacha20_poly1305
    case NID_chacha20_poly1305:
        //_OPENSSL_ia32_cpuid(_OPENSSL_ia32cap_P); // check this
        *cipher = csdk_cipher_chacha20_poly1305();
        break;
#else
    case NID_aes_128_cfb128:
        *cipher = csdk_cipher_128_cfb();
        break;
    case NID_aes_256_cfb128:
        *cipher = csdk_cipher_256_cfb();
        break;
    case NID_aes_128_ctr:
        *cipher = csdk_cipher_128_ctr();
        break;
    case NID_aes_256_ctr:
        *cipher = csdk_cipher_256_ctr();
        break;
    case NID_aes_128_gcm:
        *cipher = csdk_cipher_128_gcm();
        break;
    case NID_aes_256_gcm:
        *cipher = csdk_cipher_256_gcm();
    break;
#endif
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }
    return ok;
}
