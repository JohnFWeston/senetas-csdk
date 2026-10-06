/*
 * Copyright 2010-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "modes_local.h"
#include <string.h>

#if defined(__GNUC__) && !defined(STRICT_ALIGNMENT)
typedef size_t size_t_aX __attribute((__aligned__(1)));
#else
typedef size_t size_t_aX;
#endif

#if defined(BSWAP4) && defined(STRICT_ALIGNMENT)
/* redefine, because alignment is ensured */
# undef  GETU32
# define GETU32(p)       BSWAP4(*(const u32 *)(p))
# undef  PUTU32
# define PUTU32(p,v)     *(u32 *)(p) = BSWAP4(v)
#endif

#define PACK(s)         ((size_t)(s)<<(sizeof(size_t)*8-16))
#define REDUCE1BIT(V)   do { \
        if (sizeof(size_t)==8) { \
                u64 T = U64(0xe100000000000000) & (0-(V.lo&1)); \
                V.lo  = (V.hi<<63)|(V.lo>>1); \
                V.hi  = (V.hi>>1 )^T; \
        } \
        else { \
                u32 T = 0xe1000000U & (0-(u32)(V.lo&1)); \
                V.lo  = (V.hi<<63)|(V.lo>>1); \
                V.hi  = (V.hi>>1 )^((u64)T<<32); \
        } \
} while(0)

static void gcm_init_4bit(u128 Htable[16], u64 H[2])
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

void gcm_gmult_4bit(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_4bit(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                    size_t len);

# define GCM_MUL(ctx)      gcm_gmult_4bit(ctx->Xi.u,ctx->Htable)
#  define GHASH(ctx,in,len) gcm_ghash_4bit((ctx)->Xi.u,(ctx)->Htable,in,len)
/*
 * GHASH_CHUNK is "stride parameter" missioned to mitigate cache trashing
 * effect. In other words idea is to hash data while it's still in L1 cache
 * after encryption pass...
 */
#  define GHASH_CHUNK       (3*1024)
#  define GHASH_ASM_X86_OR_64
extern unsigned int OPENSSL_ia32cap_P[];

void gcm_init_clmul(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_clmul(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_clmul(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                     size_t len);

void gcm_init_avx(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_avx(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_avx(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                   size_t len);

# undef  GCM_MUL
# define GCM_MUL(ctx)           (*gcm_gmult_p)(ctx->Xi.u,ctx->Htable)
#  undef  GHASH
#  define GHASH(ctx,in,len)     (*gcm_ghash_p)(ctx->Xi.u,ctx->Htable,in,len)

void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key, block128_f block)
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
    if (OPENSSL_ia32cap_P[1] & (1 << 1)) { /* check PCLMULQDQ bit */
        if (((OPENSSL_ia32cap_P[1] >> 22) & 0x41) == 0x41) { /* AVX+MOVBE */
            gcm_init_avx(ctx->Htable, ctx->H.u);
            ctx->gmult = gcm_gmult_avx;
            CTX__GHASH(gcm_ghash_avx);
        } else {
            gcm_init_clmul(ctx->Htable, ctx->H.u);
            ctx->gmult = gcm_gmult_clmul;
            CTX__GHASH(gcm_ghash_clmul);
        }
        return;
    }
    gcm_init_4bit(ctx->Htable, ctx->H.u);
    ctx->gmult = gcm_gmult_4bit;
    CTX__GHASH(gcm_ghash_4bit);
# undef CTX__GHASH
}

void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv,
                         size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int ctr;
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;

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
        u64 len0 = len;

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

int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
                      size_t len)
{
    size_t i;
    unsigned int n;
    u64 alen = ctx->len.u[0];
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;

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

int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr, mres;
    size_t i;
    u64 mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;

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
    if (16 % sizeof(size_t) == 0) { /* always true actually */
        do {
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
                size_t j = GHASH_CHUNK;

                while (j) {
                    size_t_aX *out_t = (size_t_aX *)out;
                    const size_t_aX *in_t = (const size_t_aX *)in;

                    (*block) (ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if (is_endian.little)
                        ctx->Yi.d[3] = BSWAP4(ctr);
                    else
                        ctx->Yi.d[3] = ctr;
                    for (i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    j -= 16;
                }
                GHASH(ctx, out - GHASH_CHUNK, GHASH_CHUNK);
                len -= GHASH_CHUNK;
            }
            if ((i = (len & (size_t)-16))) {
                size_t j = i;

                while (len >= 16) {
                    size_t_aX *out_t = (size_t_aX *)out;
                    const size_t_aX *in_t = (const size_t_aX *)in;

                    (*block) (ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if (is_endian.little)
                        ctx->Yi.d[3] = BSWAP4(ctr);
                    else
                        ctx->Yi.d[3] = ctr;
                    for (i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    len -= 16;
                }
                GHASH(ctx, out - j, j);
            }
            if (len) {
                (*block) (ctx->Yi.c, ctx->EKi.c, key);
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
        } while (0);
    }
    for (i = 0; i < len; ++i) {
        if (n == 0) {
            (*block) (ctx->Yi.c, ctx->EKi.c, key);
            ++ctr;
            if (is_endian.little)
                ctx->Yi.d[3] = BSWAP4(ctr);
            else
                ctx->Yi.d[3] = ctr;
        }
        ctx->Xn[mres++] = out[i] = in[i] ^ ctx->EKi.c[n];
        n = (n + 1) % 16;
        if (mres == sizeof(ctx->Xn)) {
            GHASH(ctx,ctx->Xn,sizeof(ctx->Xn));
            mres = 0;
        }
    }

    ctx->mres = mres;
    return 0;
}

int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr, mres;
    size_t i;
    u64 mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;

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
    if (16 % sizeof(size_t) == 0) { /* always true actually */
        do {
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
                size_t j = GHASH_CHUNK;

                GHASH(ctx, in, GHASH_CHUNK);
                while (j) {
                    size_t_aX *out_t = (size_t_aX *)out;
                    const size_t_aX *in_t = (const size_t_aX *)in;

                    (*block) (ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if (is_endian.little)
                        ctx->Yi.d[3] = BSWAP4(ctr);
                    else
                        ctx->Yi.d[3] = ctr;
                    for (i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    j -= 16;
                }
                len -= GHASH_CHUNK;
            }
            if ((i = (len & (size_t)-16))) {
                GHASH(ctx, in, i);
                while (len >= 16) {
                    size_t_aX *out_t = (size_t_aX *)out;
                    const size_t_aX *in_t = (const size_t_aX *)in;

                    (*block) (ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if (is_endian.little)
                        ctx->Yi.d[3] = BSWAP4(ctr);
                    else
                        ctx->Yi.d[3] = ctr;
                    for (i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    len -= 16;
                }
            }
            if (len) {
                (*block) (ctx->Yi.c, ctx->EKi.c, key);
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
        } while (0);
    }
    for (i = 0; i < len; ++i) {
        u8 c;
        if (n == 0) {
            (*block) (ctx->Yi.c, ctx->EKi.c, key);
            ++ctr;
            if (is_endian.little)
                ctx->Yi.d[3] = BSWAP4(ctr);
            else
                ctx->Yi.d[3] = ctr;
        }
        out[i] = (ctx->Xn[mres++] = c = in[i]) ^ ctx->EKi.c[n];
        n = (n + 1) % 16;
        if (mres == sizeof(ctx->Xn)) {
            GHASH(ctx,ctx->Xn,sizeof(ctx->Xn));
            mres = 0;
        }
    }

    ctx->mres = mres;
    return 0;
}

int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ctr128_f stream)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr, mres;
    size_t i;
    u64 mlen = ctx->len.u[1];
    void *key = ctx->key;
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;

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

int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ctr128_f stream)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr, mres;
    size_t i;
    u64 mlen = ctx->len.u[1];
    void *key = ctx->key;
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;

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

int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx, const unsigned char *tag,
                         size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    u64 alen = ctx->len.u[0] << 3;
    u64 clen = ctx->len.u[1] << 3;
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;

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

void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len)
{
    CRYPTO_gcm128_finish(ctx, NULL, 0);
    memcpy(tag, ctx->Xi.c,
           len <= sizeof(ctx->Xi.c) ? len : sizeof(ctx->Xi.c));
}

GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block)
{
    GCM128_CONTEXT *ret;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) != NULL)
        CRYPTO_gcm128_init(ret, key, block);

    return ret;
}

void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}
