/*
 * XOR cipher hook.
 *
 * Included from csdk_ciphers.c for CSDK_CIPHER_TARGET_xor.
 * Each block is XORed with the raw key. A 256-bit key XORs both halves.
 * This is the smallest working example of the four cipher hooks.
 *
 * csdk_key_st holds the key size in bits (ks), the block size in bytes (bs),
 * and the raw key. The GCM context follows the OpenSSL layout so the mode
 * layer can run GHASH over it. Do not reorder those fields.
 */

#include <emmintrin.h>

/* Key schedule. The raw key is 16-byte aligned for the SSE loads. */
typedef struct __attribute__((packed, aligned(16))) csdk_key_st {
    int ks; /* key size in bits */
    int bs; /* cipher block size in bytes */
    unsigned char dummy[8]; /* pad so key is 16-byte aligned */
    unsigned char key[32];
} CSDK_KEY;

extern void _ctr32_encrypt_blocks(const unsigned char *in,
                                  unsigned char *out,
                                  size_t blocks,
                                  const CSDK_KEY *key,
                                  const unsigned char ivec[16]);

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

typedef struct __attribute__((packed, aligned(16))) csdk_gcm_st_s {
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

/* Copy the raw key. XOR uses the same bytes to encrypt and decrypt. */
static int xor_set_key(const unsigned char *userKey, EVP_CIPHER_CTX *ctx,
                       CSDK_KEY *key)
{
    key->ks = EVP_CIPHER_CTX_key_length(ctx) * 8;
    key->bs = 16;
    memcpy(key->key, userKey, EVP_CIPHER_CTX_key_length(ctx));
    return 0;
}

/* Decrypt key setup for CFB, CTR, and GCM. */
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
        CSDK_KEY *key = EVP_CIPHER_CTX_get_cipher_data(ctx);

        xor_set_key(userKey, ctx, key);
        break;
    }
    case NID_aes_128_gcm:
    case NID_aes_256_gcm: {
        CSDK_GCM_CTX *gctx = EVP_CIPHER_CTX_get_cipher_data(ctx);

        xor_set_key(userKey, ctx, &gctx->ks.ks);
        break;
    }
    default:
        break;
    }
    return 0;
}

/* Encrypt key setup for CFB, CTR, and GCM. */
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
        CSDK_KEY *key = EVP_CIPHER_CTX_get_cipher_data(ctx);

        xor_set_key(userKey, ctx, key);
        break;
    }
    case NID_aes_128_gcm:
    case NID_aes_256_gcm: {
        CSDK_GCM_CTX *gctx = EVP_CIPHER_CTX_get_cipher_data(ctx);

        xor_set_key(userKey, ctx, &gctx->ks.ks);
        break;
    }
    default:
        break;
    }
    return 0;
}

/* XOR one block with the key. A key longer than one block XORs the rest too. */
void _csdk_encrypt(const unsigned char *in, unsigned char *out,
                   const CSDK_KEY *key)
{
    __m128i block = _mm_loadu_si128((const __m128i *)in);
    __m128i mask = _mm_load_si128((const __m128i *)key->key);

    block = _mm_xor_si128(block, mask);
    if (key->ks / 8 > key->bs) {
        mask = _mm_load_si128((const __m128i *)&key->key[key->bs]);
        block = _mm_xor_si128(block, mask);
    }
    _mm_storeu_si128((__m128i *)out, block);
}

/* CTR encrypt, in the assembly helper. */
static inline __attribute__((always_inline))
void _csdk_encrypt_ctr32(const unsigned char *in, unsigned char *out,
                         size_t blocks, const CSDK_KEY *key,
                         const unsigned char ivec[16])
{
    _ctr32_encrypt_blocks(in, out, blocks, key, ivec);
}
