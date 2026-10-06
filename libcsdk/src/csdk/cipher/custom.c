/*
 * Empty cipher hook.
 *
 * Included from csdk_ciphers.c for CSDK_CIPHER_TARGET_custom.
 * The mode layer calls _csdk_set_encrypt_key, _csdk_set_decrypt_key,
 * _csdk_encrypt, and _csdk_encrypt_ctr32.
 *
 * csdk_key_st holds the key size in bits (ks), the block size in bytes (bs),
 * and any private key schedule. The GCM context follows the OpenSSL layout
 * so the mode layer can run GHASH over it. Do not reorder those fields.
 *
 * This target does not compile until the cipher calls replace the error below.
 */

#error "Insert the cipher implementation and call it from the hooks below."

/* Key schedule. ks is bits, bs is bytes. Private state goes below those two. */
struct csdk_key_st {
    int ks; /* key size in bits */
    int bs; /* cipher block size in bytes */

    /* Initialised by the set-key hooks and read by _csdk_encrypt. */
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
} csdk_gcm_st_t;
typedef struct csdk_gcm_st_s CSDK_GCM_CTX;

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
        CSDK_KEY *key = EVP_CIPHER_CTX_get_cipher_data(ctx);

        key->ks = EVP_CIPHER_CTX_key_length(ctx) * 8;
        key->bs = 16;
        /* Cipher-specific decrypt key schedule goes here. */
        break;
    }
    case NID_aes_128_gcm:
    case NID_aes_256_gcm: {
        CSDK_GCM_CTX *gctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
        CSDK_KEY *key = &gctx->ks.ks;

        key->ks = EVP_CIPHER_CTX_key_length(ctx) * 8;
        key->bs = 16;
        /* Cipher-specific decrypt key schedule goes here. */
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

        key->ks = EVP_CIPHER_CTX_key_length(ctx) * 8;
        key->bs = 16;
        /* Cipher-specific encrypt key schedule goes here. */
        break;
    }
    case NID_aes_128_gcm:
    case NID_aes_256_gcm: {
        CSDK_GCM_CTX *gctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
        CSDK_KEY *key = &gctx->ks.ks;

        key->ks = EVP_CIPHER_CTX_key_length(ctx) * 8;
        key->bs = 16;
        /* Cipher-specific encrypt key schedule goes here. */
        break;
    }
    default:
        break;
    }
    return 0;
}

/* Encrypt one block. CFB and GCM call this. */
static inline __attribute__((always_inline))
void _csdk_encrypt(const unsigned char *in, unsigned char *out,
                   const CSDK_KEY *key)
{
    (void)in;
    (void)out;
    (void)key;
    /* Block encrypt goes here. */
}

/* Encrypt CTR in 32-bit counter blocks. */
static inline __attribute__((always_inline))
void _csdk_encrypt_ctr32(const unsigned char *in, unsigned char *out,
                         size_t blocks, const CSDK_KEY *key,
                         const unsigned char ivec[16])
{
    (void)in;
    (void)out;
    (void)blocks;
    (void)key;
    (void)ivec;
    /* CTR encrypt goes here. It may call _csdk_encrypt per block. */
}
