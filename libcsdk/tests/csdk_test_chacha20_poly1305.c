/*
 * Self-test for the chacha20_poly1305 cipher target.
 *
 * Loads the libcsdk engine and checks known-answer vectors, then runs
 * unknown-answer round trips. A test returns 0 on success, -1 when it is
 * skipped, and a positive count of failures.
 */

#define _GNU_SOURCE
#include <stdio.h>

#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stddef.h>

#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/x509.h>

#include "../src/csdk/csdk.h"

BIO *bio_err = NULL;

#define TEST_FREE(s) do { if (s) { free((void *)s); s=NULL; } } while(0)

static csdk_stats_t stats = {0};



/*
 * KAT chacha20poly1305 test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_chacha20poly1305_enc( void )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;


    unsigned char ccpoly_key[] =
    {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };

    unsigned char ccpoly_iv[] =
    {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };

    unsigned char ccpoly_plaintext[] =
    {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };

    unsigned char ccpoly_ciphertext[] =
    {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };

    unsigned char ccpoly_tag[] =
    {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };

    unsigned char ccpoly_aad[] =
    {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };

    unsigned char ct[sizeof(ccpoly_ciphertext)] = {0};
    unsigned char tag[sizeof(ccpoly_tag)] = {0};

    type = EVP_chacha20_poly1305();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        errors++;
        goto err_enc;
    }
    EVP_CIPHER_CTX_set_app_data(ctx, (void*) &stats);

    if (!EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 1))
    {
        errors++;
        goto err_enc;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)sizeof(ccpoly_iv), NULL))
    {
        errors++;
        goto err_enc;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, ccpoly_key, ccpoly_iv, 1))
    {
        errors++;
        goto err_enc;
    }

    /* 96 bit IV */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, sizeof(ccpoly_iv), ccpoly_iv))
    {
        errors++;
        goto err_enc;
    }

    // aad
    if (!EVP_Cipher(ctx, NULL, ccpoly_aad, (unsigned int)sizeof(ccpoly_aad)))
    {
        errors++;
        goto err_enc;
    }
    if (EVP_Cipher(ctx, ct, ccpoly_plaintext, (unsigned int)sizeof(ccpoly_plaintext)) != (int)sizeof(ccpoly_plaintext))
    {
        errors++;
        goto err_enc;
    }
    if (EVP_Cipher(ctx, NULL, NULL, 0) < 0)
    {
        errors++;
        goto err_enc;
    }
    /* Get the tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)sizeof(tag), tag))
    {
        errors++;
        goto err_enc;
    }

    if(memcmp( ct, ccpoly_ciphertext, sizeof( ccpoly_ciphertext )) ||
       memcmp( tag, ccpoly_tag, sizeof( ccpoly_tag )))
    {
        errors++;
    }
err_enc:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return errors;

}

/*
 * KAT chacha20poly1305 decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_chacha20poly1305_dec( void )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;
    unsigned int integrity_error = 0;

    unsigned char  ccpoly_key[] =
    {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };

    unsigned char  ccpoly_iv[] =
    {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };
    unsigned char  ccpoly_plaintext[] =
    {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };
    unsigned char  ccpoly_ciphertext[] =
    {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    unsigned char  ccpoly_tag[] =
    {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    unsigned char  ccpoly_aad[] =
    {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };

    unsigned char pt[sizeof(ccpoly_plaintext)] = {0};

    type = EVP_chacha20_poly1305();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        errors++;
        goto err_dec;
    }

    EVP_CIPHER_CTX_set_app_data(ctx, (void*) &stats);

    if (!EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 0))
    {
        errors++;
        goto err_dec;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)sizeof(ccpoly_iv), NULL))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)sizeof(ccpoly_tag), ccpoly_tag))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, ccpoly_key, ccpoly_iv, 0))
    {
        errors++;
        goto err_dec;
    }

    /* 96 bit IV */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, sizeof(ccpoly_iv), ccpoly_iv))
    {
        errors++;
        goto err_dec;
    }

    if (!EVP_Cipher(ctx, NULL, ccpoly_aad, (unsigned int)sizeof(ccpoly_aad)))
    {
        errors++;
        goto err_dec;
    }
    integrity_error = 0;

    if (EVP_Cipher(ctx, pt, ccpoly_ciphertext, (unsigned int)sizeof(pt)) != (int)sizeof(pt))
    {
        integrity_error = 1;
    }

    if (EVP_Cipher(ctx, NULL, NULL, 0) < 0)
    {
        integrity_error = 1;
    }

    if(memcmp( pt, ccpoly_plaintext, sizeof( ccpoly_plaintext )) || integrity_error )
    {
        //printf( "KAT CHACHA20POLY1305 Decrypt Error\n" );
        errors++;
    }
err_dec:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return errors;
}


/*
 * UKAT chacha20poly1305 encrypt test - for application selftest access
 *
 * @param ct - returned ciphertext - call with NULL to get required max buffer size
 * @param tag - returned tag - call with NULL to get required max buffer size
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_chacha20poly1305_enc( unsigned char * ct, unsigned char * tag )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;

    unsigned char ccpoly_key[] =
    {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };

    unsigned char ccpoly_iv[] =
    {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };

    unsigned char ccpoly_plaintext[] =
    {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };
    unsigned char ccpoly_aad[] =
    {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };

    if (!ct)
        return (sizeof(ccpoly_plaintext));
    if (!tag)
        return (16);


    type = EVP_chacha20_poly1305();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        errors++;
        goto err_enc;
    }
    EVP_CIPHER_CTX_set_app_data(ctx, (void*) &stats);

    if (!EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 1))
    {
        errors++;
        goto err_enc;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)sizeof(ccpoly_iv), NULL))
    {
        errors++;
        goto err_enc;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, ccpoly_key, ccpoly_iv, 1))
    {
        errors++;
        goto err_enc;
    }

    /* 96 bit IV */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, sizeof(ccpoly_iv), ccpoly_iv))
    {
        errors++;
        goto err_enc;
    }

    // aad
    if (!EVP_Cipher(ctx, NULL, ccpoly_aad, (unsigned int)sizeof(ccpoly_aad)))
    {
        errors++;
        goto err_enc;
    }
    if (EVP_Cipher(ctx, ct, ccpoly_plaintext, (unsigned int)sizeof(ccpoly_plaintext)) != (int)sizeof(ccpoly_plaintext))
    {
        errors++;
        goto err_enc;
    }
    if (EVP_Cipher(ctx, NULL, NULL, 0) < 0)
    {
        errors++;
        goto err_enc;
    }
    /* Get the tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
    {
        errors++;
        goto err_enc;
    }

err_enc:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return errors;

}

/*
 * UKAT chacha20poly1305 decrypt test - for application selftest access
 *
 * @param pt - returned plaintext - call with NULL to get required max buffer size
 * @param integrity_error - 0 on success
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_chacha20poly1305_dec( unsigned char * pt, int * integrity_error )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;


    unsigned char  ccpoly_key[] =
    {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };

    unsigned char  ccpoly_iv[] =
    {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };
    unsigned char  ccpoly_ciphertext[] =
    {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    unsigned char  ccpoly_tag[] =
    {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    unsigned char  ccpoly_aad[] =
    {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };

    if (!pt)
        return (sizeof(ccpoly_ciphertext));
    if (!integrity_error)
    {
        errors++;
        goto err_dec;
    }
    *integrity_error = 0;

    type = EVP_chacha20_poly1305();

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        errors++;
        goto err_dec;
    }

    EVP_CIPHER_CTX_set_app_data(ctx, (void*) &stats);

    if (!EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 0))
    {
        errors++;
        goto err_dec;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)sizeof(ccpoly_iv), NULL))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)sizeof(ccpoly_tag), ccpoly_tag))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, ccpoly_key, ccpoly_iv, 0))
    {
        errors++;
        goto err_dec;
    }

    /* 96 bit IV */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, sizeof(ccpoly_iv), ccpoly_iv))
    {
        errors++;
        goto err_dec;
    }

    if (!EVP_Cipher(ctx, NULL, ccpoly_aad, (unsigned int)sizeof(ccpoly_aad)))
    {
        errors++;
        goto err_dec;
    }

    if (EVP_Cipher(ctx, pt, ccpoly_ciphertext, (unsigned int)sizeof(ccpoly_ciphertext)) != (int)sizeof(ccpoly_ciphertext))
    {
        *integrity_error = 1;
    }

    if (EVP_Cipher(ctx, NULL, NULL, 0) < 0)
    {
        *integrity_error = 1;
    }

err_dec:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return errors;
}

/*
 * setup initial openssl load and err reporting
 */
static void csdk_test_init(void)
{
    bio_err = BIO_new_fp(stdout, BIO_NOCLOSE);
    OPENSSL_init_crypto( OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_DYNAMIC, NULL);
}

/*
 * helper function to load openssl engine
 *
 * @param engine
 *
 * @return NULL on error or ENGINE ptr on success
 */
static ENGINE *try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e)
    {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0))
        {
            BIO_printf(bio_err, "engine ID %p failed to load\n", (void*)e);
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}

/*
 * setup engine by name and configure debug
 *
 * @param engine
 * @param debug
 *
 * @return
 */
static ENGINE *csdk_setup_engine(const char *engine, int debug)
{
    ENGINE *e = NULL;
    BIO_printf(bio_err, "Setting up engine (%s)\n", engine);
    if (engine)
    {
        if (strcmp(engine, "auto") == 0)
        {
            BIO_printf(bio_err, "enabling auto ENGINE support\n");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL && (e = try_load_engine(engine)) == NULL)
        {
            BIO_printf(bio_err, "invalid engine \"%s\"\n", engine);
            ERR_print_errors(bio_err);
            return NULL;
        }
        if (debug)
        {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0);
        }
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL))
        {
            BIO_printf(bio_err, "can't use that engine\n");
            ERR_print_errors(bio_err);
            ENGINE_free(e);
            return NULL;
        }

        BIO_printf(bio_err, "engine \"%s\" set (%s).\n", ENGINE_get_id(e), ENGINE_get_name(e));
    }
    return e;
}

/*
 * @param e
 */
void csdk_release_engine(ENGINE *e)
{
    if (e != NULL)
    {
        ENGINE_free(e);
    }
}

static void print_kat_result(const char * label, int err)
{
    switch (err)
    {
        case -1:
            printf("%s Skipped\n", label);
            break;
        case 0:
            printf("%s Passed\n", label);
            break;
        default:
            printf("%s FAILED\n", label);
            break;
   }
}

static int csdk_test_kat_symmetric( void )
{
    int errors = 0;
    int err = 0;

    err = KAT_chacha20poly1305_enc();
    print_kat_result("KAT CHACHA20POLY1305 Encrypt Test", err);
    if (err <0) err = 0;
    errors += err;
    //ERR_print_errors(bio_err);

    err = KAT_chacha20poly1305_dec();
    print_kat_result("KAT CHACHA20POLY1305 Decrypt Test", err);
    if (err <0) err = 0;
    errors += err;
    //ERR_print_errors(bio_err);

    return errors;
}

static void printbytes( unsigned char *b, int len )
{
    int i = 0;

    if (!b)
        return;

    for( i = 0; i < len; i++ )
    {
        if(i>0 && i % 16 == 0 )
        {
            printf( "\n" );
        }
        printf("%02x ", b[i] );
    }
    printf( "\n" );
}

static void print_ukat_result(const char * label, int err,
                         const char * s1, unsigned char * b1, int l1,
                         const char * s2, unsigned char * b2, int l2)
{
    switch (err)
    {
        case -1:
            printf("%s Skipped\n", label);
            break;
        case 0:
            printf("%s Complete\n", label);
            if (s1)
                printf("%s ...\n", s1);
            printbytes( b1, l1 );
            if (s2)
                printf("%s ...\n", s2);
            printbytes( b2, l2 );
            break;
        default:
            printf("%s FAILED\n", label);
            break;
    }
    printf("\n");
}
static int csdk_test_ukat_symmetric( void )
{
    int errors = 0;
    int err = 0;
    unsigned char * c = NULL;
    int len = 0;
    unsigned char *t =  NULL;
    int tlen = 0;
    int  i= 0;

    len = UKAT_chacha20poly1305_enc(NULL, NULL);
    if (len <= 0)
        print_ukat_result("UKAT CHACHA20POLY1305 Encrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
        {
            print_ukat_result("UKAT CHACHA20POLY1305 Encrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
            errors++;
        }
        else
        {
            tlen = UKAT_chacha20poly1305_enc(c, NULL);
            if (tlen <= 0)
                print_ukat_result("UKAT CHACHA20POLY1305 Encrypt Test", tlen, NULL, NULL, 0, NULL, NULL, 0);
            else
            {
                t = calloc(1,tlen);
                if (!t)
                    print_ukat_result("UKAT CHACHA20POLY1305 Encrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
                else
                {
                    err = UKAT_chacha20poly1305_enc(c, t);
                    print_ukat_result("UKAT CHACHA20POLY1305 Encrypt Test", err, "CT", c, len, "TAG", t, tlen);
                    if (err <0) err = 0;
                    errors += err;
                }
            }
        }
        TEST_FREE(c);
        TEST_FREE(t);
    }
    //ERR_print_errors(bio_err);

    len = UKAT_chacha20poly1305_dec(NULL, &i);
    if (len <= 0)
        print_ukat_result("UKAT CHACHA20POLY1305 Decrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
        {
            print_ukat_result("UKAT CHACHA20POLY1305 Decrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
            errors++;
        }
        else
        {
            err = UKAT_chacha20poly1305_dec(c, &i);
            print_ukat_result("UKAT CHACHA20POLY1305 Decrypt Test", err, "PT", c, len,  NULL, NULL, 0 );
            if (err <0) err = 0;
            errors += err;
        }
        TEST_FREE(c);
    }
    //ERR_print_errors(bio_err);

    return errors;
}

void print_stats( void )
{
    // TTDPOLY - how to generalise the stats
    printf("Engine Statistics\n");
    printf("-------------------------------------------------\n");
    printf("... csdk_256_aead_init_key = %llu\n", stats.csdk_256_aead_init_key);
    printf("... csdk_256_aead_cipher =   %llu\n", stats.csdk_256_aead_cipher);
    printf("... csdk_256_aead_ctrl =     %llu\n", stats.csdk_256_aead_ctrl);
    printf("-------------------------------------------------\n");
}

/*
 * csdk_test utility to demonstrate ENGINE usage and setup.
 *
 * @param argc
 * @param argv[]
 *
 * @return
 */
int main(int argc, char *argv[])
{
    int errors = 0;
    const char *engine_id = "libcsdk";

    (void) argc;
    (void) argv;

    csdk_test_init();

    BIO_printf(bio_err, "CSDK OpenSSL Engine Test %s\n", "1.0");
    if (!csdk_setup_engine(engine_id, 1))
    {
        BIO_printf(bio_err, "Engine not found. Please ensure OPENSSL_ENGINES path is set correctly\n");
        return 1;
    }

    OpenSSL_add_all_algorithms();

    printf("\n\nTesting all KATs\n\n");
    errors += csdk_test_kat_symmetric();
    printf("\n\nTesting all UKATs\n\n");
    errors += csdk_test_ukat_symmetric();

    print_stats();

    printf("\nTest complete\n\n");

    //ERR_print_errors(bio_err);

    // NB: Number of errors is logged as self test failure, so important to reflect status of all tests
    // for normal encryptor operation
    return errors;
}
