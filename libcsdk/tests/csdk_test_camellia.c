/*
 * Self-test for the camellia cipher target.
 * tests/csdk_test_camellia_simd.c is a link to this file.
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

#ifndef PROFILE
//#define PROFILE
#endif

static csdk_stats_t stats = {0};

#ifdef PROFILE
/*
 * support function for time difference calculation
 *
 * @param diff   time between start and end
 * @param start  start time
 * @param end    end time
 */
static void csdk_tm_calc_diff(struct timespec * diff, struct timespec start, struct timespec end)
{
    if ((end.tv_nsec-start.tv_nsec)<0)
    {
        diff->tv_sec = end.tv_sec-start.tv_sec-1;
        diff->tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
    } else {
        diff->tv_sec = end.tv_sec-start.tv_sec;
        diff->tv_nsec = end.tv_nsec-start.tv_nsec;
    }
    return;
}
#endif






#if 0
static void _printbytes( unsigned char *b, int len )
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
        printf("0x%02x, ", b[i] );
    }
    printf( "\n" );
}
#endif
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

/*
 * internal KAT AES implementation for example CSDK reference only.
 *
 * @param cipher
 * @param enc_flag
 * @param key
 * @param iv
 * @param data
 * @param data_size
 * @param data_ok
 *
 * @return 0 on success
 */
static int KAT_camellia( const EVP_CIPHER * cipher,
             int enc,
             const unsigned char *key,
             const unsigned char  *iv,
             const unsigned char *data,
             int data_size,
             const unsigned char *exp_data,
             int exp_data_size  )
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int olen = 0;
    unsigned char * buf = NULL;
    int errors = 1;
#ifdef PROFILE
    struct timespec tm1;
    struct timespec tm2;
    struct timespec tmd;
    clock_gettime(CLOCK_MONOTONIC, &tm1);
#endif

    if(!(ctx = EVP_CIPHER_CTX_new()))
        goto err;

    EVP_CIPHER_CTX_set_app_data(ctx, (void*) &stats);

    buf = calloc(1, exp_data_size+16);
    if (!buf)
        goto err;
    if (enc)
    {
        if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
            goto err;

        if(1 != EVP_EncryptUpdate(ctx, (unsigned char*) buf, &len, (const unsigned char*) data, data_size))
            goto err;

        olen = len;
        if(1 != EVP_EncryptFinal_ex(ctx, buf + len, &len))
            goto err;

        olen += len;
    }
    else
    {
        if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
            goto err;

        if(1 != EVP_DecryptUpdate(ctx, buf, &len, (const unsigned char*) data, data_size))
            goto err;
        olen = len;

        if(1 != EVP_DecryptFinal_ex(ctx, buf + len, &len))
            goto err;
        olen += len;
    }
    if (olen != exp_data_size)
        goto err;

    if (!memcmp( buf, exp_data, olen ))
        errors=0;

#ifdef PROFILE
    clock_gettime(CLOCK_MONOTONIC, &tm2);
    csdk_tm_calc_diff( &tmd, tm1, tm2);
    printf(">%.2lld.%.9ld (secs)\n", (long long) tmd.tv_sec, tmd.tv_nsec);
#endif
err:
    if (buf)
        free(buf);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);

    return errors;
}

/*
 * KAT 128 cfb encrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_128_cfb_enc( void )
{
    int errors = 0;

    // openssl test vectors
    unsigned char key[] =
    {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };

    unsigned char iv[] =
    {

        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    unsigned char ptext[] =
    {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    };

    unsigned char ctext[] =
    {
        0x14, 0xF7, 0x64, 0x61, 0x87, 0x81, 0x7E, 0xB5, 0x86, 0x59, 0x91, 0x46, 0xB8, 0x2B, 0xD7, 0x19,
        0xA5, 0x3D, 0x28, 0xBB, 0x82, 0xDF, 0x74, 0x11, 0x03, 0xEA, 0x4F, 0x92, 0x1A, 0x44, 0x88, 0x0B,
        0x9C, 0x21, 0x57, 0xA6, 0x64, 0x62, 0x6D, 0x1D, 0xEF, 0x9E, 0xA4, 0x20, 0xFD, 0xE6, 0x9B, 0x96,
        0x74, 0x2A, 0x25, 0xF0, 0x54, 0x23, 0x40, 0xC7, 0xBA, 0xEF, 0x24, 0xCA, 0x84, 0x82, 0xBB, 0x09
    };

#ifndef DEBUG_CFB
    errors += KAT_camellia( EVP_aes_128_cfb128(), 1, key, iv, ptext, sizeof( ptext ), ctext, sizeof( ctext ));
#else
    errors=0;
    {
    unsigned char ct[16]={0};
    int i,j;
    for (i=0;i<4;i++)
    {
        for (j=0;j<16;j++)
        {
            ct[j] = iv[j]^key[j]^ptext[(i*16) + j];
        }
        _printbytes( ct, 16 );
        memcpy(iv, ct, 16);
    }
    }
#endif

    return errors;
}

/*
 * KAT 128 cfb decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_128_cfb_dec( void )
{
    int errors = 0;


    unsigned char key[] =
    {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };

    unsigned char iv[] =
    {

        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    unsigned char ptext[] =
    {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    };

    unsigned char ctext[] =
    {
        0x14, 0xF7, 0x64, 0x61, 0x87, 0x81, 0x7E, 0xB5, 0x86, 0x59, 0x91, 0x46, 0xB8, 0x2B, 0xD7, 0x19,
        0xA5, 0x3D, 0x28, 0xBB, 0x82, 0xDF, 0x74, 0x11, 0x03, 0xEA, 0x4F, 0x92, 0x1A, 0x44, 0x88, 0x0B,
        0x9C, 0x21, 0x57, 0xA6, 0x64, 0x62, 0x6D, 0x1D, 0xEF, 0x9E, 0xA4, 0x20, 0xFD, 0xE6, 0x9B, 0x96,
        0x74, 0x2A, 0x25, 0xF0, 0x54, 0x23, 0x40, 0xC7, 0xBA, 0xEF, 0x24, 0xCA, 0x84, 0x82, 0xBB, 0x09
    };
#ifndef DEBUG_CFB
    errors += KAT_camellia( EVP_aes_128_cfb128(), 0, key, iv, ctext, sizeof( ctext ), ptext, sizeof( ptext ));
#else
    errors = 0;
    {
    unsigned char pt[16]={0};
    int i,j;
    for (i=0;i<4;i++)
    {
        for (j=0;j<16;j++)
        {
           pt[j] = iv[j]^key[j]^ctext[(i*16) + j];
        }
        _printbytes( pt, 16 );
        memcpy(iv, &ctext[i*16], 16);
    }
    }
#endif
    return errors;
}

/*
 * KAT 256 cfb encrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_256_cfb_enc( void )
{
    int errors = 0;

    // openssl test vectors
    static unsigned char key[] =
    {
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    };

    static unsigned char iv[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static unsigned char ptext[] =
    {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    };

    static unsigned char ctext[] =
    {
        0xCF, 0x61, 0x07, 0xBB, 0x0C, 0xEA, 0x7D, 0x7F, 0xB1, 0xBD, 0x31, 0xF5, 0xE7, 0xB0, 0x6C, 0x93,
        0x89, 0xBE, 0xDB, 0x4C, 0xCD, 0xD8, 0x64, 0xEA, 0x11, 0xBA, 0x4C, 0xBE, 0x84, 0x9B, 0x5E, 0x2B,
        0x55, 0x5F, 0xC3, 0xF3, 0x4B, 0xDD, 0x2D, 0x54, 0xC6, 0x2D, 0x9E, 0x3B, 0xF3, 0x38, 0xC1, 0xC4,
        0x59, 0x53, 0xAD, 0xCE, 0x14, 0xDB, 0x8C, 0x7F, 0x39, 0xF1, 0xBD, 0x39, 0xF3, 0x59, 0xBF, 0xFA
    };

#ifndef DEBUG_CFB
    errors += KAT_camellia( EVP_aes_256_cfb128(), 1, key, iv, ptext, sizeof( ptext ), ctext, sizeof( ctext ));
#else
    errors = 0;
    {
    unsigned char ct[16]={0};
    int i,j;
    for (i=0;i<4;i++)
    {
        for (j=0;j<16;j++)
        {
            ct[j] = iv[j]^key[j]^key[j+16]^ptext[(i*16) + j];
         }
        _printbytes( ct, 16 );
        memcpy(iv, ct, 16);
    }
    }
#endif
   return errors;
}

/*
 * KAT 256 cfb decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_256_cfb_dec( void )
{
    int errors = 0;


    // openssl test vectors
    static unsigned char key[] =
    {
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    };

    static unsigned char iv[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static unsigned char ptext[] =
    {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    };

    static unsigned char ctext[] =
    {
        0xCF, 0x61, 0x07, 0xBB, 0x0C, 0xEA, 0x7D, 0x7F, 0xB1, 0xBD, 0x31, 0xF5, 0xE7, 0xB0, 0x6C, 0x93,
        0x89, 0xBE, 0xDB, 0x4C, 0xCD, 0xD8, 0x64, 0xEA, 0x11, 0xBA, 0x4C, 0xBE, 0x84, 0x9B, 0x5E, 0x2B,
        0x55, 0x5F, 0xC3, 0xF3, 0x4B, 0xDD, 0x2D, 0x54, 0xC6, 0x2D, 0x9E, 0x3B, 0xF3, 0x38, 0xC1, 0xC4,
        0x59, 0x53, 0xAD, 0xCE, 0x14, 0xDB, 0x8C, 0x7F, 0x39, 0xF1, 0xBD, 0x39, 0xF3, 0x59, 0xBF, 0xFA
    };

#ifndef DEBUG_CFB
    errors += KAT_camellia( EVP_aes_256_cfb128(), 0, key, iv, ctext, sizeof( ctext ), ptext, sizeof( ptext ));
#else
    errors = 0;
    {
    unsigned char pt[16]={0};
    int i,j;
    for (i=0;i<4;i++)
    {
        for (j=0;j<16;j++)
        {
            pt[j] = iv[j]^key[j]^key[j+16]^ctext[(i*16) + j];
         }
        _printbytes( pt, 16 );
        memcpy(iv, &ctext[i*16], 16);
    }
    }
#endif
    return errors;
}

#if 0
// TV from https://datatracker.ietf.org/doc/rfc5528/
Cipher = CAMELLIA-128-CTR
Key = 7E24067817FAE0D743D6CE1F32539163
IV = 006CB6DBC0543B59DA48D90B00000001
Operation = ENCRYPT
Plaintext = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
Ciphertext = DBF3C78DC08396D4DA7C907765BBCB442B8E8E0F31F0DCA72C7417E35360E048

#endif
/*
 * KAT 128 ctr encrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_128_ctr_enc( void )
{
    int errors = 0;

    // AES CTR128 SP800-38a
    static unsigned char key[] =
    {
        0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7, 0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63
    };

    // Init. Counter
    static unsigned char iv[] =
    {
        0x00, 0x6C, 0xB6, 0xDB,
        0xC0 ,0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B,
        0x00, 0x00, 0x00, 0x01
    };

    static unsigned char ptext[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    static unsigned char ctext[] =
    {
        0xDB, 0xF3, 0xC7, 0x8D, 0xC0, 0x83, 0x96, 0xD4, 0xDA, 0x7C, 0x90, 0x77, 0x65, 0xBB, 0xCB, 0x44,
        0x2B, 0x8E, 0x8E, 0x0F, 0x31, 0xF0, 0xDC, 0xA7, 0x2C, 0x74, 0x17, 0xE3, 0x53, 0x60, 0xE0, 0x48
    };

    errors += KAT_camellia( EVP_aes_128_ctr(), 1, key, iv, ptext, sizeof( ptext ), ctext, sizeof( ctext ));

    return errors;
}

/*
 * KAT 128 ctr decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_128_ctr_dec( void )
{
    int errors = 0;


    static unsigned char key[] =
    {
        0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7, 0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63
    };

    // Init. Counter
    static unsigned char iv[] =
    {
        0x00, 0x6C, 0xB6, 0xDB,
        0xC0 ,0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B,
        0x00, 0x00, 0x00, 0x01
    };

    static unsigned char ptext[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    static unsigned char ctext[] =
    {
        0xDB, 0xF3, 0xC7, 0x8D, 0xC0, 0x83, 0x96, 0xD4, 0xDA, 0x7C, 0x90, 0x77, 0x65, 0xBB, 0xCB, 0x44,
        0x2B, 0x8E, 0x8E, 0x0F, 0x31, 0xF0, 0xDC, 0xA7, 0x2C, 0x74, 0x17, 0xE3, 0x53, 0x60, 0xE0, 0x48
    };

    errors += KAT_camellia( EVP_aes_128_ctr(), 0, key, iv, ctext, sizeof( ctext ), ptext, sizeof( ptext ));

    return errors;
}


#if 0
// TV from https://datatracker.ietf.org/doc/rfc5528/
Cipher = CAMELLIA-256-CTR
Key = FF7A617CE69148E4F1726E2F43581DE2AA62D9F805532EDFF1EED687FB54153D
IV = 001CC5B751A51D70A1C1114800000001
Operation = ENCRYPT
Plaintext = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223
Ciphertext = A4DA23FCE6A5FFAA6D64AE9A0652A42CD161A34B65F9679F75C01F101F71276F15EF0D8D


Cipher = CAMELLIA-256-CTR
Key = F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884
IV = 00FAAC24C1585EF15A43D87500000001
Operation = ENCRYPT
Plaintext = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
Ciphertext = D6C30392246F7808A83C2B22A8839E45E51CD48A1CDF406EBC9CC2D3AB834108

#endif
/*
 * KAT 256 ctr encrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_256_ctr_enc( void )
{
    int errors = 0;

    static unsigned char key[] =
    {
        0xF6, 0xD6, 0x6D, 0x6B, 0xD5, 0x2D, 0x59, 0xBB, 0x07, 0x96, 0x36, 0x58, 0x79, 0xEF, 0xF8, 0x86,
        0xC6, 0x6D, 0xD5, 0x1A, 0x5B, 0x6A, 0x99, 0x74, 0x4B, 0x50, 0x59, 0x0C, 0x87, 0xA2, 0x38, 0x84
    };

    // Init. Counter
    static unsigned char iv[] =
    {
        0x00, 0xFA, 0xAC, 0x24, 0xC1, 0x58, 0x5E, 0xF1, 0x5A, 0x43, 0xD8, 0x75, 0x00, 0x00, 0x00, 0x01
    };

    static unsigned char ptext[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    static unsigned char ctext[] =
    {
        0xD6, 0xC3, 0x03, 0x92, 0x24, 0x6F, 0x78, 0x08, 0xA8, 0x3C, 0x2B, 0x22, 0xA8, 0x83, 0x9E, 0x45,
        0xE5, 0x1C, 0xD4, 0x8A, 0x1C, 0xDF, 0x40, 0x6E, 0xBC, 0x9C, 0xC2, 0xD3, 0xAB, 0x83, 0x41, 0x08
    };

    errors += KAT_camellia( EVP_aes_256_ctr(), 1, key, iv, ptext, sizeof( ptext ), ctext, sizeof( ctext ));

    return errors;
}

/*
 * KAT 256 ctr decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_256_ctr_dec( void )
{
    int errors = 0;


    static unsigned char key[] =
    {
        0xF6, 0xD6, 0x6D, 0x6B, 0xD5, 0x2D, 0x59, 0xBB, 0x07, 0x96, 0x36, 0x58, 0x79, 0xEF, 0xF8, 0x86,
        0xC6, 0x6D, 0xD5, 0x1A, 0x5B, 0x6A, 0x99, 0x74, 0x4B, 0x50, 0x59, 0x0C, 0x87, 0xA2, 0x38, 0x84
    };

    // Init. Counter
    static unsigned char iv[] =
    {
        0x00, 0xFA, 0xAC, 0x24, 0xC1, 0x58, 0x5E, 0xF1, 0x5A, 0x43, 0xD8, 0x75, 0x00, 0x00, 0x00, 0x01
    };

    static unsigned char ptext[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    static unsigned char ctext[] =
    {
        0xD6, 0xC3, 0x03, 0x92, 0x24, 0x6F, 0x78, 0x08, 0xA8, 0x3C, 0x2B, 0x22, 0xA8, 0x83, 0x9E, 0x45,
        0xE5, 0x1C, 0xD4, 0x8A, 0x1C, 0xDF, 0x40, 0x6E, 0xBC, 0x9C, 0xC2, 0xD3, 0xAB, 0x83, 0x41, 0x08
    };

    errors += KAT_camellia( EVP_aes_256_ctr(), 0, key, iv, ctext, sizeof( ctext ), ptext, sizeof( ptext ));

    return errors;
}


/*
 * KAT 128 gcm encrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_128_gcm_enc( void )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;

    unsigned char  gcm_key_128[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    unsigned char  gcm_aes_iv_128[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    unsigned char  gcm_128_plaintext[] =
    {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39
    };
    unsigned char  gcm_128_ciphertext[] =
    {   
        0xd0, 0xd9, 0x4a, 0x13, 0xb6, 0x32, 0xf3, 0x37, 0xa0, 0xcc, 0x99, 0x55, 0xb9, 0x4f, 0xa0, 0x20,
        0xc8, 0x15, 0xf9, 0x03, 0xaa, 0xb1, 0x2f, 0x1e, 0xfa, 0xf2, 0xfe, 0x9d, 0x90, 0xf7, 0x29, 0xa6, 
        0xcc, 0xcb, 0xfa, 0x98, 0x6e, 0xf2, 0xff, 0x2c, 0x33, 0xde, 0x41, 0x8d, 0x9a, 0x25, 0x29, 0x09,
        0x1c, 0xf1, 0x8f, 0xe6, 0x52, 0xc1, 0xcf, 0xde, 0x13, 0xf8, 0x26, 0x06
    };

    unsigned char  gcm_128_tag[] =
    {   
        0x9f, 0x45, 0x88, 0x69, 0x43, 0x15, 0x76, 0xea, 0x6a, 0x09, 0x54, 0x56, 0xec, 0x6b, 0x81, 0x01
    };
    unsigned char  gcm_aad[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    unsigned char ct[sizeof(gcm_128_ciphertext)] = {0};
    unsigned char tag[sizeof(gcm_128_tag)] = {0};

    // encrypt
    type = EVP_aes_128_gcm();

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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(gcm_aes_iv_128), NULL))
    {
        errors++;
        goto err_enc;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, gcm_key_128, gcm_aes_iv_128, 1))
    {
        errors++;
        goto err_enc;
    }

    /* 96 bit IV */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, gcm_aes_iv_128))
    {
        errors++;
        goto err_enc;
    }
    // aad
    if (!EVP_Cipher(ctx, NULL, gcm_aad, (unsigned int)sizeof(gcm_aad)))
    {
        errors++;
        goto err_enc;
    }

    if (EVP_Cipher(ctx, ct, gcm_128_plaintext, (unsigned int)sizeof(gcm_128_plaintext)) != (int)sizeof(gcm_128_plaintext))
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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(tag), tag))
    {
        errors++;
        goto err_enc;
    }

    if(memcmp( ct, gcm_128_ciphertext, sizeof( gcm_128_ciphertext )) ||
       memcmp( tag, gcm_128_tag, sizeof( gcm_128_tag )))
    {
        errors++;
    }
err_enc:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return errors;
}

#if 0
    taken from https://datatracker.ietf.org/doc/html/draft-kato-ipsec-camellia-gcm-03#page-7
  ------ Spec Test Case 4 (Camellia-128) ------
  KEY : feffe9928665731c6d6a8f9467308308
  IV  : cafebabefacedbaddecaf888
  AD  : feedfacedeadbeeffeedfacedeadbeefabaddad2
  P   : d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
        1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
  C   : d0d94a13b632f337a0cc9955b94fa020c815f903aab12f1efaf2fe9d90f729a6
        cccbfa986ef2ff2c33de418d9a2529091cf18fe652c1cfde13f82606
  T   : 9f458869431576ea6a095456ec6b8101
#endif
/*
 * KAT 128 gcm decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_128_gcm_dec( void )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;
    unsigned int integrity_error = 0;


    unsigned char  gcm_key_128[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    unsigned char  gcm_aes_iv_128[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    unsigned char  gcm_128_plaintext[] =
    {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39
    };
    unsigned char  gcm_128_ciphertext[] =
    {
        0xd0, 0xd9, 0x4a, 0x13, 0xb6, 0x32, 0xf3, 0x37, 0xa0, 0xcc, 0x99, 0x55, 0xb9, 0x4f, 0xa0, 0x20,
        0xc8, 0x15, 0xf9, 0x03, 0xaa, 0xb1, 0x2f, 0x1e, 0xfa, 0xf2, 0xfe, 0x9d, 0x90, 0xf7, 0x29, 0xa6,
        0xcc, 0xcb, 0xfa, 0x98, 0x6e, 0xf2, 0xff, 0x2c, 0x33, 0xde, 0x41, 0x8d, 0x9a, 0x25, 0x29, 0x09,
        0x1c, 0xf1, 0x8f, 0xe6, 0x52, 0xc1, 0xcf, 0xde, 0x13, 0xf8, 0x26, 0x06
    };

    unsigned char  gcm_128_tag[] =
    {
        0x9f, 0x45, 0x88, 0x69, 0x43, 0x15, 0x76, 0xea, 0x6a, 0x09, 0x54, 0x56, 0xec, 0x6b, 0x81, 0x01
    };
    unsigned char  gcm_aad[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    unsigned char pt[sizeof(gcm_128_plaintext)] = {0};

    type = EVP_aes_128_gcm();

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

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(gcm_aes_iv_128), NULL))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)sizeof(gcm_128_tag), gcm_128_tag))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, gcm_key_128, gcm_aes_iv_128, 0))
    {
        errors++;
        goto err_dec;
    }

    if (!EVP_Cipher(ctx, NULL, gcm_aad, (unsigned int)sizeof(gcm_aad)))
    {
        errors++;
        goto err_dec;
    }
    integrity_error = 0;

    if (EVP_Cipher(ctx, pt, gcm_128_ciphertext, (unsigned int)sizeof(pt)) != (int)sizeof(pt))
    {
        integrity_error = 1;
    }

    if (EVP_Cipher(ctx, NULL, NULL, 0) < 0)
    {
        integrity_error = 1;
    }
    if(memcmp( pt, gcm_128_plaintext, sizeof( gcm_128_plaintext )) || integrity_error )
    {
        errors++;
    }
err_dec:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return errors;
}
#if 0
    taken from https://datatracker.ietf.org/doc/html/draft-kato-ipsec-camellia-gcm-03#page-7
  ------ Spec Test Case 4 (Camellia-128) ------
  KEY : feffe9928665731c6d6a8f9467308308
  IV  : cafebabefacedbaddecaf888
  AD  : feedfacedeadbeeffeedfacedeadbeefabaddad2
  P   : d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
        1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
  C   : d0d94a13b632f337a0cc9955b94fa020c815f903aab12f1efaf2fe9d90f729a6
        cccbfa986ef2ff2c33de418d9a2529091cf18fe652c1cfde13f82606
  T   : 9f458869431576ea6a095456ec6b8101
#endif
#if 0
    taken from https://datatracker.ietf.org/doc/html/draft-kato-ipsec-camellia-gcm-03#page-7
------ Spec Test Case 16 (Camellia-256) ------
  KEY : feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
  IV  : cafebabefacedbaddecaf888
  AD  : feedfacedeadbeeffeedfacedeadbeefabaddad2
  P   : d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
        1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
  C   : ad142c11579dd95e41f3c1f324dabc255864d920f1b65759d8f560d4948d4477
        58dfdcf77aa9f62581c7ff572a037f810cb1a9c4b3ca6ed638179b77
  T   : 4e4b178d8fe26fdc95e2e7246dd94bec

#endif

/*
 * KAT 256 gcm encrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_256_gcm_enc( void )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;

    unsigned char gcm_key_256[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    unsigned char gcm_aes_iv_256[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    unsigned char gcm_256_plaintext[] =
    {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39
    };
    unsigned char gcm_256_ciphertext[] =
    {
        0xad, 0x14, 0x2c, 0x11, 0x57, 0x9d, 0xd9, 0x5e, 0x41, 0xf3, 0xc1, 0xf3, 0x24, 0xda, 0xbc, 0x25,
        0x58, 0x64, 0xd9, 0x20, 0xf1, 0xb6, 0x57, 0x59, 0xd8, 0xf5, 0x60, 0xd4, 0x94, 0x8d, 0x44, 0x77,
        0x58, 0xdf, 0xdc, 0xf7, 0x7a, 0xa9, 0xf6, 0x25, 0x81, 0xc7, 0xff, 0x57, 0x2a, 0x03, 0x7f, 0x81,
        0x0c, 0xb1, 0xa9, 0xc4, 0xb3, 0xca, 0x6e, 0xd6, 0x38, 0x17, 0x9b, 0x77
    };
    unsigned char gcm_256_tag[] =
    {
        0x4e, 0x4b, 0x17, 0x8d, 0x8f, 0xe2, 0x6f, 0xdc, 0x95, 0xe2, 0xe7, 0x24, 0x6d, 0xd9, 0x4b, 0xec
    };
    unsigned char gcm_aad[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };


    unsigned char ct[sizeof(gcm_256_ciphertext)] = {0};
    unsigned char tag[sizeof(gcm_256_tag)] = {0};

    type = EVP_aes_256_gcm();

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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(gcm_aes_iv_256), NULL))
    {
        errors++;
        goto err_enc;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, gcm_key_256, gcm_aes_iv_256, 1))
    {
        errors++;
        goto err_enc;
    }

    /* 96 bit IV */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, gcm_aes_iv_256))
    {
        errors++;
        goto err_enc;
    }
    // aad
    if (!EVP_Cipher(ctx, NULL, gcm_aad, (unsigned int)sizeof(gcm_aad)))
    {
        errors++;
        goto err_enc;
    }
    if (EVP_Cipher(ctx, ct, gcm_256_plaintext, (unsigned int)sizeof(gcm_256_plaintext)) != (int)sizeof(gcm_256_plaintext))
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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(tag), tag))
    {
        errors++;
        goto err_enc;
    }

    if(memcmp( ct, gcm_256_ciphertext, sizeof( gcm_256_ciphertext )) ||
           memcmp( tag, gcm_256_tag, sizeof( gcm_256_tag )))
    {
        errors++;
    }
err_enc:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return errors;

}

/*
 * KAT 256 gcm decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int KAT_256_gcm_dec( void )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;
    unsigned int integrity_error = 0;

    unsigned char gcm_key_256[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    unsigned char gcm_aes_iv_256[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    unsigned char gcm_256_plaintext[] =
    {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39
    };
    unsigned char gcm_256_ciphertext[] =
    {
        0xad, 0x14, 0x2c, 0x11, 0x57, 0x9d, 0xd9, 0x5e, 0x41, 0xf3, 0xc1, 0xf3, 0x24, 0xda, 0xbc, 0x25,
        0x58, 0x64, 0xd9, 0x20, 0xf1, 0xb6, 0x57, 0x59, 0xd8, 0xf5, 0x60, 0xd4, 0x94, 0x8d, 0x44, 0x77,
        0x58, 0xdf, 0xdc, 0xf7, 0x7a, 0xa9, 0xf6, 0x25, 0x81, 0xc7, 0xff, 0x57, 0x2a, 0x03, 0x7f, 0x81,
        0x0c, 0xb1, 0xa9, 0xc4, 0xb3, 0xca, 0x6e, 0xd6, 0x38, 0x17, 0x9b, 0x77
    };
    unsigned char gcm_256_tag[] =
    {
        0x4e, 0x4b, 0x17, 0x8d, 0x8f, 0xe2, 0x6f, 0xdc, 0x95, 0xe2, 0xe7, 0x24, 0x6d, 0xd9, 0x4b, 0xec
    };
    unsigned char gcm_aad[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    unsigned char pt[sizeof(gcm_256_plaintext)] = {0};

    type = EVP_aes_256_gcm();

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

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(gcm_aes_iv_256), NULL))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)sizeof(gcm_256_tag), gcm_256_tag))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, gcm_key_256, gcm_aes_iv_256, 0))
    {
        errors++;
        goto err_dec;
    }

    if (!EVP_Cipher(ctx, NULL, gcm_aad, (unsigned int)sizeof(gcm_aad)))
    {
        errors++;
        goto err_dec;
    }
    integrity_error = 0;

    if (EVP_Cipher(ctx, pt, gcm_256_ciphertext, (unsigned int)sizeof(pt)) != (int)sizeof(pt))
    {
        integrity_error = 1;
    }

    if (EVP_Cipher(ctx, NULL, NULL, 0) < 0)
    {
        integrity_error = 1;
    }

    if(memcmp( pt, gcm_256_plaintext, sizeof( gcm_256_plaintext )) || integrity_error )
    {
        errors++;
    }
err_dec:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return errors;
}


/*
 * internal UKAT AES implementation for example CSDK reference only.
 *
 * @param cipher
 * @param enc_flag
 * @param key
 * @param iv
 * @param data
 * @param data_size
 * @param data_out
 *
 * @return 0 on success
 */
static int UKAT_camellia( const EVP_CIPHER * cipher,
             int enc,
             const unsigned char *key,
             const unsigned char  *iv,
             const unsigned char *data,
             int data_size,
             unsigned char *data_out)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int olen = 0;
    int errors = 1;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        goto err;

    EVP_CIPHER_CTX_set_app_data(ctx, (void*) &stats);

    if (enc)
    {
        if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
            goto err;

        if(1 != EVP_EncryptUpdate(ctx, (unsigned char*) data_out, &len, (const unsigned char*) data, data_size))
            goto err;

        olen = len;
        if(1 != EVP_EncryptFinal_ex(ctx, data_out + len, &len))
            goto err;

        olen += len;
    }
    else
    {
        if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
            goto err;

        if(1 != EVP_DecryptUpdate(ctx, data_out, &len, (const unsigned char*) data, data_size))
            goto err;
        olen = len;

        if(1 != EVP_DecryptFinal_ex(ctx, data_out + len, &len))
            goto err;
        olen += len;
    }

    if (olen != data_size)
        goto err;
    errors = 0;
err:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);

    return errors;
}

/*
 * UKAT 128 cfb encrypt test - for application selftest access
 *
 * @param ctext - ciphertext to return - call with NULL to get required size
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_128_cfb_enc( unsigned char *ctext )
{
    int errors = 0;

    static unsigned char key[] =
    {
        0x94, 0x97, 0x9c, 0x4e, 0x24, 0x4f, 0x75, 0x01, 0x94, 0xa3, 0xd0, 0x2c, 0x9a, 0x3f, 0x37, 0x88
    };

    static unsigned char iv[] =
    {
        0x2e, 0x66, 0x00, 0x9f, 0xf2, 0x17, 0x3b, 0x4a, 0x1a, 0x5f, 0x5d, 0x2c, 0xd9, 0x3a, 0xcb, 0x2a
    };

    static unsigned char ptext[] =
    {
        0x10, 0x20, 0xbb, 0xba, 0xbe, 0x5e, 0x67, 0xbe, 0xd7, 0xe1, 0xb9, 0x7e, 0xb8, 0x1f, 0x97, 0x55,
        0x1a, 0x81, 0x1d, 0x02, 0x94, 0xce, 0x40, 0xb6, 0x61, 0xe7, 0xb1, 0x6c, 0x64, 0xb6, 0x04, 0x79,
        0x69, 0x61, 0x12, 0x64, 0xae, 0xc3, 0x9c, 0xf7, 0xa2, 0x1c, 0x31, 0x96, 0xec, 0x07, 0x51, 0xd0,
        0xaf, 0xad, 0xd2, 0x34, 0x0c, 0x39, 0x83, 0x66, 0xe9, 0x8c, 0x10, 0x72, 0xf1, 0x31, 0x25, 0x5f
    };

#if 0 //expected
    static unsigned char ctext[] =
    {
        0xaa, 0xd1, 0x27, 0x6b, 0x68, 0x06, 0x29, 0xf5, 0x59, 0x1d, 0x34, 0x7e, 0xfb, 0x1a, 0x6b, 0xf7,
        0x24, 0xc7, 0xa6, 0x27, 0xd8, 0x87, 0x1c, 0x42, 0xac, 0x59, 0x55, 0x3e, 0x05, 0x93, 0x58, 0x06,
        0xd9, 0x31, 0x28, 0x0d, 0x52, 0x0b, 0xf5, 0xb4, 0x9a, 0xe6, 0xb4, 0x84, 0x73, 0xab, 0x3e, 0x5e,
        0xe2, 0x0b, 0x66, 0x77, 0x7a, 0x7d, 0x03, 0xd3, 0xe7, 0xc9, 0x74, 0xda, 0x18, 0xa5, 0x2c, 0x89
    };
#endif
    if (!ctext)
        return sizeof(ptext);

    errors += UKAT_camellia( EVP_aes_128_cfb128(), 1, key, iv, ptext, sizeof( ptext ), ctext );

#ifdef DEBUG_CFB
    unsigned char ct[16]={0};
    int i,j;
    for (i=0;i<4;i++)
    {
        for (j=0;j<16;j++)
        {
            ct[j] = iv[j]^key[j]^ptext[(i*16) + j];
         }
        printbytes( ct[j], 16 );
        memcpy(iv, ct, 16);
    }
#endif

    return errors;
}

/*
 * UKAT 128 cfb decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_128_cfb_dec( unsigned char * ptext )
{
    int errors = 0;

    static unsigned char key[] =
    {
        0x94, 0x97, 0x9c, 0x4e, 0x24, 0x4f, 0x75, 0x01, 0x94, 0xa3, 0xd0, 0x2c, 0x9a, 0x3f, 0x37, 0x88
    };

    static unsigned char iv[] =
    {
        0x2e, 0x66, 0x00, 0x9f, 0xf2, 0x17, 0x3b, 0x4a, 0x1a, 0x5f, 0x5d, 0x2c, 0xd9, 0x3a, 0xcb, 0x2a
    };
#if 0 // expected response...
    static unsigned char ptext[] =
    {
        0x10, 0x20, 0xbb, 0xba, 0xbe, 0x5e, 0x67, 0xbe, 0xd7, 0xe1, 0xb9, 0x7e, 0xb8, 0x1f, 0x97, 0x55,
        0x1a, 0x81, 0x1d, 0x02, 0x94, 0xce, 0x40, 0xb6, 0x61, 0xe7, 0xb1, 0x6c, 0x64, 0xb6, 0x04, 0x79,
        0x69, 0x61, 0x12, 0x64, 0xae, 0xc3, 0x9c, 0xf7, 0xa2, 0x1c, 0x31, 0x96, 0xec, 0x07, 0x51, 0xd0,
        0xaf, 0xad, 0xd2, 0x34, 0x0c, 0x39, 0x83, 0x66, 0xe9, 0x8c, 0x10, 0x72, 0xf1, 0x31, 0x25, 0x5f
    };
#endif
    static unsigned char ctext[] =
    {
        0xaa, 0xd1, 0x27, 0x6b, 0x68, 0x06, 0x29, 0xf5, 0x59, 0x1d, 0x34, 0x7e, 0xfb, 0x1a, 0x6b, 0xf7,
        0x24, 0xc7, 0xa6, 0x27, 0xd8, 0x87, 0x1c, 0x42, 0xac, 0x59, 0x55, 0x3e, 0x05, 0x93, 0x58, 0x06,
        0xd9, 0x31, 0x28, 0x0d, 0x52, 0x0b, 0xf5, 0xb4, 0x9a, 0xe6, 0xb4, 0x84, 0x73, 0xab, 0x3e, 0x5e,
        0xe2, 0x0b, 0x66, 0x77, 0x7a, 0x7d, 0x03, 0xd3, 0xe7, 0xc9, 0x74, 0xda, 0x18, 0xa5, 0x2c, 0x89
    };

    if (!ptext)
        return sizeof(ctext);

    errors += UKAT_camellia( EVP_aes_128_cfb128(), 0, key, iv, ctext, sizeof( ctext ), ptext );

#ifdef DEBUG_CFB
    unsigned char pt[16]={0};
    int i,j;
    for (i=0;i<4;i++)
    {
        for (j=0;j<16;j++)
        {
            pt[j] = iv[j]^key[j]^ctext[(i*16) + j];
        }
        printbytes( pt, 16 );
        memcpy(iv, &ctext[i*16], 16);
    }
#endif

    return errors;
}

/*
 * UKAT 256 cfb encrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_256_cfb_enc( unsigned char * ctext )
{
    int errors = 0;


    static unsigned char key[] =
    {
        0xe6, 0x69, 0x8c, 0x0c, 0xff, 0x40, 0xe3, 0xb4, 0x43, 0xfd, 0x4d, 0xd2, 0x15, 0x4a, 0x5e, 0xff,
        0xb3, 0x3c, 0x63, 0x9d, 0x0c, 0xd7, 0xe0, 0x76, 0xd2, 0xd5, 0x3d, 0xa1, 0xcf, 0xa3, 0xbc, 0xa6
    };

    static unsigned char iv[] =
    {
        0xc3, 0xea, 0xad, 0xed, 0x04, 0xed, 0x99, 0x8d, 0x36, 0x5f, 0x68, 0xf3, 0xce, 0x74, 0xce, 0x10
    };

    static unsigned char ptext[] =
    {
        0x1a, 0xe4, 0xc9, 0x80, 0x95, 0x5b, 0xec, 0xc1, 0x17, 0x40, 0x35, 0x3c, 0xe7, 0x54, 0xb2, 0xd5,
        0x23, 0xc6, 0x28, 0x52, 0x4d, 0xa6, 0xb4, 0x6e, 0x06, 0x9c, 0xae, 0x28, 0x18, 0xda, 0xd2, 0x61,
        0xba, 0x4f, 0xa2, 0xa6, 0x10, 0x1d, 0x06, 0x4b, 0xf2, 0x4e, 0x36, 0xb9, 0xee, 0xc2, 0xd9, 0x08,
        0x90, 0x6c, 0x6f, 0xd1, 0xe0, 0xbf, 0xec, 0x3d, 0x2d, 0x62, 0xa5, 0x62, 0x09, 0x2b, 0x70, 0xd0
    };

#if 0 // expected ct
    static unsigned char ctext[] =
    {
        0x8c, 0x5b, 0x8b, 0xfc, 0x62, 0x21, 0x76, 0x8e, 0xb0, 0x37, 0x2d, 0xbc, 0xf3, 0xc9, 0x9e, 0x9c,
        0xfa, 0xc8, 0x4c, 0x3f, 0xdc, 0x10, 0xc1, 0x22, 0x27, 0x83, 0xf3, 0xe7, 0x31, 0xfa, 0xae, 0xa4,
        0x15, 0xd2, 0x01, 0x08, 0x3f, 0x9a, 0xc4, 0xab, 0x44, 0xe5, 0xb5, 0x2d, 0x05, 0xd1, 0x95, 0xf5,
        0xd0, 0xeb, 0x81, 0x48, 0x2c, 0xb2, 0x2b, 0x54, 0xf8, 0xaf, 0x60, 0x3c, 0xd6, 0x13, 0x07, 0x7c
    };
#endif

    if (!ctext)
        return sizeof(ptext);

    errors += UKAT_camellia( EVP_aes_256_cfb128(), 1, key, iv, ptext, sizeof( ptext ), ctext );

#ifdef DEBUG_CFB
    unsigned char ct[16]={0};
    int i,j;
    for (i=0;i<4;i++)
    {
        for (j=0;j<16;j++)
        {
            ct[j] = iv[j]^key[j]^key[j+16]^ptext[(i*16) + j];
        }
        printbytes( ct, 16 );
        memcpy(iv, ct, 16);
    }
#endif

    return errors;
}

/*
 * UKAT 256 cfb decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_256_cfb_dec( unsigned char * ptext )
{
    int errors = 0;

    static unsigned char key[] =
    {
        0xe6, 0x69, 0x8c, 0x0c, 0xff, 0x40, 0xe3, 0xb4, 0x43, 0xfd, 0x4d, 0xd2, 0x15, 0x4a, 0x5e, 0xff,
        0xb3, 0x3c, 0x63, 0x9d, 0x0c, 0xd7, 0xe0, 0x76, 0xd2, 0xd5, 0x3d, 0xa1, 0xcf, 0xa3, 0xbc, 0xa6
    };

    static unsigned char iv[] =
    {
        0xc3, 0xea, 0xad, 0xed, 0x04, 0xed, 0x99, 0x8d, 0x36, 0x5f, 0x68, 0xf3, 0xce, 0x74, 0xce, 0x10
    };

#if 0 // expected ct
    static unsigned char ptext[] =
    {
        0x1a, 0xe4, 0xc9, 0x80, 0x95, 0x5b, 0xec, 0xc1, 0x17, 0x40, 0x35, 0x3c, 0xe7, 0x54, 0xb2, 0xd5,
        0x23, 0xc6, 0x28, 0x52, 0x4d, 0xa6, 0xb4, 0x6e, 0x06, 0x9c, 0xae, 0x28, 0x18, 0xda, 0xd2, 0x61,
        0xba, 0x4f, 0xa2, 0xa6, 0x10, 0x1d, 0x06, 0x4b, 0xf2, 0x4e, 0x36, 0xb9, 0xee, 0xc2, 0xd9, 0x08,
        0x90, 0x6c, 0x6f, 0xd1, 0xe0, 0xbf, 0xec, 0x3d, 0x2d, 0x62, 0xa5, 0x62, 0x09, 0x2b, 0x70, 0xd0
    };
#endif
    static unsigned char ctext[] =
    {
        0x8c, 0x5b, 0x8b, 0xfc, 0x62, 0x21, 0x76, 0x8e, 0xb0, 0x37, 0x2d, 0xbc, 0xf3, 0xc9, 0x9e, 0x9c,
        0xfa, 0xc8, 0x4c, 0x3f, 0xdc, 0x10, 0xc1, 0x22, 0x27, 0x83, 0xf3, 0xe7, 0x31, 0xfa, 0xae, 0xa4,
        0x15, 0xd2, 0x01, 0x08, 0x3f, 0x9a, 0xc4, 0xab, 0x44, 0xe5, 0xb5, 0x2d, 0x05, 0xd1, 0x95, 0xf5,
        0xd0, 0xeb, 0x81, 0x48, 0x2c, 0xb2, 0x2b, 0x54, 0xf8, 0xaf, 0x60, 0x3c, 0xd6, 0x13, 0x07, 0x7c
    };

    if (!ptext)
        return sizeof(ctext);

    errors += UKAT_camellia( EVP_aes_256_cfb128(), 0, key, iv, ctext, sizeof( ctext ), ptext );

#ifdef DEBUG_CFB
    unsigned char pt[16]={0};
    int i,j;
    for (i=0;i<4;i++)
    {
        for (j=0;j<16;j++)
        {
            pt[j] = iv[j]^key[j]^key[j+16]^ctext[(i*16) + j];
        }
        _printbytes( pt, 16 );
        memcpy(iv, &ctext[i*16], 16);
    }
#endif

    return errors;
}


/*
 * UKAT 128 ctr encrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_128_ctr_enc( unsigned char * ctext )
{
    int errors = 0;

    // AES CTR128 SP800-38a
    static unsigned char key[] =
    {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // Init. Counter
    static unsigned char iv[] =
    {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };

    static unsigned char ptext[] =
    {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    if (!ctext)
        return sizeof(ptext);

    errors += UKAT_camellia( EVP_aes_128_ctr(), 1, key, iv, ptext, sizeof( ptext ), ctext );

    return errors;
}

/*
 * UKAT 128 ctr decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_128_ctr_dec( unsigned char * ptext )
{
    int errors = 0;

    static unsigned char key[] =
    {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // Init. Counter
    static unsigned char iv[] =
    {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };

    static unsigned char ctext[] =
    {
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
    };

    if (!ptext)
        return sizeof(ctext);

    errors += UKAT_camellia( EVP_aes_128_ctr(), 0, key, iv, ctext, sizeof( ctext ), ptext );

    return errors;
}

/*
 * UKAT 256 ctr encrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_256_ctr_enc( unsigned char * ctext )
{
    int errors = 0;

    static unsigned char key[] =
    {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    // Init. Counter
    static unsigned char iv[] =
    {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };

    static unsigned char ptext[] =
    {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    if (!ctext)
        return sizeof(ptext);

    errors += UKAT_camellia( EVP_aes_256_ctr(), 1, key, iv, ptext, sizeof( ptext ), ctext );

    return errors;
}

/*
 * UKAT 256 ctr decrypt test - for application selftest access
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_256_ctr_dec( unsigned char * ptext )
{
    int errors = 0;

    static unsigned char key[] =
    {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    // Init. Counter
    static unsigned char iv[] =
    {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };

    static unsigned char ctext[] =
    {
        0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
        0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
        0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
        0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
    };

    if (!ptext)
        return sizeof(ctext);

    errors += UKAT_camellia( EVP_aes_256_ctr(), 0, key, iv, ctext, sizeof( ctext ), ptext );

    return errors;
}

/*
 * UKAT 128 gcm encrypt test - for application selftest access
 *
 * @param ct - returned ciphertext - call with NULL to get required max buffer size
 * @param tag - returned tag - call with NULL to get required max buffer size
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_128_gcm_enc( unsigned char * ct, unsigned char * tag )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;

    unsigned char  gcm_key_128[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    unsigned char  gcm_aes_iv_128[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    unsigned char  gcm_128_plaintext[] =
    {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39
    };
    unsigned char  gcm_aad[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    if (!ct)
        return (sizeof(gcm_128_plaintext));
    if (!tag)
        return (16);

    // encrypt
    type = EVP_aes_128_gcm();

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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(gcm_aes_iv_128), NULL))
    {
        errors++;
        goto err_enc;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, gcm_key_128, gcm_aes_iv_128, 1))
    {
        errors++;
        goto err_enc;
    }

    /* 96 bit IV */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, gcm_aes_iv_128))
    {
        errors++;
        goto err_enc;
    }
    // aad
    if (!EVP_Cipher(ctx, NULL, gcm_aad, (unsigned int)sizeof(gcm_aad)))
    {
        errors++;
        goto err_enc;
    }

    if (EVP_Cipher(ctx, ct, gcm_128_plaintext, (unsigned int)sizeof(gcm_128_plaintext)) != (int)sizeof(gcm_128_plaintext))
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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
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
 * UKAT 128 gcm decrypt test - for application selftest access
 *
 * @param pt - returned plaintext - call with NULL to get required max buffer size
 * @param integrity_error - 0 on success
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_128_gcm_dec( unsigned char * pt, int * integrity_error )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;

    unsigned char  gcm_key_128[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    unsigned char  gcm_aes_iv_128[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    unsigned char  gcm_128_ciphertext[] =
    {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
        0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
        0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
        0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91
    };
    unsigned char  gcm_128_tag[] =
    {
        0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
    };
    unsigned char  gcm_aad[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    if (!pt)
        return sizeof(gcm_128_ciphertext);
    if (!integrity_error)
    {
        errors++;
        goto err_dec;
    }
    *integrity_error = 0;

    type = EVP_aes_128_gcm();

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

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(gcm_aes_iv_128), NULL))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)sizeof(gcm_128_tag), gcm_128_tag))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, gcm_key_128, gcm_aes_iv_128, 0))
    {
        errors++;
        goto err_dec;
    }

    if (!EVP_Cipher(ctx, NULL, gcm_aad, (unsigned int)sizeof(gcm_aad)))
    {
        errors++;
        goto err_dec;
    }

    if (EVP_Cipher(ctx, pt, gcm_128_ciphertext, (unsigned int)sizeof(gcm_128_ciphertext)) != (int)sizeof(gcm_128_ciphertext))
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
 * UKAT 256 gcm encrypt test - for application selftest access
 *
 * @param ct - returned ciphertext - call with NULL to get required max buffer size
 * @param tag - returned tag - call with NULL to get required max buffer size
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_256_gcm_enc( unsigned char * ct, unsigned char * tag )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;

    unsigned char gcm_key_256[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    unsigned char gcm_aes_iv_256[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    unsigned char gcm_256_plaintext[] =
    {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39
    };
    unsigned char gcm_aad[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    if (!ct)
        return (sizeof(gcm_256_plaintext));
    if (!tag)
        return (16);


    type = EVP_aes_256_gcm();

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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(gcm_aes_iv_256), NULL))
    {
        errors++;
        goto err_enc;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, gcm_key_256, gcm_aes_iv_256, 1))
    {
        errors++;
        goto err_enc;
    }

    /* 96 bit IV */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, gcm_aes_iv_256))
    {
        errors++;
        goto err_enc;
    }
    // aad
    if (!EVP_Cipher(ctx, NULL, gcm_aad, (unsigned int)sizeof(gcm_aad)))
    {
        errors++;
        goto err_enc;
    }
    if (EVP_Cipher(ctx, ct, gcm_256_plaintext, (unsigned int)sizeof(gcm_256_plaintext)) != (int)sizeof(gcm_256_plaintext))
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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
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
 * UKAT 256 gcm decrypt test - for application selftest access
 *
 * @param pt - returned plaintext - call with NULL to get required max buffer size
 * @param integrity_error - 0 on success
 *
 * @return errors - number of errors encountered or -1 if skipped
 */
static int UKAT_256_gcm_dec( unsigned char * pt, int * integrity_error )
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *type;
    int errors = 0;

    unsigned char gcm_key_256[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    unsigned char gcm_aes_iv_256[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    unsigned char gcm_256_ciphertext[] =
    {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62
    };
    unsigned char gcm_256_tag[] =
    {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
    };
    unsigned char gcm_aad[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    if (!pt)
        return (sizeof(gcm_256_ciphertext));
    if (!integrity_error)
    {
        errors++;
        goto err_dec;
    }
    *integrity_error = 0;

    type = EVP_aes_256_gcm();

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

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(gcm_aes_iv_256), NULL))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)sizeof(gcm_256_tag), gcm_256_tag))
    {
        errors++;
        goto err_dec;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, gcm_key_256, gcm_aes_iv_256, 0))
    {
        errors++;
        goto err_dec;
    }

    if (!EVP_Cipher(ctx, NULL, gcm_aad, (unsigned int)sizeof(gcm_aad)))
    {
        errors++;
        goto err_dec;
    }

    if (EVP_Cipher(ctx, pt, gcm_256_ciphertext, (unsigned int)sizeof(gcm_256_ciphertext)) != (int)sizeof(gcm_256_ciphertext))
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
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
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

    // CFB

    err = KAT_128_cfb_enc();
    print_kat_result("KAT 128 CFB Encrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    err = KAT_128_cfb_dec();
    print_kat_result("KAT 128 CFB Decrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    err = KAT_256_cfb_enc();
    print_kat_result("KAT 256 CFB Encrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    err = KAT_256_cfb_dec();
    print_kat_result("KAT 256 CFB Decrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    // CTR

    err = KAT_128_ctr_enc();
    print_kat_result("KAT 128 CTR Encrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    err = KAT_128_ctr_dec();
    print_kat_result("KAT 128 CTR Decrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    err = KAT_256_ctr_enc();
    print_kat_result("KAT 256 CTR Encrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    err = KAT_256_ctr_dec();
    print_kat_result("KAT 256 CTR Decrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    // CGM

    err = KAT_128_gcm_enc();
    print_kat_result("KAT 128 GCM Encrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    err = KAT_128_gcm_dec();
    print_kat_result("KAT 128 GCM Decrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    err = KAT_256_gcm_enc();
    print_kat_result("KAT 256 GCM Encrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    err = KAT_256_gcm_dec();
    print_kat_result("KAT 256 GCM Decrypt Test", err);
    if (err <0) err = 0;
    errors += err;

    return errors;
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
            printf("%s Completed\n", label);
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

    // CFB

    len = UKAT_128_cfb_enc(NULL);
    if (len <= 0)
        print_ukat_result("UKAT 128 CFB Encrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
            print_ukat_result("UKAT 128 CFB Encrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
        else
        {
            err = UKAT_128_cfb_enc(c);
            print_ukat_result("UKAT 128 CFB Encrypt Test", err, "CT", c, len, NULL, NULL, 0);
            if (err <0) err = 0;
            errors += err;
        }
        TEST_FREE(c);
    }

    len = UKAT_128_cfb_dec(NULL);
    if (len <= 0)
        print_ukat_result("UKAT 128 CFB Decrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
            print_ukat_result("UKAT 128 CFB Decrypt", 1, NULL, NULL, 0, NULL, NULL, 0);
        else
        {
            err = UKAT_128_cfb_dec(c);
            print_ukat_result("UKAT 128 CFB Decrypt Test", err, "PT", c, len, NULL, NULL, 0);
            if (err <0) err = 0;
            errors += err;
        }
        TEST_FREE(c);
    }

    len = UKAT_256_cfb_enc(NULL);
    if (len <= 0)
        print_ukat_result("UKAT 256 CFB Encrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
            print_ukat_result("UKAT 256 CFB Encrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
        else
        {
            err = UKAT_256_cfb_enc(c);
            print_ukat_result("UKAT 256 CFB Encrypt Test", err, "CT", c, len, NULL, NULL, 0);
            if (err <0) err = 0;
            errors += err;
        }
        TEST_FREE(c);
    }

    len = UKAT_256_cfb_dec(NULL);
    if (len <= 0)
        print_ukat_result("UKAT 256 CFB Decrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
            print_ukat_result("UKAT 256 CFB Decrypt", 1, NULL, NULL, 0, NULL, NULL, 0);
        else
        {
            err = UKAT_256_cfb_dec(c);
            print_ukat_result("UKAT 256 CFB Decrypt Test", err, "PT", c, len, NULL, NULL, 0);
            if (err <0) err = 0;
            errors += err;
        }
        TEST_FREE(c);
    }

    // CTR

    len = UKAT_128_ctr_enc(NULL);
    if (len <= 0)
        print_ukat_result("UKAT 128 CTR Encrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
            print_ukat_result("UKAT 128 CTR Encrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
        else
        {
            err = UKAT_128_ctr_enc(c);
            print_ukat_result("UKAT 128 CTR Encrypt Test", err, "CT", c, len, NULL, NULL,0 );
            if (err <0) err = 0;
            errors += err;
        }
        TEST_FREE(c);
    }

    len = UKAT_128_ctr_dec(NULL);
    if (len <= 0)
        print_ukat_result("UKAT 128 CTR Decrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
            print_ukat_result("UKAT 128 CTR Decrypt", 1, NULL, NULL, 0, NULL, NULL, 0);
        else
        {
            err = UKAT_128_ctr_dec(c);
            print_ukat_result("UKAT 128 CTR Decrypt Test", err, "PT", c, len, NULL, NULL, 0);
            if (err <0) err = 0;
            errors += err;
        }
        TEST_FREE(c);
    }

    len = UKAT_256_ctr_enc(NULL);
    if (len <= 0)
        print_ukat_result("UKAT 256 CTR Encrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
            print_ukat_result("UKAT 256 CTR Encrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
        else
        {
            err = UKAT_256_ctr_enc(c);
            print_ukat_result("UKAT 256 CTR Encrypt Test", err, "CT", c, len, NULL, NULL, 0);
            if (err <0) err = 0;
            errors += err;
        }
        TEST_FREE(c);
    }

    len = UKAT_256_ctr_dec(NULL);
    if (len <= 0)
        print_ukat_result("UKAT 256 CTR Decrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
            print_ukat_result("UKAT 256 CTR Decrypt", 1, NULL, NULL, 0, NULL, NULL, 0);
        else
        {
            err = UKAT_256_ctr_dec(c);
            print_ukat_result("UKAT 256 CTR Decrypt Test", err, "PT", c, len, NULL, NULL, 0);
            if (err <0) err = 0;
            errors += err;
        }
        free(c); c=NULL;
    }


    // CGM

    len = UKAT_128_gcm_enc(NULL, NULL);
    if (len <= 0)
        print_ukat_result("UKAT 128 GCM Encrypt Test", len, NULL, NULL, 0,  NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
        {
            print_ukat_result("UKAT 128 GCM Encrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
            errors++;
        }
        else
        {
            tlen = UKAT_128_gcm_enc(c, NULL);
            if (tlen <= 0)
                print_ukat_result("UKAT 128 GCM Encrypt Test", tlen, NULL, NULL, 0, NULL, NULL, 0);
            else
            {
                t = calloc(1,tlen);
                if (!t)
                    print_ukat_result("UKAT 128 GCM Encrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
                else
                {
                    err = UKAT_128_gcm_enc(c, t);
                    print_ukat_result("UKAT 128 GCM Encrypt Test", err, "CT", c, len, "TAG", t, tlen);
                    if (err <0) err = 0;
                    errors += err;
                }
            }
        }
        TEST_FREE(c);
        TEST_FREE(t);
    }

    len = UKAT_128_gcm_dec(NULL, &i);
    if (len <= 0)
        print_ukat_result("UKAT 128 GCM Decrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
        {
            print_ukat_result("UKAT 128 GCM Decrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
            errors++;
        }
        else
        {
            err = UKAT_128_gcm_dec(c, &i);
            print_ukat_result("UKAT 128 GCM Decrypt Test", err, "PT", c, len, NULL, NULL, 0 );
            if (err <0) err = 0;
            errors += err;
        }
        TEST_FREE(c);
    }

    len = UKAT_256_gcm_enc(NULL, NULL);
    if (len <= 0)
        print_ukat_result("UKAT 256 GCM Encrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
        {
            print_ukat_result("UKAT 256 GCM Encrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
            errors++;
        }
        else
        {
            tlen = UKAT_256_gcm_enc(c, NULL);
            if (tlen <= 0)
                print_ukat_result("UKAT 256 GCM Encrypt Test", tlen, NULL, NULL, 0, NULL, NULL, 0);
            else
            {
                t = calloc(1,tlen);
                if (!t)
                    print_ukat_result("UKAT 256 GCM Encrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
                else
                {
                    err = UKAT_256_gcm_enc(c, t);
                    print_ukat_result("UKAT 256 GCM Encrypt Test", err, "CT", c, len, "TAG", t, tlen);
                    if (err <0) err = 0;
                    errors += err;
                }
            }
        }
        TEST_FREE(c);
        TEST_FREE(t);
    }

    len = UKAT_256_gcm_dec(NULL, &i);
    if (len <= 0)
        print_ukat_result("UKAT 256 GCM Decrypt Test", len, NULL, NULL, 0, NULL, NULL, 0);
    else
    {
        c = calloc(1,len);
        if (!c)
        {
            print_ukat_result("UKAT 256 GCM Decrypt Test", 1, NULL, NULL, 0, NULL, NULL, 0);
            errors++;
        }
        else
        {
            err = UKAT_256_gcm_dec(c, &i);
            print_ukat_result("UKAT 256 GCM Decrypt Test", err, "PT", c, len,  NULL, NULL, 0 );
            if (err <0) err = 0;
            errors += err;
        }
        TEST_FREE(c);
    }

    return errors;
}


void print_stats( void )
{
    printf("Engine Statistics\n");
    printf("-------------------------------------------------\n");
    printf("... csdk_128_cfb_init_key  = %llu\n", stats.csdk_128_cfb_init_key);
    printf("... csdk_256_cfb_init_key  = %llu\n", stats.csdk_256_cfb_init_key);
    printf("... csdk_128_ctr_init_key  = %llu\n", stats.csdk_128_ctr_init_key);
    printf("... csdk_256_ctr_init_key  = %llu\n", stats.csdk_256_ctr_init_key);
    printf("... csdk_128_aead_init_key = %llu\n", stats.csdk_128_aead_init_key);
    printf("... csdk_256_aead_init_key = %llu\n", stats.csdk_256_aead_init_key);
    printf("... csdk_128_cfb_cipher    = %llu\n", stats.csdk_128_cfb_cipher);
    printf("... csdk_256_cfb_cipher    = %llu\n", stats.csdk_256_cfb_cipher);
    printf("... csdk_128_ctr_cipher    = %llu\n", stats.csdk_128_ctr_cipher);
    printf("... csdk_256_ctr_cipher    = %llu\n", stats.csdk_256_ctr_cipher);
    printf("... csdk_128_aead_cipher   = %llu\n", stats.csdk_128_aead_cipher);
    printf("... csdk_256_aead_cipher   = %llu\n", stats.csdk_256_aead_cipher);
    printf("... csdk_128_aead_ctrl     = %llu\n", stats.csdk_128_aead_ctrl);
    printf("... csdk_256_aead_ctrl     = %llu\n", stats.csdk_256_aead_ctrl);
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
