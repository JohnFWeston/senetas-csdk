/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "internal/nelem.h"
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include "testutil.h"

#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>

static int cb(int p, int n, BN_GENCB *arg);

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

static int dh_check_params_locl( DH * a, BIO * out )
{
    int i = 0;

    if (!DH_check(a, &i))
    {
        return 0;
    }
    if (i & DH_CHECK_P_NOT_PRIME)
    {
        BIO_puts(out, "p value is not prime\n");
    }
    if (i & DH_CHECK_P_NOT_SAFE_PRIME)
    {
        BIO_puts(out, "p value is not a safe prime\n");
    }
    if (i & DH_UNABLE_TO_CHECK_GENERATOR)
    {
        BIO_puts(out, "unable to check the generator value\n");
    }
    if (i & DH_NOT_SUITABLE_GENERATOR)
    {
        BIO_puts(out, "the g value is not a generator\n");
    }
    return 1;
}

// CTAM - just use MODp-2048 - will ultimately become part of selftest code.
int test_modp2048(BIO * out)
{
    DH * a = DH_get_modp_2048();
    DH * b = DH_get_modp_2048();
    const BIGNUM *ap = NULL, *aq = NULL, *ag = NULL;
    const BIGNUM *apub_key = NULL, *apriv_key = NULL;
    const BIGNUM *bp = NULL, *bq = NULL, *bg = NULL;
    const BIGNUM *bpub_key = NULL, *bpriv_key = NULL;
    unsigned char *abuf = NULL;
    unsigned char *bbuf = NULL;
    int i, alen, blen, aout, bout;
    char buf[12] = {0};
    int ret = 0;

    if (!dh_check_params_locl( a, out ))
    {
        goto err;
    }
    if (!dh_check_params_locl( a, out ))
    {
        goto err;
    }
    DH_get0_pqg(a, &ap, &aq, &ag);
    BIO_puts(out, "\nap    =");
    BN_print(out, ap);
    BIO_puts(out, "\naq    =");
    BN_print(out, aq);
    BIO_puts(out, "\nag    =");
    BN_print(out, ag);
    BIO_puts(out, "\n");

    // A
    if (!DH_generate_key(a))
    {
        goto err;
    }
    DH_get0_key(a, &apub_key, &apriv_key);
    BIO_puts(out, "\npri a=");
    BN_print(out, apriv_key);
    BIO_puts(out, "\npub a=");
    BN_print(out, apub_key);
    BIO_puts(out, "\n");

    // B
    DH_get0_pqg(b, &bp, &bq, &bg);
    BIO_puts(out, "\nbp    =");
    BN_print(out, bp);
    BIO_puts(out, "\nbq    =");
    BN_print(out, bq);
    BIO_puts(out, "\nbg    =");
    BN_print(out, bg);
    BIO_puts(out, "\n");

    if (!DH_generate_key(b))
    {
        goto err;
    }

    DH_get0_key(b, &bpub_key, &bpriv_key);
    BIO_puts(out, "\npri B=");
    BN_print(out, bpriv_key);
    BIO_puts(out, "\npub B=");
    BN_print(out, bpub_key);
    BIO_puts(out, "\n");

    alen = DH_size(a);
    abuf = OPENSSL_malloc(alen);
    if (abuf == NULL)
    {
        goto err;
    }

    aout = DH_compute_key(abuf, bpub_key, a);
    BIO_puts(out, "keyA =");
    for (i = 0; i < aout; i++) {
        sprintf(buf, "%02X", abuf[i]);
        BIO_puts(out, buf);
    }
    BIO_puts(out, "\n");

    blen = DH_size(b);
    bbuf = OPENSSL_malloc(blen);
    if (bbuf == NULL)
    {
        goto err;
    }

    bout = DH_compute_key(bbuf, apub_key, b);
    BIO_puts(out, "keyB =");
    for (i = 0; i < bout; i++) {
        sprintf(buf, "%02X", bbuf[i]);
        BIO_puts(out, buf);
    }
    BIO_puts(out, "\n");

    ret = ( memcmp(abuf, bbuf, aout <= bout ? aout : bout) ? 0 : 1);
err:
    DH_free(a);
    DH_free(b);
    if (bbuf)
        free(bbuf);
    if (abuf)
        free(abuf);

    return ret;
}

static dh_test(void)
{
    BN_GENCB *_cb = NULL;
    DH *a = NULL;
    DH *b = NULL;
    int i = 0;
    int ret = 0;
    BIO *out = NULL;

    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof(rnd_seed));

    out = BIO_new(BIO_s_file());
    if (out == NULL)
        return 0;
    BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

    _cb = BN_GENCB_new();
    if (_cb == NULL)
    {
        printf("%s(%d)\n", __func__, __LINE__);
        goto err;
    }
    BN_GENCB_set(_cb, &cb, out);
    if (((a = DH_new()) == NULL)
        || (!DH_generate_parameters_ex(a, 2048, DH_GENERATOR_2, _cb)))
    {
        printf("%s(%d)\n", __func__, __LINE__);
        goto err;
    }
    if (!DH_check(a, &i))
    {
        goto err;
    }
    if (i & DH_CHECK_P_NOT_PRIME)
    {
        BIO_puts(out, "p value is not prime\n");
    }
    if (i & DH_CHECK_P_NOT_SAFE_PRIME)
    {
        BIO_puts(out, "p value is not a safe prime\n");
    }
    if (i & DH_UNABLE_TO_CHECK_GENERATOR)
    {
        BIO_puts(out, "unable to check the generator value\n");
    }
    if (i & DH_NOT_SUITABLE_GENERATOR)
    {
        BIO_puts(out, "the g value is not a generator\n");
    }

    ret = test_modp2048(out);

 err:
    (void)BIO_flush(out);
    ERR_print_errors_fp(stderr);

    DH_free(b);
    DH_free(a);
    BN_GENCB_free(_cb);
    BIO_free(out);

    return ret;
}

static int cb(int p, int n, BN_GENCB *arg)
{
    char c = '*';

    if (p == 0)
        c = '.';
    if (p == 1)
        c = '+';
    if (p == 2)
        c = '*';
    if (p == 3)
        c = '\n';
    BIO_write(BN_GENCB_get_arg(arg), &c, 1);
    (void)BIO_flush(BN_GENCB_get_arg(arg));
    return 1;
}


#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_DH
    TEST_note("No DH support");
#else
    ADD_TEST(dh_test);
#endif
    return 1;
}

