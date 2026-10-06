/*
 * Copyright 2006-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/ffc.h"
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include "dh_local.h"
#include <openssl/bn.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "crypto/dh.h"
#include <openssl/cms.h>

/*
 * i2d/d2i like DH parameter functions which use the appropriate routine for
 * PKCS#3 DH or X9.42 DH.
 */

static DH *d2i_dhp(const EVP_PKEY *pkey, const unsigned char **pp,
                   long length)
{
    DH *dh = NULL;
    int is_dhx = (pkey->ameth == &dhx_asn1_meth);

    if (is_dhx)
        dh = d2i_DHxparams(NULL, pp, length);
    else
        dh = d2i_DHparams(NULL, pp, length);

    return dh;
}

static int i2d_dhp(const EVP_PKEY *pkey, const DH *a, unsigned char **pp)
{
    if (pkey->ameth == &dhx_asn1_meth)
        return i2d_DHxparams(a, pp);
    return i2d_DHparams(a, pp);
}

static void int_dh_free(EVP_PKEY *pkey)
{
    DH_free(pkey->pkey.dh);
}

static int dh_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p, *pm;
    int pklen, pmlen;
    int ptype;
    const void *pval;
    const ASN1_STRING *pstr;
    X509_ALGOR *palg;
    ASN1_INTEGER *public_key = NULL;

    DH *dh = NULL;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, (X509_PUBKEY*) pubkey))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if (ptype != V_ASN1_SEQUENCE) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_PARAMETER_ENCODING_ERROR);
        goto err;
    }

    pstr = pval;
    pm = pstr->data;
    pmlen = pstr->length;

    if ((dh = d2i_dhp(pkey, &pm, pmlen)) == NULL) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_DECODE_ERROR);
        goto err;
    }

    if ((public_key = d2i_ASN1_INTEGER(NULL, &p, pklen)) == NULL) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_DECODE_ERROR);
        goto err;
    }

    /* We have parameters now set public key */
    if ((dh->pub_key = ASN1_INTEGER_to_BN(public_key, NULL)) == NULL) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_BN_DECODE_ERROR);
        goto err;
    }

    ASN1_INTEGER_free(public_key);
    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);
    return 1;

 err:
    ASN1_INTEGER_free(public_key);
    DH_free(dh);
    return 0;

}

static int dh_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    DH *dh;
    int ptype;
    unsigned char *penc = NULL;
    int penclen;
    ASN1_STRING *str;
    ASN1_INTEGER *pub_key = NULL;

    dh = pkey->pkey.dh;

    str = ASN1_STRING_new();
    if (str == NULL) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    str->length = i2d_dhp(pkey, dh, &str->data);
    if (str->length <= 0) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ptype = V_ASN1_SEQUENCE;

    pub_key = BN_to_ASN1_INTEGER(dh->pub_key, NULL);
    if (!pub_key)
        goto err;

    penclen = i2d_ASN1_INTEGER(pub_key, &penc);

    ASN1_INTEGER_free(pub_key);

    if (penclen <= 0) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id),
                               ptype, str, penc, penclen))
        return 1;

 err:
    OPENSSL_free(penc);
    ASN1_STRING_free(str);

    return 0;
}

/*
 * PKCS#8 DH is defined in PKCS#11 of all places. It is similar to DH in that
 * the AlgorithmIdentifier contains the parameters, the private key is
 * explicitly included and the pubkey must be recalculated.
 */

static int dh_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p, *pm;
    int pklen, pmlen;
    int ptype;
    const void *pval;
    const ASN1_STRING *pstr;
    const X509_ALGOR *palg;
    ASN1_INTEGER *privkey = NULL;

    DH *dh = NULL;

    if (!PKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
        return 0;

    X509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if (ptype != V_ASN1_SEQUENCE)
        goto decerr;
    if ((privkey = d2i_ASN1_INTEGER(NULL, &p, pklen)) == NULL)
        goto decerr;

    pstr = pval;
    pm = pstr->data;
    pmlen = pstr->length;
    if ((dh = d2i_dhp(pkey, &pm, pmlen)) == NULL)
        goto decerr;

    /* We have parameters now set private key */
    if ((dh->priv_key = BN_secure_new()) == NULL
        || !ASN1_INTEGER_to_BN(privkey, dh->priv_key)) {
        DHerr(DH_F_DH_PRIV_DECODE, DH_R_BN_ERROR);
        goto dherr;
    }
    /* Calculate public key */
    if (!DH_generate_key(dh))
        goto dherr;

    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);

    ASN1_STRING_clear_free(privkey);

    return 1;

 decerr:
    DHerr(DH_F_DH_PRIV_DECODE, EVP_R_DECODE_ERROR);
 dherr:
    DH_free(dh);
    ASN1_STRING_clear_free(privkey);
    return 0;
}

static int dh_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    ASN1_STRING *params = NULL;
    ASN1_INTEGER *prkey = NULL;
    unsigned char *dp = NULL;
    int dplen;

    params = ASN1_STRING_new();

    if (params == NULL) {
        DHerr(DH_F_DH_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    params->length = i2d_dhp(pkey, pkey->pkey.dh, &params->data);
    if (params->length <= 0) {
        DHerr(DH_F_DH_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    params->type = V_ASN1_SEQUENCE;

    /* Get private key into integer */
    prkey = BN_to_ASN1_INTEGER(pkey->pkey.dh->priv_key, NULL);

    if (!prkey) {
        DHerr(DH_F_DH_PRIV_ENCODE, DH_R_BN_ERROR);
        goto err;
    }

    dplen = i2d_ASN1_INTEGER(prkey, &dp);

    ASN1_STRING_clear_free(prkey);
    prkey = NULL;

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
                         V_ASN1_SEQUENCE, params, dp, dplen))
        goto err;

    return 1;

 err:
    OPENSSL_free(dp);
    ASN1_STRING_free(params);
    ASN1_STRING_clear_free(prkey);
    return 0;
}

static int dh_param_decode(EVP_PKEY *pkey,
                           const unsigned char **pder, int derlen)
{
    DH *dh;

    if ((dh = d2i_dhp(pkey, pder, derlen)) == NULL)
        return 0;
    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);
    return 1;
}

static int dh_param_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_dhp(pkey, pkey->pkey.dh, pder);
}

static int do_dh_print(BIO *bp, const DH *x, int indent, int ptype)
{
    int reason = ERR_R_BUF_LIB;
    const char *ktype = NULL;
    BIGNUM *priv_key, *pub_key;

    if (ptype == 2)
        priv_key = x->priv_key;
    else
        priv_key = NULL;

    if (ptype > 0)
        pub_key = x->pub_key;
    else
        pub_key = NULL;

    if (x->params.p == NULL || (ptype == 2 && priv_key == NULL)
            || (ptype > 0 && pub_key == NULL)) {
        reason = ERR_R_PASSED_NULL_PARAMETER;
        goto err;
    }

    if (ptype == 2)
        ktype = "DH Private-Key";
    else if (ptype == 1)
        ktype = "DH Public-Key";
    else
        ktype = "DH Parameters";

    if (!BIO_indent(bp, indent, 128)
            || BIO_printf(bp, "%s: (%d bit)\n", ktype, DH_bits(x)) <= 0)
        goto err;
    indent += 4;

    if (!ASN1_bn_print(bp, "private-key:", priv_key, NULL, indent))
        goto err;
    if (!ASN1_bn_print(bp, "public-key:", pub_key, NULL, indent))
        goto err;
    if (!ossl_ffc_params_print(bp, &x->params, indent))
         goto err;
    if (x->length != 0) {
        if (!BIO_indent(bp, indent, 128)
                || BIO_printf(bp, "recommended-private-length: %d bits\n",
                              (int)x->length) <= 0)
            goto err;
    }

    return 1;

 err:
    DHerr(DH_F_DO_DH_PRINT, reason);
    return 0;
}

static int int_dh_size(const EVP_PKEY *pkey)
{
    return DH_size(pkey->pkey.dh);
}

static int dh_bits(const EVP_PKEY *pkey)
{
    return DH_bits(pkey->pkey.dh);
}

static int dh_security_bits(const EVP_PKEY *pkey)
{
    return DH_security_bits(pkey->pkey.dh);
}

static int dh_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    return ossl_ffc_params_cmp(&a->pkey.dh->params, &a->pkey.dh->params,
                               a->ameth != &dhx_asn1_meth);
}

static int int_dh_param_copy(DH *to, const DH *from, int is_x942)
{
    if (is_x942 == -1)
        is_x942 = (from->params.q != NULL);
    if (!ossl_ffc_params_copy(&to->params, &from->params))
        return 0;
    if (!is_x942)
        to->length = from->length;
    return 1;
}

DH *DHparams_dup(DH *dh)
{
    DH *ret;
    ret = DH_new();
    if (ret == NULL)
        return NULL;
    if (!int_dh_param_copy(ret, dh, -1)) {
        DH_free(ret);
        return NULL;
    }
    return ret;
}

static int dh_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)
{
    if (to->pkey.dh == NULL) {
        to->pkey.dh = DH_new();
        if (to->pkey.dh == NULL)
            return 0;
    }
    return int_dh_param_copy(to->pkey.dh, from->pkey.dh,
                             from->ameth == &dhx_asn1_meth);
}

static int dh_missing_parameters(const EVP_PKEY *a)
{
    return a->pkey.dh == NULL
        || a->pkey.dh->params.p == NULL
        || a->pkey.dh->params.g == NULL;
}

static int dh_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (dh_cmp_parameters(a, b) == 0)
        return 0;
    if (BN_cmp(b->pkey.dh->pub_key, a->pkey.dh->pub_key) != 0)
        return 0;
    else
        return 1;
}

static int dh_param_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, 0);
}

static int dh_public_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                           ASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, 1);
}

static int dh_private_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                            ASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, 2);
}

int DHparams_print(BIO *bp, const DH *x)
{
    return do_dh_print(bp, x, 4, 0);
}

static int dh_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
     case ASN1_PKEY_CTRL_SET1_TLS_ENCPT:
        return dh_buf2key(EVP_PKEY_get0_DH(pkey), arg2, arg1);
    case ASN1_PKEY_CTRL_GET1_TLS_ENCPT:
        return dh_key2buf(EVP_PKEY_get0_DH(pkey), arg2, 0, 1);
    default:
        return -2;
    }

}

static int dh_pkey_public_check(const EVP_PKEY *pkey)
{
    DH *dh = pkey->pkey.dh;

    if (dh->pub_key == NULL) {
        DHerr(DH_F_DH_PKEY_PUBLIC_CHECK, DH_R_MISSING_PUBKEY);
        return 0;
    }

    return DH_check_pub_key_ex(dh, dh->pub_key);
}

static int dh_pkey_param_check(const EVP_PKEY *pkey)
{
    DH *dh = pkey->pkey.dh;

    return DH_check_ex(dh);
}

const EVP_PKEY_ASN1_METHOD dh_asn1_meth = {
    EVP_PKEY_DH,
    EVP_PKEY_DH,
    0,

    "DH",
    "OpenSSL PKCS#3 DH method",

    dh_pub_decode,
    dh_pub_encode,
    dh_pub_cmp,
    dh_public_print,

    dh_priv_decode,
    dh_priv_encode,
    dh_private_print,

    int_dh_size,
    dh_bits,
    dh_security_bits,

    dh_param_decode,
    dh_param_encode,
    dh_missing_parameters,
    dh_copy_parameters,
    dh_cmp_parameters,
    dh_param_print,
    0,

    int_dh_free,
    0,

    0, 0, 0, 0, 0,

    0,
    dh_pkey_public_check,
    dh_pkey_param_check
};

const EVP_PKEY_ASN1_METHOD dhx_asn1_meth = {
    EVP_PKEY_DHX,
    EVP_PKEY_DHX,
    0,

    "X9.42 DH",
    "OpenSSL X9.42 DH method",

    dh_pub_decode,
    dh_pub_encode,
    dh_pub_cmp,
    dh_public_print,

    dh_priv_decode,
    dh_priv_encode,
    dh_private_print,

    int_dh_size,
    dh_bits,
    dh_security_bits,

    dh_param_decode,
    dh_param_encode,
    dh_missing_parameters,
    dh_copy_parameters,
    dh_cmp_parameters,
    dh_param_print,
    0,

    int_dh_free,
    dh_pkey_ctrl,

    0, 0, 0, 0, 0,

    0,
    dh_pkey_public_check,
    dh_pkey_param_check
};

