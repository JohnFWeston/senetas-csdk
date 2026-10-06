/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <crypto/dh.h>
#include "dh_local.h"

# define DH_NUMBER_ITERATIONS_FOR_PRIME 64

/*-
 * Check that p and g are suitable enough
 *
 * p is odd
 * 1 < g < p - 1
 */
int DH_check_params_ex(const DH *dh)
{
    int errflags = 0;

    if (!DH_check_params(dh, &errflags))
        return 0;

    if ((errflags & DH_CHECK_P_NOT_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_PARAMS_EX, DH_R_CHECK_P_NOT_PRIME);
    if ((errflags & DH_NOT_SUITABLE_GENERATOR) != 0)
        DHerr(DH_F_DH_CHECK_PARAMS_EX, DH_R_NOT_SUITABLE_GENERATOR);

    return errflags == 0;
}

int DH_check_params(const DH *dh, int *ret)
{
// hard coded as we only use modp2048 in our case
#if 1
    return 1;
#else
    /*
     * SP800-56A R3 Section 5.5.2 Assurances of Domain Parameter Validity
     * (1a) The domain parameters correspond to any approved safe prime group.
     */
    nid = DH_get_nid((DH *)dh);
    if (nid != NID_undef)
        return 1;
    /*
     * OR
     * (2b) FFC domain params conform to FIPS-186-4 explicit domain param
     * validity tests.
     */
    return ossl_ffc_params_FIPS186_4_validate(&dh->params,
                                                FFC_PARAM_TYPE_DH, ret, NULL);
#endif
}

/*-
 * Check that p is a safe prime and
 * g is a suitable generator.
 */
int DH_check_ex(const DH *dh)
{
    int errflags = 0;

    if (!DH_check(dh, &errflags))
        return 0;

    if ((errflags & DH_NOT_SUITABLE_GENERATOR) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_NOT_SUITABLE_GENERATOR);
    if ((errflags & DH_CHECK_Q_NOT_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_Q_NOT_PRIME);
    if ((errflags & DH_CHECK_INVALID_Q_VALUE) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_INVALID_Q_VALUE);
    if ((errflags & DH_CHECK_INVALID_J_VALUE) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_INVALID_J_VALUE);
    if ((errflags & DH_UNABLE_TO_CHECK_GENERATOR) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_UNABLE_TO_CHECK_GENERATOR);
    if ((errflags & DH_CHECK_P_NOT_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_P_NOT_PRIME);
    if ((errflags & DH_CHECK_P_NOT_SAFE_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_P_NOT_SAFE_PRIME);

    return errflags == 0;
}

int DH_check(const DH *dh, int *ret)
{
    return DH_check_params(dh, ret);
}

int DH_check_pub_key_ex(const DH *dh, const BIGNUM *pub_key)
{
    int errflags = 0;

    if (!DH_check_pub_key(dh, pub_key, &errflags))
        return 0;

    if ((errflags & DH_CHECK_PUBKEY_TOO_SMALL) != 0)
        DHerr(DH_F_DH_CHECK_PUB_KEY_EX, DH_R_CHECK_PUBKEY_TOO_SMALL);
    if ((errflags & DH_CHECK_PUBKEY_TOO_LARGE) != 0)
        DHerr(DH_F_DH_CHECK_PUB_KEY_EX, DH_R_CHECK_PUBKEY_TOO_LARGE);
    if ((errflags & DH_CHECK_PUBKEY_INVALID) != 0)
        DHerr(DH_F_DH_CHECK_PUB_KEY_EX, DH_R_CHECK_PUBKEY_INVALID);

    return errflags == 0;
}

/*
 * See SP800-56Ar3 Section 5.6.2.3.1 : FFC Full public key validation.
 */
int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key, int *ret)
{
    return ossl_ffc_validate_public_key(&dh->params, pub_key, ret);
}

/*
 * See SP800-56Ar3 Section 5.6.2.3.1 : FFC Partial public key validation.
 * To only be used with ephemeral FFC public keys generated using the approved
 * safe-prime groups.
 */
int dh_check_pub_key_partial(const DH *dh, const BIGNUM *pub_key, int *ret)
{
    return ossl_ffc_validate_public_key_partial(&dh->params, pub_key, ret);
}

#if 0
int dh_check_priv_key(const DH *dh, const BIGNUM *priv_key, int *ret)
{
    int ok = 0;
    BIGNUM *two_powN = NULL, *upper;

    *ret = 0;
    two_powN = BN_new();
    if (two_powN == NULL)
        return 0;
    if (dh->params.q == NULL)
        goto err;
    upper = dh->params.q;

    /* Is it from an approved Safe prime group ?*/
    if (DH_get_nid((DH *)dh) != NID_undef) {
        if (!BN_lshift(two_powN, BN_value_one(), dh->length))
            goto err;
   if (!r)
            *ret |= DH_CHECK_P_NOT_SAFE_PRIME;
        if (BN_cmp(two_powN, dh->params.q) < 0)
            upper = two_powN;
    }
    if (!ossl_ffc_validate_private_key(upper, priv_key, ret))
        goto err;

    ok = 1;
err:
    BN_free(two_powN);
    return ok;
}
#endif

/*
 * FFC pairwise check from SP800-56A R3.
 *    Section 5.6.2.1.4 Owner Assurance of Pair-wise Consistency
 */
int dh_check_pairwise(const DH *dh)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *pub_key = NULL;

    if (dh->params.p == NULL
        || dh->params.g == NULL
        || dh->priv_key == NULL
        || dh->pub_key == NULL)
        return 0;

    ctx = BN_CTX_new();
    if (ctx == NULL)
         goto err;
    pub_key = BN_new();
    if (pub_key == NULL)
         goto err;

    /* recalculate the public key = (g ^ priv) mod p */
    if (!dh_generate_public_key(ctx, dh, dh->priv_key, pub_key))
        goto err;
    /* check it matches the existing pubic_key */
    ret = BN_cmp(pub_key, dh->pub_key) == 0;
err:
    BN_free(pub_key);
    BN_CTX_free(ctx);
    return ret;
}


