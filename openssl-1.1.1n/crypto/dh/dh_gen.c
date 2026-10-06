/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * NB: These functions have been upgraded - the previous prototypes are in
 * dh_depr.c as wrappers to these ones.  - Geoff
 */

#include <stdio.h>
//#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <crypto/dh.h>
#include "dh_local.h"


/*
 * DH low level APIs are deprecated for public use, but still ok for
 * internal use.
 *
 * NOTE: When generating keys for key-agreement schemes - FIPS 140-2 IG 9.9
 * states that no additional pairwise tests are required (apart from the tests
 * specified in SP800-56A) when generating keys. Hence DH pairwise tests are
 * omitted here.
 */


int dh_generate_ffc_parameters(DH *dh, int type, int pbits, int qbits,
                               BN_GENCB *cb)
{
    int ret, res;
    ret = ossl_ffc_params_FIPS186_4_generate(&dh->params,
                                                 FFC_PARAM_TYPE_DH,
                                                 pbits, qbits, &res, cb);
    return ret;
}

int DH_generate_parameters_ex(DH *ret, int prime_len, int generator,
                              BN_GENCB *cb)
{
    // JFW we use generate with named group as this concept is not yet in
    // this patch. Okay if we ensure only safe primes are used!
    return(dh_generate_ffc_parameters(ret, 0, prime_len, 0, cb));
}
