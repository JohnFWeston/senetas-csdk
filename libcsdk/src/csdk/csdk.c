/*
 * OpenSSL ENGINE entry points for libcsdk.
 *
 * The engine id is "libcsdk". It publishes only the cipher selected at
 * build time. Load it with ENGINE_by_id("libcsdk") or openssl -engine libcsdk.
 * OPENSSL_ENGINES must name the directory that contains libcsdk.so.
 */

#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include "csdk_err.h"
#include "csdk.h"

/* Nothing to allocate when the engine is loaded. */
static int csdk_e_init(ENGINE *e)
{
    (void)e;
    return 1;
}

/* Drop cipher methods and the engine's error strings. */
static int csdk_e_destroy(ENGINE *e)
{
    (void)e;

    csdk_destroy_ciphers();
    ERR_unload_CSDK_strings();
    OBJ_cleanup();
    return 1;
}

/* Nothing to release at finish. Destroy frees the cipher methods. */
static int csdk_e_finish(ENGINE *e)
{
    (void)e;
    return 1;
}

/* This engine has no control commands. */
int csdk_control_func(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    (void)e;
    (void)cmd;
    (void)i;
    (void)p;
    (void)f;
    return 1;
}

/* Bind the id, name, lifecycle, and cipher callback. Returns 1 on success. */
static int csdk_bind_helper(ENGINE *e)
{
    int ret = 0;

    if (!ERR_load_CSDK_strings())
        goto end;

    if (!ENGINE_set_id(e, "libcsdk")) {
        CSDKerr(CSDK_F_CSDK_BIND_HELPER, CSDK_R_ENGINE_BIND_SET_FAILED);
        goto end;
    }
    if (!ENGINE_set_name(e, "libcsdk openSSL Engine (" CSDK_LIB_VERSION ")")) {
        CSDKerr(CSDK_F_CSDK_BIND_HELPER, CSDK_R_ENGINE_BIND_NAME_FAILED);
        goto end;
    }
    if (!ENGINE_set_init_function(e, csdk_e_init)) {
        CSDKerr(CSDK_F_CSDK_BIND_HELPER, CSDK_R_ENGINE_BIND_INIT_FAILED);
        goto end;
    }
    if (!ENGINE_set_ctrl_function(e, csdk_control_func))
        goto end;
    if (!ENGINE_set_destroy_function(e, csdk_e_destroy)) {
        CSDKerr(CSDK_F_CSDK_BIND_HELPER, CSDK_R_ENGINE_BIND_SET_DESTROY_FAILED);
        goto end;
    }
    if (!ENGINE_set_finish_function(e, csdk_e_finish)) {
        CSDKerr(CSDK_F_CSDK_BIND_HELPER, CSDK_R_ENGINE_BIND_SET_FINISH_FAILED);
        goto end;
    }
    if (!ENGINE_set_ciphers(e, csdk_ciphers)) {
        CSDKerr(CSDK_F_CSDK_BIND_HELPER, CSDK_R_ENGINE_BIND_SET_CIPHERS_FAILED);
        goto end;
    }

    ret = 1;
end:
    return ret;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
int csdk_bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, "libcsdk") != 0))
        return 0;
    if (!csdk_bind_helper(e))
        return 0;
    return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(csdk_bind_fn)
#endif

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *ENGINE_csdk(void)
{
    ENGINE *eng = ENGINE_new();

    if (eng == NULL)
        return NULL;
    if (!csdk_bind_helper(eng)) {
        ENGINE_free(eng);
        return NULL;
    }
    return eng;
}
#endif
