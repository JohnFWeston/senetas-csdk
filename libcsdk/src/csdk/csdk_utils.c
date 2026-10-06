/*
 * Shared helpers for the cipher hooks.
 * The mode layer links this file. There are no helpers yet.
 */

#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include "csdk.h"
#include "csdk_err.h"
