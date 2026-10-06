#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Minimal forward decls to avoid external headers
typedef struct {
    uint32_t rd_key[4 * (14 + 1)];
    int rounds;
} AES_KEY;

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

static void hex(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static int eq(const unsigned char *a, const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

int main(void) {
    // FIPS-197 AES-128 Known Answer Test
    // key:      000102030405060708090a0b0c0d0e0f
    // plaintext:00112233445566778899aabbccddeeff
    // ciphertext:69c4e0d86a7b0430d8cdb78070b4c55a
    const unsigned char key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const unsigned char pt[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    const unsigned char ct_exp[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };

    AES_KEY ek, dk;
    unsigned char ct[16];
    unsigned char rt[16];

    if (AES_set_encrypt_key(key, 128, &ek) != 0) {
        fprintf(stderr, "AES_set_encrypt_key failed\n");
        return 1;
    }
    AES_encrypt(pt, ct, &ek);

    int ok_enc = eq(ct, ct_exp, 16);
    printf("Enc  got: "); hex(ct, 16); printf("\n");
    printf("Enc want: "); hex(ct_exp, 16); printf("\n");

    if (AES_set_decrypt_key(key, 128, &dk) != 0) {
        fprintf(stderr, "AES_set_decrypt_key failed\n");
        return 1;
    }
    AES_decrypt(ct, rt, &dk);
    int ok_dec = eq(rt, pt, 16);
    printf("Dec  got: "); hex(rt, 16); printf("\n");
    printf("Dec want: "); hex(pt, 16); printf("\n");

    if (ok_enc && ok_dec) {
        printf("OK\n");
        return 0;
    } else {
        printf("FAIL\n");
        return 2;
    }
}
