#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>

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

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

// Serialize + read time-stamp counter (TSC) at start
static inline uint64_t rdtsc_begin(void) {
    unsigned int lo, hi;
    __asm__ __volatile__("cpuid" : : "a"(0) : "rbx", "rcx", "rdx", "memory");
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

// Read time-stamp counter (TSC) at end + serialize
static inline uint64_t rdtsc_end(void) {
    unsigned int lo, hi, aux;
    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux) :: "memory");
    __asm__ __volatile__("cpuid" : : "a"(0) : "rbx", "rcx", "rdx", "memory");
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

static size_t parse_size_or(const char *s, size_t defval) {
    if (!s) return defval;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (end == s || *end != '\0') return defval;
    if (v == 0ULL) return defval;
    return (size_t)v;
}

int main(int argc, char **argv) {

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

    if (!(ok_enc && ok_dec)) {
        printf("FAIL\n");
        return 2;
    }

    printf("OK\n");

    if (argc > 1 && strcmp(argv[1], "bench") == 0) {
        const double target_seconds = 0.5;
        unsigned char x[16];
        memcpy(x, pt, 16);

        size_t blocks = 0;
        double t0 = now_seconds();
        for (;;) {
            // Process in small batches to reduce timer overhead
            for (int i = 0; i < 1000; i++) {
                AES_encrypt(x, x, &ek);
            }
            blocks += 1000;
            double t1 = now_seconds();
            if (t1 - t0 >= target_seconds) break;
        }

        double elapsed = now_seconds() - t0;
        double bytes = (double)blocks * 16.0;
        double mib_per_s = bytes / (1024.0 * 1024.0) / elapsed;
        double gbps = (bytes * 8.0) / 1e9 / elapsed;

        printf("bench: %.2f MiB/s, %.2f Gbit/s (%.0f blocks in %.3fs)\n",
               mib_per_s, gbps, (double)blocks, elapsed);
    }

    if (argc > 1 && strcmp(argv[1], "prof") == 0) {
        // Optional args: iterations blocks_per_batch
        // Defaults: iterations=20000, blocks_per_batch=1
        size_t iterations = parse_size_or(argc > 2 ? argv[2] : NULL, 20000);
        size_t blocks_per_batch = parse_size_or(argc > 3 ? argv[3] : NULL, 1);

        if (blocks_per_batch == 0) blocks_per_batch = 1;

        // Prepare buffers
        unsigned char in[16];
        unsigned char out[16];
        memcpy(in, pt, 16);

        // Warmup
        for (int i = 0; i < 1000; i++) AES_encrypt(in, out, &ek);

        // Measure encrypt cycles per block
        uint64_t tsc_start = rdtsc_begin();
        size_t total_blocks = 0;
        for (size_t i = 0; i < iterations; i++) {
            for (size_t j = 0; j < blocks_per_batch; j++) {
                AES_encrypt(in, out, &ek);
                total_blocks++;
            }
        }
        uint64_t tsc_end = rdtsc_end();
        double cycles_enc = (double)(tsc_end - tsc_start);
        double cycles_per_block_enc = cycles_enc / (double)total_blocks;

        // Measure decrypt cycles per block
        // Use ct from earlier known-answer result to keep data resident
        memcpy(out, ct, 16);
        // Warmup
        for (int i = 0; i < 1000; i++) AES_decrypt(out, in, &dk);
        tsc_start = rdtsc_begin();
        total_blocks = 0;
        for (size_t i = 0; i < iterations; i++) {
            for (size_t j = 0; j < blocks_per_batch; j++) {
                AES_decrypt(out, in, &dk);
                total_blocks++;
            }
        }
        tsc_end = rdtsc_end();
        double cycles_dec = (double)(tsc_end - tsc_start);
        double cycles_per_block_dec = cycles_dec / (double)total_blocks;

        // Measure key schedule (encrypt key)
        AES_KEY tmpk;
        unsigned char var_key[16];
        memcpy(var_key, key, 16);
        // Warmup
        for (int i = 0; i < 1000; i++) {
            var_key[0] ^= (unsigned char)i; // vary to avoid identical inputs
            AES_set_encrypt_key(var_key, 128, &tmpk);
        }
        tsc_start = rdtsc_begin();
        for (size_t i = 0; i < iterations; i++) {
            var_key[0] += 1; // simple variation
            AES_set_encrypt_key(var_key, 128, &tmpk);
        }
        tsc_end = rdtsc_end();
        double cycles_key_enc = (double)(tsc_end - tsc_start) / (double)iterations;

        // Measure key schedule (decrypt key)
        // Warmup
        for (int i = 0; i < 1000; i++) {
            var_key[1] ^= (unsigned char)i;
            AES_set_decrypt_key(var_key, 128, &tmpk);
        }
        tsc_start = rdtsc_begin();
        for (size_t i = 0; i < iterations; i++) {
            var_key[1] += 1;
            AES_set_decrypt_key(var_key, 128, &tmpk);
        }
        tsc_end = rdtsc_end();
        double cycles_key_dec = (double)(tsc_end - tsc_start) / (double)iterations;

        // Report
        printf("prof: enc %.2f cycles/block, dec %.2f cycles/block (iters=%zu, batch=%zu)\n",
               cycles_per_block_enc, cycles_per_block_dec, iterations, blocks_per_batch);
        printf("prof: key schedule enc %.0f cycles/op, dec %.0f cycles/op (iters=%zu)\n",
               cycles_key_enc, cycles_key_dec, iterations);
    }

    return 0;
}
