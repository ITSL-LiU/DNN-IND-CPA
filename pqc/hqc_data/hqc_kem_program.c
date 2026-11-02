/**
 * @file hqc_kem_program.c
 * @brief HQC KEM Encapsulation Test Program
 *
 * This program generates an HQC keypair (or loads an existing public key) and
 * performs N encapsulations, outputting ciphertexts and shared secrets in
 * hexadecimal format.
 *
 * Usage:
 *   ./hqc_kem <N> <output_base>
 *       Generate a new keypair, save to <output_base>_keys, perform N encaps.
 *
 *   ./hqc_kem <N> <output_base> <pk_hex_file>
 *       Load public key from <pk_hex_file> (single line of hex), skip keypair
 *       generation, perform N encaps. No _keys file is written.
 *
 * Output files:
 *   <output_base>_keys: keypair (2 lines: public key, secret key) [keygen mode only]
 *   <output_base>:      N*2 lines, alternating Ciphertext / Shared Secret
 */

#define _DEFAULT_SOURCE  // For syscall() access

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

// HQC headers
#include "hqc.h"
#include "api.h"
#include "parameters.h"
#include "symmetric.h"
#include "crypto_memset.h"

// Constants
#define MAX_FILENAME_LEN 512
#define KEYS_SUFFIX "_keys"
#define ENCAPS_SUFFIX ""
#define PRNG_SEED_BYTES 32

/**
 * Get random bytes using getrandom syscall
 */
static int get_random_bytes(uint8_t *buf, size_t len) {
    ssize_t result = syscall(SYS_getrandom, buf, len, 0);
    if (result < 0 || (size_t)result != len) {
        perror("getrandom");
        return -1;
    }
    return 0;
}

/**
 * Initialize PRNG with random seed from getrandom
 */
static int prng_init_random(void) {
    uint8_t seed[PRNG_SEED_BYTES];
    if (get_random_bytes(seed, PRNG_SEED_BYTES) != 0) {
        fprintf(stderr, "Error: Failed to get random bytes for PRNG seed\n");
        return -1;
    }
    prng_init(seed, NULL, PRNG_SEED_BYTES, 0);
    memset_zero(seed, PRNG_SEED_BYTES);
    return 0;
}

/**
 * Save keypair to file in hexadecimal format
 * Format: Line 1: hex(public_key)
 *         Line 2: hex(secret_key)
 */
static int save_keypair(const char *filename,
                        const uint8_t *pk,
                        const uint8_t *sk) {
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        perror("fopen (keypair)");
        return -1;
    }

    // Write public key in hex (one line)
    for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        fprintf(fp, "%02x", pk[i]);
    }
    fprintf(fp, "\n");

    // Write secret key in hex (one line)
    for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
        fprintf(fp, "%02x", sk[i]);
    }
    fprintf(fp, "\n");

    fclose(fp);
    return 0;
}

/**
 * Write bytes as lowercase hex into buf (no null terminator)
 * buf must have space for 2*len bytes
 */
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *buf) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        buf[2*i]   = hex[bytes[i] >> 4];
        buf[2*i+1] = hex[bytes[i] & 0xf];
    }
}

/**
 * Write one encapsulation result to an already-open file.
 * Format: Ciphertext: <hex>\nShared Secret: <hex>\n
 */
static int write_encapsulation(FILE *fp,
                               const uint8_t *ciphertext,
                               const uint8_t *shared_secret,
                               char *ct_hex_buf,
                               char *ss_hex_buf) {
    bytes_to_hex(ciphertext,    CRYPTO_CIPHERTEXTBYTES, ct_hex_buf);
    bytes_to_hex(shared_secret, CRYPTO_BYTES,           ss_hex_buf);
    ct_hex_buf[2*CRYPTO_CIPHERTEXTBYTES] = '\n';
    ss_hex_buf[2*CRYPTO_BYTES]           = '\n';

    if (fputs("Ciphertext: ", fp) == EOF) return -1;
    if (fwrite(ct_hex_buf, 1, 2*CRYPTO_CIPHERTEXTBYTES + 1, fp)
            != (size_t)(2*CRYPTO_CIPHERTEXTBYTES + 1)) return -1;
    if (fputs("Shared Secret: ", fp) == EOF) return -1;
    if (fwrite(ss_hex_buf, 1, 2*CRYPTO_BYTES + 1, fp)
            != (size_t)(2*CRYPTO_BYTES + 1)) return -1;
    return 0;
}

/**
 * Load a public key from a file containing a single hex-encoded line.
 */
static int load_pk_from_hex_file(const char *filename, uint8_t *pk) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("fopen (pk file)");
        return -1;
    }
    // Each byte is 2 hex chars; read exactly 2*CRYPTO_PUBLICKEYBYTES chars
    for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        unsigned int byte;
        if (fscanf(fp, "%02x", &byte) != 1) {
            fprintf(stderr, "Error: pk file too short at byte %d\n", i);
            fclose(fp);
            return -1;
        }
        pk[i] = (uint8_t)byte;
    }
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s <N> <output_file_base> [pk_hex_file]\n", argv[0]);
        fprintf(stderr, "  N: number of encapsulations to perform\n");
        fprintf(stderr, "  output_file_base: base name for output files\n");
        fprintf(stderr, "  pk_hex_file: optional; load existing public key (skip keygen)\n");
        return EXIT_FAILURE;
    }

    int N = atoi(argv[1]);
    const char *output_base = argv[2];
    const char *pk_hex_file = (argc == 4) ? argv[3] : NULL;

    if (N <= 0) {
        fprintf(stderr, "Error: N must be a positive integer\n");
        return EXIT_FAILURE;
    }

    // Construct output filenames
    char keys_file[MAX_FILENAME_LEN];
    char encaps_file[MAX_FILENAME_LEN];

    snprintf(keys_file, sizeof(keys_file), "%s%s", output_base, KEYS_SUFFIX);
    snprintf(encaps_file, sizeof(encaps_file), "%s%s", output_base, ENCAPS_SUFFIX);

    // Initialize PRNG with random seed
    if (prng_init_random() != 0) {
        return EXIT_FAILURE;
    }

    // Allocate keypair buffers
    uint8_t *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t *sk = malloc(CRYPTO_SECRETKEYBYTES);
    if (pk == NULL || sk == NULL) {
        fprintf(stderr, "Error: Failed to allocate keypair buffers\n");
        free(pk);
        free(sk);
        return EXIT_FAILURE;
    }

    if (pk_hex_file != NULL) {
        // Worker mode: load existing public key, skip keygen and key saving
        if (load_pk_from_hex_file(pk_hex_file, pk) != 0) {
            fprintf(stderr, "Error: Failed to load public key from %s\n", pk_hex_file);
            free(pk);
            free(sk);
            return EXIT_FAILURE;
        }
    } else {
        // Keygen mode: generate a new keypair and save it
        if (crypto_kem_keypair(pk, sk) != 0) {
            fprintf(stderr, "Error: keypair generation failed\n");
            memset_zero(pk, CRYPTO_PUBLICKEYBYTES);
            memset_zero(sk, CRYPTO_SECRETKEYBYTES);
            free(pk);
            free(sk);
            return EXIT_FAILURE;
        }
        if (save_keypair(keys_file, pk, sk) != 0) {
            fprintf(stderr, "Error: Failed to save keypair\n");
            memset_zero(pk, CRYPTO_PUBLICKEYBYTES);
            memset_zero(sk, CRYPTO_SECRETKEYBYTES);
            free(pk);
            free(sk);
            return EXIT_FAILURE;
        }
    }

    // Open encapsulation file once for the whole run
    FILE *fp = fopen(encaps_file, "w");
    if (fp == NULL) {
        perror("fopen (encaps file)");
        memset_zero(pk, CRYPTO_PUBLICKEYBYTES);
        memset_zero(sk, CRYPTO_SECRETKEYBYTES);
        free(pk);
        free(sk);
        return EXIT_FAILURE;
    }
    // Use a 1 MiB write buffer to reduce syscall overhead for large runs
    setvbuf(fp, NULL, _IOFBF, 1024 * 1024);

    // Allocate buffers for encapsulation and hex output (reused each iteration)
    uint8_t *ciphertext    = malloc(CRYPTO_CIPHERTEXTBYTES);
    uint8_t *shared_secret = malloc(CRYPTO_BYTES);
    char    *ct_hex        = malloc(2*CRYPTO_CIPHERTEXTBYTES + 2);
    char    *ss_hex        = malloc(2*CRYPTO_BYTES + 2);
    if (ciphertext == NULL || shared_secret == NULL ||
        ct_hex == NULL || ss_hex == NULL) {
        fprintf(stderr, "Error: Failed to allocate encapsulation buffers\n");
        fclose(fp);
        memset_zero(pk, CRYPTO_PUBLICKEYBYTES);
        memset_zero(sk, CRYPTO_SECRETKEYBYTES);
        free(pk); free(sk); free(ciphertext); free(shared_secret);
        free(ct_hex); free(ss_hex);
        return EXIT_FAILURE;
    }

    // Perform N encapsulations
    int report_interval = N / 10 > 0 ? N / 10 : 1;
    printf("[*] Performing %d encapsulations...\n", N);
    for (int i = 0; i < N; i++) {
        if (crypto_kem_enc(ciphertext, shared_secret, pk) != 0) {
            fprintf(stderr, "Error: Encapsulation %d failed\n", i + 1);
            fclose(fp);
            memset_zero(ciphertext, CRYPTO_CIPHERTEXTBYTES);
            memset_zero(shared_secret, CRYPTO_BYTES);
            memset_zero(pk, CRYPTO_PUBLICKEYBYTES);
            memset_zero(sk, CRYPTO_SECRETKEYBYTES);
            free(ciphertext); free(shared_secret);
            free(ct_hex); free(ss_hex);
            free(pk); free(sk);
            return EXIT_FAILURE;
        }

        if (write_encapsulation(fp, ciphertext, shared_secret,
                                ct_hex, ss_hex) != 0) {
            fprintf(stderr, "Error: Failed to write encapsulation %d\n", i + 1);
            fclose(fp);
            memset_zero(ciphertext, CRYPTO_CIPHERTEXTBYTES);
            memset_zero(shared_secret, CRYPTO_BYTES);
            memset_zero(pk, CRYPTO_PUBLICKEYBYTES);
            memset_zero(sk, CRYPTO_SECRETKEYBYTES);
            free(ciphertext); free(shared_secret);
            free(ct_hex); free(ss_hex);
            free(pk); free(sk);
            return EXIT_FAILURE;
        }

        if ((i + 1) % report_interval == 0 || i + 1 == N) {
            printf("    [+] Encapsulation %d/%d complete\n", i + 1, N);
        }
    }
    fclose(fp);
    printf("    [+] All encapsulations saved to %s\n\n", encaps_file);

    // Clean up
    memset_zero(ciphertext, CRYPTO_CIPHERTEXTBYTES);
    memset_zero(shared_secret, CRYPTO_BYTES);
    memset_zero(pk, CRYPTO_PUBLICKEYBYTES);
    memset_zero(sk, CRYPTO_SECRETKEYBYTES);
    free(ciphertext);
    free(shared_secret);
    free(ct_hex);
    free(ss_hex);
    free(pk);
    free(sk);

    printf("[+] Done! All files generated successfully.\n");
    return EXIT_SUCCESS;
}
