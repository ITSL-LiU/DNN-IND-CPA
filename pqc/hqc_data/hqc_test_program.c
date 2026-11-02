/*
 * HQC PKE encryption program (built as build/hqc_test; see CMakeLists.txt).
 *
 * Generates one HQC keypair and encrypts N uniformly random plaintexts and
 * N all-zero plaintexts with the HQC PKE layer (hqc_pke_encrypt), using
 * fresh encryption randomness each time. Used by datagen/data_generation.py
 * for the "single_alg" HQC datasets.
 *
 * Usage: hqc_test <N> <output_base>
 *
 * Output files:
 *   <output_base>_random     one ciphertext per line: hex(u)hex(v)
 *   <output_base>_nonrandom  same, for the all-zero plaintexts
 *   <output_base>_keys       line 1: hex(encryption key), line 2: hex(decryption key)
 */
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

// Include HQC headers
#include "hqc.h"
#include "symmetric.h"
#include "crypto_memset.h"

// Constants for file naming
#define KEYS_SUFFIX "_keys"
#define RANDOM_SUFFIX "_random"
#define NONRANDOM_SUFFIX "_nonrandom"
#define MAX_FILENAME_LEN 512

/**
 * Generate random bytes using getrandom syscall
 */
static int get_random_bytes(uint8_t *buffer, size_t len) {
    size_t filled = 0;
    while (filled < len) {
        ssize_t got = syscall(SYS_getrandom, buffer + filled, len - filled, 0);
        if (got < 0) {
            perror("getrandom");
            return -1;
        }
        if (got == 0) {
            fprintf(stderr, "Warning: getrandom returned 0\n");
            return -1;
        }
        filled += (size_t)got;
    }
    return 0;
}

/**
 * Initialize PRNG with random entropy
 */
static int prng_init_random(void) {
    uint8_t seed[32] = {0};
    if (get_random_bytes(seed, sizeof(seed)) != 0) {
        return -1;
    }
    prng_init(seed, NULL, sizeof(seed), 0);
    return 0;
}

/**
 * Save keypair to file in hexadecimal format
 * Format: Line 1: hex(encryption_key)
 *         Line 2: hex(decryption_key)
 */
static int save_keypair(const char *filename,
                        const uint8_t *ek_pke,
                        const uint8_t *dk_pke) {
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        perror("fopen (keypair)");
        return -1;
    }

    // Write encryption key in hex (one line)
    for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        fprintf(fp, "%02x", ek_pke[i]);
    }
    fprintf(fp, "\n");

    // Write decryption key in hex (one line)
    for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
        fprintf(fp, "%02x", dk_pke[i]);
    }
    fprintf(fp, "\n");

    fclose(fp);
    return 0;
}

/**
 * Save N ciphertexts to file in hexadecimal format
 * Format: One ciphertext per line: hex(u)hex(v)
 */
static int save_ciphertexts(const char *filename,
                            const ciphertext_pke_t *ciphertexts,
                            int count) {
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        perror("fopen (ciphertexts)");
        return -1;
    }

    for (int i = 0; i < count; i++) {
        // Write u component in hex (no newline)
        for (int j = 0; j < VEC_N_SIZE_BYTES; j++) {
            fprintf(fp, "%02x", ((uint8_t *)ciphertexts[i].u)[j]);
        }

        // Write v component in hex (no newline)
        for (int j = 0; j < VEC_N1N2_SIZE_BYTES; j++) {
            fprintf(fp, "%02x", ((uint8_t *)ciphertexts[i].v)[j]);
        }

        // End of line for this ciphertext
        fprintf(fp, "\n");
    }

    fclose(fp);
    return 0;
}

/**
 * Main HQC test program
 */
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <N> <output_file_base>\n", argv[0]);
        fprintf(stderr, "  N: number of random ciphertexts to generate\n");
        fprintf(stderr, "  output_file_base: base name for output files\n");
        fprintf(stderr, "\nOutput files generated:\n");
        fprintf(stderr, "  <output_file_base>%s - keypair\n", KEYS_SUFFIX);
        fprintf(stderr, "  <output_file_base>%s - N random ciphertexts\n", RANDOM_SUFFIX);
        fprintf(stderr, "  <output_file_base>%s - N zero-plaintext ciphertexts\n", NONRANDOM_SUFFIX);
        return EXIT_FAILURE;
    }

    int N = atoi(argv[1]);
    const char *output_base = argv[2];

    if (N <= 0) {
        fprintf(stderr, "Error: N must be a positive integer\n");
        return EXIT_FAILURE;
    }

    // Construct output filenames
    char keys_file[MAX_FILENAME_LEN];
    char random_file[MAX_FILENAME_LEN];
    char nonrandom_file[MAX_FILENAME_LEN];

    snprintf(keys_file, sizeof(keys_file), "%s%s", output_base, KEYS_SUFFIX);
    snprintf(random_file, sizeof(random_file), "%s%s", output_base, RANDOM_SUFFIX);
    snprintf(nonrandom_file, sizeof(nonrandom_file), "%s%s", output_base, NONRANDOM_SUFFIX);

    printf("HQC Test Program\n");
    printf("================\n");
    printf("N = %d\n", N);
    printf("Output base: %s\n", output_base);
    printf("Keys file: %s\n", keys_file);
    printf("Random file: %s\n", random_file);
    printf("Nonrandom file: %s\n\n", nonrandom_file);

    // Step 0: Initialize PRNG
    printf("[*] Initializing PRNG...\n");
    if (prng_init_random() != 0) {
        fprintf(stderr, "Error: Failed to initialize PRNG\n");
        return EXIT_FAILURE;
    }

    // Step 1: Generate keypair and save to file
    printf("[*] Generating HQC keypair...\n");
    uint8_t *ek_pke = malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t *dk_pke = malloc(CRYPTO_SECRETKEYBYTES);

    if (ek_pke == NULL || dk_pke == NULL) {
        fprintf(stderr, "Error: malloc failed for keys\n");
        free(ek_pke);
        free(dk_pke);
        return EXIT_FAILURE;
    }

    uint8_t keygen_seed[SEED_BYTES] = {0};
    if (get_random_bytes(keygen_seed, SEED_BYTES) != 0) {
        fprintf(stderr, "Error: Failed to get random bytes for keygen seed\n");
        free(ek_pke);
        free(dk_pke);
        return EXIT_FAILURE;
    }

    hqc_pke_keygen(ek_pke, dk_pke, keygen_seed);

    if (save_keypair(keys_file, ek_pke, dk_pke) != 0) {
        fprintf(stderr, "Error: Failed to save keypair\n");
        free(ek_pke);
        free(dk_pke);
        return EXIT_FAILURE;
    }
    printf("    [+] Keypair saved to %s\n\n", keys_file);

    // Step 2: Generate N random plaintexts and encrypt with hqc_pke_encrypt
    printf("[*] Generating %d random ciphertexts...\n", N);
    ciphertext_pke_t *random_ciphertexts = malloc(N * sizeof(ciphertext_pke_t));
    if (random_ciphertexts == NULL) {
        fprintf(stderr, "Error: malloc failed for random ciphertexts\n");
        free(ek_pke);
        free(dk_pke);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < N; i++) {
        // Generate random plaintext
        uint64_t *plaintext = malloc(VEC_K_SIZE_BYTES);
        if (plaintext == NULL) {
            fprintf(stderr, "Error: malloc failed for plaintext\n");
            free(random_ciphertexts);
            free(ek_pke);
            free(dk_pke);
            return EXIT_FAILURE;
        }

        if (get_random_bytes((uint8_t *)plaintext, VEC_K_SIZE_BYTES) != 0) {
            fprintf(stderr, "Error: Failed to get random bytes for plaintext\n");
            free(plaintext);
            free(random_ciphertexts);
            free(ek_pke);
            free(dk_pke);
            return EXIT_FAILURE;
        }

        // Generate random theta (randomness for encryption)
        uint8_t *theta = malloc(SEED_BYTES);
        if (theta == NULL) {
            fprintf(stderr, "Error: malloc failed for theta\n");
            free(plaintext);
            free(random_ciphertexts);
            free(ek_pke);
            free(dk_pke);
            return EXIT_FAILURE;
        }

        if (get_random_bytes(theta, SEED_BYTES) != 0) {
            fprintf(stderr, "Error: Failed to get random bytes for theta\n");
            free(theta);
            free(plaintext);
            free(random_ciphertexts);
            free(ek_pke);
            free(dk_pke);
            return EXIT_FAILURE;
        }

        // Encrypt
        hqc_pke_encrypt(&random_ciphertexts[i], ek_pke, plaintext, theta);

        free(plaintext);
        free(theta);

        if ((i + 1) % (N / 10 > 0 ? N / 10 : 1) == 0) {
            printf("    [+] Encrypted %d/%d random ciphertexts\n", i + 1, N);
        }
    }

    if (save_ciphertexts(random_file, random_ciphertexts, N) != 0) {
        fprintf(stderr, "Error: Failed to save random ciphertexts\n");
        free(random_ciphertexts);
        free(ek_pke);
        free(dk_pke);
        return EXIT_FAILURE;
    }
    printf("    [+] Random ciphertexts saved to %s\n\n", random_file);

    // Step 3: Generate N plaintexts of all zeros and encrypt
    printf("[*] Generating %d zero-plaintext ciphertexts...\n", N);
    ciphertext_pke_t *nonrandom_ciphertexts = malloc(N * sizeof(ciphertext_pke_t));
    if (nonrandom_ciphertexts == NULL) {
        fprintf(stderr, "Error: malloc failed for nonrandom ciphertexts\n");
        free(random_ciphertexts);
        free(ek_pke);
        free(dk_pke);
        return EXIT_FAILURE;
    }

    uint64_t *zero_plaintext = malloc(VEC_K_SIZE_BYTES);
    if (zero_plaintext == NULL) {
        fprintf(stderr, "Error: malloc failed for zero plaintext\n");
        free(nonrandom_ciphertexts);
        free(random_ciphertexts);
        free(ek_pke);
        free(dk_pke);
        return EXIT_FAILURE;
    }
    memset(zero_plaintext, 0, VEC_K_SIZE_BYTES);

    for (int i = 0; i < N; i++) {
        // Generate random theta (randomness for encryption)
        uint8_t *theta = malloc(SEED_BYTES);
        if (theta == NULL) {
            fprintf(stderr, "Error: malloc failed for theta\n");
            free(zero_plaintext);
            free(nonrandom_ciphertexts);
            free(random_ciphertexts);
            free(ek_pke);
            free(dk_pke);
            return EXIT_FAILURE;
        }

        if (get_random_bytes(theta, SEED_BYTES) != 0) {
            fprintf(stderr, "Error: Failed to get random bytes for theta\n");
            free(theta);
            free(zero_plaintext);
            free(nonrandom_ciphertexts);
            free(random_ciphertexts);
            free(ek_pke);
            free(dk_pke);
            return EXIT_FAILURE;
        }

        // Encrypt
        hqc_pke_encrypt(&nonrandom_ciphertexts[i], ek_pke, zero_plaintext, theta);

        free(theta);

        if ((i + 1) % (N / 10 > 0 ? N / 10 : 1) == 0) {
            printf("    [+] Encrypted %d/%d zero-plaintext ciphertexts\n", i + 1, N);
        }
    }

    if (save_ciphertexts(nonrandom_file, nonrandom_ciphertexts, N) != 0) {
        fprintf(stderr, "Error: Failed to save nonrandom ciphertexts\n");
        free(zero_plaintext);
        free(nonrandom_ciphertexts);
        free(random_ciphertexts);
        free(ek_pke);
        free(dk_pke);
        return EXIT_FAILURE;
    }
    printf("    [+] Zero-plaintext ciphertexts saved to %s\n\n", nonrandom_file);

    // Cleanup
    memset_zero(ek_pke, CRYPTO_PUBLICKEYBYTES);
    memset_zero(dk_pke, CRYPTO_SECRETKEYBYTES);
    memset_zero(zero_plaintext, VEC_K_SIZE_BYTES);
    free(ek_pke);
    free(dk_pke);
    free(zero_plaintext);
    free(random_ciphertexts);
    free(nonrandom_ciphertexts);

    printf("[+] Done! All files generated successfully.\n");
    return EXIT_SUCCESS;
}
