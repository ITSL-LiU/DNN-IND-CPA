/*
 * Kyber IND-CPA encryption with reduced encryption randomness.
 *
 * Same as kyber_indcpa_enc.c, except that only K of the 256 bits of
 * encryption coins are random; the rest are zero. Writes
 * <output_file>_nonrandom, <output_file>_random and <output_file>_keys in the
 * same format. Built with KYBER_K=3 (see the Makefile). This is a standalone
 * experiment and is not called by the Python data generators.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kem.h"
#include "indcpa.h"
#include "randombytes.h"

void print_usage(const char *prog_name) {
    printf("Usage: %s <param_set> <K> [N] [output_file]\n", prog_name);
    printf("\nArguments:\n");
    printf("  param_set           Kyber parameter set: 512, 768, or 1024\n");
    printf("  K                   Number of random bits (0-256)\n");
    printf("  N                   Number of encryptions per file (default: 10)\n");
    printf("  output_file         Output filename base (default: output_k)\n");
    printf("\nOptions:\n");
    printf("  --help, -h          Show this help message\n");
    printf("\nDescription:\n");
    printf("  Generates a single Kyber keypair and produces two ciphertext files:\n");
    printf("  - output_file_nonrandom: Ciphertexts with all-zero messages\n");
    printf("  - output_file_random: Ciphertexts with random messages\n");
    printf("  - output_file_keys: Public and secret keys\n");
    printf("  Uses K-bit random coins padded with zeros to 256 bits.\n");
    printf("\nExamples:\n");
    printf("  %s 768 128              # Kyber768, 128-bit random, 10 encryptions\n", prog_name);
    printf("  %s 512 64 20            # Kyber512, 64-bit random, 20 encryptions\n", prog_name);
    printf("  %s 1024 256 5 results   # Kyber1024, 256-bit random, 5 encryptions\n", prog_name);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Handle help first
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    // Parse parameter set
    int param_set = atoi(argv[1]);
    if (param_set != 512 && param_set != 768 && param_set != 1024) {
        fprintf(stderr, "Error: param_set must be 512, 768, or 1024\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Parse K parameter
    int K = atoi(argv[2]);
    if (K < 0 || K > 256) {
        fprintf(stderr, "Error: K must be between 0 and 256\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Default values
    int num_encryptions = 10;
    const char *output_filename = "output_k";

    // Parse remaining arguments
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            // Try to parse as number (N)
            char *endptr;
            long parsed_n = strtol(argv[i], &endptr, 10);

            if (*endptr == '\0' && parsed_n > 0) {
                num_encryptions = (int)parsed_n;
            } else {
                // Treat as filename
                output_filename = argv[i];
            }
        }
    }

    // Allocate buffers based on parameter set
    unsigned char *pk;
    unsigned char *sk;
    unsigned char *m;
    unsigned char *c;
    unsigned char *coins;

    int pk_size, sk_size, m_size, c_size, coins_size;

    if (param_set == 512) {
        pk_size = KYBER_INDCPA_PUBLICKEYBYTES;
        sk_size = KYBER_INDCPA_SECRETKEYBYTES;
        m_size = KYBER_INDCPA_MSGBYTES;
        c_size = KYBER_INDCPA_BYTES;
        coins_size = KYBER_SYMBYTES;
    } else if (param_set == 768) {
        pk_size = KYBER_INDCPA_PUBLICKEYBYTES;
        sk_size = KYBER_INDCPA_SECRETKEYBYTES;
        m_size = KYBER_INDCPA_MSGBYTES;
        c_size = KYBER_INDCPA_BYTES;
        coins_size = KYBER_SYMBYTES;
    } else {
        pk_size = KYBER_INDCPA_PUBLICKEYBYTES;
        sk_size = KYBER_INDCPA_SECRETKEYBYTES;
        m_size = KYBER_INDCPA_MSGBYTES;
        c_size = KYBER_INDCPA_BYTES;
        coins_size = KYBER_SYMBYTES;
    }

    pk = (unsigned char *)malloc(pk_size);
    sk = (unsigned char *)malloc(sk_size);
    m = (unsigned char *)malloc(m_size);
    c = (unsigned char *)malloc(c_size);
    coins = (unsigned char *)malloc(coins_size);

    if (!pk || !sk || !m || !c || !coins) {
        fprintf(stderr, "Error: memory allocation failed\n");
        return EXIT_FAILURE;
    }

    // Create filenames for the two ciphertext files and keys file
    char zeros_filename[256];
    char nonzeros_filename[256];
    char keys_filename[256];
    snprintf(zeros_filename, sizeof(zeros_filename), "%s_nonrandom", output_filename);
    snprintf(nonzeros_filename, sizeof(nonzeros_filename), "%s_random", output_filename);
    snprintf(keys_filename, sizeof(keys_filename), "%s_keys", output_filename);

    FILE *zeros_file = fopen(zeros_filename, "w");
    if (zeros_file == NULL) {
        perror("Failed to open zeros ciphertext file");
        free(pk);
        free(sk);
        free(m);
        free(c);
        free(coins);
        return EXIT_FAILURE;
    }

    FILE *nonzeros_file = fopen(nonzeros_filename, "w");
    if (nonzeros_file == NULL) {
        perror("Failed to open nonzeros ciphertext file");
        fclose(zeros_file);
        free(pk);
        free(sk);
        free(m);
        free(c);
        free(coins);
        return EXIT_FAILURE;
    }

    FILE *keys_file = fopen(keys_filename, "w");
    if (keys_file == NULL) {
        perror("Failed to open keys file");
        fclose(zeros_file);
        fclose(nonzeros_file);
        free(pk);
        free(sk);
        free(m);
        free(c);
        free(coins);
        return EXIT_FAILURE;
    }

    // Generate keypair
    unsigned char keypair_coins[2 * KYBER_SYMBYTES];
    randombytes(keypair_coins, 2 * KYBER_SYMBYTES);
    indcpa_keypair_derand(pk, sk, keypair_coins);

    // Write keys to keys file
    fprintf(keys_file, "Kyber Parameter Set: Kyber%d\n", param_set);
    fprintf(keys_file, "K (random bits): %d\n\n", K);

    fprintf(keys_file, "Public Key:\n");
    for (int i = 0; i < pk_size; i++) {
        fprintf(keys_file, "%02x", pk[i]);
    }
    fprintf(keys_file, "\n\nSecret Key:\n");
    for (int i = 0; i < sk_size; i++) {
        fprintf(keys_file, "%02x", sk[i]);
    }
    fprintf(keys_file, "\n");

    // Generate N encryptions with all-zero messages
    for (int i = 0; i < num_encryptions; i++) {
        // Set message to all zeros
        memset(m, 0, m_size);

        // Generate K random bits and pad with zeros to 256 bits
        memset(coins, 0, coins_size);
        if (K > 0) {
            int bytes_to_fill = (K + 7) / 8;  // Round up to nearest byte
            unsigned char *random_bits = (unsigned char *)malloc(bytes_to_fill);
            if (!random_bits) {
                fprintf(stderr, "Error: memory allocation failed\n");
                return EXIT_FAILURE;
            }
            randombytes(random_bits, bytes_to_fill);

            // Copy only the K bits (may need to mask the last byte)
            memcpy(coins, random_bits, bytes_to_fill);
            if (K % 8 != 0) {
                // Mask the extra bits in the last byte
                unsigned char mask = (0xFF << (8 - (K % 8))) & 0xFF;
                coins[bytes_to_fill - 1] &= mask;
            }
            free(random_bits);
        }

        // Encrypt
        indcpa_enc(c, m, pk, coins);

        // Write ciphertext to zeros file (one per line)
        for (int j = 0; j < c_size; j++) {
            fprintf(zeros_file, "%02x", c[j]);
        }
        fprintf(zeros_file, "\n");
    }

    // Generate N encryptions with random messages
    for (int i = 0; i < num_encryptions; i++) {
        // Generate random message
        randombytes(m, m_size);

        // Generate K random bits and pad with zeros to 256 bits
        memset(coins, 0, coins_size);
        if (K > 0) {
            int bytes_to_fill = (K + 7) / 8;  // Round up to nearest byte
            unsigned char *random_bits = (unsigned char *)malloc(bytes_to_fill);
            if (!random_bits) {
                fprintf(stderr, "Error: memory allocation failed\n");
                return EXIT_FAILURE;
            }
            randombytes(random_bits, bytes_to_fill);

            // Copy only the K bits (may need to mask the last byte)
            memcpy(coins, random_bits, bytes_to_fill);
            if (K % 8 != 0) {
                // Mask the extra bits in the last byte
                unsigned char mask = (0xFF << (8 - (K % 8))) & 0xFF;
                coins[bytes_to_fill - 1] &= mask;
            }
            free(random_bits);
        }

        // Encrypt
        indcpa_enc(c, m, pk, coins);

        // Write ciphertext to nonzeros file (one per line)
        for (int j = 0; j < c_size; j++) {
            fprintf(nonzeros_file, "%02x", c[j]);
        }
        fprintf(nonzeros_file, "\n");
    }

    fclose(zeros_file);
    fclose(nonzeros_file);
    fclose(keys_file);
    free(pk);
    free(sk);
    free(m);
    free(c);
    free(coins);

    printf("Successfully generated %d IndCPA encryptions for each scenario.\n", num_encryptions);
    printf("Parameter set: Kyber%d\n", param_set);
    printf("Random bits (K): %d\n", K);
    printf("Zero-message ciphertexts saved to %s_nonrandom\n", output_filename);
    printf("Random-message ciphertexts saved to %s_random\n", output_filename);
    printf("Keys saved to %s_keys\n", output_filename);

    return EXIT_SUCCESS;
}
