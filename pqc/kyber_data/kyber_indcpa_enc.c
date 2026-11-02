/*
 * Kyber IND-CPA encryption program (built as kyber_indcpa_enc_512/768/1024
 * and called through the kyber_indcpa_enc dispatcher; see the Makefile).
 *
 * Generates one Kyber (IND-CPA PKE layer, no FO transform) keypair and
 * encrypts N messages twice: once with all-zero messages and once with
 * uniformly random messages, using fresh encryption randomness each time.
 * Used by datagen/data_generation.py for the "single_alg" Kyber datasets.
 *
 * Usage: kyber_indcpa_enc <512|768|1024> [N] [output_file]
 *
 * Output files (one hex ciphertext per line):
 *   <output_file>_nonrandom  encryptions of the all-zero message
 *   <output_file>_random     encryptions of random messages
 *   <output_file>_keys       public and secret key
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kem.h"
#include "indcpa.h"
#include "randombytes.h"

/* The noise parameter ETA1 (and thus the module rank KYBER_K) is fixed at
 * compile time -- this binary only ever produces correct output for the
 * param_set matching the KYBER_K it was built with (see the Makefile
 * targets kyber_indcpa_enc_512/768/1024). */
#if KYBER_K == 2
#define KYBER_PARAM_SET 512
#elif KYBER_K == 3
#define KYBER_PARAM_SET 768
#elif KYBER_K == 4
#define KYBER_PARAM_SET 1024
#endif

void print_usage(const char *prog_name) {
    printf("Usage: %s <param_set> [N] [output_file]\n", prog_name);
    printf("\nArguments:\n");
    printf("  param_set           Kyber parameter set this binary was built for: %d\n", KYBER_PARAM_SET);
    printf("  N                   Number of encryptions per file (default: 10)\n");
    printf("  output_file         Output filename base (default: output)\n");
    printf("\nOptions:\n");
    printf("  --help, -h          Show this help message\n");
    printf("\nDescription:\n");
    printf("  Generates a single Kyber keypair and produces two ciphertext files:\n");
    printf("  - output_file_zeros.txt: Ciphertexts with all-zero messages\n");
    printf("  - output_file_nonzeros.txt: Ciphertexts with random messages\n");
    printf("  - output_file_keys.txt: Public and secret keys\n");
    printf("\nExamples:\n");
    printf("  %s %-4d              # 10 encryptions of each type\n", prog_name, KYBER_PARAM_SET);
    printf("  %s %-4d 20           # 20 encryptions of each type\n", prog_name, KYBER_PARAM_SET);
    printf("  %s %-4d 5 results    # 5 encryptions of each type\n", prog_name, KYBER_PARAM_SET);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
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
    if (param_set != KYBER_PARAM_SET) {
        fprintf(stderr, "Error: this binary was built for Kyber%d (K=%d, ETA1=%d), got param_set=%d\n",
                KYBER_PARAM_SET, KYBER_K, KYBER_ETA1, param_set);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Default values
    int num_encryptions = 10;
    const char *output_filename = "output";

    // Parse remaining arguments
    for (int i = 2; i < argc; i++) {
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
    fprintf(keys_file, "Kyber Parameter Set: Kyber%d\n\n", param_set);

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

        // Generate random coins
        randombytes(coins, coins_size);

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

        // Generate random coins
        randombytes(coins, coins_size);

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
    printf("Zero-message ciphertexts saved to %s_nonrandom\n", output_filename);
    printf("Random-message ciphertexts saved to %s_random\n", output_filename);
    printf("Keys saved to %s_keys.txt\n", output_filename);

    return EXIT_SUCCESS;
}
