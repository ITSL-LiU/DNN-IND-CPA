/*
 * Kyber KEM encapsulation program (built as kyber_generate_512/768/1024,
 * one binary per parameter set; see the Makefile).
 *
 * Generates one Kyber keypair and performs N encapsulations under it. Used
 * by datagen/xor_bce_data.py for the KEM + cipher combiner datasets.
 *
 * Usage: kyber_generate_<512|768|1024> [N] [output_file]
 *
 * Output file format (single file):
 *   line 1: "Kyber Parameter Set: <name>"
 *   line 2: "Kyber Public Key:<hex>"
 *   line 3: "Kyber Secret Key:<hex>"
 *   then N pairs of lines "Ciphertext:<hex>" / "Shared Secret:<hex>"
 * The three header lines are moved to <output_file>_keys by
 * extract_kyber_keys() in xor_bce_data.py.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kem.h"
#include "randombytes.h"

#define N 10 // Number of ciphertext/shared secret pairs to generate

void print_usage(const char *prog_name) {
    printf("Usage: %s [N] [output_file]\n", prog_name);
    printf("Arguments:\n");
    printf("  N                   Number of ciphertext/shared secret pairs (default: %d)\n", N);
    printf("  output_file         Output filename (default: output.txt)\n");
    printf("\nNote: This binary was compiled for %s\n", CRYPTO_ALGNAME);
    printf("\nExamples:\n");
    printf("  %s                  # Generate %d pairs, output to output.txt\n", prog_name, N);
    printf("  %s 20               # Generate 20 pairs, output to output.txt\n", prog_name);
    printf("  %s 5 results.txt    # Generate 5 pairs, output to results.txt\n", prog_name);
}

int main(int argc, char *argv[]) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];   // Public Key
    unsigned char sk[CRYPTO_SECRETKEYBYTES];   // Secret Key
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];  // Ciphertext
    unsigned char ss[CRYPTO_BYTES];            // Shared Secret
    int num_pairs = N;  // Default number of pairs
    const char *output_filename = "output.txt";  // Default output filename

    // Parse command line arguments
    if (argc > 1) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }

        // First argument could be N (number) or filename
        char *endptr;
        long parsed_n = strtol(argv[1], &endptr, 10);

        if (*endptr == '\0' && parsed_n > 0) {
            // First arg is a number
            num_pairs = (int)parsed_n;

            // Second arg (if exists) is output filename
            if (argc > 2) {
                output_filename = argv[2];
            }
        } else {
            // First arg is output filename
            output_filename = argv[1];
        }
    }

    FILE *output_file = fopen(output_filename, "w");
    if (output_file == NULL) {
        perror("Failed to open output file");
        return EXIT_FAILURE;
    }

    // Generate Kyber keypair (always random)
    if (crypto_kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "Keypair generation failed.\n");
        fclose(output_file);
        return EXIT_FAILURE;
    }

    fprintf(output_file, "Kyber Parameter Set: %s \n", CRYPTO_ALGNAME);

    fprintf(output_file, "Kyber Public Key:");
    for (size_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        fprintf(output_file, "%02x", pk[i]);
    }
    fprintf(output_file, "\nKyber Secret Key:");
    for (size_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
        fprintf(output_file, "%02x", sk[i]);
    }

    // Generate num_pairs pairs of ciphertext and shared secrets
    for (int i = 0; i < num_pairs; i++) {
        // Random encapsulation
        if (crypto_kem_enc(ct, ss, pk) != 0) {
            fprintf(stderr, "Encapsulation failed at iteration %d.\n", i + 1);
            fclose(output_file);
            return EXIT_FAILURE;
        }

        fprintf(output_file, "\nCiphertext:");
        for (size_t j = 0; j < CRYPTO_CIPHERTEXTBYTES; j++) {
            fprintf(output_file, "%02x", ct[j]);
        }
        fprintf(output_file, "\n");

        fprintf(output_file, "Shared Secret:");
        for (size_t j = 0; j < CRYPTO_BYTES; j++) {
            fprintf(output_file, "%02x", ss[j]);
        }
    }

    fclose(output_file);
    printf("Successfully generated %d ciphertext/shared secret pairs.\n", num_pairs);
    printf("Output saved to %s\n", output_filename);

    return EXIT_SUCCESS;
}
