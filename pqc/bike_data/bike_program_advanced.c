/*
 * BIKE KEM Test Program (Advanced - Repeat Encryption for Analysis)
 *
 * This program demonstrates the BIKE Key Encapsulation Mechanism by:
 * 1. Generates a BIKE keypair and saves it to output_file_keys (in hex format)
 * 2. Encrypts N messages, outputs to output_file_random (hex format, one ciphertext per line)
 * 3. Encrypts N additional messages, outputs to output_file_nonrandom (hex format, one ciphertext per line)
 *
 * Output Format:
 * - Keys file: Contains public key and secret key in hex on a single line
 * - Ciphertext files: One entry per line in format: CIPHERTEXT_HEX || SHAREDSECRET_HEX
 *   Each line length: (CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES) * 2 characters
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// BIKE public API headers
#include "bike-kem/include/kem.h"
#include "bike-kem/include/api.h"

// Function to append ciphertext and shared secret to file in hex format
// One ciphertext per line: ct_hex + ss_hex
int append_ciphertext_to_file(const char *filename,
                              const unsigned char *ct,
                              const unsigned char *ss)
{
  FILE *f = fopen(filename, "a");
  if (!f) {
    perror("Failed to open file for appending");
    return 1;
  }

  // Write ciphertext in hex
  for (size_t i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) {
    fprintf(f, "%02x", ct[i]);
  }

  // Write shared secret in hex (same line, no separator)
  for (size_t i = 0; i < CRYPTO_BYTES; i++) {
    fprintf(f, "%02x", ss[i]);
  }

  // Newline to separate entries
  fprintf(f, "\n");

  fclose(f);
  return 0;
}

int main(int argc, char *argv[])
{
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <N> <output_file>\n", argv[0]);
    fprintf(stderr, "  N: number of messages to encrypt\n");
    fprintf(stderr, "  output_file: base name for output files\n");
    return 1;
  }

  // Parse arguments
  int N = atoi(argv[1]);
  if (N <= 0) {
    fprintf(stderr, "Error: N must be a positive integer\n");
    return 1;
  }

  const char *output_base = argv[2];

  // Build output filenames
  size_t base_len = strlen(output_base);
  char *output_keys = malloc(base_len + 10);
  char *output_random = malloc(base_len + 20);
  char *output_nonrandom = malloc(base_len + 20);

  if (!output_keys || !output_random || !output_nonrandom) {
    fprintf(stderr, "Error: memory allocation failed\n");
    return 1;
  }

  sprintf(output_keys, "%s_keys", output_base);
  sprintf(output_random, "%s_random", output_base);
  sprintf(output_nonrandom, "%s_nonrandom", output_base);

  printf("BIKE KEM Test Program (Advanced)\n");
  printf("================================\n");
  printf("N = %d\n", N);
  printf("Output files:\n");
  printf("  Keys: %s\n", output_keys);
  printf("  Random: %s\n", output_random);
  printf("  Non-random: %s\n", output_nonrandom);
  printf("\nKey sizes:\n");
  printf("  Public key: %lu bytes\n", (unsigned long)CRYPTO_PUBLICKEYBYTES);
  printf("  Secret key: %lu bytes\n", (unsigned long)CRYPTO_SECRETKEYBYTES);
  printf("  Ciphertext: %lu bytes\n", (unsigned long)CRYPTO_CIPHERTEXTBYTES);
  printf("  Shared secret: %lu bytes\n", (unsigned long)CRYPTO_BYTES);

  // Allocate buffers
  unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
  unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
  unsigned char *ct = malloc(CRYPTO_CIPHERTEXTBYTES);
  unsigned char *ss = malloc(CRYPTO_BYTES);

  if (!pk || !sk || !ct || !ss) {
    fprintf(stderr, "Error: memory allocation failed for buffers\n");
    return 1;
  }

  printf("\n--- Step 1: Generating keypair ---\n");
  int res = crypto_kem_keypair(pk, sk);
  if (res != 0) {
    fprintf(stderr, "Error: keypair generation failed with code %d\n", res);
    return 1;
  }
  printf("Keypair generated successfully\n");

  // Save keypair to file in hex format (pk || sk)
  FILE *keys_file = fopen(output_keys, "w");
  if (!keys_file) {
    perror("Failed to open keys file");
    return 1;
  }

  // Write public key in hex
  for (size_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
    fprintf(keys_file, "%02x", pk[i]);
  }

  // Write secret key in hex (same line)
  for (size_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
    fprintf(keys_file, "%02x", sk[i]);
  }

  // Newline at end
  fprintf(keys_file, "\n");

  fclose(keys_file);
  printf("Keypair saved to %s\n", output_keys);

  // Clear output files (create empty files)
  FILE *f_random = fopen(output_random, "w");
  FILE *f_nonrandom = fopen(output_nonrandom, "w");
  if (!f_random || !f_nonrandom) {
    perror("Failed to create output files");
    return 1;
  }
  fclose(f_random);
  fclose(f_nonrandom);

  printf("\n--- Step 2: Encrypting first batch with random error vectors ---\n");
  for (int i = 0; i < N; i++) {
    // crypto_kem_enc generates random error vectors internally
    res = crypto_kem_enc(ct, ss, pk);
    if (res != 0) {
      fprintf(stderr, "Error: encryption batch 1, message %d failed with code %d\n", i, res);
      return 1;
    }

    // Append to random file
    if (append_ciphertext_to_file(output_random, ct, ss) != 0) {
      fprintf(stderr, "Error: failed to write random ciphertext %d to file\n", i);
      return 1;
    }

    if ((i + 1) % (N / 10 + 1) == 0 || i == 0) {
      printf("  Encrypted %d/%d messages in first batch\n", i + 1, N);
    }
  }
  printf("Completed encrypting %d messages in first batch\n", N);

  printf("\n--- Step 3: Encrypting second batch with random error vectors ---\n");

  for (int i = 0; i < N; i++) {
    // Generate another set of random error vectors
    res = crypto_kem_enc(ct, ss, pk);
    if (res != 0) {
      fprintf(stderr, "Error: encryption batch 2, message %d failed with code %d\n", i, res);
      return 1;
    }

    // Append to nonrandom file (which is also random in this version)
    if (append_ciphertext_to_file(output_nonrandom, ct, ss) != 0) {
      fprintf(stderr, "Error: failed to write second batch ciphertext %d to file\n", i);
      return 1;
    }

    if ((i + 1) % (N / 10 + 1) == 0 || i == 0) {
      printf("  Encrypted %d/%d messages in second batch\n", i + 1, N);
    }
  }
  printf("Completed encrypting %d messages in second batch\n", N);

  // Cleanup
  free(pk);
  free(sk);
  free(ct);
  free(ss);
  free(output_keys);
  free(output_random);
  free(output_nonrandom);

  printf("\n--- Summary ---\n");
  printf("Successfully generated:\n");
  printf("  - %s (public key: %lu bytes, secret key: %lu bytes)\n",
         output_keys, (unsigned long)CRYPTO_PUBLICKEYBYTES, (unsigned long)CRYPTO_SECRETKEYBYTES);
  printf("  - %s (%d ciphertexts with random error vectors, batch 1)\n", output_random, N);
  printf("  - %s (%d ciphertexts with random error vectors, batch 2)\n", output_nonrandom, N);
  printf("\nTotal output size:\n");
  printf("  - Keys: %lu bytes\n", (unsigned long)(CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES));
  printf("  - Random: %lu bytes\n", (unsigned long)(N * (CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES)));
  printf("  - Non-random: %lu bytes\n", (unsigned long)(N * (CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES)));

  return 0;
}
