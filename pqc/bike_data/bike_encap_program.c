/*
 * BIKE KEM Encapsulation Program
 *
 * This program:
 * 1. Generates a BIKE keypair and saves it to output_file_keys
 * 2. Performs N encapsulations using the public key
 * 3. Saves ciphertext and shared secrets to output_file
 *
 * Output Format:
 * - Keys file (output_file_keys): public key || secret key in hex
 * - Output file: alternating rows of "Ciphertext: <hex>" and "Shared secret: <hex>"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bike-kem/include/kem.h"
#include "bike-kem/include/api.h"

// Function to save keys to file in hex format
int save_keys_to_file(const char *filename,
                      const unsigned char *pk,
                      const unsigned char *sk)
{
  FILE *f = fopen(filename, "w");
  if (!f) {
    perror("Failed to open keys file for writing");
    return 1;
  }

  // Write public key in hex
  for (size_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
    fprintf(f, "%02x", pk[i]);
  }

  // Write secret key in hex (same line)
  for (size_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
    fprintf(f, "%02x", sk[i]);
  }

  fprintf(f, "\n");
  fclose(f);
  return 0;
}

// Write bytes as lowercase hex into buf (no null terminator).
// buf must have space for 2*len bytes.
static void bytes_to_hex(const unsigned char *bytes, size_t len, char *buf)
{
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    buf[2*i]   = hex[bytes[i] >> 4];
    buf[2*i+1] = hex[bytes[i] & 0xf];
  }
}

// Write one encapsulation to an already-open file.
// ct_hex_buf/ss_hex_buf are scratch buffers (caller-allocated, reused each call).
int write_encapsulation_to_file(FILE *f,
                                 const unsigned char *ct,
                                 const unsigned char *ss,
                                 char *ct_hex_buf,
                                 char *ss_hex_buf)
{
  bytes_to_hex(ct, CRYPTO_CIPHERTEXTBYTES, ct_hex_buf);
  bytes_to_hex(ss, CRYPTO_BYTES,           ss_hex_buf);
  ct_hex_buf[2*CRYPTO_CIPHERTEXTBYTES] = '\n';
  ss_hex_buf[2*CRYPTO_BYTES]           = '\n';

  if (fputs("Ciphertext: ", f) == EOF) return 1;
  if (fwrite(ct_hex_buf, 1, 2*CRYPTO_CIPHERTEXTBYTES + 1, f)
      != (size_t)(2*CRYPTO_CIPHERTEXTBYTES + 1)) return 1;
  if (fputs("Shared Secret: ", f) == EOF) return 1;
  if (fwrite(ss_hex_buf, 1, 2*CRYPTO_BYTES + 1, f)
      != (size_t)(2*CRYPTO_BYTES + 1)) return 1;
  return 0;
}

int main(int argc, char *argv[])
{
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <N> <output_file>\n", argv[0]);
    fprintf(stderr, "  N: number of encapsulations to perform\n");
    fprintf(stderr, "  output_file: base name for output files\n");
    fprintf(stderr, "    - Keys will be saved to output_file_keys\n");
    fprintf(stderr, "    - Encapsulations will be saved to output_file\n");
    return 1;
  }

  // Parse arguments
  int N = atoi(argv[1]);
  if (N <= 0) {
    fprintf(stderr, "Error: N must be a positive integer\n");
    return 1;
  }

  const char *output_file = argv[2];

  // Build output filenames
  size_t base_len = strlen(output_file);
  char *output_keys = malloc(base_len + 10);

  if (!output_keys) {
    fprintf(stderr, "Error: memory allocation failed\n");
    return 1;
  }

  sprintf(output_keys, "%s_keys", output_file);

  printf("BIKE KEM Encapsulation Program\n");
  printf("==============================\n");
  printf("N = %d\n", N);
  printf("Output files:\n");
  printf("  Keys: %s\n", output_keys);
  printf("  Encapsulations: %s\n", output_file);
  printf("\nKey sizes:\n");
  printf("  Public key: %lu bytes\n", (unsigned long)CRYPTO_PUBLICKEYBYTES);
  printf("  Secret key: %lu bytes\n", (unsigned long)CRYPTO_SECRETKEYBYTES);
  printf("  Ciphertext: %lu bytes\n", (unsigned long)CRYPTO_CIPHERTEXTBYTES);
  printf("  Shared secret: %lu bytes\n", (unsigned long)CRYPTO_BYTES);

  // Allocate buffers
  unsigned char *pk     = malloc(CRYPTO_PUBLICKEYBYTES);
  unsigned char *sk     = malloc(CRYPTO_SECRETKEYBYTES);
  unsigned char *ct     = malloc(CRYPTO_CIPHERTEXTBYTES);
  unsigned char *ss     = malloc(CRYPTO_BYTES);
  char          *ct_hex = malloc(2*CRYPTO_CIPHERTEXTBYTES + 2);
  char          *ss_hex = malloc(2*CRYPTO_BYTES + 2);

  if (!pk || !sk || !ct || !ss || !ct_hex || !ss_hex) {
    fprintf(stderr, "Error: memory allocation failed for key/ciphertext buffers\n");
    return 1;
  }

  printf("\n--- Step 1: Generating keypair ---\n");
  int res = crypto_kem_keypair(pk, sk);
  if (res != 0) {
    fprintf(stderr, "Error: keypair generation failed with code %d\n", res);
    free(pk);
    free(sk);
    free(ct);
    free(ss);
    free(output_keys);
    return 1;
  }
  printf("Keypair generated successfully\n");

  // Save keypair to file
  if (save_keys_to_file(output_keys, pk, sk) != 0) {
    fprintf(stderr, "Error: failed to save keys to file\n");
    free(pk);
    free(sk);
    free(ct);
    free(ss);
    free(output_keys);
    return 1;
  }
  printf("Keypair saved to %s\n", output_keys);

  // Open output file once for the whole run
  FILE *f_output = fopen(output_file, "w");
  if (!f_output) {
    perror("Failed to create output file");
    free(pk); free(sk); free(ct); free(ss);
    free(ct_hex); free(ss_hex); free(output_keys);
    return 1;
  }

  int report_interval = N / 10 > 0 ? N / 10 : 1;
  printf("\n--- Step 2: Performing encapsulations ---\n");
  for (int i = 0; i < N; i++) {
    res = crypto_kem_enc(ct, ss, pk);
    if (res != 0) {
      fprintf(stderr, "Error: encapsulation %d failed with code %d\n", i + 1, res);
      fclose(f_output);
      free(pk); free(sk); free(ct); free(ss);
      free(ct_hex); free(ss_hex); free(output_keys);
      return 1;
    }

    if (write_encapsulation_to_file(f_output, ct, ss, ct_hex, ss_hex) != 0) {
      fprintf(stderr, "Error: failed to write encapsulation %d to file\n", i + 1);
      fclose(f_output);
      free(pk); free(sk); free(ct); free(ss);
      free(ct_hex); free(ss_hex); free(output_keys);
      return 1;
    }

    if ((i + 1) % report_interval == 0 || i + 1 == N) {
      printf("  Completed %d/%d encapsulations\n", i + 1, N);
    }
  }
  fclose(f_output);
  printf("Completed all %d encapsulations\n", N);

  // Cleanup
  free(pk); free(sk); free(ct); free(ss);
  free(ct_hex); free(ss_hex); free(output_keys);

  printf("\n--- Summary ---\n");
  printf("Successfully generated:\n");
  printf("  - %s (keypair in hex format)\n", output_keys);
  printf("  - %s (%d encapsulations with labeled ciphertext and shared secret pairs)\n",
         output_file, N);

  return 0;
}
