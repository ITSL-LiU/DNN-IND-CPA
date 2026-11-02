/*
 * BIKE PKE Test Program (Similar to Kyber and HQC)
 *
 * This program demonstrates the BIKE Public Key Encryption by:
 * 1. Generates a BIKE keypair and saves it to output_file_keys (in hex format)
 * 2. Encrypts N zero messages, outputs to output_file_nonrandom (hex format, one ciphertext per line)
 * 3. Encrypts N random messages, outputs to output_file_random (hex format, one ciphertext per line)
 *
 * Output Format:
 * - Keys file: Contains public key and secret key in hex (two lines)
 * - Ciphertext files: One entry per line in format: hex(c0)||hex(c1)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// BIKE public API headers
#include "bike-kem/include/kem.h"
#include "bike-kem/include/api.h"

// Internal BIKE headers (needed for PKE-level operations)
#include "bike-kem/include/internal/types.h"
#include "bike-kem/include/internal/sampling.h"
#include "bike-kem/include/internal/sha.h"
#include "bike-kem/include/internal/utilities.h"
#include "bike-kem/include/internal/gf2x.h"

// Helper function prototypes (copied from kem.c)
static ret_t function_h(OUT pad_e_t *e, IN const m_t *m, IN const pk_t *pk);
static ret_t function_l(OUT m_t *out, IN const pad_e_t *e);
static ret_t encrypt(OUT ct_t *ct, IN const pad_e_t *e, IN const pk_t *pk, IN const m_t *m);

// Implementation of helper functions from kem.c
_INLINE_ void convert_m_to_seed_type(OUT seed_t *seed, IN const m_t *m)
{
  bike_static_assert(sizeof(*m) == sizeof(*seed), m_size_eq_seed_size);
  bike_memcpy(seed->raw, m->raw, sizeof(*seed));
}

// (e0, e1) = H(m)
_INLINE_ ret_t function_h(OUT pad_e_t *e, IN const m_t *m, IN const pk_t *pk)
{
  DEFER_CLEANUP(seed_t seed = {0}, seed_cleanup);

#if defined(BIND_PK_AND_M)
  DEFER_CLEANUP(sha_dgst_t  dgst = {0}, sha_dgst_cleanup);
  DEFER_CLEANUP(pk_m_bind_t pk_m = {0}, pk_m_bind_cleanup);

  // Copy the public key and the message to a temporary buffer
  pk_m.pk = *pk;
  pk_m.m  = *m;

  // Hash the binded pk and m
  GUARD(sha(&dgst, sizeof(pk_m), (uint8_t *)&pk_m));

  // Convert digest to seed - we need to implement this
  bike_memcpy(seed.raw, dgst.u.raw, sizeof(seed));
#else
  // pk is unused parameter in this case
  (void)pk;

  convert_m_to_seed_type(&seed, m);
#endif
  return generate_error_vector(e, &seed);
}

// out = L(e)
_INLINE_ ret_t function_l(OUT m_t *out, IN const pad_e_t *e)
{
  DEFER_CLEANUP(sha_dgst_t dgst = {0}, sha_dgst_cleanup);
  DEFER_CLEANUP(e_t tmp, e_cleanup);

  // Take the padding away
  tmp.val[0] = e->val[0].val;
  tmp.val[1] = e->val[1].val;

  GUARD(sha(&dgst, sizeof(tmp), (uint8_t *)&tmp));

  // Truncate the SHA384 digest to a 256-bits m_t
  bike_static_assert(sizeof(dgst) >= sizeof(*out), dgst_size_lt_m_size);
  bike_memcpy(out->raw, dgst.u.raw, sizeof(*out));

  return SUCCESS;
}

_INLINE_ ret_t encrypt(OUT ct_t *ct,
                       IN const pad_e_t *e,
                       IN const pk_t *pk,
                       IN const m_t *m)
{
  // Pad the public key and the ciphertext
  pad_r_t p_ct = {0};
  pad_r_t p_pk = {0};
  p_pk.val     = *pk;

  // Generate the ciphertext
  // ct = pk * e1 + e0
  gf2x_mod_mul(&p_ct, &e->val[1], &p_pk);
  gf2x_mod_add(&p_ct, &p_ct, &e->val[0]);

  ct->c0 = p_ct.val;

  // c1 = L(e0, e1)
  GUARD(function_l(&ct->c1, e));

  // m xor L(e0, e1)
  for(size_t i = 0; i < sizeof(*m); i++) {
    ct->c1.raw[i] ^= m->raw[i];
  }

  return SUCCESS;
}

// Function to save ciphertext to file in hex format (one per line)
int append_ciphertext_to_file(const char *filename, const ct_t *ct)
{
  FILE *f = fopen(filename, "a");
  if (!f) {
    perror("Failed to open file for appending");
    return 1;
  }

  // Write c0 in hex
  for (size_t i = 0; i < R_BYTES; i++) {
    fprintf(f, "%02x", ct->c0.raw[i]);
  }

  // Write c1 in hex (same line, no separator)
  for (size_t i = 0; i < M_BYTES; i++) {
    fprintf(f, "%02x", ct->c1.raw[i]);
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

  printf("BIKE PKE Test Program\n");
  printf("====================\n");
  printf("N = %d\n", N);
  printf("Output files:\n");
  printf("  Keys: %s\n", output_keys);
  printf("  Random: %s\n", output_random);
  printf("  Non-random: %s\n", output_nonrandom);
  printf("\nKey sizes:\n");
  printf("  Public key: %lu bytes\n", (unsigned long)CRYPTO_PUBLICKEYBYTES);
  printf("  Secret key: %lu bytes\n", (unsigned long)CRYPTO_SECRETKEYBYTES);
  printf("  Ciphertext: %lu bytes\n", (unsigned long)(R_BYTES + M_BYTES));
  printf("  Message: %lu bytes\n", (unsigned long)M_BYTES);

  // Allocate buffers
  unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
  unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);

  if (!pk || !sk) {
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

  // Save keypair to file in hex format
  FILE *keys_file = fopen(output_keys, "w");
  if (!keys_file) {
    perror("Failed to open keys file");
    return 1;
  }

  // Write public key in hex
  for (size_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
    fprintf(keys_file, "%02x", pk[i]);
  }
  fprintf(keys_file, "\n");

  // Write secret key in hex
  for (size_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
    fprintf(keys_file, "%02x", sk[i]);
  }
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

  // Convert pk to internal type
  pk_t l_pk;
  bike_memcpy(&l_pk, pk, sizeof(l_pk));

  printf("\n--- Step 2: Encrypting zero messages ---\n");
  for (int i = 0; i < N; i++) {
    // Create zero message
    m_t m_zero;
    memset(&m_zero, 0, sizeof(m_zero));

    // Generate error vector from message
    DEFER_CLEANUP(pad_e_t e, pad_e_cleanup);
    DEFER_CLEANUP(seed_t rand_seed = {0}, seed_cleanup);

    // Get random seed for error vector
    get_seeds((seeds_t *)&rand_seed);
    if (generate_error_vector(&e, &rand_seed) != SUCCESS) {
      fprintf(stderr, "Error: failed to generate error vector for nonrandom message %d\n", i);
      return 1;
    }

    // Encrypt
    ct_t ct;
    if (encrypt(&ct, &e, &l_pk, &m_zero) != SUCCESS) {
      fprintf(stderr, "Error: encryption of zero message %d failed\n", i);
      return 1;
    }

    // Append to nonrandom file
    if (append_ciphertext_to_file(output_nonrandom, &ct) != 0) {
      fprintf(stderr, "Error: failed to write nonrandom ciphertext %d to file\n", i);
      return 1;
    }

    if ((i + 1) % (N / 10 + 1) == 0 || i == 0) {
      printf("  Encrypted %d/%d zero messages\n", i + 1, N);
    }
  }
  printf("Completed encrypting %d zero messages\n", N);

  printf("\n--- Step 3: Encrypting random messages ---\n");
  for (int i = 0; i < N; i++) {
    // Create random message
    m_t m_rand;
    DEFER_CLEANUP(seeds_t seeds = {0}, seeds_cleanup);
    get_seeds(&seeds);
    bike_memcpy(&m_rand, &seeds.seed[0], sizeof(m_rand));

    // Generate error vector
    DEFER_CLEANUP(pad_e_t e, pad_e_cleanup);
    DEFER_CLEANUP(seed_t rand_seed = {0}, seed_cleanup);

    get_seeds((seeds_t *)&rand_seed);
    if (generate_error_vector(&e, &rand_seed) != SUCCESS) {
      fprintf(stderr, "Error: failed to generate error vector for random message %d\n", i);
      return 1;
    }

    // Encrypt
    ct_t ct;
    if (encrypt(&ct, &e, &l_pk, &m_rand) != SUCCESS) {
      fprintf(stderr, "Error: encryption of random message %d failed\n", i);
      return 1;
    }

    // Append to random file
    if (append_ciphertext_to_file(output_random, &ct) != 0) {
      fprintf(stderr, "Error: failed to write random ciphertext %d to file\n", i);
      return 1;
    }

    if ((i + 1) % (N / 10 + 1) == 0 || i == 0) {
      printf("  Encrypted %d/%d random messages\n", i + 1, N);
    }
  }
  printf("Completed encrypting %d random messages\n", N);

  // Cleanup
  free(pk);
  free(sk);
  free(output_keys);
  free(output_random);
  free(output_nonrandom);

  printf("\n--- Summary ---\n");
  printf("Successfully generated:\n");
  printf("  - %s_keys (public key and secret key)\n", output_base);
  printf("  - %s_nonrandom (%d zero-message ciphertexts)\n", output_base, N);
  printf("  - %s_random (%d random-message ciphertexts)\n", output_base, N);

  return 0;
}
