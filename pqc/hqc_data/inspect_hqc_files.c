/*
 * Debug utility: print sizes, a hex dump and byte statistics of a binary
 * HQC key or ciphertext file, detecting the HQC variant (1/3/5) from the
 * file size. Not used by the data generation pipeline, which works with hex
 * text files.
 *
 * Usage: inspect_hqc_files <file> [-v]
 */
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

// HQC-5 sizes
#define HQC5_EK_SIZE     7237
#define HQC5_DK_SIZE     7333
#define HQC5_CTXT_SIZE   14405  // u=7205 + v=7200

// HQC-3 sizes
#define HQC3_EK_SIZE     4514
#define HQC3_DK_SIZE     4602
#define HQC3_CTXT_SIZE   8978

// HQC-1 sizes
#define HQC1_EK_SIZE     2241
#define HQC1_DK_SIZE     2321
#define HQC1_CTXT_SIZE   4433

typedef enum {
    HQC_UNKNOWN,
    HQC_1,
    HQC_3,
    HQC_5,
} hqc_variant_t;

typedef struct {
    hqc_variant_t variant;
    size_t ek_size;
    size_t dk_size;
    size_t ctxt_size;
} hqc_sizes_t;

// Forward declarations
static int inspect_keypair(FILE *fp, const char *filename);
static int inspect_ciphertexts(FILE *fp, const char *filename);
static void print_usage(const char *prog);
static hqc_sizes_t get_hqc_sizes(hqc_variant_t variant);
static hqc_variant_t detect_variant(size_t file_size, const char *filename);
static void print_hex(const uint8_t *data, size_t len, int bytes_per_line);
static void print_stats(const uint8_t *data, size_t len);

static hqc_sizes_t get_hqc_sizes(hqc_variant_t variant) {
    hqc_sizes_t sizes = {.variant = variant};

    switch (variant) {
        case HQC_1:
            sizes.ek_size = HQC1_EK_SIZE;
            sizes.dk_size = HQC1_DK_SIZE;
            sizes.ctxt_size = HQC1_CTXT_SIZE;
            break;
        case HQC_3:
            sizes.ek_size = HQC3_EK_SIZE;
            sizes.dk_size = HQC3_DK_SIZE;
            sizes.ctxt_size = HQC3_CTXT_SIZE;
            break;
        case HQC_5:
            sizes.ek_size = HQC5_EK_SIZE;
            sizes.dk_size = HQC5_DK_SIZE;
            sizes.ctxt_size = HQC5_CTXT_SIZE;
            break;
        default:
            break;
    }

    return sizes;
}

static hqc_variant_t detect_variant(size_t file_size, const char *filename) {
    // Try to detect by file size - check larger variants first
    if (strstr(filename, "_keys")) {
        // Keypair file
        if (file_size == HQC5_EK_SIZE + HQC5_DK_SIZE) return HQC_5;
        if (file_size == HQC3_EK_SIZE + HQC3_DK_SIZE) return HQC_3;
        if (file_size == HQC1_EK_SIZE + HQC1_DK_SIZE) return HQC_1;
    } else {
        // Ciphertext file - try to divide evenly (check larger first)
        if (file_size % HQC5_CTXT_SIZE == 0) return HQC_5;
        if (file_size % HQC3_CTXT_SIZE == 0) return HQC_3;
        if (file_size % HQC1_CTXT_SIZE == 0) return HQC_1;
    }

    return HQC_UNKNOWN;
}

static void print_hex(const uint8_t *data, size_t len, int bytes_per_line) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % bytes_per_line == 0 && i + 1 < len) {
            printf("\n");
        } else if (i + 1 < len) {
            printf(" ");
        }
    }
    printf("\n");
}

static void print_stats(const uint8_t *data, size_t len) {
    size_t ones = 0;
    size_t zeros = 0;

    for (size_t i = 0; i < len; i++) {
        for (int bit = 0; bit < 8; bit++) {
            if (data[i] & (1 << bit)) {
                ones++;
            } else {
                zeros++;
            }
        }
    }

    double ones_pct = 100.0 * ones / (ones + zeros);

    printf("  Bytes:       %zu\n", len);
    printf("  Bits:        %zu (%zu ones, %zu zeros)\n", ones + zeros, ones, zeros);
    printf("  Entropy:     %.2f%% ones\n", ones_pct);
}

static int inspect_keypair(FILE *fp, const char *filename) {
    hqc_sizes_t sizes;
    struct stat st;

    if (fstat(fileno(fp), &st) != 0) {
        perror("fstat");
        return -1;
    }

    hqc_variant_t variant = detect_variant(st.st_size, filename);
    if (variant == HQC_UNKNOWN) {
        fprintf(stderr, "Error: Could not detect HQC variant from file size %zu\n", st.st_size);
        return -1;
    }

    sizes = get_hqc_sizes(variant);

    printf("Keypair File: %s\n", filename);
    printf("================\n");
    int variant_num = (variant == HQC_1) ? 1 : (variant == HQC_3) ? 3 : 5;
    printf("Detected Variant: HQC-%d\n", variant_num);
    printf("File Size: %zu bytes\n", (size_t)st.st_size);
    printf("Expected:  %zu bytes\n\n", sizes.ek_size + sizes.dk_size);

    if ((size_t)st.st_size != sizes.ek_size + sizes.dk_size) {
        fprintf(stderr, "Warning: File size mismatch!\n");
        return -1;
    }

    // Read encryption key
    uint8_t *ek = malloc(sizes.ek_size);
    if (!ek || fread(ek, 1, sizes.ek_size, fp) != sizes.ek_size) {
        perror("fread (ek)");
        free(ek);
        return -1;
    }

    // Read decryption key
    uint8_t *dk = malloc(sizes.dk_size);
    if (!dk || fread(dk, 1, sizes.dk_size, fp) != sizes.dk_size) {
        perror("fread (dk)");
        free(ek);
        free(dk);
        return -1;
    }

    printf("Encryption Key Statistics:\n");
    print_stats(ek, sizes.ek_size);
    printf("\n");

    printf("Decryption Key Statistics:\n");
    print_stats(dk, sizes.dk_size);
    printf("\n");

    printf("First 64 bytes of Encryption Key (hex):\n");
    print_hex(ek, 64, 16);
    printf("\n");

    printf("First 64 bytes of Decryption Key (hex):\n");
    print_hex(dk, 64, 16);
    printf("\n");

    free(ek);
    free(dk);
    return 0;
}

static int inspect_ciphertexts(FILE *fp, const char *filename) {
    hqc_sizes_t sizes;
    struct stat st;

    if (fstat(fileno(fp), &st) != 0) {
        perror("fstat");
        return -1;
    }

    hqc_variant_t variant = detect_variant(st.st_size, filename);
    if (variant == HQC_UNKNOWN) {
        fprintf(stderr, "Error: Could not detect HQC variant from file size %zu\n", st.st_size);
        return -1;
    }

    sizes = get_hqc_sizes(variant);

    size_t num_ctxts = st.st_size / sizes.ctxt_size;

    printf("Ciphertext File: %s\n", filename);
    printf("====================\n");
    int variant_num = (variant == HQC_1) ? 1 : (variant == HQC_3) ? 3 : 5;
    printf("Detected Variant:  HQC-%d\n", variant_num);
    printf("File Size:         %zu bytes\n", (size_t)st.st_size);
    printf("Ciphertext Size:   %zu bytes (u=%zu + v=%zu)\n",
           sizes.ctxt_size, sizes.ctxt_size / 2 + 5, sizes.ctxt_size / 2);
    printf("Number of Ctxts:   %zu\n\n", num_ctxts);

    // Show first 3 ciphertexts
    size_t show_count = (num_ctxts > 3) ? 3 : num_ctxts;

    for (size_t i = 0; i < show_count; i++) {
        uint8_t *ctxt = malloc(sizes.ctxt_size);
        if (!ctxt || fread(ctxt, 1, sizes.ctxt_size, fp) != sizes.ctxt_size) {
            perror("fread (ctxt)");
            free(ctxt);
            return -1;
        }

        printf("Ciphertext %zu Statistics:\n", i + 1);
        print_stats(ctxt, sizes.ctxt_size);
        printf("\n");

        printf("Ciphertext %zu - First 32 bytes (hex):\n", i + 1);
        print_hex(ctxt, 32, 16);
        printf("\n");

        free(ctxt);
    }

    if (num_ctxts > show_count) {
        printf("... and %zu more ciphertexts\n", num_ctxts - show_count);
    }

    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <file> [options]\n", prog);
    fprintf(stderr, "\nInspect HQC binary files (keys or ciphertexts)\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -h, --help     Show this help message\n");
    fprintf(stderr, "  -v, --verbose  Show more detailed information\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *filename = argv[1];
    FILE *fp = fopen(filename, "rb");

    if (!fp) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    int result;
    if (strstr(filename, "_keys")) {
        result = inspect_keypair(fp, filename);
    } else {
        result = inspect_ciphertexts(fp, filename);
    }

    fclose(fp);
    return (result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
