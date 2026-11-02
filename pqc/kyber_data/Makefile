# Builds the Kyber data-generation programs against the reference
# implementation in ../kyber/ref (i.e. pqc/kyber, cloned by setup.sh).
#   kyber_generate_*     KEM encapsulations  (datagen/xor_bce_data.py)
#   kyber_indcpa_enc*    IND-CPA encryptions (datagen/data_generation.py)
#   kyber_indcpa_enc_k   reduced-randomness experiment (not used by datagen/)

CC = gcc
CFLAGS = -Wall -Wextra -O3
KYBER_DIR = ../kyber/ref
INCLUDES = -I $(KYBER_DIR)

# Kyber source files
KYBER_SOURCES = $(KYBER_DIR)/kem.c \
                $(KYBER_DIR)/indcpa.c \
                $(KYBER_DIR)/polyvec.c \
                $(KYBER_DIR)/poly.c \
                $(KYBER_DIR)/ntt.c \
                $(KYBER_DIR)/cbd.c \
                $(KYBER_DIR)/reduce.c \
                $(KYBER_DIR)/verify.c \
                $(KYBER_DIR)/fips202.c \
                $(KYBER_DIR)/symmetric-shake.c \
                $(KYBER_DIR)/randombytes.c

# Target programs
TARGETS = kyber_generate_512 kyber_generate_768 kyber_generate_1024 kyber_indcpa_enc_512 kyber_indcpa_enc_768 kyber_indcpa_enc_1024 kyber_indcpa_enc kyber_indcpa_enc_k

.PHONY: all clean help

all: $(TARGETS)

kyber_generate_512: kyber_generate.c $(KYBER_SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=2 $(INCLUDES) kyber_generate.c $(KYBER_SOURCES) -o $@

kyber_generate_768: kyber_generate.c $(KYBER_SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=3 $(INCLUDES) kyber_generate.c $(KYBER_SOURCES) -o $@

kyber_generate_1024: kyber_generate.c $(KYBER_SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=4 $(INCLUDES) kyber_generate.c $(KYBER_SOURCES) -o $@

# KYBER_K (and thus ETA1, the noise parameter that actually distinguishes
# Kyber512/768/1024) is fixed at compile time, so each param_set needs its
# own binary; kyber_indcpa_enc below is a thin dispatcher over these three
# that preserves the original single-binary "<param_set> ..." CLI.
kyber_indcpa_enc_512: kyber_indcpa_enc.c $(KYBER_SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=2 $(INCLUDES) kyber_indcpa_enc.c $(KYBER_SOURCES) -o $@

kyber_indcpa_enc_768: kyber_indcpa_enc.c $(KYBER_SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=3 $(INCLUDES) kyber_indcpa_enc.c $(KYBER_SOURCES) -o $@

kyber_indcpa_enc_1024: kyber_indcpa_enc.c $(KYBER_SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=4 $(INCLUDES) kyber_indcpa_enc.c $(KYBER_SOURCES) -o $@

kyber_indcpa_enc: kyber_indcpa_enc_dispatch.c kyber_indcpa_enc_512 kyber_indcpa_enc_768 kyber_indcpa_enc_1024
	$(CC) $(CFLAGS) kyber_indcpa_enc_dispatch.c -o $@

kyber_indcpa_enc_k: kyber_indcpa_enc_k.c $(KYBER_SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=3 $(INCLUDES) kyber_indcpa_enc_k.c $(KYBER_SOURCES) -o $@

clean:
	rm -f $(TARGETS)

help:
	@echo "Kyber Generate Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all                    - Build all programs (default)"
	@echo "  kyber_generate_512     - Build Kyber512 variant"
	@echo "  kyber_generate_768     - Build Kyber768 variant"
	@echo "  kyber_generate_1024    - Build Kyber1024 variant"
	@echo "  kyber_indcpa_enc_512   - Build IndCPA encryption, Kyber512 params (K=2)"
	@echo "  kyber_indcpa_enc_768   - Build IndCPA encryption, Kyber768 params (K=3)"
	@echo "  kyber_indcpa_enc_1024  - Build IndCPA encryption, Kyber1024 params (K=4)"
	@echo "  kyber_indcpa_enc       - Build dispatcher over the three binaries above"
	@echo "  kyber_indcpa_enc_k     - Build IndCPA encryption with K-bit randomness"
	@echo "  clean                  - Remove all built programs"
	@echo "  help                   - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make                                    - Build all programs"
	@echo "  make kyber_generate_768                 - Build only Kyber768"
	@echo "  ./kyber_generate_512 output.txt         - Run Kyber512 with custom output file"
	@echo "  ./kyber_generate_768 --zero-seed data.txt - Run Kyber768 with zero seed"
