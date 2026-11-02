#!/bin/bash
# dataset_gen_single_alg.sh -- generate the single-algorithm datasets
# (Kyber512, HQC, BIKE, RSA-OAEP, unpadded RSA, RC4) and the AES-CTR / AES-CBC
# nonce/IV-reset datasets into <output_folder>.
#
# Run from the repository root, with your Python environment active:
#   ./scripts/dataset_gen_single_alg.sh data/

if [ -z "$1" ]; then
    echo "Usage: $0 <output_folder>"
    exit 1
fi

# Ensure exactly one trailing slash: generate_data.py appends the algorithm
# name directly to this prefix.
OUTPUT_DIR="${1%/}/"
mkdir -p "$OUTPUT_DIR"

echo "Starting data generation..."
echo "============================="

# --- single_alg mode: random vs. all-zero plaintexts ---

echo "[1/6] Generating kyber512 data..."
python datagen/generate_data.py single_alg configs/config.json kyber512 "$OUTPUT_DIR"
echo "✓ Completed kyber512"
echo ""

echo "[2/6] Generating HQC data..."
python datagen/generate_data.py single_alg configs/config.json HQC "$OUTPUT_DIR"
echo "✓ Completed HQC"
echo ""

echo "[3/6] Generating BIKE data..."
python datagen/generate_data.py single_alg configs/config.json BIKE "$OUTPUT_DIR"
echo "✓ Completed BIKE"
echo ""

echo "[4/6] Generating rsa_padded data..."
python datagen/generate_data.py single_alg configs/config.json rsa_padded "$OUTPUT_DIR"
echo "✓ Completed rsa_padded"
echo ""

echo "[5/6] Generating rsa_unpadded data..."
python datagen/generate_data.py single_alg configs/config.json rsa_unpadded "$OUTPUT_DIR"
echo "✓ Completed rsa_unpadded"
echo ""

echo "[6/6] Generating rc4 data..."
python datagen/generate_data.py single_alg configs/config.json rc4 "$OUTPUT_DIR"
echo "✓ Completed rc4"
echo ""

# --- sym mode: AES with a fixed nonce/IV reset every 1000 / 10000 samples ---

echo "[1/4] Generating aes_ctr data (reset=1000)..."
python datagen/generate_data.py sym configs/config.json aes_ctr 1000 "$OUTPUT_DIR"
echo "✓ Completed aes_ctr reset=1000"
echo ""

echo "[2/4] Generating aes_ctr data (reset=10000)..."
python datagen/generate_data.py sym configs/config.json aes_ctr 10000 "$OUTPUT_DIR"
echo "✓ Completed aes_ctr reset=10000"
echo ""

echo "[3/4] Generating aes_cbc data (reset=1000)..."
python datagen/generate_data.py sym configs/config.json aes_cbc 1000 "$OUTPUT_DIR"
echo "✓ Completed aes_cbc reset=1000"
echo ""

echo "[4/4] Generating aes_cbc data (reset=10000)..."
python datagen/generate_data.py sym configs/config.json aes_cbc 10000 "$OUTPUT_DIR"
echo "✓ Completed aes_cbc reset=10000"
echo ""

echo "============================="
echo "All data generation completed!"
