#!/bin/bash
# dataset_gen.sh -- generate the KEM + cipher combiner datasets
# (generate_data.py "combiner" mode) for Kyber512, BIKE and HQC combined with
# RSA-OAEP, unpadded RSA and the plaintext secret, plus unpadded RSA +
# plaintext. Output goes to completion_data/combiner_data_3/.
#
# Run from the repository root, with your Python environment active:
#   ./scripts/dataset_gen.sh

mkdir -p completion_data/combiner_data_3


echo "Starting data generation..."
echo "============================="

echo "[1/10] Generating kyber rsa_padded..."
python datagen/generate_data.py combiner configs/config.json kyber512 rsa_padded completion_data/combiner_data_3/
echo "✓ Completed kyber rsa_padded"
echo ""


echo "[2/10] Generating kyber rsa_unpadded data..."
python datagen/generate_data.py combiner configs/config.json kyber512 rsa_unpadded  completion_data/combiner_data_3/
echo "✓ Completed kyber rsa_unpadded"
echo ""

echo "[3/10] Generating kyber + plaintext data..."
python datagen/generate_data.py combiner configs/config.json kyber512 plaintext completion_data/combiner_data_3/
echo "✓ Completed kyber + plaintext"
echo ""


echo "[4/10] Generating BIKE rsa_padded..."
python datagen/generate_data.py combiner configs/config.json BIKE rsa_padded completion_data/combiner_data_3/
echo "✓ Completed BIKE rsa_padded"
echo ""


echo "[5/10] Generating BIKE rsa_unpadded data..."
python datagen/generate_data.py combiner configs/config.json  BIKE rsa_unpadded  completion_data/combiner_data_3/
echo "✓ Completed BIKE rsa_unpadded"
echo ""

echo "[6/10] Generating BIKE + plaintext data..."
python datagen/generate_data.py combiner configs/config.json BIKE plaintext completion_data/combiner_data_3/
echo "✓ Completed BIKE + plaintext"
echo ""

echo "[7/10] Generating HQC rsa_padded..."
python datagen/generate_data.py combiner configs/config.json HQC rsa_padded completion_data/combiner_data_3/
echo "✓ Completed HQC rsa_padded"
echo ""


echo "[8/10] Generating HQC rsa_unpadded data..."
python datagen/generate_data.py combiner configs/config.json HQC rsa_unpadded  completion_data/combiner_data_3/
echo "✓ Completed HQC rsa_unpadded"
echo ""

echo "[9/10] Generating HQC + plaintext data..."
python datagen/generate_data.py combiner configs/config.json HQC plaintext completion_data/combiner_data_3/
echo "✓ Completed HQC + plaintext"
echo ""

echo "[10] Generating RSA + plaintext data..."
python datagen/generate_data.py combiner configs/config.json rsa_unpadded plaintext completion_data/combiner_data_3/
echo "✓ Completed RSA + plaintext"
echo ""

echo "============================="
echo "All data generation completed!"
