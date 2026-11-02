#!/bin/bash
# sym_dataset_gen.sh -- generate the symmetric cascade datasets
# (generate_data.py "cascade" mode, outer(inner(pt))) for pairs of AES-CTR,
# AES-ECB, AES-CBC, ChaCha20 and DES into data/.
#
# Run from the repository root, with your Python environment active:
#   ./scripts/sym_dataset_gen.sh

mkdir -p data

echo "Starting data generation..."
echo "============================="


# Arguments: <inner cipher> <outer cipher> <output prefix>
python datagen/generate_data.py cascade configs/config.json aes_ctr aes_ecb data/
python datagen/generate_data.py cascade configs/config.json aes_ctr aes_cbc data/
python datagen/generate_data.py cascade configs/config.json aes_ctr des data/

python datagen/generate_data.py cascade configs/config.json aes_ecb aes_ctr data/
python datagen/generate_data.py cascade configs/config.json aes_ecb aes_cbc data/
python datagen/generate_data.py cascade configs/config.json aes_ecb chacha20 data/

python datagen/generate_data.py cascade configs/config.json aes_cbc aes_ctr data/
python datagen/generate_data.py cascade configs/config.json aes_cbc aes_ecb data/
python datagen/generate_data.py cascade configs/config.json aes_cbc chacha20 data/
python datagen/generate_data.py cascade configs/config.json aes_cbc des data/

python datagen/generate_data.py cascade configs/config.json chacha20 aes_ctr data/
python datagen/generate_data.py cascade configs/config.json chacha20 aes_ecb data/
python datagen/generate_data.py cascade configs/config.json chacha20 aes_cbc data/
python datagen/generate_data.py cascade configs/config.json chacha20 des data/

python datagen/generate_data.py cascade configs/config.json des aes_ctr data/
python datagen/generate_data.py cascade configs/config.json des aes_cbc data/
python datagen/generate_data.py cascade configs/config.json des chacha20 data/

echo "============================="
echo "All data generation completed!"
