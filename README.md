# DNN-IND-CPA

Neural-network distinguishers for IND-CPA style experiments. For a given
encryption scheme, two classes of ciphertexts are generated (for example
encryptions of random plaintexts vs. encryptions of an all-zero plaintext),
and a neural network is trained to tell them apart. Validation accuracy
significantly above 50% means the network found a distinguisher.

The repository covers:

- **Post-quantum schemes:** Kyber (ML-KEM), BIKE and HQC, through their reference
  implementations.
- **Classical schemes:** RSA (OAEP-padded and textbook), RC4, AES (ECB/CBC/CTR),
  ChaCha20 and DES.
- **KEM + cipher combiners:** a KEM ciphertext concatenated with an encryption of
  either its own shared secret or an independent random value.

## Repository layout

```
.
├── setup.sh              Fetch and build the C programs in pqc/
├── configs/              JSON configs (dataset sizes and training hyperparameters)
├── datagen/              Python dataset generation
│   ├── generate_data.py      Command-line entry point (all modes)
│   ├── data_generation.py    single_alg mode: Kyber, BIKE, HQC, RSA, RC4
│   ├── xor_bce_data.py       combiner mode: KEM + cipher
│   ├── sym_datagen.py        cascade and sym modes: symmetric ciphers
│   ├── rsa_datageneration.py RSA ciphertext file writers
│   └── rsa_unpadded.py       Textbook RSA
├── training/
│   ├── ind_cpa.py            Train the distinguishers
│   ├── evaluate_model.py     Evaluate a saved model on held-out data
│   ├── crypto_import.py      Load hex ciphertext files into NumPy arrays
│   └── model_layers.py       Custom Keras layer used when loading models
├── baselines/
│   ├── chi_square.py         Per-row chi-squared byte-bias test
│   └── chi_baseline_eval.py  Chi-squared test as a baseline classifier
├── scripts/              Batch scripts that generate full sets of datasets
└── pqc/                  C programs that produce the PQC ciphertexts
    ├── kyber_data/           Kyber programs (Makefile; needs pqc/kyber)
    ├── bike_data/            BIKE programs (build.sh; needs bike-kem)
    └── hqc_data/             HQC programs (CMake; needs HQC v5.0.0 sources)
```

All commands below are run from the repository root. The data generators
call the PQC programs with paths relative to it (`./pqc/...`).

## Requirements

- gcc, make, CMake ≥ 3.21 and git, to build the PQC programs.
- Python 3 with `numpy`, `scipy`, `scikit-learn`, `pycryptodome` and
  `tensorflow`. Install `tensorflow[and-cuda]` for GPU training.

## Setup

1. Download the HQC reference implementation, version 5.0.0, from
   <https://pqc-hqc.org/implementation.html>. Unpack it so that
   `pqc/hqc_data/hqc-v5.0.0/src` exists. Without it, `setup.sh` skips HQC and
   the HQC datasets can't be generated.
2. Run

   ```bash
   ./setup.sh
   ```

   This clones [pq-crystals/kyber](https://github.com/pq-crystals/kyber) into
   `pqc/kyber` and [awslabs/bike-kem](https://github.com/awslabs/bike-kem)
   into `pqc/bike_data/bike-kem`. It then builds all PQC programs and creates
   `data/`. Some of the BIKE and HQC programs are compiled with
   `-march=native`, so build on the machine (architecture) where you will
   generate data.

## Generating data

```bash
python datagen/generate_data.py <mode> <config> <mode arguments...>
```

The output prefix is concatenated directly with the algorithm name, so give
directories with a trailing slash (`data/`). Each class is written as
`<prefix>_train`, `<prefix>_validation` and `<prefix>_test`, with one
hex-encoded ciphertext per line. The sizes come from `N_TRAIN`, `N_VALIDATE`
and `N_TEST` in the config.

| Mode | Arguments | Class 0 / class 1 prefixes |
|---|---|---|
| `single_alg` | `<alg> <out>` | `<out><alg>_random` / `<out><alg>_nonrandom` |
| `combiner` | `<kem> <cipher> <out>` | `<out><kem><cipher>_indep` / `<out><kem><cipher>_nonindep` |
| `cascade` | `<inner> <outer> <out>` | `<out><inner><outer>_random` / `..._nonrandom` |
| `sym` | `<alg> <reset> <out>` | `<out><alg><reset>_random` / `..._nonrandom` |
| `RC4` | `<out> <L>` | `<out>RC4_<L>_random` / `..._nonrandom` |
| `RC4_unscaled` | `<out> <L>` | as `RC4` |

- **`single_alg`**: one key, random plaintexts vs. a fixed all-zero
  plaintext. `<alg>` is one of `kyber512`, `kyber768`, `kyber1024`, `BIKE`,
  `HQC`, `rsa_padded`, `rsa_unpadded` or `rc4`. Kyber, BIKE and HQC use the
  underlying IND-CPA public-key encryption.
- **`combiner`**: KEM ciphertext ‖ encryption of the KEM's shared secret
  (`nonindep`) vs. of an independent random secret (`indep`).
  - `<kem>` is one of `kyber512`, `kyber768`, `kyber1024`, `BIKE`, `HQC`,
    `rsa_unpadded`, `rsa1024`, `rsa512`, `AES_ECB` or `RC4_<L>`.
  - `<cipher>` is one of `rsa_padded`, `rsa_unpadded` or `plaintext` (the
    secret is appended unencrypted).
- **`cascade`**: `outer(inner(pt))` on 16-byte plaintexts. The ciphers are
  `aes_ctr`, `aes_ecb`, `aes_cbc`, `chacha20` and `des`.
- **`sym`**: `aes_ctr` or `aes_cbc` with a fixed nonce/IV that is reset every
  `<reset>` encryptions.
- **`RC4`**: RC4 on `L`-byte plaintexts, with a fixed 13-byte key and a fresh
  3-byte IV prefix per sample. The sample counts are scaled by 16/L so every
  L gets the same number of bytes. `RC4_unscaled` uses the config counts as
  they are.

Example:

```bash
python datagen/generate_data.py single_alg configs/config.json kyber512 data/
# -> data/kyber512_random_{train,validation,test}
#    data/kyber512_nonrandom_{train,validation,test}
```

The scripts in `scripts/` run whole batches of these commands. They use
whichever `python` is on your `PATH`, so activate your environment first.

## Training

```bash
python training/ind_cpa.py configs/config.json data/kyber512_random data/kyber512_nonrandom
```

The script trains four fully connected networks one after another on the
`_train` split and validates on the `_validation` split:

- `small_`: 2 × 100 units
- `big_`: 4 × 600 units
- `s_resnet_`: 3 × 100 units with a skip connection
- `l_resnet_`: 5 × 600 units with skip connections

For each network, it writes the best model (`.h5`), a per-epoch CSV log and
the Keras history (`.npy`) to the current directory. A GPU is required by
default; set `USE_GPU=0` to train on the CPU.

## Evaluation and baselines

```bash
# Accuracy and two-sided binomial test of a trained model on the held-out _test split
python training/evaluate_model.py small_<...>.h5 data/kyber512_random_test data/kyber512_nonrandom_test

# Non-learned baseline: chi-squared byte-bias test per ciphertext
python baselines/chi_baseline_eval.py data/rc4_random_validation data/rc4_nonrandom_validation
```

`evaluate_model.py` uses `scipy.stats.binom_test`, which was removed in
SciPy 1.12. Use an older SciPy to run it.

## Configuration

| Key | Used by | Meaning |
|---|---|---|
| `N_TRAIN`, `N_VALIDATE`, `N_TEST` | data generation, training | Samples per class and split (training reads at most `N_TRAIN` / `N_VALIDATE` lines) |
| `USE_BYTES` | training | `true`: one input per byte; `false`: one input per bit |
| `learning_rate`, `momentum` | training | SGD (Nesterov) optimiser settings |
| `batch_size`, `epochs` | training | Batch size and maximum number of epochs |
| `ES_patience`, `ES_delta` | training | Early stopping on validation loss |
| `LR_patience`, `LR_factor`, `LR_delta`, `LR_min` | training | Learning-rate reduction on plateau |
| `K` | none | Not used by the current code |

The configs:

- `configs/config.json`: the default.
- `configs/config_rc4_large.json`: larger sample counts, for use with
  `RC4_unscaled`.
- `configs/minconfig.json`: a tiny smoke-test config.
