"""
generate_data.py -- command-line entry point for all dataset generation.

Every mode writes, for each of the two classes, three files with the suffixes
_train, _validation and _test. These are hex-encoded ciphertexts, one per
line, and ind_cpa.py consumes them. The number of samples per split comes
from the config file (N_TRAIN, N_VALIDATE, N_TEST).

Run from the repository root (the PQC binaries are called with paths relative
to it):

    python datagen/generate_data.py <mode> <config> <mode-specific args...>

Modes:
    single_alg <alg> <out_prefix>
        One public-key or stream cipher, encrypting random plaintexts vs.
        all-zero plaintexts.  Classes: <out_prefix><alg>_random / _nonrandom

    combiner <kem> <cipher> <out_prefix>
        KEM ciphertext concatenated with an encryption (<cipher>) of either
        the KEM's own shared secret or an independent random secret.
        Classes: <out_prefix><kem><cipher>_nonindep / _indep

    cascade <inner> <outer> <out_prefix>
        Two symmetric ciphers applied in sequence, random vs. all-zero
        plaintexts.  Classes: <out_prefix><inner><outer>_random / _nonrandom

    sym <alg> <reset> <out_prefix>
        AES-CTR / AES-CBC with a fixed nonce / IV that is reset every <reset>
        encryptions.  Classes: <out_prefix><alg><reset>_random / _nonrandom

    RC4 <out_prefix> <L>
        RC4 on L-byte plaintexts, sample counts scaled by 16/L.
        Classes: <out_prefix>RC4_<L>_random / _nonrandom

    RC4_unscaled <out_prefix> <L>
        As RC4 but with the config's sample counts used verbatim.

Note that <out_prefix> is concatenated directly with the algorithm name, so
a directory prefix needs a trailing slash (e.g. "data/").
"""
import sys
import json
from data_generation import generate_data, RC4_generate
from xor_bce_data import generate_kem_and_cipher
from sym_datagen import data_casc_gen, data_sing_gen

# Select the algorithms

mode = sys.argv[1]
config = sys.argv[2]

with open(config, 'r') as f:
    config = json.load(f)

N_TRAIN = config["N_TRAIN"]
N_VALIDATE = config["N_VALIDATE"]
N_TEST = config["N_TEST"]

if mode == "single_alg":
    alg = sys.argv[3]
    path = sys.argv[4]
    impl_algs = ["kyber512", "kyber768", "kyber1024", "HQC", "BIKE", "rsa_padded", "rsa_unpadded", "rc4"]
    if alg not in impl_algs:
        print(f"Error: unknown algorithm '{alg}'. Choose from: {impl_algs}")
        sys.exit(1)

    u_path = path + alg
    generate_data(alg, N_TRAIN,  N_VALIDATE, N_TEST, u_path)

elif mode == "combiner":
    kem = sys.argv[3]
    cipher = sys.argv[4]
    path = sys.argv[5]
    impl_kems = ["kyber512", "kyber768", "kyber1024", "HQC", "BIKE", "rsa_unpadded", "rsa1024", "rsa512", "AES_ECB" ]
    impl_cipher = ["rsa_padded", "rsa_unpadded", "plaintext"]
    # "RC4_<L>" (RC4 as the KEM with an L-byte secret) is also accepted.
    is_rc4 = kem.startswith("RC4_") and kem[4:].isdigit() and int(kem[4:]) > 0
    if kem not in impl_kems and not is_rc4:
        print(f"Error: unknown KEM '{kem}'. Choose from: {impl_kems} or RC4_<L>")
        sys.exit(1)
    if cipher not in impl_cipher:
        print(f"Error: unknown cipher '{cipher}'. Choose from: {impl_cipher}")
        sys.exit(1)

    u_path = path + kem + cipher
    # Note the argument order here is (train, test, validate).
    generate_kem_and_cipher(kem, cipher, N_TRAIN, N_TEST,  N_VALIDATE,  u_path)


elif mode == "cascade":

    alg1 = sys.argv[3]
    alg2 = sys.argv[4]
    path = sys.argv[5]
    ciphers = ["aes_ctr", "aes_ecb", "aes_cbc", "chacha20", "des"]

    if alg1 not in ciphers:
        print(f"Error: unknown KEM '{alg1}'. Choose from: {ciphers}")
        sys.exit(1)
    if alg2 not in ciphers:
        print(f"Error: unknown KEM '{alg2}'. Choose from: {ciphers}")
        sys.exit(1)
    u_path = path + alg1 + alg2

    data_casc_gen(alg1, alg2, N_TRAIN, N_VALIDATE, N_TEST, u_path)

elif mode == "sym":

    alg = sys.argv[3]
    reset = sys.argv[4]
    path = sys.argv[5]
    ciphers = ["aes_ctr", "aes_cbc"]
    if alg not in ciphers:
        print(f"Error: unknown KEM '{alg}'. Choose from: {ciphers}")
        sys.exit(1)
    u_path = path + alg + reset

    reset = int(reset)
    data_sing_gen(alg, reset, N_TRAIN, N_VALIDATE, N_TEST, u_path)

elif mode == "RC4":
    path = sys.argv[3]
    l = sys.argv[4]

    # config.json's sample counts are calibrated for L=16. Scale them by 16/L
    # so every L gets the same total number of bytes (L=8 -> 2x samples,
    # L=32 -> 0.5x samples).
    RC4_REF_LEN = 16
    scale = lambda n: (n * RC4_REF_LEN) // int(l)

    u_path = path + "RC4_" + l
    # Note the argument order here is (train, test, validate).
    RC4_generate(u_path, scale(N_TRAIN), scale(N_TEST), scale(N_VALIDATE), l)

elif mode == "RC4_unscaled":
    # Same as "RC4" but uses the config's N_TRAIN/N_VALIDATE/N_TEST verbatim
    # (no 16/L scaling), for configs that set the per-L sample counts directly
    # (e.g. config_rc4_large.json).
    path = sys.argv[3]
    l = sys.argv[4]

    u_path = path + "RC4_" + l
    RC4_generate(u_path, N_TRAIN, N_TEST, N_VALIDATE, l)
