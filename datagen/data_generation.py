"""
data_generation.py -- datasets for a single encryption algorithm ("single_alg"
mode of generate_data.py).

For every algorithm two classes are produced under one fixed key:
    <output_file>_random     encryptions of uniformly random plaintexts
    <output_file>_nonrandom  encryptions of a fixed all-zero plaintext
each split into _train / _validation / _test files with one hex-encoded
ciphertext per line. An IND-CPA secure scheme should make these two classes
indistinguishable.

The PQC schemes (Kyber, BIKE, HQC) are produced by the C programs in pqc/,
which write <output_file>_random and <output_file>_nonrandom in one go;
split_file() then cuts each of those into the three splits. RSA and RC4 are
generated directly in Python, one split file at a time.
"""
import subprocess

from rsa_datageneration import RSA_padded_generate_and_fill, RSA_unpadded_generate_and_fill
from xor_bce_data import generate_combiner_ciphers

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, ARC4
from Crypto.Random import get_random_bytes

from rsa_unpadded import unp_rsa


def generate_data(algorithm, n_train, n_valid, n_test, output_file):
    """Generate the random/nonrandom datasets for `algorithm`.

    Note the argument order is (train, validate, test). The binaries in pqc/
    are invoked with paths relative to the repository root, so this must be
    run from there.
    """
    # Where the RSA / RC4 key is stored (not used by the PQC binaries, which
    # write their own <output_file>_keys).
    keyfile = output_file + "_pk.pem"

    # --- Kyber (IND-CPA encryption, see pqc/kyber_data/kyber_indcpa_enc.c) ---
    if algorithm == "kyber512":
         subprocess.run("./pqc/kyber_data/kyber_indcpa_enc 512 %s %s " %(n_test+n_train+n_valid, output_file), shell=True)

         split_file(output_file+ "_nonrandom", n_train, n_valid)
         split_file(output_file+ "_random", n_train, n_valid)

    elif algorithm == "kyber768":
         subprocess.run("./pqc/kyber_data/kyber_indcpa_enc 768 %s %s " %(n_test+n_train+n_valid, output_file), shell=True)

         split_file(output_file+ "_nonrandom", n_train, n_valid)
         split_file(output_file+ "_random", n_train, n_valid)

    elif algorithm == "kyber1024":
         subprocess.run("./pqc/kyber_data/kyber_indcpa_enc 1024 %s %s " %(n_test+n_train +n_valid, output_file), shell=True)

         split_file(output_file+ "_nonrandom", n_train, n_valid)
         split_file(output_file+ "_random", n_train, n_valid)

    # --- BIKE (PKE layer, see pqc/bike_data/bike_program_pke.c) ---
    elif algorithm == "BIKE":
        subprocess.run("./pqc/bike_data/bike_program_pke %s %s " %(n_test+n_train + n_valid, output_file), shell=True)

        split_file(output_file+ "_nonrandom", n_train, n_valid)
        split_file(output_file+ "_random", n_train, n_valid)

    # --- HQC (PKE layer, see pqc/hqc_data/hqc_test_program.c) ---
    elif algorithm == "HQC":
        subprocess.run("./pqc/hqc_data/build/hqc_test %s %s " %(n_test+n_train+n_valid, output_file), shell=True)

        split_file(output_file+ "_nonrandom", n_train, n_valid)
        split_file(output_file+ "_random", n_train, n_valid)

    # --- RSA-2048 with OAEP padding, 16-byte plaintexts ---
    elif algorithm == "rsa_padded":

        key = RSA.generate(2048)
        pk = key.publickey().export_key()
        cipher = PKCS1_OAEP.new(RSA.import_key(pk))


        RSA_padded_generate_and_fill(output_file + "_random_train", n_train, True, cipher)
        RSA_padded_generate_and_fill(output_file + "_random_test", n_test, True, cipher)
        RSA_padded_generate_and_fill(output_file + "_random_validation", n_valid, True, cipher)
        RSA_padded_generate_and_fill(output_file + "_nonrandom_validation", n_valid, False, cipher)
        RSA_padded_generate_and_fill(output_file + "_nonrandom_train", n_train, False, cipher)
        RSA_padded_generate_and_fill(output_file + "_nonrandom_test", n_test, False, cipher)

        with open(keyfile, "wb") as kf:
            kf.write(pk)

    # --- Textbook (unpadded) RSA-2048, 16-byte plaintexts. Deterministic, so
    # --- every all-zero plaintext gives the same ciphertext. ---
    elif algorithm == "rsa_unpadded":
        rsa_instance = unp_rsa()

        RSA_unpadded_generate_and_fill(output_file + "_random_train", n_train, True, rsa_instance)
        RSA_unpadded_generate_and_fill(output_file + "_random_test", n_test, True, rsa_instance)
        RSA_unpadded_generate_and_fill(output_file + "_random_validation", n_valid, True, rsa_instance)
        RSA_unpadded_generate_and_fill(output_file + "_nonrandom_train", n_train, False, rsa_instance)
        RSA_unpadded_generate_and_fill(output_file + "_nonrandom_test", n_test, False, rsa_instance)
        RSA_unpadded_generate_and_fill(output_file + "_nonrandom_validation", n_valid, False, rsa_instance)

        # Stores the private exponent d
        with open(keyfile, "w") as kf:
            kf.write(str(rsa_instance.d))

    # --- RC4 on 16-byte plaintexts ---
    elif algorithm == "rc4":
        RC4_generate(output_file, n_train, n_test, n_valid, 16)



    # --- Unpadded RSA and AES-ECB side by side (not exposed through
    # --- generate_data.py; produces no validation split) ---
    elif algorithm == "rsa_and_aes":
        rsa_instance = unp_rsa()

        aes_key = get_random_bytes(16)

        aes_instance = AES.new(aes_key, AES.MODE_ECB)
        generate_combiner_ciphers(True, output_file + "_random_train", n_train, rsa_instance, aes_instance)
        generate_combiner_ciphers(False, output_file + "_nonrandom_train", n_train, rsa_instance, aes_instance)
        generate_combiner_ciphers(True, output_file + "_random_test", n_test, rsa_instance, aes_instance)
        generate_combiner_ciphers(False, output_file + "_nonrandom_test", n_test, rsa_instance, aes_instance)

    else:
        print("Invalid choice of algorithm, valid choices are: \n kyber \n rsa_padded \n and rsa_unpadded")


def RC4_generate(output_file, n_train, n_test, n_valid, l):
    """Generate RC4 random/nonrandom datasets with l-byte plaintexts.

    Note the argument order is (train, test, validate). One 13-byte key is
    fixed for the whole dataset and a fresh 3-byte IV is prepended to it for
    every sample (WEP-style keying); the IV is not written to the output.
    """
    l = int(l)
    keyfile = output_file + "_pk.pem"
    key = get_random_bytes(13)



    RC4_generate_and_fill(output_file + "_random_train", n_train, True, l, key)
    RC4_generate_and_fill(output_file + "_random_test", n_test, True, l, key)
    RC4_generate_and_fill(output_file + "_random_validation", n_valid, True, l, key)
    RC4_generate_and_fill(output_file + "_nonrandom_train", n_train, False, l, key)
    RC4_generate_and_fill(output_file + "_nonrandom_test", n_test, False, l, key)
    RC4_generate_and_fill(output_file + "_nonrandom_validation", n_valid, False, l, key)

    with open(keyfile, "wb") as kf:
        kf.write(key)

def RC4_generate_and_fill(file, n, userandom, l, key):
    """Write n RC4 ciphertexts to `file`, one hex string per line.

    userandom=True encrypts random l-byte plaintexts, False encrypts l zero
    bytes (so the ciphertext is the raw RC4 keystream).
    """

    with open(file, "w") as f:
        for i in range(n):
            if userandom:
                plaintext = get_random_bytes(l)
            else:
                plaintext = bytes(l)
            iv = get_random_bytes(3)
            cipher = ARC4.new(iv + key)

            ciphertext = cipher.encrypt(plaintext)

            f.write(ciphertext.hex() + "\n")


def split_file(input_file, n_train, n_valid):
    """Split input_file line-wise into <input_file>_train (first n_train
    lines), _validation (next n_valid lines) and _test (the rest)."""
    with open(input_file, "r") as input , open(input_file + "_train", "w") as train_file,  open(input_file + "_validation", "w") as valid_file, open(input_file + "_test", "w") as test_file:
        lines =input.readlines()
        train_file.writelines(lines[:n_train])
        valid_file.writelines(lines[n_train:n_train+n_valid])
        test_file.writelines(lines[n_train+n_valid:])


# Small smoke test: writes 5 samples per split for three algorithms into the
# current directory.
if __name__ == '__main__':
    generate_data("rsa_padded", 5, 5, 5, "padded_bacon")
    generate_data("rsa_unpadded", 5, 5, 5, "unpadded_bacon")
    generate_data("kyber512", 5, 5, 5 ,"pqc_bacon")
