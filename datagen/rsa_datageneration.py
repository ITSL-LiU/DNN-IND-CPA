"""
rsa_datageneration.py -- helpers that write RSA ciphertext files, one hex
ciphertext per line. Used by data_generation.py ("single_alg" mode).

userandom=True encrypts random 16-byte plaintexts, False encrypts 16 zero
bytes.
"""
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from rsa_unpadded import unp_rsa


# Sample counts for the standalone __main__ run below only.
N_TRAIN = 10
N_TEST = 10


def RSA_padded_generate_and_fill(file, N, userandom, cipher):
    """Write N RSA-OAEP ciphertexts (`cipher` is a PKCS1_OAEP object)."""
    check_remove(file)
    with open(file, "w") as f:

        for i in range(N):
            if userandom:
                plaintext = get_random_bytes(16)
            else:
                plaintext = bytes(16)

            ciphertext = cipher.encrypt(plaintext)
            hex_string = ''.join(format(byte, '02x') for byte in ciphertext)

            f.write(hex_string + "\n")


def RSA_unpadded_generate_and_fill(file, N, userandom, rsa_instance):
    """Write N textbook-RSA ciphertexts (`rsa_instance` is an unp_rsa)."""
    check_remove(file)
    with open(file, "w") as f:

        for i in range(N):
            if userandom:
                plaintext = get_random_bytes(16)
            else:
                plaintext = bytes(16)

            pt = int.from_bytes(plaintext, byteorder="big")  # Convert bytes to integer
            ciphertext = rsa_instance.encrypt(pt)  # Encrypt the plaintext
            hex_string = ciphertext

            f.write(hex_string + "\n")

def check_remove(file):
    """Delete `file` if it exists (otherwise just print a note)."""
    if os.path.exists(file):
        os.remove(file)
    else:
        print("file %s does not exist" % file)


# Unused helper: write alternating "Ciphertext:" / "Shared secret:" lines for
# N random 16-byte secrets.
def RSA_padded_cipher_and_secrets(file, N, rsa_instance):
    check_remove(file)
    with open(file, "w") as f:
        for i in range(N):

            plaintext = get_random_bytes(16)

            pt = int.from_bytes(plaintext, byteorder="big")  # Convert bytes to integer
            ciphertext = rsa_instance.encrypt(pt)  # Encrypt the plaintext
            hex_string = hex(ciphertext)[2:]

            f.write("Ciphertext:" + hex_string + "\n")
            hpt = hex(pt)
            f.write("Shared secret:" + hpt[2:] +"\n")


# Small manual test (all calls write to the same file, so only the last one
# is kept).
if __name__ == '__main__':

    os.makedirs("data/RSA", exist_ok=True)  # Fixed: Ensure path exists

    key = RSA.generate(2048)
    pk = key.publickey().export_key()
    cipher = PKCS1_OAEP.new(RSA.import_key(pk))


    RSA_padded_generate_and_fill("data/RSA/rsa_padded_random_train", N_TRAIN, True, cipher)
    RSA_padded_generate_and_fill("data/RSA/rsa_padded_random_train", N_TEST, True, cipher)
    RSA_padded_generate_and_fill("data/RSA/rsa_padded_random_train", N_TRAIN, False, cipher)
    RSA_padded_generate_and_fill("data/RSA/rsa_padded_random_train", N_TEST, False, cipher)

    rsa_instance = unp_rsa()

    RSA_unpadded_generate_and_fill("data/RSA/rsa_padded_random_train", N_TRAIN, True, rsa_instance)
    RSA_unpadded_generate_and_fill("data/RSA/rsa_padded_random_train", N_TEST, True, rsa_instance)
    RSA_unpadded_generate_and_fill("data/RSA/rsa_padded_random_train", N_TRAIN, False, rsa_instance)
    RSA_unpadded_generate_and_fill("data/RSA/rsa_padded_random_train", N_TEST, False, rsa_instance)
