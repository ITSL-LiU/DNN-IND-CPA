"""
sym_datagen.py -- symmetric-cipher datasets ("cascade" and "sym" modes of
generate_data.py).

Both modes encrypt 16-byte plaintexts, which are uniformly random for the
_random class and all zero for the _nonrandom class. Each class gets
_train / _validation / _test files with one hex ciphertext per line.

cascade: ct = outer(inner(pt)) with two independent keys. Every split file
         gets fresh cipher objects (and so a fresh random IV/nonce for
         CBC/CTR/ChaCha20), which are then kept for the whole file.
sym:     a single AES-CTR / AES-CBC cipher with a fixed nonce/IV that is
         re-instantiated every `rst` encryptions, so the keystream (CTR) or
         chaining state (CBC) repeats with period `rst`.
"""
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, ChaCha20, DES
from Crypto.Util.Padding import pad
import base64



def data_casc_gen(inner_cipher, outer_cipher, n_train, n_validate, n_test, output_base):
        """Generate the six cascade files <output_base>_{random,nonrandom}_{train,test,validation}."""

        # Key sizes: ChaCha20 needs 32 bytes, DES 8 bytes, AES 16 bytes.
        k32 = ["chacha20"]
        k8 =  ["des"]

        if inner_cipher in k32:
            key1 = get_random_bytes(32)
        elif inner_cipher in k8:
            key1 = get_random_bytes(8)
        else:
            key1 = get_random_bytes(16)

        if outer_cipher in k32:
            key2 = get_random_bytes(32)

        elif outer_cipher in k8:
            key2 = get_random_bytes(8)
        else:
            key2 = get_random_bytes(16)

        data_gen_file(inner_cipher, outer_cipher, n_train, output_base + "_random_train", True, key1, key2)
        data_gen_file(inner_cipher, outer_cipher, n_train, output_base + "_nonrandom_train", False, key1, key2)
        data_gen_file(inner_cipher, outer_cipher, n_test, output_base + "_random_test", True, key1, key2)
        data_gen_file(inner_cipher, outer_cipher, n_test, output_base + "_nonrandom_test", False, key1, key2)
        data_gen_file(inner_cipher, outer_cipher, n_validate, output_base + "_random_validation", True, key1, key2)
        data_gen_file(inner_cipher, outer_cipher, n_validate, output_base + "_nonrandom_validation", False, key1, key2)



def data_gen_file(inner_cipher, outer_cipher, n, output_file, userandom, key1, key2):
         """Write n cascade ciphertexts outer(inner(pt)) to output_file."""
         inner = make_cipher(inner_cipher, key1)
         outer = make_cipher(outer_cipher, key2)

         with open(output_file, "w") as of:

            for i in range(n):
                if userandom:
                    pt = get_random_bytes(16)
                else:
                    pt = bytes(16)

                ct1 = inner.encrypt(pt)
                ct2 = outer.encrypt(ct1)
                of.write(ct2.hex()+"\n")


def make_cipher(cipher, key):
    """Cipher object with a library-chosen random IV/nonce where applicable."""
    if cipher == "aes_cbc":
        return AES.new(key, AES.MODE_CBC)

    elif cipher == "aes_ecb":
        return AES.new(key, AES.MODE_ECB)

    elif cipher == "aes_ctr":
        return AES.new(key, AES.MODE_CTR)

    elif cipher == "chacha20":
        return ChaCha20.new(key=key)

    elif cipher == "des":
        return DES.new(key, DES.MODE_ECB)

def make_fixed_cipher(alg, key, fixed_val):
    """AES-CBC / AES-CTR cipher object with a caller-supplied IV / nonce."""
    if alg == "aes_cbc":
        return AES.new(key, AES.MODE_CBC, iv=fixed_val)

    elif alg == "aes_ctr":
        return AES.new(key, AES.MODE_CTR, nonce=fixed_val)


def data_sing_gen(alg, rst, n_train, n_validate, n_test, output_base):
        """Generate the six "sym" files; the IV/nonce is reset every `rst` samples."""

        # One key and one IV (16 bytes, CBC) / nonce (8 bytes, CTR) for all files.
        key = get_random_bytes(16)
        fixed_val = get_random_bytes(16) if alg == "aes_cbc" else get_random_bytes(8)

        data_sing_gen_file(alg, n_train, output_base + "_random_train", True, key, fixed_val, rst)
        data_sing_gen_file(alg, n_train, output_base + "_nonrandom_train", False, key, fixed_val, rst)
        data_sing_gen_file(alg, n_test, output_base + "_random_test", True, key, fixed_val, rst)
        data_sing_gen_file(alg, n_test, output_base + "_nonrandom_test", False, key, fixed_val, rst)
        data_sing_gen_file(alg, n_validate, output_base + "_random_validation", True, key, fixed_val, rst)
        data_sing_gen_file(alg, n_validate, output_base + "_nonrandom_validation", False, key, fixed_val, rst)


def data_sing_gen_file(alg, n, output_file, userandom, key, fixed_val, rst):
         """Write n ciphertexts to output_file, restarting the cipher (same
         key and IV/nonce) every `rst` encryptions."""
         cipher = make_fixed_cipher(alg, key, fixed_val)

         with open(output_file, "w") as of:

            for i in range(n):
                if i > 0 and i % rst == 0:
                    cipher = make_fixed_cipher(alg, key, fixed_val)

                if userandom:
                    pt = get_random_bytes(16)
                else:
                    pt = bytes(16)

                ct = cipher.encrypt(pt)
                of.write(ct.hex()+"\n")

# Small manual test: writes one cascade dataset into the current directory.
if __name__ == "__main__":
    ciphers = ["aes_ctr", "aes_ecb", "aes_cbc", "chacha20", "des"]


    data_casc_gen("aes_ecb", "chacha20", 100000, 20000, 20000, "test_here")
  #  for i in ciphers:
  #      for j in ciphers:
  #          data_gen(i,j, 10, "test_random" + i +j, True)
  #          data_gen(i,j, 10, "test_nonrandom" + i +j, False)
