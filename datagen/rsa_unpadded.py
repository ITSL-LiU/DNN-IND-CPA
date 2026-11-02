"""
rsa_unpadded.py -- minimal textbook RSA (no padding), used to generate
deterministic RSA ciphertexts. Not secure; for experiments only.
"""
from Crypto.Util import number
import random

class unp_rsa:
    """Textbook RSA keypair. encrypt() takes an integer and returns the
    ciphertext as a hex string zero-padded to keysize/4 characters."""
    def __init__(self, keysize=2048):
        self.keysize = keysize
        self.generate_keys()

    def generate_keys(self):
        # Generate two large prime numbers p and q
        self.p = number.getPrime(self.keysize // 2)
        self.q = number.getPrime(self.keysize // 2)
        # Calculate n = p * q and phi = (p-1) * (q-1)
        self.n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1)
        # Pick a public exponent e such that 1 < e < phi and gcd(e, phi) = 1
        self.e = 65537  # Commonly used public exponent
        while number.GCD(self.e, phi) != 1:
            self.e = random.randint(3, phi - 1)
        # Compute the private exponent d such that (d * e) ≡ 1 (mod phi)
        self.d = number.inverse(self.e, phi)

    def encrypt(self, plaintext):
        """
        Encrypt the plaintext integer with the public key (n, e).
        Pads the ciphertext to ensure it's always of size keysize.
        """
        if plaintext >= self.n:
            raise ValueError("Plaintext must be smaller than modulus n.")
        # Ciphertext is calculated as plaintext^e % n
        ciphertext = pow(plaintext, self.e, self.n)
        # Convert ciphertext to a hex representation padded to keysize bits
        hex_ciphertext = hex(ciphertext)[2:]  # Strip "0x" prefix
        padded_ciphertext = hex_ciphertext.zfill(self.keysize//4)  # Zero padding
        return padded_ciphertext  # Return as a string for consistency

    def decrypt(self, ciphertext):
        """
        Decrypt the ciphertext integer with the private key (n, d).
        Assumes ciphertext is already in binary format and properly padded.
        Note: encrypt() returns hex, not binary, so the two are not inverses
        as written. Not used by the data generation.
        """
        # Convert padded binary string back to integer
        ciphertext_int = int(ciphertext, 2)
        # Compute the plaintext using modular exponentiation
        plaintext = pow(ciphertext_int, self.d, self.n)
        return plaintext

def test_rsa():
    keysize = 1024  # Key size in bits
    rsa = unp_rsa(keysize)
    print("Public Key (n, e):")
    print(f"n = {rsa.n}")
    print(f"e = {rsa.e}")
    print()
    print("Private Key (n, d):")
    print(f"d = {rsa.d}")
    print()
    # Example plaintext (must be less than n)
    plaintext = bytes(16)  # Replace this with any integer less than `rsa.n`
    print(f"Original Plaintext: {plaintext}")
    # Encryption
    ciphertext = rsa.encrypt(plaintext)
    print(f"Ciphertext (padded to {keysize} bits): {ciphertext}")
    # Decryption
    decrypted_plaintext = rsa.decrypt(ciphertext)
    print(f"Decrypted Plaintext: {decrypted_plaintext}")
    # Verify correctness
    assert plaintext == decrypted_plaintext, "Decrypted value does not match the original plaintext!"
    print("\nRSA Encryption/Decryption Successful!")

if __name__ == "__main__":
    test_rsa()
