"""
xor_bce_data.py -- datasets for KEM + cipher combiners ("combiner" mode of
generate_data.py).

Each sample is a KEM ciphertext concatenated with an encryption of a secret:
    <output_file>_nonindep  the secret is the KEM's own shared secret
    <output_file>_indep     the secret is an independent random value of the
                            same length
each with _train / _validation / _test splits, one hex string per line. If
the network can tell the two classes apart, the pair leaks information about
the relation between the KEM's shared secret and the second ciphertext.

Generation happens in two steps:
  1. A raw file of N KEM outputs is written, with alternating lines
     "Ciphertext:<hex>" and "Shared Secret:<hex>". This comes from a C program
     in pqc/ (Kyber, HQC, BIKE) or from Python (RSA, AES-ECB, RC4).
  2. _stream_complete() reads those pairs and writes the six split files,
     appending the second ciphertext (RSA-OAEP, unpadded RSA, or the secret
     itself for "plaintext") to each KEM ciphertext.
"""
import re
import subprocess
import shutil
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import  PKCS1_OAEP, AES, ARC4
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import os
import math
from rsa_datageneration import RSA_padded_generate_and_fill
from rsa_unpadded import unp_rsa

def generate_combiner_ciphers(independent, output_file, n, rsa_instance, aes_instance):
    """Write n lines of unpadded-RSA(pt1) || AES(pt2), where pt2 == pt1 unless
    `independent`. Used only by the "rsa_and_aes" case in data_generation.py.
    """

    check_delete(output_file)


    with open(output_file, "w") as f:
        for i in range(n):
            if independent:
                pt1 = get_random_bytes(16)
                pt2 = get_random_bytes(16)
            else:
                pt1 = get_random_bytes(16)
                pt2 = pt1

            rsa_pt = int.from_bytes(pt1, byteorder="big")  # Convert bytes to integer
            rsa_ct = rsa_instance.encrypt(rsa_pt)  # Encrypt the plaintext

            aes_ct = aes_instance.encrypt(pt2)

            f.write(rsa_ct + aes_ct.hex() + "\n")


def _stream_complete(raw_file, sections, make_ctext):
    """
    Stream the raw KEM output file into split output files without loading
    everything into memory at once.

    raw_file:   path to file with alternating "Ciphertext:<hex>" /
                "Shared Secret:<hex>" lines.
    sections:   list of (output_path, count, independent) tuples processed
                in order (they consume consecutive pairs from raw_file).
    make_ctext: callable(pt_bytes) -> hex_string  (cipher-specific)
    """
    with open(raw_file, "r", buffering=1 << 20) as raw:
        for (out_path, count, independent) in sections:
            with open(out_path, "w", buffering=1 << 20) as out:
                for _ in range(count):
                    ct_line = raw.readline()
                    ss_line = raw.readline()
                    ct_hex = ct_line.split(":", 1)[1].strip()
                    ss_hex = ss_line.split(":", 1)[1].strip()
                    pt = get_random_bytes(len(ss_hex) // 2) if independent else bytes.fromhex(ss_hex)
                    out.write(ct_hex + make_ctext(pt) + "\n")


def generate_kem_and_cipher(kem, cipher, n_train, n_test, n_valid, output_file):
    """Generate the indep/nonindep combiner datasets for (kem, cipher).

    Note the argument order is (train, test, validate). The binaries in pqc/
    are invoked with paths relative to the repository root, so this must be
    run from there.
    """

    implemented_kems = ["kyber512", "kyber768", "kyber1024", "HQC", "BIKE", "rsa_unpadded", "rsa1024", "rsa512", "AES_ECB"]
    implemented_ciphers = ["rsa_unpadded", "rsa_padded", "plaintext"]
    # "RC4_<L>": RC4 used as the KEM, encrypting a random L-byte secret.
    rc4_len = int(kem[4:]) if re.fullmatch(r"RC4_[1-9][0-9]*", kem) else None
    assert (kem in implemented_kems or rc4_len is not None) and cipher in implemented_ciphers

    # Intermediate raw KEM output file (deleted again at the end).
    if rc4_len is not None:
        # Namespaced by output_file so concurrent runs of the same combo
        # don't share an intermediate file.
        file_name = output_file + "_kem_tmp"
    else:
        file_name = "kem_tmp" + kem + cipher

    check_delete(file_name)

    # Every output sample consumes its own KEM output, for both classes.
    n = 2 * n_train + 2 * n_test + 2 * n_valid

    # --- Step 1: write n raw KEM (ciphertext, shared secret) pairs ---
    if kem == "kyber512":
        subprocess.run("./pqc/kyber_data/kyber_generate_512 %s %s" % (n, file_name), shell=True)
        extract_kyber_keys(file_name)

    elif kem == "kyber768":
        subprocess.run("./pqc/kyber_data/kyber_generate_768 %s %s" % (n, file_name), shell=True)
        extract_kyber_keys(file_name)

    elif kem == "kyber1024":
        subprocess.run("./pqc/kyber_data/kyber_generate_1024 %s %s" % (n, file_name), shell=True)
        extract_kyber_keys(file_name)

    elif kem == "HQC":
        # Step 1: generate one keypair using a single-sample run; this writes
        # <file_name>_keys (hex pk on line 1) and <file_name> (1 sample).
        pk_file = file_name + "_pk"
        subprocess.run(
            ["./pqc/hqc_data/build/hqc_kem", "1", file_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # Extract the public key (first line of _keys) into a standalone pk file
        with open(file_name + "_keys", "r") as kf:
            pk_hex = kf.readline().strip()
        with open(pk_file, "w") as pf:
            pf.write(pk_hex + "\n")

        # Step 2: spawn one process per CPU core; all share the same public key.
        n_workers = os.cpu_count() or 1
        remaining = n - 1  # 1 sample already generated above
        chunk_size = math.ceil(remaining / n_workers)
        chunk_files = []
        procs = []
        for i in range(n_workers):
            this_n = min(chunk_size, remaining - i * chunk_size)
            if this_n <= 0:
                break
            cf = "%s_chunk%d" % (file_name, i)
            chunk_files.append(cf)
            procs.append(subprocess.Popen(
                ["./pqc/hqc_data/build/hqc_kem", str(this_n), cf, pk_file],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ))
        for p in procs:
            p.wait()
        os.remove(pk_file)

        # Step 3: append all chunk files to the initial 1-sample file; clean up
        with open(file_name, "ab") as out:
            for cf in chunk_files:
                if os.path.exists(cf):
                    with open(cf, "rb") as inp:
                        shutil.copyfileobj(inp, out, length=1 << 20)
                    os.remove(cf)
                keys_chunk = cf + "_keys"
                if os.path.exists(keys_chunk):
                    os.remove(keys_chunk)

    elif kem == "BIKE":
        subprocess.run("./pqc/bike_data/bike_encap_program  %s %s" % (n, file_name), shell=True)

    elif kem == "rsa_unpadded":
        gen_unp_rsa_file(file_name, n, 2048)

    elif kem == "rsa1024":
        gen_unp_rsa_file(file_name, n, 1024)

    elif kem == "rsa512":
        gen_unp_rsa_file(file_name, n, 512)


    elif kem == "AES_ECB":
        gen_aes_ecb_file(file_name, n)

    elif rc4_len is not None:
        gen_rc4_file(file_name, n, rc4_len)

    # --- Step 2: combine each KEM output with the second ciphertext ---

    # Define the six output sections in the order they appear in the raw file
    sections = [
        (output_file + "_indep_train",        n_train, True),
        (output_file + "_nonindep_train",      n_train, False),
        (output_file + "_indep_test",          n_test,  True),
        (output_file + "_nonindep_test",       n_test,  False),
        (output_file + "_indep_validation",    n_valid, True),
        (output_file + "_nonindep_validation", n_valid, False),
    ]

    # make_ctext(secret_bytes) -> hex string appended to the KEM ciphertext.
    # The cipher's key is written to <file_name>_keys.
    if cipher == "rsa_padded":
        key = RSA.generate(2048)
        public_key = key.publickey().export_key()
        rsa_enc = PKCS1_OAEP.new(RSA.import_key(public_key))
        with open(file_name + "_keys", "wb") as kf:
            kf.write(public_key)
        def make_ctext(pt): return rsa_enc.encrypt(pt).hex()

    elif cipher == "rsa_unpadded":
        rsa_enc = unp_rsa()
        with open(file_name + "_keys", "w") as kf:
            kf.write(str(rsa_enc.d))
        def make_ctext(pt): return rsa_enc.encrypt(int.from_bytes(pt, byteorder="big"))

    elif cipher == "plaintext":
        # The secret is appended in the clear.
        def make_ctext(pt): return pt.hex()

    _stream_complete(file_name, sections, make_ctext)
    check_delete(file_name)


# --- Older helpers that build combiner rows from in-memory ciphertext (ct)
# --- and shared-secret (ss) lists. Superseded by _stream_complete() and not
# --- used by the current pipeline.

def complete_with_rsa_pad(output, ct, ss, independent, rsa_cipher):

    with open(output, "w") as of:

        i = 0
        for c in ct:
            if independent:
                pt = get_random_bytes(len(ss[0].strip())//2)

            else:
                pt = bytes.fromhex(ss[i].strip())

            i = i+1

            c_text= rsa_cipher.encrypt(pt)
            c_text = c_text.hex()
            of.write(c.strip() + c_text + "\n")

def complete_with_rsa_unpad(output, ct, ss, independent, rsa_cipher):

    with open(output, "w") as of:

        i = 0
        for c in ct :
            if independent:
                pt = get_random_bytes(len(ss[0].strip())//2)
                pt = int.from_bytes(pt, byteorder="big")
            else:
                pt = ss[i].strip()
                pt = int(pt,16)

            i = i+1

            c_text = rsa_cipher.encrypt(pt)
            of.write(c.strip() + c_text + "\n")

def complete_with_pt(output, ct, ss, independent):

    with open(output, "w") as of:
        i = 0
        for c in ct:
            if independent:
                pt = get_random_bytes(len(ss[0].strip())//2)
                pt = pt.hex()
            else:
                pt = ss[i]

            i = i+1
            of.write(c.strip() + pt.strip()+"\n")

def check_delete(file):
    """Delete `file` if it exists (otherwise just print a note)."""
    if os.path.exists(file):
        os.remove(file)
    else:
        print("The file %s does not exist" % file)


# Unused helper: encrypt one byte string under a freshly generated RSA key.
def rsa_cipher(string, n, padded = True):
    if padded:
        key = RSA.generate(2048)
        public_key = key.publickey().export_key()
        cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
        c_text= cipher.encrypt(string)
        return c_text.hex()
    else:
        rsa_instance = unp_rsa()  # Create an instance of unpadded RSA
        plaintext = int.from_bytes(string, byteorder="big")  # Convert bytes to integer
        ciphertext = rsa_instance.encrypt(plaintext)  # Encrypt the plaintext
        return ciphertext  # Return the encrypted integer

# Unused helper: copy the values of all "<keyword>:<value>" lines of
# input_file into output_file.
def process_file(input_file, output_file, keyword):
    # Open the input file to read its contents
    try:
        with open(input_file, "r") as i_file, open(output_file, "w+") as o_file:
            lines = i_file.readlines()

            for l in lines:
                x  =l.split(":")
                if x[0] == keyword:
                    o_file.write(x[1])


        print(f"Processed file saved to '{output_file}'")

    except FileNotFoundError:
        print("Error: The specified input file does not exist!")
    except Exception as e:
        print(f"An error occurred: {e}")


# --- Python "KEMs": write n raw Ciphertext/Shared Secret pairs to `file` in
# --- the same format as the C programs. Each encrypts a random secret.

def gen_unp_rsa_file(file, n, k):
    """Unpadded k-bit RSA encrypting random 16-byte secrets."""
    with open(file, "w") as f:
        rsa_instance = unp_rsa(k)

        with open(file + "_keys", "w") as kf:
            kf.write(str(rsa_instance.d))

        for i in range(n):

            pt = get_random_bytes(16)

            pt_int = int.from_bytes(pt, byteorder="big")
            c_text = rsa_instance.encrypt(pt_int)
            f.write("Ciphertext:" + c_text + "\n")
            f.write("Shared Secret:" + pt.hex()+"\n")


def gen_aes_ecb_file(file, n):
    """AES-128-ECB under one fixed key, encrypting random 16-byte secrets."""
    with open(file, "w") as f:

        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_ECB)
        for _ in range(n):
            pt = get_random_bytes(16)
            ct_bytes = cipher.encrypt(pt)
            f.write("Ciphertext:" + ct_bytes.hex() + "\n")
            f.write("Shared Secret:" + pt.hex()+"\n")



def gen_rc4_file(file, n, l):
    # Keyed like RC4_generate in data_generation.py: one fixed 13-byte key per
    # dataset, a fresh 3-byte IV prepended per sample, IV not output.
    key = get_random_bytes(13)
    with open(file + "_keys", "wb") as kf:
        kf.write(key)

    with open(file, "w", buffering=1 << 20) as f:
        for _ in range(n):
            pt = get_random_bytes(l)
            iv = get_random_bytes(3)
            ct_bytes = ARC4.new(iv + key).encrypt(pt)
            f.write("Ciphertext:" + ct_bytes.hex() + "\n")
            f.write("Shared Secret:" + pt.hex() + "\n")


def extract_kyber_keys(file):
    """kyber_generate_* writes three header lines (parameter set, public key,
    secret key) before the Ciphertext/Shared Secret pairs. Move them to
    <file>_keys so `file` holds only the pairs."""
    with open(file, 'r') as f:
         lines = f.readlines()

    with open(file + "_keys", 'w') as f_out:
        f_out.writelines(lines[:3])

    with open(file, 'w') as f:
        f.writelines(lines[3:])
