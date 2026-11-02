"""
crypto_import.py -- load a file of hex-encoded ciphertexts (one per line, all
the same length) into a NumPy array.
"""
import numpy as np

def import_hex_ciphers(key_file, max_keys, bytemode=False):
    """Read at most `max_keys` lines of `key_file`.

    Returns a uint8 array of shape (n, bytes_per_line) if `bytemode`, else
    the unpacked bits with shape (n, 8 * bytes_per_line).
    """
    with open(key_file, 'r') as f:
        lines = [l.strip() for l in f if l.strip()]

    lines = lines[:max_keys]
    n = len(lines)

    # Decode all lines at once, then reshape into one row per ciphertext.
    combined = ''.join(lines)
    raw = np.array(bytearray.fromhex(combined), dtype=np.uint8)

    if bytemode:
        return raw.reshape(n, len(lines[0]) // 2)
    else:
        return np.unpackbits(raw).reshape(n, len(lines[0]) * 4)
