#!/usr/bin/env python
# coding: utf-8
"""
evaluate_model.py  --  load a saved .h5 model and evaluate it on two classes.

Usage:
    python training/evaluate_model.py model.h5 path/class0 path/class1 [--bitmode] [-n N]

Arguments:
    model.h5   : Keras model saved via model.save() (e.g. by ind_cpa.py)
    class0     : file of hex-encoded ciphertexts for class 0 (label 0),
                 typically the held-out <prefix>_test file
    class1     : file of hex-encoded ciphertexts for class 1 (label 1)
    --bytemode : represent each byte as an integer (default)
    --bitmode  : unpack each byte into 8 bits instead
    -n N       : max samples to load per class (default: all)

Outputs:
    - Accuracy on the combined test set
    - Two-sided binomial test  H0: accuracy = 0.5  vs  H1: accuracy != 0.5
"""

import sys
import os
import argparse
import numpy as np
import tensorflow as tf
from scipy.stats import binom_test
from sklearn.preprocessing import MinMaxScaler

from crypto_import import import_hex_ciphers
import model_layers  # registers custom Slice layer so load_model can deserialise it  # noqa: F401


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Evaluate a saved Keras model on two cipher classes.")
    p.add_argument("model_h5",   help=".h5 file produced by model.save()")
    p.add_argument("class0_path", help="Hex-cipher file for class 0")
    p.add_argument("class1_path", help="Hex-cipher file for class 1")
    p.add_argument("--bytemode", action="store_true", default=True,
                   help="Load data as raw bytes instead of unpacked bits (default: True)")
    p.add_argument("--bitmode", dest="bytemode", action="store_false",
                   help="Load data as unpacked bits instead of raw bytes")
    p.add_argument("-n", "--num_samples", type=int, default=10_000_000,
                   help="Max samples to load per class (default: all)")
    return p.parse_args()


# ── Data loading ─────────────────────────────────────────────────────────────

def load_class(path, n, bytemode):
    data = import_hex_ciphers(path, n, bytemode=bytemode).astype(np.float32)
    if data is None or len(data) == 0:
        print(f"ERROR: no data loaded from {path}")
        sys.exit(1)
    return data


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # ── Load model ────────────────────────────────────────────────────────────
    if not os.path.isfile(args.model_h5):
        print(f"ERROR: model file not found: {args.model_h5}")
        sys.exit(1)

    print(f"Loading model from {args.model_h5} …")
    model = tf.keras.models.load_model(args.model_h5)
    model.summary()

    # ── Load data ─────────────────────────────────────────────────────────────
    print(f"\nLoading class 0 from {args.class0_path} …")
    data0 = load_class(args.class0_path, args.num_samples, args.bytemode)

    print(f"Loading class 1 from {args.class1_path} …")
    data1 = load_class(args.class1_path, args.num_samples, args.bytemode)

    # Verify shape compatibility with model input
    expected_input = model.input_shape[1:]   # strip batch dim
    if data0.shape[1:] != expected_input:
        print(f"ERROR: data shape {data0.shape[1:]} does not match model input {expected_input}")
        print("       Try toggling --bytemode.")
        sys.exit(1)

    n0, n1 = len(data0), len(data1)
    print(f"\nSamples  —  class 0: {n0},  class 1: {n1},  total: {n0 + n1}")

    # ── Normalise (fit on combined evaluation data) ───────────────────────────
    X = np.concatenate([data0, data1], axis=0)
    y = np.concatenate([np.zeros(n0, dtype=np.float32),
                        np.ones(n1,  dtype=np.float32)])

    scaler = MinMaxScaler()
    X = scaler.fit_transform(X).astype(np.float32)

    # ── Predict ───────────────────────────────────────────────────────────────
    print("\nRunning predictions …")
    probs = model.predict(X, batch_size=4096, verbose=1).flatten()
    preds = (probs >= 0.5).astype(np.float32)

    # ── Accuracy ──────────────────────────────────────────────────────────────
    correct = int(np.sum(preds == y))
    total   = len(y)
    accuracy = correct / total

    print(f"\n{'='*50}")
    print(f"  Correct predictions : {correct} / {total}")
    print(f"  Accuracy            : {accuracy:.6f}  ({accuracy*100:.4f} %)")

    # ── Binomial test ─────────────────────────────────────────────────────────
    pvalue = binom_test(correct, total, p=0.5, alternative='two-sided')
    print(f"\n  Binomial test  H0: accuracy = 0.5  vs  H1: accuracy ≠ 0.5")
    print(f"  p-value             : {pvalue:.6e}")

    alpha = 0.05
    if pvalue < alpha:
        print(f"  Decision (α={alpha})   : REJECT H0  —  accuracy is significantly different from chance")
    else:
        print(f"  Decision (α={alpha})   : FAIL TO REJECT H0  —  no significant difference from chance")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
