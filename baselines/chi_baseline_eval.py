#!/usr/bin/env python
# coding: utf-8
"""
chi_baseline_eval.py -- chi-squared byte-bias baseline classifier.

Wraps chi_square_byte_bias() from chi_square.py as a non-learned baseline
classifier: a row is predicted nonrandom (label 1) if its per-row chi-squared
test rejects the uniform byte distribution (i.e. finds bias), else predicted
random (label 0). Reports accuracy against the true class0/class1 labels in
the same textual format as training/evaluate_model.py, so results can be
parsed identically.

Usage:
    python baselines/chi_baseline_eval.py class0_validation_path class1_validation_path [--alpha A]

Arguments:
    class0_validation_path : hex-cipher file for class 0 (true label 0 = random plaintext)
    class1_validation_path : hex-cipher file for class 1 (true label 1 = nonrandom plaintext)
    --alpha                : significance level for the chi-squared bias test (default: chi_square.ALPHA)
"""

import sys
import argparse
from scipy.stats import binomtest

from chi_square import chi_square_byte_bias, ALPHA


def parse_args():
    p = argparse.ArgumentParser(description="Chi-squared byte-bias baseline classifier.")
    p.add_argument("class0_path", help="Validation file for class 0 (true label 0 = random)")
    p.add_argument("class1_path", help="Validation file for class 1 (true label 1 = nonrandom)")
    p.add_argument("--alpha", type=float, default=ALPHA,
                   help=f"Significance level for the chi-squared bias test (default: {ALPHA})")
    return p.parse_args()


def evaluate(class0_path, class1_path, alpha=ALPHA):
    """Score the chi-squared baseline on two class files.

    Returns a dict with n0, n1, correct, total, accuracy and the two-sided
    binomial p-value against chance, or None if either file has no rows.
    """
    res0 = chi_square_byte_bias(class0_path, alpha=alpha)
    res1 = chi_square_byte_bias(class1_path, alpha=alpha)

    if not res0 or not res1:
        return None

    correct0 = sum(1 for r in res0 if not r["biased"])   # predicted random, true random
    correct1 = sum(1 for r in res1 if r["biased"])         # predicted nonrandom, true nonrandom

    n0, n1 = len(res0), len(res1)
    correct = correct0 + correct1
    total = n0 + n1
    pvalue = binomtest(correct, total, p=0.5, alternative='two-sided').pvalue

    return {"n0": n0, "n1": n1, "correct": correct, "total": total,
            "accuracy": correct / total, "pvalue": pvalue}


def main():
    args = parse_args()

    res = evaluate(args.class0_path, args.class1_path, alpha=args.alpha)
    if res is None:
        print(f"ERROR: no rows loaded from {args.class0_path} or {args.class1_path}")
        sys.exit(1)

    n0, n1, total = res["n0"], res["n1"], res["total"]
    correct, accuracy, pvalue = res["correct"], res["accuracy"], res["pvalue"]

    print(f"\nSamples  —  class 0: {n0},  class 1: {n1},  total: {total}")

    print(f"\n{'='*50}")
    print(f"  Correct predictions : {correct} / {total}")
    print(f"  Accuracy            : {accuracy:.6f}  ({accuracy*100:.4f} %)")

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
