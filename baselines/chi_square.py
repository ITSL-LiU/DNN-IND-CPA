"""
chi_square.py -- per-row chi-squared test for byte bias.

For every line of a ciphertext file, the 256 byte-value frequencies are
compared with a uniform distribution. A row is "biased" if the test rejects
uniformity at significance level ALPHA. Used as a non-learned baseline by
chi_baseline_eval.py.

Usage:
    python baselines/chi_square.py <file> [-s]
"""
import argparse
from scipy.stats import chisquare, chi2

ALPHA = 0.01
NUM_BYTE_VALUES = 256


def _row_to_bytes(line):
    """Parse one line as hex (an optional "label:" prefix is dropped). Lines
    that are not valid hex are taken as raw text."""
    line = line.strip()
    if ":" in line:
        line = line.split(":", 1)[1].strip()
    try:
        return bytes.fromhex(line)
    except ValueError:
        return line.encode()


def chi_square_byte_bias(file_path, alpha=ALPHA):
    """For each row in file_path, count byte frequencies and run a
    chi-squared goodness-of-fit test against a uniform byte distribution.

    Returns a list of dicts, one per row, with the test statistic, p-value,
    the alpha decision boundary and whether the row is biased (rejects the
    null hypothesis of a uniform byte distribution).
    """
    # 255 degrees of freedom (256 byte values minus one constraint).
    critical_value = chi2.ppf(1 - alpha, df=NUM_BYTE_VALUES - 1)
    results = []

    with open(file_path, "r") as f:
        for row_num, line in enumerate(f, start=1):
            if not line.strip():
                continue

            row_bytes = _row_to_bytes(line)
            if not row_bytes:
                continue

            observed = [0] * NUM_BYTE_VALUES
            for b in row_bytes:
                observed[b] += 1

            expected = len(row_bytes) / NUM_BYTE_VALUES
            statistic, p_value = chisquare(observed, f_exp=[expected] * NUM_BYTE_VALUES)
            biased = statistic > critical_value

            results.append({
                "row": row_num,
                "n_bytes": len(row_bytes),
                "statistic": statistic,
                "p_value": p_value,
                "critical_value": critical_value,
                "biased": biased,
            })

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chi-squared byte-bias test per row of a file.")
    parser.add_argument("file_path")
    parser.add_argument("-s", "--simple", action="store_true",
                         help="print only row count, biased row count and biased percentage")
    args = parser.parse_args()

    results = chi_square_byte_bias(args.file_path)

    if args.simple:
        n_rows = len(results)
        n_biased = sum(1 for res in results if res["biased"])
        pct_biased = (n_biased / n_rows * 100) if n_rows else 0.0
        print(f"rows: {n_rows}")
        print(f"biased rows: {n_biased}")
        print(f"biased percentage: {pct_biased:.2f}%")
    else:
        for res in results:
            verdict = "BIASED" if res["biased"] else "uniform"
            print(f"row {res['row']}: chi2={res['statistic']:.2f} "
                  f"(critical={res['critical_value']:.2f}, p={res['p_value']:.4g}) -> {verdict}")
