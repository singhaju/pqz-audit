"""Medians, minima and maxima of every cloud-w17 job (raw data unmodified).

Usage: python3 -I summary_w17.py [out_dir]
Writes summary_w17_<job>.csv (one row per configuration group) into out_dir
(default: analysis/out-w17) and prints the alone-check of exp2a.
Timed rows only (warmup == 0). Times in ms (time_ns / 1e6).
"""
import csv, os, statistics, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(BASE, "results", "cloud-w17")
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "out-w17")
os.makedirs(OUT, exist_ok=True)

KEYS = ["exp", "series", "n", "mb", "sigma", "layout", "predicate", "agg", "approach"]
JOBS = {
    "exp2a": "exp2a/exp2a.csv", "exp2a-alone": "exp2a-alone/exp2a.csv",
    "exp2b": "exp2b/exp2b.csv", "exp2bd": "exp2bd/exp2bd.csv", "exp2c": "exp2c/exp2c.csv",
    "exp3a": "exp3a/exp3a.csv", "exp3ad": "exp3ad/exp3ad.csv",
    "exp3b-r1": "exp3b-r1/exp3b.csv", "exp3b-r2": "exp3b-r2/exp3b.csv",
    "exp3c": "exp3c/exp3c.csv", "exp3d": "exp3d/exp3d.csv",
    "exp1": "exp1/exp1.csv", "exp1_construction": "exp1_construction/exp1_construction.csv",
}


def load(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def group(rows):
    g = {}
    for r in rows:
        if r["warmup"] not in ("0", ""):
            continue
        g.setdefault(tuple(r[k] for k in KEYS), []).append(r)
    return g


def stats(rs):
    t = [float(r["time_ns"]) / 1e6 for r in rs]
    return len(t), statistics.median(t), min(t), max(t)


def summarize(name):
    rows = load(os.path.join(RES, JOBS[name]))
    g = group(rows)
    out = os.path.join(OUT, f"summary_w17_{name}.csv")
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(KEYS + ["runs", "median_ms", "min_ms", "max_ms", "n_blocks", "n_retained_blocks", "n_cand", "n_sel", "bytes"])
        for k, rs in g.items():
            n, med, lo, hi = stats(rs)
            r0 = rs[0]
            w.writerow(list(k) + [n, f"{med:.6g}", f"{lo:.6g}", f"{hi:.6g}",
                                  r0["n_blocks"], r0["n_retained_blocks"], r0["n_cand"], r0["n_sel"], r0["bytes"]])
    return g


groups = {n: summarize(n) for n in JOBS}

# alone-check of exp2a: Phase A copy (pinned, 15 jobs in parallel) against the alone copy
a, b = groups["exp2a"], groups["exp2a-alone"]
print("exp2a alone-check: cell, phaseA median ms, alone median ms, diff %")
worst = 0.0
rows_out = []
for k in a:
    if k not in b:
        continue
    ma, mb = stats(a[k])[1], stats(b[k])[1]
    d = (ma - mb) / mb * 100 if mb else float("nan")
    rows_out.append((k, ma, mb, d))
    if abs(d) > worst:
        worst = abs(d)
with open(os.path.join(OUT, "alonecheck_w17_exp2a.csv"), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(KEYS + ["phaseA_median_ms", "alone_median_ms", "diff_pct"])
    for k, ma, mb, d in rows_out:
        w.writerow(list(k) + [f"{ma:.6g}", f"{mb:.6g}", f"{d:.2f}"])
big = [(k, ma, mb, d) for k, ma, mb, d in rows_out if abs(d) > 10]
print(f"cells compared: {len(rows_out)}, largest |diff| {worst:.2f}%, cells with |diff|>10%: {len(big)}")
for k, ma, mb, d in sorted(big, key=lambda x: -abs(x[3]))[:25]:
    print("  ", k[1:], f"A={ma:.4g} alone={mb:.4g} diff={d:+.1f}%")
