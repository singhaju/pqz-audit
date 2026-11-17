"""Recompute one plotted median per figure with the plain csv module.

Reads the raw files directly, drops warm-up rows the same way the figure
scripts do, recomputes one median per figure, and compares it with the value
the figure CSV says it plotted.  Prints OK or MISMATCH for each check.
"""

from __future__ import annotations

import csv
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
OUT = os.path.join(HERE, "out")


def read_rows(path):
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        return list(csv.DictReader(fh))


def num(value):
    if value is None or value == "":
        return None
    return float(value)


def timed_proof(row):
    return num(row.get("warmup")) == 0.0


def timed_ledger(row):
    return row.get("kind") == "timed"


def median(rows, field):
    return statistics.median(num(row[field]) for row in rows)


def figure_rows(name):
    return read_rows(os.path.join(OUT, f"{name}.csv"))


def find_plotted(rows, metric, series, x=None):
    for row in rows:
        if row.get("metric") != metric or row.get("series") != series:
            continue
        if row.get("status") != "plotted":
            continue
        if x is None:
            return row
        try:
            if abs(float(row.get("x")) - float(x)) < 1e-9:
                return row
        except (TypeError, ValueError):
            continue
    raise KeyError(f"no plotted row metric={metric} series={series} x={x}")


def same(actual, expected, rel=2e-6):
    return abs(actual - expected) <= rel * max(abs(expected), 1e-12)


def main():
    checks = []
    failures = 0

    proof = os.path.join(REPO, "bench", "pqz-proof", "results", "full-2",
                         "raw.csv")
    ledger = os.path.join(REPO, "bench", "pqz-ledger", "results", "full-1",
                          "with-tx-auth")
    exp2a_path = os.path.join(REPO, "bench", "pqz-eval", "results", "full-1",
                              "exp2a", "exp2a.csv")
    exp1_path = os.path.join(REPO, "bench", "pqz-eval", "results", "full-1",
                             "exp1", "exp1.csv")
    baseline_path = os.path.join(REPO, "bench", "pqz-baselines",
                                 "results-papers-run2", "baseline_costs.csv")

    # exp4a: R_RC at N_Q = 1e5, prove_s -> ms.
    rows = [r for r in read_rows(proof) if timed_proof(r)
            and r.get("experiment") == "scale" and r.get("rel") == "rc"
            and num(r.get("n_records")) == 100000.0]
    actual = median(rows, "prove_s") * 1000.0
    expected = float(find_plotted(figure_rows("fig_exp4a"), "prove_s", "rc",
                                  100000)["median"])
    checks.append(("exp4a", "R_RC N=1e5 prove ms", actual, expected))

    # exp4b: bundle, distinct proofs, q = 25, total_verify_s -> ms.
    rows = [r for r in read_rows(proof) if timed_proof(r)
            and r.get("experiment") == "q" and r.get("rel") == "bundle"
            and r.get("mode") == "distinct" and num(r.get("q")) == 25.0]
    actual = median(rows, "total_verify_s") * 1000.0
    expected = float(find_plotted(figure_rows("fig_exp4b"), "total_verify_s",
                                  "distinct", 25)["median"])
    checks.append(("exp4b", "bundle distinct q=25 ms", actual, expected))

    # exp5a: pqz, q = 100, lat_p50_ns -> ms.
    rows = [r for r in read_rows(os.path.join(
        ledger, "exp5a_latency_throughput.csv")) if timed_ledger(r)
        and r.get("system") == "pqz" and num(r.get("q")) == 100.0]
    actual = median(rows, "lat_p50_ns") / 1e6
    expected = float(find_plotted(figure_rows("fig_exp5a"), "lat_p50", "pqz",
                                  100)["median"])
    checks.append(("exp5a", "pqz q=100 latency ms", actual, expected))

    # exp5b: authorize, op_latency_ns -> ms.
    rows = [r for r in read_rows(os.path.join(
        ledger, "exp5b_governance.csv")) if timed_ledger(r)
        and r.get("op") == "authorize"]
    actual = median(rows, "op_latency_ns") / 1e6
    expected = float(find_plotted(figure_rows("fig_exp5b"), "op_latency",
                                  "authorize")["median"])
    checks.append(("exp5b", "authorize latency ms", actual, expected))

    # exp6a: exp2a pqz query at N=1e6, clustered P4, sigma=1%.
    exp2a = read_rows(exp2a_path)
    rows = [r for r in exp2a if timed_proof(r)
            and num(r.get("n")) == 1_000_000.0
            and abs(num(r.get("sigma")) - 0.01) < 1e-12
            and r.get("layout") == "clustered" and r.get("predicate") == "P4"
            and r.get("approach") == "pqz"]
    actual = median(rows, "time_ns") / 1e6
    expected = float(find_plotted(figure_rows("fig_exp6a"), "query",
                                  "Full")["median"])
    checks.append(("exp6a", "Full query ms", actual, expected))

    # exp6b: block-filtering O_j from the same two query medians.
    rows_full = [r for r in exp2a if timed_proof(r)
                 and num(r.get("n")) == 1_000_000.0
                 and abs(num(r.get("sigma")) - 0.01) < 1e-12
                 and r.get("layout") == "clustered"
                 and r.get("predicate") == "P4"
                 and r.get("approach") == "prot_full_scan"]
    t_full = median(rows, "time_ns")
    t_scan = median(rows_full, "time_ns")
    actual = (t_scan - t_full) / t_full * 100.0
    expected = float(find_plotted(figure_rows("fig_exp6b"), "O_pct",
                                  "w/o Block Filtering (query only)")["median"])
    checks.append(("exp6b", "w/o block filtering O_j %", actual, expected))

    # exp1: sigma1pct at N=1e6, time_ns -> ms.
    rows = [r for r in read_rows(exp1_path) if timed_proof(r)
            and r.get("series") == "sigma1pct"
            and num(r.get("n")) == 1_000_000.0]
    actual = median(rows, "time_ns") / 1e6
    expected = float(find_plotted(figure_rows("fig_exp1_baselines"),
                                  "query_time", "sigma1pct (pqz)",
                                  1000000)["median"])
    checks.append(("exp1", "sigma1pct N=1e6 query ms", actual, expected))

    # exp1 extra: Dong proof formula, s=3, c in {10, 50, 100}, time -> ms.
    for c in (10, 50, 100):
        rows = [r for r in read_rows(baseline_path)
                if r.get("phase") == "proof" and r.get("scheme") == "Dong et al."
                and r.get("status") == "full"
                and f"c={c};" in r.get("param_set", "")
                and "s=3;" in r.get("param_set", "")]
        actual = float(rows[0]["time_ns"]) / 1e6
        expected = float(find_plotted(
            figure_rows("fig_exp1_baselines"), "baseline_time",
            f"Dong et al. proof c={c} s=3")["median"])
        checks.append(("exp1", f"Dong proof c={c} s=3 ms", actual, expected))

    for figure, label, actual, expected in checks:
        ok = same(actual, expected)
        if not ok:
            failures += 1
        print(f"{figure} {'OK' if ok else 'MISMATCH'}  {label}: "
              f"raw={actual:.10g} csv={expected:.10g}")

    if failures:
        print(f"{failures} MISMATCH")
        return 1
    print(f"all {len(checks)} checks OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
