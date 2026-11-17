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
RES = os.path.join(REPO, "bench", "pqz-eval", "results")
OUT = os.path.join(HERE, "out")


def read_rows(path):
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        return list(csv.DictReader(fh))


def num(value):
    if value is None or value == "":
        return None
    return float(value)


def timed(row):
    return num(row.get("warmup")) == 0.0


def median(rows, field):
    return statistics.median(num(row[field]) for row in rows)


def figure_rows(name):
    return read_rows(os.path.join(OUT, f"{name}.csv"))


def find(rows, **conditions):
    for row in rows:
        if all(row.get(key) == value for key, value in conditions.items()):
            return row
    raise KeyError(f"no row matching {conditions}")


def same(actual, expected, rel=1e-6):
    return abs(actual - expected) <= rel * max(abs(expected), 1e-12)


def main():
    checks = []
    failures = 0

    exp1_path = os.path.join(RES, "full-1", "exp1", "exp1.csv")
    exp2a_path = os.path.join(RES, "full-1", "exp2a", "exp2a.csv")
    exp2b_path = os.path.join(RES, "full-1", "exp2b", "exp2b.csv")
    exp3a_path = os.path.join(RES, "full-1", "exp3a", "exp3a.csv")
    exp3b_path = os.path.join(RES, "full-2", "exp3b", "exp3b.csv")

    # exp1_full: sigma1pct at N=1e6, time_ns -> ms.
    rows = [r for r in read_rows(exp1_path) if timed(r)
            and r.get("series") == "sigma1pct"
            and num(r.get("n")) == 1_000_000.0]
    actual = median(rows, "time_ns") / 1e6
    expected = float(find(
        figure_rows("fig_exp1_full"),
        series="sigma1pct", n="1000000",
    )["median_ms"])
    checks.append(("exp1_full", "sigma1pct N=1e6 query ms", actual, expected))

    # exp2a_full: pqz, clustered, P4, median ms.
    rows = [r for r in read_rows(exp2a_path) if timed(r)
            and r.get("layout") == "clustered"
            and r.get("predicate") == "P4"
            and r.get("approach") == "pqz"]
    actual = median(rows, "time_ns") / 1e6
    expected = float(find(
        figure_rows("fig_exp2a_full"),
        record_type="group", layout="clustered", predicate="P4",
        approach="pqz",
    )["median_ms"])
    checks.append(("exp2a_full", "pqz clustered P4 query ms", actual, expected))

    # exp2b_full: pqz, clustered, sigma=1%, median ms.
    rows = [r for r in read_rows(exp2b_path) if timed(r)
            and r.get("layout") == "clustered"
            and r.get("approach") == "pqz"
            and abs(num(r.get("sigma")) - 0.01) < 1e-12]
    actual = median(rows, "time_ns") / 1e6
    expected = float(find(
        figure_rows("fig_exp2b_full"),
        panel="selectivity", approach="pqz", layout="clustered", x="1",
    )["median_ms"])
    checks.append(("exp2b_full", "pqz clustered sigma=1% query ms",
                   actual, expected))

    # exp3a_full: pqz, n_sel=1e5, SUM, median ms.
    rows = [r for r in read_rows(exp3a_path) if timed(r)
            and r.get("agg") == "SUM"
            and r.get("approach") == "pqz"
            and num(r.get("n_sel")) == 100_000.0]
    actual = median(rows, "time_ns") / 1e6
    expected = float(find(
        figure_rows("fig_exp3a_full"),
        record_type="group", agg="SUM", approach="pqz", n_sel="100000",
    )["median_ms"])
    checks.append(("exp3a_full", "pqz n_sel=1e5 SUM ms", actual, expected))

    # exp3b_full: SUM pqz bar, median ms.
    rows = [r for r in read_rows(exp3b_path) if timed(r)
            and num(r.get("n")) == 1_000_000.0
            and abs(num(r.get("sigma")) - 0.01) < 1e-12
            and r.get("agg") == "SUM"
            and r.get("approach") == "pqz"]
    actual = median(rows, "time_ns") / 1e6
    expected = float(find(
        figure_rows("fig_exp3b_full"),
        record_type="bar", agg="SUM", approach="pqz",
    )["median"])
    checks.append(("exp3b_full", "SUM pqz aggregation ms", actual, expected))

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
