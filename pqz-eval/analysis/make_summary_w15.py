"""Write results/cloud-w15/SUMMARY-w15.md from the raw CSVs of the cloud-w15 run (numbers only)."""

from __future__ import annotations

import csv
import os

import numpy as np

import common
import w15_common as w

OUT = os.path.join(w.CLOUD, "SUMMARY-w15.md")
FIG_DIR = w.OUT_DEFAULT


def g(x):
    """4 significant digits, no exponent."""
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return "-"
    if isinstance(x, str):
        return x
    s = f"{float(x):.4g}"
    if "e" in s:
        s = f"{float(s):f}".rstrip("0").rstrip(".")
    return s


def table(header, body):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for row in body:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return lines


def read_rows(path):
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def triple(values, scale=1.0):
    values = [v * scale for v in values if v is not None]
    if not values:
        return ["-", "-", "-"]
    a = np.asarray(values)
    return [g(np.median(a)), g(a.min()), g(a.max())]


def uniq(values):
    vals = sorted({v for v in values if v not in (None, "")})
    return "/".join(vals) if vals else "-"


def env_lines(path, keys):
    out = []
    if not os.path.isfile(path):
        return [f"{path}: MISSING"]
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if any(line.startswith(k) for k in keys):
                out.append(line.strip())
    return out


def main():
    md = []
    md.append("# SUMMARY-w15 (numbers only)")
    md.append("")
    md.append("All times in ms unless stated. Median / min / max over timed runs (warm-up rows excluded). "
              "Values rounded to 4 significant digits. n = number of timed runs. `-` = not applicable / empty.")
    md.append("")
    md.append("## 0. Environment (filtered lines of the env files)")
    for p, keys in ((os.path.join(w.CLOUD, "exp1d", "env.txt"), ("cpu", "logical_cores", "kernel", "MemTotal", "rustc", "mode")),
                    (os.path.join(w.CLOUD, "proof-full", "env.txt"), ("cpu", "logical_cores", "kernel", "rustc", "winterfell", "mode", "block size", "threads")),
                    (os.path.join(w.CLOUD, "out2", "machine2.txt"), ("date_utc", "rustc")),
                    (os.path.join(w.CLOUD, "machine.txt"), ("cpu", "logical_cores", "kernel", "date_utc", "rustc"))):
        md.append(f"- `{os.path.relpath(p, w.CLOUD)}`: " + ("; ".join(env_lines(p, keys)) or "(no matching lines)"))
    md.append("")

    # ---------------- (a) Exp 1
    md.append("## (a) PQZ-Audit Exp 1, run 1 (`exp1d/exp1d.csv`), time in ms")
    rows = [r for r in read_rows(w.EXP1_CSV)]
    timed = [r for r in rows if r["warmup"] == "0"]
    cell_keys = ("series", "n", "sigma", "predicate", "agg", "layout", "approach")
    cells = {}
    for r in timed:
        cells.setdefault(tuple(r[k] for k in cell_keys), []).append(float(r["time_ns"]) / 1e6)
    md.append(f"warm-up rows excluded: {len(rows) - len(timed)} of {len(rows)} rows.")
    md.append("")
    body = []
    for key in sorted(cells, key=lambda k: (k[0], int(k[1]))):
        v = cells[key]
        body.append(list(key) + [len(v)] + triple(v))
    md += table(list(cell_keys) + ["n runs", "median", "min", "max"], body)
    md.append("")
    md.append("### Repeat (`out2/exp1d2/exp1d.csv`): max |median_repeat / median_run1 - 1| per series")
    rep = [r for r in read_rows(w.EXP1_REPEAT_CSV) if r["warmup"] == "0"]
    cells2 = {}
    for r in rep:
        cells2.setdefault(tuple(r[k] for k in cell_keys), []).append(float(r["time_ns"]) / 1e6)
    body = []
    for series in sorted({k[0] for k in cells}):
        dev = []
        for key, v in cells.items():
            if key[0] != series:
                continue
            if key not in cells2:
                dev.append((None, key))
                continue
            ratio = np.median(cells2[key]) / np.median(v)
            dev.append((abs(ratio - 1), key))
        missing = [k for d, k in dev if d is None]
        valid = [(d, k) for d, k in dev if d is not None]
        dmax, kmax = max(valid, key=lambda t: t[0])
        body.append([series, len(valid), g(dmax), f"N={kmax[1]}", f"{len(missing)} missing cells"])
    md += table(["series", "cells compared", "max abs(ratio-1)", "at", "note"], body)
    md.append("")
    md.append("### Log-log slope of the medians vs N")
    md.append("Method: ordinary least squares of log10(median ms) on log10(N) over all N points of the series "
              "(`common.loglog_fit`, np.polyfit degree 1), run 1. Also given: slope over the first and last 3 N points.")
    md.append("")
    body = []
    for series in ("sigma1pct", "fixed_nq1000"):
        pts = sorted((int(k[1]), float(np.median(v))) for k, v in cells.items() if k[0] == series)
        fit = common.loglog_fit([p[0] for p in pts], [p[1] for p in pts])
        lo = common.loglog_fit([p[0] for p in pts[:3]], [p[1] for p in pts[:3]])
        hi = common.loglog_fit([p[0] for p in pts[-3:]], [p[1] for p in pts[-3:]])
        body.append([series, len(pts), g(fit["slope"]), g(fit["r2"]), g(lo["slope"]), g(hi["slope"])])
    md += table(["series", "points", "slope (all)", "R^2", "slope (first 3 N)", "slope (last 3 N)"], body)
    md.append("")

    # ---------------- (b) proof-full
    md.append("## (b) proof-full (`proof-full/raw.csv`), warm-up rows excluded")
    praw = read_rows(w.PROOF_CSV)
    ptimed = [r for r in praw if r["warmup"] == "0"]
    md.append(f"rows: {len(praw)} total, {len(praw) - len(ptimed)} warm-up, {len(ptimed)} timed.")
    pk = ("experiment", "rel", "n_records", "depth", "q", "mode")
    groups = {}
    for r in ptimed:
        groups.setdefault(tuple(r[k] for k in pk), []).append(r)
    short = {k: len(v) for k, v in groups.items() if len(v) < 30}
    md.append("row sets with fewer than 30 timed runs: " + (str(short) if short else "none (every row set has 30 timed runs)") + ".")
    md.append("")
    header = ["exp", "rel", "N", "depth", "q", "mode", "n",
              "prove med", "prove min", "prove max",
              "verify med", "verify min", "verify max",
              "total_verify med", "total_verify min", "total_verify max",
              "per-request (total/q) med", "proof_bytes", "prove_peak_rss_kb med", "verify_peak_rss_kb med",
              "conj_bits", "udr_bits", "ldr_bits", "trace_rows", "trace_s med"]

    def prow(key, rs):
        col = lambda c: [num(r[c]) for r in rs]
        ms = lambda c: triple(col(c), 1000.0)
        tv = [v for v in col("total_verify_s") if v is not None]
        q = num(key[4])
        per = g(np.median(tv) * 1000.0 / q) if (tv and q) else "-"
        rss = [v for v in col("prove_peak_rss_kb") if v is not None]
        vrss = [v for v in col("verify_peak_rss_kb") if v is not None]
        ts = [v for v in col("trace_s") if v is not None]
        return (list(key) + [len(rs)] + ms("prove_s") + ms("verify_s") + ms("total_verify_s") +
                [per, uniq([r["proof_bytes"] for r in rs]),
                 g(np.median(rss)) if rss else "-", g(np.median(vrss)) if vrss else "-",
                 uniq([r["conj_bits"] for r in rs]), uniq([r["udr_bits"] for r in rs]),
                 uniq([r["ldr_bits"] for r in rs]), uniq([r["trace_rows"] for r in rs]),
                 g(np.median(ts) * 1000.0) if ts else "-"])

    def skey(k):
        f = lambda s: int(s) if s not in ("", None) else -1
        return (k[0], k[1], f(k[2]), f(k[3]), f(k[4]), k[5])

    md.append("Units: prove, verify, total_verify, trace_s in ms; proof_bytes in bytes (all distinct values shown, `/`-separated); "
              "rss in kB.")
    md.append("")
    for name, sel in (("b1. experiment=scale (prove vs workload; auth depth 10 and 20 are the rel=auth rows)", "scale"),
                      ("b2. experiment=q (q sweep; total_verify = verification of q proofs, mode distinct vs same)", "q")):
        md.append(f"### {name}")
        body = [prow(k, groups[k]) for k in sorted(groups, key=skey) if k[0] == sel]
        md += table(header, body)
        md.append("")
    md.append("### b3. Other checks")
    md.append("- experiments present: " + ", ".join(sorted({r["experiment"] for r in ptimed})) + ".")
    md.append("- rows with n_records = 1000000: " + str(sum(1 for r in ptimed if r["n_records"] == "1000000")) + ".")
    md.append("- coverM rows: " + str(sum(1 for r in ptimed if "cover" in r["experiment"].lower() or "cover" in r["rel"].lower())) +
              " (no coverM experiment/rel in this file).")
    md.append("- hwm_reset_ok values among timed rows: " + uniq([r["hwm_reset_ok"] for r in ptimed]) + ".")
    md.append("- loadavg1 (timed rows): min " + g(min(num(r["loadavg1"]) for r in ptimed)) +
              ", max " + g(max(num(r["loadavg1"]) for r in ptimed)) + ".")
    fail = os.path.join(w.CLOUD, "proof-full", "failures.txt")
    md.append("- `proof-full/failures.txt`: " + (f"{os.path.getsize(fail)} bytes" if os.path.isfile(fail) else "MISSING") + ".")
    md.append("")

    # ---------------- (c) baselines
    md.append("## (c) Baselines (`out2/<name>/raw_runs.csv`, timed runs only), ms")
    for name in w.BASELINE_DIRS:
        md.append(f"### c-{name}")
        groups_b = w.load_baseline(name)
        body = []
        for (stage, params) in sorted(groups_b):
            v = groups_b[(stage, params)]
            body.append([stage, params, len(v)] + triple(v))
        md += table(["stage", "params", "n runs", "median", "min", "max"], body)
        md.append("")

    # ---------------- (d) figure lines
    md.append("## (d) Values behind the lines of each figure (read back from `journal2/figures/results-w15/fig_*_w15.csv`)")
    for fig in ("fig_exp1_w15", "fig_exp4a_w15", "fig_exp4b_w15"):
        p = os.path.join(FIG_DIR, fig + ".csv")
        md.append(f"### {fig}")
        if not os.path.isfile(p):
            md.append(f"MISSING: {p}")
            continue
        body = []
        for r in read_rows(p):
            body.append([r["series"], r["x"] or "-", r["n_runs"], g(num(r["median"])),
                         g(num(r["min"])) if r["min"] else "-", g(num(r["max"])) if r["max"] else "-", r["unit"],
                         r["note"] if r["metric"].startswith(("baseline", "prove_s")) and not r["x"] else ""])
        md += table(["series", "x", "n runs", "median", "min", "max", "unit", "params used (flat lines)"], body)
        md.append("")

    with open(OUT, "w", encoding="utf-8") as handle:
        handle.write("\n".join(md) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
