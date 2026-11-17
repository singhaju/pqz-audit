"""Medians, minima and maxima of every cloud-w18 job (raw data unmodified), plus the alone-checks.

Usage: python3 -I summary_w18.py [--results DIR] [--out DIR]
  results: default env W18_RESULTS, else bench/pqz-eval/results/cloud-w18
  out:     default env W18_OUT,     else bench/pqz-eval/analysis/out-w18

Writes into out:
  summary_w18_<job>.csv       one row per configuration group (exp* csv jobs: as summary_w17.py;
                              baseline jobs: stage + params; ledger jobs: _exp5a/_exp5b/_exp5c;
                              proof jobs: group keys + medians of the numeric columns)
  summary_w18_jobs.csv        exit code, wall clock and peak RSS of every job (from exit_code.txt, time.txt)
  alonecheck_w18_<family>.csv S2 value against the S4 alone value (exp3c n=10000, dong, dart, dopiv),
                              diff % = (S2 - alone) / alone * 100; rule of CLOUD-PLAN-work18: > 10 % -> alone value is used
Timed rows only (warmup == 0 / kind == timed). Times in ms.
Refuses (exit 2) when a needed job or csv is missing, empty or failed. The alone-check jobs are optional:
a missing one is reported and skipped.
"""
import argparse
import csv
import os
import re
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import w18_common as W  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--results")
ap.add_argument("--out")
args = ap.parse_args()
R = W.Results(W.results_dir(args.results))
OUT = W.out_dir(args.out, os.path.join(W.HERE, "out-w18"))

KEYS = ["exp", "series", "n", "mb", "sigma", "layout", "predicate", "agg", "approach"]
EXP_JOBS = {  # job -> csv
    "exp2a": "exp2a.csv", "exp1": "exp1.csv", "exp1_construction": "exp1_construction.csv",
    "exp3d": "exp3d.csv", "exp2c": "exp2c.csv", "exp2b": "exp2b.csv", "exp2bd": "exp2bd.csv",
    "exp3a": "exp3a.csv", "exp3c": "exp3c.csv", "exp3b-r1": "exp3b.csv", "exp3b-r2": "exp3b.csv",
    "exp3ad": "exp3ad.csv", "exp1d": "exp1d.csv",
}
BASE_JOBS = ["lhcpm-full", "lhcpm",
             "dong-e1", "dong-e1-c10000", "dong-e4a", "dong-e4a-c100000", "dong-e4b",
             "dopiv-e1", "dopiv-lazy-e1", "dopiv-e4a", "dopiv-lazy-e4a", "dopiv-e4a-c100000",
             "dopiv-lazy-e4a-c100000", "dopiv-e4b", "dart-e1", "dart-e4a", "dart-e4b"]
LEDGER = ["ledger-with-tx-auth", "ledger-no-tx-auth"]
LEDGER_FILES = ["exp5a_latency_throughput.csv", "exp5b_governance.csv", "exp5c_bytes_per_epoch.csv"]
PROOF = {  # job -> (csv, group keys, numeric columns)
    "proofbench-full": ("raw.csv", ["experiment", "rel", "n_records", "depth", "q", "mode"],
                        ["trace_s", "prove_s", "verify_s", "total_verify_s", "proof_bytes", "prove_peak_rss_kb"]),
    "proofbench-ablation": ("raw.csv", ["experiment", "rel", "g_blocks", "mode", "n_records"],
                            ["trace_s", "prove_s", "verify_s", "proof_bytes", "prove_peak_rss_kb"]),
    "covermerkle-g2000": ("raw.csv", ["experiment", "rel", "g_blocks", "r_retained"],
                          ["trace_s", "prove_s", "verify_s", "proof_bytes", "prove_peak_rss_kb"]),
    "chunked-single": ("raw.csv", ["experiment", "rel", "m_records", "n_chunks"],
                       ["prove_total_s", "trace_total_s", "prove_only_total_s", "verify_total_s",
                        "proof_bytes_sum", "prove_peak_rss_kb_max_chunk"]),
}

required = [(j, c) for j, c in EXP_JOBS.items()] + [(j, "raw_runs.csv") for j in BASE_JOBS]
required = [(j, c) for j, c in required]
required += [(j, f) for j in LEDGER for f in LEDGER_FILES]
required += [(j, c) for j, (c, _, _) in PROOF.items()]
optional = [("ac-exp3c-n10000", "exp3c.csv"), ("ac-dong", "raw_runs.csv"), ("ac-dart", "raw_runs.csv"),
            ("ac-dopiv", "raw_runs.csv")]
ok_ac = R.preflight(required, optional)


def writecsv(name, header, rows):
    with open(os.path.join(OUT, name), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def fnum(x):
    return f"{x:.6g}"


# ---------------------------------------------------------------- exp* csv jobs
def exp_groups(rows):
    g = {}
    for r in rows:
        if not W.is_timed(r):
            continue
        g.setdefault(tuple(r[k] for k in KEYS), []).append(r)
    return g


def stats_ms(rs):
    m, lo, hi, n = W.S([float(r["time_ns"]) / 1e6 for r in rs])
    return n, m, lo, hi


EXP = {}
for job, c in EXP_JOBS.items():
    g = exp_groups(R.rd(job, c))
    if not g:
        sys.exit(f"REFUSING: {job}/{c} has no timed rows")
    EXP[job] = g
    rows = []
    for k, rs in g.items():
        n, med, lo, hi = stats_ms(rs)
        r0 = rs[0]
        rows.append(list(k) + [n, fnum(med), fnum(lo), fnum(hi), r0["n_blocks"], r0["n_retained_blocks"],
                               r0["n_cand"], r0["n_sel"], r0["bytes"]])
    writecsv(f"summary_w18_{job}.csv",
             KEYS + ["runs", "median_ms", "min_ms", "max_ms", "n_blocks", "n_retained_blocks", "n_cand", "n_sel", "bytes"],
             rows)

# ---------------------------------------------------------------- baseline jobs
BASE = {}
for job in BASE_JOBS:
    g = {}
    for r in R.rd(job, "raw_runs.csv"):
        g.setdefault((r["baseline"], r["stage"], r["params"]), []).append(float(r["ms"]))
    BASE[job] = g
    rows = []
    for (b, stg, prm), v in g.items():
        m, lo, hi, n = W.S(v)
        rows.append([b, stg, prm, n, fnum(m), fnum(lo), fnum(hi)])
    writecsv(f"summary_w18_{job}.csv", ["baseline", "stage", "params", "runs", "median_ms", "min_ms", "max_ms"], rows)

# ---------------------------------------------------------------- ledger jobs
for job in LEDGER:
    a = [r for r in R.rd(job, "exp5a_latency_throughput.csv") if W.is_timed(r)]
    g = {}
    for r in a:
        g.setdefault((r["system"], r["workload"], int(r["q"])), []).append(r)
    rows = []
    for (sy, wl, q), rs in sorted(g.items()):
        lat = W.S([float(r["lat_p50_ns"]) / 1e6 for r in rs])
        thr = W.S([float(r["throughput_tx_per_s"]) for r in rs])
        rows.append([sy, wl, q, lat[3], fnum(lat[0]), fnum(lat[1]), fnum(lat[2]), fnum(thr[0]), fnum(thr[1]), fnum(thr[2])])
    writecsv(f"summary_w18_{job}_exp5a.csv",
             ["system", "workload", "q", "runs", "lat_p50_median_ms", "lat_p50_min_ms", "lat_p50_max_ms",
              "thr_median_tx_s", "thr_min_tx_s", "thr_max_tx_s"], rows)
    g = {}
    for r in R.rd(job, "exp5b_governance.csv"):
        if W.is_timed(r):
            g.setdefault(r["op"], []).append(float(r["op_latency_ns"]) / 1e6)
    writecsv(f"summary_w18_{job}_exp5b.csv", ["op", "runs", "median_ms", "min_ms", "max_ms"],
             [[k, len(v), fnum(statistics.median(v)), fnum(min(v)), fnum(max(v))] for k, v in sorted(g.items())])
    g = {}
    for r in R.rd(job, "exp5c_bytes_per_epoch.csv"):
        if W.is_timed(r):
            g.setdefault((r["system"], r["N"], r["method"]), set()).add(r["bytes_total"])
    writecsv(f"summary_w18_{job}_exp5c.csv", ["system", "N", "method", "distinct_bytes_total_values"],
             [list(k) + [";".join(sorted(v))] for k, v in sorted(g.items())])

# ---------------------------------------------------------------- proof jobs
for job, (c, gk, cols) in PROOF.items():
    g = {}
    for r in R.rd(job, c):
        if not W.is_timed(r):
            continue
        g.setdefault(tuple(r.get(k, "") for k in gk), []).append(r)
    if not g:
        sys.exit(f"REFUSING: {job}/{c} has no timed rows")
    rows = []
    for k, rs in sorted(g.items()):
        row = list(k) + [len(rs)]
        for col in cols:
            vals = [float(r[col]) for r in rs if r.get(col, "") != ""]
            row += [fnum(statistics.median(vals)), fnum(min(vals)), fnum(max(vals))] if vals else ["", "", ""]
        rows.append(row)
    hdr = gk + ["runs"] + [f"{col}_{s}" for col in cols for s in ("median", "min", "max")]
    writecsv(f"summary_w18_{job}.csv", hdr, rows)


# ---------------------------------------------------------------- jobs table (exit code, wall, RSS)
def time_txt(path):
    wall = rss = ""
    if not os.path.isfile(path):
        return wall, rss
    for ln in open(path, errors="replace"):
        m = re.search(r"Elapsed \(wall clock\) time.*: (.*)$", ln)
        if m:
            t = m.group(1).strip().split(":")
            try:
                sec = 0.0
                for x in t:
                    sec = sec * 60 + float(x)
                wall = f"{sec:.2f}"
            except ValueError:
                wall = ""
        m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", ln)
        if m:
            rss = m.group(1)
    return wall, rss


jobs_all = list(EXP_JOBS) + BASE_JOBS + LEDGER + list(PROOF) + sorted(ok_ac)
rows = []
for j in jobs_all:
    wall, rss = time_txt(R.p(j, "time.txt"))
    rows.append([j, open(R.p(j, "exit_code.txt")).read().strip(), wall, rss])
writecsv("summary_w18_jobs.csv", ["job", "exit_code", "wall_s", "max_rss_kb"], rows)

# ---------------------------------------------------------------- alone-checks (logic in w18_common.alone_compare)
status = []
for family, (kcols, arows) in W.alone_compare(R, ok_ac).items():
    writecsv(f"alonecheck_w18_{family}.csv",
             kcols + ["s2_job", "s2_runs", "s2_median_ms", "alone_runs", "alone_median_ms", "diff_pct", "over_10pct"],
             [r[:len(kcols)] + [r[len(kcols)], r[len(kcols) + 1], fnum(r[len(kcols) + 2]), r[len(kcols) + 3],
                                fnum(r[len(kcols) + 4]), round(r[-2], 2), r[-1]] for r in arows])
    worst = max(abs(r[-2]) for r in arows)
    big = [r for r in arows if r[-1]]
    print(f"alone-check {family}: cells compared {len(arows)}, largest |diff| {worst:.2f}%, "
          f"cells with |diff| > {W.ALONE_RULE_PCT:g}%: {len(big)}")
    for r in sorted(big, key=lambda x: -abs(x[-2])):
        print("   ", r[:len(kcols)], f"S2={r[len(kcols) + 2]:.6g} alone={r[len(kcols) + 4]:.6g} diff={r[-2]:.2f}%")
    if big:
        print(f"    RULE (CLOUD-PLAN-work18, rule 3): > {W.ALONE_RULE_PCT:g}% -> the alone value is used for the "
              f"family {family} in the paper, and the text says so")
    status.append(family)

print()
print("summary_w18 done:", len(os.listdir(OUT)), "files in", OUT)
if not status:
    print("NOTE: no alone-check was available; no alonecheck_w18_*.csv written")
