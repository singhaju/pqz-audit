"""Print every number the paper's evaluation section needs, from raw files only.

Inputs are the raw CSVs written by the experiment binaries.  Nothing is
estimated: each output row carries the source file and the row filter that
produced it.  Missing data is the literal string MISSING, never a guess.

Usage (from bench/pqz-eval/analysis, with PYTHONPATH=.):
    /path/to/.venv-bench/bin/python paper_numbers.py
    /path/to/.venv-bench/bin/python paper_numbers.py --self-check
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys

import common


MISSING = "MISSING"
REPO_ROOT = os.path.dirname(os.path.dirname(common.BASE_DIR))

EVAL_FILES = {
    "exp1": "results/full-1/exp1/exp1.csv",
    "exp2a": "results/full-1/exp2a/exp2a.csv",
    "exp2b": "results/full-1/exp2b/exp2b.csv",
    "exp2c": "results/full-1/exp2c/exp2c.csv",
    "exp3a": "results/full-1/exp3a/exp3a.csv",
    "exp3c": "results/full-1/exp3c/exp3c.csv",
    "exp3b_v2": "results/full-2/exp3b/exp3b.csv",
    "exp3d_v2": "results/full-2/exp3d/exp3d.csv",
    "exp1_construction": "results/full-1/exp1_construction/exp1_construction.csv",
}

PROOF_FULL2 = os.path.join("..", "pqz-proof", "results", "full-2", "raw.csv")
PROOF_ABLATION = os.path.join("..", "pqz-proof", "results", "ablation-1", "raw.csv")
LEDGER_DIR = os.path.join("..", "pqz-ledger", "results", "full-1")
# WORK7 (entry 372): baseline rows now come from results-papers-run2 (was "results": s=10, older unit costs)
BASELINE_DIR = os.path.join("..", "pqz-baselines", "results-papers-run2")
BASELINE_COSTS_FILE = "baseline_costs.csv"          # WORK7 (entry 372): Dong et al. and DOPIV (paper formulas)
BASELINE_PROF_FILE = "baseline_costs_profbigo.csv"  # WORK7 (entry 372): DART, DOPIV audit, L-HCPM (each row has source and status)
BASELINE_COSTS_SCHEMES = ("Dong et al.", "DOPIV")   # WORK7 (entry 372): DART/L-HCPM rows of baseline_costs.csv are placeholders, superseded by the profbigo file
REJECT_FILE = os.path.join(LEDGER_DIR, "reject-1000.txt")

SECTION_TITLES = {
    1: "Run counts actually used",
    2: "Ranges actually used",
    3: "Experiment 1: query scalability",
    4: "Experiment 2: private predicate execution",
    5: "Experiment 3: private aggregation",
    6: "Experiment 4: proof generation and verification",
    7: "Experiment 5: blockchain overhead",
    8: "Experiment 6: ablation and rejection",
    9: "Construction costs and storage",
}

TABLE_TITLES = {
    "1-runs-eval": "Timed and warm-up runs per approach (eval CSVs)",
    "1-runs-proof": "Timed and warm-up runs per group (proof CSVs)",
    "1-runs-ledger": "Timed and warm-up runs per group (ledger CSVs)",
    "2-ranges": "Distinct parameter values per experiment (warm-up rows excluded)",
    "3-exp1-query": "Query time vs N, per series (approach=pqz)",
    "3-exp1-nqn": "N_Q/N in experiment 1 (N_Q := n_cand)",
    # WORK7 (entry 372): title now covers the professor-table rows and the values reported by the papers
    "3-baseline-costs": "Baseline costs (results-papers-run2): authors' formulas or professor table with our unit costs, or values reported by the papers; not measured",
    "3-baseline-units": "Baseline primitive unit costs (raw_unit_runs medians)",
    "4-exp2a": "Predicate x approach at sigma=0.01 and N=1e6, per layout",
    "4-exp2b": "Selectivity sweep, per layout",
    "4-exp2c": "Block-size sweep, per layout",
    "4-eta": "Retained-block fraction eta_Q = N_Q/N (N_Q := n_cand)",
    "5-exp3a-sum": "SUM aggregation vs selected fraction (exp3a)",
    "5-exp3b-ops": "SUM and AVG per approach at N=1e6, sigma=0.01 (exp3b v2)",
    "5-count-raw": "COUNT raw nanoseconds (timer resolution; no R_HE ratio)",
    "5-rhe": "R_HE = 1 - T_pqz/T_full_he (SUM and AVG only)",
    "6-proof-scale": "Prove/verify time, proof size and peak RSS vs workload",
    "6-proof-largest": "Largest-workload proof numbers",
    "6-proof-q": "Verification cost for q=1 and q=200 audit requests",
    "7-exp5c-bytes": "On-chain bytes per epoch, with and without tx signatures",
    "7-exp5a": "Transaction latency and throughput per variant, with and without tx signatures",
    "7-exp5b": "Governance operation latency, with and without tx signatures",
    "7-threshold": "Threshold-signature/sharing operations, with and without tx signatures",
    "8-abl-blockfilter": "Ablation: w/o Block Filtering (Protected Full Scan / PQZ)",
    "8-abl-selectivehe": "Ablation: w/o Selective HE (Full-Domain HE / PQZ)",
    "8-abl-batchedrc": "Ablation: w/o Batched RC, per configuration",
    "8-abl-batchedrc-ratio": "Ablation: w/o Batched RC, per_block/batched ratio",
    "8-reject": "Rejection results (production defences, 1000 trials per attack)",
    "9-construction-times": "Per-record construction cost (single run, no warm-up)",
    "9-storage": "Storage per record and per block (single run)",
}


# ------------------------------------------------------------------ helpers

def source_path(relpath):
    return os.path.relpath(os.path.join(common.BASE_DIR, relpath), REPO_ROOT)


def load_all(relpath):
    """Read a CSV without dropping anything; coerce numbers with common._to_number."""
    path = os.path.join(common.BASE_DIR, relpath)
    if not os.path.isfile(path):
        sys.exit(f"refusing to continue: input CSV not found: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return [
            {key: common._to_number(value) for key, value in row.items()}
            for row in csv.DictReader(handle)
        ]


def load_timed_eval(relpath):
    rows, _ = common.load_csv(
        os.path.join(common.BASE_DIR, relpath), required=("warmup", "time_ns")
    )
    return rows


def stats(rows, keys, value):
    return common.group_stats(rows, keys, value=value)


def is_timed_eval(row):
    return row.get("warmup") in (0, None)


def fmt_value(value, unit):
    if value == MISSING:
        return MISSING
    if isinstance(value, str):
        return value.replace("|", "\\|")
    if value is None:
        return MISSING
    if unit == "bytes" or unit.startswith("bytes/"):
        return f"{value:,.0f}"
    if unit == "ms":
        return f"{value:.4f}"
    if unit == "ns":
        return f"{value:.1f}"
    if unit == "ratio":
        return f"{value:.4f}"
    if unit == "MiB":
        return f"{value:.2f}"
    if unit == "KiB":
        return f"{value:,.0f}"
    if unit == "tx/s":
        return f"{value:.2f}"
    if unit in ("%", "percent"):
        return f"{value:.4f}"
    if unit == "runs":
        return f"{value:g}"
    return f"{value:.6g}"


def add_value(rows, section, table, label, metric, value, unit, source, filt,
              note="", n_runs=None, vmin=None, vmax=None):
    if value is None:
        value = MISSING
    rows.append({
        "section": section, "table": table, "row": label, "metric": metric,
        "value": value, "unit": unit,
        "n_runs": "" if n_runs is None else n_runs,
        "min": "" if vmin is None else vmin,
        "max": "" if vmax is None else vmax,
        "source": source, "filter": filt, "note": note,
    })


def add_stat(rows, section, table, label, metric, entry, unit, source, filt,
             note="", factor=1.0):
    if entry is None:
        add_value(rows, section, table, label, metric, MISSING, unit, source, filt,
                  note=note or "no rows match the filter")
        return
    add_value(
        rows, section, table, label, metric,
        entry["median"] * factor, unit, source, filt, note=note,
        n_runs=entry["n"], vmin=entry["min"] * factor, vmax=entry["max"] * factor,
    )


def distinct_string(values):
    cleaned = [value for value in values if value is not None and value != ""]
    return ", ".join(str(value) for value in sorted(set(cleaned), key=common.sort_key))


def ratio(num, den):
    if num is None or den is None or den == 0:
        return None
    return num / den


# ------------------------------------------------------------------ section 1

def section_run_counts(rows):
    for name, relpath in EVAL_FILES.items():
        raw = load_all(relpath)
        src = source_path(relpath)
        for approach in sorted({str(row.get("approach")) for row in raw}):
            members = [row for row in raw if str(row.get("approach")) == approach]
            timed = [row for row in members if row.get("warmup") in (0, None)]
            warm = [row for row in members if row.get("warmup") == 1]
            configs = {
                (row.get("series"), row.get("n"), row.get("mb"), row.get("sigma"),
                 row.get("layout"), row.get("predicate"), row.get("agg"))
                for row in timed
            }
            label = f"{name}:{approach}"
            add_value(rows, 1, "1-runs-eval", label, "timed_runs_total", len(timed),
                      "runs", src, f"warmup=0; approach={approach}",
                      note=f"{len(configs)} distinct configurations")
            add_value(rows, 1, "1-runs-eval", label, "warmup_runs_total", len(warm),
                      "runs", src, f"warmup=1; approach={approach}")
            per_timed = len(timed) / len(configs) if configs else None
            per_warm = len(warm) / len(configs) if configs else None
            add_value(rows, 1, "1-runs-eval", label, "timed_runs_per_config", per_timed,
                      "runs", src, f"warmup=0; approach={approach}; divided by distinct configurations")
            add_value(rows, 1, "1-runs-eval", label, "warmup_runs_per_config", per_warm,
                      "runs", src, f"warmup=1; approach={approach}; divided by distinct configurations")

    for name, relpath in (("proof-full-2", PROOF_FULL2), ("proof-ablation-1", PROOF_ABLATION)):
        raw = load_all(relpath)
        src = source_path(relpath)
        groups = sorted({str(row.get("rel")) for row in raw})
        if name == "proof-ablation-1":
            groups = sorted({str(row.get("mode")) for row in raw})
            key_name = "mode"
        else:
            key_name = "rel"
        for group in groups:
            members = [row for row in raw if str(row.get(key_name)) == group]
            timed = [row for row in members if row.get("warmup") == 0]
            warm = [row for row in members if row.get("warmup") == 1]
            configs = {
                (row.get("experiment"), row.get("rel"), row.get("n_records"),
                 row.get("depth"), row.get("q"), row.get("mode"))
                for row in timed
            }
            label = f"{name}:{group}"
            add_value(rows, 1, "1-runs-proof", label, "timed_runs_total", len(timed),
                      "runs", src, f"warmup=0; {key_name}={group}",
                      note=f"{len(configs)} distinct configurations")
            add_value(rows, 1, "1-runs-proof", label, "warmup_runs_total", len(warm),
                      "runs", src, f"warmup=1; {key_name}={group}")
            add_value(rows, 1, "1-runs-proof", label, "timed_runs_per_config",
                      len(timed) / len(configs) if configs else None, "runs", src,
                      f"warmup=0; {key_name}={group}; divided by distinct configurations")
            add_value(rows, 1, "1-runs-proof", label, "warmup_runs_per_config",
                      len(warm) / len(configs) if configs else None, "runs", src,
                      f"warmup=1; {key_name}={group}; divided by distinct configurations")

    ledger_files = {
        "exp5a": "exp5a_latency_throughput.csv",
        "exp5b": "exp5b_governance.csv",
        "exp5c": "exp5c_bytes_per_epoch.csv",
        "threshold": "threshold.csv",
    }
    for variant in ("with-tx-auth", "no-tx-auth"):
        for name, filename in ledger_files.items():
            relpath = os.path.join(LEDGER_DIR, variant, filename)
            raw = load_all(relpath)
            src = source_path(relpath)
            timed = [row for row in raw if str(row.get("kind")) == "timed"]
            warm = [row for row in raw if str(row.get("kind")) == "warmup"]
            if name == "threshold":
                keys = ("domain", "variant", "t", "n", "op", "inner_reps")
            elif name == "exp5a":
                keys = ("system", "workload", "q")
            elif name == "exp5b":
                keys = ("op",)
            else:
                keys = ("system", "N")
            configs = {tuple(row.get(key) for key in keys) for row in timed}
            label = f"{variant}:{name}"
            add_value(rows, 1, "1-runs-ledger", label, "timed_runs_total", len(timed),
                      "runs", src, "kind=timed",
                      note=f"{len(configs)} distinct configurations")
            add_value(rows, 1, "1-runs-ledger", label, "warmup_runs_total", len(warm),
                      "runs", src, "kind=warmup")
            add_value(rows, 1, "1-runs-ledger", label, "timed_runs_per_config",
                      len(timed) / len(configs) if configs else None, "runs", src,
                      "kind=timed; divided by distinct configurations")
            add_value(rows, 1, "1-runs-ledger", label, "warmup_runs_per_config",
                      len(warm) / len(configs) if configs else None, "runs", src,
                      "kind=warmup; divided by distinct configurations")


# ------------------------------------------------------------------ section 2

def section_ranges(rows):
    for name, relpath in EVAL_FILES.items():
        timed = load_timed_eval(relpath)
        src = source_path(relpath)
        filt = "warmup=0 rows, all series and approaches"
        add_value(rows, 2, "2-ranges", name, "N_values", distinct_string(r.get("n") for r in timed),
                  "", src, filt)
        add_value(rows, 2, "2-ranges", name, "m_B_values", distinct_string(r.get("mb") for r in timed),
                  "", src, filt)
        sigmas = [r.get("sigma") for r in timed]
        add_value(rows, 2, "2-ranges", name, "selectivity_sigma_values", distinct_string(sigmas),
                  "", src, filt, note="sigma is the result-selectivity fraction (0.0010 = 0.1%)")
        add_value(rows, 2, "2-ranges", name, "predicates", distinct_string(r.get("predicate") for r in timed),
                  "", src, filt)
        add_value(rows, 2, "2-ranges", name, "layouts", distinct_string(r.get("layout") for r in timed),
                  "", src, filt)
        add_value(rows, 2, "2-ranges", name, "aggregates", distinct_string(r.get("agg") for r in timed),
                  "", src, filt)


# ------------------------------------------------------------------ section 3

def section_exp1(rows):
    timed = load_timed_eval(EVAL_FILES["exp1"])
    src = source_path(EVAL_FILES["exp1"])
    time_stats = stats(timed, ("series", "n"), "time_ns")
    nq_stats = stats(timed, ("series", "n"), "n_cand")
    for series in sorted({str(row.get("series")) for row in timed}):
        for n in sorted({row.get("n") for row in timed if row.get("n") is not None}):
            key = (series, n)
            entry = time_stats.get(key)
            add_stat(rows, 3, "3-exp1-query", f"{series}:N={n}", "query_time_ms", entry,
                     "ms", src, f"warmup=0; series={series}; n={n}; approach=pqz",
                     factor=1.0 / common.TIME_DIVISOR_NS)
            n_cand = nq_stats.get(key)
            value = ratio(n_cand["median"], n) if n_cand is not None else None
            add_value(rows, 3, "3-exp1-nqn", f"{series}:N={n}", "N_Q/N", value, "ratio",
                      src, f"warmup=0; series={series}; n={n}; median(n_cand)/N",
                      note="N_Q := n_cand (records requiring exact evaluation)",
                      n_runs=None if n_cand is None else n_cand["n"])
    add_value(rows, 3, "3-exp1-query", "baseline approaches", "query_time_vs_N",
              MISSING, "", src, "approach != pqz",
              note="exp1.csv contains only approach=pqz; the paper's baseline references are "
                   "model-derived in table 3-baseline-costs, not measured at each N")

    # WORK7 (entry 372): baseline rows from the two run2 files. Same row label, metric, unit and
    # filter layout as before; the note now carries status, source, formula and the file's own note.
    def baseline_note(item, keys):
        parts = [f"{key}={item.get(key)}" for key in keys if item.get(key) not in (None, "")]
        if item.get("shape_only") not in (0, False, None, "0", "false"):
            parts.append("shape_only")
        return "; ".join(parts)

    # WORK7 (entry 372): baseline_costs.csv, Dong et al. and DOPIV only
    base = load_all(os.path.join(BASELINE_DIR, BASELINE_COSTS_FILE))
    base_src = source_path(os.path.join(BASELINE_DIR, BASELINE_COSTS_FILE))
    for item in base:
        if item.get("scheme") not in BASELINE_COSTS_SCHEMES:
            continue
        label = f"{item.get('scheme')}:{item.get('phase')}:{item.get('param_set')}"
        value = item.get("time_ns")
        note = baseline_note(item, ("status", "source", "formula_text", "unit_costs_used",
                                    "label", "note"))
        add_value(rows, 3, "3-baseline-costs", label, "baseline_time_ms",
                  None if not isinstance(value, (int, float)) else value / common.TIME_DIVISOR_NS,
                  "ms", base_src, f"scheme={item.get('scheme')}; phase={item.get('phase')}; "
                  f"param_set={item.get('param_set')}", note=note,
                  n_runs=None if not isinstance(value, (int, float)) else 1)

    # WORK7 (entry 372): baseline_costs_profbigo.csv, DART, DOPIV audit and L-HCPM; status and source
    # text are copied from the file. n_runs stays blank for values the papers report (nothing was run).
    prof = load_all(os.path.join(BASELINE_DIR, BASELINE_PROF_FILE))
    prof_src = source_path(os.path.join(BASELINE_DIR, BASELINE_PROF_FILE))
    for item in prof:
        label = f"{item.get('scheme')}:{item.get('phase')}:{item.get('param_set')}"
        value = item.get("time_ns")
        note = baseline_note(item, ("status", "source", "formula_text", "values_used", "note"))
        numeric = isinstance(value, (int, float))
        add_value(rows, 3, "3-baseline-costs", label, "baseline_time_ms",
                  None if not numeric else value / common.TIME_DIVISOR_NS,
                  "ms", prof_src, f"scheme={item.get('scheme')}; phase={item.get('phase')}; "
                  f"param_set={item.get('param_set')}", note=note,
                  n_runs=1 if numeric and item.get("status") != "reported" else None)

    units = load_all(os.path.join(BASELINE_DIR, "unit_costs.csv"))
    unit_src = source_path(os.path.join(BASELINE_DIR, "unit_costs.csv"))
    for item in units:
        add_value(rows, 3, "3-baseline-units", str(item.get("unit")), "unit_median_ns",
                  item.get("median_ns"), "ns", unit_src, f"unit={item.get('unit')}",
                  note=str(item.get("description")), n_runs=item.get("runs"),
                  vmin=item.get("min_ns"), vmax=item.get("max_ns"))


# ------------------------------------------------------------------ section 4

def section_exp2(rows):
    for name, relpath in (("exp2a", EVAL_FILES["exp2a"]),
                          ("exp2b", EVAL_FILES["exp2b"]),
                          ("exp2c", EVAL_FILES["exp2c"])):
        timed = load_timed_eval(relpath)
        src = source_path(relpath)
        if name == "exp2a":
            table, keys = "4-exp2a", ("layout", "predicate", "approach")
            label_keys = ("layout", "predicate", "approach")
        elif name == "exp2b":
            table, keys = "4-exp2b", ("layout", "sigma", "approach")
            label_keys = ("layout", "sigma", "approach")
        else:
            table, keys = "4-exp2c", ("layout", "mb", "approach")
            label_keys = ("layout", "mb", "approach")
        time_stats = stats(timed, keys, "time_ns")
        for key in sorted(time_stats, key=lambda item: tuple(str(x) for x in item)):
            if name == "exp2a":
                label = f"{key[0]}:{key[1]}:{key[2]}"
                filt = f"warmup=0; layout={key[0]}; predicate={key[1]}; approach={key[2]}; "
                filt += "n=1000000; mb=500; sigma=0.01"
            elif name == "exp2b":
                label = f"{key[0]}:sigma={key[1]}:{key[2]}"
                filt = f"warmup=0; layout={key[0]}; sigma={key[1]}; approach={key[2]}; "
                filt += "n=1000000; mb=500"
            else:
                label = f"{key[0]}:mb={key[1]}:{key[2]}"
                filt = f"warmup=0; layout={key[0]}; mb={key[1]}; approach={key[2]}; "
                filt += "n=1000000; sigma=0.01"
            add_stat(rows, 4, table, label, "query_time_ms", time_stats[key], "ms", src,
                     filt, factor=1.0 / common.TIME_DIVISOR_NS)

        pqz = [row for row in timed if row.get("approach") == "pqz"]
        eta_keys = keys[:-1]
        eta_stats = stats(pqz, eta_keys, "n_cand")
        for key in sorted(eta_stats, key=lambda item: tuple(str(x) for x in item)):
            entry = eta_stats[key]
            n_value = next(
                (row.get("n") for row in pqz
                 if tuple(row.get(k) for k in eta_keys) == key and row.get("n")),
                None,
            )
            value = ratio(entry["median"], n_value) if n_value else None
            if name == "exp2a":
                label = f"exp2a:{key[0]}:{key[1]}"
                filt = f"warmup=0; approach=pqz; layout={key[0]}; predicate={key[1]}; n=1000000"
            elif name == "exp2b":
                label = f"exp2b:{key[0]}:sigma={key[1]}"
                filt = f"warmup=0; approach=pqz; layout={key[0]}; sigma={key[1]}; n=1000000"
            else:
                label = f"exp2c:{key[0]}:mb={key[1]}"
                filt = f"warmup=0; approach=pqz; layout={key[0]}; mb={key[1]}; n=1000000"
            add_value(rows, 4, "4-eta", label, "eta_Q", value, "ratio", src, filt,
                      note="eta_Q = median(n_cand)/N; N_Q := n_cand", n_runs=entry["n"])


# ------------------------------------------------------------------ section 5

def section_exp3(rows):
    exp3a = load_timed_eval(EVAL_FILES["exp3a"])
    src3a = source_path(EVAL_FILES["exp3a"])
    sum_stats = stats(exp3a, ("sigma", "approach"), "time_ns")
    for key in sorted(sum_stats, key=lambda item: (float(item[0]), str(item[1]))):
        add_stat(rows, 5, "5-exp3a-sum", f"sigma={key[0]}:{key[1]}", "aggregation_time_ms",
                 sum_stats[key], "ms", src3a,
                 f"warmup=0; series=sigma; sigma={key[0]}; approach={key[1]}; agg=SUM; n=1000000",
                 factor=1.0 / common.TIME_DIVISOR_NS)

    exp3b = load_timed_eval(EVAL_FILES["exp3b_v2"])
    src3b = source_path(EVAL_FILES["exp3b_v2"])
    agg_stats = stats(exp3b, ("agg", "approach"), "time_ns")
    for agg in ("SUM", "AVG"):
        for approach in ("plain_agg", "full_he", "pqz"):
            key = (agg, approach)
            add_stat(rows, 5, "5-exp3b-ops", f"{agg}:{approach}", "aggregation_time_ms",
                     agg_stats.get(key), "ms", src3b,
                     f"warmup=0; series=agg; agg={agg}; approach={approach}; n=1000000; sigma=0.01",
                     factor=1.0 / common.TIME_DIVISOR_NS)
    for approach in ("plain_agg", "full_he", "pqz"):
        key = ("COUNT", approach)
        note = ("timer resolution; no R_HE ratio" if approach in ("pqz", "plain_agg")
                else "raw nanoseconds; no R_HE ratio for COUNT")
        add_stat(rows, 5, "5-count-raw", f"exp3b:{approach}", "count_aggregation_ns",
                 agg_stats.get(key), "ns", src3b,
                 f"warmup=0; series=agg; agg=COUNT; approach={approach}; n=1000000; sigma=0.01",
                 note=note)

    exp3d = load_timed_eval(EVAL_FILES["exp3d_v2"])
    src3d = source_path(EVAL_FILES["exp3d_v2"])
    count_stats = stats(exp3d, ("sigma", "approach"), "time_ns")
    for key in sorted(count_stats, key=lambda item: (float(item[0]), str(item[1]))):
        add_stat(rows, 5, "5-count-raw", f"exp3d:sigma={key[0]}:{key[1]}",
                 "count_aggregation_ns", count_stats[key], "ns", src3d,
                 f"warmup=0; series=count_sweep; sigma={key[0]}; approach={key[1]}; agg=COUNT; n=1000000",
                 note="timer resolution; no R_HE ratio")

    for sigma in sorted({key[0] for key in sum_stats}, key=float):
        he = sum_stats.get((sigma, "full_he"))
        pqz = sum_stats.get((sigma, "pqz"))
        value = None if he is None or pqz is None else 1.0 - pqz["median"] / he["median"]
        add_value(rows, 5, "5-rhe", f"exp3a:SUM:sigma={sigma}", "R_HE", value, "ratio",
                  src3a, f"warmup=0; agg=SUM; sigma={sigma}; 1 - median(pqz)/median(full_he)",
                  note="R_HE computed from the two medians")
    for agg in ("SUM", "AVG"):
        he = agg_stats.get((agg, "full_he"))
        pqz = agg_stats.get((agg, "pqz"))
        value = None if he is None or pqz is None else 1.0 - pqz["median"] / he["median"]
        add_value(rows, 5, "5-rhe", f"exp3b:{agg}:sigma=0.01", "R_HE", value, "ratio",
                  src3b, f"warmup=0; agg={agg}; sigma=0.01; 1 - median(pqz)/median(full_he)",
                  note="R_HE computed from the two medians")


# ------------------------------------------------------------------ section 6

def proof_rows(rows_data, experiment):
    return [row for row in rows_data if row.get("experiment") == experiment
            and row.get("warmup") == 0]


def add_proof_metrics(rows, table, label, entry_map, src, filt, note=""):
    specs = (
        ("prove_ms", "prove_s", 1e3, "ms"),
        ("verify_ms", "verify_s", 1e3, "ms"),
        ("proof_bytes", "proof_bytes", 1.0, "bytes"),
        ("prove_peak_rss_mib", "prove_peak_rss_kb", 1.0 / 1024.0, "MiB"),
        ("verify_peak_rss_mib", "verify_peak_rss_kb", 1.0 / 1024.0, "MiB"),
    )
    for metric, source_metric, factor, unit in specs:
        add_stat(rows, 6, table, label, metric, entry_map.get(source_metric), unit,
                 src, filt + f"; value={source_metric}", note=note, factor=factor)


def section_proof(rows):
    raw = load_all(PROOF_FULL2)
    src = source_path(PROOF_FULL2)
    scale = proof_rows(raw, "scale")
    metric_names = ("prove_s", "verify_s", "proof_bytes",
                    "prove_peak_rss_kb", "verify_peak_rss_kb")

    def entries_for(selected, keys):
        return {name: stats(selected, keys, name) for name in metric_names}

    scale_entries = entries_for(scale, ("rel", "n_records"))
    for rel in ("rc", "exec"):
        for n in sorted({row.get("n_records") for row in scale
                         if row.get("rel") == rel and row.get("n_records") is not None}):
            emap = {name: scale_entries[name].get((rel, n)) for name in metric_names}
            add_proof_metrics(rows, "6-proof-scale", f"{rel}:n={n}", emap, src,
                              f"warmup=0; experiment=scale; rel={rel}; n_records={n}")

    auth_entries = entries_for(scale, ("rel", "depth"))
    for depth in sorted({row.get("depth") for row in scale
                         if row.get("rel") == "auth" and row.get("depth") is not None},
                        key=common.sort_key):
        emap = {name: auth_entries[name].get(("auth", depth)) for name in metric_names}
        add_proof_metrics(rows, "6-proof-scale", f"auth:depth={depth}", emap, src,
                          f"warmup=0; experiment=scale; rel=auth; depth={depth}")

    largest = (
        ("rc", 100000, ("rel", "n_records"), ("rc", 100000)),
        ("exec", 100000, ("rel", "n_records"), ("exec", 100000)),
        ("auth", 20, ("rel", "depth"), ("auth", 20)),
    )
    for label_rel, workload, keys, key in largest:
        if keys == ("rel", "n_records"):
            emap = {name: scale_entries[name].get(key) for name in metric_names}
            filt = f"warmup=0; experiment=scale; rel={label_rel}; n_records={workload}"
        else:
            emap = {name: auth_entries[name].get(key) for name in metric_names}
            filt = f"warmup=0; experiment=scale; rel=auth; depth={workload}"
        add_proof_metrics(rows, "6-proof-largest", f"{label_rel}:workload={workload}", emap,
                          src, filt, note="largest workload in the scale experiment")

    q_rows = proof_rows(raw, "q")
    q_stats = stats(q_rows, ("rel", "mode", "q"), "total_verify_s")
    for rel in ("rc", "exec", "auth", "bundle"):
        for mode in ("same", "distinct"):
            one = q_stats.get((rel, mode, 1))
            two_hundred = q_stats.get((rel, mode, 200))
            for q, entry in ((1, one), (200, two_hundred)):
                label = f"{rel}:{mode}:q={q}"
                filt = f"warmup=0; experiment=q; rel={rel}; mode={mode}; q={q}"
                add_stat(rows, 6, "6-proof-q", label, "total_verify_ms", entry, "ms", src,
                         filt + "; value=total_verify_s", factor=1e3)
                per_request = None if entry is None else entry["median"] * 1e3 / q
                add_value(rows, 6, "6-proof-q", label, "per_request_verify_ms",
                          per_request, "ms", src, filt + "; total_verify_s / q",
                          n_runs=None if entry is None else entry["n"])
                if q == 200:
                    value = None if one is None or two_hundred is None else \
                        two_hundred["median"] / one["median"]
                    add_value(rows, 6, "6-proof-q", label, "ratio_vs_q1", value, "ratio",
                              src, filt + "; total_verify_s(q=200)/total_verify_s(q=1)",
                              note="expected approximately 200 if per-request cost is constant")


# ------------------------------------------------------------------ section 7

def section_ledger(rows):
    for variant in ("with-tx-auth", "no-tx-auth"):
        relpath = os.path.join(LEDGER_DIR, variant, "exp5c_bytes_per_epoch.csv")
        raw = load_all(relpath)
        src = source_path(relpath)
        for system in ("pqz", "per_record_baseline"):
            for n in sorted({row.get("N") for row in raw
                             if row.get("system") == system and row.get("N") is not None},
                            key=common.sort_key):
                selected = [row for row in raw if row.get("system") == system
                            and row.get("N") == n and str(row.get("kind")) in ("timed", "formula")]
                timed = [row for row in selected if str(row.get("kind")) == "timed"]
                formula = next((row for row in selected if str(row.get("kind")) == "formula"), None)
                if timed:
                    entry = stats(timed, ("system", "N"), "bytes_total").get((system, n))
                    sig = stats(timed, ("system", "N"), "bytes_tx_sig").get((system, n))
                    label = f"{variant}:{system}:N={n}:measured"
                    filt = f"kind=timed; system={system}; N={n}"
                    add_stat(rows, 7, "7-exp5c-bytes", label, "bytes_total", entry, "bytes",
                             src, filt + "; value=bytes_total")
                    add_stat(rows, 7, "7-exp5c-bytes", label, "bytes_tx_sig", sig, "bytes",
                             src, filt + "; value=bytes_tx_sig")
                if formula is not None:
                    label = f"{variant}:{system}:N={n}:formula"
                    filt = f"kind=formula; system={system}; N={n}"
                    add_value(rows, 7, "7-exp5c-bytes", label, "bytes_total",
                              formula.get("bytes_total"), "bytes", src, filt + "; value=bytes_total",
                              note=str(formula.get("method")), n_runs=1)
                    add_value(rows, 7, "7-exp5c-bytes", label, "bytes_tx_sig",
                              formula.get("bytes_tx_sig"), "bytes", src, filt + "; value=bytes_tx_sig",
                              note=str(formula.get("method")), n_runs=1)
                if not timed and formula is None:
                    add_value(rows, 7, "7-exp5c-bytes", f"{variant}:{system}:N={n}",
                              "bytes_total", MISSING, "bytes", src,
                              f"system={system}; N={n}", note="no timed or formula rows")

        relpath = os.path.join(LEDGER_DIR, variant, "exp5a_latency_throughput.csv")
        raw = load_all(relpath)
        src = source_path(relpath)
        timed = [row for row in raw if str(row.get("kind")) == "timed"]
        for key in sorted({(row.get("system"), row.get("workload"), row.get("q")) for row in timed},
                          key=lambda item: tuple(str(x) for x in item)):
            system, workload, q = key
            label = f"{variant}:{system}:{workload}:q={q}"
            filt = f"kind=timed; system={system}; workload={workload}; q={q}"
            for metric, column, factor, unit in (
                ("lat_mean_ms", "lat_mean_ns", 1.0 / common.TIME_DIVISOR_NS, "ms"),
                ("lat_p95_ms", "lat_p95_ns", 1.0 / common.TIME_DIVISOR_NS, "ms"),
                ("throughput_tx_s", "throughput_tx_per_s", 1.0, "tx/s"),
            ):
                entry = stats(timed, ("system", "workload", "q"), column).get(key)
                add_stat(rows, 7, "7-exp5a", label, metric, entry, unit, src,
                         filt + f"; value={column}", factor=factor)

        relpath = os.path.join(LEDGER_DIR, variant, "exp5b_governance.csv")
        raw = load_all(relpath)
        src = source_path(relpath)
        timed = [row for row in raw if str(row.get("kind")) == "timed"]
        for op in sorted({str(row.get("op")) for row in timed}):
            label = f"{variant}:{op}"
            filt = f"kind=timed; op={op}"
            for metric, column, unit in (
                ("op_latency_ms", "op_latency_ns", "ms"),
                ("derived_crit_path_ms", "derived_crit_path_ns", "ms"),
            ):
                entry = stats(timed, ("op",), column).get((op,))
                add_stat(rows, 7, "7-exp5b", label, metric, entry, unit, src,
                         filt + f"; value={column}", factor=1.0 / common.TIME_DIVISOR_NS)

        relpath = os.path.join(LEDGER_DIR, variant, "threshold.csv")
        raw = load_all(relpath)
        src = source_path(relpath)
        timed = [row for row in raw if str(row.get("kind")) != "warmup"]
        keys = ("domain", "variant", "t", "n", "op", "inner_reps")
        entries = stats(timed, keys, "ns_per_op")
        for key in sorted(entries, key=lambda item: tuple(str(x) for x in item)):
            domain, tvar, t, n, op, reps = key
            label = f"{variant}:{domain}:{tvar}:t={t},n={n}:{op}:reps={reps}"
            add_stat(rows, 7, "7-threshold", label, "threshold_ns_per_op", entries[key],
                     "ns", src,
                     f"kind!=warmup; domain={domain}; variant={tvar}; t={t}; n={n}; "
                     f"op={op}; inner_reps={reps}",
                     note="median ns per operation")


# ------------------------------------------------------------------ section 8

def section_ablation_reject(rows):
    exp2a = load_timed_eval(EVAL_FILES["exp2a"])
    src2a = source_path(EVAL_FILES["exp2a"])
    time_stats = stats(exp2a, ("layout", "predicate", "approach"), "time_ns")
    for layout in sorted({str(row.get("layout")) for row in exp2a}):
        for predicate in sorted({str(row.get("predicate")) for row in exp2a}):
            full = time_stats.get((layout, predicate, "prot_full_scan"))
            pqz = time_stats.get((layout, predicate, "pqz"))
            value = None if full is None or pqz is None or pqz["median"] == 0 else \
                full["median"] / pqz["median"]
            add_value(rows, 8, "8-abl-blockfilter", f"{layout}:{predicate}",
                      "prot_full_scan_over_pqz", value, "ratio", src2a,
                      f"warmup=0; layout={layout}; predicate={predicate}; "
                      "median(prot_full_scan)/median(pqz)",
                      note="ratio > 1 means removing block filtering costs more")

    exp3b = load_timed_eval(EVAL_FILES["exp3b_v2"])
    src3b = source_path(EVAL_FILES["exp3b_v2"])
    agg_stats = stats(exp3b, ("agg", "approach"), "time_ns")
    for agg in ("SUM", "AVG"):
        he = agg_stats.get((agg, "full_he"))
        pqz = agg_stats.get((agg, "pqz"))
        value = None if he is None or pqz is None or pqz["median"] == 0 else \
            he["median"] / pqz["median"]
        add_value(rows, 8, "8-abl-selectivehe", f"exp3b:{agg}", "full_he_over_pqz",
                  value, "ratio", src3b,
                  f"warmup=0; agg={agg}; sigma=0.01; median(full_he)/median(pqz)",
                  note="ratio > 1 means removing selective HE costs more; COUNT excluded "
                       "(timer resolution)")

    abl = load_all(PROOF_ABLATION)
    src_abl = source_path(PROOF_ABLATION)
    timed = [row for row in abl if row.get("warmup") == 0]
    metric_names = ("prove_s", "verify_s", "proof_bytes", "prove_peak_rss_kb")
    entry_map = {name: stats(timed, ("n_records", "g_blocks", "mode"), name)
                 for name in metric_names}
    for n in sorted({row.get("n_records") for row in timed if row.get("n_records") is not None}):
        g_values = sorted({row.get("g_blocks") for row in timed if row.get("n_records") == n})
        g = g_values[0] if g_values else None
        for mode in ("batched", "per_block"):
            key = (n, g, mode)
            label = f"n={n}:G={g}:{mode}"
            filt = f"warmup=0; n_records={n}; g_blocks={g}; mode={mode}"
            for metric, column, factor, unit in (
                ("prove_ms", "prove_s", 1e3, "ms"),
                ("verify_ms", "verify_s", 1e3, "ms"),
                ("proof_bytes", "proof_bytes", 1.0, "bytes"),
                ("prove_peak_rss_mib", "prove_peak_rss_kb", 1.0 / 1024.0, "MiB"),
            ):
                add_stat(rows, 8, "8-abl-batchedrc", label, metric,
                         entry_map[column].get(key), unit, src_abl,
                         filt + f"; value={column}", factor=factor)
        batched = entry_map["prove_s"].get((n, g, "batched"))
        per_block = entry_map["prove_s"].get((n, g, "per_block"))
        value = None if batched is None or per_block is None or batched["median"] == 0 else \
            per_block["median"] / batched["median"]
        add_value(rows, 8, "8-abl-batchedrc-ratio", f"n={n}:G={g}",
                  "per_block_over_batched_prove", value, "ratio", src_abl,
                  f"warmup=0; n_records={n}; g_blocks={g}; median(per_block)/median(batched)",
                  note="G=1 is one identical proof; no sign is predicted")

    path = os.path.join(common.BASE_DIR, REJECT_FILE)
    if not os.path.isfile(path):
        add_value(rows, 8, "8-reject", "reject-1000", "trials_total", MISSING, "trials",
                  source_path(REJECT_FILE), "file not found")
        return
    src_rej = source_path(REJECT_FILE)
    section = None
    attacks = []
    pattern = re.compile(r"^(\S+)\s+(.+?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/(\d+)\s*$")
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("==") or line.startswith("--"):
                section = line
                continue
            match = pattern.match(line)
            if match:
                attacks.append({
                    "section": section, "variant": match.group(1), "attack": match.group(2),
                    "trials": int(match.group(3)), "rejected": int(match.group(4)),
                    "accepted": int(match.group(5)),
                    "control": f"{match.group(6)}/{match.group(7)}",
                })
    production = [item for item in attacks if item["section"] and "production" in item["section"]]
    used = production or attacks
    if not used:
        add_value(rows, 8, "8-reject", "reject-1000", "trials_total", MISSING, "trials",
                  src_rej, "section=production defences")
        return
    for item in used:
        label = item["variant"]
        filt = f"section=production defences; variant={item['variant']}; attack={item['attack']}"
        add_value(rows, 8, "8-reject", label, "trials", item["trials"], "trials", src_rej,
                  filt, note=f"control_ok={item['control']}")
        add_value(rows, 8, "8-reject", label, "rejected", item["rejected"], "trials", src_rej, filt)
        add_value(rows, 8, "8-reject", label, "accepted", item["accepted"], "trials", src_rej, filt)
    add_value(rows, 8, "8-reject", "total", "trials_total", sum(item["trials"] for item in used),
              "trials", src_rej, "section=production defences; sum over variants")
    add_value(rows, 8, "8-reject", "total", "rejected_total",
              sum(item["rejected"] for item in used), "trials", src_rej,
              "section=production defences; sum over variants")
    add_value(rows, 8, "8-reject", "total", "accepted_total",
              sum(item["accepted"] for item in used), "trials", src_rej,
              "section=production defences; sum over variants")


# ------------------------------------------------------------------ section 9

def section_construction(rows):
    timed = load_timed_eval(EVAL_FILES["exp1_construction"])
    src = source_path(EVAL_FILES["exp1_construction"])
    per_record = [row for row in timed if row.get("series") == "per_record"]
    time_stats = stats(per_record, ("approach",), "time_ns")
    for (approach,) in sorted(time_stats, key=str):
        add_stat(rows, 9, "9-construction-times", approach, "construction_time_ns",
                 time_stats[(approach,)], "ns", src,
                 f"warmup=0; series=per_record; approach={approach}; n=1000000; mb=500",
                 note="single run; per-record cost as written by the binary")

    byte_rows = [row for row in timed if row.get("series") == "bytes"
                 or row.get("series") == "bytes_per_block"]
    for item in byte_rows:
        approach = str(item.get("approach"))
        series = str(item.get("series"))
        unit = "bytes/block" if series == "bytes_per_block" else "bytes/record"
        add_value(rows, 9, "9-storage", approach, "storage_bytes", item.get("bytes"),
                  unit, src, f"warmup=0; series={series}; approach={approach}; n=1000000",
                  note="single run", n_runs=1)
    n_blocks = next((item.get("n_blocks") for item in timed), None)
    add_value(rows, 9, "9-storage", "blocks", "n_blocks", n_blocks, "blocks", src,
              "warmup=0; n=1000000; mb=500", note="single run", n_runs=1)


# ------------------------------------------------------------------ output

def build_rows():
    rows = []
    section_run_counts(rows)
    section_ranges(rows)
    section_exp1(rows)
    section_exp2(rows)
    section_exp3(rows)
    section_proof(rows)
    section_ledger(rows)
    section_ablation_reject(rows)
    section_construction(rows)
    return rows


def write_csv(rows, path):
    fieldnames = ["section", "table", "row", "metric", "value", "unit",
                  "n_runs", "min", "max", "source", "filter", "note"]
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in rows:
            writer.writerow({key: item.get(key, "") for key in fieldnames})


def write_markdown(rows, path):
    lines = [
        "# PQZ-Audit paper numbers",
        "",
        "Generated by `bench/pqz-eval/analysis/paper_numbers.py` from the raw result CSVs only. "
        "Warm-up rows are excluded from every statistic. Medians carry the min-max range and "
        "the number of timed runs. `MISSING` means the raw files do not contain the value; "
        "it is never an estimate.",
        "",
        "Every row names its source file and the exact row filter that produced it. "
        "Ratios are computed from the two medians named in the filter.",
        "",
    ]
    section_order = []
    grouped = {}
    for item in rows:
        section_number = item["section"]
        if section_number not in grouped:
            grouped[section_number] = {}
            section_order.append(section_number)
        table = item["table"]
        grouped[section_number].setdefault(table, []).append(item)
    for section_number in section_order:
        lines.append(f"## {section_number}. {SECTION_TITLES[section_number]}")
        lines.append("")
        for table, table_rows in grouped[section_number].items():
            lines.append(f"### {TABLE_TITLES.get(table, table)}")
            lines.append("")
            lines.append("| Row | Metric | Value | Unit | n | min | max | Source | Filter / note |")
            lines.append("|---|---|---:|---|---:|---:|---:|---|---|")
            for item in table_rows:
                value = fmt_value(item["value"], item["unit"])
                vmin = fmt_value(item["min"], item["unit"]) if item["min"] != "" else ""
                vmax = fmt_value(item["max"], item["unit"]) if item["max"] != "" else ""
                note = item["note"]
                filt = item["filter"] + (f"; {note}" if note else "")
                lines.append(
                    f"| {item['row']} | {item['metric']} | {value} | {item['unit']} | "
                    f"{item['n_runs']} | {vmin} | {vmax} | `{item['source']}` | {filt} |"
                )
            lines.append("")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def missing_report(rows):
    return [item for item in rows if item["value"] == MISSING]


# ------------------------------------------------------------------ self-check

def sc_read(relpath):
    path = os.path.join(common.BASE_DIR, relpath)
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return list(csv.DictReader(handle))


def sc_float(value):
    if value is None or str(value).strip() == "":
        return None
    return float(value)


def sc_median(values):
    clean = sorted(float(value) for value in values if value is not None and str(value) != "")
    if not clean:
        return None
    middle = len(clean) // 2
    if len(clean) % 2:
        return clean[middle]
    return (clean[middle - 1] + clean[middle]) / 2.0


def sc_eval_median(relpath, value_column, predicate):
    rows = sc_read(relpath)
    values = [sc_float(row[value_column]) for row in rows
              if row.get("warmup") == "0" and predicate(row)]
    return sc_median(values)


def sc_numeric_expect(rows_index, section, table, label, metric):
    item = rows_index.get((section, table, label, metric))
    if item is None:
        raise KeyError(f"no output row {(section, table, label, metric)}")
    return item["value"]


def run_self_check(rows):
    index = {(item["section"], item["table"], item["row"], item["metric"]): item for item in rows}

    def safe_median(relpath, column, predicate, factor=1.0):
        value = sc_eval_median(relpath, column, predicate)
        return None if value is None else value * factor

    def check(section, table, label, metric, expected, tolerance=1e-6):
        try:
            actual = sc_numeric_expect(index, section, table, label, metric)
        except KeyError as exc:
            return False, f"section {section} {table}/{label}/{metric}: {exc}"
        if expected == MISSING or expected is None:
            return (actual == MISSING or actual is None), \
                f"section {section} {table}/{label}/{metric}: expected MISSING got {actual!r}"
        if actual == MISSING or actual is None:
            return False, f"section {section} {table}/{label}/{metric}: output is MISSING, recomputed {expected}"
        if isinstance(expected, str):
            return actual == expected, \
                f"section {section} {table}/{label}/{metric}: expected {expected!r} got {actual!r}"
        difference = abs(float(actual) - float(expected))
        limit = max(1e-9, abs(float(expected)) * tolerance)
        return difference <= limit, \
            f"section {section} {table}/{label}/{metric}: output {actual!r} recomputed {expected!r}"

    def eval_rows(relpath):
        return [row for row in sc_read(relpath) if row.get("warmup") == "0"]

    def relpath(key):
        return EVAL_FILES[key]

    checks = []

    # 1. run counts
    checks.append(check(1, "1-runs-eval", "exp1:pqz", "timed_runs_total",
                        sum(1 for row in sc_read(EVAL_FILES["exp1"]) if row.get("warmup") == "0")))
    checks.append(check(1, "1-runs-eval", "exp3b_v2:full_he", "timed_runs_per_config",
                        len([row for row in eval_rows(EVAL_FILES["exp3b_v2"])
                             if row.get("approach") == "full_he"]) / 3.0))
    checks.append(check(1, "1-runs-proof", "proof-full-2:rc", "timed_runs_total",
                        sum(1 for row in sc_read(PROOF_FULL2)
                            if row.get("warmup") == "0" and row.get("rel") == "rc")))

    # 2. ranges
    checks.append(check(2, "2-ranges", "exp3c", "N_values",
                        ", ".join(str(value) for value in sorted({int(row["n"]) for row in eval_rows(EVAL_FILES["exp3c"])}))))
    checks.append(check(2, "2-ranges", "exp2c", "m_B_values",
                        ", ".join(str(value) for value in sorted({int(row["mb"]) for row in eval_rows(EVAL_FILES["exp2c"])}))))
    checks.append(check(2, "2-ranges", "exp2b", "selectivity_sigma_values",
                        ", ".join(str(value) for value in sorted({float(row["sigma"]) for row in eval_rows(EVAL_FILES["exp2b"])}))))

    # 3. exp1 and baseline
    checks.append(check(3, "3-exp1-query", "sigma1pct:N=1000000", "query_time_ms",
                        safe_median(EVAL_FILES["exp1"], "time_ns",
                                    lambda row: row.get("series") == "sigma1pct"
                                    and row.get("n") == "1000000", 1e-6)))
    nqn = [float(row["n_cand"]) for row in eval_rows(EVAL_FILES["exp1"])
           if row.get("series") == "fixed_nq1000" and row.get("n") == "1000000"]
    checks.append(check(3, "3-exp1-nqn", "fixed_nq1000:N=1000000", "N_Q/N",
                        sc_median(nqn) / 1000000.0))
    # WORK7 (entry 372): baseline self-checks read the run2 files (the old c=1;s=10 row no longer exists)
    baseline = [row for row in sc_read(os.path.join(BASELINE_DIR, BASELINE_COSTS_FILE))
                if row["scheme"] == "Dong et al." and row["phase"] == "proof"
                and row["param_set"] == "c=10;s=3;reading=paper_mixed;tt=gt"]
    checks.append(check(3, "3-baseline-costs", "Dong et al.:proof:c=10;s=3;reading=paper_mixed;tt=gt",
                        "baseline_time_ms", float(baseline[0]["time_ns"]) / 1e6))
    prof_rows = sc_read(os.path.join(BASELINE_DIR, BASELINE_PROF_FILE))
    dart = [row for row in prof_rows if row["scheme"] == "DART" and row["phase"] == "audit"
            and row["param_set"] == "z=10;N=40;tf=fr_mul"]
    checks.append(check(3, "3-baseline-costs", "DART:audit:z=10;N=40;tf=fr_mul",
                        "baseline_time_ms", float(dart[0]["time_ns"]) / 1e6))
    lhcpm = [row for row in prof_rows if row["scheme"] == "L-HCPM" and row["phase"] == "audit"
             and row["param_set"] == "cache_miss"]
    checks.append(check(3, "3-baseline-costs", "L-HCPM:audit:cache_miss",
                        "baseline_time_ms", float(lhcpm[0]["time_ns"]) / 1e6))

    # 4. exp2
    checks.append(check(4, "4-exp2a", "clustered:P1:pqz", "query_time_ms",
                        safe_median(EVAL_FILES["exp2a"], "time_ns",
                                    lambda row: row.get("layout") == "clustered"
                                    and row.get("predicate") == "P1"
                                    and row.get("approach") == "pqz", 1e-6)))
    eta = [float(row["n_cand"]) for row in eval_rows(EVAL_FILES["exp2a"])
           if row.get("layout") == "clustered" and row.get("predicate") == "P1"
           and row.get("approach") == "pqz"]
    checks.append(check(4, "4-eta", "exp2a:clustered:P1", "eta_Q",
                        sc_median(eta) / 1000000.0))
    checks.append(check(4, "4-exp2b", "scattered:sigma=0.25:pqz", "query_time_ms",
                        safe_median(EVAL_FILES["exp2b"], "time_ns",
                                    lambda row: row.get("layout") == "scattered"
                                    and float(row["sigma"]) == 0.25
                                    and row.get("approach") == "pqz", 1e-6)))

    # 5. exp3
    checks.append(check(5, "5-exp3b-ops", "SUM:pqz", "aggregation_time_ms",
                        safe_median(EVAL_FILES["exp3b_v2"], "time_ns",
                                    lambda row: row.get("agg") == "SUM"
                                    and row.get("approach") == "pqz", 1e-6)))
    he = safe_median(EVAL_FILES["exp3b_v2"], "time_ns",
                     lambda row: row.get("agg") == "SUM" and row.get("approach") == "full_he")
    pqz = safe_median(EVAL_FILES["exp3b_v2"], "time_ns",
                      lambda row: row.get("agg") == "SUM" and row.get("approach") == "pqz")
    checks.append(check(5, "5-rhe", "exp3b:SUM:sigma=0.01", "R_HE",
                        None if he in (None, 0) or pqz is None else 1.0 - pqz / he))
    checks.append(check(5, "5-count-raw", "exp3b:pqz", "count_aggregation_ns",
                        safe_median(EVAL_FILES["exp3b_v2"], "time_ns",
                                    lambda row: row.get("agg") == "COUNT"
                                    and row.get("approach") == "pqz")))

    # 6. proof
    proof_rows = [row for row in sc_read(PROOF_FULL2) if row.get("warmup") == "0"]
    checks.append(check(6, "6-proof-scale", "rc:n=100000", "prove_ms",
                        sc_median([float(row["prove_s"]) for row in proof_rows
                                   if row.get("experiment") == "scale" and row.get("rel") == "rc"
                                   and row.get("n_records") == "100000"]) * 1e3))
    checks.append(check(6, "6-proof-q", "rc:same:q=200", "total_verify_ms",
                        sc_median([float(row["total_verify_s"]) for row in proof_rows
                                   if row.get("experiment") == "q" and row.get("rel") == "rc"
                                   and row.get("mode") == "same" and row.get("q") == "200"]) * 1e3))
    checks.append(check(6, "6-proof-scale", "rc:n=100000", "proof_bytes",
                        sc_median([float(row["proof_bytes"]) for row in proof_rows
                                   if row.get("experiment") == "scale" and row.get("rel") == "rc"
                                   and row.get("n_records") == "100000"])))

    # 7. ledger
    ledger_file = os.path.join(LEDGER_DIR, "with-tx-auth", "exp5c_bytes_per_epoch.csv")
    ledger = sc_read(ledger_file)
    checks.append(check(7, "7-exp5c-bytes", "with-tx-auth:pqz:N=1000000:measured", "bytes_total",
                        sc_median([float(row["bytes_total"]) for row in ledger
                                   if row.get("kind") == "timed" and row.get("system") == "pqz"
                                   and row.get("N") == "1000000"])))
    exp5a = os.path.join(LEDGER_DIR, "with-tx-auth", "exp5a_latency_throughput.csv")
    checks.append(check(7, "7-exp5a", "with-tx-auth:pqz:authorize:q=200", "lat_mean_ms",
                        sc_median([float(row["lat_mean_ns"]) for row in sc_read(exp5a)
                                   if row.get("kind") == "timed" and row.get("system") == "pqz"
                                   and row.get("workload") == "authorize"
                                   and row.get("q") == "200"]) / 1e6))
    exp5a_no = os.path.join(LEDGER_DIR, "no-tx-auth", "exp5a_latency_throughput.csv")
    checks.append(check(7, "7-exp5a", "no-tx-auth:pqz:authorize:q=200", "throughput_tx_s",
                        sc_median([float(row["throughput_tx_per_s"]) for row in sc_read(exp5a_no)
                                   if row.get("kind") == "timed" and row.get("system") == "pqz"
                                   and row.get("workload") == "authorize"
                                   and row.get("q") == "200"])))

    # 8. ablation and rejection
    exp2a = eval_rows(EVAL_FILES["exp2a"])
    full = sc_median([float(row["time_ns"]) for row in exp2a
                      if row.get("layout") == "clustered" and row.get("predicate") == "P1"
                      and row.get("approach") == "prot_full_scan"])
    pqz = sc_median([float(row["time_ns"]) for row in exp2a
                     if row.get("layout") == "clustered" and row.get("predicate") == "P1"
                     and row.get("approach") == "pqz"])
    checks.append(check(8, "8-abl-blockfilter", "clustered:P1", "prot_full_scan_over_pqz",
                        None if full is None or pqz in (None, 0) else full / pqz))
    abl = [row for row in sc_read(PROOF_ABLATION) if row.get("warmup") == "0"]
    batched = sc_median([float(row["prove_s"]) for row in abl
                         if row.get("n_records") == "8000" and row.get("mode") == "batched"])
    per_block = sc_median([float(row["prove_s"]) for row in abl
                           if row.get("n_records") == "8000" and row.get("mode") == "per_block"])
    checks.append(check(8, "8-abl-batchedrc-ratio", "n=8000:G=16", "per_block_over_batched_prove",
                        None if batched in (None, 0) or per_block is None else per_block / batched))
    reject_path = os.path.join(common.BASE_DIR, REJECT_FILE)
    reject_pattern = re.compile(r"^(\S+)\s+(.+?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/(\d+)\s*$")
    section = None
    trials = 0
    with open(reject_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("==") or line.startswith("--"):
                section = line
                continue
            match = reject_pattern.match(line)
            if match and section and "production" in section:
                trials += int(match.group(3))
    checks.append(check(8, "8-reject", "total", "trials_total", trials))

    # 9. construction
    construction = eval_rows(EVAL_FILES["exp1_construction"])
    checks.append(check(9, "9-construction-times", "aead", "construction_time_ns",
                        float(next(row["time_ns"] for row in construction
                                   if row.get("approach") == "aead"))))
    checks.append(check(9, "9-storage", "storage_record", "storage_bytes",
                        float(next(row["bytes"] for row in construction
                                   if row.get("approach") == "storage_record"))))
    checks.append(check(9, "9-construction-times", "total", "construction_time_ns",
                        float(next(row["time_ns"] for row in construction
                                   if row.get("approach") == "total"))))

    by_section = {}
    for (ok, message) in checks:
        section_number = int(message.split()[1])
        by_section.setdefault(section_number, []).append((ok, message))
    any_bad = False
    for section_number in sorted(by_section):
        bad = [message for ok, message in by_section[section_number] if not ok]
        if bad:
            any_bad = True
            print(f"Section {section_number}: MISMATCH")
            for message in bad:
                print(f"  MISMATCH {message}")
        else:
            print(f"Section {section_number}: OK ({len(by_section[section_number])} checks)")
    return 0 if not any_bad else 1


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true",
                        help="recompute three numbers per section independently and compare")
    parser.add_argument("--out", default=None, help="output directory (default: analysis/out)")
    args = parser.parse_args()

    rows = build_rows()
    if args.self_check:
        return run_self_check(rows)

    out_dir = common.out_dir(args.out)
    csv_path = os.path.join(out_dir, "paper-numbers.csv")
    md_path = os.path.join(out_dir, "paper-numbers.md")
    write_csv(rows, csv_path)
    write_markdown(rows, md_path)
    missing = missing_report(rows)
    print(f"wrote {os.path.relpath(csv_path, REPO_ROOT)} ({len(rows)} rows)")
    print(f"wrote {os.path.relpath(md_path, REPO_ROOT)}")
    if missing:
        print(f"MISSING rows: {len(missing)}")
        for item in missing:
            print(f"  section {item['section']} {item['table']} / {item['row']} / {item['metric']}")
    else:
        print("MISSING rows: 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
