#!/usr/bin/env python3
"""Draw fig_exp1_w20 and fig_exp4a_w20 and write the w20 checks (cloud-w20: L-HCPM on 32 threads, Fig. 5 with 7 points per line).

Usage: .venv-bench/bin/python -I bench/pqz-eval/analysis/make_figs_w20.py
         [--results DIR] [--w19 DIR] [--w18 DIR] [--out DIR] [--checks-out DIR]
  results:    default bench/pqz-eval/results/cloud-w20   (the w20 session; one sub-folder per job)
  w19:        default bench/pqz-eval/results/cloud-w19   (L-HCPM 1-thread points of work19, as drawn in work19)
  w18:        default bench/pqz-eval/results/cloud-w18   (Fig. 2: PQZ-Audit query + Dong/DOPIV/DART lines; cross-session repeat check)
  out:        default journal2/figures/results-w20       (fig_exp1_w20 / fig_exp4a_w20 .pdf .png .csv)
  checks-out: default bench/pqz-eval/analysis/out-w20    (w20_checks.txt, w20_checks.csv)
Tests must pass --out and --checks-out somewhere else; the defaults hold real data only.

Rules (journal2/CLOUD-PLAN-work20.md, written before any w20 number was seen). Followed literally:
  * Fig. 2 (exp1): w19 figure PLUS a second L-HCPM line, cache hit on 32 threads = median of 30 runs of audit_hit_q at q = c = N/100
    audits (job lhcpm32-audit-q). The w19 1-thread line stays (job audit-q of w19). PQZ-Audit and the baselines: the w18 values as in w19.
  * Fig. 5 (exp4a): 7 N_Q points per line (1e3, 2e3, 5e3, 1e4, 2e4, 5e4, 1e5). Solid lines, log axes, nothing rescaled.
      PQZ-Audit R_Exec / R_RC : median of the timed rows (warmup == 0) of proofbench-scale-w20 (w20 session).
      Dong, DOPIV, DOPIV lazy, DART : the drivers' own medians of the w20 e4a jobs (dong-e4a-c*, dopiv-e4a, dopiv-lazy-e4a, dart-e4a).
      L-HCPM 1 thread : w19 points at 1e3 (median of 3), 1e4 (median of 3 processes), 1e5 (sum of 4 chunks); w20 N_Q = 2e3, 5e3 one run
                        (lhcpm1-mint-N2000/N5000); N_Q = 2e4, 5e4 = SUM of the 4 chunk jobs (tier 2, optional; one run each).
      L-HCPM 32 threads : median of 3 runs for N_Q <= 1e4; ONE run for N_Q >= 2e4 (no band).
  * Required jobs missing / failed / wrong row count: the script lists them and exits 2 before anything is written.
    OPTIONAL jobs (tier-2 chunk jobs, alone-checks ac-*, w19 ac-mint-N1000-alone): a missing or failed job only omits that point /
    that check; the omission is listed in the checks file. A point that was not run is not drawn. Nothing is interpolated or invented.
  * w20_checks.txt / .csv: (a) speed-up S(T) and efficiency, (b) bridges to w19, (c) cross-session repeat check against w18,
    (d) contention (alone-check vs S3 job), (e) ratios the paper needs, (f) run counts per point, (g) padded trace rows per N_Q.
    The text has 4 significant digits; the CSV and the figure CSVs are NOT rounded (repr of the float).
    Every raw input file that was read is listed with its path and the first 16 hex of its sha256.

Raw columns relied on (see the final report of the writing session):
  lhcpm-bench raw_runs.csv : baseline, stage, params, run, ms      stage audit_hit_q | groth16_prove_mint_q; params carry q=..;[threads=T];[chunk=k/4]
  proofbench raw.csv       : experiment, rel, n_records, warmup, rule, trace_rows, prove_s   (experiment == scale, rel exec | rc)
  dong/dopiv/dart raw_runs : baseline, stage, params, run, ms      params carry c= (dong, dopiv), cov= and D= (dart), n=, m=, red=lazy
  exp1d.csv (w18)          : series, n, warmup, time_ns
  per job                  : exit_code.txt (must be 0), failures.txt (must be empty or absent), cpus.txt (scaling jobs; optional)
"""
import argparse
import csv
import hashlib
import os
import statistics as st
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import w18_common as WC  # noqa: E402

import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import LogLocator, NullFormatter, NullLocator  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--results", help="w20 results folder (default bench/pqz-eval/results/cloud-w20)")
ap.add_argument("--w19", help="w19 results folder (default bench/pqz-eval/results/cloud-w19)")
ap.add_argument("--w18", help="w18 results folder (default bench/pqz-eval/results/cloud-w18)")
ap.add_argument("--out", help="figure folder (default journal2/figures/results-w20)")
ap.add_argument("--checks-out", help="checks folder (default bench/pqz-eval/analysis/out-w20)")
args = ap.parse_args()


def find_dir(cli, default, label):
    p = os.path.abspath(cli or default)
    if not os.path.isdir(p):
        print(f"REFUSING: {label} results folder not found: {p}", file=sys.stderr)
        sys.exit(2)
    return p


RES = WC.Results(find_dir(args.results, os.path.join(WC.BASE, "results", "cloud-w20"), "w20"))
RES19 = WC.Results(find_dir(args.w19, os.path.join(WC.BASE, "results", "cloud-w19"), "w19"))
RES18 = WC.Results(find_dir(args.w18, WC.DEFAULT_RESULTS, "w18"))
OUT_DEFAULT = os.path.join(WC.ROOT, "journal2", "figures", "results-w20")
CHECKS_DEFAULT = os.path.join(WC.BASE, "analysis", "out-w20")

# ---------------------------------------------------------------- style (as the w19 figures)
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 6.5, "axes.labelsize": 6.5,
    "xtick.labelsize": 6.5, "ytick.labelsize": 6.5, "legend.fontsize": 6,
    "axes.linewidth": 0.7, "xtick.major.width": 0.7, "ytick.major.width": 0.7,
    "xtick.minor.width": 0.5, "ytick.minor.width": 0.5,
    "xtick.direction": "out", "ytick.direction": "out",
    "pdf.fonttype": 42, "ps.fonttype": 42,
})
W = 3.45  # IEEE column width (in)
BLUE, SKY, ORANGE, GREEN, PINK, GREY = "#0072B2", "#56B4E9", "#E69F00", "#009E73", "#CC79A7", "#555555"
WINE = "#8A1C5F"  # L-HCPM 32 threads: same family as PINK (L-HCPM), darker
STY = {  # key: color, linestyle, linewidth, marker, markersize, hollow
    "pqz":       (BLUE, "-", 1.4, "o", 3.6, False),
    "pqz_rc":    (SKY, "-", 1.4, "s", 3.4, False),
    "dong":      (GREY, "-", 1.0, "s", 3.0, False),
    "dopiv":     (ORANGE, "-", 1.0, "^", 3.2, False),
    "dopiv_lazy": (ORANGE, "-", 0.7, "v", 3.0, True),
    "dart":      (GREEN, "-", 1.0, "D", 2.6, False),
    "lhcpm":     (PINK, "-", 1.0, "x", 3.4, False),       # 1 thread (as w19)
    "lhcpm32":   (WINE, "-", 1.2, "P", 3.6, False),       # 32 threads (new in w20)
}

# ---------------------------------------------------------------- the plan's numbers
NQ = [1000, 2000, 5000, 10000, 20000, 50000, 100000]          # Fig. 5 points
QS = [100, 200, 500, 1000, 2000, 5000, 10000]                 # Fig. 2: q = c = N/100
NS = [q * 100 for q in QS]                                    # N = 1e4 .. 1e6
TS = [1, 8, 16, 32]
MINT, AUDIT = "groth16_prove_mint_q", "audit_hit_q"
CONTENTION_FLAG = 1.05
TIER2 = {20000: ("lhcpm1-mint-N20000", 5000), 50000: ("lhcpm1-mint-N50000", 12500)}   # N_Q -> (job prefix, proofs per chunk)
CHUNKS = 4

# ---------------------------------------------------------------- what is needed (refuse before drawing)
NEED20 = [("lhcpm32-audit-q", "raw_runs.csv")]
NEED20 += [(f"lhcpm-audit-scaling-T{T}", "raw_runs.csv") for T in TS]
NEED20 += [(f"lhcpm32-mint-N{n}", "raw_runs.csv") for n in NQ]
NEED20 += [(f"lhcpm-mint-scaling-T{T}", "raw_runs.csv") for T in TS]
NEED20 += [("proofbench-scale-w20", "raw.csv")]
NEED20 += [(f"dong-e4a-c{c}", "raw_runs.csv") for c in NQ]
NEED20 += [(j, "raw_runs.csv") for j in ("dopiv-e4a", "dopiv-lazy-e4a", "dart-e4a", "lhcpm1-mint-N2000", "lhcpm1-mint-N5000")]
OPT20 = [(f"{pre}-chunk{k}", "raw_runs.csv") for pre, _ in TIER2.values() for k in range(1, CHUNKS + 1)]
OPT20 += [(j, "raw_runs.csv") for j in ("ac-dong", "ac-dart", "ac-dopiv", "ac-lhcpm1-mint-N2000")]
NEED19 = [("audit-q", "raw_runs.csv"), ("mint-N1000-4wide", "raw_runs.csv")]
NEED19 += [(f"mint-N10000-run{k}", "raw_runs.csv") for k in (1, 2, 3)]
NEED19 += [(f"mint-N100000-chunk{k}", "raw_runs.csv") for k in range(1, CHUNKS + 1)]
OPT19 = [("ac-mint-N1000-alone", "raw_runs.csv")]
NEED18 = [("exp1d", "exp1d.csv"), ("proofbench-full", "raw.csv")]
NEED18 += [(j, "raw_runs.csv") for j in ("dong-e1", "dong-e1-c10000", "dopiv-e1", "dopiv-lazy-e1", "dart-e1",
                                         "dong-e4a", "dong-e4a-c100000", "dopiv-e4a", "dopiv-e4a-c100000",
                                         "dopiv-lazy-e4a", "dopiv-lazy-e4a-c100000", "dart-e4a")]

OK20 = RES.preflight(NEED20, OPT20)
OK19 = RES19.preflight(NEED19, OPT19)
RES18.preflight(NEED18)

missing = []   # required cells that are not there: the script refuses (exit 2)
omitted = []   # optional points / checks that are not there: listed in the checks file, not drawn
INPUTS = {}    # path -> first 16 hex of sha256 of every raw input file that was read
_CACHE = {}


def sha16(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()[:16]


def reg(path):
    if path not in INPUTS:
        INPUTS[path] = sha16(path)


def rd(res, job, fname):
    """Rows of one csv (cached); the file is registered with its hash. Any refusal of the shared reader is exit 2."""
    path = res.p(job, fname)
    if path not in _CACHE:
        try:
            _CACHE[path] = res.rd(job, fname)
        except SystemExit as e:
            print(str(e.code), file=sys.stderr)
            sys.exit(2)
        reg(path)
    return _CACHE[path]


def read_small(res, job, fname):
    """Text of a small file (cpus.txt, exit_code.txt, FAILED_JOBS.txt ...) or None; registered when read."""
    path = res.p(job, fname) if job else os.path.join(res.path, fname)
    if not os.path.isfile(path):
        return None
    reg(path)
    with open(path, errors="replace") as f:
        return f.read()


def reason(res, job, fname="raw_runs.csv"):
    pr = res.job_problems(job)
    if pr and "folder missing" in pr[0]:
        return f"{job}: job folder missing"
    return pr[0] if pr else f"{job}/{fname}: missing or empty"


def rel(path):
    try:
        r = os.path.relpath(path, WC.ROOT)
        return path if r.startswith("..") else r
    except ValueError:
        return path


def stat(v, info=""):
    return dict(med=st.median(v), lo=min(v), hi=max(v), n=len(v), info=info)


def g4(x):
    """4 significant digits, no exponent."""
    s = f"{x:.4g}"
    if "e" in s:
        v = float(s)
        s = f"{v:.0f}" if abs(v) >= 1 else f"{v:.12f}".rstrip("0")
    return s


def pct(ratio):
    return f"{(ratio - 1.0) * 100.0:+.4g} %"


# ---------------------------------------------------------------- readers
def baseline_cells(res, job, stage):
    """-> list of (params_dict, [ms...]) for one raw_runs.csv and stage."""
    g = defaultdict(list)
    for r in rd(res, job, "raw_runs.csv"):
        if r["stage"] == stage:
            g[r["params"]].append(float(r["ms"]))
    return [(WC.parse_params(k)[0], v) for k, v in g.items()]


def pick(cells, **want):
    """Unique cell whose params match `want` (str compare; value None = key absent) -> stat, else None."""
    hit = []
    for p, v in cells:
        ok = True
        for k, w in want.items():
            if w is None:
                if k in p:
                    ok = False
            elif p.get(k) != str(w):
                ok = False
        if ok:
            hit.append((p, v))
    if len(hit) == 1:
        p, v = hit[0]
        return stat(v, "runs=" + p.get("runs", "-"))
    return None


def base_rows(figtag, label_key, xs, jobs_of, stage, extra, res, sess):
    """One baseline line: for every x the first job of jobs_of(x) that has the cell; a missing cell is a REQUIRED problem."""
    rows = []
    for x in xs:
        S = used = None
        for job in jobs_of(x):
            S = pick(baseline_cells(res, job, stage), **extra(x))
            if S:
                used = job
                break
        if S:
            rows.append((x, S, f"{sess}/{used}"))
        else:
            missing.append(f"{figtag} {label_key} x={x} ({sess} jobs {jobs_of(x)}, stage {stage}, want {extra(x)})")
    return rows


def lh_cell(res, job, stage, q, T, n_exp):
    """All rows of `stage` with q == q in an lhcpm-bench raw_runs.csv -> (stat, None) or (None, problem).
    The params key threads must equal T (absent = 1: the 1-thread path writes no threads key). n_exp = expected number of timed rows."""
    ms, runs = [], set()
    for r in rd(res, job, "raw_runs.csv"):
        if r["stage"] != stage:
            continue
        p, _ = WC.parse_params(r["params"])
        if p.get("q") != str(q):
            continue
        th = int(p.get("threads", "1"))
        if th != T:
            return None, f"{job}: rows at q={q} have threads={th}, expected {T}"
        if stage == MINT and p.get("constraints") != "2676":
            return None, f"{job}: constraints={p.get('constraints')}, expected 2676"
        if "chunk" in p and p["chunk"].split("/")[0] != job.rsplit("chunk", 1)[-1]:
            return None, f"{job}: params say chunk={p['chunk']}, the job name says chunk{job.rsplit('chunk', 1)[-1]}"
        runs.add(p.get("runs", "-"))
        ms.append(float(r["ms"]))
    if len(ms) != n_exp:
        return None, f"{job}: {len(ms)} timed rows at q={q} ({stage}), expected {n_exp}"
    return stat(ms, f"threads={T};planned runs={'/'.join(sorted(runs))}"), None


def lh_or_missing(tag, res, job, stage, q, T, n_exp, sink):
    S, prob = lh_cell(res, job, stage, q, T, n_exp)
    if prob:
        sink.append(f"{tag}: {prob}")
    return S


def chunk_sum(tag, res, ok, prefix, q_chunk, sink, sess):
    """Sum of the 4 chunk jobs `prefix-chunk1..4` (one run each) -> stat dict (n=1) or None.
    All problems of one point go into `sink` as ONE message (the point is then not drawn)."""
    vals, probs = [], []
    for k in range(1, CHUNKS + 1):
        job = f"{prefix}-chunk{k}"
        if ok is not None and job not in ok:
            probs.append(reason(res, job))
            continue
        S, prob = lh_cell(res, job, MINT, q_chunk, 1, 1)
        if prob:
            probs.append(prob)
            continue
        vals.append(S["med"])
    if probs:
        sink.append(f"{tag}: not drawn, {len(probs)} of {CHUNKS} chunk jobs unusable: " + " | ".join(probs))
        return None
    tot = sum(vals)
    return dict(med=tot, lo=tot, hi=tot, n=1, info=f"sum of {CHUNKS} chunks of {q_chunk}", chunks=vals)


def pqz_scale(res, job, sizes, sess):
    """proofbench raw.csv, experiment scale, rel exec|rc -> {(rel, N): dict(stat, rule, warm, trace)}; missing sizes are REQUIRED problems."""
    g, warm, rules, trace = defaultdict(list), defaultdict(int), defaultdict(set), defaultdict(set)
    for r in rd(res, job, "raw.csv"):
        if r["experiment"] != "scale" or r["rel"] not in ("exec", "rc"):
            continue
        key = (r["rel"], int(r["n_records"]))
        if WC.is_timed(r):
            g[key].append(float(r["prove_s"]) * 1000.0)
        else:
            warm[key] += 1
        rules[key].add(r["rule"])
        trace[key].add(r.get("trace_rows", ""))
    out = {}
    for rel_ in ("exec", "rc"):
        for x in sizes:
            if (rel_, x) in g:
                out[(rel_, x)] = dict(S=stat(g[(rel_, x)], "; ".join(sorted(rules[(rel_, x)]))), rule=sorted(rules[(rel_, x)]),
                                      warm=warm[(rel_, x)], trace=sorted(trace[(rel_, x)]), job=f"{sess}/{job}")
            else:
                missing.append(f"PQZ {rel_} N_Q={x} ({sess}/{job}: no timed row)")
    return out


# ---------------------------------------------------------------- figure object (as w19, CSV not rounded)
class Fig:
    def __init__(self, name, header):
        self.name, self.header = name, header
        self.series = []  # dict(key, label, rows=[(x, stat, job)])

    def add(self, key, label, rows):
        self.series.append(dict(key=key, label=label, rows=rows))

    def by_key(self, key):
        for s in self.series:
            if s["key"] == key:
                return {x: S for x, S, _ in s["rows"]}
        return {}

    def write_csv(self, out):
        with open(os.path.join(out, self.name + ".csv"), "w", newline="") as f:
            for line in self.header:
                f.write("# " + line + "\n")
            w = csv.writer(f)
            w.writerow(["figure", "series", "x", "median_ms", "min_ms", "max_ms", "n_runs", "source_job"])
            for s in self.series:
                for x, S, job in s["rows"]:
                    w.writerow([self.name, s["label"], x, repr(float(S["med"])), repr(float(S["lo"])), repr(float(S["hi"])), S["n"], job])

    def print_table(self, ref_labels, xname):
        print(f"\n=== {self.name}: x = {xname}; median ms (n)")
        for s in self.series:
            print(f"  {s['label']}: " + "; ".join(f"{x}: {g4(S['med'])} (n={S['n']})" for x, S, _ in s["rows"]))
        print("  ratio to PQZ-Audit at the same x (series median / PQZ median):")
        refs = {lab: {x: S["med"] for x, S, _ in s["rows"]} for s in self.series for lab in ref_labels if s["label"] == lab}
        for s in self.series:
            if s["label"] in ref_labels:
                continue
            parts = []
            for x, S, _ in s["rows"]:
                r = " / ".join(f"{S['med'] / refs[lab][x]:.3g}x" if x in refs[lab] else "n/a" for lab in refs)
                parts.append(f"{x}: {r}")
            print(f"  {s['label']} ({' / '.join(refs)}): " + "; ".join(parts))


def band_drawn(s):
    return len(s["rows"]) > 1 and all(S["n"] >= 5 for _, S, _ in s["rows"])


def draw(fig_obj, xlabel, ylabel, unit_div, xticks, figsize, legend_ncol=2, ylim=None, xlim=None, xticklabels=None, xminor=True):
    fig, ax = plt.subplots(figsize=figsize)
    handles = []
    for s in fig_obj.series:
        if not s["rows"]:
            continue
        c, ls, lw, mk, ms, hollow = STY[s["key"]]
        xs = [x for x, _, _ in s["rows"]]
        ys = [S["med"] / unit_div for _, S, _ in s["rows"]]
        kw = dict(color=c, ls=ls, lw=lw, marker=mk, ms=ms, label=s["label"],
                  mfc="white" if hollow else c, mec=c, mew=0.8, zorder=4 if s["key"].startswith("pqz") else 3)
        h, = ax.plot(xs, ys, **kw)
        if band_drawn(s):  # min-max band where n >= 5 at every point of the line (as w19)
            ax.fill_between(xs, [S["lo"] / unit_div for _, S, _ in s["rows"]],
                            [S["hi"] / unit_div for _, S, _ in s["rows"]], color=c, alpha=0.2, lw=0, zorder=1)
        handles.append(h)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    if xticks:
        ax.set_xticks(xticks)
        if xticklabels:
            ax.set_xticklabels(xticklabels)
    if not xminor:
        ax.xaxis.set_minor_locator(NullLocator())
    if xlim:
        ax.set_xlim(*xlim)
    if ylim:
        ax.set_ylim(*ylim)
    ax.yaxis.set_minor_locator(LogLocator(base=10, subs=range(2, 10), numticks=20))
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.grid(True, which="major", lw=0.4, alpha=0.35)
    ax.grid(True, which="minor", lw=0.25, alpha=0.18)
    fig.legend(handles=handles, loc="lower center", ncol=legend_ncol, frameon=False,
               handlelength=2.6, columnspacing=1.0, labelspacing=0.25, borderaxespad=0.2)
    return fig, ax


def save(fig, out, name, legend_rows):
    fig.tight_layout(rect=(0, 0.025 * legend_rows + 0.03, 1, 1), pad=0.4)
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(out, f"{name}.{ext}"), dpi=200)
    plt.close(fig)


# ================================================================ FIG 2 (paper Fig. 2): exp1
def fig1():
    cov = {N: N // 100 for N in NS}
    q = defaultdict(list)
    for r in rd(RES18, "exp1d", "exp1d.csv"):
        if WC.is_timed(r) and r["series"] == "sigma1pct":
            q[int(r["n"])].append(float(r["time_ns"]) / 1e6)
    pqz = []
    for N in NS:
        if N in q:
            pqz.append((N, stat(q[N], "sigma1pct, warmup==0"), "w18/exp1d"))
        else:
            missing.append(f"fig2 PQZ query N={N} (w18/exp1d)")
    dong = base_rows("fig2", "dong", NS, lambda N: ["dong-e1", "dong-e1-c10000"], "proofgen", lambda N: dict(c=cov[N]), RES18, "w18")
    dopiv = base_rows("fig2", "dopiv", NS, lambda N: ["dopiv-e1"], "proofgen", lambda N: dict(c=cov[N], red=None), RES18, "w18")
    dlazy = base_rows("fig2", "dopiv_lazy", NS, lambda N: ["dopiv-lazy-e1"], "proofgen", lambda N: dict(c=cov[N], red="lazy"), RES18, "w18")
    dart = base_rows("fig2", "dart", NS, lambda N: ["dart-e1"], "proofgen_nozk",
                     lambda N: dict(cov=cov[N], D=N // 200, z=max(1, -(-cov[N] // 200))), RES18, "w18")
    lh1, lh32 = [], []
    for N in NS:
        S = lh_or_missing(f"fig2 L-HCPM 1 thread N={N}", RES19, "audit-q", AUDIT, N // 100, 1, 30, missing)
        if S:
            lh1.append((N, S, f"w19/audit-q (q={N // 100})"))
        S = lh_or_missing(f"fig2 L-HCPM 32 threads N={N}", RES, "lhcpm32-audit-q", AUDIT, N // 100, 32, 30, missing)
        if S:
            lh32.append((N, S, f"w20/lhcpm32-audit-q (q={N // 100})"))
    F = Fig("fig_exp1_w20", [
        "Exp 1 (query/proof cost vs number of protected records N). PQZ-Audit and the three other baselines: cloud-w18 session (one instance, one image). L-HCPM 1 thread: cloud-w19 session. L-HCPM 32 threads: cloud-w20 session (third session, same instance type). Medians of non-warm-up runs; ms. Values are not rounded.",
        "PQZ-Audit: query only, sigma_Q = 1 %, results/cloud-w18/exp1d/exp1d.csv (series sigma1pct, warmup==0).",
        "Baselines at coverage cov = 0.01 N records, each its own line: Dong proofgen (c = cov, s=3), DOPIV proofgen (c = cov, m=16384; default reduction and lazy reduction),",
        "DART proofgen_nozk (file = 100 x cov records, so D = N/200 and z = max(1, ceil(cov/200)) as run; no zk proof). Not re-run in w20.",
        "L-HCPM 1 thread (w19, as drawn in work19): audit_hit_q at q = c = 0.01 N audits, cache hit, c different ciphertexts, one audit after another, results/cloud-w19/audit-q (30 runs + 3 warm-up per q).",
        "L-HCPM 32 threads (w20): the same q audits split into 32 contiguous ranges on 32 workers (own rng each, barrier start, every output checked after the timer; independent audits in parallel, no batching), results/cloud-w20/lhcpm32-audit-q (30 runs + 3 warm-up per q). The cache-miss path is NOT run.",
        "Dong: c = 100..5000 use n = 10c (job dong-e1); c = 10000 uses n = 2c = 20000 (job dong-e1-c10000), so the last Dong point has a different n/c ratio.",
        "n_runs = 30 for most cells, 5 for the largest cells; band = min-max where n >= 5 at every point of the line. Baseline proofs are generated by different systems, parameters as in the job params string.",
    ])
    F.add("pqz", "PQZ-Audit query (σ$_Q$=1%)", pqz)
    F.add("dong", "Dong et al. proof gen.", dong)
    F.add("dopiv", "DOPIV proof gen.", dopiv)
    F.add("dopiv_lazy", "DOPIV proof gen. (lazy red.)", dlazy)
    F.add("dart", "DART proof gen. (no zk proof)", dart)
    F.add("lhcpm", "L-HCPM cache hit, 1 thread", lh1)
    F.add("lhcpm32", "L-HCPM cache hit, 32 threads", lh32)
    return F, dict(xlabel="N (protected records)", ylabel="time (ms)", unit_div=1.0, xticks=[1e4, 1e5, 1e6],
                   figsize=(W, 3.55), xlim=(8e3, 1.25e6), rows=4, ref=["PQZ-Audit query (σ$_Q$=1%)"], xname="N records")


# ================================================================ FIG 5 (paper Fig. 5): exp4a
def lh1_points():
    """L-HCPM 1 thread, 7 N_Q points: w19 (1e3, 1e4, 1e5), w20 one run (2e3, 5e3), sums of 4 chunks (2e4, 5e4; optional, tier 2)."""
    pts = {}
    S = lh_or_missing("fig5 L-HCPM 1 thread N_Q=1000", RES19, "mint-N1000-4wide", MINT, 1000, 1, 3, missing)
    if S:
        pts[1000] = (S, "w19/mint-N1000-4wide (3 runs)")
    runs = [lh_or_missing(f"fig5 L-HCPM 1 thread N_Q=10000 run{k}", RES19, f"mint-N10000-run{k}", MINT, 10000, 1, 1, missing) for k in (1, 2, 3)]
    if all(runs):
        v = [r["med"] for r in runs]
        pts[10000] = (stat(v, "median of 3 processes, one run each"), "w19/mint-N10000-run1..3 (3 processes)")
    S = chunk_sum("fig5 L-HCPM 1 thread N_Q=100000", RES19, None, "mint-N100000", 25000, missing, "w19")
    if S:
        pts[100000] = (S, "w19/mint-N100000-chunk1..4 (sum of 4 chunks of 25000)")
    for N in (2000, 5000):
        S = lh_or_missing(f"fig5 L-HCPM 1 thread N_Q={N}", RES, f"lhcpm1-mint-N{N}", MINT, N, 1, 1, missing)
        if S:
            pts[N] = (S, f"w20/lhcpm1-mint-N{N} (1 run)")
    for N, (pre, qc) in TIER2.items():
        S = chunk_sum(f"fig5 L-HCPM 1 thread N_Q={N}", RES, OK20, pre, qc, omitted, "w20")
        if S:
            pts[N] = (S, f"w20/{pre}-chunk1..4 (sum of 4 chunks of {qc})")
    return [(N, pts[N][0], pts[N][1]) for N in NQ if N in pts]


def lh32_points():
    rows = []
    for N in NQ:
        n_exp = 3 if N <= 10000 else 1
        S = lh_or_missing(f"fig5 L-HCPM 32 threads N_Q={N}", RES, f"lhcpm32-mint-N{N}", MINT, N, 32, n_exp, missing)
        if S:
            rows.append((N, S, f"w20/lhcpm32-mint-N{N} ({n_exp} run{'s' if n_exp > 1 else ''})"))
    return rows


def fig2():
    P20 = pqz_scale(RES, "proofbench-scale-w20", NQ, "w20")
    P18 = pqz_scale(RES18, "proofbench-full", [1000, 10000, 100000], "w18")

    def pq(rel_):
        return [(x, P20[(rel_, x)]["S"], P20[(rel_, x)]["job"]) for x in NQ if (rel_, x) in P20]

    dong = base_rows("fig5", "dong", NQ, lambda x: [f"dong-e4a-c{x}"], "proofgen", lambda x: dict(c=x, n=2 * x), RES, "w20")
    dopiv = base_rows("fig5", "dopiv", NQ, lambda x: ["dopiv-e4a"], "proofgen", lambda x: dict(c=x, m=16384, red=None), RES, "w20")
    dlazy = base_rows("fig5", "dopiv_lazy", NQ, lambda x: ["dopiv-lazy-e4a"], "proofgen", lambda x: dict(c=x, m=16384, red="lazy"), RES, "w20")
    dart = base_rows("fig5", "dart", NQ, lambda x: ["dart-e4a"], "proofgen_nozk",
                     lambda x: dict(cov=x, D=5000, z=max(1, -(-x // 200))), RES, "w20")
    lh1, lh32 = lh1_points(), lh32_points()
    F = Fig("fig_exp4a_w20", [
        "Exp 4a (proof generation time vs records covered by the proof N_Q), 7 points per line (1e3, 2e3, 5e3, 1e4, 2e4, 5e4, 1e5). PQZ-Audit, Dong, DOPIV, DART and L-HCPM 32 threads: cloud-w20 session (one instance). L-HCPM 1 thread: w19 points at 1e3, 1e4, 1e5 (second session) and w20 points at 2e3 to 5e4. Medians of non-warm-up runs; ms. Values are not rounded.",
        "PQZ-Audit: R_Exec and R_RC proof generation, rayon default = all logical cores, results/cloud-w20/proofbench-scale-w20/raw.csv (experiment scale, prove_s x 1000, warmup==0). The STARK trace is padded to a power of two (column trace_rows), so the time is a staircase in N_Q, not a smooth curve.",
        "Baselines (w20 e4a jobs, the drivers' own run rule): Dong proofgen (c = N_Q, n = 2c, s=3, one job per c); DOPIV proofgen (c = N_Q, m=16384; default and lazy reduction, one job per system);",
        "DART proofgen_nozk (file of 1e6 records, D = 5000, z = ceil(N_Q/200); its cost follows the file/parameters, not only the coverage; no zk proof).",
        "L-HCPM Mint: N_Q Groth16 proofs of the 2676-constraint stand-in circuit, one after another per worker, witness synthesis inside the timer, fresh randomness per proof, nothing batched.",
        "  32 threads (w20, lhcpm32-mint-N*): T=32 workers on all vCPUs, items in 32 contiguous ranges, barrier start, every output checked after the timer; N_Q <= 1e4: median of 3 runs (+1 warm-up not drawn); N_Q >= 2e4: ONE run (n_runs = 1, no band).",
        "  1 thread: N_Q = 1e3 median of 3 runs (w19 mint-N1000-4wide); 1e4 median of 3 processes (w19 mint-N10000-run1..3); 2e3 and 5e3 one run (w20 lhcpm1-mint-N2000/N5000); 2e4 and 5e4 SUM of 4 chunk jobs (one run each; w20 tier 2); 1e5 SUM of 4 chunks of 25,000 (w19). n_runs = 1 for sums, no band.",
        "n_runs: PQZ-Audit and the baselines follow the drivers' own rule (30 timed runs + 3 warm-up when the first run takes < 60 s, else 5 runs); the exact count of every point is in the column n_runs and in w20_checks.txt part f; band = min-max where n >= 5 at every point of the line.",
    ])
    F.add("pqz", "PQZ-Audit R$_{Exec}$ proof gen.", pq("exec"))
    F.add("pqz_rc", "PQZ-Audit R$_{RC}$ proof gen.", pq("rc"))
    F.add("dong", "Dong et al.", dong)
    F.add("dopiv", "DOPIV", dopiv)
    F.add("dopiv_lazy", "DOPIV (lazy red.)", dlazy)
    F.add("dart", "DART, no zk proof (file 1e6 records)", dart)
    F.add("lhcpm", "L-HCPM Mint, 1 thread", lh1)
    F.add("lhcpm32", "L-HCPM Mint, 32 threads", lh32)
    # w18 values at 1e3, 1e4, 1e5 for the cross-session repeat check (reported, never drawn)
    w18 = {
        "pqz": [(x, P18[("exec", x)]["S"], "w18/proofbench-full") for x in (1000, 10000, 100000) if ("exec", x) in P18],
        "pqz_rc": [(x, P18[("rc", x)]["S"], "w18/proofbench-full") for x in (1000, 10000, 100000) if ("rc", x) in P18],
        "dong": base_rows("w18check", "dong", [1000, 10000, 100000], lambda x: ["dong-e4a", "dong-e4a-c100000"], "proofgen", lambda x: dict(c=x), RES18, "w18"),
        "dopiv": base_rows("w18check", "dopiv", [1000, 10000, 100000], lambda x: ["dopiv-e4a", "dopiv-e4a-c100000"], "proofgen", lambda x: dict(c=x, red=None), RES18, "w18"),
        "dopiv_lazy": base_rows("w18check", "dopiv_lazy", [1000, 10000, 100000], lambda x: ["dopiv-lazy-e4a", "dopiv-lazy-e4a-c100000"], "proofgen", lambda x: dict(c=x, red="lazy"), RES18, "w18"),
        "dart": base_rows("w18check", "dart", [1000, 10000, 100000], lambda x: ["dart-e4a"], "proofgen_nozk",
                          lambda x: dict(cov=x, D=5000, z=max(1, -(-x // 200))), RES18, "w18"),
    }
    xt = ["$10^3$", "$2{\\times}10^3$", "$5{\\times}10^3$", "$10^4$", "$2{\\times}10^4$", "$5{\\times}10^4$", "$10^5$"]
    return F, dict(xlabel="N$_Q$ (records covered by the proof)", ylabel="proof generation time (s)", unit_div=1000.0,
                   xticks=NQ, figsize=(W, 3.55), xlim=(7e2, 1.5e5), rows=4, xticklabels=xt, xminor=False,
                   ref=["PQZ-Audit R$_{Exec}$ proof gen.", "PQZ-Audit R$_{RC}$ proof gen."], xname="N_Q records"), P20, w18


# ================================================================ checks (text + csv)
class Checks:
    def __init__(self):
        self.lines, self.rows = [], []

    def t(self, s=""):
        self.lines.append(s)

    def h(self, title):
        self.lines += ["", "=" * 3 + " " + title]

    def r(self, section, item, x, quantity, value, unit="", note=""):
        v = repr(float(value)) if isinstance(value, float) else str(value)
        self.rows.append([section, item, x, quantity, v, unit, note])


def cpus_count(res, job):
    txt = read_small(res, job, "cpus.txt")
    if txt is None:
        return None, "cpus.txt not found"
    s = txt.strip()
    n = 0
    for tok in s.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, b = tok.split("-", 1)
            n += int(b) - int(a) + 1
        else:
            n += 1
    return n, s


OMIT_MARK = "@@OMITTED@@"
SCALING = (("audit q=10000", lambda T: f"lhcpm-audit-scaling-T{T}", AUDIT, 10000, lambda T: 30),
           ("Mint N_Q=1000", lambda T: f"lhcpm-mint-scaling-T{T}", MINT, 1000, lambda T: 1 if T == 1 else 3))
SPD = {}


def scaling_cells():
    """The 8 speed-up cells (T = 1, 8, 16, 32 for the audit and for Mint); REQUIRED: a wrong row count is a refusal."""
    for item, job_of, stage, q, n_of in SCALING:
        SPD[item] = {}
        for T in TS:
            S, prob = lh_cell(RES, job_of(T), stage, q, T, n_of(T))
            if prob:
                missing.append(f"speed-up {item} T={T}: {prob}")
            else:
                SPD[item][T] = S


def build_checks(F1, F2, P20, w18, kw5):
    C = Checks()
    C.t("w20 CHECKS (cloud-w20: L-HCPM on 32 threads, Fig. 5 with 7 points per line)")
    C.t("values in ms unless said; text = 4 significant digits; w20_checks.csv and the figure CSVs are not rounded; nothing is rescaled or interpolated.")
    C.t("plan: journal2/CLOUD-PLAN-work20.md; script: bench/pqz-eval/analysis/make_figs_w20.py")

    # ---------------- run status
    C.h("RUN STATUS of the w20 results folder (what the pull says)")
    markers = [m for m in ("S1_DONE", "S2_DONE", "S3_DONE", "S4_DONE", "DONE", "TIMEOUT", "SMOKE_FAILED", "BUILD_FAILED", "S4_SKIPPED_no_time",
                           "S3_TIER2_SKIPPED_no_time", "S3_TIER2_DISABLED", "STOPPED_failed_long_job") if os.path.exists(os.path.join(RES.path, m))]
    C.t("markers present: " + (", ".join(markers) if markers else "none"))
    for fn in ("FAILED_JOBS.txt", "NOT_RUN.txt", "RETRIED_JOBS.txt"):
        txt = read_small(RES, None, fn)
        body = txt.strip().replace("\n", " | ") if txt is not None and txt.strip() else ("(empty)" if txt is not None else "(file not present)")
        C.t(f"{fn}: {body}")
    C.r("status", "markers", "", "present", ",".join(markers))
    C.h("POINTS AND CHECKS NOT AVAILABLE (optional jobs missing or failed; not drawn / not computed)")
    C.t(OMIT_MARK)  # replaced in main() after ALL checks ran (parts b and d can add entries)

    # ---------------- (a) speed-up
    C.h("(a) SPEED-UP S(T) = median(T=1, pinned) / median(T); parallel efficiency = S / T")
    C.t("T=1 is pinned to the first physical core; T=8 / 16 to the first 8 / 16 physical cores (one thread per core, no hyper-threading);")
    C.t("T=32 on all 32 vCPUs (16 physical cores x 2). So S(16) = 16 cores without hyper-threading, S(32) adds hyper-threading.")
    spd = {}
    for item, job_of, stage, q, n_of in SCALING:
        C.t(f"{item} (a timed run = {q} {'audits' if stage == AUDIT else 'Mint proofs'}):")
        cells = SPD[item]
        spd[item] = cells
        base = cells[1]["med"]
        for T in TS:
            S = cells[T]
            n_cpu, cpu_txt = cpus_count(RES, job_of(T))
            pin = f"cpus.txt lists {n_cpu} CPU(s)" + ("" if n_cpu == T else f"  ** MISMATCH, expected {T} **") if n_cpu is not None else cpu_txt
            sp = base / S["med"]
            C.t(f"  T={T:<2d}: median {g4(S['med'])} ms (min {g4(S['lo'])}, max {g4(S['hi'])}, n={S['n']}); per item {g4(S['med'] / q)} ms; "
                f"S = {g4(sp)}; efficiency S/T = {g4(sp / T)}; {pin}")
            C.r("a_speedup", item, T, "median_ms", S["med"], "ms", f"n={S['n']}")
            C.r("a_speedup", item, T, "min_ms", S["lo"], "ms")
            C.r("a_speedup", item, T, "max_ms", S["hi"], "ms")
            C.r("a_speedup", item, T, "n_timed_runs", S["n"])
            C.r("a_speedup", item, T, "per_item_ms", S["med"] / q, "ms")
            C.r("a_speedup", item, T, "S", sp, "ratio", "T=1 median / T median")
            C.r("a_speedup", item, T, "efficiency", sp / T, "ratio", "S / T")
            C.r("a_speedup", item, T, "cpus_listed", "" if n_cpu is None else n_cpu, "", cpu_txt if n_cpu is None else "")
    C.t("  note: the Mint T=1 value is ONE run (the plan); the T >= 8 values are medians of 3 runs.")
    S32a, _ = lh_cell(RES, "lhcpm32-audit-q", AUDIT, 10000, 32, 30)
    r = S32a["med"] / spd["audit q=10000"][32]["med"]
    C.t(f"  repeat inside the session, audit q=10000, T=32: lhcpm32-audit-q median {g4(S32a['med'])} ms vs lhcpm-audit-scaling-T32 {g4(spd['audit q=10000'][32]['med'])} ms; ratio {g4(r)} ({pct(r)})")
    C.r("a_speedup", "audit q=10000 repeat T=32", 32, "ratio_lhcpm32-audit-q_over_scaling-T32", r, "ratio")
    S32m, _ = lh_cell(RES, "lhcpm32-mint-N1000", MINT, 1000, 32, 3)
    r = S32m["med"] / spd["Mint N_Q=1000"][32]["med"]
    C.t(f"  repeat inside the session, Mint N_Q=1000, T=32: lhcpm32-mint-N1000 median {g4(S32m['med'])} ms vs lhcpm-mint-scaling-T32 {g4(spd['Mint N_Q=1000'][32]['med'])} ms; ratio {g4(r)} ({pct(r)})")
    C.r("a_speedup", "Mint N_Q=1000 repeat T=32", 32, "ratio_lhcpm32-mint-N1000_over_scaling-T32", r, "ratio")

    # ---------------- (b) bridges
    C.h("(b) BRIDGES: w20 in-session 1-thread values vs the w19 1-thread values (ratio = w20 / w19; nothing rescaled)")
    w19a, _ = lh_cell(RES19, "audit-q", AUDIT, 10000, 1, 30)
    a1 = spd["audit q=10000"][1]
    r = (a1["med"] / 10000) / (w19a["med"] / 10000)
    C.t(f"audit q=10000 per audit: w20 T=1 pinned {g4(a1['med'] / 10000)} ms (n={a1['n']}); w19 audit-q {g4(w19a['med'] / 10000)} ms (n={w19a['n']}); ratio {g4(r)} ({pct(r)})")
    C.r("b_bridge", "audit q=10000 per audit", 1, "w20_T1_ms", a1["med"] / 10000, "ms")
    C.r("b_bridge", "audit q=10000 per audit", 1, "w19_ms", w19a["med"] / 10000, "ms")
    C.r("b_bridge", "audit q=10000 per audit", 1, "ratio_w20_over_w19", r, "ratio")
    w19m, _ = lh_cell(RES19, "mint-N1000-4wide", MINT, 1000, 1, 3)
    m1 = spd["Mint N_Q=1000"][1]
    r = (m1["med"] / 1000) / (w19m["med"] / 1000)
    C.t(f"Mint per proof: w20 T=1 pinned (1 run) {g4(m1['med'] / 1000)} ms; w19 mint-N1000-4wide (median of 3, the value drawn in w19) {g4(w19m['med'] / 1000)} ms; ratio {g4(r)} ({pct(r)})")
    C.r("b_bridge", "Mint per proof N_Q=1000", 1, "w20_T1_ms", m1["med"] / 1000, "ms")
    C.r("b_bridge", "Mint per proof N_Q=1000", 1, "w19_4wide_ms", w19m["med"] / 1000, "ms")
    C.r("b_bridge", "Mint per proof N_Q=1000", 1, "ratio_w20_over_w19_4wide", r, "ratio")
    if "ac-mint-N1000-alone" in OK19:
        w19al, pw = lh_cell(RES19, "ac-mint-N1000-alone", MINT, 1000, 1, 3)
    else:
        w19al, pw = None, reason(RES19, "ac-mint-N1000-alone")
    if w19al:
        r = (m1["med"] / 1000) / (w19al["med"] / 1000)
        C.t(f"   same against w19 ac-mint-N1000-alone (median of 3, alone): {g4(w19al['med'] / 1000)} ms; ratio {g4(r)} ({pct(r)})")
        C.r("b_bridge", "Mint per proof N_Q=1000", 1, "ratio_w20_over_w19_alone", r, "ratio")
    else:
        omitted.append(f"w19 ac-mint-N1000-alone not usable ({pw}): bridge to the alone value not computed")
        C.t("   (w19 ac-mint-N1000-alone not usable: that second bridge is not computed)")
    C.t("Mint, 1 thread, per proof at every N_Q that has a 1-thread point (a flat line = no size effect):")
    for x, S, job in F2.series_dict["lhcpm"]:
        C.t(f"   N_Q={x}: {g4(S['med'] / x)} ms per proof  ({job}; n={S['n']})")
        C.r("b_bridge", "Mint 1 thread per proof", x, "per_proof_ms", S["med"] / x, "ms", job)
    if F2.chunks:
        for N, (vals, qc) in sorted(F2.chunks.items()):
            C.t(f"   chunks of N_Q={N}: " + ", ".join(g4(v) for v in vals) + f" ms; min-max spread {g4(100 * (max(vals) - min(vals)) / (sum(vals) / len(vals)))} % of the mean chunk")
            C.r("b_bridge", f"chunks N_Q={N}", N, "spread_pct_of_mean", 100 * (max(vals) - min(vals)) / (sum(vals) / len(vals)), "%")

    # ---------------- (c) cross-session repeat check
    C.h("(c) CROSS-SESSION REPEAT CHECK: w20 vs w18 at N_Q = 1e3, 1e4, 1e5 (ratio = w20 / w18; the w20 values are the ones drawn)")
    labels = {"pqz": "PQZ-Audit R_Exec", "pqz_rc": "PQZ-Audit R_RC", "dong": "Dong", "dopiv": "DOPIV", "dopiv_lazy": "DOPIV lazy", "dart": "DART (no zk)"}
    for key, lab in labels.items():
        w20 = F2.fig.by_key(key)
        for x, S18, job in w18[key]:
            if x not in w20:
                continue
            r = w20[x]["med"] / S18["med"]
            C.t(f"  {lab:18s} N_Q={x:<6d}: w20 {g4(w20[x]['med'])} (n={w20[x]['n']})  w18 {g4(S18['med'])} (n={S18['n']}, {job})  ratio {g4(r)} ({pct(r)})")
            C.r("c_cross_session", lab, x, "w20_median_ms", w20[x]["med"], "ms", f"n={w20[x]['n']}")
            C.r("c_cross_session", lab, x, "w18_median_ms", S18["med"], "ms", f"n={S18['n']} {job}")
            C.r("c_cross_session", lab, x, "ratio_w20_over_w18", r, "ratio")

    # ---------------- (d) contention
    C.h(f"(d) CONTENTION: alone-check (ac-*, run alone on pin 0) vs the S3 job of the same cell (4 jobs at once); ratio = S3 / alone; flag if > {CONTENTION_FLAG}")
    cont = []
    pairs = [("ac-dong", "dong-e4a-c1000", ("proofgen", "verify"), dict(c=1000, n=2000)),
             ("ac-dart", "dart-e4a", ("proofgen_nozk", "verify_nozk"), dict(cov=1000, D=5000)),
             ("ac-dopiv", "dopiv-e4a", ("proofgen", "verify"), dict(c=1000, m=16384, red=None))]
    for ac, s3, stages, want in pairs:
        if ac not in OK20:
            msg = f"{ac}: {reason(RES, ac)} (alone-check not available)"
            C.t("  - " + msg)
            omitted.append(msg)
            continue
        for stg in stages:
            A = pick(baseline_cells(RES, ac, stg), **want)
            B = pick(baseline_cells(RES, s3, stg), **want)
            if not A or not B:
                msg = f"{ac} vs {s3} stage {stg}: cell not found (want {want})"
                C.t("  - " + msg)
                omitted.append(msg)
                continue
            cont.append((f"{ac} vs {s3} {stg}", B["med"], A["med"], B["n"], A["n"]))
    if "ac-lhcpm1-mint-N2000" in OK20:
        A, p1 = lh_cell(RES, "ac-lhcpm1-mint-N2000", MINT, 2000, 1, 1)
        B, p2 = lh_cell(RES, "lhcpm1-mint-N2000", MINT, 2000, 1, 1)
        if A and B:
            cont.append(("ac-lhcpm1-mint-N2000 vs lhcpm1-mint-N2000 groth16_prove_mint_q", B["med"], A["med"], 1, 1))
        else:
            msg = f"ac-lhcpm1-mint-N2000 vs lhcpm1-mint-N2000: {p1 or p2}"
            C.t("  - " + msg)
            omitted.append(msg)
    else:
        msg = f"ac-lhcpm1-mint-N2000: {reason(RES, 'ac-lhcpm1-mint-N2000')} (alone-check not available)"
        C.t("  - " + msg)
        omitted.append(msg)
    over = False
    for name, s3v, alv, ns3, nal in cont:
        r = s3v / alv
        flag = r > CONTENTION_FLAG
        over = over or flag
        C.t(f"  {name}: S3 {g4(s3v)} ms (n={ns3}); alone {g4(alv)} ms (n={nal}); S3/alone = {g4(r)} ({pct(r)}){'   ** FLAG: above ' + str(CONTENTION_FLAG) + ' **' if flag else ''}")
        C.r("d_contention", name, "", "s3_median_ms", s3v, "ms", f"n={ns3}")
        C.r("d_contention", name, "", "alone_median_ms", alv, "ms", f"n={nal}")
        C.r("d_contention", name, "", "ratio_s3_over_alone", r, "ratio", "FLAG>1.05" if flag else "")
    if cont:
        C.t("  RESULT: " + ("at least one ratio is above 1.05: the paper says so (contention slows the baselines, which favours PQZ-Audit)." if over
                            else "no ratio above 1.05."))
        C.r("d_contention", "summary", "", "any_ratio_above_1.05", "yes" if over else "no")

    # ---------------- (e) ratios the paper needs
    C.h("(e) RATIOS THE PAPER NEEDS")
    C.t("Fig. 2: time of c = N/100 audits (ms); ratio = L-HCPM / PQZ-Audit query (how many times PQZ-Audit is faster); S_pt = 1 thread / 32 threads at the same N")
    C.t("  (the 1-thread line is the w19 session, the 32-thread line the w20 session: S_pt crosses sessions; the in-session S(T) is in part a)")
    pq1, l1, l32 = F1.fig.by_key("pqz"), F1.fig.by_key("lhcpm"), F1.fig.by_key("lhcpm32")
    for N in NS:
        parts = [f"  N={N:<8d} q=c={N // 100:<6d}"]
        if N in pq1:
            parts.append(f"PQZ query {g4(pq1[N]['med'])}")
            C.r("e_fig2", "PQZ-Audit query", N, "median_ms", pq1[N]["med"], "ms")
        if N in l1:
            parts.append(f"L-HCPM 1T {g4(l1[N]['med'])}")
            C.r("e_fig2", "L-HCPM cache hit 1 thread", N, "median_ms", l1[N]["med"], "ms")
        if N in l32:
            parts.append(f"L-HCPM 32T {g4(l32[N]['med'])}")
            C.r("e_fig2", "L-HCPM cache hit 32 threads", N, "median_ms", l32[N]["med"], "ms")
        if N in pq1 and N in l1:
            parts.append(f"1T/PQZ {g4(l1[N]['med'] / pq1[N]['med'])}x")
            C.r("e_fig2", "ratio", N, "L-HCPM_1T_over_PQZ", l1[N]["med"] / pq1[N]["med"], "ratio")
        if N in pq1 and N in l32:
            parts.append(f"32T/PQZ {g4(l32[N]['med'] / pq1[N]['med'])}x")
            C.r("e_fig2", "ratio", N, "L-HCPM_32T_over_PQZ", l32[N]["med"] / pq1[N]["med"], "ratio")
        if N in l1 and N in l32:
            parts.append(f"S_pt {g4(l1[N]['med'] / l32[N]['med'])}")
            C.r("e_fig2", "ratio", N, "L-HCPM_1T_over_32T", l1[N]["med"] / l32[N]["med"], "ratio")
        C.t("; ".join(parts))
    C.t("Fig. 5: proof generation of N_Q records (ms); ratios = L-HCPM Mint / PQZ-Audit (R_Exec, R_RC); S_pt = 1 thread / 32 threads")
    ex, rc, m1t, m32 = F2.fig.by_key("pqz"), F2.fig.by_key("pqz_rc"), F2.fig.by_key("lhcpm"), F2.fig.by_key("lhcpm32")
    for N in NQ:
        parts = [f"  N_Q={N:<7d}"]
        for lab, d in (("R_Exec", ex), ("R_RC", rc), ("L-HCPM 1T", m1t), ("L-HCPM 32T", m32)):
            if N in d:
                parts.append(f"{lab} {g4(d[N]['med'])}")
                C.r("e_fig5", lab, N, "median_ms", d[N]["med"], "ms")
        for lab, num, den in (("32T/R_Exec", m32, ex), ("32T/R_RC", m32, rc), ("1T/R_Exec", m1t, ex), ("1T/R_RC", m1t, rc), ("S_pt 1T/32T", m1t, m32)):
            if N in num and N in den:
                rr = num[N]["med"] / den[N]["med"]
                parts.append(f"{lab} {g4(rr)}x")
                C.r("e_fig5", "ratio", N, lab.replace("/", "_over_").replace(" ", "_"), rr, "ratio")
        C.t("; ".join(parts))
    C.t("  S_pt at N_Q = 1e3, 1e4, 1e5 mixes sessions (1 thread from w19, 32 threads from w20); at 2e3, 5e3, 2e4, 5e4 both are w20.")
    C.t("Fig. 5: the other baselines against PQZ-Audit (baseline median / R_Exec median):")
    for key, lab in (("dong", "Dong"), ("dopiv", "DOPIV"), ("dopiv_lazy", "DOPIV lazy"), ("dart", "DART (no zk)")):
        d = F2.fig.by_key(key)
        C.t(f"  {lab:12s}: " + "; ".join(f"{N}: {g4(d[N]['med'] / ex[N]['med'])}x" for N in NQ if N in d and N in ex))
        for N in NQ:
            if N in d and N in ex:
                C.r("e_fig5", "ratio", N, f"{lab}_over_R_Exec".replace(" ", "_"), d[N]["med"] / ex[N]["med"], "ratio")
    C.t("  where is the baseline FASTER than PQZ-Audit (ratio < 1 above = the PQZ-Audit line lies ABOVE the baseline line in Fig. 5)?")
    C.t("  this decides the sentence 'PQZ-Audit proof generation above DOPIV at every coverage and above DART at 1e5 records' (plan rule 7):")
    for k, lab in (("dong", "Dong"), ("dopiv", "DOPIV"), ("dopiv_lazy", "DOPIV lazy"), ("dart", "DART (no zk)")):
        d = F2.fig.by_key(k)
        for rl, ref in (("R_Exec", ex), ("R_RC", rc)):
            xs = [N for N in NQ if N in d and N in ref and d[N]["med"] < ref[N]["med"]]
            C.t(f"    {lab:12s} faster than PQZ-Audit {rl}: " + (", ".join(str(N) for N in xs) if xs else "at no N_Q drawn"))
            C.r("e_fig5", f"{lab} faster than {rl}", "", "N_Q_list", " ".join(str(N) for N in xs) if xs else "none")

    # ---------------- (f) run counts
    C.h("(f) RUN COUNTS per drawn point (n = timed rows in the csv; planned = runs= in params or the proofbench rule; band = min-max band drawn on the line)")
    for F in (F1.fig, F2.fig):
        C.t(f"{F.name}:")
        for s in F.series:
            C.t(f"  {s['label']}" + ("   [band drawn]" if band_drawn(s) else ""))
            for x, S, job in s["rows"]:
                C.t(f"     x={x}: n={S['n']}; {S['info']}; {job}")
                C.r("f_run_counts", f"{F.name} | {s['label']}", x, "n_timed_runs", S["n"], "", f"{S['info']} | {job}")
    C.t("PQZ-Audit proofbench rows (w20): warm-up rows present in raw.csv (warmup=1) and the rule text, per rel and N_Q:")
    for (rel_, x), d in sorted(P20.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        C.t(f"  {rel_:5s} N_Q={x:<7d}: timed n={d['S']['n']}; warm-up rows {d['warm']}; rule: {'; '.join(d['rule'])}")
        C.r("f_run_counts", f"proofbench {rel_}", x, "warmup_rows", d["warm"], "", "; ".join(d["rule"]))

    # ---------------- (g) padded trace rows
    C.h("(g) PADDED STARK TRACE ROWS per N_Q (column trace_rows of proofbench-scale-w20; time is a staircase in N_Q)")
    prev = None
    for x in NQ:
        te, tr = P20.get(("exec", x)), P20.get(("rc", x))
        if not te or not tr:
            continue
        rows_e, rows_r = te["trace"], tr["trace"]
        line = f"  N_Q={x:<7d}: trace_rows exec {','.join(rows_e)}; rc {','.join(rows_r)}"
        ok_one = len(rows_e) == 1 and len(rows_r) == 1 and rows_e[0].isdigit() and rows_r[0].isdigit()
        if ok_one:
            re_ = int(rows_e[0])
            line += f"; rows / N_Q = {g4(re_ / x)}"
            if len(rows_e) == 1 and rows_e != rows_r:
                line += "  ** exec and rc differ **"
            if prev:
                px, pre_, pte, ptr = prev
                line += (f"; vs N_Q={px}: N_Q x{g4(x / px)}, rows x{g4(re_ / pre_)}, R_Exec time x{g4(te['S']['med'] / pte)}, "
                         f"R_RC time x{g4(tr['S']['med'] / ptr)}")
                C.r("g_trace_rows", "step", x, "N_Q_ratio", x / px, "ratio", f"vs {px}")
                C.r("g_trace_rows", "step", x, "rows_ratio", re_ / pre_, "ratio", f"vs {px}")
                C.r("g_trace_rows", "step", x, "R_Exec_time_ratio", te["S"]["med"] / pte, "ratio", f"vs {px}")
                C.r("g_trace_rows", "step", x, "R_RC_time_ratio", tr["S"]["med"] / ptr, "ratio", f"vs {px}")
            prev = (x, re_, te["S"]["med"], tr["S"]["med"])
        else:
            line += "  (trace_rows empty, not numeric or not unique: not used)"
        C.t(line)
        C.r("g_trace_rows", "exec", x, "trace_rows", ",".join(rows_e))
        C.r("g_trace_rows", "rc", x, "trace_rows", ",".join(rows_r))
    C.t("  the fill (used rows / padded rows) quoted in the plan is NOT a column of the csv and is not computed here.")
    return C


# ================================================================ main
if __name__ == "__main__":
    f1 = fig1()
    f2 = fig2()
    scaling_cells()
    if missing:
        print("REFUSING: cells needed by the figures are missing or wrong, nothing written:", file=sys.stderr)
        for m in sorted(set(missing)):
            print("  - " + m, file=sys.stderr)
        sys.exit(2)
    (F1, kw1) = f1
    (F2, kw2, P20, w18) = f2

    class _F:  # small holder so build_checks can reach the figure object and the chunk data
        pass

    h1, h2 = _F(), _F()
    h1.fig = F1
    h2.fig = F2
    h2.series_dict = {"lhcpm": [r for s in F2.series if s["key"] == "lhcpm" for r in s["rows"]]}
    h2.chunks = {}
    for N, (pre, qc) in TIER2.items():
        for x, S, _ in h2.series_dict["lhcpm"]:
            if x == N and "chunks" in S:
                h2.chunks[N] = (S["chunks"], qc)
    for x, S, _ in h2.series_dict["lhcpm"]:
        if x == 100000 and "chunks" in S:
            h2.chunks[100000] = (S["chunks"], 25000)
    C = build_checks(h1, h2, P20, w18, kw2)

    out = WC.out_dir(args.out, OUT_DEFAULT)
    cdir = WC.out_dir(args.checks_out, CHECKS_DEFAULT)
    # input list (complete only now: every file was read by this point)
    i = C.lines.index(OMIT_MARK)
    if omitted:
        C.lines[i:i + 1] = ["  - " + o for o in dict.fromkeys(omitted)]
        for o in dict.fromkeys(omitted):
            C.r("omitted", "optional", "", "reason", o)
    else:
        C.lines[i:i + 1] = ["  none: every optional job was present and usable"]
    C.h("INPUT FILES (path, sha256 first 16 hex): every raw file this script read")
    for p in sorted(INPUTS):
        C.t(f"  {INPUTS[p]}  {rel(p)}")
        C.r("inputs", rel(p), "", "sha256_16", INPUTS[p])
    C.t("")
    C.t(f"w20 folder: {rel(RES.path)}; w19 folder: {rel(RES19.path)}; w18 folder: {rel(RES18.path)}")
    txt = "\n".join(C.lines) + "\n"
    with open(os.path.join(cdir, "w20_checks.txt"), "w") as f:
        f.write(txt)
    with open(os.path.join(cdir, "w20_checks.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["section", "item", "x", "quantity", "value", "unit", "note"])
        w.writerows(C.rows)
    print(txt)
    for F, kw in ((F1, kw1), (F2, kw2)):
        F.write_csv(out)
        F.print_table(kw["ref"], kw["xname"])
        fig, ax = draw(F, kw["xlabel"], kw["ylabel"], kw["unit_div"], kw["xticks"], kw["figsize"], xlim=kw["xlim"],
                       xticklabels=kw.get("xticklabels"), xminor=kw.get("xminor", True))
        save(fig, out, F.name, kw["rows"])
    print("\nREQUIRED CELLS MISSING: none")
    print("OPTIONAL POINTS / CHECKS NOT AVAILABLE: " + ("none" if not omitted else f"{len(omitted)} (listed in w20_checks.txt)"))
    for o in omitted:
        print("  - " + o)
    print("figures written to", out)
    print("checks written to", cdir)
