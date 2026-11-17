#!/usr/bin/env python3
"""Draw fig_exp1_w19 and fig_exp4a_w19 (all lines solid): the w18 figures with the L-HCPM lines at MATCHED COVERAGE.

Usage: .venv-bench/bin/python -I bench/pqz-eval/analysis/make_figs_w19.py [--results18 DIR] [--results19 DIR] [--out DIR]
  results18: default bench/pqz-eval/results/cloud-w18 (PQZ-Audit, Dong, DOPIV, DART lines: unchanged from make_figs_w18.py)
  results19: default bench/pqz-eval/results/cloud-w19 (L-HCPM lines only; second cloud session, see journal2/CLOUD-PLAN-work19.md)
  out:       default journal2/figures/results-w19
Rules (written before any w19 number was seen, CLOUD-PLAN-work19.md):
  * Fig. 2 (exp1): L-HCPM cache hit = median of 30 runs of audit_hit_q at q = c = 0.01 N audits (c distinct ciphertexts, one after another).
  * Fig. 5 (exp4a): L-HCPM Mint at N_Q = 1e3: median of the 3 runs of mint-N1000-4wide; at 1e4: median of the 3 processes
    mint-N10000-run1..3; at 1e5: the SUM of the 4 chunks of 25,000 proofs (one run in four pieces, so no band).
  * Every run is kept. A missing job or cell makes the script refuse (exit 2) before anything is drawn.
  * The bridge check (q=1 against w18), the contention check (alone against 4-wide) and the chunk spread are printed and written to
    analysis/out-w19/lhcpm_w19_checks.txt. No value is rescaled.
The cache-miss path of L-HCPM (SamplePre/TrapGen) is NOT measured and not drawn.
Writes: .pdf, .png (200 dpi) and .csv per figure.
"""
import argparse
import csv
import os
import statistics as st
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import w18_common as WC  # noqa: E402

import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import LogLocator, NullFormatter  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--results18")
ap.add_argument("--results19")
ap.add_argument("--out")
args = ap.parse_args()
RES = WC.Results(WC.results_dir(args.results18))
RES19 = WC.Results(WC.results_dir(args.results19 or os.path.join(WC.BASE, "results", "cloud-w19")))
OUT = WC.out_dir(args.out, os.path.join(WC.ROOT, "journal2", "figures", "results-w19"))
CHECKS_DIR = WC.out_dir(None, os.path.join(WC.BASE, "analysis", "out-w19"))

# ---------------------------------------------------------------- style (as the w18 figures)
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
STY = {  # key: color, linestyle, linewidth, marker, markersize, hollow
    "pqz":       (BLUE, "-", 1.4, "o", 3.6, False),
    "pqz_rc":    (SKY, "-", 1.4, "s", 3.4, False),
    "dong":      (GREY, "-", 1.0, "s", 3.0, False),
    "dopiv":     (ORANGE, "-", 1.0, "^", 3.2, False),
    "dopiv_lazy": (ORANGE, "-", 0.7, "v", 3.0, True),
    "dart":      (GREEN, "-", 1.0, "D", 2.6, False),
    "lhcpm":     (PINK, "-", 1.0, "x", 3.4, False),
}

# ---------------------------------------------------------------- what is needed (refuse before drawing)
NEED = [("exp1d", "exp1d.csv"), ("proofbench-full", "raw.csv")]
NEED += [(j, "raw_runs.csv") for j in ("dong-e1", "dong-e1-c10000", "dopiv-e1", "dopiv-lazy-e1", "dart-e1",
                                       "dong-e4a", "dong-e4a-c100000", "dopiv-e4a", "dopiv-e4a-c100000",
                                       "dopiv-lazy-e4a", "dopiv-lazy-e4a-c100000", "dart-e4a",
                                       "lhcpm")]  # lhcpm: only the q=1 cache hit of w18 (bridge check)
RES.preflight(NEED)
NEED19 = [(j, "raw_runs.csv") for j in ("audit-q", "mint-N1000-4wide", "ac-mint-N1000-alone",
                                        "mint-N10000-run1", "mint-N10000-run2", "mint-N10000-run3",
                                        "mint-N100000-chunk1", "mint-N100000-chunk2",
                                        "mint-N100000-chunk3", "mint-N100000-chunk4")]
RES19.preflight(NEED19)

missing = []


def baseline_cells(job, stage, res=None):
    """-> list of (params_dict, [ms...]) for one raw_runs.csv and stage."""
    g = defaultdict(list)
    for r in (res or RES).rd(job, "raw_runs.csv"):
        if r["stage"] == stage:
            g[r["params"]].append(float(r["ms"]))
    return [(WC.parse_params(k)[0], v) for k, v in g.items()]


def stat(v):
    return dict(med=st.median(v), lo=min(v), hi=max(v), n=len(v))


def pick(cells, **want):
    """Return the unique cell whose params match want (str compare); a want value None = key absent."""
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
            hit.append(v)
    if len(hit) == 1:
        return stat(hit[0])
    return None


class Fig:
    def __init__(self, name, header):
        self.name, self.header = name, header
        self.series = []  # dict(key,label,rows=[(x,stat,job)])

    def add(self, key, label, rows, kind="meas"):
        self.series.append(dict(key=key, label=label, rows=rows, kind=kind))

    def write_csv(self):
        with open(os.path.join(OUT, self.name + ".csv"), "w", newline="") as f:
            for line in self.header:
                f.write("# " + line + "\n")
            w = csv.writer(f)
            w.writerow(["figure", "series", "x", "median_ms", "min_ms", "max_ms", "n_runs", "source_job"])
            for s in self.series:
                for x, S, job in s["rows"]:
                    w.writerow([self.name, s["label"], x, f"{S['med']:.6g}", f"{S['lo']:.6g}",
                                f"{S['hi']:.6g}", S["n"], job])

    def print_table(self, ref_labels, xname):
        print(f"\n=== {self.name}: x = {xname}; median ms (n)")
        for s in self.series:
            print(f"  {s['label']}: " + "; ".join(f"{x}: {S['med']:.4g} (n={S['n']})" for x, S, _ in s["rows"]))
        print("  ratio to PQZ-Audit at the same x (baseline median / PQZ median):")
        refs = {lab: {x: S["med"] for x, S, _ in s["rows"]} for s in self.series
                for lab in ref_labels if s["label"] == lab}
        for s in self.series:
            if s["label"] in ref_labels:
                continue
            parts = []
            for x, S, _ in s["rows"]:
                r = " / ".join(f"{S['med'] / refs[lab][x]:.3g}x" if x in refs[lab] else "n/a" for lab in refs)
                parts.append(f"{x}: {r}")
            print(f"  {s['label']} ({' / '.join(refs)}): " + "; ".join(parts))


def draw(fig_obj, xlabel, ylabel, unit_div, xticks, figsize, legend_ncol=2, ylim=None, xlim=None):
    fig, ax = plt.subplots(figsize=figsize)
    handles = []
    for s in fig_obj.series:
        c, ls, lw, mk, ms, hollow = STY[s["key"]]
        xs = [x for x, _, _ in s["rows"]]
        ys = [S["med"] / unit_div for _, S, _ in s["rows"]]
        kw = dict(color=c, ls=ls, lw=lw, marker=mk, ms=ms, label=s["label"],
                  mfc="white" if hollow else c, mec=c, mew=0.8, zorder=4 if s["key"].startswith("pqz") else 3)
        h, = ax.plot(xs, ys, **kw)
        # min-max band where n >= 5 at every point of the line
        if len(xs) > 1:
            idx = [i for i, (_, S, _) in enumerate(s["rows"]) if S["n"] >= 5]
            if len(idx) == len(xs):
                ax.fill_between(xs, [S["lo"] / unit_div for _, S, _ in s["rows"]],
                                [S["hi"] / unit_div for _, S, _ in s["rows"]], color=c, alpha=0.2, lw=0, zorder=1)
        handles.append(h)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    if xticks:
        ax.set_xticks(xticks)
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


def save(fig, name, legend_rows):
    fig.tight_layout(rect=(0, 0.025 * legend_rows + 0.03, 1, 1), pad=0.4)
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(OUT, f"{name}.{ext}"), dpi=200)
    plt.close(fig)


def base_rows(figtag, label_key, xs, jobs, stage, extra):
    """One baseline line: for every x the first job of `jobs` that has the cell; else the cell is reported missing."""
    rows = []
    for x in xs:
        S = used = None
        for job in jobs:
            S = pick(baseline_cells(job, stage), **extra(x))
            if S:
                used = job
                break
        if S:
            rows.append((x, S, used))
        else:
            missing.append(f"{figtag} {label_key} x={x} (jobs {jobs}, stage {stage}, want {extra(x)})")
    return rows


# ================================================================ L-HCPM, second session (w19)
def lhcpm_cache_hit(Ns):
    """Cache hit at q = c = N/100 audits: median of the 30 runs of audit_hit_q (w19, job audit-q)."""
    cells = baseline_cells("audit-q", "audit_hit_q", RES19)
    rows = []
    for N in Ns:
        S = pick(cells, q=N // 100)
        if S and S["n"] == 30:
            rows.append((N, S, "audit-q (w19, q=%d)" % (N // 100)))
        else:
            missing.append(f"fig1 L-HCPM audit_hit_q q={N // 100} (need 30 runs, got {S['n'] if S else 'none'})")
    return rows


def mint_cells():
    """-> dict with the drawn Mint values (ms) and every raw value, from the w19 jobs."""
    ms = lambda job: [float(r["ms"]) for r in RES19.rd(job, "raw_runs.csv") if r["stage"] == "groth16_prove_mint_q"]  # noqa: E731
    out = {}
    four = ms("mint-N1000-4wide")
    alone = ms("ac-mint-N1000-alone")
    runs4 = [ms(f"mint-N10000-run{k}") for k in (1, 2, 3)]
    chunks = [ms(f"mint-N100000-chunk{k}") for k in (1, 2, 3, 4)]
    problems = []
    if len(four) != 3:
        problems.append(f"mint-N1000-4wide: {len(four)} rows, need 3")
    if len(alone) != 3:
        problems.append(f"ac-mint-N1000-alone: {len(alone)} rows, need 3")
    if any(len(v) != 1 for v in runs4):
        problems.append("mint-N10000-run*: need one row each")
    if any(len(v) != 1 for v in chunks):
        problems.append("mint-N100000-chunk*: need one row each")
    if problems:
        for p in problems:
            missing.append("fig2 L-HCPM Mint " + p)
        return None
    out["four"], out["alone"] = four, alone
    out["runs4"] = [v[0] for v in runs4]
    out["chunks"] = [v[0] for v in chunks]
    return out


def write_checks(M, hit_rows):
    """Bridge check, contention check, chunk spread: text file + stdout. No rescaling."""
    lines = []
    w18_hit = pick(baseline_cells("lhcpm", "audit_hit_q"), q=1)
    w19_q1 = pick(baseline_cells("audit-q", "audit_hit_q", RES19), q=1)
    lines.append("w19 L-HCPM matched-coverage run: checks (values in ms unless said)")
    lines.append("")
    lines.append("BRIDGE (q=1 cache hit): w19 audit-q q=1 median %.4f (min %.4f, max %.4f, n=%d); w18 lhcpm audit_hit_q q=1 median %.4f (n=%d); "
                 "w19/w18 = %.4f" % (w19_q1["med"], w19_q1["lo"], w19_q1["hi"], w19_q1["n"], w18_hit["med"], w18_hit["n"],
                                    w19_q1["med"] / w18_hit["med"]))
    lines.append("  note: w19 q=1 audits walk through 10,000 distinct ciphertexts; the w18 q<=200 audits used 16-200 instances.")
    lines.append("")
    lines.append("CACHE HIT PER AUDIT (median / q): " + "; ".join(
        "q=%d: %.4f ms" % (int(j.split("q=")[1].rstrip(")")), S["med"] / int(j.split("q=")[1].rstrip(")"))) for _, S, j in hit_rows))
    lines.append("  every q (all 11 points) per audit: " + "; ".join(
        "q=%d: %.4f" % (int(p["q"]), st.median(v) / int(p["q"])) for p, v in sorted(baseline_cells("audit-q", "audit_hit_q", RES19), key=lambda t: int(t[0]["q"]))))
    lines.append("")
    four, alone = st.median(M["four"]), st.median(M["alone"])
    lines.append("CONTENTION (Mint, 1000 proofs, 3 runs + 1 warm-up each): 4-wide median %.1f ms (runs %s); alone median %.1f ms (runs %s); "
                 "4-wide / alone = %.5f, alone / 4-wide = %.5f" % (
                     four, ", ".join("%.1f" % x for x in M["four"]), alone, ", ".join("%.1f" % x for x in M["alone"]),
                     four / alone, alone / four))
    lines.append("  the 4-wide value is the one drawn; contention would make it LARGER than the alone value.")
    lines.append("")
    c = M["chunks"]
    lines.append("MINT N_Q=1e5: 4 chunks of 25,000 proofs: %s ms; sum %.1f ms = %.1f s = %.2f h; per proof %.4f ms; chunk min-max spread %.3f %% of the mean chunk" % (
        ", ".join("%.1f" % x for x in c), sum(c), sum(c) / 1000.0, sum(c) / 3.6e6, sum(c) / 1e5,
        100.0 * (max(c) - min(c)) / (sum(c) / 4.0)))
    r = M["runs4"]
    lines.append("MINT N_Q=1e4: 3 processes: %s ms; median %.1f ms = %.1f s; per proof %.4f ms; min-max spread %.3f %% of the median" % (
        ", ".join("%.1f" % x for x in r), st.median(r), st.median(r) / 1000.0, st.median(r) / 1e4,
        100.0 * (max(r) - min(r)) / st.median(r)))
    lines.append("MINT N_Q=1e3: median %.1f ms = %.1f s; per proof %.4f ms; min-max spread %.3f %% of the median" % (
        four, four / 1000.0, four / 1e3, 100.0 * (max(M['four']) - min(M['four'])) / four))
    lines.append("MINT per proof, w19 (1e3 / 1e4 / 1e5): %.4f / %.4f / %.4f ms; w18 single proof (lhcpm-full groth16_prove_mint): %.4f ms" % (
        four / 1e3, st.median(r) / 1e4, sum(c) / 1e5,
        st.median([float(x["ms"]) for x in RES.rd("lhcpm-full", "raw_runs.csv") if x["stage"] == "groth16_prove_mint"])))
    txt = "\n".join(lines) + "\n"
    with open(os.path.join(CHECKS_DIR, "lhcpm_w19_checks.txt"), "w") as f:
        f.write(txt)
    print(txt)


# ================================================================ FIG 1 (paper Fig. 2)
def fig1():
    Ns = [10000, 20000, 50000, 100000, 200000, 500000, 1000000]
    cov = {N: N // 100 for N in Ns}
    q = defaultdict(list)
    for r in RES.rd("exp1d", "exp1d.csv"):
        if WC.is_timed(r) and r["series"] == "sigma1pct":
            q[int(r["n"])].append(float(r["time_ns"]) / 1e6)
    pqz = []
    for N in Ns:
        if N in q:
            pqz.append((N, stat(q[N]), "exp1d"))
        else:
            missing.append(f"fig1 PQZ N={N}")
    dong = base_rows("fig1", "dong", Ns, ["dong-e1", "dong-e1-c10000"], "proofgen", lambda N: dict(c=cov[N]))
    dopiv = base_rows("fig1", "dopiv", Ns, ["dopiv-e1"], "proofgen", lambda N: dict(c=cov[N], red=None))
    dlazy = base_rows("fig1", "dopiv_lazy", Ns, ["dopiv-lazy-e1"], "proofgen", lambda N: dict(c=cov[N], red="lazy"))
    dart = base_rows("fig1", "dart", Ns, ["dart-e1"], "proofgen_nozk",
                     lambda N: dict(cov=cov[N], D=N // 200, z=max(1, -(-cov[N] // 200))))
    lh = lhcpm_cache_hit(Ns)
    F = Fig("fig_exp1_w19", [
        "Exp 1 (query/proof cost vs number of protected records N). PQZ-Audit and the three other baselines: cloud-w18 session (one instance, one image). L-HCPM: cloud-w19 session (second session, same instance type). Medians of non-warm-up runs; ms.",
        "PQZ-Audit: query only, sigma_Q = 1 %, results/cloud-w18/exp1d/exp1d.csv (series sigma1pct, warmup==0).",
        "Baselines at coverage cov = 0.01 N records, each its own line: Dong proofgen (c = cov, s=3), DOPIV proofgen (c = cov, m=16384; default reduction and lazy reduction),",
        "DART proofgen_nozk (file = 100 x cov records, so D = N/200 and z = max(1, ceil(cov/200)) as run; no zk proof).",
        "L-HCPM (w19): audit_hit_q at q = c = 0.01 N audits, cache hit, c different ciphertexts, one audit after another, single thread, results/cloud-w19/audit-q (30 runs + 3 warm-up per q). The cache-miss path is NOT run.",
        "Dong: c = 100..5000 use n = 10c (job dong-e1); c = 10000 uses n = 2c = 20000 (job dong-e1-c10000), so the last Dong point has a different n/c ratio.",
        "n_runs = 30 for most cells, 5 for the largest cells; band = min-max where n >= 5 at every point of the line. Baseline proofs are generated by different systems, parameters as in the job params string.",
    ])
    F.add("pqz", "PQZ-Audit query (σ$_Q$=1%)", pqz)
    F.add("dong", "Dong et al. proof gen.", dong)
    F.add("dopiv", "DOPIV proof gen.", dopiv)
    F.add("dopiv_lazy", "DOPIV proof gen. (lazy red.)", dlazy)
    F.add("dart", "DART proof gen. (no zk proof)", dart)
    F.add("lhcpm", "L-HCPM cache hit, $c$ audits (one by one)", lh)
    return F, dict(xlabel="N (protected records)", ylabel="time (ms)", unit_div=1.0, xticks=[1e4, 1e5, 1e6],
                   figsize=(W, 3.55), xlim=(8e3, 1.25e6), rows=4, ref=["PQZ-Audit query (σ$_Q$=1%)"], xname="N records")


# ================================================================ FIG 2 (paper Fig. 5)
def fig2():
    NQ = [1000, 10000, 100000]
    sc = defaultdict(list)
    for r in RES.rd("proofbench-full", "raw.csv"):
        if WC.is_timed(r) and r["experiment"] == "scale" and r["rel"] in ("exec", "rc"):
            sc[(r["rel"], int(r["n_records"]))].append(float(r["prove_s"]) * 1000.0)

    def pq(rel):
        rows = []
        for x in NQ:
            if (rel, x) in sc:
                rows.append((x, stat(sc[(rel, x)]), "proofbench-full"))
            else:
                missing.append(f"fig2 PQZ {rel} N_Q={x}")
        return rows

    dong = base_rows("fig2", "dong", NQ, ["dong-e4a", "dong-e4a-c100000"], "proofgen", lambda x: dict(c=x))
    dopiv = base_rows("fig2", "dopiv", NQ, ["dopiv-e4a", "dopiv-e4a-c100000"], "proofgen", lambda x: dict(c=x, red=None))
    dlazy = base_rows("fig2", "dopiv_lazy", NQ, ["dopiv-lazy-e4a", "dopiv-lazy-e4a-c100000"], "proofgen",
                      lambda x: dict(c=x, red="lazy"))
    dart = base_rows("fig2", "dart", NQ, ["dart-e4a"], "proofgen_nozk",
                     lambda x: dict(cov=x, D=5000, z=max(1, -(-x // 200))))
    M = mint_cells()
    lh = []
    if M:
        lh = [(1000, stat(M["four"]), "mint-N1000-4wide (w19, 3 runs)"),
              (10000, stat(M["runs4"]), "mint-N10000-run1..3 (w19, 3 processes)"),
              (100000, dict(med=sum(M["chunks"]), lo=sum(M["chunks"]), hi=sum(M["chunks"]), n=1),
               "mint-N100000-chunk1..4 (w19, sum of 4 chunks of 25000)")]
    F = Fig("fig_exp4a_w19", [
        "Exp 4a (proof generation time vs records covered by the proof N_Q). PQZ-Audit and the other baselines: cloud-w18 session. L-HCPM Mint: cloud-w19 session (second session, same instance type). Medians of non-warm-up runs; ms.",
        "PQZ-Audit: R_Exec and R_RC proof generation, rayon default = all logical cores, results/cloud-w18/proofbench-full/raw.csv (experiment scale, prove_s x 1000).",
        "Baselines: Dong proofgen (c = N_Q, n = 2c, s=3); DOPIV proofgen (c = N_Q, m=16384; default and lazy reduction); DART proofgen_nozk (file of 1e6 records, D = 5000, z = N_Q/200;",
        "its cost follows the file/parameters, not only the coverage; no zk proof).",
        "L-HCPM Mint (w19): N_Q Groth16 proofs of the 2676-constraint stand-in circuit, one after another, single thread, witness synthesis inside the timer, fresh randomness per proof, nothing batched.",
        "  N_Q = 1e3: median of 3 runs (mint-N1000-4wide, 4 jobs on 4 cores at once); N_Q = 1e4: median of 3 processes (1 run each); N_Q = 1e5: ONE run in 4 chunks of 25,000 proofs, drawn value = sum of the 4 chunk times (n_runs = 1, no band).",
        "n_runs = 30 for the 1e3 cells and the PQZ cells, 5 for the largest baseline cells; band = min-max where n >= 5 at every point of the line.",
    ])
    F.add("pqz", "PQZ-Audit R$_{Exec}$ proof gen.", pq("exec"))
    F.add("pqz_rc", "PQZ-Audit R$_{RC}$ proof gen.", pq("rc"))
    F.add("dong", "Dong et al.", dong)
    F.add("dopiv", "DOPIV", dopiv)
    F.add("dopiv_lazy", "DOPIV (lazy red.)", dlazy)
    F.add("dart", "DART, no zk proof (file 1e6 records)", dart)
    F.add("lhcpm", "L-HCPM Mint, $N_Q$ proofs (one by one)", lh)
    return F, dict(xlabel="N$_Q$ (records covered by the proof)", ylabel="proof generation time (s)", unit_div=1000.0,
                   xticks=NQ, figsize=(W, 3.55), xlim=(7e2, 1.5e5), rows=4,
                   ref=["PQZ-Audit R$_{Exec}$ proof gen.", "PQZ-Audit R$_{RC}$ proof gen."], xname="N_Q records"), M, lh


if __name__ == "__main__":
    f1 = fig1()
    f2 = fig2()
    if missing:
        print("REFUSING: cells needed by the figures are missing, nothing drawn:", file=sys.stderr)
        for m in missing:
            print("  - " + m, file=sys.stderr)
        sys.exit(2)
    (F1, kw1) = f1
    (F2, kw2, M, _lh) = f2
    write_checks(M, [r for s in F1.series if s["key"] == "lhcpm" for r in s["rows"]])
    for F, kw in ((F1, kw1), (F2, kw2)):
        F.write_csv()
        F.print_table(kw["ref"], kw["xname"])
        fig, ax = draw(F, kw["xlabel"], kw["ylabel"], kw["unit_div"], kw["xticks"], kw["figsize"], xlim=kw["xlim"])
        save(fig, F.name, kw["rows"])
    print("\nMISSING CELLS: none")
    print("written to", OUT)
