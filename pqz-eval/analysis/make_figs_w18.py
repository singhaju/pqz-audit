#!/usr/bin/env python3
"""Draw fig_exp1_w18, fig_exp4a_w18, fig_exp4b_w18 from the cloud-w18 run (all lines solid).

Usage: .venv-bench/bin/python -I bench/pqz-eval/analysis/make_figs_w18.py [--results DIR] [--out DIR]
  results: default env W18_RESULTS, else bench/pqz-eval/results/cloud-w18
  out:     default env W18_OUT,     else journal2/figures/results-w18   (tests must pass --out elsewhere)
Same logic and style as journal2/figures/results-w17/make_figs_solid_w17.py. Differences:
  * one results folder, one sub-folder per job (w18 names: exp1d, proofbench-full, lhcpm, lhcpm-full, ...);
  * the L-HCPM Mint stand-in comes from lhcpm-full (stage groth16_prove_mint) of the SAME run, not from w15;
  * a missing job, csv or cell is NOT left out silently: the script lists them and exits 2 before drawing.
Values are medians of the non-warm-up runs; min-max band where n >= 5. Nothing is invented or interpolated.
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
ap.add_argument("--results")
ap.add_argument("--out")
args = ap.parse_args()
RES = WC.Results(WC.results_dir(args.results))
OUT = WC.out_dir(args.out, os.path.join(WC.ROOT, "journal2", "figures", "results-w18"))

# ---------------------------------------------------------------- style (as the w17 solid figures)
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 6.5, "axes.labelsize": 6.5,
    "xtick.labelsize": 6.5, "ytick.labelsize": 6.5, "legend.fontsize": 6,
    "axes.linewidth": 0.7, "xtick.major.width": 0.7, "ytick.major.width": 0.7,
    "xtick.minor.width": 0.5, "ytick.minor.width": 0.5,
    "xtick.direction": "out", "ytick.direction": "out",
    "pdf.fonttype": 42, "ps.fonttype": 42,
})
W = 3.45  # IEEE column width (in)
# Okabe-Ito (colour-blind safe)
BLUE, SKY, ORANGE, GREEN, PINK, GREY = "#0072B2", "#56B4E9", "#E69F00", "#009E73", "#CC79A7", "#555555"
STY = {  # key: color, linestyle, linewidth, marker, markersize, hollow
    "pqz":       (BLUE, "-", 1.4, "o", 3.6, False),
    "pqz_rc":    (SKY, "-", 1.4, "s", 3.4, False),
    "dong":      (GREY, "-", 1.0, "s", 3.0, False),
    "dopiv":     (ORANGE, "-", 1.0, "^", 3.2, False),
    "dopiv_lazy": (ORANGE, "-", 0.7, "v", 3.0, True),
    "dart":      (GREEN, "-", 1.0, "D", 2.6, False),
    "lhcpm":     (PINK, "-", 1.0, "x", 3.4, False),
    "lhcpm_flat": (PINK, "-", 0.8, None, 0, False),
}

# ---------------------------------------------------------------- what is needed (refuse before drawing)
NEED = [("exp1d", "exp1d.csv"), ("proofbench-full", "raw.csv"), ("lhcpm", "raw_runs.csv"), ("lhcpm-full", "raw_runs.csv")]
NEED += [(j, "raw_runs.csv") for j in ("dong-e1", "dong-e1-c10000", "dopiv-e1", "dopiv-lazy-e1", "dart-e1",
                                       "dong-e4a", "dong-e4a-c100000", "dopiv-e4a", "dopiv-e4a-c100000",
                                       "dopiv-lazy-e4a", "dopiv-lazy-e4a-c100000", "dart-e4a",
                                       "dong-e4b", "dopiv-e4b", "dart-e4b")]
RES.preflight(NEED)

missing = []


def baseline_cells(job, stage):
    """-> list of (params_dict, [ms...]) for one raw_runs.csv and stage."""
    g = defaultdict(list)
    for r in RES.rd(job, "raw_runs.csv"):
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
        if s["key"] == "lhcpm_flat":
            h, = ax.plot(xs, ys, color=c, ls=ls, lw=lw, label=s["label"], zorder=2)
        else:
            kw = dict(color=c, ls=ls, lw=lw, marker=mk, ms=ms, label=s["label"],
                      mfc="white" if hollow else c, mec=c, mew=0.8, zorder=4 if s["key"].startswith("pqz") else 3)
            h, = ax.plot(xs, ys, **kw)
        # min-max band where n >= 5
        if len(xs) > 1 and s["key"] != "lhcpm_flat":
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


# ================================================================ FIG 1
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
    hit = pick(baseline_cells("lhcpm", "audit_hit_q"), q=1)
    lh = [(N, hit, "lhcpm (audit_hit_q, q=1)") for N in Ns] if hit else []
    if not hit:
        missing.append("fig1 L-HCPM audit_hit_q q=1")
    F = Fig("fig_exp1_w18", [
        "Exp 1 (query/proof cost vs number of protected records N), cloud-w18 session, one instance, one image. Medians of non-warm-up runs; ms.",
        "PQZ-Audit: query only, sigma_Q = 1 %, results/cloud-w18/exp1d/exp1d.csv (series sigma1pct, warmup==0).",
        "Baselines at coverage cov = 0.01 N records, each its own line: Dong proofgen (c = cov, s=3), DOPIV proofgen (c = cov, m=16384; default reduction and lazy reduction),",
        "DART proofgen_nozk (file = 100 x cov records, so D = N/200 and z = max(1, ceil(cov/200)) as run; no zk proof), L-HCPM audit_hit_q q=1 (cache hit, O(1), one value repeated at every N).",
        "Dong: c = 100..5000 use n = 10c (job dong-e1); c = 10000 uses n = 2c = 20000 (job dong-e1-c10000), so the last Dong point has a different n/c ratio.",
        "n_runs = 30 for most cells, 5 for the largest cells; band = min-max where n >= 5. Baseline proofs are generated by different systems, parameters as in the job params string.",
    ])
    F.add("pqz", "PQZ-Audit query (σ$_Q$=1%)", pqz)
    F.add("dong", "Dong et al. proof gen.", dong)
    F.add("dopiv", "DOPIV proof gen.", dopiv)
    F.add("dopiv_lazy", "DOPIV proof gen. (lazy red.)", dlazy)
    F.add("dart", "DART proof gen. (no zk proof)", dart)
    F.add("lhcpm_flat", "L-HCPM cache hit (per transaction)", lh)
    return F, dict(xlabel="N (protected records)", ylabel="time (ms)", unit_div=1.0, xticks=[1e4, 1e5, 1e6],
                   figsize=(W, 3.55), xlim=(8e3, 1.25e6), rows=4, ref=["PQZ-Audit query (σ$_Q$=1%)"], xname="N records")


# ================================================================ FIG 2
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
    mint = pick(baseline_cells("lhcpm-full", "groth16_prove_mint"))
    lh = [(x, mint, "lhcpm-full (groth16_prove_mint)") for x in NQ] if mint else []
    if not mint:
        missing.append("fig2 L-HCPM Mint (lhcpm-full)")
    F = Fig("fig_exp4a_w18", [
        "Exp 4a (proof generation time vs records covered by the proof N_Q), cloud-w18 session, one instance, one image. Medians of non-warm-up runs; ms.",
        "PQZ-Audit: R_Exec and R_RC proof generation, rayon default = all logical cores, results/cloud-w18/proofbench-full/raw.csv (experiment scale, prove_s x 1000).",
        "Baselines: Dong proofgen (c = N_Q, n = 2c, s=3); DOPIV proofgen (c = N_Q, m=16384; default and lazy reduction); DART proofgen_nozk (file of 1e6 records, D = 5000, z = N_Q/200;",
        "its cost follows the file/parameters, not only the coverage; no zk proof); L-HCPM Mint (stand-in circuit, 2676 constraints, constant in N_Q, one value repeated).",
        "L-HCPM Mint comes from lhcpm-full of the same run (stage groth16_prove_mint).",
        "n_runs = 30 for the 1e3 cells and the PQZ cells, 5 for the largest baseline cells; band = min-max where n >= 5.",
    ])
    F.add("pqz", "PQZ-Audit R$_{Exec}$ proof gen.", pq("exec"))
    F.add("pqz_rc", "PQZ-Audit R$_{RC}$ proof gen.", pq("rc"))
    F.add("dong", "Dong et al.", dong)
    F.add("dopiv", "DOPIV", dopiv)
    F.add("dopiv_lazy", "DOPIV (lazy red.)", dlazy)
    F.add("dart", "DART, no zk proof (file 1e6 records)", dart)
    F.add("lhcpm_flat", "L-HCPM Mint, stand-in circuit", lh)
    return F, dict(xlabel="N$_Q$ (records covered by the proof)", ylabel="proof generation time (s)", unit_div=1000.0,
                   xticks=NQ, figsize=(W, 3.55), xlim=(7e2, 1.5e5), rows=4,
                   ref=["PQZ-Audit R$_{Exec}$ proof gen.", "PQZ-Audit R$_{RC}$ proof gen."], xname="N_Q records")


# ================================================================ FIG 3
def fig3():
    Q = [1, 10, 25, 50, 100, 200]
    tv = defaultdict(list)
    for r in RES.rd("proofbench-full", "raw.csv"):
        if (WC.is_timed(r) and r["experiment"] == "q" and r["rel"] == "bundle"
                and r["mode"] == "distinct" and r["total_verify_s"]):
            tv[int(r["q"])].append(float(r["total_verify_s"]) * 1000.0)
    pqz = []
    for q in Q:
        if q in tv:
            pqz.append((q, stat(tv[q]), "proofbench-full"))
        else:
            missing.append(f"fig3 PQZ q={q}")
    dong = base_rows("fig3", "dong", Q, ["dong-e4b"], "verify_q", lambda q: dict(q=q, c=1000))
    dopiv = base_rows("fig3", "dopiv", Q, ["dopiv-e4b"], "verify_q", lambda q: dict(audits=q, red=None))
    dlazy = base_rows("fig3", "dopiv_lazy", Q, ["dopiv-e4b"], "verify_q", lambda q: dict(audits=q, red="lazy"))
    dart = base_rows("fig3", "dart", Q, ["dart-e4b"], "verify_q", lambda q: dict(q=q, cov=1000))
    lh = base_rows("fig3", "lhcpm", Q, ["lhcpm"], "groth16_verify_q", lambda q: dict(q=q))
    F = Fig("fig_exp4b_w18", [
        "Exp 4b (total verification time for q audit proofs), cloud-w18 session, one instance, one image. Medians of non-warm-up runs; ms.",
        "PQZ-Audit: bundle verification of q distinct requests, results/cloud-w18/proofbench-full/raw.csv (experiment q, rel bundle, mode distinct, total_verify_s x 1000).",
        "Every baseline is measured at each q with q different proofs (not one audit times q): Dong verify_q, DOPIV verify_q (default and lazy reduction), DART verify_q (no zk proof), L-HCPM groth16_verify_q.",
        "Coverage 1000 records per audit for all (L-HCPM: one transaction per audit). n_runs = 30 for q = 1, 5 for q >= 10 baselines; PQZ n = 30 at every q; band = min-max where n >= 5.",
    ])
    F.add("pqz", "PQZ-Audit bundle", pqz)
    F.add("dong", "Dong et al.", dong)
    F.add("dopiv", "DOPIV", dopiv)
    F.add("dopiv_lazy", "DOPIV (lazy red.)", dlazy)
    F.add("dart", "DART (no zk proof)", dart)
    F.add("lhcpm", "L-HCPM Groth16 verify", lh)
    return F, dict(xlabel="audit requests q", ylabel="total verification time (ms)", unit_div=1.0, xticks=[1, 10, 100],
                   figsize=(W, 3.3), xlim=(0.8, 260), rows=3, ref=["PQZ-Audit bundle"], xname="q audits")


if __name__ == "__main__":
    built = [f() for f in (fig1, fig2, fig3)]
    if missing:
        print("REFUSING: cells needed by the figures are missing, nothing drawn:", file=sys.stderr)
        for m in missing:
            print("  - " + m, file=sys.stderr)
        sys.exit(2)
    for F, kw in built:
        F.write_csv()
        F.print_table(kw["ref"], kw["xname"])
        fig, ax = draw(F, kw["xlabel"], kw["ylabel"], kw["unit_div"], kw["xticks"], kw["figsize"], xlim=kw["xlim"])
        save(fig, F.name, kw["rows"])
    print("\nMISSING CELLS: none")
    print("written to", OUT)
