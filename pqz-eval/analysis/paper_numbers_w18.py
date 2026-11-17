"""Every number that the paper quotes from the cloud-w18 run, each with its source job.

Usage: python3 -I paper_numbers_w18.py [--results DIR] [--txt FILE] > paper_numbers_w18.txt
  results: default env W18_RESULTS, else bench/pqz-eval/results/cloud-w18

Covers what work17 took from w16 (Exp 1 and Exp 4: PQZ-Audit exp1d, the four baselines, proof prototype,
L-HCPM) AND from w17 (Exp 2, 3, 5, 6, R_CoverM, chunked single proofs), plus the alone-check comparison.
Every printed line starts with [job] = the job folder the numbers come from. Medians of timed rows
(warmup == 0, kind == timed); min/max = range of timed rows. Times in ms unless a unit is printed.
O_j range: (T_abl_min - T_full_max)/T_full_max to (T_abl_max - T_full_min)/T_full_min.
Refuses (exit 2) when a needed job or csv is missing, empty or failed, or when a baseline cell is not found
exactly once. The four alone-check jobs are optional.
"""
import argparse
import math
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import w18_common as W  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--results")
ap.add_argument("--txt", help="also write the printed text to this file")
args = ap.parse_args()
R = W.Results(W.results_dir(args.results))

# ------------------------------------------------------------------ what is needed
EXP = {"exp2a": "exp2a.csv", "exp1": "exp1.csv", "exp1_construction": "exp1_construction.csv", "exp1d": "exp1d.csv",
       "exp2bd": "exp2bd.csv", "exp2c": "exp2c.csv", "exp2b": "exp2b.csv", "exp3a": "exp3a.csv",
       "exp3c": "exp3c.csv", "exp3b-r1": "exp3b.csv", "exp3b-r2": "exp3b.csv", "exp3ad": "exp3ad.csv",
       "exp3d": "exp3d.csv"}
BASEJ = ["lhcpm-full", "lhcpm", "dong-e1", "dong-e1-c10000", "dong-e4a", "dong-e4a-c100000", "dong-e4b",
         "dopiv-e1", "dopiv-lazy-e1", "dopiv-e4a", "dopiv-lazy-e4a", "dopiv-e4a-c100000", "dopiv-lazy-e4a-c100000",
         "dopiv-e4b", "dart-e1", "dart-e4a", "dart-e4b"]
LEDGER = ["ledger-with-tx-auth", "ledger-no-tx-auth"]
LFILES = ["exp5a_latency_throughput.csv", "exp5b_governance.csv", "exp5c_bytes_per_epoch.csv"]
PROOFJ = ["proofbench-full", "proofbench-ablation", "covermerkle-g2000", "chunked-single"]
req = list(EXP.items()) + [(j, "raw_runs.csv") for j in BASEJ] + [(j, f) for j in LEDGER for f in LFILES] \
    + [(j, "raw.csv") for j in PROOFJ]
ok_ac = R.preflight(req, [("ac-exp3c-n10000", "exp3c.csv"), ("ac-dong", "raw_runs.csv"),
                          ("ac-dart", "raw_runs.csv"), ("ac-dopiv", "raw_runs.csv")])

# ------------------------------------------------------------------ output (stdout, optionally a file too)
_buf = []


def out(s=""):
    print(s)
    _buf.append(s)


# ------------------------------------------------------------------ helpers
def cells(job, fname, keyf, val=lambda r: float(r["time_ns"]) / 1e6):
    g = defaultdict(list)
    for r in R.rd(job, fname):
        if W.is_timed(r):
            g[keyf(r)].append(val(r))
    return g


def get(g, k, what=""):
    if k not in g or not g[k]:
        sys.exit(f"REFUSING: cell {k} {what} not found")
    return g[k]


def S(v):
    return W.S(v)


def line(src, label, v, unit="ms", fmt="%.4g"):
    m, lo, hi, n = S(v)
    out(f"[{src}] {label}: median {fmt % m} {unit} (min {fmt % lo}, max {fmt % hi}, n={n})")
    return m, lo, hi


def slope(xs, ys):
    lx, ly = [math.log(x) for x in xs], [math.log(y) for y in ys]
    mx, my = sum(lx) / len(lx), sum(ly) / len(ly)
    return sum((a - mx) * (b - my) for a, b in zip(lx, ly)) / sum((a - mx) ** 2 for a in lx)


def oj(full, abl):
    return ((abl[0] - full[0]) / full[0] * 100,
            (abl[1] - full[2]) / full[2] * 100,
            (abl[2] - full[1]) / full[1] * 100)


_bcache = {}


def bcells(job):
    if job not in _bcache:
        _bcache[job] = W.base_groups(R.rd(job, "raw_runs.csv"))
    return _bcache[job]


def bcell(job, stage, **want):
    """Values (ms) of the ONE baseline cell of job/stage whose params contain every key=value of want.
    A want value None means: the key must be absent from params (e.g. red for the default DOPIV reduction)."""
    hits = []
    for (b, stg, prm), v in bcells(job).items():
        if stg != stage:
            continue
        d, _ = W.parse_params(prm)
        if all((k not in d) if val is None else d.get(k) == str(val) for k, val in want.items()):
            hits.append(v)
    if len(hits) != 1:
        sys.exit(f"REFUSING: baseline cell {job}/{stage} {want}: {len(hits)} matches (need exactly 1)")
    return hits[0]


def bmed(job, stage, **want):
    return S(bcell(job, stage, **want))[0]


# ================================================================== EXP 1 (PQZ-Audit rows from exp1d, baselines from the e1 jobs)
NS = [10000, 20000, 50000, 100000, 200000, 500000, 1000000]
out("=== EXP 1 PQZ-Audit rows: exp1d (the drawn line) ===")
d1 = cells("exp1d", "exp1d.csv", lambda r: (r["series"], int(r["n"])))
p1 = {}
for sr in ("sigma1pct", "fixed_nq1000"):
    p1[sr] = [S(get(d1, (sr, n), "exp1d"))[0] for n in NS]
    out(f"[exp1d] {sr}: " + "  ".join("N=%g:%.4g" % (n, m) for n, m in zip(NS, p1[sr])) + "  slope %.3f" % slope(NS, p1[sr]))
out("[exp1d] sigma1pct min/max over runs at N=1e4: %.4g-%.4g ms; at N=1e6: %.4g-%.4g ms" % (
    min(d1[("sigma1pct", 10000)]), max(d1[("sigma1pct", 10000)]), min(d1[("sigma1pct", 1000000)]), max(d1[("sigma1pct", 1000000)])))
x1 = cells("exp1", "exp1.csv", lambda r: (r["series"], int(r["n"])))
out("")
out("=== EXP 1 PQZ-Audit rows: exp1 (second copy of the same cells, same session) and difference to exp1d ===")
for sr in ("sigma1pct", "fixed_nq1000"):
    n1 = sorted(k[1] for k in x1 if k[0] == sr)  # exp1 does not have every N of exp1d (w17: five N values)
    if not n1 or any(n not in NS for n in n1):
        sys.exit(f"REFUSING: exp1 series {sr} has N values {n1}, not a subset of {NS}")
    m2 = [S(get(x1, (sr, n), "exp1"))[0] for n in n1]
    ref = [p1[sr][NS.index(n)] for n in n1]
    df = [(a - b) / b * 100 for a, b in zip(m2, ref)]
    out(f"[exp1] {sr}: " + "  ".join("N=%g:%.4g" % (n, m) for n, m in zip(n1, m2)) + "  slope %.3f" % slope(n1, m2))
    out(f"[exp1 vs exp1d] {sr}: difference (exp1 - exp1d)/exp1d at N={n1}: " + "  ".join("%+.1f%%" % x for x in df)
        + f"  max |diff| {max(abs(x) for x in df):.1f}%")

out("")
out("=== EXP 1 baselines at the matched coverage c = 0.01 N (proof-generation stage) ===")


def e1_job(base, c):
    if base == "dong":
        return "dong-e1-c10000" if c == 10000 else "dong-e1"
    return {"dopiv": "dopiv-e1", "dopiv-lazy": "dopiv-lazy-e1", "dart": "dart-e1"}[base]


rows1 = []
for n in NS:
    c = n // 100
    dg = S(bcell(e1_job("dong", c), "proofgen", c=c, s=3))
    dp = S(bcell("dopiv-e1", "proofgen", c=c))
    dz = S(bcell("dopiv-lazy-e1", "proofgen", c=c, red="lazy"))
    da = S(bcell("dart-e1", "proofgen_nozk", cov=c))
    rows1.append((n, c, dg, dp, dz, da))
    out(f"N={n:g} c={c}: [{e1_job('dong', c)}] dong {dg[0]:.4g} [{dg[1]:.4g}-{dg[2]:.4g}] (n={dg[3]})  [dopiv-e1] dopiv {dp[0]:.4g} (n={dp[3]})"
        f"  [dopiv-lazy-e1] lazy {dz[0]:.4g}  [dart-e1] dart {da[0]:.4g} (n={da[3]})")
cs = [r[1] for r in rows1]
out("[e1 jobs] log-log slope over c: dong %.3f, dopiv %.3f, dopiv lazy %.3f, dart %.3f" % tuple(
    slope(cs, [r[k][0] for r in rows1]) for k in (2, 3, 4, 5)))
out("[e1 jobs] min-max proof generation: dong %.4g-%.4g, dopiv %.4g-%.4g, lazy %.4g-%.4g, dart %.4g-%.4g ms" % (
    rows1[0][2][0], rows1[-1][2][0], min(r[3][0] for r in rows1), max(r[3][0] for r in rows1),
    min(r[4][0] for r in rows1), max(r[4][0] for r in rows1), rows1[0][5][0], rows1[-1][5][0]))
pz = p1["sigma1pct"]
for lab, k in (("dong", 2), ("dopiv", 3), ("dopiv lazy", 4), ("dart", 5)):
    f = [r[k][0] / p for r, p in zip(rows1, pz)]
    out(f"[exp1d + e1 jobs] factor {lab} / PQZ-Audit (sigma1pct) per N: " + "  ".join("%.3g" % x for x in f)
        + f"   range {min(f):.3g}-{max(f):.3g}")
out("")
hit_q1 = bmed("lhcpm", "audit_hit_q", q=1)
hit_full = S(bcell("lhcpm-full", "audit_hit"))
out(f"[lhcpm] L-HCPM cache hit (audit_hit_q, q=1): median {hit_q1:.4g} ms")
out(f"[lhcpm-full] L-HCPM cache hit (audit_hit): median {hit_full[0]:.4g} ms (min {hit_full[1]:.4g}, max {hit_full[2]:.4g}, n={hit_full[3]})"
    f";  difference to lhcpm q=1: {(hit_full[0] - hit_q1) / hit_q1 * 100:+.2f}%")
for n, p in zip(NS, pz):
    out(f"  N={n:g}: PQZ-Audit {p:.4g} ms vs L-HCPM cache hit {hit_q1:.4g} ms -> {'PQZ below' if p < hit_q1 else 'PQZ above'} (ratio {hit_q1 / p:.3g})")

# ================================================================== EXP 4a
out("")
out("=== EXP 4 proof generation (proofbench-full, experiment=scale; prove_s, trace_s) ===")
pb = R.rd("proofbench-full", "raw.csv")


def pcells(keyf, col, scale=1.0, rows=None):
    g = defaultdict(list)
    for r in (rows if rows is not None else pb):
        if W.is_timed(r) and r.get(col, "") != "":
            g[keyf(r)].append(float(r[col]) * scale)
    return g


sc_key = lambda r: (r["experiment"], r["rel"], r["n_records"], r["depth"])  # noqa: E731
sprove = pcells(sc_key, "prove_s", 1e3)
strace = pcells(sc_key, "trace_s", 1e3)
sver = pcells(sc_key, "verify_s", 1e3)
sbytes = pcells(sc_key, "proof_bytes", 1 / 1024)
srss = pcells(sc_key, "prove_peak_rss_kb", 1 / 1048576)
PN = ["1000", "10000", "100000"]
ex = {}
for rel in ("rc", "exec"):
    for n in PN:
        k = ("scale", rel, n, "")
        pv, tr = get(sprove, k, "proofbench-full"), get(strace, k)
        ex[(rel, n)] = S(pv)
        m, lo, hi, nn = S(pv)
        out(f"[proofbench-full] R_{rel} N_Q={n}: prove {m:.4g} ms [{lo:.4g}-{hi:.4g}] n={nn}; trace {S(tr)[0]:.4g} ms [{S(tr)[1]:.4g}-{S(tr)[2]:.4g}];"
            f" trace+prove (sum of medians) {(m + S(tr)[0]) / 1e3:.4g} s; verify {S(get(sver, k))[0]:.4g} ms;"
            f" proof {S(get(sbytes, k))[0]:.4g} KiB; peak RSS {S(get(srss, k))[0]:.4g} GiB ({S(get(srss, k))[0] * 1024:.4g} MiB)")
for dep in ("10", "20"):
    k = ("scale", "auth", "", dep)
    line("proofbench-full", f"R_Auth depth {dep} prove", get(sprove, k, "auth"), "ms")
    line("proofbench-full", f"R_Auth depth {dep} verify", get(sver, k), "ms")
out("[proofbench-full] proof KiB range R_RC: %.4g-%.4g; peak RSS range R_RC: %.4g MiB - %.4g GiB; R_Exec peak at 1e5: %.4g GiB" % (
    S(sbytes[("scale", "rc", "1000", "")])[0], S(sbytes[("scale", "rc", "100000", "")])[0],
    S(srss[("scale", "rc", "1000", "")])[0] * 1024, S(srss[("scale", "rc", "100000", "")])[0],
    S(srss[("scale", "exec", "100000", "")])[0]))

out("")
out("=== EXP 4 proof generation: baselines at the same coverage (single thread) ===")
CS = [1000, 10000, 100000]


def e4a_job(base, c):
    return {("dong", 100000): "dong-e4a-c100000", ("dopiv", 100000): "dopiv-e4a-c100000",
            ("dopiv-lazy", 100000): "dopiv-lazy-e4a-c100000"}.get((base, c), {
                "dong": "dong-e4a", "dopiv": "dopiv-e4a", "dopiv-lazy": "dopiv-lazy-e4a", "dart": "dart-e4a"}[base])


B4 = {}
for c, n in zip(CS, PN):
    dg = S(bcell(e4a_job("dong", c), "proofgen", c=c, s=3))
    dp = S(bcell(e4a_job("dopiv", c), "proofgen", c=c))
    dz = S(bcell(e4a_job("dopiv-lazy", c), "proofgen", c=c, red="lazy"))
    da = S(bcell("dart-e4a", "proofgen_nozk", cov=c))
    B4[c] = (dg, dp, dz, da)
    re_ = ex[("exec", n)][0]
    out(f"c={c}: [{e4a_job('dong', c)}] dong {dg[0]:.4g} ms (n={dg[3]})  [{e4a_job('dopiv', c)}] dopiv {dp[0]:.4g}  "
        f"[{e4a_job('dopiv-lazy', c)}] lazy {dz[0]:.4g}  [dart-e4a] dart {da[0]:.4g}")
    out(f"   vs R_Exec ({re_:.4g} ms): dong/R_Exec {dg[0] / re_:.3g}, R_Exec/dopiv {re_ / dp[0]:.3g}, R_Exec/lazy {re_ / dz[0]:.3g}, "
        f"dart/R_Exec {da[0] / re_:.3g}")
mint = S(bcell("lhcpm-full", "groth16_prove_mint"))
out(f"[lhcpm-full] L-HCPM Mint stand-in (groth16_prove_mint, 2676 constraints): median {mint[0]:.4g} ms (min {mint[1]:.4g}, max {mint[2]:.4g}, n={mint[3]})")
for n in PN:
    out(f"   Mint / R_Exec at N_Q={n}: {mint[0] / ex[('exec', n)][0]:.3g}")
tr = S(bcell("lhcpm-full", "groth16_prove_transfer"))
out(f"[lhcpm-full] L-HCPM Transfer stand-in (8786 constraints): median {tr[0]:.4g} ms")
for pub in (3, 13):
    out(f"[lhcpm-full] groth16_verify public_inputs={pub}: median {bmed('lhcpm-full', 'groth16_verify', public_inputs=pub):.4g} ms")

# ================================================================== EXP 4b
out("")
out("=== EXP 4 verification, q sweep (proofbench-full bundle, mode distinct / same; baselines verify_q) ===")
qk = lambda r: (r["experiment"], r["rel"], r["q"], r["mode"])  # noqa: E731
qv = pcells(qk, "total_verify_s", 1e3)
QS = [1, 10, 25, 50, 100, 200]
bun = {}
for q in QS:
    for mode in ("distinct", "same"):
        v = get(qv, ("q", "bundle", str(q), mode), "proofbench-full bundle")
        bun[(q, mode)] = S(v)
    out(f"[proofbench-full] bundle q={q}: distinct {bun[(q, 'distinct')][0]:.4g} ms [{bun[(q, 'distinct')][1]:.4g}-{bun[(q, 'distinct')][2]:.4g}]"
        f" ({bun[(q, 'distinct')][0] / q:.4g} per request), same {bun[(q, 'same')][0]:.4g} ms")
out("[proofbench-full] bundle slope in q (distinct): %.3f" % slope(QS, [bun[(q, 'distinct')][0] for q in QS]))
cmv = [float(r["verify_s"]) * 1e3 for r in R.rd("covermerkle-g2000", "raw.csv") if W.is_timed(r)]
cmv_by = defaultdict(list)
for r in R.rd("covermerkle-g2000", "raw.csv"):
    if W.is_timed(r):
        cmv_by[r["r_retained"]].append(float(r["verify_s"]) * 1e3)
sums = [bun[(1, "distinct")][0] + S(v)[0] for v in cmv_by.values()]
out("[proofbench-full + covermerkle-g2000] bundle q=1 + R_CoverM verify (sum of medians): %.4g-%.4g ms (R_CoverM verify %.4g-%.4g ms)" % (
    min(sums), max(sums), min(S(v)[0] for v in cmv_by.values()), max(S(v)[0] for v in cmv_by.values())))
vq = {}
for q in QS:
    vq[("dong", q)] = S(bcell("dong-e4b", "verify_q", q=q))
    vq[("dopiv", q)] = S(bcell("dopiv-e4b", "verify_q", audits=q, red=None))
    vq[("dopiv-lazy", q)] = S(bcell("dopiv-e4b", "verify_q", audits=q, red="lazy"))
    vq[("dart", q)] = S(bcell("dart-e4b", "verify_q", q=q))
    vq[("lhcpm", q)] = S(bcell("lhcpm", "groth16_verify_q", q=q))
    vq[("lhcpm-hit", q)] = S(bcell("lhcpm", "audit_hit_q", q=q))
src = {"dong": "dong-e4b", "dopiv": "dopiv-e4b", "dopiv-lazy": "dopiv-e4b (red=lazy)", "dart": "dart-e4b",
       "lhcpm": "lhcpm", "lhcpm-hit": "lhcpm"}
for k in ("dong", "dopiv", "dopiv-lazy", "dart", "lhcpm", "lhcpm-hit"):
    out(f"[{src[k]}] {k} verify_q: " + "  ".join("q=%d:%.4g(n=%d)" % (q, vq[(k, q)][0], vq[(k, q)][3]) for q in QS)
        + "   slope in q %.3f" % slope(QS, [vq[(k, q)][0] for q in QS]))
for q in (1, 200):
    pq = bun[(q, "distinct")][0]
    out(f"q={q}: PQZ bundle {pq:.4g} ms; dong/PQZ {vq[('dong', q)][0] / pq:.3g}; dopiv/PQZ {vq[('dopiv', q)][0] / pq:.3g}; "
        f"lazy/PQZ {vq[('dopiv-lazy', q)][0] / pq:.3g}; dart/PQZ {vq[('dart', q)][0] / pq:.3g}; PQZ/L-HCPM-verify {pq / vq[('lhcpm', q)][0]:.3g}")
out("[dopiv-e4b] DOPIV verify (stage verify) at c=1000: default %.4g ms, lazy %.4g ms" % (
    bmed("dopiv-e4b", "verify", red=None), bmed("dopiv-e4b", "verify", red="lazy")))

# ================================================================== w17 part: EXP 2
out("")
out("=== EXP 2 table (exp2a, run alone; 30 runs after 3 warm-up) ===")
a_rows = R.rd("exp2a", "exp2a.csv")
g = cells("exp2a", "exp2a.csv", lambda r: (r["layout"], r["predicate"], r["approach"]))
for lay in ("clustered", "scattered"):
    for ap_ in ("trad_scan", "prot_full_scan", "pqz"):
        out(f"[exp2a] {lay} {ap_}  " + "  ".join("%s %.4g [%.4g-%.4g]" % ((p,) + S(get(g, (lay, p, ap_)))[:3]) for p in ("P1", "P2", "P3", "P4")))
ret = defaultdict(set)
for r in a_rows:
    if r["approach"] == "pqz" and W.is_timed(r):
        ret[(r["layout"], r["predicate"])].add((r["n_retained_blocks"], r["n_blocks"]))
out(f"[exp2a] retained/total blocks {dict(ret)}")
sp = [S(g[("scattered", p, "pqz")])[0] for p in ("P1", "P2", "P3", "P4")]
out("[exp2a] scattered pqz range over P1..P4: %.4g-%.4g ms" % (min(sp), max(sp)))
allr = []
for p in ("P1", "P2", "P3", "P4"):
    for lay in ("clustered", "scattered"):
        pq_, fs = S(g[(lay, p, "pqz")])[0], S(g[(lay, p, "prot_full_scan")])[0]
        allr.append((lay, p, fs / pq_))
        out(f"[exp2a]   {lay} {p}: protected full / PQZ = {fs / pq_:.3g}; PQZ vs full scan {100 * (pq_ - fs) / fs:+.2f}%")
cl = [x[2] for x in allr if x[0] == "clustered"]
out(f"[exp2a] clustered speed-up range (protected full / PQZ): {min(cl):.3g}-{max(cl):.3g}")

out("")
out("=== EXP 2 selectivity (exp2bd, dense) ===")
gb = cells("exp2bd", "exp2bd.csv", lambda r: (r["layout"], r["approach"], float(r["sigma"])))
sig = sorted({k[2] for k in gb})
for lay in ("clustered", "scattered"):
    for ap_ in ("trad_scan", "prot_full_scan", "pqz"):
        out(f"[exp2bd] {lay} {ap_}  " + "  ".join("%g%%:%.4g" % (s * 100, S(gb[(lay, ap_, s)])[0]) for s in sig))
for lay in ("clustered", "scattered"):
    ms = [S(gb[(lay, "prot_full_scan", s)])[0] for s in sig]
    out(f"[exp2bd] {lay} prot_full_scan range over sweep {min(ms):.4g}-{max(ms):.4g}")
pqs = [S(gb[("clustered", "pqz", s)])[0] for s in sig]
out("[exp2bd] clustered pqz slope over sigma: %.3f" % slope([s * 1e6 for s in sig], pqs))
out("[exp2bd] gap protected full / pqz at 25%%: %.3g ; at 0.1%%: %.3g" % (
    S(gb[("clustered", "prot_full_scan", 0.25)])[0] / pqs[-1], S(gb[("clustered", "prot_full_scan", 0.001)])[0] / pqs[0]))
for i, s in enumerate(sig):
    t = S(gb[("clustered", "trad_scan", s)])[0]
    out(f"[exp2bd]   sigma {s * 100:g}%: pqz {pqs[i]:.4g} vs trad {t:.4g} -> {'pqz below' if pqs[i] < t else 'pqz above'} (ratio {t / pqs[i]:.3g})")
ps = [S(gb[("scattered", "pqz", s)])[0] for s in sig]
out(f"[exp2bd] scattered pqz 0.1%: {ps[0]:.4g}  25%: {ps[-1]:.4g}")

out("")
out("=== EXP 2 block size (exp2c) ===")
gc = cells("exp2c", "exp2c.csv", lambda r: (r["layout"], r["approach"], int(r["mb"])))
for lay in ("clustered", "scattered"):
    for ap_ in ("pqz", "prot_full_scan"):
        out(f"[exp2c] {lay} {ap_}  " + "  ".join("m_B=%d:%.4g" % (m, S(get(gc, (lay, ap_, m)))[0]) for m in (100, 250, 500, 1000)))

out("")
out("=== cross-checks of the same cell across jobs (clustered P4 sigma=1%, m_B=500) ===")
gg = cells("exp2a", "exp2a.csv", lambda r: (r["layout"], r["predicate"], r["approach"]))
out("[exp2a] pqz P4 %.4g, prot_full P4 %.4g, trad P4 %.4g" % tuple(S(gg[("clustered", "P4", x)])[0] for x in ("pqz", "prot_full_scan", "trad_scan")))
for nm in ("exp2b", "exp2bd", "exp2c"):
    gx = defaultdict(list)
    for r in R.rd(nm, EXP[nm]):
        if W.is_timed(r) and r["layout"] == "clustered" and abs(float(r["sigma"]) - 0.01) < 1e-9 and r["mb"] == "500":
            gx[r["approach"]].append(float(r["time_ns"]) / 1e6)
    out(f"[{nm}] pqz %.4g, prot_full %.4g, trad %.4g" % tuple(S(get(gx, x))[0] for x in ("pqz", "prot_full_scan", "trad_scan")))

# ================================================================== EXP 3
out("")
out("=== EXP 3 sigma sweep: Full-Domain HE (exp3a) with the PQZ-Audit values of the same job ===")
ge = cells("exp3a", "exp3a.csv", lambda r: (r["approach"], float(r["sigma"])))
he_sig = sorted({k[1] for k in ge if k[0] == "full_he"})
for s in he_sig:
    he, pz_ = S(ge[("full_he", s)])[0], S(ge[("pqz", s)])[0]
    lo, hi = S(ge[("full_he", s)])[1:3]
    out(f"[exp3a] sigma {s * 100:g}%: full_he {he / 1e3:.4g} s [{lo / 1e3:.4g}-{hi / 1e3:.4g}], pqz {pz_:.4g} ms, R_HE {100 * (1 - pz_ / he):.2f}%, ratio {he / pz_:.3g}")
pzs = sorted({k[1] for k in ge if k[0] == "pqz"})
out("[exp3a] pqz slope: %.3f" % slope([s * 1e6 for s in pzs], [S(ge[("pqz", s)])[0] for s in pzs]))
out("[exp3a] full_he over sweep: %.4g-%.4g s" % (min(S(ge[("full_he", s)])[0] for s in he_sig) / 1e3, max(S(ge[("full_he", s)])[0] for s in he_sig) / 1e3))
out("[exp3a] full_he overall min/max over all runs: %.4g-%.4g s" % (min(min(ge[("full_he", s)]) for s in he_sig) / 1e3, max(max(ge[("full_he", s)]) for s in he_sig) / 1e3))
gd = cells("exp3ad", "exp3ad.csv", lambda r: (r["approach"], float(r["sigma"])))
ds = sorted({k[1] for k in gd if k[0] == "pqz"})
out("[exp3ad] pqz dense:  " + "  ".join("%g%%:%.4g" % (s * 100, S(gd[("pqz", s)])[0]) for s in ds))
out("[exp3ad] pqz dense slope: %.3f ; min n_Q: %.4g ms (n_Q=1000), max: %.4g ms (n_Q=250000)" % (
    slope([s * 1e6 for s in ds], [S(gd[("pqz", s)])[0] for s in ds]), S(gd[("pqz", ds[0])])[0], S(gd[("pqz", ds[-1])])[0]))
out("[exp3ad] per-ciphertext PQZ cost at 1000..250000:  " + "  ".join("%.1f us" % (S(gd[("pqz", s)])[0] * 1e3 / (s * 1e6)) for s in ds))
out("[exp3ad] plain dense: %.4g ms at 1e3, %.4g at 2.5e5" % (S(gd[("plain_agg", ds[0])])[0], S(gd[("plain_agg", ds[-1])])[0]))
for s in he_sig:
    he, pz_ = S(ge[("full_he", s)])[0], S(gd[("pqz", s)])[0]
    out(f"[exp3a + exp3ad]   R_HE with dense pqz sigma {s * 100:g}%: {100 * (1 - pz_ / he):.2f}%")
out("[exp3a + exp3ad] break-even n_Q (HE cost / per-ct cost) ~ %.3g records" % (S(ge[("full_he", 0.01)])[0] / (S(gd[("pqz", 0.25)])[0] / 250000)))

out("")
out("=== EXP 3 operator table (exp3b r1 = primary, r2 = repeat), sigma=1%, N=1e6 ===")
T = {}
for nm in ("exp3b-r1", "exp3b-r2"):
    T[nm] = cells(nm, "exp3b.csv", lambda r: (r["agg"], r["approach"]), val=lambda r: float(r["time_ns"]))
    out(nm)
    for agg in ("SUM", "AVG", "COUNT"):
        out(f"[{nm}]   {agg}  " + "  ".join(
            ("%s %.4g ms [%.4g-%.4g]" % ((ap_,) + tuple(x / 1e6 for x in S(get(T[nm], (agg, ap_)))[:3]))) if agg != "COUNT" or ap_ == "full_he"
            else ("%s %.4g ns [%.4g-%.4g]" % ((ap_,) + S(get(T[nm], (agg, ap_)))[:3])) for ap_ in ("plain_agg", "full_he", "pqz")))
        he, pz_ = S(T[nm][(agg, "full_he")])[0], S(T[nm][(agg, "pqz")])[0]
        if agg != "COUNT":
            out(f"[{nm}]       R_HE {100 * (1 - pz_ / he):.2f}%   ratio {he / pz_:.4g}")
r1 = {k: [x / 1e6 for x in v] for k, v in T["exp3b-r1"].items()}
r2 = {k: [x / 1e6 for x in v] for k, v in T["exp3b-r2"].items()}
for agg in ("SUM", "AVG", "COUNT"):
    x, y = S(r1[(agg, "full_he")])[0], S(r2[(agg, "full_he")])[0]
    out(f"[exp3b-r1 vs exp3b-r2] full_he {agg}: {x / 1e3:.4g} vs {y / 1e3:.4g} s, diff {100 * (y - x) / x:+.2f}%")
out("[exp3a] full_he sigma=1%%: %.4g s (other job, same cell as exp3b)" % (S(ge[("full_he", 0.01)])[0] / 1e3))

out("")
out("=== EXP 3 N sweep (exp3c, P1, sigma=1%) ===")
gf = cells("exp3c", "exp3c.csv", lambda r: (r["layout"], r["approach"], int(r["n"])))
for lay in ("clustered", "scattered"):
    ns = sorted({k[2] for k in gf if k[0] == lay})
    out(f"[exp3c] {lay}  " + "  ".join("N=%g: he %.4g s, pqz %.4g ms, ratio %.3g" % (
        n, S(gf[(lay, "full_he", n)])[0] / 1e3, S(gf[(lay, "pqz", n)])[0], S(gf[(lay, "full_he", n)])[0] / S(gf[(lay, "pqz", n)])[0]) for n in ns))
    out(f"[exp3c] {lay} slopes: he %.3f pqz %.3f" % (slope(ns, [S(gf[(lay, "full_he", n)])[0] for n in ns]), slope(ns, [S(gf[(lay, "pqz", n)])[0] for n in ns])))

# ================================================================== EXP 5
out("")
out("=== EXP 5 ledger ===")
lat = cells("ledger-with-tx-auth", "exp5a_latency_throughput.csv", lambda r: (r["system"], int(r["q"])), val=lambda r: float(r["lat_p50_ns"]) / 1e6)
thr = cells("ledger-with-tx-auth", "exp5a_latency_throughput.csv", lambda r: (r["system"], int(r["q"])), val=lambda r: float(r["throughput_tx_per_s"]))
for sysn in ("pqz", "per_record_baseline"):
    for q in (1, 10, 25, 50, 100, 200):
        out("[ledger-with-tx-auth] %s q=%d p50 %.4g ms [%.4g-%.4g]  thr %.0f tx/s [%.0f-%.0f]" % (
            (sysn, q) + S(get(lat, (sysn, q)))[:3] + S(get(thr, (sysn, q)))[:3]))
gv = cells("ledger-with-tx-auth", "exp5b_governance.csv", lambda r: r["op"], val=lambda r: float(r["op_latency_ns"]) / 1e6)
for k in sorted(gv):
    line("ledger-with-tx-auth", "governance " + k, gv[k])
g5 = defaultdict(set)
for r in R.rd("ledger-with-tx-auth", "exp5c_bytes_per_epoch.csv"):
    g5[(r["system"], r["N"], r["method"])].add(r["bytes_total"])
out(f"[ledger-with-tx-auth] bytes per epoch: {dict(g5)}")
gn = cells("ledger-no-tx-auth", "exp5a_latency_throughput.csv", lambda r: (r["system"], int(r["q"])), val=lambda r: float(r["lat_p50_ns"]) / 1e6)
out("[ledger-no-tx-auth] no tx-auth: pqz p50 q=1 %.4g, q=200 %.4g ms" % (S(get(gn, ("pqz", 1)))[0], S(get(gn, ("pqz", 200)))[0]))

# ================================================================== EXP 6
out("")
out("=== EXP 6 ablation ===")
q_full = S(g[("clustered", "P4", "pqz")])
q_abl = S(g[("clustered", "P4", "prot_full_scan")])
out("[exp2a] block filtering (clustered P4): full %.4g [%.4g-%.4g], ablated %.4g [%.4g-%.4g]" % (q_full[:3] + q_abl[:3]))
out("[exp2a]   O_j %+.0f%%, range %+.0f%% to %+.0f%%" % oj(q_full, q_abl))
s_full = S(r1[("SUM", "pqz")])
s_abl = S(r1[("SUM", "full_he")])
out("[exp3b-r1] selective HE: full %.4g, ablated %.4g ms; O_j %+.0f%% range %+.0f%% to %+.0f%%" % ((s_full[0], s_abl[0]) + oj(s_full, s_abl)))
s_full2 = S(r2[("SUM", "pqz")])
s_abl2 = S(r2[("SUM", "full_he")])
out("[exp3b-r2] selective HE r2: full %.4g, ablated %.4g ms; O_j %+.0f%% range %+.0f%% to %+.0f%%" % ((s_full2[0], s_abl2[0]) + oj(s_full2, s_abl2)))
out("[exp2a + exp3b-r1] Stage A total (query P4 + r1 SUM): full %.4g ms; without block filtering %.4g ms (%+.1f%%)" % (
    q_full[0] + s_full[0], q_abl[0] + s_full[0], 100 * (q_abl[0] - q_full[0]) / (q_full[0] + s_full[0])))
ga = pcells(lambda r: (int(r["g_blocks"]), r["mode"]), "prove_s", 1e3, R.rd("proofbench-ablation", "raw.csv"))
for gblk in (1, 4, 16, 64):
    fu, ab_ = S(get(ga, (gblk, "batched"))), S(get(ga, (gblk, "per_block")))
    out("[proofbench-ablation] batched RC G=%d: full %.4g ms [%.4g-%.4g], ablated %.4g ms [%.4g-%.4g], O_j %+.2f%% range %+.1f%% to %+.1f%%, ratio %.3g" % (
        (gblk,) + fu[:3] + ab_[:3] + oj(fu, ab_) + (ab_[0] / fu[0],)))
gt = pcells(lambda r: (int(r["g_blocks"]), r["mode"]), "trace_s", 1e3, R.rd("proofbench-ablation", "raw.csv"))
out("[proofbench-ablation] trace_s medians (ms): " + str({k: round(S(v)[0], 1) for k, v in gt.items()}))
gb2 = pcells(lambda r: (int(r["g_blocks"]), r["mode"]), "proof_bytes", 1 / 1024, R.rd("proofbench-ablation", "raw.csv"))
out("[proofbench-ablation] proof KiB medians: " + str({k: round(S(v)[0], 1) for k, v in gb2.items()}))

out("")
out("=== R_CoverM (covermerkle-g2000, G=2000; three retained-block counts) ===")
cm = R.rd("covermerkle-g2000", "raw.csv")
for rr in ("21", "500", "1987"):
    sub = [r for r in cm if W.is_timed(r) and r["r_retained"] == rr]
    if not sub:
        sys.exit(f"REFUSING: covermerkle-g2000 has no timed rows for r_retained={rr}")
    out(f"[covermerkle-g2000] retained blocks {rr}")
    for col, lab, sc, un in (("prove_s", "prove", 1, "s"), ("trace_s", "trace", 1, "s"), ("verify_s", "verify", 1e3, "ms")):
        line("covermerkle-g2000", "  " + lab, [float(r[col]) * sc for r in sub], un)
    line("covermerkle-g2000", "  proof", [float(r["proof_bytes"]) / 1024 for r in sub], "KiB")
    line("covermerkle-g2000", "  prove peak RSS", [float(r["prove_peak_rss_kb"]) / 1048576 for r in sub], "GiB")

out("")
out("=== chunked single proofs (3 runs, no warm-up) ===")
ch = [r for r in R.rd("chunked-single", "raw.csv") if W.is_timed(r)]
for rel in ("rc", "exec"):
    rr = [r for r in ch if r["rel"] == rel]
    if not rr:
        sys.exit(f"REFUSING: chunked-single has no timed rows for rel={rel}")
    for col in ("prove_total_s", "trace_total_s", "prove_only_total_s", "verify_total_s"):
        line("chunked-single", f"{rel} {col}", [float(r[col]) for r in rr], "s")
    line("chunked-single", f"{rel} proof KiB", [float(r["proof_bytes_sum"]) / 1024 for r in rr], "KiB")
    line("chunked-single", f"{rel} peak RSS GiB", [float(r["prove_peak_rss_kb_max_chunk"]) / 1048576 for r in rr], "GiB")
    out(f"[chunked-single] {rel} m_records {rr[0]['m_records']} n_chunks {rr[0]['n_chunks']}")

# ================================================================== alone-checks
out("")
out("=== ALONE-CHECKS (S2 value vs alone value; rule: > 10% -> alone value used in the paper) ===")
ac = W.alone_compare(R, ok_ac)
if not ac:
    out("no alone-check job present in the results folder; nothing compared")
for fam, (kc, rows) in ac.items():
    for r in rows:
        k = len(kc)
        out(f"[{r[k]} vs ac-{fam if fam != 'exp3c' else 'exp3c-n10000'}] {fam} {r[:k]}: S2 {r[k + 2]:.4g} ms (n={r[k + 1]}), alone {r[k + 4]:.4g} ms (n={r[k + 3]}),"
            f" diff {r[-2]:+.2f}%{'  ** OVER 10% **' if r[-1] else ''}")
    out(f"   {fam}: largest |diff| {max(abs(r[-2]) for r in rows):.2f}%")
for missing in W.ALONE_CHECKS:
    if missing not in ok_ac:
        out(f"[{missing}] not present (optional), not compared")

if args.txt:
    with open(args.txt, "w") as fh:
        fh.write("\n".join(_buf) + "\n")
