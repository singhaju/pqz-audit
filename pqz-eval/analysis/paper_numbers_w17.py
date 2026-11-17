"""Every number that work17 prints for Exp 2, 3, 5, 6 and the proof pieces, from results/cloud-w17.

Usage: python3 -I paper_numbers_w17.py > out-w17/paper_numbers_w17.txt
Medians of timed rows (warmup == 0); min/max = range of timed rows.
O_j range: (T_abl_min - T_full_max)/T_full_max to (T_abl_max - T_full_min)/T_full_min (as in work16).
"""
import csv, math, os, statistics as st
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(BASE, "results", "cloud-w17")


def rd(p):
    with open(os.path.join(R, p), newline="") as fh:
        return list(csv.DictReader(fh))


def cells(rows, keyf, val=lambda r: float(r["time_ns"]) / 1e6):
    g = defaultdict(list)
    for r in rows:
        if r.get("warmup", "0") in ("0", "") and r.get("kind", "timed") != "warmup":
            g[keyf(r)].append(val(r))
    return g


def S(v):
    return st.median(v), min(v), max(v), len(v)


def line(label, v, unit="ms", fmt="%.4g"):
    m, lo, hi, n = S(v)
    print(f"{label}: median {fmt % m} {unit} (min {fmt % lo}, max {fmt % hi}, n={n})")
    return m, lo, hi


def slope(xs, ys):
    lx, ly = [math.log(x) for x in xs], [math.log(y) for y in ys]
    mx, my = sum(lx) / len(lx), sum(ly) / len(ly)
    return sum((a - mx) * (b - my) for a, b in zip(lx, ly)) / sum((a - mx) ** 2 for a in lx)


def oj(full, abl):
    return ((abl[0] - full[0]) / full[0] * 100,
            (abl[1] - full[2]) / full[2] * 100,
            (abl[2] - full[1]) / full[1] * 100)


print("=== EXP 2 table (exp2a-alone; 30 runs after 3 warm-up) ===")
a = rd("exp2a-alone/exp2a.csv")
g = cells(a, lambda r: (r["layout"], r["predicate"], r["approach"]))
for lay in ("clustered", "scattered"):
    for ap in ("trad_scan", "prot_full_scan", "pqz"):
        print(lay, ap, "  ".join("%s %.4g [%.4g-%.4g]" % ((p,) + S(g[(lay, p, ap)])[:3]) for p in ("P1", "P2", "P3", "P4")))
ret = defaultdict(set)
for r in a:
    if r["approach"] == "pqz" and r["warmup"] == "0":
        ret[(r["layout"], r["predicate"])].add((r["n_retained_blocks"], r["n_blocks"]))
print("retained/total blocks", dict(ret))
print("scattered pqz range over P1..P4: %.4g-%.4g ms" % (min(S(g[("scattered", p, "pqz")])[0] for p in ("P1", "P2", "P3", "P4")), max(S(g[("scattered", p, "pqz")])[0] for p in ("P1", "P2", "P3", "P4"))))
for p in ("P1", "P2", "P3", "P4"):
    for lay in ("clustered", "scattered"):
        pq, fs = S(g[(lay, p, "pqz")])[0], S(g[(lay, p, "prot_full_scan")])[0]
        print(f"  {lay} {p}: protected full / PQZ = {fs / pq:.3g}; PQZ vs full scan {100 * (pq - fs) / fs:+.2f}%")

print("\n=== EXP 2 selectivity (exp2bd, dense; parallel phase) ===")
b = rd("exp2bd/exp2bd.csv")
gb = cells(b, lambda r: (r["layout"], r["approach"], float(r["sigma"])))
sig = sorted({k[2] for k in gb})
for lay in ("clustered", "scattered"):
    for ap in ("trad_scan", "prot_full_scan", "pqz"):
        print(lay, ap, "  ".join("%g%%:%.4g" % (s * 100, S(gb[(lay, ap, s)])[0]) for s in sig))
for ap in ("prot_full_scan",):
    for lay in ("clustered", "scattered"):
        ms = [S(gb[(lay, ap, s)])[0] for s in sig]
        print(f"{lay} {ap} range over sweep {min(ms):.4g}-{max(ms):.4g}")
pq = [S(gb[("clustered", "pqz", s)])[0] for s in sig]
print("clustered pqz slope over sigma: %.3f" % slope([s * 1e6 for s in sig], pq))
print("gap protected full / pqz at 25%%: %.3g ; at 0.1%%: %.3g" % (S(gb[("clustered", "prot_full_scan", 0.25)])[0] / pq[-1], S(gb[("clustered", "prot_full_scan", 0.001)])[0] / pq[0]))
# crossover with traditional scan (clustered)
for i, s in enumerate(sig):
    t = S(gb[("clustered", "trad_scan", s)])[0]
    print(f"  sigma {s*100:g}%: pqz {pq[i]:.4g} vs trad {t:.4g} -> {'pqz below' if pq[i] < t else 'pqz above'} (ratio {t / pq[i]:.3g})")
for lay in ("scattered",):
    ps = [S(gb[(lay, "pqz", s)])[0] for s in sig]
    print("scattered pqz 0.1%:", ps[0], "25%:", ps[-1])

print("\n=== EXP 2 block size (exp2c; parallel phase) ===")
c = rd("exp2c/exp2c.csv")
gc = cells(c, lambda r: (r["layout"], r["approach"], int(r["mb"])))
for lay in ("clustered", "scattered"):
    print(lay, "pqz", "  ".join("m_B=%d:%.4g" % (m, S(gc[(lay, "pqz", m)])[0]) for m in (100, 250, 500, 1000)))
    print(lay, "prot_full_scan", "  ".join("m_B=%d:%.4g" % (m, S(gc[(lay, "prot_full_scan", m)])[0]) for m in (100, 250, 500, 1000)))

print("\n=== cross-checks of the same cell across jobs (clustered P4 sigma=1%) ===")
for nm, p in (("exp2a (parallel)", "exp2a/exp2a.csv"), ("exp2a-alone", "exp2a-alone/exp2a.csv")):
    gg = cells(rd(p), lambda r: (r["layout"], r["predicate"], r["approach"]))
    print(nm, "pqz P4 %.4g, prot_full P4 %.4g, trad P4 %.4g" % tuple(S(gg[("clustered", "P4", x)])[0] for x in ("pqz", "prot_full_scan", "trad_scan")))
for nm, p in (("exp2b", "exp2b/exp2b.csv"), ("exp2bd", "exp2bd/exp2bd.csv"), ("exp2c(mb500)", "exp2c/exp2c.csv")):
    rows = [r for r in rd(p) if r["layout"] == "clustered" and abs(float(r["sigma"]) - 0.01) < 1e-9 and (r["mb"] == "500")]
    gg = cells(rows, lambda r: r["approach"])
    print(nm, "pqz %.4g, prot_full %.4g, trad %.4g" % tuple(S(gg[x])[0] for x in ("pqz", "prot_full_scan", "trad_scan")))

print("\n=== EXP 3 sigma sweep: Full-Domain HE (exp3a) with the PQZ-Audit values of the same job ===")
e = rd("exp3a/exp3a.csv")
ge = cells(e, lambda r: (r["approach"], float(r["sigma"])))
he_sig = sorted({k[1] for k in ge if k[0] == "full_he"})
for s in he_sig:
    he, pz = S(ge[("full_he", s)])[0], S(ge[("pqz", s)])[0]
    print(f"sigma {s*100:g}%: full_he {he/1e3:.4g} s [{S(ge[('full_he', s)])[1]/1e3:.4g}-{S(ge[('full_he', s)])[2]/1e3:.4g}], pqz {pz:.4g} ms, R_HE {100*(1-pz/he):.2f}%, ratio {he/pz:.3g}")
pzs = sorted({k[1] for k in ge if k[0] == "pqz"})
print("pqz slope (exp3a):", slope([s * 1e6 for s in pzs], [S(ge[("pqz", s)])[0] for s in pzs]))
print("full_he over sweep: %.4g-%.4g s" % (min(S(ge[("full_he", s)])[0] for s in he_sig) / 1e3, max(S(ge[("full_he", s)])[0] for s in he_sig) / 1e3))
print("full_he overall min/max over all runs: %.4g-%.4g s" % (min(min(ge[("full_he", s)]) for s in he_sig) / 1e3, max(max(ge[("full_he", s)]) for s in he_sig) / 1e3))
d = rd("exp3ad/exp3ad.csv")
gd = cells(d, lambda r: (r["approach"], float(r["sigma"])))
ds = sorted({k[1] for k in gd if k[0] == "pqz"})
print("pqz dense: ", "  ".join("%g%%:%.4g" % (s * 100, S(gd[("pqz", s)])[0]) for s in ds))
print("pqz dense slope: %.3f ; min n_Q: %.4g ms (n_Q=1000), max: %.4g ms (n_Q=250000)" % (slope([s * 1e6 for s in ds], [S(gd[("pqz", s)])[0] for s in ds]), S(gd[("pqz", ds[0])])[0], S(gd[("pqz", ds[-1])])[0]))
print("per-ciphertext PQZ cost at 1000..250000: ", "  ".join("%.1f us" % (S(gd[("pqz", s)])[0] * 1e3 / (s * 1e6)) for s in ds))
print("plain dense: %.4g ms at 1e3, %.4g at 2.5e5" % (S(gd[("plain_agg", ds[0])])[0], S(gd[("plain_agg", ds[-1])])[0]))
# R_HE using dense pqz (as drawn) and HE from exp3a
for s in he_sig:
    he, pz = S(ge[("full_he", s)])[0], S(gd[("pqz", s)])[0]
    print(f"  R_HE with dense pqz sigma {s*100:g}%: {100*(1-pz/he):.2f}%")
print("break-even n_Q (HE cost / per-ct cost) ~ %.3g records" % (S(ge[("full_he", 0.01)])[0] / (S(gd[("pqz", 0.25)])[0] / 250000)))

print("\n=== EXP 3 operator table (exp3b r1 = primary, r2 = repeat), sigma=1%, N=1e6 ===")
for nm in ("exp3b-r1", "exp3b-r2"):
    t = cells(rd(f"{nm}/exp3b.csv"), lambda r: (r["agg"], r["approach"]), val=lambda r: float(r["time_ns"]))
    print(nm)
    for agg in ("SUM", "AVG", "COUNT"):
        print("  ", agg, "  ".join("%s %.4g ms [%.4g-%.4g]" % ((ap,) + tuple(x / 1e6 for x in S(t[(agg, ap)])[:3])) if agg != "COUNT" or ap == "full_he" else "%s %.4g ns [%.4g-%.4g]" % ((ap,) + S(t[(agg, ap)])[:3]) for ap in ("plain_agg", "full_he", "pqz")))
        he, pz = S(t[(agg, "full_he")])[0], S(t[(agg, "pqz")])[0]
        if agg != "COUNT":
            hi = oj((pz, pz, pz), (he, he, he))[0]
            print(f"      R_HE {100*(1-pz/he):.2f}%   ratio {he/pz:.4g}")
r1 = cells(rd("exp3b-r1/exp3b.csv"), lambda r: (r["agg"], r["approach"]), val=lambda r: float(r["time_ns"]) / 1e6)
r2 = cells(rd("exp3b-r2/exp3b.csv"), lambda r: (r["agg"], r["approach"]), val=lambda r: float(r["time_ns"]) / 1e6)
for agg in ("SUM", "AVG", "COUNT"):
    x, y = S(r1[(agg, "full_he")])[0], S(r2[(agg, "full_he")])[0]
    print(f"r1 vs r2 full_he {agg}: {x/1e3:.4g} vs {y/1e3:.4g} s, diff {100*(y-x)/x:+.2f}%")
print("exp3a full_he sigma=1%% (parallel, other job): %.4g s" % (S(ge[("full_he", 0.01)])[0] / 1e3))

print("\n=== EXP 3 N sweep (exp3c, P1, sigma=1%) ===")
f = rd("exp3c/exp3c.csv")
gf = cells(f, lambda r: (r["layout"], r["approach"], int(r["n"])))
for lay in ("clustered", "scattered"):
    ns = sorted({k[2] for k in gf if k[0] == lay})
    print(lay, "  ".join("N=%g: he %.4g s, pqz %.4g ms, ratio %.3g" % (n, S(gf[(lay, "full_he", n)])[0] / 1e3, S(gf[(lay, "pqz", n)])[0], S(gf[(lay, "full_he", n)])[0] / S(gf[(lay, "pqz", n)])[0]) for n in ns))
    print(lay, "slopes: he %.3f pqz %.3f" % (slope(ns, [S(gf[(lay, "full_he", n)])[0] for n in ns]), slope(ns, [S(gf[(lay, "pqz", n)])[0] for n in ns])))

print("\n=== EXP 1 PQZ-Audit rows (w17 session) ===")
x1 = cells(rd("exp1/exp1.csv"), lambda r: (r["series"], int(r["n"])))
for sr in ("sigma1pct", "fixed_nq1000"):
    ns = sorted({k[1] for k in x1 if k[0] == sr})
    print(sr, "  ".join("N=%g:%.4g" % (n, S(x1[(sr, n)])[0]) for n in ns), " slope %.3f" % slope(ns, [S(x1[(sr, n)])[0] for n in ns]))

print("\n=== EXP 5 ledger ===")
l = rd("ledger-with-tx-auth/exp5a_latency_throughput.csv")
for sysn in ("pqz", "per_record_baseline"):
    gl = cells([r for r in l if r["kind"] == "timed"], lambda r: (r["system"], int(r["q"])), val=lambda r: float(r["lat_p50_ns"]) / 1e6)
    gt = cells([r for r in l if r["kind"] == "timed"], lambda r: (r["system"], int(r["q"])), val=lambda r: float(r["throughput_tx_per_s"]))
    for q in (1, 10, 25, 50, 100, 200):
        print(sysn, "q=%d p50 %.4g ms [%.4g-%.4g]  thr %.0f tx/s [%.0f-%.0f]" % ((q,) + S(gl[(sysn, q)])[:3] + S(gt[(sysn, q)])[:3]))
gv = cells(rd("ledger-with-tx-auth/exp5b_governance.csv"), lambda r: r["op"], val=lambda r: float(r["op_latency_ns"]) / 1e6)
for k in sorted(gv):
    line("governance " + k, gv[k])
g5 = defaultdict(set)
for r in rd("ledger-with-tx-auth/exp5c_bytes_per_epoch.csv"):
    g5[(r["system"], r["N"], r["method"])].add(r["bytes_total"])
print("bytes per epoch:", dict(g5))
try:
    gn = cells(rd("ledger-no-tx-auth/exp5a_latency_throughput.csv"), lambda r: (r["system"], int(r["q"])), val=lambda r: float(r["lat_p50_ns"]) / 1e6)
    print("no tx-auth: pqz p50 q=1 %.4g, q=200 %.4g ms" % (S(gn[("pqz", 1)])[0], S(gn[("pqz", 200)])[0]))
except Exception as ex:
    print("no tx-auth read failed", ex)

print("\n=== EXP 6 ablation ===")
q_full = S(g[("clustered", "P4", "pqz")][:])
q_abl = S(g[("clustered", "P4", "prot_full_scan")][:])
print("block filtering (exp2a-alone, clustered P4): full %.4g [%.4g-%.4g], ablated %.4g [%.4g-%.4g]" % (q_full[:3] + q_abl[:3]))
o = oj(q_full, q_abl)
print("  O_j %+.0f%%, range %+.0f%% to %+.0f%%" % o)
s_full = S(r1[("SUM", "pqz")]); s_abl = S(r1[("SUM", "full_he")])
print("selective HE r1: full %.4g, ablated %.4g ms; O_j %+.0f%% range %+.0f%% to %+.0f%%" % ((s_full[0], s_abl[0]) + oj(s_full, s_abl)))
s_full2 = S(r2[("SUM", "pqz")]); s_abl2 = S(r2[("SUM", "full_he")])
print("selective HE r2: full %.4g, ablated %.4g ms; O_j %+.0f%% range %+.0f%% to %+.0f%%" % ((s_full2[0], s_abl2[0]) + oj(s_full2, s_abl2)))
print("Stage A total (exp2a-alone query P4 + r1 SUM): full %.4g ms; without block filtering %.4g ms (%+.1f%%)" % (q_full[0] + s_full[0], q_abl[0] + s_full[0], 100 * (q_abl[0] - q_full[0]) / (q_full[0] + s_full[0])))
ab = rd("proofbench-ablation/raw.csv")
ga = cells(ab, lambda r: (int(r["g_blocks"]), r["mode"]), val=lambda r: float(r["prove_s"]) * 1e3)
for gblk in (1, 4, 16, 64):
    fu, ab_ = S(ga[(gblk, "batched")]), S(ga[(gblk, "per_block")])
    print("batched RC G=%d: full %.4g ms [%.4g-%.4g], ablated %.4g ms [%.4g-%.4g], O_j %+.2f%% range %+.1f%% to %+.1f%%, ratio %.3g" % ((gblk,) + fu[:3] + ab_[:3] + oj(fu, ab_) + (ab_[0] / fu[0],)))
gt = cells(ab, lambda r: (int(r["g_blocks"]), r["mode"]), val=lambda r: float(r["trace_s"]) * 1e3)
print("trace_s medians:", {k: round(S(v)[0], 1) for k, v in gt.items()})
gb2 = cells(ab, lambda r: (int(r["g_blocks"]), r["mode"]), val=lambda r: float(r["proof_bytes"]) / 1024)
print("proof KiB medians:", {k: round(S(v)[0], 1) for k, v in gb2.items()})

print("\n=== R_CoverM (covermerkle, G=2000; three retained-block counts, 30 runs + 3 warm-up each) ===")
cm = rd("covermerkle-g2000/raw.csv")
for rr in ("21", "500", "1987"):
    sub = [r for r in cm if r["warmup"] == "0" and r["r_retained"] == rr]
    print("retained blocks", rr)
    for col, lab, sc, un in (("prove_s", "prove", 1, "s"), ("trace_s", "trace", 1, "s"), ("verify_s", "verify", 1e3, "ms")):
        line("  " + lab, [float(r[col]) * sc for r in sub], un, "%.4g")
    line("  proof", [float(r["proof_bytes"]) / 1024 for r in sub], "KiB", "%.4g")
    line("  prove peak RSS", [float(r["prove_peak_rss_kb"]) / 1048576 for r in sub], "GiB", "%.4g")

print("\n=== chunked single proofs (3 runs, no warm-up) ===")
ch = rd("chunked-single/raw.csv")
for rel in ("rc", "exec"):
    rr = [r for r in ch if r["rel"] == rel]
    for col in ("prove_total_s", "trace_total_s", "prove_only_total_s", "verify_total_s"):
        line(f"{rel} {col}", [float(r[col]) for r in rr], "s", "%.4g")
    line(f"{rel} proof KiB", [float(r["proof_bytes_sum"]) / 1024 for r in rr], "KiB", "%.4g")
    line(f"{rel} peak RSS GiB", [float(r["prove_peak_rss_kb_max_chunk"]) / 1048576 for r in rr], "GiB", "%.4g")
    print(rel, "m_records", rr[0]["m_records"], "n_chunks", rr[0]["n_chunks"])
