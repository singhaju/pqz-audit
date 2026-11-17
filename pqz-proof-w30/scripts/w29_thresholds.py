#!/usr/bin/env python3
"""w29 threshold check (lead, entry 438). Reads results/w29/*.raw.csv (read-only) and applies journal2/UPGRADE-w29-plan.md section 2:
ratio = median over rounds of the per-round median of paired ratios (rep k of A with rep k of B, same round); min-max of the per-round
values; noise: p90/min of the raw timed times > 1.15 = noisy, cannot pass. Also prints the all-pairs median.
Sensitivity (entry 437 rule): round 2 of rc n=20000 (spans the suspend) left out, labelled as a check only."""
import csv, statistics as st, sys, os
D = os.environ.get("W29_DIR") or os.path.join(os.path.dirname(__file__), "..", "results", "w29")

def p90(xs):
    xs = sorted(xs); k = 0.9 * (len(xs) - 1); f = int(k); c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)

def prove(rel, n):
    """returns {label: {round: [prove_s by rep]}} for timed rows; round from '# prove rel=' lines."""
    out, rnd = {}, -1
    with open(os.path.join(D, f"prove_{rel}_n{n}.raw.csv")) as fh:
        hdr = None
        for line in fh:
            if line.startswith("# prove rel="): rnd += 1; continue
            if line.startswith("#"): continue
            row = next(csv.reader([line]))
            if hdr is None: hdr = row; continue
            r = dict(zip(hdr, row))
            if r["phase"] != "timed": continue
            out.setdefault(r["label"], {}).setdefault(rnd, []).append(float(r["prove_s"]))
    return out

def verify(kind, hashsel):
    out = {}
    with open(os.path.join(D, f"verify_{kind}.raw.csv")) as fh:
        rows = csv.DictReader(l for l in fh if not l.startswith("#"))
        for r in rows:
            if r["hashsel"] == hashsel and r["phase"] == "timed":
                out.setdefault(int(r["round"]), []).append(float(r["total_s"])); nq = r["n"]
    return out, nq

def noise(d):
    xs = [x for v in d.values() for x in v]; return p90(xs) / min(xs)

def ratio(a, b, skip=()):
    per, allp = [], []
    for k in sorted(set(a) & set(b)):
        if k in skip: continue
        pr = [x / y for x, y in zip(a[k], b[k])]; per.append(st.median(pr)); allp += pr
    return st.median(per), min(per), max(per), st.median(allp), len(per)

def sumd(a, b):
    return {k: [x + y for x, y in zip(a[k], b[k])] for k in set(a) & set(b)}

def line(name, thr, num, den, skip=()):
    m, lo, hi, ap, nr = ratio(num, den, skip)
    nz = max(noise(num), noise(den)); ok = m >= thr and nz <= 1.15
    print(f"{name}: ratio {m:.3f} (rounds {nr}, per-round min {lo:.3f} max {hi:.3f}; all-pairs median {ap:.3f}) threshold >= {thr} "
          f"noise p90/min num {noise(num):.3f} den {noise(den):.3f} -> {'PASS' if ok else ('NOISY' if nz > 1.15 else 'FAIL')}")

e5 = prove("exec", 50000)
line("T-P1 R_Exec 5e4 S0/S2", 1.40, e5["S0"], e5["S2"])
e2, r2 = prove("exec", 20000), prove("rc", 20000)
line("T-P2 Exec+RC 2e4 S0/S2", 1.28, sumd(e2["S0"], r2["S0"]), sumd(e2["S2"], r2["S2"]))
line("T-P2 sensitivity (round 2 of rc 2e4 left out; check only)", 1.28, sumd(e2["S0"], r2["S0"]), sumd(e2["S2"], r2["S2"]), skip=(1,))
b3, nq1 = verify("bundle3", "sha3"); p2, nq2 = verify("pair2", "blake3")
print(f"verify N_Q: bundle3 {nq1}, pair2 {nq2}")
line("T-V2 bundle3 sha3 / pair2 blake3", 1.10, b3, p2)
line("T-V1 same ratio", 2.40, b3, p2)
# decomposition (not thresholds)
for nm, a, b in [("A1-i only (sha3 bundle3/pair2)", b3, verify("pair2", "sha3")[0]),
                 ("Blake3 only (bundle3 sha3/blake3)", b3, verify("bundle3", "blake3")[0]),
                 ("exec chunked/single sha3", verify("execchunk", "sha3")[0], verify("execsingle", "sha3")[0]),
                 ("exec chunked/single blake3", verify("execchunk", "blake3")[0], verify("execsingle", "blake3")[0])]:
    m, lo, hi, ap, nr = ratio(a, b); print(f"  info {nm}: {m:.3f} (min {lo:.3f} max {hi:.3f})")
for rel in ("exec", "rc"):
    for n in (5000, 10000, 20000, 50000, 100000):
        d = prove(rel, n); m, lo, hi, _, _ = ratio(d["S0"], d["S2"]); m1, _, _, _, _ = ratio(d["S1"], d["S2"])
        print(f"  info prove {rel} {n}: S0/S2 {m:.3f} (min {lo:.3f} max {hi:.3f}) S1/S2 {m1:.3f} noise S0 {noise(d['S0']):.3f} S2 {noise(d['S2']):.3f}")
