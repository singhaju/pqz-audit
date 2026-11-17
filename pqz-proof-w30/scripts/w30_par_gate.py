#!/usr/bin/env python3
"""w30 parallel-chunk gate (lead, entry 443, written BEFORE the gate run). Plan UPGRADE-w30 section 5: go to cloud only if the laptop
paired ratio S2-seq / S4-par >= 1.10 at 5e4 or 1e5 (rel exec or rc). Same-boundary metric: S2 = trace_s + prove_s + bound_s (bound
measured once per child), S4 = prove_s (wall clock: boundary + pools + traces + proofs). Ratio = median over rounds of the per-round
median of paired ratios (rep k with rep k); noise p90/min > 1.15 = NOISY, cannot pass (w29 rule). Reads raw CSVs only."""
import csv, statistics as st, os
D = os.environ.get("W30_OUT") or os.path.join(os.path.dirname(__file__), "..", "results", "w30-gate")
def p90(xs):
    xs = sorted(xs); k = 0.9 * (len(xs) - 1); f = int(k); c = min(f + 1, len(xs) - 1); return xs[f] + (xs[c] - xs[f]) * (k - f)
def load(rel, n):
    out, rnd, hdr = {}, -1, None
    for line in open(os.path.join(D, f"prove_{rel}_n{n}.raw.csv")):
        if line.startswith("# prove rel="): rnd += 1; continue
        if line.startswith("#"): continue
        row = next(csv.reader([line]))
        if hdr is None: hdr = row; continue
        r = dict(zip(hdr, row))
        if r["phase"] != "timed": continue
        t = float(r["prove_s"]) if r["label"] in ("S4", "S5") else float(r["trace_s"]) + float(r["prove_s"]) + float(r["bound_s"])
        out.setdefault(r["label"], {}).setdefault(rnd, []).append(t)
    return out
any_pass = False
for rel in ("exec", "rc"):
    for n in (50000, 100000):
        d = load(rel, n); a, b = d["S2"], d["S4"]
        per = [st.median([x / y for x, y in zip(a[k], b[k])]) for k in sorted(set(a) & set(b))]
        nz = [p90([x for v in s.values() for x in v]) / min(x for v in s.values() for x in v) for s in (a, b)]
        m = st.median(per); ok = m >= 1.10 and max(nz) <= 1.15; any_pass |= ok
        print(f"{rel} {n}: S2/S4 {m:.3f} (rounds {len(per)}, min {min(per):.3f} max {max(per):.3f}) noise S2 {nz[0]:.3f} S4 {nz[1]:.3f} "
              f"-> {'PASS' if ok else ('NOISY' if max(nz) > 1.15 else 'FAIL')}")
print("GATE (any cell PASS):", "PASS -> S4 goes to cloud" if any_pass else "NOT MET -> 'no gain on one machine'")
