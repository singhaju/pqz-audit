#!/usr/bin/env python3
"""Summarize proofbench raw.csv: per point median, min, max over the timed (non warm-up) runs. Usage: summarize.py raw.csv"""
import csv, sys, statistics as st
from collections import OrderedDict

rows = list(csv.DictReader(open(sys.argv[1])))
pts = OrderedDict()
for r in rows:
    if r['warmup'] == '1':
        continue
    key = (r['experiment'], r['rel'], r['n_records'], r['depth'], r['q'], r['mode'])
    pts.setdefault(key, []).append(r)

def col(rs, c):
    v = [float(r[c]) for r in rs if r[c] != '']
    return v

def fmt(v, scale=1.0, nd=4):
    if not v:
        return '-'
    return f"{st.median(v)*scale:.{nd}f} ({min(v)*scale:.{nd}f}-{max(v)*scale:.{nd}f})"

print("SCALE: median (min-max) over timed runs; times in s; sizes in KiB; RSS in MiB")
print("rel | N_Q | depth | runs | rule | trace rows | trace_s | prove_s | verify_s | proof KiB | prove peak RSS MiB | conj/udr/ldr bits")
for k, rs in pts.items():
    if k[0] != 'scale':
        continue
    r0 = rs[0]
    print(f"{k[1]} | {k[2] or '-'} | {k[3] or '-'} | {len(rs)} | {r0['rule'][:28]} | {r0['trace_rows']} | "
          f"{fmt(col(rs,'trace_s'))} | {fmt(col(rs,'prove_s'))} | {fmt(col(rs,'verify_s'),1000,3)} ms | "
          f"{st.median(col(rs,'proof_bytes'))/1024:.1f} | {st.median(col(rs,'prove_peak_rss_kb'))/1024:.0f} | "
          f"{r0['conj_bits']}/{r0['udr_bits']}/{r0['ldr_bits']}")
print()
print("Q: total time of q verifications (s), median (min-max); per-verification mean in ms")
print("rel | mode | q | runs | total_s | per verify ms | bundle bytes")
for k, rs in pts.items():
    if k[0] != 'q':
        continue
    r0 = rs[0]
    print(f"{k[1]} | {k[5]} | {k[4]} | {len(rs)} | {fmt(col(rs,'total_verify_s'),1,4)} | "
          f"{st.median(col(rs,'verify_s'))*1000:.3f} | {r0['proof_bytes']}")

# Exp 6 ablation ("w/o Batched RC"): batched (one proof over G*500 records) vs per_block (G proofs of 500 records).
# Times/sizes of per_block are sums over its G proofs. Ratio = per_block median / batched median.
abl = OrderedDict()
for r in rows:
    if r['experiment'] != 'ablation' or r['warmup'] == '1':
        continue
    abl.setdefault((int(r['g_blocks']), r['mode']), []).append(r)
if abl:
    print()
    print("ABLATION (R_RC, 500 records per block): median (min-max) over timed runs; times in s (verify in ms); proof in KiB; RSS in MiB")
    print("G | series | runs | trace_s | prove_s | verify ms | proof KiB | prove peak RSS MiB")
    for (g, ser), rs in sorted(abl.items(), key=lambda kv: (kv[0][0], kv[0][1] != 'batched')):
        print(f"{g} | {ser} | {len(rs)} | {fmt(col(rs,'trace_s'))} | {fmt(col(rs,'prove_s'))} | "
              f"{fmt(col(rs,'verify_s'),1000,3)} | {st.median(col(rs,'proof_bytes'))/1024:.1f} | "
              f"{st.median(col(rs,'prove_peak_rss_kb'))/1024:.0f}")
    print("ratio per_block / batched (ratio of medians)")
    print("G | trace_s | prove_s | trace_s+prove_s | verify | proof bytes | prove peak RSS")
    for g in sorted({k[0] for k in abl}):
        b, p = abl.get((g, 'batched')), abl.get((g, 'per_block'))
        if not b or not p:
            print(f"{g} | (missing series)")
            continue
        m = lambda rs, c: st.median(col(rs, c))
        tp = lambda rs: st.median([float(r['trace_s']) + float(r['prove_s']) for r in rs])
        print(f"{g} | {m(p,'trace_s')/m(b,'trace_s'):.2f} | {m(p,'prove_s')/m(b,'prove_s'):.2f} | {tp(p)/tp(b):.2f} | "
              f"{m(p,'verify_s')/m(b,'verify_s'):.2f} | {m(p,'proof_bytes')/m(b,'proof_bytes'):.2f} | "
              f"{m(p,'prove_peak_rss_kb')/m(b,'prove_peak_rss_kb'):.2f}")
