#!/usr/bin/env python3
"""Summarize results/cover-*/raw.csv: per point median (min-max) over the timed (warmup = 0) runs. Usage: summarize_cover.py raw.csv"""
import csv, sys, statistics as st
from collections import OrderedDict

rows = list(csv.DictReader(open(sys.argv[1])))
pts = OrderedDict()
fails = []
for r in rows:
    key = (r['experiment'], r['rel'], int(r['g_blocks']), int(r['r_retained']))
    if r['rule'] == 'point failed':
        fails.append((key, r['note']))
        continue
    if r['warmup'] == '1':
        continue
    pts.setdefault(key, []).append(r)

def col(rs, c):
    return [float(r[c]) for r in rs if r[c] != '']

def fmt(v, scale=1.0, nd=4):
    return f"{st.median(v)*scale:.{nd}f} ({min(v)*scale:.{nd}f}-{max(v)*scale:.{nd}f})"

print("median (min-max) over timed runs; times in s (verify in ms); proof in KiB; RSS in MiB")
print("experiment | G | r | n_records | runs | trace rows | trace_s | prove_s | verify_ms | proof KiB (median) | prove peak RSS MiB (median, max) | conj/udr/ldr")
for k, rs in pts.items():
    r0 = rs[0]
    rss = col(rs, 'prove_peak_rss_kb')
    print(f"{k[0]} | {k[2]} | {k[3]} | {r0['n_records'] or '-'} | {len(rs)} | {r0['trace_rows']} | {fmt(col(rs,'trace_s'))} | "
          f"{fmt(col(rs,'prove_s'))} | {fmt(col(rs,'verify_s'),1000,3)} | {st.median(col(rs,'proof_bytes'))/1024:.1f} | "
          f"{st.median(rss)/1024:.0f}, {max(rss)/1024:.0f} | {r0['conj_bits']}/{r0['udr_bits']}/{r0['ldr_bits']}")
for k, n in fails:
    print(f"FAILED point {k}: {n}")
