#!/usr/bin/env python3
"""Median / min / max per point from results/<run>/raw.csv of `chunked` (warm-up rows and FAILED rows excluded from the stats).
Usage: python3 scripts/summarize_chunked.py results/chunked-1/raw.csv"""
import csv
import statistics as st
import sys
from collections import OrderedDict

COLS = ["prove_total_s", "trace_total_s", "prove_only_total_s", "verify_total_s", "proof_bytes_sum",
        "prove_peak_rss_kb_max_chunk", "max_chunk_prove_s"]

rows = list(csv.DictReader(open(sys.argv[1])))
pts = OrderedDict()
for r in rows:
    key = (r["experiment"], r["rel"], r["m_records"])
    pts.setdefault(key, {"timed": [], "warm": [], "failed": []})
    if r["note"].startswith("FAILED"):
        pts[key]["failed"].append(r)
    elif r["warmup"] == "1":
        pts[key]["warm"].append(r)
    else:
        pts[key]["timed"].append(r)

for (exp, rel, m), d in pts.items():
    t = d["timed"]
    head = f"{exp} rel={rel} M={m}"
    if t:
        head += f" chunks={t[0]['n_chunks']} (last chunk {t[0]['last_chunk_records']} records) timed_runs={len(t)} warmup_rows={len(d['warm'])}"
    print(head)
    for c in COLS:
        if not t:
            break
        v = [float(x[c]) for x in t]
        print(f"  {c:30s} median {st.median(v):14.4f}  min {min(v):14.4f}  max {max(v):14.4f}")
    if t:
        print(f"  loadavg1_start range {min(float(x['loadavg1_start']) for x in t)}-{max(float(x['loadavg1_start']) for x in t)}")
        print(f"  conj/udr/ldr bits (min over chunks, run 1): {t[0]['conj_bits']}/{t[0]['udr_bits']}/{t[0]['ldr_bits']}")
    for f in d["failed"]:
        print(f"  FAILED run {f['run']} (warmup={f['warmup']}): {f['note']}")
    print()
