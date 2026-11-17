#!/bin/bash
# Demo: one small end-to-end audit (N = 10,000 records, packed format P2r) with the existing program w35.
# It runs the audit pipeline of the program w35 (private query, STARK proofs, checks) and prints the main timings.
# Needs only cargo. Takes about 1-2 minutes for the first build, then about 1 second to run. No network after the build.
set -e
cd "$(dirname "$0")/../pqz-integrated-w46"
cargo build --release --locked --bin w35 2>&1 | tail -2
OUT="$(mktemp -d)"
./target/release/w35 run --setting P3 --n 10000 --layouts clustered --runs 1 \
  --chunk 4 --gap-merge 1 --fmt p2r --limit-s 60 --out "$OUT" > "$OUT/stdout.txt" 2>&1
python3 - "$OUT/raw.csv" <<'PY'
import csv, sys
r = list(csv.DictReader(open(sys.argv[1])))[0]
rows = [("records N", "n"), ("query result: matching records", "result_count"), ("query result: sum", "result_sum"),
        ("log generation (s)", "gen_s"), ("record-consistency proving (s)", "rc_prove_s"),
        ("authorization proof (s)", "auth_prove_s"), ("execution proof (s)", "exec_prove_s"),
        ("auditor-side check of proofs (s)", "aa_check_s"), ("requester verification (s)", "p7_s"),
        ("execution proof size (bytes)", "exec_proof_bytes"), ("proof security (conjectured bits)", "exec_conj_bits")]
print("PQZ-Audit demo: one audit, N=10,000, packed format P2r (laptop smoke run, not a paper number)")
for label, k in rows:
    if k in r: print(f"  {label:38s} {r[k]}")
print("Timings are for one run on this machine; the program writes failures.txt next to the raw file (empty = no failure).")
print("Raw output:", sys.argv[1])
PY
