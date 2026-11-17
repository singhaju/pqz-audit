#!/usr/bin/env bash
# usage: run_exp3c.sh <results-dir>   (exp3c N sweep, 30 timed + 3 warm-up; full_he 10 + 1 by the program's own rule)
set -u
OUT="$1"
cd "$(dirname "$0")"
mkdir -p "$OUT"
cargo build --release >/dev/null 2>&1 || { echo "build failed"; exit 1; }
echo "$(date -u +%FT%TZ) start exp3c load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/progress.log"
s=$(date +%s)
./target/release/exp exp3c --runs 30 --warmup 3 --out "$OUT/exp3c" > "$OUT/exp3c.stdout" 2> "$OUT/exp3c.stderr"
rc=$?
echo "$(date -u +%FT%TZ) end exp3c rc=$rc seconds=$(( $(date +%s) - s )) load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/progress.log"
echo "$(date -u +%FT%TZ) EXP3C DONE rc=$rc" >> "$OUT/progress.log"
