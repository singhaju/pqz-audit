#!/usr/bin/env bash
# usage: run_exp3b_only.sh <results-dir>  (exp3b alone, 30 timed + 3 warm-up)
set -u
OUT="$1"
cd "$(dirname "$0")"
echo "$(date -u +%FT%TZ) start exp3b load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/progress.log"
s=$(date +%s)
./target/release/exp exp3b --runs 30 --warmup 3 --out "$OUT/exp3b" > "$OUT/exp3b.stdout" 2> "$OUT/exp3b.stderr"
rc=$?
echo "$(date -u +%FT%TZ) end exp3b rc=$rc seconds=$(( $(date +%s) - s )) load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/progress.log"
echo "$(date -u +%FT%TZ) ALL DONE rc=$rc" >> "$OUT/progress.log"
