#!/usr/bin/env bash
# usage: run_dense.sh <results-dir>
# Denser sweeps for the paper graphs (new experiment names; exp1/exp2b/exp3a are unchanged):
#   exp1d  (N sweep, 7 points x 2 series), exp2bd (selectivity, 9 points x 2 layouts),
#   exp3ad (selectivity, SUM, plain_agg + pqz only; no full_he, see FULL-RUN-PLAN.md).
# 30 timed + 3 warm-up, one job at a time, load gate 6.0 as in run_full.sh / run_full2.sh.
set -u
OUT="$1"
LOAD1=$(cut -d' ' -f1 /proc/loadavg)
if awk -v l="$LOAD1" 'BEGIN { exit !(l > 6.0) }'; then
  echo "refusing to start: 1-min load average is $LOAD1 (limit 6.0)"
  exit 3
fi
cd "$(dirname "$0")"
mkdir -p "$OUT"
cargo build --release >/dev/null 2>&1 || { echo "build failed"; exit 1; }
for e in exp1d exp2bd exp3ad; do
  echo "$(date -u +%FT%TZ) start $e load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/progress.log"
  s=$(date +%s)
  ./target/release/exp "$e" --runs 30 --warmup 3 --out "$OUT/$e" > "$OUT/$e.stdout" 2> "$OUT/$e.stderr"
  rc=$?
  echo "$(date -u +%FT%TZ) end $e rc=$rc seconds=$(( $(date +%s) - s )) load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/progress.log"
  [ $rc -ne 0 ] && { echo "STOP: $e failed" >> "$OUT/progress.log"; exit $rc; }
done
echo "$(date -u +%FT%TZ) ALL DONE" >> "$OUT/progress.log"
