#!/usr/bin/env bash
# usage: run_full.sh <results-dir>   (full Stage A run: 30 timed runs + 3 warm-up, one at a time)
set -u
OUT="$1"
RUNS=30
WARM=3
LOAD1=$(cut -d' ' -f1 /proc/loadavg)
if awk -v l="$LOAD1" 'BEGIN { exit !(l > 6.0) }'; then
  echo "refusing to start: 1-min load average is $LOAD1 (limit 6.0)"
  exit 3
fi
cd "$(dirname "$0")"
mkdir -p "$OUT"
cargo build --release >/dev/null 2>&1 || { echo "build failed"; exit 1; }
for e in exp1_construction exp1 exp2a exp2b exp2c exp3a exp3b; do
  echo "$(date -u +%FT%TZ) start $e load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/progress.log"
  s=$(date +%s)
  ./target/release/exp "$e" --runs "$RUNS" --warmup "$WARM" --out "$OUT/$e" > "$OUT/$e.stdout" 2> "$OUT/$e.stderr"
  rc=$?
  echo "$(date -u +%FT%TZ) end $e rc=$rc seconds=$(( $(date +%s) - s )) load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/progress.log"
  [ $rc -ne 0 ] && { echo "STOP: $e failed" >> "$OUT/progress.log"; exit $rc; }
done
echo "$(date -u +%FT%TZ) ALL DONE" >> "$OUT/progress.log"
