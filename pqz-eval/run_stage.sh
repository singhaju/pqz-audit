#!/usr/bin/env bash
# usage: run_stage.sh <results-dir> <runs> <warmup>   (runs the Stage A experiments one at a time)
set -u
OUT="$1"; RUNS="$2"; WARM="$3"
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
