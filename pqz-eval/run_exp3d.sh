#!/usr/bin/env bash
# usage: run_exp3d.sh <results-dir>   (exp3d COUNT vs selected fraction, plain_agg and pqz only, 30 timed + 3 warm-up)
set -u
OUT="$1"
cd "$(dirname "$0")"
mkdir -p "$OUT"
cargo build --release >/dev/null 2>&1 || { echo "build failed"; exit 1; }
echo "$(date -u +%FT%TZ) start exp3d load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/progress.log"
s=$(date +%s)
./target/release/exp exp3d --runs 30 --warmup 3 --out "$OUT/exp3d" > "$OUT/exp3d.stdout" 2> "$OUT/exp3d.stderr"
rc=$?
echo "$(date -u +%FT%TZ) end exp3d rc=$rc seconds=$(( $(date +%s) - s )) load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$OUT/progress.log"
echo "$(date -u +%FT%TZ) EXP3D DONE rc=$rc" >> "$OUT/progress.log"
