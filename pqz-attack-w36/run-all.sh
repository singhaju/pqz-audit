#!/bin/bash
# Run the w33 stage C attack test (same trial plan as bench/pqz-attack-w30-fixed/run-all.sh). Run from bench/pqz-attack-w33.
set -e
OUT=results/attack-w33
mkdir -p "$OUT"
nice -n 15 cargo build --release -j 8
sha256sum target/release/attack | cut -c1-16 > "$OUT/binary-sha256-prefix.txt"
ARGS="out=$OUT attack_trials=20 honest_trials=50 n20k=3 n50k=1 h20k=4 h50k=1"
RAYON_NUM_THREADS=8 nice -n 15 target/release/attack run $ARGS > "$OUT/log.txt" 2>&1
target/release/attack merge "$OUT" >> "$OUT/log.txt" 2>&1
