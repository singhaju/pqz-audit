#!/bin/bash
# w38 attack test: P2r (packed) full plan + old-format small plan. Run from bench/pqz-attack-w38. Laptop only.
set -e
export CARGO_TARGET_DIR="$(cd .. && pwd)/w38-exp4/target-attack-w38"
export RUSTFLAGS="-C target-cpu=x86-64-v3"
BIN="$CARGO_TARGET_DIR/release/attack"
OUT=results/attack-w38-p2r
OLD=results/attack-w38-old
mkdir -p "$OUT" "$OLD"
nice -n 15 cargo build --release --offline -j 8
sha256sum "$BIN" | cut -c1-16 > "$OUT/binary-sha256-prefix.txt"
cp "$OUT/binary-sha256-prefix.txt" "$OLD/binary-sha256-prefix.txt"
export RAYON_NUM_THREADS=8
nice -n 15 "$BIN" run fmt=p2r out=$OUT attack_trials=20 honest_trials=50 n20k=3 n50k=1 h20k=4 h50k=1 > "$OUT/log.txt" 2>&1
"$BIN" merge "$OUT" >> "$OUT/log.txt" 2>&1
# old format (default path), small plan, to show nothing regressed
nice -n 15 "$BIN" run out=$OLD attack_trials=3 honest_trials=4 n20k=3 n50k=0 h20k=4 h50k=0 > "$OLD/log.txt" 2>&1
"$BIN" merge "$OLD" >> "$OLD/log.txt" 2>&1
