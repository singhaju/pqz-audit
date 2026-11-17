#!/usr/bin/env bash
# w29 laptop matrix (lead, entry 436). Plan: journal2/UPGRADE-w29-plan.md section 3. Block size 100 (= paper's cloud runs).
# Raw files: results/w29/*.raw.csv (appended, never edited). Laptop ratios only; nothing here enters the paper.
set -u
cd "$(dirname "$0")/.."
PY=../../.venv-bench/bin/python
mkdir -p results/w29
LOG=results/w29/driver.log
echo "# start $(TZ=Asia/Bangkok date '+%F %T') Thai; sha256 bins:" >> "$LOG"
sha256sum bin/w29-sha3 bin/w29-blake3 >> "$LOG"
$PY -I scripts/w29_driver.py env >> "$LOG" 2>&1
for r in 1 2 3 4 5; do
  echo "# prove round $r start $(TZ=Asia/Bangkok date '+%F %T')" >> "$LOG"
  $PY -I scripts/w29_driver.py prove --block 100 --warm 3 --timed 10 >> "$LOG" 2>&1 || echo "# prove round $r FAILED rc=$?" >> "$LOG"
done
echo "# verify start $(TZ=Asia/Bangkok date '+%F %T')" >> "$LOG"
$PY -I scripts/w29_driver.py verify --block 100 --cpu 10 --rounds 8 --warm 10 --timed 25 >> "$LOG" 2>&1 || echo "# verify FAILED rc=$?" >> "$LOG"
$PY -I scripts/w29_driver.py summary >> "$LOG" 2>&1
echo "# done $(TZ=Asia/Bangkok date '+%F %T') Thai" >> "$LOG"
