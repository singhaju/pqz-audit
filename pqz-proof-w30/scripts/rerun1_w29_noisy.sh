#!/usr/bin/env bash
# w29 RERUN 1 (lead, entry 438): the T-P1 and T-P2 cells of the first matrix were NOISY by the pre-set rule (p90/min > 1.15; noise sits in
# round 1 and in the suspend round). Same binaries and settings, a NEW folder beside the first run (results/w29-rerun1); the first run
# stays as it is and stays NOISY. Verdict rule written before this run: the same thresholds and the same noise rule, applied to all 5
# rounds of this rerun, nothing left out; both runs are reported.
set -u
cd "$(dirname "$0")/.."
PY=../../.venv-bench/bin/python
export W29_OUT=results/w29-rerun1
mkdir -p "$W29_OUT"
LOG=$W29_OUT/driver.log
echo "# RERUN1 start $(TZ=Asia/Bangkok date '+%F %T') Thai; sha256 bins:" >> "$LOG"
sha256sum bin/w29-sha3 bin/w29-blake3 >> "$LOG"
$PY -I scripts/w29_driver.py env >> "$LOG" 2>&1
for r in 1 2 3 4 5; do
  echo "# prove round $r start $(TZ=Asia/Bangkok date '+%F %T')" >> "$LOG"
  $PY -I scripts/w29_driver.py prove --rels exec --sizes 20000,50000 --block 100 --warm 3 --timed 10 >> "$LOG" 2>&1 || echo "# exec round $r FAILED rc=$?" >> "$LOG"
  $PY -I scripts/w29_driver.py prove --rels rc --sizes 20000 --block 100 --warm 3 --timed 10 >> "$LOG" 2>&1 || echo "# rc round $r FAILED rc=$?" >> "$LOG"
done
echo "# done $(TZ=Asia/Bangkok date '+%F %T') Thai" >> "$LOG"
