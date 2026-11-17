#!/usr/bin/env bash
# w29 laptop matrix RESUME (lead, entry 437). The first run (run_w29_matrix.sh) stopped: the laptop suspended at 17:10:42 Thai
# (during round 2, rc n=20000, rep 8/13), resumed about 18:10, then was rebooted at 18:11 Thai. Done before the stop: round 1 (all 10
# cells), round 2 exec (5 cells) and rc n=5000, 10000, 20000. This script runs the rest with the SAME settings, appending to the same
# raw files (nothing is deleted or edited): round 2 rc n=50000 and 100000, rounds 3-5 in full, then verify, then summary.
# Sleep is blocked with systemd-inhibit for the length of the run (no system setting is changed).
set -u
cd "$(dirname "$0")/.."
PY=../../.venv-bench/bin/python
LOG=results/w29/driver.log
echo "# RESUME start $(TZ=Asia/Bangkok date '+%F %T') Thai (first run stopped by suspend 17:10:42 and reboot 18:11); sha256 bins:" >> "$LOG"
sha256sum bin/w29-sha3 bin/w29-blake3 >> "$LOG"
$PY -I scripts/w29_driver.py env >> "$LOG" 2>&1
echo "# prove round 2 (rest: rc 50000,100000) start $(TZ=Asia/Bangkok date '+%F %T')" >> "$LOG"
$PY -I scripts/w29_driver.py prove --rels rc --sizes 50000,100000 --block 100 --warm 3 --timed 10 >> "$LOG" 2>&1 || echo "# prove round 2 rest FAILED rc=$?" >> "$LOG"
for r in 3 4 5; do
  echo "# prove round $r start $(TZ=Asia/Bangkok date '+%F %T')" >> "$LOG"
  $PY -I scripts/w29_driver.py prove --block 100 --warm 3 --timed 10 >> "$LOG" 2>&1 || echo "# prove round $r FAILED rc=$?" >> "$LOG"
done
echo "# verify start $(TZ=Asia/Bangkok date '+%F %T')" >> "$LOG"
$PY -I scripts/w29_driver.py verify --block 100 --cpu 10 --rounds 8 --warm 10 --timed 25 >> "$LOG" 2>&1 || echo "# verify FAILED rc=$?" >> "$LOG"
$PY -I scripts/w29_driver.py summary >> "$LOG" 2>&1
echo "# done $(TZ=Asia/Bangkok date '+%F %T') Thai" >> "$LOG"
