#!/usr/bin/env bash
# w30 parallel-chunk gate run (lead, entry 443): S2 vs S4 only, exec+rc, 5e4 and 1e5, 3 rounds x (3 warm + 10 timed). Rule in w30_par_gate.py.
set -u; cd "$(dirname "$0")/.."; PY=../../.venv-bench/bin/python
export W30_OUT=results/w30-gate; mkdir -p "$W30_OUT"; LOG=$W30_OUT/driver.log
echo "# GATE start $(TZ=Asia/Bangkok date '+%F %T') Thai" >> "$LOG"; $PY -I scripts/w30_driver.py env >> "$LOG" 2>&1
for r in 1 2 3; do echo "# round $r $(TZ=Asia/Bangkok date '+%F %T')" >> "$LOG"
  $PY -I scripts/w30_driver.py prove --labels S2,S4 --rels exec,rc --sizes 50000,100000 --block 100 --warm 3 --timed 10 >> "$LOG" 2>&1 || echo "# round $r FAILED rc=$?" >> "$LOG"; done
$PY -I scripts/w30_par_gate.py > "$W30_OUT/gate.txt" 2>&1; echo "# done $(TZ=Asia/Bangkok date '+%F %T') Thai" >> "$LOG"
