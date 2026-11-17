#!/bin/bash
# w25 pilot, rest of the matrix (written by the lead after the pilot agent was cut off by a rate limit).
# Run from bench/pqz-proof-w25:  bash scripts/run_rest.sh   (about 10-15 minutes; local, no network)
set -u
cd "$(dirname "$0")/.."
OUT=results/pilot-1
# 1. security sweep for blowup 4 and 16 (do the library's three estimates stay >= 127 / 49?); blowup 4 may be rejected by the AIR (constraint degree 7)
{
  for b in 4 16; do
    if [ "$b" = 4 ]; then qmin=45; qmax=66; else qmin=34; qmax=40; fi
    echo "# blowup $b queries $qmin..$qmax (exec n=1000 block=100)"
    ./bin/pilot-sha3 secsweep rel=exec n=1000 block=100 blowup=$b qmin=$qmin qmax=$qmax 2>&1 | tail -n 30
  done
} > $OUT/secsweep.txt 2>&1
# 2. M3 (R_RC at N_Q=20000, default vs best) and L3 (split vs single), best = blake3-b8-q40
python3 scripts/pilot_driver.py m3 blake3-b8-q40 > $OUT/driver-m3.log 2>&1
python3 scripts/pilot_driver.py l3 blake3-b8-q40 > $OUT/driver-l3.log 2>&1
echo done > $OUT/rest.done
