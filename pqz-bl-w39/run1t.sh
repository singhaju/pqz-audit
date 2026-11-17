#!/bin/bash
# usage: run1t.sh COV  -> 1-thread laptop run, 1 warm-up + 3 runs, pinned to core 2
cov=$1
cd "$(dirname "$0")"
PY="../../.venv-bench/bin/python"
taskset -c 2 $PY -I peakrss.py results/laptop-1t-cov$cov.rss dart-zk/target/release/dart-bench --cov $cov --file-records 1000000 --runs 3 --warmup 1 --big-above 1000000000 \
  --stages proofgen_nozk,verify_nozk,zkprove_only,proofgen_zk,verify_zk --params-tag laptop1t --out results/laptop-1t-cov$cov \
  > results/laptop-1t-cov$cov.log 2>&1
