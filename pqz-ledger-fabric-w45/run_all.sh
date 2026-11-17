#!/usr/bin/env bash
# Exp 5 (w45) full matrix. Run from this folder after ./test-network/network.sh up createChannel + deployCC (see README-w45.md).
cd "$(dirname "$0")/client" || exit 1
O=../results/exp5_runs.csv
for N in 10000 100000; do ./pqzbench -mode pqz -n $N -runs 10 -out $O; done
for N in 10000 100000; do ./pqzbench -mode v2 -n $N -batch 100 -runs 10 -out $O; done
for N in 10000 100000; do ./pqzbench -mode v1 -n $N -batch 100 -runs 10 -out $O; done
for N in 10000 100000; do ./pqzbench -mode v2 -n $N -batch 1 -runs 10 -out $O; done
for N in 10000 100000; do ./pqzbench -mode v1 -n $N -batch 1 -runs 10 -out $O; done
echo DONE
