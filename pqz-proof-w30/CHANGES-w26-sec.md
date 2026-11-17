# CHANGES-w26-sec: files added for the security-vs-cost measurement

Date 2026-11-11. Only NEW files were added in `bench/pqz-proof-w25/`. Nothing existing was edited
(`src/*`, `Cargo.toml`, `Cargo.lock`, `scripts/pilot_driver.py` and the other scripts, `bin/*`, `results/pilot-1/*` are unchanged).
The existing binary `bin/pilot-sha3` (built 2026-11-10, sha256 starts `e7b323691463d0ee`) was used; no rebuild.

## New files

1. `scripts/secsweep_w26.py`: driver. Sub-commands `env`, `bundle`, `prove`, `summary`.
   - `bundle`: 8 rounds. In each round one FRESH `pilot child bundle` per setting, pinned with `taskset -c 10`; per process 10 warm-up
     and 25 timed verifications (rc + auth + exec, n = 1000); settings interleaved one run each per repetition, start setting rotating.
   - `prove`: one fresh `pilot child prove rel=exec n=N` per setting (all cores), 3 warm-up + 10 timed, interleaved round-robin, rotating start.
   - `summary`: reads the raw CSV files and writes the summary files (raw files are never modified).
   - The environment variable `SECSWEEP_W26_OUT` (smoke tests only) redirects the output folder; it was not set for the real runs.
2. `results/sec-w26/secsweep.txt` (+ `secsweep.err`): output of `bin/pilot-sha3 secsweep rel=exec n=1000 blowup=8 qmin=40 qmax=255 grind=16`
   (library limit is 255 queries; the end of the file shows the failure at 255, see the report).
3. `results/sec-w26/env.txt`: machine and binary facts. `results/sec-w26/child-stderr.log`: stderr of all children (empty if no failure).
4. `results/sec-w26/bundle.raw.csv`, `prove_n5000.raw.csv`, `prove_n20000.raw.csv`: raw data (unmodified). `driver-bundle.log`, `driver-prove.log`: driver logs.
5. `results/sec-w26/bundle.summary.csv`, `prove_n5000.summary.csv`, `prove_n20000.summary.csv`, `summary.txt`: made by `secsweep_w26.py summary`.
6. `results/sec-w26/TASK-sec-w26.report.md`: the report.
7. `CHANGES-w26-sec.md` (this file).

A smoke test (2 rounds) of the bundle driver wrote to the session scratchpad, not to this folder.
