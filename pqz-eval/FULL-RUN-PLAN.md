# Full run plan (written 2026-10-31, before any full-run result is looked at)

Pilot: `results/pilot-1/` (3 timed runs + 1 warm-up, laptop, loadavg about 3-5, governor powersave). Pilot is for timing only, not quotable.

## Pilot wall time (seconds, includes data build)
construction 46, exp1 135, exp2a 91, exp2b 419, exp2c 353, exp3a 2213, exp3b 1059.
Cause of exp3a/3b cost: `full_he` adds all N=10^6 BFV ciphertexts, about 102 s per run (about 100 microseconds per add), independent of selectivity.

## Rule decided now (not from results)
- All experiments: 30 timed runs + 3 warm-up (as in the design), EXCEPT `full_he` (Full-Domain HE) only: 10 timed + 1 warm-up. Reason: 102 s per run; 30 runs at 8 points would take about 7 h. State this in the paper. Spread is reported with n=10 for that approach.
- Estimated full time: about 1 h for exp1/2a/2b/2c/construction, about 2.5 h for full_he, about 0.5 h for the pqz/plain parts of exp3: roughly 4-5 h, laptop only. No cloud needed (log 0.85 GiB at N=10^6).
- One job at a time. No other heavy job during timing. Record loadavg and governor in progress.log/env.txt.
- Proof (`bench/pqz-proof`), ledger (`bench/pqz-ledger`), baselines (`bench/pqz-baselines`): re-run after Stage A, one at a time, same quiet rule.
- If a point fails the gate (different selected sets), the run stops; report it.

## Order
1. Stage A full (`./run_full.sh results/full-1`)
2. pqz-baselines unit costs + calc (re-run)
3. pqz-proof full (`bench/pqz-proof/scripts`, see its README)
4. pqz-ledger `ledgerbench` full + `reject --trials 1000` + mutation build
5. Analysis (`analysis/*.py`), hypotheses table, figures
6. Log, runbook, work4 [XX] fill (later)

## Who does what
- opencode (deepseek-v4.1-flash): code changes, analysis scripts, figure scripts, README text.
- Claude main: review of diffs and results, hypotheses verdict, paper wording, anything about security.

## Updates (2026-10-31)
- Pilot-1 is INVALID for quoting: the Bloom filter used a 16-bit slice for the bit index (defect found with `examples/fpcheck.rs`, see `smoke/FP-INVESTIGATION.md`), so pruning was inflated (e.g. 49 retained blocks instead of 21). Fixed in `src/search.rs` (double hashing); 31 tests pass. All results must be re-run: `results/pilot-1/` is kept only as the record of the defect.
- Load gate in `run_full.sh` set to 1-min load <= 6.0 (was 2.0, an arbitrary value from the job that wrote it). Reason: the desktop and the user's other tool sessions keep the load near 4 on 22 logical cores; timed queries are single-threaded. Load average is logged before/after every experiment. Not a "quiet machine": a limitation to state in the paper.
- Full run 1: `./run_full.sh results/full-1` started 2026-10-31.
