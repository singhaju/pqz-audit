# pqz-ledger (PROVISIONAL)

Ledger and threshold layer for the PQZ-Audit experiments (journal2, paper main(11)):
Experiment 5 (blockchain overhead), the (t,n) panel, and the rejection checks.

**Status: PROVISIONAL.** The professor has not chosen the ledger, the threshold schemes, the epoch length or the
validator count. Every choice below is a stand-in so that the code, the CSV format and the checks exist. Nothing here is a
result for the paper until the professor confirms the choices. This crate does not depend on `bench/pqz-eval/`.

## What the "ledger" is (read this before using any number)

An **in-process simulation** in one process on one machine:

- n validators (default 4, quorum 3), each with its own replica of the contract state; a round-robin leader executes a
  block, signs the header with ML-DSA-65 (crate `ml-dsa` 0.1.1), the other validators re-execute and vote, and a
  quorum certificate (QC) of signatures finalizes the block. Hashes are SHA3-256 (`sha3` 0.12.0).
- **No network, no view change, no mempool, no real concurrency** (validators run one after another on one thread).
- Therefore latency and throughput here are **computation** (hashing, state execution, ML-DSA sign and verify) and
  **not** the latency or throughput of consensus over a network. Every CSV row has a `scope` column saying so.
  `derived_*` columns are computed from the measured per-validator times assuming parallel validators and zero network delay;
  they are derived, not measured on a deployment.
- Per-transaction submitter signatures (ML-DSA-65, 3309 B each) are a provisional choice and dominate the CPU time.
  `ledgerbench --no-tx-auth` turns them off, so both variants can be reported.
- Not audited: `ml-dsa` says so itself. Seeds (ChaCha20, key seeds) are fixed for reproducibility: benchmarks only.

## Layout

| File | Content |
|---|---|
| `src/ledger.rs` | BFT-style simulation: blocks, QC, verified state reads, byte accounting |
| `src/contract.rs` | governance contract: epoch anchor, authorize, consume (Priv lifecycle), per-record baseline tx; defence flags |
| `src/statemap.rs` | Merkle-committed key-value state (RFC 6962 style), journal for rollback |
| `src/audit.rs` | minimal audit block chain (epoch root, A_e, Gamma_e, Omega_e) and the block-coverage check |
| `src/threshold.rs`, `src/shamir.rs` | Shamir over GF(2^127-1), T_priv / T_rec / T_disc domains, optional ML-DSA multisig for T_priv |
| `src/attacks.rs`, `src/bin/reject.rs` | rejection harness and mutation tests |
| `src/bench.rs`, `src/bin/ledgerbench.rs`, `src/env.rs` | benchmark driver, raw CSV, env.txt |
| `DESIGN.md` | decisions, mapping of T_priv/T_rec/T_disc to the paper, what is excluded, paper-vs-code mismatches |

## Commands

```
cargo test --release                                    # 46 tests
cargo run --release --bin reject                        # 1000 trials per attack variant; exit 1 if any is accepted
cargo run --release --features mutation --target-dir target/mut --bin reject -- --mutate --trials 200
cargo run --release --bin ledgerbench -- --out results  # 30 timed runs + 3 warm-up per point; raw CSV + env.txt
cargo run --release --bin ledgerbench -- --quick --out /tmp/smoke   # tiny settings, NOT for reporting
```

`ledgerbench` options: `--runs N --warmup N --seed N --validators N --only exp5a,exp5b,exp5c,thr --no-tx-auth`.
Use a separate `--target-dir` for the `mutation` feature so the reporting binaries are never built with it.

## Outputs of `ledgerbench` (raw rows, one per run; `kind` is `warmup`, `timed` or `formula`; no summaries)

| File | Points |
|---|---|
| `exp5a_latency_throughput.csv` | q in {1,10,25,50,100,200} x {pqz `authorize`, per-record baseline `commit_record`} |
| `exp5b_governance.csv` | `routine_anchor`, `routine_read`, `authorize`, `consume` (one operation per run) |
| `exp5c_bytes_per_epoch.csv` | N in {1e4,1e5,1e6} x {pqz, per-record baseline}; N enters the pqz epoch only through the root |
| `threshold.csv` | (t,n) in {(3,5),(5,9),(7,13)} x {T_priv, T_rec, T_disc} x {setup_deal, combine}; T_priv multisig variant; T_rec secret sizes 32, 1024, 16384 B |
| `env.txt` | CPU, governor, kernel, rustc, SHA-256 of Cargo.lock, crate versions, run settings |

Per-record baseline bytes for N above `baseline_measured_max` (default 1e4) are not executed (state-root recomputation is
quadratic over the epoch); they come from an exact byte formula that a unit test checks against measured runs. These rows have
`kind=formula`.

## Known limits

- Laptop CPU governor may be `powersave` (see `env.txt`); timings carry that noise.
- Dong et al. (ref7) is not implemented (no readable source). Only our own per-record on-chain baseline exists.
- The proof system, protected search, HE and KEM are not here. See `DESIGN.md`, section 3.

## Known flaw in results/full-1 (found 2026-10-31, not fixed, raw files untouched)
In `results/full-1/no-tx-auth/exp5c_bytes_per_epoch.csv` the `per_record_baseline` rows of kind `formula` (N = 1e5, 1e6) still contain the per-transaction signature bytes (`bytes_tx_sig` = 3.3e8, 3.3e9), although the flag `--no-tx-auth` removes signatures (the measured row at N = 1e4 has `bytes_tx_sig` = 0). The formula ignores the flag. Do not quote the no-tx-auth per-record baseline bytes at N = 1e5 and 1e6; use `with-tx-auth` for the byte comparison. The pqz bytes per epoch are not affected.
