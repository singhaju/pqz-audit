# pqz-ledger-bl-w37 (w37-fair, 2026-11-15)

A NEW crate: a copy of `bench/pqz-ledger` (not edited) plus one added transaction type, so that the per-record on-chain baseline of Exp 5
runs as real code on the same simulated ledger as PQZ-Audit. The simulation is unchanged: in-process, 4 validators, quorum 3, ML-DSA-65
signatures (3309 B), SHA3-256, a Merkle state root recomputed per block, blocks of at most 100 txs. No network, no consensus, no mempool.

## What is added (only these places differ from `pqz-ledger`)
- `src/contract.rs`: `Tx::CommitRecordV2 { e, i, ph, c }`, `Reject::{RecordSeq, RecordCommitMismatch}`, `key_cnt`, `record_commit`.
  The contract (1) requires `State[e]` (epoch anchored), (2) recomputes `c = SHA3("PQZ-REC" || e || i || ph)`, (3) rejects a duplicate `Rec[e,i]`,
  (4) requires `i == Cnt[e]` (next sequence number), (5) writes `Rec[e,i] := ph || c` and `Cnt[e] := Cnt[e] + 1`.
  The per-record signature is the ledger's own submitter ML-DSA-65 signature on every transaction (verified by all validators), exactly as for PQZ.
- `src/bench.rs`: `BenchCfg.baseline` ("v1" = the original `CommitRecord`, "v2" = `CommitRecordV2`, "both" = default), `baseline_bytes_formula_v`,
  the exp5a/exp5c loops take the list of baselines. CSV columns are unchanged. New system label `per_record_baseline_v2` (workload `commit_record_v2`).
- `src/bin/ledgerbench.rs`: new flags `--baseline v1|v2|both`, `--baseline-measured-max N`, `--qs a,b,c`, `--ns a,b,c`. All old flags unchanged.
- Tests added: `w37_commit_record_v2_accepts_honest_and_rejects_each_violation` (contract), `w37_v2_through_ledger_signature_and_contract_checks` (ledger,
  with forged/flipped signature, tampered body, duplicate, gap, bad commitment), `v2_records_are_in_state_and_counter_matches` and the extended
  `baseline_formula_equals_measurement` (bytes formula equals measured bytes for v1 and v2) in `bench.rs`. `cargo test --release --offline`: 49 passed.

## What it is NOT
It is not Dong et al.'s blockchain (that scheme stores only challenge seeds and audit results on-chain, not per-record commitments); it is our own hypothetical
per-record design that the paper says is "motivated by" Dong et al. The v2 record carries only a payload HASH (the payload is not on-chain).

## Build and run
    cargo build --release --offline
    ./target/release/ledgerbench --out DIR --only exp5a,exp5c --baseline both [--qs 1,10,25,50,100,200] [--ns 10000] [--runs 30 --warmup 3]
