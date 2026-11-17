# CHANGES-w25: every edit in this copy of `bench/pqz-proof`

Date 2026-11-10. This folder is a COPY of `bench/pqz-proof/` (without `target/` and `results/`). The original crate was not touched.
Check: `diff -rq bench/pqz-proof bench/pqz-proof-w25 -x target -x bin -x results -x __pycache__` lists only the files below
(Cargo.lock is identical; the build uses `cargo ... --offline`).

## Edited files (2)

1. `Cargo.toml`: one new cargo feature in `[features]`:
   `blake3 = []` (no new dependency; `Blake3_256` is already in `winter-crypto`, which `winterfell` re-exports).
2. `src/prove.rs`:
   - L1 (hash of the proof commitments): `pub type Hash = CommitHash<F>;` where `CommitHash` is `Sha3_256` by default and
     `Blake3_256` when built with `--features blake3`. `Coin`, `Vc` follow `Hash`. The in-circuit hash (Rescue Prime `Rp64_256`,
     `src/rescue.rs`) is not changed. New constant `HASH_NAME` ("Sha3_256" / "Blake3_256") for result files.
   - L2 (proof options): `default_options()` now reads the environment variables `PQZ_QUERIES`, `PQZ_BLOWUP`, `PQZ_GRIND`
     (defaults 40, 8, 16 = the old values). A value that is set but not a number stops the program (no silent fallback).
     New helper `options_with(queries, blowup, grind)` builds `ProofOptions` with the unchanged rest: `FieldExtension::Quadratic`,
     FRI folding 8, remainder max degree 31, `BatchingMethod::Linear` for both batchings. The verifier minimum
     (`MIN_BITS = 80` conjectured bits, `AcceptableOptions::MinConjecturedSecurity`) is unchanged and still passes for every setting used.

With no environment variable set and no feature, the build is the original crate (same types, same numbers).

## New files (3)

3. `src/bin/pilot.rs`: new binary (auto-discovered by cargo). Child processes for the interleaved measurements and the security sweep.
   It calls the crate's own `build_*_trace`, `prove_trace`, `verify_proof`, `security_of`; only the loop around them is new.
4. `scripts/pilot_driver.py`: starts one fresh `pilot child` process per measurement point and asks them, round-robin, for one run each per repetition.
5. `CHANGES-w25.md` (this file), `TASK-pilot.report.md` (report) and `results/pilot-1/*` (results). `bin/` holds the four built binaries
   (`pilot-sha3`, `pilot-blake3`, `proofbench-sha3`, `proofbench-blake3`; `proofbench-*` built from the unchanged `src/bin/proofbench.rs`, not used for the numbers).

## Not changed

`src/bin/*` except the new `pilot.rs`, `src/exec.rs`, `src/data.rs`, `src/rc.rs`, `src/auth.rs`, `src/rescue.rs`, all tests, `Cargo.lock`, `DESIGN.md`, `README.md`.
`bench/zkalba-eval/`, `.secrets/`, `journal1/`, `journal2/`, `STATE.md`: not touched by this task.
