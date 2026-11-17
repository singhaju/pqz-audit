# pqz-bl: baselines that are RUN, not computed (work15, entry 384)

User, 2026-11-05: "make sure we run it in same environment and make it correctly and real. no predict, no put number from their paper."
So each baseline's audit operation is implemented from the paper's own algorithm text and timed by us, on the same machine and in the same session as PQZ-Audit.
Layout: `bench/pqz-bl/{dong,dopiv,dart,lhcpm}/`, one standalone Rust crate each (lib + one bin). Nothing outside your own crate directory is touched.
The old calculator `bench/pqz-baselines/` stays as it is (read-only reference for unit costs and for hash-to-G1 code in `src/lib.rs`).

## Sources (read them; do not rely on memory)
`journal2/comparison-papers/baselines-main11/text/{dong,dopiv,dart,lhcpm}.txt` (pdftotext, two columns: lines are fragments; the PDFs are next to them, render a page to PNG with `pdftoppm -r 110 -f P -l P -png` when an equation is unclear) and `findings-*.md` (line numbers and what the papers do NOT say).
Professor's cost table (for the operation counts to cross-check): `journal2/pqz-audit-journal-main11-professor.tex`, search `tab:comp-cost`.

## Rules (the user's truth rules)
1. Implement the algorithm as the paper states it. Where the paper is silent or our setting forces a change (curve, field size, parameters), choose the simplest faithful option and write it into `FIDELITY.md` in your crate: what runs, what is simplified, what is NOT run, which choices favour the baseline and which favour PQZ-Audit.
2. NO number from any paper may be used as a result or as a tuning target. Parameters from the papers (c, s, N, M, n, m, q, constraint counts) are inputs, listed in FIDELITY.md with the source line. A parameter the paper does not give is OURS and is marked so.
3. Every operation is real: real group elements, real pairings, real hashing, real field arithmetic. No sleeping, no table lookups of costs, no `black_box`-free dead code that the compiler can drop: feed results into `std::hint::black_box` and CHECK the output (verification result true).
4. Correctness tests (`cargo test --release`): an honest proof/audit verifies; a tampered proof (flip one value) is rejected. A test that fails is a finding: report it, do not weaken it.
5. Timing harness (same for all four): one thread (no rayon, no threads), `std::time::Instant`, 3 untimed warm-up runs, 30 timed runs, each run is the WHOLE named stage with fresh random challenge. Inputs (keys, tags, data, ciphertexts) are generated BEFORE timing and are not part of the stage.
   Stages: `proofgen` (storage-side, if the paper has one), `verify` (auditor side). For L-HCPM: `audit_hit`, `groth16_verify`, `groth16_prove_mint`, `groth16_prove_transfer`.
6. Output: `raw_runs.csv` with header `baseline,stage,params,run,ms` (ms = f64 milliseconds, one row per timed run), written to `--out DIR` (default `results/`). Print a one-line summary per (stage, params): median, min, max. Command line: `--runs 30 --warmup 3 --out DIR [--quick]` (`--quick` = 3 runs, 1 warm-up, small grid, for smoke tests).
7. Build with `cargo build --release` in your crate directory (never run the build from another crate's directory). Network: only `cargo` fetching crates.io is allowed. No cloud, no AWS, no other machine. Never `pkill -f` or `pgrep -f`. The shell is fish: use bash scripts, no heredocs in fish; Write tool for files.
8. Do not install system packages. Do not touch `.secrets/`, `bench/zkalba-eval/`, or any file outside `bench/pqz-bl/<your crate>/`.
9. Library versions: use exact versions in `Cargo.toml`. For pairing on BLS12-381 use `bls12_381 = { version = "0.8.0", features = ["experimental"] }` (as `bench/pqz-baselines/Cargo.toml`; its `Cargo.lock` can be copied so the build resolves offline). For BN254 use arkworks 0.4.x (`ark-ff`, `ark-ec`, `ark-bn254`, `ark-groth16`, `ark-relations`, `ark-snark`, `ark-std`, all `=0.4.0` unless 0.4.0 does not exist for a crate; then the newest 0.4.x). Do not use `rayon`/`parallel` features.
10. Report back (final message, at most 40 lines): files written, what runs, what does NOT run and why, the test results (copy the lines), the smoke-run summary lines, every deviation from the paper, anything you could not decide. Do not claim anything you did not run.

## Fairness notes that go to the paper (keep them true)
- Curve: Dong and DART use a Type A symmetric pairing (|q| = 160 bit, |G| = 512 bit, JPBC). We use BLS12-381 (asymmetric, 255-bit scalars, 381-bit base field). Symmetric formulas must be mapped to the asymmetric setting; say where each element lives (G1 or G2) and what that does to the cost.
- Our single-thread baselines vs PQZ-Audit proof generation, which uses all cores by default: disclose.
- All baselines run in memory, no network, no blockchain, no disk.
