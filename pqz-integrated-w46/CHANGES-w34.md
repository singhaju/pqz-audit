# CHANGES-w34: w30 driver with the Plonky3 (w33) proof layer

Crate `bench/pqz-integrated-w35/` (package `pqz-integrated-w35`, binary `w34`). Plan: `journal2/UPGRADE-w34-cloud-plonky3-plan.md` section 8, part E1, gate L5.
Base: `bench/pqz-integrated-w30/` (read-only; its `CHANGES-w30.md` is copied here unchanged and still describes the stage timers, gates and the log).
Not modified: `bench/pqz-plonky3-w35/`, `pqz-eval`, `pqz-ledger`, w30, w29 and every other crate.

## What stays the same as w30
Log construction (P3a: AES-256-GCM, 45 keyed tags, descriptor `D_i`, Bloom block summary, `B_{e,g}`, `R_e`), ledger simulation (P4b), the protected search (P6a:
BPS then RPS), the gates, the stage timers (monotonic `Instant`, per-stage VmHWM with reset), one fresh child process per run, the CSV
file names, `raw.csv` column order, BLOCK (`m_B`) = 500, theta = 2^31, seed `DEFAULT_SEED`. Extra columns are only at the END: `p7_native_s`, `stream_link`, `exec_stream`.
Settings: only `P3` exists. `S0`, `S2` and anything else give exit code 2 and a clear message (`src/lib.rs:91`).

## Proof layer (what is replaced). Line numbers are of `src/lib.rs` in this crate, w30 lines in brackets
| Place | w30 (winterfell, Rescue Prime) | w34 (w33, Plonky3 0.8.0) |
|---|---|---|
| Word type | `Word` of 8 Rescue field elements (w30 lib.rs:17) | w33 `RawWord = [u64; 8]`; header = w33 `header_word` (`lib.rs:198`), record word `[PID, EPOCH, seq, id, v, b, tag, 0]` (`lib.rs:207`) |
| Field helpers | `f4`, `tag_of_descriptor` mod `F::MODULUS` (w30:96, 104) | same rule mod `GOLDILOCKS_P` as u64 (`lib.rs:103`, `111`) |
| R_RC statement | `build_rc_trace`, `RcPublic` with a Rescue digest (w30:241-290) | `c1::words(wl)` + `plain::rc_public` (digest by w33 native Poseidon2 sponge) `lib.rs:270-271`; AIR `plain::rc_air` `lib.rs:274` |
| R_RC prove | `prove_trace`, `default_options`, linked chunks (S2) (w30:241-290) | `p3_uni_stark::prove(&c1::config(&FriOpts::std()), ...)`, one proof over the whole epoch stream `lib.rs:280` |
| R_RC verify (AA, P4a) | `verify_rc` / `verify_rc_chunked` (w30:297) | `plain::verify_rc` (guarded) `lib.rs:295` |
| R_Exec statement | `ExecPublic` with a Rescue digest, ctx = B_Q (w30:320-372) | `ExecPublic { digest = native_digest(Poseidon2), n_blocks, block_size, theta, count, sum, ctx }` `lib.rs:310-312`; AIR `c1::air` `lib.rs:315` |
| R_Exec prove / verify | `prove_trace`, `verify_exec(_chunked)` (w30:320-390) | `p3_uni_stark::prove` `lib.rs:321`; `plain::verify_exec` (guarded) `lib.rs:332` |
| R_Auth instance | `honest_auth_instance(depth, seed)` (Rescue) (w30:493) | w33 `honest_auth_instance::<Val,_>(&perm, AUTH_DEPTH, seed)` `lib.rs:528` |
| `bind_hash` (B_Q) | Rescue `bind_hash` (w30:~498) | w33 Poseidon2 `bind_hash::<Val,_>(&perm, ...)` `lib.rs:531` |
| `d_Q` | SHA3 over label, qid, predicate, then `f4` (w30:487) | unchanged SHA3 (not Rescue), `lib.rs:517`; kept as is |
| R_Auth prove / verify | `build_auth_trace`, `prove_trace`, `verify_auth` (w30:493-519) | `plain::auth_air_for`, `build_trace`, `p3_uni_stark::prove` `lib.rs:535-540`; `plain::verify_auth` `lib.rs:552` |
| Execution context | ctx = B_Q (w30 run_one P6b/P7) | ctx = C_Q = w33 `exec_context(perm, B_Q, d_Q, RID)` (Poseidon2) `lib.rs:849-850`; RID = 1 (`pub const RID` in `lib.rs`) |
| Reference hash chain (gate G3d) | `chain_digest` (Rescue, from w30 `data`) | `ref_chain_digest` `lib.rs:127`: own Poseidon2 sponge written on the raw permutation, independent of w33 `native_digest` (a test compares the two) |
| Security bits columns | `security_of(&proof)` (winterfell) | w33 `estimate(&c1::sec_input(&opts(), rows))` `lib.rs:252`, `541` (library estimate: conjectured 127, proven UDR 49, proven LDR 69-74) |
| Requester P7 | `verify_auth`, then `verify_exec` with `ctx = B_Q` overwritten | `verify_requester` `lib.rs:396`: native checks first (all ON: stream link, C_Q link, scope; `lib.rs:363-380`), then Auth, then Exec; the Exec statement is the one the CSP sent, its ctx is CHECKED not overwritten |
| Extra requester check | none | `exec.theta == THETA` (`lib.rs:365`): the requester knows its own predicate; w33 does not check it, the proof only binds the stated theta |

FRI options: `FriOpts::std()` (log_blowup 3, 40 queries, 16 query-PoW bits, final poly 2^5, max arity 2^3), set once in `opts()` (`lib.rs:69`). Plain mode only. No zero knowledge.

## How the w33 statements are built from the driver's log (BLOCK = 500)
- The log (`build_log`, `lib.rs:186`) writes, per block `g`, one header word then 500 record words, into a w33 `Workload { n_blocks = G, block_size = 500, epoch = 1, pid = 7, seq_start = 1, words }`. This is the SAME word layout `Workload::synthetic` of w33 uses (header + `block_size` records, `n_words = n_blocks * 501`); the driver's words come from the real records instead of the synthetic draw.
- R_RC: `plain::rc_public(c1::words(&log.wl), 500)` (`lib.rs:270-271`) gives `RcPublic { digest, n_blocks = G, block_size = 500, header0 = first header }`. One proof over all `G * 501` words.
- R_Exec: `exec_input` (`lib.rs:603`) picks the blocks (default: those BPS retained, headers kept), the claim (count = selected ids, sum = sum of `b` of the selected records) comes from the SEARCH, not from the words. `prove_exec_stage` (`lib.rs:306-312`) builds `ExecPublic` with `theta = THETA`, that claim, and `ctx = C_Q`. The sum is stored as one element (C1 mode, `sum: vec![claim.1]`).
- Gates re-derive both digests with `ref_chain_digest` and compare with the statements (`lib.rs:763-768`).

## Deviation to read first: R_Exec covers the RETAINED blocks, not the whole stream
w30 proves R_Exec only over the BPS-retained blocks (r of G). w33 `check_stream_link` needs the R_Exec digest to equal the R_RC digest, which only holds when R_Exec covers every block. I kept the w30 behaviour as the default, because switching would change what P6b measures:
- `--exec-stream retained` (default): if r == G the full w33 link is applied (`native_bundle_checks`). Otherwise a SUBSET link: same block size and `0 < exec blocks <= rc blocks`, then the C_Q link and scope (`native_request_checks`). The subset link does NOT prove that the retained words are blocks of the R_RC stream (as in w30; only the gates, which hold the log, check it). Test `subset_link_is_weaker_and_the_gates_cover_it` shows both sides: the requester accepts a foreign subset of the same size, the gates reject it.
- `--exec-stream whole`: R_Exec over all G blocks, the full w33 stream link applies and ties the two proofs. Measured at 1e5 (below): R_Exec prove 1.05 s instead of 0.019 s.
The column `stream_link` (full or subset) and `exec_stream` record which was used.

## Dropped from w30
Linked-chunk mode (S2) and the Rescue / winterfell code paths. The w30 tests for S2 (`*_linked`) are not ported; the other w30 tests are ported (see `tests/w34.rs`).

## Tests (`cargo test --release --offline`): 20 passed, 0 failed
Ported: honest clustered and scattered (retained and whole), `run_one` end to end (4 variants), wrong claimed count / sum / theta rejected, exec context bound to the Auth statement, tampered Auth statement, dropped hit block caught by the gates, changed word caught by the gates, digests follow the stream, descriptor tags tie search to stream, ledger anchor and Omega check, bad arguments.
New (L5): `e2e_honest_run_passes_the_gates`; `tampered_proof_bytes_are_rejected` (R_RC, R_Auth, R_Exec at 7 byte positions, last byte, truncated, empty, swapped proofs); `mismatched_stream_is_rejected` (R_RC of log A with R_Exec of log B is refused with `link: R_RC digest != R_Exec digest`, and a one-word change in the Exec stream is refused); `subset_link_is_weaker_and_the_gates_cover_it`; `statements_are_built_from_the_driver_log`; `count_and_sum_at_n2000_match_the_plain_reference`.
Debug builds are not used (the Plonky3 prover panics on invalid traces in debug).

## Gate L5: evidence (laptop, Dell Precision 5690, all runs below on one machine, no AWS)
All commands run in `bench/pqz-integrated-w35/`. Binary: `target/release/w34`.
1. Smoke: `./target/release/w34 run --setting P3 --n 2000 --layouts clustered --runs 1 --limit-s 300 --out $PWD/results/smoke-P3` -> exit 0, `raw.csv` status `ok`, `failures.txt` empty. n_selected 20, r = 1 of 4 blocks, link subset.
2. n = 100000: `./target/release/w34 run --setting P3 --n 100000 --layouts clustered --runs 1 --limit-s 3000 --out $PWD/results/n100000-P3` -> status `ok`, gates passed. Numbers in the table below. Also run with `--exec-stream whole` into `results/n100000-P3-whole` (status `ok`, `stream_link` = full).
3. Same seed as w30 at n = 2000: `../pqz-integrated-w30/target/release/w30 run --setting S0 --n 2000 --layouts clustered --runs 1 --limit-s 600 --out $PWD/results/ref-w30-S0-n2000` (read-only binary, output in this crate) -> status `ok`. Both drivers: seed 5787506232797710676, n_selected = 20, r = 1, r_hit_blocks = 1. The sum is not a CSV column; both drivers gate the claimed (count, sum) against the plain reference over the same generated records (G2). The w34 test prints `count=20 sum=15904545` and asserts claim == statement == plain reference. So the w30 run that passed G2 has the same count and sum (equality of the w30 sum is by that gate, not read from its CSV).
4. n = 1e6 NOT run on the laptop (30 GB RAM, about 12 GB free).

`/usr/bin/time -v` does not exist on this machine. Peak RSS comes from the driver (VmHWM read in the child after each stage, with a reset before each stage); `process_peak_rss_kb` is the maximum over the stages. Stage peaks are in `raw.csv`.

### n = 100000, clustered, `exec_stream retained` (results/n100000-P3/raw.csv)
G = 200 blocks, 1000 selected, r = 3 retained blocks.
| stage | time (s) | stage peak RSS (kB) |
|---|---|---|
| P3a log | 2.393 | 93 516 |
| P3b R_RC prove (pub 0.130, trace 0.269, prove 0.836; 131072 rows; 184 517 bytes) | 1.237 | 2 560 248 |
| P4a AA verify R_RC | 0.0013 | 201 060 |
| P4b ledger | 0.0021 | 201 060 |
| P5 R_Auth (64 rows; 126 821 bytes) | 0.0039 | 201 060 |
| P6a search (BPS 0.00001, RPS 0.00007) | 0.0001 | 201 060 |
| P6b R_Exec (2048 rows; 157 765 bytes; prove 0.019) | 0.0265 | 241 764 |
| P7 requester (native 0.000004, Auth 0.0008, Exec 0.0009) | 0.0017 | 201 200 |
| total of the 8 stage timers | 3.666 | process peak 2 560 248 (2.44 GiB) |
Gates 0.122 s (outside the timers). Security (library estimate): conjectured 127 bits, proven unique-decoding 49, proven list-decoding 69-74.
With `--exec-stream whole`: P6b 1.470 s (131072 rows, 204 517 bytes), P7 0.0021 s, total 4.991 s, process peak 3 075 008 kB.

### n = 1e6 memory estimate (NOT measured)
Peak is in P3b (R_RC). At 1e5: 2 560 248 kB peak, about 201 000 kB held before the stage, so about 2 359 000 kB for 131 072 rows = about 18.0 kB per trace row. At 1e6: 2000 blocks x 501 = 1 002 000 words -> 1 048 576 rows (8 x). Linear estimate: 8 x 2.36 GB + the held log (about 10 x 0.2 GB = 2 GB) = about 21 GB. This is a linear extrapolation from one point, not a measurement; the real value can differ. It does not fit the 12 GB that are free on this laptop. With `--exec-stream whole` the Exec stage would be about the same size as R_RC and does not raise the peak above it.

## Build
`cargo build --release --offline` and `cargo test --release --offline`, both with the `Cargo.lock` seeded from w33's (Plonky3 crates `=0.8.0`). Release binary sha256 (first 16 hex): `f4cf5a438d01bd46`.
