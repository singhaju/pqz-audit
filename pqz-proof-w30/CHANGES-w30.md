# CHANGES-w30: parallel proving of the linked chunks (copy of `bench/pqz-proof-w29`)

Date 2026-11-14. Spec: `journal2/UPGRADE-w30-plan.md` section 5. Laptop, build + tests only. NO timing result was produced or is reported here
(the smoke runs only show that the programs and the driver work; their output is in the scratchpad, not in this folder).

## What is this
`cp -a` of w29 (nothing dropped; `bin/w29-*`, `results/w29*`, old `CHANGES-*` are still inside as copies). w29 itself was not touched.
Sequential linked mode and single mode are the w29 code, unchanged and still the default. New: a parallel mode for the linked chunks of R_Exec and R_RC.
The AIRs (`exec_link.rs`, `rc_link.rs`), `chain_link.rs`, `split.rs`, the publics, the verifiers: byte-identical to w29. The proofs of the parallel mode pass
the same `verify_exec_chunked` / `verify_rc_chunked` (no verifier change).

## Check 2: where do S_in, cnt_in, sum_in, hdr_before come from?
NOT from the trace of chunk i-1. Already in w29: `chain_link::reference_chunks` runs the reference sponge (`rescue::perm`) natively over all
records and counts natively; `exec_chunk_instances` / `rc_chunk_instances` call it for ALL chunks before any proof, and the sequential
`prove_exec_chunked` / `prove_rc_chunked` consume exactly these instances. So no new "boundary function" was needed; the parallel mode uses
the same function, and the test below proves that its values equal what the traces contain.

## Files changed / new (relative to w29)
| file | change |
|---|---|
| `src/par_link.rs` | NEW. `split_threads` (thread rule), `run_in_pools` (one OS thread + one rayon `ThreadPool` per chunk, work inside `pool.install`), `prove_exec_chunked_parallel`, `prove_rc_chunked_parallel`, `ParStats`, `total_threads`. 1 unit test (`thread_split_rules`). |
| `src/lib.rs` | one line: `pub mod par_link;` |
| `Cargo.toml` | `rayon = { version = "=1.12.0", optional = true }`, feature `concurrent` = `["winterfell/concurrent", "dep:rayon"]` (rayon 1.12.0 is the version already in the lock). `Cargo.lock`: only `rayon` added to the dependencies of `pqz-proof`. |
| `src/bin/w30.rs` | NEW (copy of `w29.rs`). Flag `--parallel-chunks` (with `mode=linked`; optional `threads=N`, default = size of the rayon global pool = all logical cores). Row mode column `linked-par`. Two trailing columns on EVERY prove row: `bound_s`, `threads`. Verify children unchanged. |
| `scripts/w30_driver.py` | NEW (copy of `w29_driver.py`). Settings S0..S5, interleaved round-robin with rotating start (6 settings, `rep % 6`); output `results/w30` (env `W30_OUT`); binaries `bin/w30-*`; CSV = w29 columns + `bound_s,threads`; summary adds `median_full_ms` and paired ratios S2/S4 and S3/S5. |
| `tests/parallel.rs` | NEW, 5 tests. |
| `bin/w30-sha3`, `bin/w30-blake3` | NEW binaries. |

Labels: S0 sha3 single, S1 blake3 single, S2 blake3 linked (sequential), S3 sha3 linked (sequential), **S4 blake3 linked parallel, S5 sha3 linked parallel**.

## Parallel mode, step by step
1. Boundary values of all chunks (single thread, native sponge + counting + copy of the chunk words).
2. Thread split (`par_link::split_threads`): total T = `rayon::current_num_threads()` (all logical cores; 22 here). Padded rows of chunk i = `split::chunk_rows`
   (power of two, min 32). Every chunk gets at least 1 thread, `floor(T * rows_i / sum rows)` otherwise, then largest-remainder rounding so the total is exactly T
   (ties: the higher chunk index gets the extra thread; when removing, the most over-served chunk with more than 1 thread loses one). If T < number of chunks every chunk gets 1.
   Example (50000 records, block 100, 4 chunks, 22 cores): 14+6+1+1.
3. One OS thread per chunk; each builds its own `rayon::ThreadPool` of its size and runs trace build + proof inside `pool.install` (winterfell's rayon calls therefore stay in that pool).
4. Join all; collect proofs and publics.

## Timer boundary
S4/S5 (`prove_s` column of the parallel row, = `ParStats::wall_s`): from the start of the boundary computation (step 1) to the moment the last chunk proof is returned.
It includes: boundary values, copying the chunk words, creating and dropping the thread pools, trace building, proving. It does NOT include serialising or verification (verify_s is
printed for information). Statement preparation and the workload are outside, as in w29.
**Not comparable with S2/S3 `prove_s`** (those are proving only; trace build is the column `trace_s`, the boundary is outside). For the comparison S2 vs S4 and S3 vs S5 use
`full_ms` = trace_s + prove_s + bound_s of the sequential row (the summary prints it and the paired ratio `seq/par`). `bound_s` of S2/S3 is measured ONCE at child start-up, outside
every timer (minimum of 3 repetitions), so it is a stable estimate, not a per-run value. Parallel row: `trace_s` = the longest per-chunk trace build (information, inside `prove_s`),
`bound_s` = boundary time of that run (inside `prove_s`), `threads` = "a+b+c".
The boundary computation is single-threaded in both modes; it is a serial part of S4/S5 (its size is in `bound_s`).

## Tests (release; all outputs in `results/tests/w30-*`)
`tests/parallel.rs`:
- `boundary_values_equal_trace_values_50_workloads_both_relations`: 50 random workloads (blocks 1..12, block size 3..9, random theta, chunk counts cycled 1,2,3,4: histogram 13/13/12/12),
  both relations, NO proving. For each chunk it compares the natively computed values (`reference_chunks`, and the publics of `exec_chunk_instances` / `rc_chunk_instances`, which the
  sequential prover consumes) with values read from traces: (a) the chunk's own trace at the last real row (state S, cnt, sum, hdr counter) and row 0 (cnt_in, sum_in, hdr_before+1), chained
  chunk to chunk; (b) the one-chunk trace of the WHOLE stream at the row before the chunk's first word (S_in, cnt_in, sum_in, hdr_before). Also the final cnt/sum = `reference_result`, digest = commitment.
- `exec_parallel_proofs_verify_1_to_4_chunks`, `rc_parallel_proofs_verify_1_to_4_chunks`: splits [8], [4,4], [3,3,2], [3,2,2,1] (8 blocks of 4), thread totals 1, 3, 6 and all cores; the parallel
  proofs verify with the unchanged verifiers, thread counts sum to the total, and the chunk publics are equal (Debug string) to those of the sequential mode.
- `parallel_with_plan_split_and_a_tampered_parallel_proof_is_rejected`: 40 blocks, `plan_split` split, parallel proofs verify; a changed `cnt_in` is rejected.
- `each_chunk_runs_in_its_own_pool_of_the_requested_size`: inside each chunk `rayon::current_num_threads()` equals the requested size; four chunks wait on a barrier (proves they really run at the same time).
- lib unit test `par_link::tests::thread_split_rules` (sum = total, >= 1 each, monotone in rows, fewer threads than chunks).
Full release suite: `w30-all-release-sha3.stdout` 88 passed, 0 failed (lib 4, cover 16, covermerkle 20, linked 23, parallel 5, relations 20); `--features blake3`
`w30-all-release-blake3.stdout`: the same 88 passed. (w29 had 82: the 6 new ones are 1 lib + 5 parallel.) `w30-parallel-release-sha3.stdout`: the 5 parallel tests alone.
Debug build of the new tests was not run (release is the gate, as in w29; RC splits with a 1-block chunk are skipped in debug in the new tests as in `linked.rs`).

## Binaries
Built with `cargo build --release --offline --bin w30` (default = SHA3) and `... --features blake3 --bin w30`, copied right after each build.
- `bin/w30-sha3` sha256 `9a5759f551ed79b1b50733124ef4b644b9896d37e8ce708ef96e023ec7a4493b`
- `bin/w30-blake3` sha256 `2927385651fee50cdd25b219d1505c2e3bc62127076adc278aa8a3310be4a17d`
Smoke (1 run each, no numbers kept): S4 and S5 of R_Exec at N_Q 5000 and 50000 (block 100), S4 of R_RC at 50000: the honest parallel proofs verified (the child asserts it); READY lines print
`Blake3_256` / `Sha3_256`. The driver was smoke-tested on R_RC N_Q 5000 (all six settings, outside this folder).

## Command for the lead (laptop matrix; 3 rounds)
Run from `bench/pqz-proof-w30` (one round = one command; repeat 3 times; raw files are appended, never edited; load rule of w29 applies):
```
for r in 1 2 3; do ../../.venv-bench/bin/python -I scripts/w30_driver.py prove --rels exec,rc --sizes 20000,50000,100000 --block 100 --warm 3 --timed 10; done
../../.venv-bench/bin/python -I scripts/w30_driver.py env     # once, before: writes results/w30/w30-env.txt
../../.venv-bench/bin/python -I scripts/w30_driver.py summary # after
```
Read for the gate (plan section 5, ratio S2-seq / S2-par >= 1.10 at 5x10^4 or 10^5): `paired_ratio_seq_over_par_full` in `results/w30/prove_*.summary.csv` (S4 vs S2 = Blake3, S5 vs S3 = SHA3);
`paired_ratio_seq_over_par_provems` compares only `prove_s` of S2 with the parallel wall (unfair to S2, kept for information).

## Open / notes for the lead
- Memory: all chunks are alive at once in the parallel mode (peak RSS is higher than sequential); `vmrss_kb` is printed after the run only.
- Thread-pool creation and drop are inside the timer (conservative against S4/S5).
- With the default split most of the rows sit in 1-2 chunks (e.g. 262144 + 131072 + 8192 + 4096 rows at 50000), so the gain is limited by the largest chunk's thread share and by the serial boundary step; that is a property to be measured, not assumed.
- `bin/w29-*`, `results/w29*` and the old `results/tests/*.stdout` (w29 names) were copied from w29 and are not w30 results.

## Lead fix e443 (after attack finding)
Date 2026-11-14. Cause: `bench/pqz-attack-w30/REPORT-w30.md` (attack experiment on w29): A1 = the Auth proof of request 1 was accepted together with the Exec
proof of request 2 (nothing tied Exec's ctx to the Auth statement); A2 = proofs with 30 or 35 queries (105/120 conjectured bits) were accepted because the
verifier only had a floor of 80 bits. Both fixed here, in `bench/pqz-proof-w30` only (w29 and `bench/pqz-attack-w30` untouched). Backup of the pre-fix `src/`, `tests/`, `bin/`
(scratchpad, not in the repo): `w30-src-backup`, `w30-bin-backup`. NO timing result was produced or is reported. The numbers in the earlier sections of this file
(binary sha256, 88 tests) describe the state BEFORE this fix.

### (a) Strict options
- `prove::verify_proof::<A>(proof, pub)` (no `min_bits` argument any more) = `winterfell::AcceptableOptions::OptionSet(vec![default_options()])`: only a proof
  made with exactly `default_options()` is accepted (queries, blowup, grinding, extension, FRI folding, remainder, batching). Used by `verify_exec`, `verify_rc`,
  `verify_auth`, `verify_cover`, `verify_covermerkle`, `verify_exec_chunked`, `verify_rc_chunked` (every chunk), `request::verify_request*`, and by the bins
  `w30`, `w29`, `chunked`, `cover`, `covermerkle`, `proofbench` (their `MIN_BITS` constants and the "min_bits accepted" line of the env file were removed; the
  line now says "verifier accepts only default_options() (strict, no bit floor)"). The signatures of all `verify_*` lost the last `min_bits: u32` argument.
- Kept, separately named: `prove::verify_proof_min_bits::<A>(proof, pub, min_bits)` (the old floor rule). Used only by bin `pilot` (it sweeps PQZ_QUERIES etc. and
  verifies non-default options on purpose) and by tests (`tests/relations.rs::exec_security_floor_enforced`, `tests/request.rs` controls).
- Chunk proofs: the prover side uses `default_options()` everywhere (bin w30/w29/chunked and `prove_exec_chunked(.., default_options(), ..)`), and each chunk goes through `verify_proof`, so
  they are strict as well. `check_same_options` stays (cheap early exit), it is now implied.
- Caveat: `default_options()` reads PQZ_QUERIES / PQZ_BLOWUP / PQZ_GRIND. A verifier process that sets them changes what it accepts (only a deployment concern; the prover has the same
  variables). The drivers do not set them.

### (b) Context binding
- New module `src/request.rs` (+ `pub mod request;` in `lib.rs`).
- `exec_context(b_q: [F;4], d_q: [F;4], rid: u64) -> [F;4]` = C_Q = H("PQZA-EXEC" || B_Q || Auth_Q || RID_Q). Mapping in this prototype: B_Q = `AuthPublic::b_q`,
  Auth_Q = `AuthPublic::d_q` (the Auth statement's digest), RID_Q = `u64`, 0 for a routine request (paper: bottom). H = native Rescue Prime sponge (`rescue::perm`, rate 8, capacity 4),
  fixed-length: capacity = [11, 0, 0, 0] (11 absorbed elements), message in the order tag0, tag1, b_q[4], d_q[4], rid (tag "PQZA-EXEC" = 2 elements: LE u64 of "PQZA-EXE" and "C"), added into the
  rate, last block zero padded, output = state[4..8]. This is a prototype choice (the paper only says H(...)); the owner may fix another encoding, the check does not depend on it.
- `verify_request(auth_proof, auth_pub, exec_proof, exec_pub, rid)`: computes `exec_context(auth_pub.b_q, auth_pub.d_q, rid)`, rejects ("link: Exec ctx != exec_context(...)") if it differs
  from `exec_pub.ctx`, then `verify_auth`, then `verify_exec`.
- `verify_request_chunked(auth_proof, auth_pub, exec_proofs, &ExecChunkedStatement, rid)`: the same check on the statement ctx, then `verify_auth`, then `verify_exec_chunked` (which already requires every chunk's ctx = statement ctx).
- bin `w30`: `verify kind=pair2` and `kind=bundle3` verify Auth + Exec through `verify_request` INSIDE the timed region (parse of both proofs, binding, both proof checks; the rc proof of bundle3
  still through `verify_proof`). The benchmark Exec statement of these kinds is built with ctx = `exec_context(auth.b_q, auth.d_q, 0)` of its Auth statement (`prepare(.., exec_ctx)`).
  Stand-alone Exec statements (execsingle, execchunk, prove rows) keep `ctx_of(seed)` (no Auth statement exists there). CSV formats are unchanged. bin `w29` keeps its separate verification (it is the w29 record), only strict.

### (c) Tests
New `tests/request.rs`, 13 tests: context depends on every input; honest pair accepted (single depth 6 and 10; chunked [8], [4,4], [3,3,2]); privileged rid accepted only with the matching rid;
Auth of request 1 + Exec of request 2 rejected (single both directions, chunked) with the binding error; same workload but other request's ctx rejected; ctx off by one element (4 elements) rejected
(a) proof made honestly for the wrong ctx, (b) public ctx changed after proving, chunked: statement ctx, and one chunk's ctx; 30- and 35-query proofs rejected by every verifier (exec, rc, auth, exec chunked,
rc chunked, pair single, pair chunked, cover, covermerkle) with a control that the same proof is valid under `verify_proof_min_bits`; other blowup / grinding / queries (41, 40-blowup 16, grind 15) rejected;
default options accepted by both verifiers.
Old tests: all 88 pass, adjusted only by dropping the `MIN_BITS` argument (mechanical); the single test that relied on the floor rule, `exec_security_floor_enforced` (min_bits 400 rejected), now calls
`verify_proof_min_bits::<ExecAir>(.., 400)`. No test had relied on a weak proof being accepted.
Results: `results/tests/w30-e443-all-release-sha3.stdout`: 101 passed, 0 failed (lib 4, cover 16, covermerkle 20, linked 23, parallel 5, relations 20, request 13);
`results/tests/w30-e443-all-release-blake3.stdout` (`--features blake3`): the same 101 passed.

### (d) Binaries (rebuilt as above: `cargo build --release --offline --bin w30` and `... --features blake3 --bin w30`, each copied right after its build)
- `bin/w30-sha3` sha256 `252ee30b0abdbb3b200904a53821a15e8bba5eb761053bb615e4d24ac88b910d`
- `bin/w30-blake3` sha256 `cd9570dd8414355c163cd40d58919d37b04474eee4b124f952e029cfa6f0be57`
Smoke (1 run each, no number kept): `verify kind=pair2` and `kind=bundle3` for both binaries and `execchunk` n=5000 for sha3: honest proofs verify (the child asserts it); READY lines print `Sha3_256` / `Blake3_256`.
The old binaries (sha256 above in "Binaries") are superseded. `bin/w29-*` are old copies, not rebuilt. Any timing in `results/w30*` made before this fix does not include the binding or the strict check; the pair2/bundle3 numbers must be re-measured.
