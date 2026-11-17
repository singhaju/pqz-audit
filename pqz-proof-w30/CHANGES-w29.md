# CHANGES-w29: linked chunks for R_Exec and R_RC (copy of `bench/pqz-proof-w25`)

Date 2026-11-13. Spec: `journal2/UPGRADE-w29-plan.md` sections 1-3. Laptop only. The AIR has NOT yet been reviewed by the lead; no timing
result in this folder is a real result (the smoke run is in the scratchpad, not here).

## What is this
A copy of the w25 prototype (Rust, winterfell 0.13.1, f64 field) plus a "linked chunks" variant of R_Exec and R_RC: the stream of
whole blocks is cut into at most 4 chunks, each chunk is a separate STARK proof, and the chunks are tied together by public sponge state and by
verifier-side chain checks. The existing relations are not changed.

## Copy check
Command (run in `bench/`):
`/usr/bin/diff -rq --exclude=target --exclude=results --exclude=__pycache__ pqz-proof-w25 pqz-proof-w29`
Result: only these differences.
- Only in w25: `bin/` (4 old binaries, not copied on purpose)
- Only in w29: `bin/w29-sha3`, `bin/w29-blake3`, `scripts/w29_driver.py`, `src/bin/w29.rs`, `src/chain_link.rs`, `src/exec_link.rs`,
  `src/rc_link.rs`, `src/split.rs`, `tests/linked.rs`
- Changed: `src/lib.rs` (four `pub mod` lines added)
(`-x bin` must NOT be used: it also hides `src/bin/`.) `src/exec.rs, rc.rs, auth.rs, chain.rs, data.rs, rescue.rs, prove.rs` are byte-identical to w25.
`Cargo.toml` is unchanged (autodiscovery builds `src/bin/w29.rs`).

## New files
| file | content |
|---|---|
| `src/split.rs` | `plan_split(n_blocks, block_size, max_chunks)`: 1:1 port of the pilot's `best_split` DP (`scripts/pilot_driver.py`): whole blocks, padded rows of a chunk = `pow2_len(blocks*(bs+1)*8)` (min 32), minimise total padded rows, tie to FEWER chunks, result sorted in decreasing order. 3 unit tests (brute force). |
| `src/chain_link.rs` | `fill_chain_from`, `reference_chunks` (public link values from the reference sponge `rescue::perm`), `check_links` (checks common to both relations), `check_same_options`. |
| `src/exec_link.rs` | `ExecChunkPublic`, `ExecChunkAir`, `build_exec_chunk_trace`, `ExecChunkInstance`, `exec_chunk_instances`, `prove_exec_chunked`, `verify_exec_chunked`. |
| `src/rc_link.rs` | the same for R_RC: `RcChunkPublic`, `RcChunkAir`, `build_rc_chunk_trace`, `RcChunkInstance`, `rc_chunk_instances`, `prove_rc_chunked`, `verify_rc_chunked`. |
| `tests/linked.rs` | 23 tests (below). |
| `src/bin/w29.rs` | child programs of the matrix (`child prove`, `child verify`), same READY/ROW/IDLE protocol as `pilot.rs`. |
| `scripts/w29_driver.py` | driver: `env`, `prove`, `verify`, `summary` (fresh process per point, interleaved round-robin, rotating start, raw CSV append-only). |

## Helpers copied from existing private code (existing files not edited)
- `fill_chain_from` (chain_link.rs): the loop of `chain::fill_chain`, with a start state and a word slice instead of a `Workload`.
- `build_exec_chunk_trace` (exec_link.rs): copy of `exec::build_exec_trace` with start state and start (cnt, sum).
- `build_rc_chunk_trace` (rc_link.rs): copy of `rc::build_rc_trace` with start state and start header count.
- `ExecChunkAir::evaluate_transition`, `RcChunkAir::evaluate_transition`: copies of the transition constraints of `ExecAir` / `RcAir` (same
  degrees, same periodic columns, same width 33 / 26). `chunk4` helper copied in exec_link.rs.

## Public inputs and assertions

### ExecChunkPublic
`total_groups` (words of the WHOLE stream), `chunk_index`, `n_blocks_chunk`, `block_size`, `theta` (< 2^32), `ctx` (4 elements), `s_in: Option<[F;12]>`
(None for chunk 0), `hdr_first` (header word of the first block of the chunk), `cnt_in`, `sum_in`, `s_out` (12 elements; last chunk: only
elements 4..8 = digest, rest 0), `cnt_out`, `sum_out`, `is_last`. All of it goes into `to_elements` (so into the Fiat-Shamir seed).

Assertions of `ExecChunkAir` (`exec_link.rs::get_assertions`):
- row 0: S[0..4] = `cap_init(total_groups)` for chunk 0, else `s_in[0..4]`;
- row 0, chunks i>0 only: S[4+j] = `s_in[4+j] + hdr_first[j]` for j = 0..8;
- row 0: accD = 0, accV = 0, cnt = `cnt_in`, sum = `sum_in`;
- last real row (`n_groups*8 - 1`): not last chunk: S[0..12] = `s_out`; last chunk: S[4..8] = digest;
- last real row: cnt = `cnt_out`, sum = `sum_out`.

### RcChunkPublic
`total_groups`, `chunk_index`, `n_blocks_chunk`, `block_size`, `hdr_before` (real headers before this chunk), `s_in: Option<[F;12]>`, `hdr_first`,
`s_out`, `is_last`.

Assertions of `RcChunkAir` (`rc_link.rs::get_assertions`):
- `hdr_first[2] == block_size` is asserted in code (panic otherwise);
- row 0: S[0..4] = `cap_init(total_groups)` (chunk 0) or `s_in[0..4]`; S[4+j] = (rate of `s_in`, or 0 for chunk 0) + `hdr_first[j]`;
- row 0: K = (h[3], h[0], h[4]-1), cnt = 0, mb = block_size, hdr = `hdr_before + 1`;
- last real row: S full `s_out` (last chunk: S[4..8] = digest only); cnt = block_size, mb = block_size, hdr = `hdr_before + n_blocks_chunk`.

## Verifier checks (file:line of the `return Err`)
Common, `chain_link.rs::check_links` (line 133): chunks exist (136); n_blocks, block_size > 0 (139); `chunk_index == i` (146); `block_size` equals the
statement (149); `total_groups = n_blocks*(block_size+1)` (152); `n_blocks_chunk > 0` (155); no overflow of the sum (157); `s_in` present exactly for
i>0 (159); `is_last` exactly for the last chunk (162); `hdr_first[7] = 1` (166); `hdr_first[2] = block_size` (169); `s_in_i = s_out_{i-1}` (174); digest of the last
chunk = D (179); last `s_out` zero outside the digest (183); sum of `n_blocks_chunk` = `n_blocks` (188). `check_same_options` (194, error 197): all proofs
have the same options.
R_Exec, `exec_link.rs::verify_exec_chunked` (line 384): theta < 2^32 (412); theta equals the statement in every chunk (416); ctx equals the statement (419);
cnt/sum below p (422); `cnt_in_0 = sum_in_0 = 0` (427); `cnt_out_i = cnt_in_{i+1}` (431), `sum_out_i = sum_in_{i+1}` (434); final (cnt, sum) = claimed
result (438); then `verify_proof::<ExecChunkAir>` per chunk with the 80-bit floor (445).
R_RC, `rc_link.rs::verify_rc_chunked` (line 321): `hdr_first` of chunk 0 = `header0` (346); `hdr_before_i` = sum of earlier `n_blocks_chunk` (351);
then `verify_proof::<RcChunkAir>` per chunk (360).
The verifier takes the chunk publics as given (not recomputed from a workload); `n_blocks`, `block_size`, `digest`, `theta`, `ctx`, claim, `header0` are the statement.

## Tests (all run, outputs in `results/tests/`)
- `tests/linked.rs`, 23 tests: `split_reproduces_pilot_w25`; honest: `exec_honest_1_to_4_chunks`, `rc_honest_1_to_4_chunks`,
  `exec_single_chunk_equals_single_statement`; controls: `exec_control_legal_accepted`, `rc_control_legal_accepted`; rejection:
  `exec_reject_s_in_changed`, `exec_reject_s_out_changed`, `exec_reject_hdr_first_changed`, `exec_reject_counters_changed`, `exec_reject_n_blocks_chunk_changed`,
  `exec_reject_chunk_structure` (dropped / repeated / swapped / count), `exec_reject_other_workload_chunk`, `exec_reject_wrong_claim_ctx_theta`,
  `exec_reject_tampered_record_in_chunk`, `rc_reject_s_in_s_out_changed`, `rc_reject_hdr_first_changed`, `rc_reject_hdr_before_and_n_blocks`,
  `rc_reject_chunk_structure`, `rc_reject_malformed_stream_and_tampered_record`; `equivalence_random_workloads` (60 random workloads, forced splits of
  1..4 chunks, histogram [19, 19, 12, 10], random theta; honest only: the chunked count, sum and last digest equal the reference result and commitment, and
  `verify_exec_chunked` / `verify_rc_chunked` accept. It does NOT run the single proof side by side; that is covered for one fixed case by
  `exec_single_chunk_equals_single_statement`); `security_of_chunks_equals_single`;
  `old_rc_one_block_debug_degree_check` (shows the existing `rc.rs` itself trips winterfell's debug degree check on one block).
  "Deep" rejection variants change the public values consistently so that the link checks pass and require the STARK itself to reject.
- Release, default hash: `all-release-sha3.stdout`: 82 passed, 0 failed (lib 3, cover 16, covermerkle 20, linked 23, relations 20). With `--features blake3`:
  `all-release-blake3.stdout`: the same 82 passed. `linked-release.stdout`: 23 passed.
- Debug (`linked-debug.stdout`): 23 passed. In debug, `equivalence_random_workloads` skips (prints `debug-only skip`) cases where a chunk has a constant
  column (see "existing code" below); RC splits with a 1-block chunk are skipped in debug. Release is the gate.

## Binaries
Built with `cargo build --release --offline --bin w29` (default) and `... --features blake3 --bin w29`, copied right after each build.
- `bin/w29-sha3` sha256 `f271a3304991a4e0cf340adf563a8dfd47a326850b93449c2c5093b085b478cd`
- `bin/w29-blake3` sha256 `cce781bbbbe6ce0a6dff13d9dc5b9a0bca7e0fef88fa265338feae2916663f17`
(the READY lines of the smoke run print `Sha3_256` / `Blake3_256` respectively).

## Matrix choices made (not given exactly in the brief)
- Block size 500 for the prove matrix and for exec chunked / single verify at 50000 (as the pilot's L3 split runs); block 100 and seed 1000 for
  bundle3 / pair2 / rc1 at N_Q = 1000 (as the pilot's `bundle`). The pilot's own default for `prove` was block 100: do not compare with it without noting this.
- Prove timing = `prove_s` only (trace building is a separate column `trace_s`); chunked = sum over chunks. Serialisation and verification are after the timers.
- Verify timing = parse + verify of the serialised proofs (as the pilot); for chunked it includes all link checks.
- One round for verify (10 warm-up + 25 timed in one fresh process per hash and kind). `--rounds` is available.
- Security bits for chunked = minimum over the chunks.
- `results/w29-env.txt` was written by `w29_driver.py env` (CPU, governor, kernel, rustc, memory, binary hashes).

## Smoke run (NOT results)
Output in the scratchpad `.../scratchpad/w29-smoke/` (warm 1, timed 2, N_Q 5000 and 10000, verify at big-n 5000). Load average was 2.7-4.9 during it. Only shows the driver works.

## Deviations from the spec
1. `security_of_chunks_equals_single`: conjectured (127) and proven unique-decoding (49) bits are equal for chunks and single; the list-decoding bits are NOT equal
   (they depend on the trace length: 73/74 in the test, 69/70 at 5000-10000 records). The test asserts equality for conj and udr and `>=` for ldr.
2. Debug build: see below; the debug test covers fixed small cases and skips degenerate ones.
3. Last chunk: only the digest part of `s_out` is public (the rest must be 0, checked by the verifier); the spec's "full s_out" applies to non-last chunks.

## What looked wrong in existing code (reported, not fixed)
- Winterfell DEBUG builds check actual constraint degrees. A column that is constant over the whole trace gives actual degree 0 and a panic
  (release does not check). Seen in the existing `rc.rs` for a one-block stream (the "hdr hold" column is constant; `old_rc_one_block_debug_degree_check`),
  and in exec chunks with constant data (no record matches). Not a soundness issue; it is a test-environment limitation.
- `exec.rs` does not assert `header0` at row 0 (the digest binds it); the linked version asserts the first word only through `s_in + hdr_first` for chunks i>0.
- `RC`: `seq_start` of a block header is not compared with the last seq of the previous block (the plan already flags this).
- `ldr` bits vary with the trace length (see deviation 1).

## Not done / open
- Full matrix not run (smoke only, as ordered). AIR not reviewed by the lead yet.
- No cloud, no AWS, no network.
