# pqz-integrated-w35: w34 end-to-end plus BlockCover / PruneValid (D2-D5, D1c)

Status 2026-11-15: LAPTOP PROTOTYPE, design v3 (D1c: header words in the accumulators, fixes the 64-bit tag-slot link). Spec: `journal2/DESIGN-w35-blockcover.md` (section 3 D2-D5, section 7 gates, section 8 D1c).
Copy of `pqz-integrated-w34` (its code and 20 honest tests unchanged and passing) with `../pqz-plonky3-w35` as proof layer
(chunk AIR D1/D1b/D1c and run AIR D4, see that README). `pqz-eval` and `pqz-ledger` are used read-only; they were NOT edited.
ALL TIMINGS HERE ARE LAPTOP SMOKE DATA (22 cores, shared machine, plain mode, cold single run). They are not benchmark numbers.

## What is built

| file | content |
|---|---|
| `src/w35.rs` | D2: `Bloom35` (copy of the pqz-eval Bloom code: m = 45*count bits, fp 0.01, k clamped 1..8, positions `(h1 + i*h2) % nbits`), `BloomOpening`, `Block35` (B_{e,g} with sigma and MRoot(S)), `epoch_root35`. D3: `aa_finalize` with `AaChecks`. D4: `plan_runs` (gap_merge), `prove_runs`, `respond`. D5: `requester_native35`, `verify_requester35`, `ReqChecks`. `run_one35` (full pipeline with gates), `Outcome35`. |
| `src/lib.rs` | w34 lib plus `h_cts` in `Log`, `descriptor_h`, `h_ct_of`; v3: `hd_of`, `header_of_block` (header slots 5-6 = hd_g), `build_log` writes the v3 header words |
| `src/bin/w35.rs` | CLI (below) |
| `tests/common/mod.rs` | fixture `Fx` (v3: `reprove_stream` proves a modified stream with consistent chunk statements) |
| `tests/w35_bloom.rs` (5) | Bloom35 bits equal pqz-eval bits (same sha3 digest), openings vs MRoot, `formula_absent` vs `bps_eval`, `descriptor_h`, Block35 commitment binding |
| `tests/w35_honest.rs` (9) | honest gates (list below) |
| `tests/w35_attacks.rs` (16) | A1-A16 |
| `tests/w34.rs` (20) | old w34 tests, unchanged |

## CLI

```
w35 run --setting P3 --n N --layouts clustered|scattered[,..] --runs R --chunk C --gap-merge K --out DIR [--limit-s S] [--append]
```
`--runs R` = repeats per point (fresh process each). Output: `DIR/raw.csv`, `env.txt`, `failures.txt`, `stderr/`. Stage columns:
`aa_check_s` (AA verifies all chunk proofs and does the native checks, D3), `req_native_s` (requester native checks of D5, step 1-2),
`runs`, `blocks_proven`, `req_bytes` (block list + Bloom openings + run proofs + Auth proof), `exec_prove_s` (R_Exec run proofs), `p3b_s` (chunk proofs).
A child that fails (prover error, verifier reject, gate failure) is recorded as a FAILED row; the note column of every ok row says "LAPTOP SMOKE DATA".

## v3 (D1c) in the integrated crate

- Header word = `[e, g, m_b, pid, seq_start_g, hd_lo, hd_hi, 1]`; `hd_g = SHA3("pqz-w35-hd" || e || g || D_{g,1..B})`, `hd_lo`/`hd_hi` = u64 LE of bytes 0..8 / 8..16, each mod p.
- `aa_finalize` step 3 rebuilds, from the AA's own material, the tag slots AND the header word of every block of every chunk (`derive_headers`), recomputes
  alpha and beta (hash over s_in, s_out, meta, hdr_first, tag slots, header words) and the three accumulators natively. Messages: "alpha differs ...",
  "beta differs ...", "acc_k differs ...".
- Requester `hdr_first` check: compares slots 0..4 and the flag slot 7 (== 1) only. The requester has no descriptors, so it cannot know hd_g; slots 5-6
  of the first header of a run stay bound by the anchored sponge states (`states`) as before. This is a deliberate weakening of the old
  full-word compare, not a gap: the AA's D1c check has already pinned every header word of the stream.
- `ChunkProof.claimed` is a TEST-ONLY side channel: the tag slots and header words the stream has. It is read only when `AaChecks::tag_slots` or
  `AaChecks::d1c_hdr` is OFF, to model an AA that trusts that part of the stream (an attacker with a 2^64 slot collision, or a missing header check).
  Production uses `::ON` and never reads it.
- Switches added: `AaChecks.d1c_hdr` (the AA rebuilds the header words itself), `AaChecks.tag_slots` (the AA rebuilds the 64-bit tag slots itself).

## Design of the checks and the test switches

`AaChecks` and `ReqChecks` are structs of booleans, one per check. Production code uses `::ON`. The switches exist ONLY for the tests:
each attack is run with all checks ON (must be rejected) and again with only the check that catches it OFF (to show that the check is the one doing the work).

Requester order (D5): native checks first (R_e rebuild from the block list vs the anchored R_e; run shape; run states; hdr_first;
Bloom zero-bit openings for every block outside the runs, with Merkle paths vs the anchored MRoot(S)), then the C_Q link, scope and
theta == THETA, then Auth, then every run proof. Result = sum over the runs; zero runs give (0,0).

## Honest gates (all pass)

clustered and scattered; empty result; all blocks retained; c in {1, 4, 16}; G not a multiple of c (G = 13 with c = 4 and 16; G = 40 with c = 16,
chunks 16, 16, 8); gap_merge 0 and 1 (2 runs vs 1 run; 8 vs 12 blocks proven in the test fixture); result equals the plain reference;
chunked digest equals the w33 one-proof digest. The last one is tested in `w35_honest` (native, c = 1, 4, 16 at N = 6500 and 20000, G = 13 and 40, G not a multiple of c where applicable)
and in `pqz-plonky3-w35/tests/w35_chunk.rs` (with the AIR proofs). In `run_one35` the AA digest equals `ref_chain_digest` and `plain::rc_public`.

## Attacks A1-A16

"ON" = all checks on. "OFF" = only the named check off. Y = as stated.

| # | attack | rejected, all ON | caught by | accepted with that check OFF |
|---|---|---|---|---|
| A1 | run over a foreign stream of the same size | Y | `states` | Y (wrong result) |
| A2 | a retained chunk left out of the runs | Y | `prune` | Y (wrong result) |
| A3 | block list with a block removed / duplicated / reordered | Y (all three) | `block_list` | Y; removal loses hits; duplicate and reorder keep the true result in this fixture |
| A4 | summary forged after the AA signed (a: bits cleared) | Y | `block_list` (R_e mismatch) (a), `open_path` (b, Merkle path vs anchored MRoot) | Y (wrong result) |
| A5 | summary forged at ingest | Y (the AA refuses) | `AaChecks.summaries` | Y |
| A6 | Bloom opening with wrong bit, corrupted path, or leaf index out of range | Y (all three) | `open_path` | Y |
| A7 | run not on chunk boundaries (a), overlapping runs (b) | Y | `run_shape` (a also by `states`; a needs both off to be accepted) | Y (b is double-counted) |
| A8 | run from another epoch's (a) or another chunk's (b) state | Y | `states` (a also by `hdr_first`; a needs both off) | Y (a: (0,0) hides the hit) |
| A9 | claimed result != sum of the runs | Y | `claim` | Y |
| A10 | broken R_RC chunk link | Y (the AA refuses) | `AaChecks.links` | Y (digest differs) |
| A11 | chunk 0 not starting at the IV | Y | `AaChecks.iv`, and the AIR rule R2b | Y (with `iv` off, chunk 0 verified with the AIR without R2b) |
| A12 | AA given a tag list that differs in one record | Y | `d1b_alpha` and `d1b_acc` (each catches it alone) | Y only when BOTH are off |
| A13 | chunk proof whose alpha != H(...) | Y (the AA refuses) | `d1b_alpha` | Y (acc is consistent for alpha = 0) |
| A14 | keyword tags of the 40 hit records substituted so the query bits clear; the attacker is given a 64-bit slot collision (`tag_slots` OFF) | Y (alpha differs, also with `tag_slots` OFF) | `d1c_hdr` (hd_g binds all descriptors); `tag_slots` is the second line (needs a 2^64 search) | Y only with BOTH `tag_slots` and `d1c_hdr` off; the requester then accepts and the answer is (0,0) != truth |
| A15 | wrong `seq_start_g` (records renumbered to match, R_RC proves) in a later header (a), wrong `g` (b), wrong seq_start in a later chunk (c); first header of chunk 1 (d) | Y (all four) | `d1c_hdr`; (d) is caught first by the `meta` hdr_first check | Y with `d1c_hdr` off (d: needs `meta` and `d1c_hdr` off) |
| A16 | header slots 5-6 != hd_g (lo, hi, both zero; first header of chunk 1 too) | Y | `d1c_hdr` | Y with `d1c_hdr` off |

Redundancy: A7a, A8a, A12 and A14-A16 are caught by two checks each (A14-A16: `d1b_alpha` and `d1b_acc` each refuse alone: with alpha off the "acc_" message appears). That is intended defence in depth, but it means a single-switch test is not enough
for them; the tests turn both off to show acceptance.

## Test counts

`cargo test --release --offline`: integrated 50 passed, 0 failed (20 w34, 16 attacks, 5 bloom, 9 honest). Plonky3 crate: 70 passed, 0 failed.
Before v3: 47 and 68. No existing test expectation was changed (the old tests only needed the new `ChunkLists`/`seal` API in their helpers).
Chunked digest == one-proof digest (c = 1, 4, 16; G = 13 and 40) is in `w35_honest` and still passes on the v3 stream.

## Findings and caveats (read these)

1. The requester holds the query formula (TK_Q). In w34, `verify_requester` has no query token, so the requester cannot compute the Bloom
   positions of the query tag. DESIGN section 2 says the requester holds TK_Q, so in w35 the `Formula` is passed to `verify_requester35`.
   This is an ASSUMPTION about the token model. If the requester must not see TK_Q, D5 cannot check the zero-bit openings and needs a different design.
2. FIXED IN v3 (D1c). The tag slot in the stream is still only a 64-bit descriptor prefix (`tag_of_descriptor(d)` = u64 LE of d[..8] mod p), so
   the D1b link alone was 64 bits wide. v3 puts hd_g (a hash of all descriptors of the block, about 127 bits in the header) into the fingerprint, and
   the AA rebuilds it (attack A14). Remaining 64-bit part: none for the link; the tag slot stays in the record word and in R_Exec but no security rests on it.
3. R_RC does not enforce `g` or `seq_start` continuity across blocks (it ties slots 0, 2, 3, 4 of a header to the first record of its block only).
   Since v3 the AA's D1c check binds every header word to the block position (A15, A16); header slots 5-6 are free in the AIRs and bound to hd_g by the AA.
4. The `s_in` of a run that starts in an unanchored place cannot be checked by a proof alone; the run-shape and `states` checks (sigma set at chunk ends) are what bind it.
5. A3 duplicate and reorder: accepted when `block_list` is off, but the result still equals the truth in the fixture, so that test shows the check fires, not a wrong sum.
6. Salt option O1: NOT built.
7. gap_merge does not change the result; it trades blocks proven against number of runs (proofs).

## Smoke runs before (v2) and after (v3, D1c) (LAPTOP SMOKE DATA, c = 4, gap_merge 1, one cold run; v2 in `results/smoke-*`, v3 in `results/smoke-v3-*`)

| N | layout | G | retained | runs | blocks proven | aa_check_s v2 -> v3 | of which native v2 -> v3 | chunk verify v2 -> v3 | req_native_s v2 -> v3 | req_bytes v2 -> v3 | p3b_s v2 -> v3 | peak RSS kB v3 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2e4 | clustered | 40 | 2 | 1 | 8 | 0.165 -> 0.166 | 0.156 -> 0.157 | 0.0091 -> 0.0086 | 0.0002 -> 0.0003 | 313290 -> 310570 | 0.219 -> 0.206 | 125568 |
| 2e4 | scattered | 40 | 39 | 1 | 40 | 0.178 -> 0.184 | 0.168 -> 0.174 | 0.0098 -> 0.0094 | 0.0001 -> 0.0001 | 323466 -> 324714 | 0.223 -> 0.214 | 782924 |
| 1e5 | clustered | 200 | 3 | 1 | 8 | 0.851 -> 0.917 | 0.801 -> 0.871 | 0.050 -> 0.046 | 0.0012 -> 0.0017 | 393706 -> 395562 | 1.274 -> 1.059 | 217620 |
| 1e5 | scattered | 200 | 200 | 1 | 200 | 0.911 -> 0.854 | 0.860 -> 0.810 | 0.051 -> 0.044 | 0.0002 -> 0.0002 | 360490 -> 361034 | 1.158 -> 1.059 | 3128448 |

The v3 results are identical to v2 (same count and sum). aa_check_s moves by -6% to +8% between the two runs: that is run-to-run noise on a shared laptop,
not a measured D1c cost (D1c adds one SHA3 over the 500 descriptors per block and 7 field multiplications per header to the native part; the proof side
is unchanged in rows and in size within noise). Other columns (exec_prove_s etc.) are in the raw.csv of each folder.

(G = N/500; also run: N = 6500 in `smoke-small`, and N = 2e4 with gap_merge 0 in `smoke-2e4-g0`: same runs and blocks proven as gap_merge 1 for this fixture.)
Scattered data keeps (nearly) every block, so the run covers the whole stream: this is the worst case for D4. "Retained" for scattered at 1e5 = 200 of 200.
No cost claim should be drawn from these numbers (single cold run, load average about 3).

## Not done / open

- No cloud run, no timed matrix (laptop only, by instruction).
- Only P3 (Plonky3, plain mode) is built; no zk-mode switch.
- DESIGN wording to fix: points 1-3 above.
