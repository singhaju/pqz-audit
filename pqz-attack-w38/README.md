# pqz-attack-w38: attack test of the packed format P2r (PQZ-Audit, w38)

Correctness only, no timing. Laptop only, no cloud. Ported from `../pqz-attack-w36` (34 attacks, same families, plan, seeds, outcome classes).
Library under test: `../pqz-plonky3-w38` (`pqz_plonky3_w38`, config C1: Goldilocks, Poseidon2 w12, Blake3 Merkle, `FriOpts::from_env()`).

## What was ported
- `src/main.rs`: the w36 harness, imports moved to w38. Default path (no `fmt=`) = OLD format, unchanged logic. New outcome class `untested`.
  `fmt=p2r` switches to `src/p2r.rs`.
- `src/p2r.rs`: everything against the packed word `[id_a,v_a,b_a,tag_a,id_b,v_b,b_b,tag_b]` with `Fmt::P2r`
  (Exec AIR without the v range check; the chunk / RC proofs range-check v < 2^32 and b < 2^20).
- Verifier used: stream link (`check_stream_link_p`) + sealed check (`check_sealed`, against the AA's own lists) + Exec proof (`verify_pair`)
  + one chunk / RC proof per chunk (`pchunk::verify_chunk`); the forms with Auth use `verify_bundle_p` (adds the C_Q link and scope check, Auth proof).
- Stream attacks (changed_record_word, dropped_record, duplicated_record, reordered_records, changed_block_header) act on the packed words:
  record (g,k) = word `g*rows_per_block+1+k/2`, half `k%2`. dropped / duplicated use a coin flip: drop or duplicate a whole packed word, or shift the half-records of one block.
  changed_record_word picks slot id, v, b or tag of a random half (v flips a bit below 2^32, b below 2^20).
- Forms: exec_single (Exec attacked, chunks honest), rc_single (one chunk proof attacked, Exec honest), pair (Auth + Exec + chunks, bundle verification),
  bundle (stream_mismatch, inverted_scope; checks ON counted, OFF in `*nochecks*` files, not counted), packed (six new attacks).
- Plan: attack_trials=20 (seeds 30000+i), honest_trials=50 (seeds 40000+i), n20k=3 n50k=1 h20k=4 h50k=1, BLOCK=100, AUTH_DEPTH=10, RID=0.
  Honest trials alternate one chunk / several chunks (about n_blocks/3 blocks per chunk). Packed honest rows use block size 100, 99, 7 or 33 (odd and even).

## Six packed attacks (family "packed", form "packed", full bundle verification, 20 trials each, 3 / 2 variants per trial)
| attack | variants | which check rejected (all 20 trials) |
|---|---|---|
| (a) v >= 2^32, either half | v in [2^32, 2^32+theta) ; v large | window: chunk/RC proof `rc[0]` (Exec alone ACCEPTS, so the chunk range check is what stops it); large v: Exec (`exec`) |
| (b) b = 2^20 or above, either half | b in [2^20, 2^21) incl. exactly 2^20 ; b large | chunk/RC proof `rc[0]` (Exec alone accepts) |
| (c) non-zero empty half, odd block (B=99) | one slot ; four slots ; hand-made kinds with vb claimed | Exec AIR (`exec`) (rc alone also rejects) |
| (d) m_g differs from B in a header | AA lists honest ; attacker lists ; Exec only, chunks honest | `lists` (alpha/beta/acc) ; Exec AIR ; `link` (digest). The real AIRs (rule hdr*(w2-B)) also reject Exec and RC alone. A weakened AIR without the rule was NOT built |
| (e) Exec over stream A, chunk publics of stream B | chunk proofs B ; chunk proofs A | `link` (R_RC final state != Exec digest). Checks OFF: B-proofs variant is accepted (expected: both are valid proofs), A-proofs variant rejected by the RC proof |
| (f) swap the two halves of a pair word | consistent attacker, AA lists ; Exec only ; dishonest prover under original statement | `lists` ; `link` ; `exec` |

## Untested (kept, counted, 1 row per instance in exec_single and rc_single: 20 + 20 = 40)
- `changed_record_word_pid_epoch_seq` (the w36 slots pid, epoch, seq of the record word): no meaning in the packed format; a packed record half is
  [id, v, b, tag]. pid, epoch, seq_start live in the header word and are covered by `changed_block_header`.
- No other w36 attack name is meaningless; all 34 names run (changed_record_word now covers the four packed slots).

## Result (results/attack-w38-p2r, merged with `attack merge`; by family: `scripts/family_summary.py`)
- Attack trials 1340 total rows in the family table: rejected 1300, accepted 0, prover_refused 0, harness_error 0, untested 40.
- Honest: 350 rows (70 per form x 5 forms), accepted 350, rejected 0.
- By form (trials / rejected): exec_single 300/280 (+20 untested), rc_single 240/220 (+20 untested), pair 640/640, bundle 40/40, packed 120/120.
- Checks OFF (`summary_nochecks.csv`, not in totals): stream_mismatch, inverted_scope and packed_exec_A_chunks_B(B proofs) are accepted 20/20, as expected for a switched-off check.
- Old format, small plan (results/attack-w38-old; attack_trials=3 honest_trials=4 n20k=3): 177 trials, 177 rejected, 0 accepted, 0 refused, 0 harness_error; honest 28/28 accepted. No regression.

## Command lines (from this folder)
```
bash run-all.sh        # builds, hashes, runs P2r full plan, then the old-format small plan
# build alone
env CARGO_TARGET_DIR=../w38-exp4/target-attack-w38 RUSTFLAGS="-C target-cpu=x86-64-v3" nice -n 15 cargo build --release --offline -j 8
# P2r full plan
RAYON_NUM_THREADS=8 attack run fmt=p2r out=results/attack-w38-p2r attack_trials=20 honest_trials=50 n20k=3 n50k=1 h20k=4 h50k=1
attack merge results/attack-w38-p2r
# old format
RAYON_NUM_THREADS=8 attack run out=results/attack-w38-old attack_trials=3 honest_trials=4 n20k=3 n50k=0 h20k=4 h50k=0
../../.venv-bench/bin/python scripts/family_summary.py results/attack-w38-p2r
```
`attack` = `../w38-exp4/target-attack-w38/release/attack`. Run time of the P2r plan: 238 s on the laptop (8 threads).

## Binary
sha256 prefix (16 hex): `f9825be7de13ad62` (file `results/attack-w38-p2r/binary-sha256-prefix.txt`). RUSTFLAGS `-C target-cpu=x86-64-v3`.

## Notes and limits
- `results/smoke.old/` is a 1-instance smoke run kept for reference.
- Frozen `bench/zkalba-eval` and protected files untouched. No git commit.
