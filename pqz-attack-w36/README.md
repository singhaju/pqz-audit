# pqz-attack-w33: the w30 attack test ported to the Plonky3 build (stage C, gate G-C1)

Our own test, not an independent audit. Laptop only. Port of `bench/pqz-attack-w30-fixed/` (read only, unchanged) to the crate
`../pqz-plonky3-w33` (config C1: Goldilocks, degree-2 extension, Poseidon2 width 12, Blake3 Merkle, blowup 8, 40 queries, 16 bit grinding).
The harness drives the library prover (`p3_uni_stark::prove`) with wrong witnesses or wrong statements and calls the library verifiers
(`rel::plain::verify_*`, `request::check_ctx`) with the verifier's own fixed `FriOpts`.

## Run

```
cd bench/pqz-attack-w33 && ./run-all.sh        # build (nice -n 15, -j 8), run, merge
.venv-bench/bin/python scripts/family_summary.py   # writes results/attack-w33/summary_by_family.csv
```

Same plan and seeds as w30 (`attack_trials=20 honest_trials=50 n20k=3 n50k=1 h20k=4 h50k=1`; attack seed 30000+i, honest seed 40000+i; same
`nq_plan`, same sub-RNG, same outcome classes). Outputs: `results/attack-w33/{raw.csv, summary.csv, summary_variants.csv, summary_by_family.csv, log.txt, binary-sha256-prefix.txt}`.
Outcome classes: `rejected` (verifier said no), `accepted` (verifier said yes: a failure), `prover_refused` (the prover refused the bad witness: counted
separately, not as a rejection), `harness_error`, `untested`. Honest rows must be accepted (a rejected honest proof is a failure).

## Result (first run of 2026-11-14, before w34; the w34 run is in the next section)

1140 attack trials: 1140 rejected, 0 accepted, 0 prover refused, 0 harness error, 0 untested. Honest proofs: 210 of 210 accepted
(exec_single 70, rc_single 70, pair 70), 0 honest rejected. Table by family and form: `results/attack-w33/summary_by_family.csv`
(the grouping into families F1..F6 is ours, made for the report; the per-attack rows are in `summary.csv`).

## w34 additions (2026-11-14): two attacks on the new native checks, form `bundle`

Backups: `archive/backups/{main.rs,run-all.sh,family_summary.py,README.md}.bak-w34`. Old results of the run of the morning (before w34, 1140 trials) are kept in `results/attack-w33-before-w34/`
(raw.csv, summary.csv, summary_variants.csv, summary_by_family.csv; the old log.txt and raw-blake3.csv were overwritten by the new run, raw.csv has the same rows). Library change: `../pqz-plonky3-w33/README.md` section "w34 changes".
Form `bundle` (verified with `request::verify_bundle_with`: native checks, then Auth, Exec, RC proofs; Auth depth 10, n_q from the same `nq_plan`, seeds 30000+i), 20 trials per attack:
- `stream_mismatch`: honest R_RC proof of stream A and honest R_Exec proof of stream B (same shape, different data, same ctx); Auth, C_Q link honest. Expected: rejected by the stream link (`link: R_RC digest != R_Exec digest`).
- `inverted_scope`: honest prover, honest witness, statement with start > end in one of s, e, t (chosen at random, both ends inside the policy leaf); Exec and RC honest. Expected: rejected by `scope: inverted range ...`.
Each trial is verified twice: checks ON (production `verify_bundle`, rows in `raw.csv`, variant `checks_on`) and checks OFF (`NativeChecks::OFF`, test-only; rows in `raw-blake3-nochecks.csv`, merged separately into `raw_nochecks.csv`, `summary_nochecks.csv`, `summary_variants_nochecks.csv`, variant `checks_off`). The checks-off rows are NOT part of the totals. Honest bundle rows: 50 honest-only trials plus the 20 honest proofs of the attack instances (checks on), and the 20 honest proofs again with checks off.
The forms `pair` (verify_request) now also run the scope check; all old attacks stay rejected.

Result, run of 2026-11-14 (`./run-all.sh`, wall time 207 s = 3.5 min, laptop, 8 threads, other small builds at the same time at nice 19):
- Checks ON, all forms: 1180 attack trials: 1180 rejected, 0 accepted, 0 prover refused, 0 harness error. Honest: 280 of 280 accepted (exec_single 70, rc_single 70, pair 70, bundle 70).
  New attacks with checks ON: stream_mismatch 20 of 20 rejected, inverted_scope 20 of 20 rejected (error prefixes `link: ` and `scope: ` confirmed in raw.csv).
- Checks OFF (test-only switch): stream_mismatch 20 of 20 ACCEPTED, inverted_scope 20 of 20 ACCEPTED, honest bundle 20 of 20 accepted. So without the two native checks both attacks pass the three STARK verifiers: the checks, not the proofs, are what stops them.
`scripts/family_summary.py` has a new family F7 (native checks) and prints the checks-off table. `cargo test --release` in this crate: 0 tests (harness only).

## Forms and attacks ported (32 names)

- `exec_single` (14): changed_block_header, changed_record_word, dropped_record, duplicated_record, reordered_records, wrong_digest, wrong_claimed_count, wrong_claimed_sum,
  other_theta, other_ctx, other_workload_proof, flipped_proof_byte, weaker_options_above_floor, weaker_options_below_floor.
- `rc_single` (11): the same without other_theta, other_ctx, wrong_claimed_sum (R_RC has no theta, ctx or sum).
- `pair` (32 = 14 + 2 + 16): the Auth + Exec request (`verify_request`: C_Q link, then Auth, then Exec): the 14 exec names, the 2 mix attacks mix_auth_of_other_request and mix_exec_of_other_request,
  and 16 Auth names: auth_changed_{b_q, d_q, depth, omega, r_pol, scope_field, uid, v_a, v_auth}, auth_flipped_proof_byte, auth_other_request_proof, auth_scope_outside_policy,
  auth_weaker_options_below_floor, auth_wrong_leaf_index, auth_wrong_leaf_uid, auth_wrong_sibling.
  (The exact list is the `pair` rows of `results/attack-w33/summary.csv`.)

## Attacks with NO meaning in w33 (not dropped silently)

The plan says "42 attacks". That is 42 DISTINCT NAMES over the five w30 forms. 32 are ported. The other 10 exist only in the w30 chunked forms
(`exec_chunked`: 22 names, `rc_chunked`: 18 names), which need linked chunk proofs. In w33 there is ONE proof per relation over the whole stream:
no chunks, no chunk boundary values, no chunk statements, no link check between chunks.

| w30 name (chunk forms only) | what it did in w30 | why it has no meaning in w33 |
|---|---|---|
| changed_s_in | change the incoming sponge state `s_in` of chunk i (alone, and together with `s_out` of chunk i-1) | there is no chunk boundary state: the sponge state runs through ONE trace |
| changed_sum_in | change the incoming sum `sum_in` of chunk i (alone, and with `sum_out` of chunk i-1); exec_chunked only | there is no incoming boundary sum: the sum is one running total in one trace |
| changed_cnt_in | change the incoming count `cnt_in` of chunk i (alone, and with `cnt_out` of chunk i-1); exec_chunked only | there is no incoming boundary count |
| changed_hdr_first | change the first header word `hdr_first` of chunk i | there is no per-chunk first header; the first word of the stream is the public `header0` of the one proof (a change of it is a changed public statement, covered by `changed_block_header` and `wrong_digest`, rows R3 / R7) |
| changed_hdr_before | change the number of headers before chunk i (`hdr_before`); rc_chunked only | there is no per-chunk header prefix: `hdr` is carried inside one trace |
| changed_n_blocks_chunk | change the block count of one chunk | there is only one `n_blocks` for the stream (a wrong value is rejected through R7; the covering attack is `dropped_record` / `wrong_digest`) |
| dropped_chunk | remove one chunk proof from the set | there are no chunk proofs; dropping records is `dropped_record` |
| repeated_chunk | submit one chunk proof twice | same; duplicating records is `duplicated_record` |
| reordered_chunks | swap two chunk proofs | same; reordering records is `reordered_records` |
| other_workload_chunk | replace one chunk proof by one for another workload | there are no chunk proofs; replacing the whole proof is `other_workload_proof` |

Also not ported: the forms `exec_chunked` and `rc_chunked` as such (their stream-mutation and statement attacks are covered by `exec_single`, `rc_single` and `pair`), and the
`sha3` / `blake3` split of the w30 test (w33 has Blake3 only; the hash label in the CSV is `blake3`).
Not covered by this test (and not by w30 either): aggregation (none in w33), the ZK property (stage B tested hiding mode separately), side channels, malformed proofs beyond one flipped byte.

## Notes on the results (disclose)

- Rejection reasons seen: `InvalidOpeningArgument` (also for flipped bytes: Merkle `CapMismatch`), `OodEvaluationMismatch`, and `link: Exec ctx != exec_context` (60 trials: the request link).
- The other_theta attack builds the trace from AIR(theta2) and proves against the original public values; the verifier rejects.
- Not an attack in either system: the scope-inverted case (start > end) is accepted by both w30 and w33 (same statement); the R_RC digest is not linked to the R_Exec digest.
- The w30 prover panics on a scope value of 2^32 or more; the w33 `build_trace` returns an error. Both count as `prover_refused`, which does not occur in the final run.
