# CHANGES-w30: L-HCPM Groth16 batch verifier (plan F1, journal2/UPGRADE-w30-plan.md section 1)

Date 2026-11-14. This folder is a copy of `bench/pqz-bl/lhcpm` (made with rsync, `target/` not copied; `Cargo.toml` and `Cargo.lock` unchanged, the crate has no path dependencies; offline build works). `bench/pqz-bl/` was not touched.
Everything of the old crate (one-by-one verifier, stages, params strings, defaults) is unchanged. No timing claim is made here: the smoke run below was on a busy laptop.

## 1. Files changed
| File | Change |
|---|---|
| `src/batch.rs` | NEW. `draw_scalars`, `sum_u128`, `batch_verify_with_scalars` (pure, fixed scalars), `batch_verify` (draws scalars from `OsRng`), `VerifySetup::verify_batch_q(start, q)`. |
| `src/lib.rs` | one line: `pub mod batch;` |
| `src/bin/lhcpm-bench.rs` | new flag `--only-batch-q` (use with `--q`) and its block; `skip_rest` and the audit-setup guard also check the flag. Nothing else touched. |
| `src/tests.rs` | appended module `batch_w30` (10 tests). Old tests untouched. |
| `CHANGES-w30.md` | this file. |
The old verifier is the unchanged `Groth16::<Bn254>::verify_with_processed_vk` (arkworks 0.4.0), called by the old `VerifySetup::verify_q` (stage `groth16_verify_q`, about 1.76 ms per check in the paper's run).

## 2. The batch equation (exact)
Prepared vk (same `pvk` object as the one-by-one path, made once in setup by `prepare_verifying_key`): `alpha_g1_beta_g2 = e(alpha, beta)` (in GT), `gamma_g2_neg_pc = -gamma`, `delta_g2_neg_pc = -delta`, `gamma_abc_g1[0..n]`. Proofs `(A_i, B_i, C_i)`, public inputs `x_i = (x_i1..x_in)`, i = 1..k, same circuit.
- One-by-one (arkworks): `IC_i = gamma_abc_g1[0] + sum_j x_ij * gamma_abc_g1[j]`; accept iff `FE( ML(A_i,B_i) * ML(IC_i,-gamma) * ML(C_i,-delta) ) == e(alpha,beta)`.
- Batch: draw `r_1..r_k` independent uniform nonzero 128-bit integers. Accept iff
  `FE( prod_i ML(r_i*A_i, B_i) * ML(IC*, -gamma) * ML(Cc, -delta) ) == e(alpha,beta)^(R)`
  with `R = sum_i r_i` (exact integer, up to 128 + log2 k bits, not reduced), `Cc = sum_i r_i*C_i`, and
  `IC* = sum_i r_i*IC_i = (sum_i r_i)*gamma_abc_g1[0] + sum_j (sum_i r_i*x_ij)*gamma_abc_g1[j]` (the public-input work is n+1 scalar mults for the whole batch, not k*n; the scalars `sum_i r_i x_ij` are in Fr).
- Cost shape: k+2 Miller loops in ONE `multi_miller_loop`, ONE final exponentiation, one Fp12 exponentiation (exponent R), k 128-bit G1 scalar mults for `r_i*A_i`, `sum r_i C_i` (plain double-and-add for k < 32, arkworks `VariableBaseMSM::msm` for k >= 32; 32 is arkworks' own window switch, NOT tuned on timings), n+1 full scalar mults for `IC*`.
- Soundness: a batch containing an invalid proof is accepted with probability about 2^-128 (standard small-exponent test; here each `r_i` is nonzero, drawn with 128 bits). Not proved here, standard argument.
- Reuse of the pvk: identical to the one-by-one path. The `e(alpha,beta)` pairing in the pvk is used as is (GT side, raised to R), so no extra Miller loop for it.
- Same errors as one-by-one: a public-input vector of the wrong length gives `MalformedVerifyingKey` (tested); an identity result of the final exp gives `UnexpectedIdentity`. Empty batch returns Ok(true) (never used by the bench).

## 3. Validation mode
Neither path validates points inside the timer. In the bench the proofs come from `Groth16::prove` and stay in memory as `Proof<Bn254>` (never serialised and parsed), exactly as in the old stage, so there is no `Validate` mode in either timer. For proofs that DO arrive as bytes, arkworks' `deserialize_compressed` uses `Validate::Yes` (on-curve and subgroup checks) and gives the same `Proof` type; the test `batch_after_serialize_deserialize_with_validation` parses with `Validate::Yes` and then batch-verifies. The batch verifier does no extra check of its own (G1 on BN254 has cofactor 1; the G2 subgroup check is the parser's job, as for the one-by-one path). A deployment that parses with `Validate::No` would need the subgroup check for B in BOTH paths.

## 4. Timer boundary (`--only-batch-q`)
For each k in `--q`: setup (untimed): circuit setup, `prepare_verifying_key`, `max(8, max k)` proofs with their own 3 public inputs (same circuit as the old `groth16_verify_q`, 4-round chain). An untimed guard asserts the batch verifier rejects a tampered input set. Then `warmup + runs` rounds. In round i, window = proofs `(i*k + j) mod len`, j = 0..k; BOTH forms are timed on that SAME window, back to back, order alternating (even rounds one-by-one first, odd rounds batch first) to cancel drift/cache order.
- Timed, one-by-one (`groth16_verify_q`): the call `verify_q(start, k)`: k times `verify_with_processed_vk` (public-input MSM, G2 prepare, 3-pair Miller loop, final exp, compare), on in-memory proofs.
- Timed, batch (`groth16_verify_batch_q`): the call `verify_batch_q(start, k)`: building the k (proof, input) reference pairs, the `OsRng` draw of 16k bytes (inside the timer: a verifier needs fresh randomness per call), scalar combinations, `r_i*A_i` and normalisation, `sum r_i*C_i`, `IC*`, G2 prepare of every B_i, one (k+2)-pair multi-Miller loop, one final exp, one Fp12 pow, compare.
- Not timed: setup, prepared vk, proof generation, parsing/validation (none, see 3), the checks (after the timer: one-by-one count == k, batch == true, both asserted every round including warm-up).
- Rows: `baseline,stage,params,run,ms`, raw per-run, same CSV writer as before. Stage names `groth16_verify_q` (params string identical to the old one: `public_inputs=3;q=K`, plus `;TAG` from `--params-tag`) and `groth16_verify_batch_q` (same params string). Warm-up and runs are the same for every k (`--runs-big` is not used in this mode). Both rows of a round share the run index.
- One-by-one rows are the same operation as old `groth16_verify_q`; k = 1 batch is a batch of one proof (it pays the extra random scalar and GT pow, so it is not expected to beat the old verifier; the plan says the old verifier is the comparator at k = 1).

## 5. RNG source
`rand::rngs::OsRng` (rand 0.8.5, getrandom(2) syscall), one `fill_bytes` of 16k bytes per batch call, split into little-endian u128 scalars; a zero scalar is redrawn (probability 2^-128). No seeded or reused RNG, no `StdRng`.

## 6. Tests (all `cargo test --release --offline`, in `src/tests.rs`, module `batch_w30`)
Result: 26 passed, 0 failed, 1 ignored (`breakdown`, old, ignored by design). 16 old + 10 new.
1. `batch_accepts_k_1_2_5_and_40_honest` (also k = 5 with 13 public inputs; k = 40 uses the Pippenger branch)
2. `batch_rejects_any_changed_proof_element`: A, B, C changed (one at a time) in every position, k = 1, 2, 5; plus k = 40 with C of the last proof changed
3. `batch_rejects_any_changed_public_input`: every input of every proof, k = 1, 2, 5
4. `batch_rejects_swapped_proofs_with_mismatched_inputs`: k = 2 swap; k = 5 swap of proofs 1 and 3; swapping proofs together with inputs is accepted
5. `batch_rejects_proof_from_another_circuit_key`
6. `batch_matches_one_by_one_with_fixed_scalars` (edge scalars 1, 2^128-1, 2^100)
7. `batch_edge_cases` (empty batch, wrong input count gives an error, same as one-by-one)
8. `scalars_are_nonzero_128bit_and_sum_is_exact` (also carry across limbs)
9. `batch_after_serialize_deserialize_with_validation`
10. `verify_batch_q_window_matches_verify_q` (windows incl. wrap-around)
Smoke run (laptop, other builds running, NO timing claim): `lhcpm-bench --only-batch-q --q 1,2,10 --runs 1 --warmup 0 --params-tag smoke` ran, 6 CSV rows, all checks passed. Output kept only in the session scratchpad, not in this folder.

## 7. Cloud command lines (same pinning as w26 `lhcpm-k`: `taskset -c <physical core>` of chain A, one process alone on the machine)
Build: `cd bench/pqz-bl-w30/lhcpm && cargo build --release` (Cargo.lock kept; needs the same vendored/online crates as pqz-bl/lhcpm).
Batch + one-by-one, 30 runs, 3 warm-up:
`taskset -c $PA ./target/release/lhcpm-bench --only-batch-q --q 1,2,3,5,10,100,1000 --params-tag w30 --runs 30 --warmup 3 --out <JOB_DIR>`
Smoke before it (like w26): `taskset -c $PA ./target/release/lhcpm-bench --only-batch-q --q 10 --runs 1 --warmup 0 --params-tag smoke --out <SMOKE_DIR>`
Cost estimate: about k x 1.8 ms per one-by-one round at k = 1000 (about 2 s) plus the batch round; 33 rounds per k, so a few minutes for the whole grid.
Note: the old `lhcpm-k` recipe passes `--big-above 100000`; it has no effect here.

## 8. Unclear or open
- Whether the paper's L-HCPM would batch at all (not checked here; the old stage verifies each proof separately). This is the baseline given the most favourable standard lever, like the Blake3 lever for the others; report it as such.
- The `sum r_i C_i` MSM threshold (32) is an a-priori choice; arkworks' MSM treats scalars as 254-bit although ours are 128-bit (this is conservative against the batch form). A dedicated 128-bit Pippenger or a GLV mult could make batch faster; not done.
- Proof pool: for k = 1000 every round uses the same 1000 proofs (pool size = max(8, max k)); for small k windows move. Public-input count is 3 only (as `groth16_verify_q`); a 13-input batch is tested for correctness but not benched.
- The `R`-power uses generic Fp12 `pow` (not cyclotomic squarings); a faster GT exponentiation would favour batch slightly.
- Claim rule of the plan (verification cell at 2 checks needs PQZ below BOTH forms) is applied after the cloud data, not here.

## 9. A2 (Addendum A, 2026-11-14): mode `--only-setup` (timing of the one-off key generation)
New file `src/setup_w30.rs` (`pub mod setup_w30;` in `src/lib.rs`), new arm and early-return block in `src/bin/lhcpm-bench.rs`; every other mode is unchanged (the new code is reached only with `--only-setup`; the diff against the section-8 sources touches the argument parser only by adding the flag and by remembering whether `--runs` / `--warmup` were given).
- Usage: `lhcpm-bench --only-setup [--runs N] [--warmup W] --params-tag T --out DIR` (defaults 5 runs, 1 warm-up; `--threads` must be 1; no other mode flag allowed, else the program stops before doing anything).
- Stage `groth16_setup_mint`: the timer wraps ONLY `Groth16::<Bn254>::circuit_specific_setup` of the Mint stand-in circuit. The circuit instance is the one `ProveSetup::new(2676, ..)` uses for its keys (892 rounds, 2,676 constraints, 3 public inputs; asserted before each timed call, outside the timer). A fresh RNG per run. After each timed run (untimed): a proof made with the new keys verifies, a changed public input is rejected. Single thread (arkworks =0.4.0 without the `parallel` feature).
- Stage `bfv_keygen_regulator`: `Params::new(4096, 28, 3.2).keygen` (pk_G, sk_G of the audit stand-in, the call `AuditCtx::setup` makes); timer = that call only; untimed check: encrypt then decrypt returns the message. TrapGen (A_G, T_G) is NOT implemented in this crate and is NOT timed (the paper text gives about 3.4 s; see FIDELITY.md).
- `DIR/raw.csv`: columns `stage,run,secs,pk_bytes,vk_bytes` (warm-up rounds are not written). `pk_bytes` / `vk_bytes` of the Groth16 row = ark-serialize `serialized_size(Compress::Yes)` of ProvingKey / VerifyingKey (laptop: 560,016 B and 360 B); of the BFV row: pk = 2 polynomials x 2 RNS limbs x 4096 x 8 B = 131,072 B, vk = `NA`.
- `DIR/meta.json` (new for this mode; the other modes write no meta.json): mode, runs, warmup, params_tag, threads, stage descriptions, what is not measured, the check, the column list.
- Tests (all in `cargo test --release --offline`): 5 unit tests in `src/tests.rs::setup_w30_tests` (circuit = the prove-stage circuit, key shapes equal; keys verify and mismatched keys fail; sizes = serialised lengths, vk = 360 B; rows and CSV format; meta.json) and 2 command-line tests in `tests/setup_cli.rs` (the real binary: raw.csv/meta.json written, 1 warm-up not written, no raw_runs.csv; `--threads 2` and a second mode flag are refused). Result: 31 passed, 1 ignored (the old 26 + 5 new) in the library, 2 passed in `setup_cli`; 0 failed.
- Laptop smoke (format check only, NOT data): `--only-setup --runs 2 --params-tag smoke --out results/smoke-setup` -> 4 rows; Groth16 setup about 144 ms, BFV keygen about 0.49 ms on this laptop.
- Release binary `target/release/lhcpm-bench` sha256 (laptop build, after this change): `50e206bdd19ddc91119334c0d7618323b5a562900e10422d6aa69b76952da443`.
- Cloud use: `cloud-w30/extra_A.sh` (job `lhcpm-setup`, `--runs 5 --warmup 1`, one pinned core).
