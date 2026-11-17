# pqz-bl-par: parallel (rayon) copies of the DOPIV, DART and Dong et al. baselines

Date: 2026-11-15. Purpose: a same-environment comparison. PQZ-Audit proves on all cores; the three baselines of
`bench/pqz-bl*` are single-threaded. These copies run the work that the published algorithm leaves independent on
a rayon pool, so both sides can use all cores. Same algorithm, same parameters, same outputs, same CLI and CSV format.

Sources were not touched: `bench/pqz-bl/{dopiv,dart,dong}` and `bench/pqz-bl-w30/dopiv` (read-only). Only the copies were edited.
No other crate or kit was changed. No git commit.

| crate (folder) | package / lib | binary | copied from |
|---|---|---|---|
| `pqz-bl-par/dopiv` | `pqz-bl-dopiv-par` / `pqz_bl_dopiv_par` | `dopiv-bench-par` | `pqz-bl-w30/dopiv` (superset of `pqz-bl/dopiv`, see point 2 below) |
| `pqz-bl-par/dart`  | `pqz-bl-dart-par` / `pqz_bl_dart_par`   | `dart-bench-par`  | `pqz-bl/dart` |
| `pqz-bl-par/dong`  | `pqz-bl-dong-par` / `pqz_bl_dong_par`   | `dong-bench-par`  | `pqz-bl/dong` |

Each crate is stand-alone (own `[workspace]`, own `Cargo.lock` with rayon 1.12 / rayon-core 1.13 added; builds with `--locked --offline`).
Added dependency: `rayon = "1.12"`. Nothing else changed in the dependency list.

Threads: rayon default = all logical CPUs; `RAYON_NUM_THREADS=k` overrides. Each binary prints `rayon threads = k` on stderr at start
(stdout and CSV files are unchanged).

## 1. What was parallelised

### DOPIV (`dopiv/src/lib.rs`)
Parallel code runs when the meter is `NoMeter` (the timing path, `Meter::PAR = true`). With the `Counts` meter the ORIGINAL sequential code
runs, so operation counts are those of the original and it is the reference in the tests.
- Matrix-vector products `B*x`, `Q_IDc*x`, `Q_pro*x` (`matvec`): rows in parallel.
- `B = (H5(ID_p||j))_j`: the n hashes H5 (one per row) in parallel; H4 hashes for the c challenged blocks in parallel (fold/reduce).
- ProofGen: aggregation of f' and e over the challenged blocks, by column range (each task owns a range of output coefficients, sums over the
  c blocks). The draw of h, xi, the `xi = ...` matvec and the final loop stay as in the original.
- ProofVerify: the independent parts run concurrently (`rayon::join`): H5 rows, H4 fold, H6, the `Q_IDc*f` product and the `Q_pro*e` product;
  then `mu = B*v`, the equality check and the norm check.
- `verify_many` (q independent audits, stage `verify_q`): audits in parallel, results ANDed (no early exit, as in the original).
- Untimed setup: the H5 rows, and the planting of the tags (RNG draws first, sequentially in the original order; matvec_setup and H4 per block in parallel).

### DART (`dart/src/lib.rs`)
The original sequential functions are kept verbatim as `*_seq` (`challenge_set_seq`, `expand_product_seq`, `msm_g1_seq`, `msm_g2_seq`,
`setup_with_trapdoor_seq`, `prove_nozk_seq`, `verify_nozk_seq`, `prove_fast_seq`, `verify_q_seq`) and are the reference in the tests.
The functions with the original names are the parallel versions.
- `challenge_set`: the z pairs (PRP_k1(l), PRG_k2(l)) in parallel.
- Eq. 4 (`gamma_a`): the z*N commitments (one SHA-512 each) in parallel, per-task partial sums of Fr added at the end.
- `c_G(tau_i)` for the z challenged chunks in parallel.
- Multi-exponentiations (`eta_tau` = prod phi_k^{beta_k} in G1, `H_Lambda` in G2, `Omega_f`, Eq. 9 product): every term is an independent
  exponentiation; terms in parallel, partial sums added (group addition is associative; the result is the same point).
- `expand_product` (coefficients of prod (c_k + x)): the original is a schoolbook running chain over the factors. The product is associative, so the
  factors are split in halves (leaves of 256 factors use the original schoolbook), the two polynomials are multiplied (schoolbook, output coefficients in parallel).
  Same work order (n^2/2), exact field arithmetic, identical coefficients.
- Independent branches run concurrently with `rayon::join`: in ProofGen, Eq. 4 and the chain c_tau -> beta -> eta; in ProofVerify, e(S_auth,h), the
  chain H_Lambda -> e(eta,H_Lambda), `Omega_f` and the Eq. 9 product (the two pairings run on different threads).
- `verify_q`: the q independent audits in parallel (each is the full `verify_nozk`, no batching, no early exit).
- Untimed setup (`setup_with_trapdoor`): RNG draws (chi, zeta, s_v, data bytes) sequential in the original order; the exponentiations rho, phi1, phi2 and the per-chunk
  commitments / tau_i / c_tau_i in parallel. `prove_fast` (untimed verifier inputs): commitments in parallel.

### Dong et al. (`dong/src/lib.rs`)
Original functions kept as `setup_seq`, `challenge_seq`, `proof_gen_seq`, `proof_verify_seq`, `make_audits_seq`, `proof_verify_many_seq` (they use the
counted primitives; the paper-formula tests use them). The original names are the parallel versions.
- `proof_gen`: mu_j = sum_l v_l m_{k_l,j} and T = prod_l sigma_{k_l}^{v_l}: the c terms in parallel (fold/reduce over l).
- `proof_verify` (eq. 1): the c hashes to G1 plus c exponentiations of prod_l H1(fname||t||k_l)^{v_l} in parallel; the three pairings run
  concurrently (`e(T,g)`, `e(H1(ID,t),Y)`, and `e(x,R)` after the products are formed); then E_GT and M_GT as in the original.
- `proof_verify_many` (`verify_q`): the q audits in parallel, ANDed.
- Untimed: `setup` (n tags: hash to G1 and s+1 exponentiations each) and `make_audits` (nonces drawn first, then challenges and proofs per audit in parallel);
  `challenge`: the c SHA-512 values v_l in parallel.

## 2. What stays sequential, and why
| item | crate | why |
|---|---|---|
| a single hash call (H6 over one long message; H1/H4 on one input) | DOPIV | a hash is a sponge/Merkle-Damgard chain over one message |
| RNG streams in the untimed setup (rejection-sampled scalars, data bytes, planted-tag draws) | all | one stream, order defines the data; drawn first, in the original order, so the stream position and the data are identical |
| Fisher-Yates challenge draw (each swap consumes the next ChaCha word) | DOPIV, Dong | a chain over one PRNG stream |
| `mu = B*v` after B and v are known; norm check ||e|| | DOPIV | data dependency / O(m) pass, small |
| the 4 Feistel rounds of one PRP evaluation (and cycle walking) | DART | each round needs the previous output (the z evaluations ARE parallel) |
| `S_auth` product of c_tau + zeta over all D chunks (setup, untimed) | DART | O(D) field multiplications in one running product; negligible, untimed |
| the final `mu_j` / `T` combination (reduce) and the equality / pairing comparison | all | O(threads) work |
| the original schoolbook recurrence inside each 256-factor leaf of `expand_product` | DART | the chain of the scheme's expansion; only above the leaf is it re-associated (see above) |
| `Counts`-meter path | DOPIV | kept sequential on purpose: it is the operation-count reference (Table 2 counts) |

The scheme is not changed anywhere. Re-association (sums, products, polynomial products) is over exact arithmetic (Fr, u64/i64 sums, group
addition), so results are exactly equal; only the representation of a projective point can differ (so points are compared in compressed form).

## 3. Differences visible to the harness (read these)
1. DART `ops.csv`: `fr_mul` / `fr_add` of the expansion are reported as the LOGICAL counts of the original schoolbook loop
   (n(n+1)/2 + n and n(n+1)/2), so ops.csv is comparable with the original; the physical work of the divide-and-conquer expansion differs in lower-order terms.
   All other DART counts equal the original for the same keys (tested). Note that the original binary seeds its keys from the clock, so `sha256`
   (PRP cycle walking) varies between any two runs, also of the original binary; this is not a change.
2. DOPIV: the copy is based on `pqz-bl-w30/dopiv` (adds `--hash sha3|blake3`; Exp 4 needs `--hash blake3`). Without `--hash`, the behaviour and the CSV columns
   are those of `pqz-bl/dopiv` (the trailing `hash` column of w30 is written ONLY when `--hash` is given). Test `sha3_run_digest_is_stable` equals the digest recorded
   from the original crate. So one `dopiv-bench-par` serves Exp 1 (default sha3) and Exp 4 (`--hash blake3`).
3. stderr gets one extra line: `rayon threads = k (...)`. stdout / CSV / `--out` files: same names, same columns.

## 4. Tests (all run with `cargo test --release --offline` in each crate folder; all pass)
Byte-identity tests compare the sequential reference (original code, kept in the crate) with the parallel code for fixed seeds, in pools of 1, 2 and 7 threads.
| crate | result | new test file | what it checks |
|---|---|---|---|
| dopiv | 27 passed (16 original + 7 w30 + 4 new) | `tests/par_equiv.rs` | setup digest is thread-count independent; proof (f, e, xi) bytes, RNG stream position and verify result identical to the `Counts` (sequential) path for sha3 and blake3, lazy and eager, 4 values of c; tampered f/e/xi rejected by both; `verify_many`; delegation check; Table 2 counts still exact |
| dart  | 14 passed (10 original + 4 new) | `tests/par_equiv.rs` | `setup_with_trapdoor` (rho, phi1, phi2, S_auth, h, blocks, tau, c_tau, trapdoor, RNG position; z_max > D too); `challenge_set` (incl. Ops); `expand_product` (n = 0..1500, around leaf and parallel thresholds; coefficients and logical Ops); `prove_nozk` (tau, eta, gamma_a bytes, Ops), `verify_nozk` (verdict, Ops), `prove_fast`; tampered tau / gamma_a; `verify_q` incl. one bad audit |
| dong  | 12 passed (7 original + 2 new in-lib + 3 CLI) | in `src/lib.rs` (`par_identical_to_seq`, `par_audits_identical_to_seq`) | setup (data, tags, u, Y, R, RNG position), challenge, `proof_gen` (mu, T compressed), `proof_verify`, `make_audits`, `proof_verify_many`; tampered mu / T rejected. The paper-formula operation-count tests run on the `*_seq` functions |

## 5. Laptop smoke (engineering only, not for the paper)
Machine: the laptop (22 logical CPUs, hybrid; many other things running; no pinning). Small commands, 5 runs, 1 warm-up, median ms. orig = `pqz-bl/*/target/release/*-bench`.
par1 = `RAYON_NUM_THREADS=1`, parall = default (22 threads).

| baseline, command | stage | orig | par, 1 thread | par, 22 threads |
|---|---|---|---|---|
| Dong `--cov 100,500 --n-factor 2` | proofgen c=100 / c=500 | 29.7 / 128.2 | 24.6 / 133.2 | 9.0 / 19.1 |
| | verify c=100 / c=500 | 36.0 / 184.1 | 36.5 / 170.8 | 8.8 / 21.7 |
| DART `--cov 1000,5000 --file-records 100000` | proofgen z=5 / z=25 | 146.0 / 133.3 | 129.1 / 117.4 | 15.9 / 15.4 |
| | verify z=5 / z=25 | 14.8 / 33.8 | 11.7 / 34.4 | 3.4 / 5.3 |
| DOPIV `--cov 100,200` (n=256, m=16384) | proofgen c=100 / c=200 | 10.6 / 11.6 | 10.7 / 10.5 | 1.8 / 2.0 |
| | verify c=100 / c=200 | 23.8 / 24.1 | 22.1 / 25.0 | 2.5 / 2.5 |

Whole-process wall time (setup included): Dong 5.80 s / 5.80 s / 0.88 s; DART 2.30 / 2.12 / 0.29 s; DOPIV 2.01 / 1.97 / 0.51 s (orig / par1 / parall).
Reading: at 1 thread the par binaries are equal to the originals within run-to-run noise (about +-15 %, some cells faster, none clearly slower), so the parallel code costs nothing when
it has one thread. With 22 threads the laptop (hybrid cores, not 22 equal cores) gives about 3x to 10x. Do NOT quote any of these numbers in the paper; the cloud run decides.
CSV files: headers and keys identical to the originals (`raw_runs.csv`, `ops.csv`, `opcounts.csv`); DOPIV `opcounts.csv` identical to the original byte for byte.

## 6. Exact commands on the cloud box (all cores, no `taskset`, one process at a time)
Upload the three folders next to the old crates so the layout is `$BASE/pqz-bl-par/{dopiv,dart,dong}`, build on the instance:
```
for d in dopiv dart dong; do ( cd $BASE/pqz-bl-par/$d && cargo build --release --locked ) ; done
# binaries: $BASE/pqz-bl-par/dopiv/target/release/dopiv-bench-par   .../dart/target/release/dart-bench-par   .../dong/target/release/dong-bench-par
```
Do not set `RAYON_NUM_THREADS` (default = all vCPUs). Do not use `taskset`. Run one job at a time so each gets the whole machine (the old kits ran 3-4 pinned
workers in parallel; that must NOT be reused for the -par binaries). Record `rayon threads = ...` from each stderr.

### Exp 1 (from `bench/cloud-w36c/steps_C.sh`, step C1; same flags and job names plus a `-par` suffix; RW = `--runs 30 --warmup 3`)
`$RES` = results folder. These replace the `JOBS+=` lines 135-139 and `jobrun` (which pins to a CPU) in a new `-par` step; each job
is run sequentially, no pool:
```
RW="--runs 30 --warmup 3"; E1COV=100,200,500,1000,2000,5000,10000
D=$BASE/pqz-bl-par
( cd $D/dong  && ./target/release/dong-bench-par  --cov 100,200,500,1000,2000,5000 --params-tag e1 $RW --out $RES/dong-e1-par        > $RES/dong-e1-par/stdout.txt  2> $RES/dong-e1-par/stderr.txt )
( cd $D/dong  && ./target/release/dong-bench-par  --cov 10000 --n-factor 2 --params-tag e1 $RW --out $RES/dong-e1-c10000-par         > $RES/dong-e1-c10000-par/stdout.txt 2> $RES/dong-e1-c10000-par/stderr.txt )
( cd $D/dart  && ./target/release/dart-bench-par  --cov $E1COV --file-records-list 10000,20000,50000,100000,200000,500000,1000000 --params-tag e1 $RW --out $RES/dart-e1-par   > $RES/dart-e1-par/stdout.txt  2> $RES/dart-e1-par/stderr.txt )
( cd $D/dopiv && ./target/release/dopiv-bench-par --cov $E1COV --params-tag e1 $RW --out $RES/dopiv-e1-par                         > $RES/dopiv-e1-par/stdout.txt 2> $RES/dopiv-e1-par/stderr.txt )
( cd $D/dopiv && ./target/release/dopiv-bench-par --cov $E1COV --lazy --params-tag e1 $RW --out $RES/dopiv-lazy-e1-par             > $RES/dopiv-lazy-e1-par/stdout.txt 2> $RES/dopiv-lazy-e1-par/stderr.txt )
```
(`mkdir -p` each `$RES/<job>` first; write `time.txt` / `exit_code.txt` as `jobrun` does, using `timed` without `taskset`.) With `--smoke` kits: `--quick` instead of the
flags as in `SMQ`, and `RW="--runs 2 --warmup 0"`.

### Exp 4 p2 (from `bench/cloud-w36a/remote_w36a.sh` steps p2-dopiv, p2-dart, p2-dong and `dong_pool.sh`)
`job_w36a.sh` takes CPUS `-` = no taskset. Variables as in `remote_w36a.sh`: `P2_COVS=1000,2000,5000,10000,20000,50000,100000`, `P2_RUNS=30`, `P2_WARM=3`,
`P2_FILE_RECORDS=1000000`; `$est` = the step's time estimate (the -par runs should be faster; keep the old timeout `est*3` as a ceiling).
```
# DOPIV (blake3, as the w30 Exp 4 step)
bash $BASE/job_w36a.sh $OUT/p2 dopiv-blake3-e4a-par pqz-bl-par/dopiv - $(( est * 3 )) any ./target/release/dopiv-bench-par --cov "$P2_COVS" --params-tag e4a --runs "$P2_RUNS" --warmup "$P2_WARM" --hash blake3 --out @JOB@
# DART
bash $BASE/job_w36a.sh $OUT/p2 dart-e4a-par pqz-bl-par/dart - $(( est * 3 )) any ./target/release/dart-bench-par --cov "$P2_COVS" --file-records "$P2_FILE_RECORDS" --params-tag e4a --runs "$P2_RUNS" --warmup "$P2_WARM" --out @JOB@
# Dong: ONE process at a time using all cores (NOT the 3-worker pinned pool of dong_pool.sh). One job per cov, as dong_pool.sh does, so the data of each cov is the same as before
for c in ${P2_COVS//,/ }; do
  bash $BASE/job_w36a.sh $OUT/p2 dong-e4a-par-c$c pqz-bl-par/dong - 5400 any ./target/release/dong-bench-par --cov "$c" --n-factor 2 --params-tag e4a --runs "${P2_RUNS:-30}" --warmup "${P2_WARM:-3}" --out @JOB@
done
```
Do not use `${PHYS[...]}` pins and do not start the three Dong workers at once.
`--q` stage `verify_q` (if a step needs it) works the same way: add `--q ...` to the same commands; `proof_verify_many` / `verify_q` / `verify_many` are parallel across audits.

## 7. "Favours whom" (disclose in the paper)
- Favours the baselines (compared with the old single-thread numbers): they now use all cores. For Dong, DART and DOPIV the verifier is also parallelised (3 pairings on
  3 threads for Dong; 2 pairings on 2 threads for DART; independent hashes and matrix products for DOPIV). The papers' cost models and real on-chain
  verifiers are single-threaded, so a "verify" time of the -par binaries is NOT what a smart contract would pay. If the paper compares verifier time on all cores, say so.
- Favours PQZ-Audit (limits of what could be parallelised, the same limits the original schemes have): the chains listed in section 2 stay sequential (single hash calls, Fisher-Yates
  draw, `mu = B*v`, the PRP rounds). Small sizes (about 10 ms for DOPIV at c = 100..200) leave little to parallelise, and the pool start-up and join overheads weigh
  more there; the speed-up grows with c / z / q.
- Not done, and it would help the baselines: no change of algorithm or implementation quality. Multi-exponentiations are still one scalar multiplication per term (no Pippenger / windowed
  multi-scalar multiplication) in the original and in the copy, and the pairings are the full `bls12_381` pairing (no shared final exponentiation). If PQZ-Audit's prover
  uses such optimisations, state that the baselines have none (it favours PQZ-Audit); if it does not, the two sides are even.
- Equal effort: every loop whose iterations are independent in the published algorithm was parallelised with rayon `par_iter` / `join`, nothing was hand-tuned per core count
  (fixed minimum task sizes in code, no thread-count switches), no SIMD or assembly added.
- The threads are the logical CPUs (32 vCPUs on the cloud box = 16 physical cores with SMT, if so configured). Say "32 vCPUs", not "32 cores", if that is what it is.
- The timed region is unchanged: the same operations are inside the timers as in the original binaries; the untimed setup is only faster.
- LHCPM and the other baselines were not touched (not asked).

## 8. Open points
- DOPIV differs from `pqz-bl/dopiv` by the w30 `--hash` option (default behaviour proven identical). If the lead wants a crate strictly from `pqz-bl/dopiv`, Exp 4 would still need the w30 one.
- `Cargo.lock` of each copy is new (rayon added); the cloud box needs the crates from the local cargo cache or network for `cargo build --locked`
  (rayon 1.12.0, rayon-core 1.13.0, crossbeam-*, either, etc.). The old kits' build step vendors nothing, so check the box has crates.io access, or vendor `~/.cargo/registry`.
- The time estimates (`est`) of the Exp 4 steps were set for single-thread runs and are upper bounds now.
- Laptop numbers are not evidence; run the -par binaries on the cloud box first with the smoke settings (`--quick` / `--runs 2 --warmup 0`) to confirm the build and the thread count.
