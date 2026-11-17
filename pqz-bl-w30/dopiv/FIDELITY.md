# DOPIV run code: fidelity notes (work15, entry 384 rules)

Paper: Zhang et al., "DOPIV: Post-Quantum Secure Identity-Based Data Outsourcing with Public Integrity Verification in Cloud Storage", IEEE TSC 15(1), 2022. Source text: `journal2/comparison-papers/baselines-main11/text/dopiv.txt` (Challenge/ProofGen/ProofVerify lines 493-535, correctness Section 4.3, Table 2 line 715); equation checked on the rendered page 340 (PDF page 7).
No number of the paper is a result or a tuning target. Table 2 is used only by `table2_integrity`/`table2_delegation` and the tests, to CHECK operation counts.

## What runs (timed stages)
- `challenge`: random c-subset V of the ell stored blocks, random binary beta in {0,1}^c (never all zero).
- `proofgen` (cloud server; the paper gives NO cost): f' = sum beta_i F_i, e = sum beta_i e_i, mask xi with signature h, f = f' + h*H6(w||v_w||theta_w||xi); Proof = (f, e, xi). 1 Hash (H6 over w, v_w, theta_w (m words), xi) and m multiplications for h*H6.
- `verify` (auditor, ProofVerify steps 1-2 only, i.e. what Table 2 counts as "integrity verification"): lambda_j = H5(ID_p||j), B = (lambda_1..lambda_n)^T; mu = B( sum beta_i H4(N_i||i) + Q_IDc f - xi H6(...) ) mod q; check Q_pro e = mu mod q and 0 < ||e|| <= c*sigma*sqrt(m) (squared, exact integers). Real mat-vec products: B v (n x n), Q_IDc f (n x m), Q_pro e (n x m), plus xi*H6 (n scalar mults).
- `verify_delegation` (separate step, as in Table 2): u_w = H2(ID_o||ID_p||w||v_w); Q_IDo theta_w == u_w mod q; and "ID_p satisfies w" reduced to: the warrant text contains ID_p and ID_o. The paper's ProofVerify begins with this validation ("validates (w,v_w,theta_w) as before"); the end-to-end ProofVerify = `verify_delegation` + `verify` (`proof_verify_full` in the lib, used in tests, not a timed stage).
- Harness: one thread, `Instant`, 3 warm-up + 30 timed runs (quick: 1 + 3), fresh random challenge each run, keys/tags/data built before timing, every result checked (`assert!(black_box(ok))`; proofgen output is verified untimed after timing).

## Parameters
Paper inputs (source line): m >= ceil(2 n log2 q) (Lemma 2, line 277; line 749); A in Z_q^{n x m}, q prime; challenge vector binary (lines 499-501); c = 350 named once, c = 50..600 in Figs. 2 and 4 (read from the figure images, findings-dopiv.md B).
OURS (the paper gives no n, m, q, ell, sigma): n = 256; q = 4294967291 (largest prime below 2^32); primary m = 16384 = ceil(2 n log2 q) (the paper's bound, met); sensitivity m = 512 (VIOLATES the bound, labelled `bound=VIOLATED` in params); ell = 600 stored blocks in the full run (350 in --quick); entry range of tags/masks +-255 (SHORT); sigma = ceil(max_i ||e_i||_2 / sqrt(m)) measured from our own tags (149-155), so the check ||sum beta_i e_i|| <= c sigma sqrt(m) is the paper's check with our sigma, not a security parameter.
Params field `bound=ok|VIOLATED`; `red=lazy` only when `--lazy` is used.

## Operation definitions
- `Hash` = SHA3-256 (the paper: "a general hash function"). H2, H4, H5 have range Z_q^n and H6 range Z_q: one logical Hash call is expanded in counter mode (SHA3-256 over domain, length-prefixed inputs, counter), output words accepted iff < q. One logical Hash with an n-word output therefore costs ceil(4n/32) = 32 SHA3-256 calls (more for long inputs: H6 hashes about 66 KB). Both numbers are counted (`opcounts.csv`: `hash_logical`, `sha3_calls`). A XOF (SHAKE256) would need about 4 times fewer permutations: this choice favours PQZ-Audit.
- `mul` = modular multiplication in Z_q: u64 product of two words < q < 2^32, reduced with `% q` (runtime q). Default `red=each`: one reduction per multiplication, accumulated in u64. `--lazy`: same multiplications, products summed in u128 and reduced once per row (about 2.5-5x faster in the smoke run). The default favours PQZ-Audit; `--lazy` favours DOPIV. Report both or say which one is used. No SIMD intrinsics, no `target-cpu=native`, no parallelism.

## Operation counts from the code (counting build, same code via a `Meter` trait; test `operation_counts_match_table2`)
`verify`, term by term (n=256, m=16384, c=350; the same holds for every n, m, c tested):
| term | counted | Table 2 term |
|---|---|---|
| Hash H5 (lambda_j) | n = 256 | n Hash |
| Hash H4 (i in V) | c = 350 | c Hash |
| Hash H6 | 1 | 1 Hash |
| mul Q_IDc f | nm = 4194304 | nm |
| mul Q_pro e | nm = 4194304 | nm |
| mul B v | n^2 = 65536 | n^2 |
| mul xi*H6 | n = 256 | n |
| total | Hash 607, mul 8454400 | (n+c+1) Hash, (n^2+2nm+n) mul = 607, 8454400: EQUAL |
Not in the formula: m = 16384 squarings for the norm check (reported separately as `norm_squarings`), vector additions (sum beta_i H4, f', e, etc., 46080 for verify), the u128 comparison. All Hash calls for i in V are made even where beta_i = 0 (the paper counts c Hash; skipping them would be a legal optimisation that favours DOPIV).
`verify_delegation`: Hash 1, mul nm = 4194304: equal to Table 2 (Hash + nm mul). 288 SHA3-256 calls (n=256).
`proofgen` (no paper formula): 1 Hash (H6), nm + m multiplications (nm only for the stand-in below), 2*m*|beta=1| element additions.
The paper does not derive n^2+2nm+n from the steps; our steps give exactly that count (B v = n^2, two n x m products = 2nm, xi*H6 = n).

## What is simplified or NOT run (read this before quoting any number)
1. **Trapdoor algorithms are NOT run**: TrapGen, NewBasisDel, SamplePre, SampleR(withBasis), KeyExtract, Proxy-oriented Signing KeyGen, Proxy-oriented TagGen as an algorithm. The paper gives no cost for them and they are outside the auditing phase. They would need Gaussian preimage sampling over a basis of dimension m = 16384, which is a separate implementation task.
2. **Planting (set-up, untimed).** Because we have no trapdoor, tags are produced by a consistent construction, not by SamplePre: random public matrices Q_pro (uniform), Q_IDc = [I_n | W] (W uniform), Q_IDo; for each block a short e_i (uniform in [-255,255]); rho_i = Q_pro e_i; eta_i = B^{-1} rho_i (B^{-1} by Gauss-Jordan mod q); the data block is solved from eta_i = H4(N_i||i) + Q_IDc F_i by choosing the last m-n entries uniformly and the first n entries by the equation. The block therefore looks uniformly random; all equations of the paper hold exactly, H4/H5 are the real hash functions. The delegation signature theta_w (short) is planted the same way (column 0 of Q_IDo set so that Q_IDo theta_w = H2(...)). Difference to the paper: tags and data are not independent (data is derived from tags); a real adversary model is out of scope here, the tests only need "honest verifies, tampered rejected".
3. **ProofGen mask.** The paper runs SamplePre(Q_IDc, T_IDc, xi, sigma) to get h with Q_IDc h = xi for random xi. We pick a short random h and set xi := Q_IDc h (one n x m mat-vec, counted). The cost of a real SamplePre is NOT included: our `proofgen` time understates the real storage-side cost (stage is storage side, not the auditor's; it favours DOPIV only in this stage).
4. Q_IDc, Q_pro, Q_IDo are taken as stored public keys; the verifier does not derive them (the paper's A R^{-1} would need an m x m inverse). B is recomputed from H5 in every `verify` (step 1 of the paper). Not cached.
5. The warrant check "ID_p satisfies w" (policy, validity period) is reduced to a substring test (not counted, negligible).
6. No Gaussian distribution anywhere: tags/masks are uniform short integers, sigma is measured. The norm check is the paper's inequality with that sigma; it is loose (aggregate of c uniform vectors is about sqrt(c) times one vector, the bound allows c times), so the norm check can pass wrongly-aggregated data, but the equation Q_pro e = mu is the one that rejects tampering (tests).
7. The verifier uses the aggregate e from the proof for the norm test (as the correctness text does: ||sum beta_i e_i||); the printed step 2 shows sum e_i without beta, read as a typo.
8. Sensitivity reading (m = 512) violates m >= ceil(2 n log2 q); with this m the hash expansion (about 10^4 SHA3 calls) dominates the multiplications. It is a timing sensitivity only; the instance has no SIS-security meaning.
9. Block count ell, names N_i = "file0/blk<i>", ID strings are ours. Randomness is a reproducible SplitMix64 stream (seed in `--seed`), not cryptographic; only the challenge and set-up use it.
10. Everything runs in memory, single thread, no network.

## Choices that favour which side
- Favours DOPIV: no SamplePre cost in proofgen; verify could skip b_i = 0 hashes (not done, so neutral); `--lazy` reduction; precomputed public keys (no derivation of Q matrices).
- Favours PQZ-Audit: default per-multiplication `%` reduction; SHA3-256 counter-mode expansion (4x permutations of a XOF); no SIMD, no native CPU flags, single thread.
- Our n, m, q are choices; the primary reading is the paper's own bound. The authors' own measurement (5.33 ms at c = 350, their machine, parameters unknown) is NOT used.

## SPEC-w16: sweeps at matched coverage (work16, entry 388)
Default behaviour (no new flag) is unchanged: same grid, same stages, same `params` strings. New flags: `--cov LIST`, `--q LIST`, `--runs-big R` (default 5), `--big-above X` (default 2000), `--params-tag TAG`, `--no-lazy`. Smoke run: `--cov 100,200 --q 1,10 --runs 3 --warmup 1 --lazy --no-lazy`.

What `--cov` runs (replaces the default grid; the old stages `challenge`, `verify_delegation` and the sensitivity reading are not run in this mode unless `--reading both` is given):
- `proofgen` and `verify` at c = cov, with the same code as the main run (n=256, q=4294967291, m=16384, one thread, fresh random challenge per run, proofgen output verified untimed, verify result checked with `black_box`).
- `verify_q` for each q in `--q`: q INDEPENDENT audits in ONE timed run. q challenges and q honest proofs are made before the timer (fresh in every run, untimed `proofgen`); the timer covers q full `verify` calls (B is recomputed from H5 in each call, as in q separate ProofVerify runs); all q results are checked true (`verify_many`, no early exit). `ms` = total for the q audits. verify_q is run at every cov point given (Exp 4b: `--cov 1000 --q 1,10,25,50,100,200`).
- Reduction: `--lazy` = lazy (u128 accumulation), no flag = default `%` per multiplication, `--lazy --no-lazy` = both, rows told apart by `red=lazy` in `params`. The default reduction favours PQZ-Audit, `--lazy` favours DOPIV; Exp plots should say which one is drawn (or draw both).
- `params` = `n=..;m=..;q=..;c=<cov>;bound=ok[;red=lazy][;audits=<Q>];runs=<R>[;<tag>]`. `audits=` is the number of audits (the modulus is `q=`). `runs=R` is the number of timed runs actually used.
- Run policy: work per run = cov (proofgen, verify) or q*cov (verify_q). If work > `--big-above` the stage uses `--runs-big` timed runs and 1 warm-up, otherwise `--runs` and `--warmup`. With the SPEC defaults (30/3 and 5/1), every cov > 2000 and every verify_q with q*cov > 2000 gets 5 timed runs.
- Operation counts (`opcounts.csv`): one counted run per cov for proofgen and verify; the harness asserts verify Hash and mul equal Table 2 at c = cov ((n+c+1) Hash, n^2+2nm+n mul).

Choice of the number of stored blocks (OURS): ell = max(cov) of the invocation. Only these ell blocks are planted (planting is untimed and costs about 5.5 ms and 98 KB per block: u32 data block 64 KB + i16 tag 32 KB), because the challenge can pick exactly these. Consequences:
- With a single cov point, ell = c: V is all stored blocks (the order and beta are random, the subset is not). With several cov points, the smaller points draw a random c-subset of the max(cov) blocks. The cost of `verify` and `proofgen` does not depend on which blocks are picked (c Hash calls, beta-weighted sums), only on c, so this does not change the timing. Say it if a plot caption says "random subset of the file".
- Memory and planting time grow with max(cov): cov 1e5 needs about 10 GB RAM and about 550 s planting (extrapolated from 200 blocks in 1.1 s). Run big points as separate invocations (one `--cov` each, different `--params-tag` or `--out`).
- The paper's cost has an ell-independent form (n+c+1 Hash, n^2+2nm+n mul); our file size does not enter `verify`. Our `proofgen` has the O(c m) aggregation term (2 m |beta=1| additions) that is not in any paper formula; it dominates at large cov (memory-bound: it reads c/2 blocks of 98 KB).

Still not run / unchanged from above: trapdoor algorithms and SamplePre (proofgen understates the real storage-side cost), Gaussian sampling, delegation verification inside `verify` (the timed `verify` is ProofVerify steps 1-2 as before), no network, no disk. `verify_q` is q sequential single-thread verifications; there is no batching across audits (the paper gives none), so verify_q is linear in q by construction.
