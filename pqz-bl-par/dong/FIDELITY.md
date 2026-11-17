# FIDELITY: Dong et al. (IEEE TNSM 2026) as RUN code

Paper: "Blockchain-Assisted Integrity Auditing Scheme With Key-Exposure Resistance in Cloud Storage Setting", Dong et al., IEEE TNSM vol. 23, 2026 (printed p. 5144-5145 for the scheme; Sec. VI.B (3) and Table V for cost; Sec. VI.D for the experiment setting).
Source text: `journal2/comparison-papers/baselines-main11/text/dong.txt`; the scheme page was also rendered to PNG and read (PDF pages 7-8) because the pdftotext equations are garbled. Line numbers below are lines of `dong.txt`.
No number from the paper is used as a result or a tuning target. The paper's cost formulas are used only in the test `op_counts_vs_paper_formula`.

## What runs (timed stages)
- `proofgen` (CSP): `proof_gen` = ProofGen, step 6: `mu_j = sum_l v_l * m_{k_l,j}` (j = 1..s) and `T = prod_l sigma_{k_l}^{v_l}`. Real Z_q arithmetic (BLS12-381 scalar field), real G1 scalar multiplications and additions.
- `verify` (auditor): `proof_verify` = ProofVerify equation (1): `e(T,g) = e(H1(ID,t),Y)^{sum v_l} * e( prod_l H1(fname||t||k_l)^{v_l} * prod_j u_j^{mu_j}, R )`. Real hash-to-G1 (H1, c+1 calls), 3 full pairings, one Gt exponentiation, one Gt multiplication; the result (true/false) is checked.
- `Challenge(tt)` is implemented (`challenge`) and called with a fresh random nonce before every run, but it is NOT inside the timed stage (the paper runs it in the smart contract and its own cost formulas do not include it). pi = partial Fisher-Yates driven by a ChaCha20 stream keyed with SHA-256("pi"||tt); f = SHA-512("f"||tt||l) reduced mod q. Both are OUR choice of PRP/PRF (the paper only says "pseudorandom permutation / function"). Indices sorted (k_1 < ... < k_c) as in the paper.
- Untimed set-up code (not part of any stage): Setup (x, Y = g^x, u_1..u_s random in G), KeyUpdate (sk_{ID,t} = H1(ID,t)^x, with the paper's check e(g,sk) = e(Y,H1(ID,t))), AuthGen (`sigma_i = sk_{ID,t} * (H1(fname||t||i) * prod_j u_j^{m_ij})^r`, R = g^r). Tags are made for ALL n blocks, so every fresh challenge hits real tags.

## What does NOT run
- The identity-based signature S_Sig on the file tag tau and its verification (step 4c and the first check of step 7). The paper itself ignores it in its cost ("we ignore the computational overhead of signature generation", line 957-958). Favours Dong (a slice of the real verification is missing).
- The blockchain: recording proof / result, smart-contract execution, gas. In-memory only (SPEC).
- Extract is replaced by KeyUpdate at t = 1 (the same formula with H1(ID,t)).
- No network, no disk, one thread.

## Parameters
| name | value | source |
|---|---|---|
| s (sectors per block) | 3 | paper, line 1059 ("3 sectors") |
| c (challenged blocks) | 10,20,...,100 | paper, lines 1063-1066 ("number of challenged blocks ranging from 10 to 100") |
| c extra points | 350, 1000, marked `extra=1` in params | OURS (not in the paper) |
| n (blocks in file) | 10 * c | paper line 1063 ("always select 10% of the data blocks") |
| sector values m_ij | random non-zero scalars of BLS12-381 Fr (255 bit) | OURS; paper has 160-bit sectors in Z_q* |
| v_l (challenge coefficients) | SHA-512-derived scalars in Fr | OURS (PRF choice) |
| ID, fname, t | "DO-identity", "file-0001", 1 | OURS |
| hash H1 | RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_ with DST `PQZ-BL-DONG-V01-...`, input encoding tag byte + length-prefixed strings + LE integers | OURS; paper: "H1 is a hash function from {0,1}* to G" (line 469), no construction given |
| key/data RNG | ChaCha20, fixed seed (keys and data are the same on every run of the binary; challenges differ per run) | OURS |
| `--quick` | c in {10, 50}, 3 runs, 1 warm-up | SPEC |

## Curve and group mapping (Type A symmetric -> BLS12-381 asymmetric)
The paper uses a Type A symmetric pairing e: G x G -> G_T with |q| = 160 bit, |G| = 512 bit (JPBC, line 1056-1058), where all elements live in one group. BLS12-381 has e: G1 x G2 -> Gt (|r| = 255 bit, G1 point 381-bit field). Mapping used:
- G1: everything that is hashed, tagged, or exponentiated: H1 outputs, u_1..u_s, sk_{ID,t}, sigma_i, T, and the verifier's product. Hence ALL c+s group exponentiations (E_G), ALL group multiplications (M_G) and ALL hash-to-group calls of the formulas are in G1, the cheaper of the two source groups.
- G2: only g, Y = g^x and R = g^r, which appear as the second pairing argument in the three pairings e(T,g), e(H1(ID,t),Y), e(X,R). No arithmetic is done in G2 inside the timed stages.
- Gt: the pairing results; E_GT and M_GT are Gt scalar multiplication / Gt multiplication.
Effect: this placement favours Dong (no G2 arithmetic, cheap-group hashing). The alternative (u_j or H1 in G2) would make every E_G/M_G/H several times dearer. The curve itself (BLS12-381 instead of Type A, 160/512 bit) is a choice forced by the common setting; we did not measure how it compares with Type A on this machine, so we make no claim about which way it moves the numbers. Against Dong: 255-bit exponents instead of 160-bit ones (a G1 scalar multiplication costs more than a 160-bit one would). Our scalar multiplication is the crate's constant-time double-and-add, with no windowing and no multi-exponentiation (Straus/Pippenger); a tuned implementation of `prod H^v` would be faster. We do not use such tricks, because the paper does not describe them.

## Operation counts versus the paper's formulas (test `op_counts_vs_paper_formula`, c = 10, s = 3)
Every Z_q / G1 / Gt / pairing / hash operation of the two stages goes through counting wrappers (`prim::*`; counting exists only under `cfg(test)`, so the timed binary has no counting overhead). Result, copied from the test output:

ProofGen = s*c*Mz + s*(c-1)*Az + c*EG + (c-1)*MG

| term | paper formula | counted | agree |
|---|---|---|---|
| M_z | s*c = 30 | 30 | yes |
| A_z | s*(c-1) = 27 | 27 | yes |
| E_G | c = 10 | 10 | yes |
| M_G | c-1 = 9 | 9 | yes |

Verify = 3P + (c+1)H + (c-1)Az + (c+s)EG + (c+s-1)MG + EGT + MGT

| term | paper formula | counted | agree |
|---|---|---|---|
| P | 3 | 3 | yes |
| H | c+1 = 11 | 11 | yes |
| A_z | c-1 = 9 | 9 | yes |
| E_G | c+s = 13 | 13 | yes |
| M_G | c+s-1 = 12 | 12 | yes |
| E_GT | 1 | 1 | yes |
| M_GT | 1 | 1 | yes |

All terms agree, and no other counted operation occurs (the test compares the whole counter struct, so any extra counted operation would fail it). How the terms arise: the first term of each sum/product is taken without an operation (hence c-1 and s-1); `prod_l H^{v_l}` has c-1 M_G, `prod_j u_j^{mu_j}` has s-1, combining the two has 1, total c+s-1.

Work that is executed but is NOT in the paper's formulas (so the measured time contains slightly more than the formula):
1. Three projective-to-affine conversions of G1 points (one field inversion each) inside the pairing wrapper, needed because `bls12_381::pairing` takes affine points.
2. The final equality test in Gt (`lhs == rhs`).
3. Building the hash input bytes (small allocations) and SHA-256/expand-message inside H1 (this is part of H, as intended).
4. The ProofGen stage includes a `Vec` allocation for mu and the indexing of stored data.
The paper's formulas also contain no symbol for addition in G, and the paper does not say how a "multiplication in G" is realised; here M_G is a G1 projective point addition.
The three pairings are three separate full pairings (no shared final exponentiation, no multi-Miller-loop), as the paper's "3P" says.

## Harness
`dong-bench --runs 30 --warmup 3 --out DIR [--quick]`: one thread, `Instant`, 3 untimed warm-ups, 30 timed runs, fresh challenge per run (drawn before the timer starts), inputs generated before timing. Each run's output goes through `black_box` and is checked: after a timed `proofgen` the proof is verified outside the timer; the timed `verify` returns the boolean that is asserted. Output `raw_runs.csv` (`baseline,stage,params,run,ms`) with baseline = `dong`, stages `proofgen`, `verify`, params `s=3;c=100` (extra points: `s=3;c=350;extra=1`).
Setup cost for the largest point (c = 1000, n = 10000 tags) is several seconds, untimed.

## Sweeps at matched coverage (SPEC-w16, work16, 2026-11-06)
Added options; with none of them the binary behaves exactly as before (test `default_grid_unchanged_quick`). No existing stage changed meaning.

| flag | meaning |
|---|---|
| `--cov LIST` | coverage points c (records covered = challenged blocks), s = 3. Replaces the default grid; stages `proofgen` and `verify` at each c. |
| `--q LIST` | adds stage `verify_q` for every q (at each `--cov` point). `--q` alone means Exp 4b: cov = 1000, only `verify_q`. |
| `--runs-big R`, `--big-above X` | if the work of a run is large (c > X for `proofgen`/`verify`; q*c > X for `verify_q`), use R timed runs (default 5) and 1 warm-up instead of `--runs` / `--warmup`. Defaults: R = 5, X = 2000. |
| `--params-tag TAG` | appended to `params` (also in the default grid) so sweeps never collide. |
| `--n-factor F` | OURS, extra. n = F * c blocks in the file (default 10, as in the default grid). Lower it only to save untimed set-up time; it does not change the timed stages. |

Row format of the sweep: `dong,<stage>,s=3;c=<c>;n=<n>[;q=<q>];runs=<R>[;TAG],<run>,<ms>`. `runs=R` is always written (the number of timed runs actually used).

- `proofgen`, `verify` at c = cov: the same `proof_gen` / `proof_verify` as above, fresh challenge per run (drawn before the timer), the proof of `verify` made before the timer, every result checked (`proofgen`: proof verified outside the timer).
- `verify_q`: q INDEPENDENT audits verified in ONE timed run. Before the timer: q different nonces -> q different challenges (`challenge`), q honest proofs (`proof_gen`). Timed: q calls of the full `proof_verify`, one after the other (no batching across audits, no sharing of H1(ID,t) or pairings, no early exit: results are combined with a non-short-circuit `&=`). The conjunction is `black_box`ed and asserted true. `ms` = total for the q verifications. The test `verify_q_counts_are_q_times_one_verify` checks that the operation counts are exactly q times one verify. Fresh challenges and proofs for every run (warm-up included), so the untimed set-up of a `verify_q` run costs q ProofGens.
- n (blocks in the file) = 10 * c, the paper's "10% challenged" (line 1063), the same rule as the default grid; so the challenge is a random c-subset of 10 c blocks. The paper's cost formulas have no n term; ProofGen and ProofVerify cost does not depend on n (only on c and s), n only decides which blocks are hit. Tags are made for all n blocks (untimed).
- "Matched coverage" means c = the number of records that PQZ-Audit covers in the same experiment point (1% of N in Exp 1, N_Q in Exp 4a, 1000 per audit in Exp 4b). A Dong challenge of c blocks covers c blocks; whether a block equals a "record" of PQZ-Audit is a modelling choice of the plot, not something this code decides (a block here = 3 sectors of 255 bit).
- Still not run: IBS signature on the file tag, blockchain, network, disk; one thread. Same curve / group mapping caveats as above (BLS12-381, no multi-exponentiation: for c = 10^4..10^5 a Straus/Pippenger multi-exponentiation would be much faster than our c separate constant-time scalar multiplications; the paper does not describe it, so we do not use it. This favours PQZ-Audit at large c).
- Untimed set-up cost (measured locally, this laptop): AuthGen about 1.1 ms per block, i.e. about 11 ms per unit of c (n = 10 c): c = 1000 -> 11 s, c = 10^4 -> about 2 min, c = 10^5 (n = 10^6 tags, roughly 300 MB) -> about 19 min.
- Timed cost measured locally (smoke, median of 3): `proofgen` about 0.33 ms per unit of c, `verify` about 0.38 ms per unit of c (c = 1000: 328 ms and 384 ms); `verify_q` about q times one verify. These are our measurements, not a prediction of the cloud machine.
