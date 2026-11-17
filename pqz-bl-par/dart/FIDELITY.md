# FIDELITY: DART auditing path, run code, NO zk-SNARK

Paper: Yu et al., "DART: Distributed Zero-Knowledge Data Auditing With Retrievability for Blockchain-Based Decentralized Storage Networks", IEEE TIFS 20, 11264-11278, 2025.
Source lines: `journal2/comparison-papers/baselines-main11/text/dart.txt` (line numbers below), equations 4-9 and Algorithms 1-2 read from the page renders (printed pages 11271-11272).

## READ THIS FIRST: what is NOT run
- **ZKP.Prove (Eq. 5, Algorithm 1 line 6; DIZK.Prove, Eq. 7) is NOT run. The proof pi is not produced.**
- **ZKP.Verify / DIZK.Verify (Algorithm 2 lines 6-9) is NOT run.**
- Therefore `proofgen_nozk` and `verify_nozk` are a **LOWER BOUND** on DART's proof generation and verification. A zk-SNARK prove over a circuit that recomputes z*N commitments, and its verification (QAP-based, jsnark/DIZK, curve and circuit size not given in the paper), are missing from both. No DART total can be read from these numbers.
- `verdict.ok` = Eq. 8 and Eq. 9 hold. It is NOT "DART accepts".
- Not run either: DART.Init key generation of ke/kv, Store timing, Retr, erasure coding (encoded blocks are random bytes), the blockchain, DIZK distribution, any network. All in memory, one thread.

## What runs (stage by stage)
Setup (outside timing): chi, zeta; rho_j = u^{chi^j} (j < N); phi_i = v^{zeta^i} (i <= |D|, G1) and h^{zeta^i} (i <= z_max, G2); random encoded blocks, N*M blocks of 32 bytes per chunk; gamma_{i,s} = COM.Commit of M blocks; f_i(chi) = sum_s gamma_{i,s} chi^s; tau_i = u^{f_i(chi)}; c_tau_i = C_G(tau_i); S_auth = v^{prod_{i in D}(c_tau_i + zeta)} (the accumulator trapdoor powers are the phi_i).

`proofgen_nozk` = Algorithm 1 without line 6:
1. lines 1-5: for l = 1..z: i = PRP_k1(l-1), alpha = PRG_k2(l); Lambda = {(i, alpha_i)}.
2. Line 7 / Eq. 4: f(x) with N coefficients gamma_{a,j} = sum_{i in Lambda} alpha_i * gamma_{i,j}; the gamma_{i,j} are **recomputed from the stored data blocks** (z*N hash commitments over M blocks each), because the ZKP would prove exactly that relation and the data-tamper test needs it. Cost: z*N SHA-512 + z*N Fr mul-add.
3. Line 8: c_tau_i = C_G(tau_i) for i in Lambda (z hashes). c_tau_i for i in D \ Lambda are read from the node's stored table (the paper's line 8 only says i in Lambda; line 9 needs D \ Lambda; storing them is our reading).
4. Line 9: beta_0..beta_{|D|-z}: schoolbook expansion of prod_{i in D \ Lambda}(c_tau_i + zeta) as a polynomial (O((|D|-z)^2) Fr mults).
5. Line 10 / Eq. 6: eta_tau = prod_{k=0}^{|D|-z} phi_k^{beta_k}, a naive product of |D|-z+1 G1 exponentiations (no Pippenger/MSM trick; the paper gives none). This DISFAVOURS DART's proofgen relative to a tuned MSM.
6. Output Prf = (tau, eta_tau, gamma_a); pi missing.
Omega_f (Eq. 9, Algorithm 2 line 14) is computed in `verify_nozk`, where Algorithm 2 puts it (the text of Section V says the data owner computes it; Algorithm 2 says SC). It is not part of Prf, so it is not in proofgen.

`verify_nozk` = Algorithm 2 without lines 6-9:
1. Lines 1-5: Lambda again (z PRP + z PRG). 2. Line 10: c_tau_i from the proof's tau (z hashes). 3. Line 11: delta_0..delta_z, expansion of prod_{i in Lambda}(c_tau_i + zeta) (z^2/2 Fr mults). 4. Line 12: H_Lambda = prod_{i=0}^{z} phi_i^{delta_i} (z+1 G2 exponentiations). 5. Line 13 / Eq. 8: e(S_auth, h) = e(eta_tau, H_Lambda): **two separate pairings** compared in GT (the paper counts none; Eq. 8 has one on each side; a shared final exponentiation / multi-Miller loop would be cheaper and is NOT used). 6. Line 14: Omega_f = prod_{j<N} rho_j^{gamma_{a,j}} (N G1 exps). 7. Line 15 / Eq. 9: prod_{i in Lambda} tau_i^{alpha_i} (z G1 exps) compared with Omega_f.

## Group mapping: symmetric Type A (paper) -> BLS12-381 (asymmetric)
The paper: symmetric pairing G1 x G1 -> GT, |p| = 160 bit, |G1| = 512 bit (l.746-748). Ours: BLS12-381, 255-bit scalars, G1 48 bytes compressed, G2 96 bytes. Every element of the paper is in the same G1, so a mapping is needed. Ours (our choice; the minimal one that makes Eq. 8 type-check):
- **G1**: u, v, rho_j, phi_i (the copy the storage node uses for eta_tau), tau_i, S_auth, eta_tau, Omega_f. Eq. 6 (|D|-z+1 exps) and Eq. 9 (N + z exps) stay entirely in G1.
- **G2**: h and a second copy phi_i = h^{zeta^i} for H_Lambda (z+1 exponentiations), so Eq. 8 is e(G1, G2) = e(G1, G2).
- Cost effect: the z+1 exponentiations for H_Lambda cost more than a G1 exponentiation (G2 arithmetic over Fp2; ratio not measured here), where Type A pays the same for all of them; the pairing on BLS12-381 is not comparable with a 512-bit Type A pairing in either direction. Hash/field costs (255-bit Fr) differ too. We do not claim equality of absolute times with the paper's JPBC setup; the paper gives no time table anyway (findings-dart.md, headline 4).
- Consistency: Eq. 8 holds because h = generator of G2, S_auth = v^{A}, eta = v^{A'}, H = h^{B}, A = A' B. (The paper's proof, Eq. 10, silently needs h = v.)
- Extra storage: the SC needs phi_i in G2 as well (z+1 elements); the paper's public-values count assumes one group.

## Parameters and their source
| parameter | value | source |
|---|---|---|
| M (blocks per commitment) | 10 | paper, l.756 ("with M = 10") |
| N (coefficients of f(x), commitments per chunk) | 20, 40 | paper, Fig. 5 captions [image; per findings-dart.md B] |
| z (challenged chunks) | grid 10, 50, 100, 200; quick 10, 100 | **OURS** (not in the paper: l.480-482 define z, no value) |
| \|D\| (chunks of the stored file) | 400 (`--chunks`) | **OURS**. The paper's Fig. 4 shows 100-800 chunks [image]; not tied to z or N. It sets the size of eta_tau's product (\|D\|-z+1 G1 exps) and of the beta expansion, so it moves proofgen_nozk strongly. It is part of the params string as `D=400`. |
| block size | 32 bytes | **OURS** |
| chunk data | random bytes | per task; erasure code not modelled |
Params string: `M=10;N=20;z=100;D=400` (D appended to the requested `M=10;N=20;z=100` because it changes the time; do not drop it).

## Choices that are ours (paper silent)
- COM.Commit: SHA-512 of the M blocks, reduced to Z_p (a hash commitment, no randomness). The paper names COM.Commit only abstractly (l.150-165); inside the ZKP circuit the cost would differ.
- C_G: SHA-512 of the compressed G1 point reduced to Z_p (paper: "a commitment that commits an element in G1 to a value in Z_p^*").
- PRP: 4-round Feistel, SHA-256 round function, cycle walking, on [0, |D|). PRG: SHA-512(k2, l) reduced to Z_p. Eq. 9 uses alpha only. Both stages recompute Lambda, as Algorithms 1 and 2 say.
- Naive exponentiation product (no multi-exponentiation), `bls12_381` constant-time scalar multiplication. Favours PQZ-Audit (slower baseline) for the G1/G2 products.
- 2 independent pairings (see above). Disfavours DART slightly versus a multi-pairing.
- Keys k1, k2 are drawn fresh per run, outside the timer. For `verify_nozk` the proof for that challenge is generated before the timer starts.

## Findings from implementing it (reported, not hidden)
1. Operation counts (from `ops.csv`, counted where the operation runs; for D=400, N=20, z=100): verify: 2 pairings, z+1 = 101 G2 exps, N + z = 120 G1 exps, 5150 Fr mults (delta expansion), 100 PRP, 200 SHA-512 (c_tau + alpha), 1016 SHA-256 (PRP rounds with cycle walking). proofgen: |D|-z+1 = 301 G1 exps, 47450 Fr mults, 2200 SHA-512 (2000 commitments, 100 c_tau, 100 alpha). These match the findings: 2 pairings in Eq. 8; z+1 for H_Lambda; z for the Eq. 9 right side.
2. The professor's row `T_ZKV + 2T_P + O(z T_E)` against the algorithm: the 2 pairings and the z exps of Eq. 9 agree; it OMITS the z+1 G2 exponentiations of H_Lambda (they are O(z) too, so inside `O(z T_E)` if T_E covers G2), the N exponentiations of Omega_f (line 14) and the O(z^2) delta expansion; for the storage side the |D|-z+1 exponentiations of eta_tau and the O((|D|-z)^2) beta expansion are N-independent but |D|-dependent, and the z*N commitments (inside the ZKP circuit in the paper, here done natively to get gamma_a) are N-dependent. The professor's `O(z N_D T_F)` audit term is not a DART formula (findings-dart.md A, D).
3. `eta_tau` makes proofgen_nozk DEcrease with z for fixed |D| (fewer factors in D \ Lambda): z=10 gives 110.8 ms, z=100 gives 75.9 ms in the smoke run, and verify_nozk increases with z. This follows from Eq. 6 as printed; it is a property of the algorithm plus our choice of |D|.
4. **k1 does not enter any check of Algorithm 2 lines 10-15**: the verifier recomputes the indices i but only alpha_i (from k2) is used in Eq. 9, and Eq. 8 uses the tau in the proof. A proof built for a different PRP key but the same k2 passes Eq. 8 and Eq. 9 here (test `tampered_eta_gamma_and_wrong_challenge_fail`). In the paper the binding of the answered indices to the challenge can only come from the ZKP (which takes {alpha_i} and the blocks) and is not visible in Eq. 8/9. Not run, not decided; flagged.
5. Tampering is caught as the paper's equations say: one flipped bit in a challenged chunk breaks Eq. 9 only (tau untouched); a changed tau breaks Eq. 8 and Eq. 9; a changed eta_tau breaks Eq. 8; a changed gamma_a breaks Eq. 9. Without the ZKP, a node that stores only the commitments gamma_{i,j} (the replay attack the paper discusses, l.436-452) would pass here; the paper prevents that with the ZKP, which is not run.
6. Findings-dart.md notes the paper prints `e(st, h)` in Algorithm 2 where Eq. 8 has S_auth and that Omega_f is the data owner's step in the text but SC's in Algorithm 2; we followed Algorithm 2.

## Disclosure that goes to the paper
Single thread, in memory, same machine and session as PQZ-Audit; BLS12-381 instead of Type A; the stage times exclude the zk-SNARK entirely (lower bound); |D|, z, block size, COM and C_G instantiations are ours.

## SPEC-w16 additions (work16, 2026-11-06): sweeps at matched coverage
Still **no zk-SNARK**: ZKP.Prove, ZKP.Verify, DIZK are NOT run in any new stage either; `proofgen_nozk`, `verify_nozk` and `verify_q` are lower bounds. The default command line (no `--cov`) is unchanged and gives the old grid (`D=400`, z in 10..200); tests of the old stages are untouched.

### New flags (active only with `--cov`)
`--cov LIST` (records covered), `--q LIST`, `--runs-big R` (default 5), `--big-above X` (default 2000), `--params-tag TAG`, `--file-records N` (default 1e6), `--file-records-list LIST` (one file size per cov), `--scale-d`, and (our extra, for splitting jobs) `--stages LIST` (default `proofgen_nozk,verify_nozk`, plus `verify_q` when `--q` is given). `--runs/--warmup/--quick/--out` as before; `--quick` = 3 runs, 1 warm-up.
- Chunk = N*M = 200 blocks (N = 20, M = 10; paper M=10, N=20 from the Fig. 5 caption). **D = ceil(file_records / 200)**, **z = max(1, ceil(cov / 200))**. D source: `--file-records-list` (per cov) if given, else `--scale-d` (file = 100 x cov records, so D = ceil(cov*100/200)), else `--file-records`. Params string: `M=10;N=20;z=Z;D=D;cov=C;runs=R[;q=Q][;TAG]`; D, z and the number of timed runs are always visible.
- Big points: if cov > `--big-above` (for `verify_q`: q*cov > `--big-above`) the stage uses `--runs-big` timed runs and 1 warm-up, otherwise `--runs`/`--warmup`.
- `verify_q`: q independent audits in ONE timed run: q fresh key pairs (k1, k2), q different proofs, all made before the timer; `ms` = total for the q `verify_nozk` calls; every verdict is checked (assert). Ops in `ops.csv` are the sum over the q audits.
- In this mode N is fixed at 20 and M at 10. Output goes to `raw_runs.csv` / `ops.csv` in `--out`; if `raw_runs.csv` already exists a numbered file (`raw_runs_1.csv`) is written, never overwritten.

### What "matched coverage" means here (and what favours whom)
- A DART audit challenges z whole chunks, so it covers z*200 records. cov = 100 and 200 both give z = 1 (200 records): DART cannot be challenged at a finer grain than one chunk, so for cov < 200 it covers MORE than PQZ-Audit's cov (favours PQZ-Audit on coverage, favours DART on cost per record).
- `proofgen_nozk` depends on the FILE size, not on cov: eta_tau (Eq. 6) multiplies |D|-z+1 G1 exponentiations and beta is an O((|D|-z)^2) expansion. With the fixed 1e6-record file (D = 5000) it is about 1.4-1.7 s at every cov, and it DEcreases slightly with z (finding 3 above). With `--scale-d` / `--file-records-list` it grows with D, i.e. with N. D is our choice (the paper does not tie D to the data volume or to z); the `D=...` field must stay in every plot label. `verify_nozk` depends on z only (and on N=20), not on D.
- Eq. 6 is still a naive product of exponentiations (no MSM), which favours PQZ-Audit; the 2 pairings are still separate.

### Untimed setup (reported, so it can be left out of the timer on the cloud box)
- File build (`setup_with_trapdoor`): D chunk commitments (20 SHA-512 each), 2 G1 exponentiations per chunk (tau_i, phi_i), z_max+1 G2 exponentiations. Measured here (one thread): D = 5000, z_max = 500: 3.4 s, file 30 MiB; D = 5000, z_max = 5: 3.0 s. About 0.6 ms per chunk, so roughly linear in D (`--scale-d` with cov = 1e5 would give D = 50000: about 30 s and 300 MiB, not needed for the planned grids). Built once per distinct D and reused across stages/cov/q (cache of the last D, rebuilt only if D changes or z_max grows).
- **Input proofs for `verify_nozk` and `verify_q` are made with `prove_fast`**, not `prove_nozk`. `prove_fast` returns the SAME `Prf` (tau, gamma_a and eta_tau; test `prove_fast_equals_prove_nozk`) but gets eta_tau from the setup trapdoor (zeta, the exponent of v, and prod(c_i + zeta)) as one G1 exponentiation instead of |D|-z+1. Reason: with D = 5000 `prove_nozk` takes about 1.5 s, so q = 200 audits would cost 300 s of untimed preparation per run. It is only used for the untimed verifier input, never inside a timed stage; `proofgen_nozk` still times the full `prove_nozk` (Algorithm 1 without line 6).

### Measured here, for planning the cloud run (one run each, this laptop, one thread; NOT results)
- D = 5000: proofgen_nozk 1.37 s (z = 500), 1.49 s (z = 50), 1.55-1.68 s (z = 1..5). verify_nozk 8.7 ms (z = 1), 14 ms (z = 5), 54 ms (z = 50), 496 ms (z = 500; the z+1 G2 exponentiations dominate). verify_q at cov = 1000 (z = 5): 14 ms per audit, q = 200 gives 2.6 s per run.
- Exp 1 smoke (D = 50, 100, 250): proofgen_nozk 13, 29, 73 ms; verify_nozk 8-13 ms.
- Rough cloud estimate per big point (runs-big 5 + 1 warm-up, so 6 stage executions): proofgen_nozk about 10 s; verify_nozk at z = 500 about 3 s; verify_q (cov 1000, q 200) about 16 s plus preparation of 200 proofs per run (small with `prove_fast`). Whole planned grid: a few minutes plus 3-4 s setup per distinct D. The cloud machine speed will scale these.

### Tests added (`cargo test --release`)
`chunk_and_challenge_sizes_follow_the_spec` (D, z formulas), `prove_fast_equals_prove_nozk`, `verify_q_honest_passes_and_each_tamper_fails` (honest q = 4 passes with 8 pairings; flipping gamma_a, eta or tau in one of four proofs, or swapping two challenges, is rejected), `matched_coverage_stages_with_data_tamper` (cov = 600 -> z = 3: honest passes; a flipped block in a challenged chunk fails).
