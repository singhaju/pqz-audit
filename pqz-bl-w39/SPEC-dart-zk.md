# SPEC: the zk-SNARK step of DART (work39)

Written before the code (2026-11-16). Goal: add DART's ZKP.Prove / ZKP.Verify to our DART re-implementation, faithfully, choosing the
CHEAPEST faithful option wherever the paper is silent, so that "DART with ZK" is still a lower bound on the real DART.
Paper: Yu et al., DART, IEEE TIFS 20, 11264-11278, 2025. Text: `journal2/comparison-papers/baselines-main11/text/dart.txt` (two columns mixed;
line numbers below are of that file). Equations and Algorithms 1-2 are images: read from the page renders (PDF pages 8-9 = printed pages 11271-11272);
the Algorithms are NOT in dart.txt.

## 1. What the paper says about the ZK step (quotes)

Scheme / tool
- l.201-203: "we adopt a QAP-based zk-SNARK framework, which offers succinct, fixed-size proofs and fast, non-interactive verification".
- l.210-211: "we leverage QAP-based zk-SNARK to prevent replay attacks launched by malicious storage nodes" (the replay attack: l.436-452, a node that keeps only the commitments gamma and discards the data).
- l.217-218: "Technically, the implementation of ZKP relies on zk-SNARK [41], [42]" ([41] Pinocchio-type, [42] Groth 2016, size of pairing-based arguments). Groth16 is not named as the choice.
- l.235-243: `ZKP.Setup(phi) -> (ke, kv)` from an R1CS instance; `ZKP.Prove(ke, x, w) -> pi` (public input x, witness w); `ZKP.Verify(kv, x, pi)`.
- DIZK variants (l.248-270): same interface, with SPARK-distributed FFT / varMSM (prover) and Lag / fixMSM (setup).
- l.432-440: the data owner generates `(ke, kv)` and the arithmetic circuit Theta in DART.Init (also l.298-299); the setup is per data owner, can be shared.

The relation (the only statements; there is no circuit description anywhere)
- Eq. 5, l.500-506: "The storage node takes as input the data blocks of the challenged file chunks {D~_{i,j}}, and calculates the ZKP proof pi:
  `pi <- ZKP.Prove(ke, Theta_Loc, {D~_{i,j}}_{i in Lambda}, {alpha_i}_{i in Lambda}, gamma_a)` (5)
  where gamma_a = {gamma_{a,j}}_{j in [0,N-1]} are the linearly aggregated outputs (commitments), Theta_Loc is the arithmetic circuit in ZKP for local challenge".
- Eq. 7, l.462-464: for a global challenge, `pi <- DIZK.Prove(ke, Theta_Glb, {D~_{i,j}}, {alpha_i}, gamma_a)`, "Theta_Glb is the arithmetic circuit of DIZK for the global challenge covering all data in the storage network".
- Verification, l.505-509: "It examines the calculation of commitments of the challenged blocks, by verifying the corresponding proof of arithmetic circuit using `ZKP.Verify(Theta_Loc, kv, gamma_a, pi)` for the local challenge while using `DIZK.Verify(Theta_Glb, kv, gamma_a, pi)` for the global challenge."
- Eq. 4 (Algorithm 1 line 7): f(x) = sum_j (sum_{i in Lambda} alpha_i gamma_{i,j}) x^j; gamma_{i,j} = COM.Commit(D~_{i,jM}, ..., D~_{i,jM+M-1}) (Store, l.466-470 region: "gamma_{i,s} = COM.Commit(D~_{i,j}, D~_{i,j+1}, ...), j in [sM, (s+1)M-1], s in [0,N-1]", "polynomial commitment f_i(chi)").
- Algorithm 1, line 6 (image): "Compute the distributed zero-knowledge proof pi <- DIZK.Prove(ke, Theta_Glb, {D~_{i,j}}_{i in Lambda}, {alpha_i}_{i in Lambda}, gamma_a)". Input list of Algorithm 1: "(M, N)" as "commitment parameters", "proof key ke, circuit Theta".
- Algorithm 2, lines 6-9 (image): "Check the proof pi by DIZK.Verify(Theta_Glb, kv, gamma_a, pi); if DIZK.Verify(...) == false then return Res = FAIL".
- Section VII-B, l.778-781: "increasing N reduces the number of required data authenticators. However, this introduces higher computational complexity when constructing and evaluating the ZKP circuit." (so the circuit grows with N; M also enters through the commitments).

### The relation we read from this (and what is NOT in the paper)
Public input x = ({alpha_i}_{i in Lambda}, gamma_a); witness w = the z*N*M encoded blocks of the z challenged chunks. The circuit checks, for every challenged chunk i and
every j < N, that gamma_{i,j} = COM.Commit(M blocks), and that gamma_{a,j} = sum_i alpha_i gamma_{i,j}. That is exactly "the calculation of commitments of the challenged
blocks" (l.505-506) and the Eq. 4 aggregation. Size: z*N commitment evaluations over M blocks each + z*N multiplications by alpha + N sums.

Not in the paper (so not decided by it): COM.Commit itself (only "COM.Commit", abstract); the circuit (no gate count, no constraint count); the curve and field of the SNARK
(the pairing parameters stated, l.746-748, are Type A with |p| = 160 bit, |G1| = 512 bit, for the pairing part; jsnark is normally used with BN254, not stated);
whether alpha_i is bound to PRG_{k2}(l) inside the circuit (x lists alpha_i as an input; we take it as a public input, which is the cheapest);
whether the circuit also binds gamma_a to the authenticators tau_i (it does not take tau as input; the binding is only Eq. 9 outside the circuit);
the DIZK cluster, the number of nodes, constraint sizes.

### Contradictions / unclear points (reported, not resolved by us)
1. Eq. 5 text (l.500-506) uses `ZKP.Prove` with `Theta_Loc` (local challenge), while Algorithm 1 line 6 and Algorithm 2 lines 6-9 print only `DIZK.Prove/Verify` with `Theta_Glb` (global challenge). The existing `FIDELITY.md` calls the missing step "ZKP.Prove Eq. 5 / Algorithm 1 line 6 / DIZK.Prove Eq. 7": the algorithms in fact name the DIZK version. We implement the local one (single prover, no distribution), the cheaper of the two. For a challenge that lies on one node (our audits), Eq. 5 is the paper's own text for this case.
2. No size of the circuit is given anywhere, and no ZK time. Section VII (l.741-748): "We implemented a prototype of our scheme in JAVA ... Desktop PC, with Ubuntu 20.04 LTS, AMD Ryzen 7 5800H GHz and 16GB memory. ... JPBC. The ZKP protocol is implemented based on jsnark library." The results are log-scale plots (Fig. 5, 8) [images]; Fig. 8(a) "proof generation time ... for varying file sizes F" and the number of DIZK nodes, Fig. 8(b) setup time. No table and no number we can quote; so there is no timing to compare our estimate with (a sanity check is not possible from the text; do not quote numbers read from the plots without re-reading the plots).
3. The "x" of Eq. 5 contains gamma_a, but Eq. 9 (the data owner's check Omega_f = prod tau_i^alpha_i) is the only link between gamma_a and the stored data; the circuit as printed proves "gamma_a is the right aggregation of commitments of SOME blocks". As the paper itself says (l.436-452) the circuit is what stops the replay of commitments.

## 2. Our implementation choices (cheapest faithful) and who they favour

| # | choice | favours | why / note |
|---|---|---|---|
| 1 | Local circuit Theta_Loc, ONE prover (no DIZK distribution, no network, no Spark) | DART (cheaper) | Eq. 5 is the paper's text for a local challenge; DIZK adds distribution overhead |
| 2 | Groth16 (arkworks 0.4.0 `ark-groth16`) | DART | Fixed-size proof, 3 pairings, the cheapest verifier of the QAP family the paper cites ([41] Pinocchio, [42] Groth16). The paper does not name a scheme |
| 3 | BN254 (same arkworks versions as `bench/pqz-bl-w30/lhcpm`) | DART | smaller than BLS12-381; jsnark also uses BN254 (not stated by the paper) |
| 4 | COM in the circuit = Poseidon over the BN254 scalar field, ONE permutation per commitment: width 11 (rate M=10, capacity 1), x^5 S-box, R_F=8, R_P=66 (the circomlib round count for t=11, quoted from memory, not re-derived), round constants and MDS from `ark-crypto-primitives` (Grain LFSR), output = first state element | DART | SNARK-friendly hash (a SHA-based COM in the circuit would cost far more constraints; SHA-256 is commonly reported at about 25,000 R1CS constraints per compression block, from memory, not measured here). R_P=66 may be a few rounds (~6 percent of constraints) above the minimum of the Poseidon script: favours us slightly, unchecked against the script output |
| 5 | One block = ONE field element (our 32-byte block reduced mod r_BN254) | DART | the paper gives no block size; we keep our 32-byte blocks (as in FIDELITY.md) and put one per Poseidon input; a bigger block would need more inputs |
| 6 | M = 10, N = 20 as in the paper (l.756, Fig. 5 captions); chunk = N*M = 200 blocks; z = ceil(cov/200); same mapping as the existing code | neutral | exactly the mapping of FIDELITY.md (`--cov`, `--file-records`) |
| 7 | alpha_i and gamma_a are PUBLIC inputs; alpha_i NOT constrained to PRG_{k2}(l) in the circuit | DART | cheapest; the paper lists alpha as an input only |
| 8 | Out-of-circuit values stay as before (SHA-512 COM, BLS12-381 gamma_a for Eq. 8/9). The zk statement uses a SEPARATE Poseidon/BN254 gamma_a, computed natively from the same blocks OUTSIDE every timer, alpha_i reduced from the BLS12-381 PRG output into BN254 Fr | neutral on time, FIDELITY caveat | in the real scheme one COM serves both; here the two values are not linked algebraically (we pay each cost once, not twice). A cost model, not a protocol |
| 9 | Circuit setup (CRS) one-time, OUTSIDE timing, like DART.Init; its time and proving-key size are recorded | DART | paper: the data owner runs setup in Init (l.432-434); cost of setup per z is not in any stage |
| 10 | `zkprove_only` times `Groth16::prove` INCLUDING witness generation (circuit synthesis: the 462 constraints per commitment are evaluated) and the random r, s; EXCLUDED (untimed): conversion of blocks and alpha into BN254 field elements, the native Poseidon values of the public input gamma_a | DART | what the prover must do in the circuit (witness generation) is timed; the public values are computed once natively outside |
| 11 | `verify_zk` = `verify_nozk` + Groth16 verify with a PREPARED vk (pairing of alpha,beta and the gamma/delta G2 preparation done outside), public inputs z + N, alpha_i taken from the Lambda the verifier already computes (Algorithm 2 lines 1-5, reused, not recomputed) | DART | no double counting of the PRP/PRG |
| 12 | `verify_zk` uses ONE challenge and ONE zk proof per coverage point (made untimed once; the verifier work does not depend on the values) | neutral | avoids re-proving at every run |
| 13 | arkworks default `OptimizationGoal::Constraints`; we do not run the optimized Poseidon (sparse MDS) or lookup tricks | us | a hand-optimized circuit could be somewhat smaller |
| 14 | single thread (1-thread crate: no `parallel` features, no rayon); the -par crate: arkworks `parallel` (rayon), `RAYON_NUM_THREADS` | neutral | |

Size, stated exactly (verified by test `constraint_count_is_as_specified`), M = 10:
constraints = z*N*(RF*(M+1)*3 + RP*3 + 1) + N = z*N*463 + N; public inputs = z + N; witness variables = z*N*473.
(S-box x^5 = 3 constraints; 8 full rounds x 11 lanes + 66 partial rounds x 1 lane; +1 for alpha_i * H; +N sums.) Groth16 adds z+N more constraints internally (one per public input). Linear in z and N; with `--cov`: z = ceil(cov/200), so constraints ~ 463 * 20 * cov/200 = 46.3 * cov (about 46,300 per 1,000 covered records).

## 3. Stages added (names for `--stages`)
- `zkprove_only`: Groth16 prove of the relation, timed alone.
- `proofgen_zk`: `prove_nozk` + `zkprove_only`, timed together (Algorithm 1 complete: lines 1-11 with line 6 as the local-circuit proof).
- `verify_zk`: `verify_nozk` + Groth16 verify (Algorithm 2 complete with lines 6-9 as the Groth16 verify).
Output: the same `raw_runs*.csv` / `ops*.csv`; the ops rows of the new stages also carry `zk_constraints`, `zk_public_inputs`, `zk_pk_bytes`, `zk_vk_bytes`, `zk_setup_ms`; one new file `zk_info*.csv` (per z: constraints, public inputs, witness variables, setup ms, pk bytes, vk bytes).
Existing stages are unchanged (the old tests pass unchanged).
