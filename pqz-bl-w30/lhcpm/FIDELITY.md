# FIDELITY: L-HCPM baseline (pqz-bl-lhcpm)

Paper: Sun, Mahfuz, Wang, "Quantum-Resistant Privacy and Auditing for Blockchain: A Lattice-Based Approach With Composable Security", IEEE TDSC 2026.
Sources: `journal2/comparison-papers/baselines-main11/text/lhcpm.txt` (line numbers below) and `findings-lhcpm.md` (section letters below).
Rule used: no number from the paper is a result or a tuning target. Paper numbers appear only as INPUT parameters (listed in section 2).
Harness: one thread, `Instant`, 3 warm-up and 30 timed runs, `--quick` = 1 warm-up and 3 runs. Each timed run is the whole named stage.
Every timed run is checked (after the timer stops): audit returns the true m; Groth16 verify returns true; each proof just made verifies.

## 1. What runs

| Stage | Params string | What the timer covers |
|---|---|---|
| `audit_hit` | `n=4096;logq=108;t=2^28` | Algorithm 2 (l.496-504) on a cache HIT, steps 1, 5, 6, 7-10 (below) |
| `groth16_verify` | `public_inputs=3` (also `public_inputs=13` in the full run) | `verify_with_processed_vk` (arkworks, BN254), prepared vk made in setup |
| `groth16_prove_mint` | `constraints=2676` | `Groth16::prove` incl. witness synthesis, fresh randomness |
| `groth16_prove_transfer` | `constraints=8786` | same, 8,786 constraints |

| `audit_hit_q` (SPEC-w16, `--q`) | `n=4096;logq=108;t=2^28;q=Q` | Q independent runs of the `audit_hit` operation in ONE timed run (see section 8) |
| `groth16_verify_q` (SPEC-w16, `--q`) | `public_inputs=3;q=Q` | Q different proofs, each with its own 3 public inputs, verified one after the other in ONE timed run |

Algorithm 2 as implemented (`src/audit.rs`):
1. `delta_G <- Cache.Get(txId)`: a real `std::collections::HashMap<[u8;32], Vec<u32>>` lookup (SipHash). The cache holds 1024 entries (64 in `--quick`), each a vector of m = 8448 `u32` (the shape of a SamplePre preimage for q = 2^32). The values are RANDOM filler: SamplePre is not run.
5. `m <- RLWE.Dec(sk_G, ct_G; delta_G)`: BFV-style decryption `m = round(t/q * [c0 + c1*s]_q) mod t`. The paper does NOT say which scheme (BFV, BGV or CKKS; findings C). We chose BFV because its decryption is the plain formula above. Details:
   - ring Z_q[X]/(X^4096 + 1), q = p0 * p1 with two NTT-friendly primes p0 = 18014398509309953, p1 = 18014398509293569 (both about 2^54, both = 1 mod 8192); q has 108 bits. RNS/CRT: Garner reconstruction of x in [0, q), exact.
   - `c1*s` is done with a negacyclic NTT per RNS prime (forward on c1, pointwise product with the secret key kept in NTT form, inverse), single thread, scalar code (no SIMD), Harvey lazy butterflies with Shoup constant multiplication. That is 4 length-4096 transforms per decryption.
   - the scaling `round(t*x/q)` is exact: f64 estimate, corrected with the exact 128-bit remainder.
   - secret key ternary, error Gaussian with sigma = 3.2 (rounded Box-Muller, cut at 6 sigma), public key (-(a s) + e, a), encryption `c0 = pk0*u + e1 + floor(q/t)*m`, `c1 = pk1*u + e2` (all in setup, outside the timer). Ciphertext = 2 polys x 2 RNS limbs x 4096 x 8 B = 131,072 B (this equals the paper's "about 128 KB" only because of this layout; not used for tuning).
   - all 4096 plaintext coefficients are random in [0, 2^28); the amount m is coefficient 0. Test: decryption returns all 4096 coefficients exactly.
   - `delta_G` is fetched (and passed to `black_box`) but BFV decryption does not use it: the paper does not say how `delta_G` enters RLWE.Dec. This favours the baseline slightly (nothing to do with it).
6. `cm' <- H(m || r_shared || H(pk_G) || cm_T)`: four field elements absorbed by the MiMC hash (below). 7-9: compare with `cm_G`, reject on mismatch. 10: return m.
   - pdftotext lost the prime marks in step 7; we read it as "if cm' != cm_G then return fail" (the only reading that makes sense of "Verification failed").
   - `r_shared` is a per-transaction input to the audit (random field element). `cm_G` is computed in setup from the true m.

MiMC (`src/mimc.rs`), over the BN254 scalar field Fr (paper: MiMC [39], l.311-312, BN254 l.631):
- permutation x -> (x + k + c_i)^5, i = 1..110, then + k. Exponent 5 because gcd(5, r-1) = 1 on BN254 Fr (this is the same choice as gnark's BN254 MiMC, to our recollection; not verified here). Rounds 110 = ceil(254 / log2 5) = ceil(109.4), the standard MiMC-e count for a 254-bit field.
- hash = Miyaguchi-Preneel, `h <- E_h(m) + h + m`, h_0 = 0 (the gnark construction as we remember it). NOT bit-compatible with gnark: the round constants are a Keccak-256 chain from OUR seed (`pqz-bl lhcpm MiMC-5 BN254 round constants v1`). Cost per round is the same.
- the audit hashes 4 elements = 440 rounds.
- `H(pk_G)` and `cm_T` are computed in setup (see 3).

Groth16 (`src/circuits.rs`): arkworks `ark-groth16 =0.4.0` on `ark-bn254 =0.4.0`, no `parallel` feature (`cargo tree` shows no rayon), no `asm` feature. Setup (`circuit_specific_setup`), `prepare_verifying_key`, the witnesses and the public-input vectors are made before timing.

## 2. Parameters taken from the paper (inputs, not results)
| Parameter | Value | Source |
|---|---|---|
| RLWE ring degree n | 4096 | findings C (TABLE IMAGE p.7620; text l.689, 781-782) |
| q | about 2^108 (ours: 108-bit product of two 54-bit primes) | same |
| sigma | 3.2 | same |
| plaintext modulus t | about 2^28 (ours: exactly 2^28) | same; the exact t is OURS |
| SIS dimensions for the cached preimage | n = 256, m = 8448, q = 2^32 | findings C (TABLE IMAGE); only the SHAPE of `delta_G` |
| Mint constraints | 2,676 | findings D (TABLE IMAGE p.7615) |
| Transfer constraints | 8,786 | same |
| Transfer public inputs | 13 | l.349, l.464 (used only for the extra verify row) |
Table images (p.7615, p.7620) were not re-checked by us; we rely on findings-lhcpm.md for them. Choices that are OURS: the BFV scheme, exact t = 2^28, the two primes, MiMC constants, cache size 1024, 16 distinct ciphertexts rotated over the runs, ternary secret key.

## 3. Simplifications and their direction
- `H(pk_G)` is computed ONCE in setup (MiMC over the 4 x 4096 residue words of pk_G) and `cm_T` (paper: H(A_G), l.311) is a random field element: A_G is not generated because TrapGen is not run. Hashing pk_G inside every audit would add thousands of MiMC blocks. Favours L-HCPM (assumes the regulator caches its own key hash; the paper's contract compares `regulatorPKHash` as a public input, on-chain check near l.480).
- The hot in-memory cache has 1024 entries, no eviction, no disk, no network. Favours L-HCPM.
- Ciphertext is stored in coefficient form (so c1 needs a forward NTT). A library that keeps ciphertexts in NTT form would save one transform per limb. Slightly disfavours L-HCPM.
- Scalar NTT code, no AVX; a tuned library (the paper used Lattigo v6.1.1 in Go, l.697-701) may be faster or slower. Direction unknown.
- Our decryption cost is OUR implementation of a BFV-style decryption. The paper gives no formula or complexity for RLWE.Dec (findings C: "NTT" has 0 hits in the text).

## 4. Stand-in circuits (IMPORTANT)
The paper's own circuits (MintProof, TransferProof, ...) are NOT available. The circuit used here is a STAND-IN: a MiMC-style chain with public inputs x0, k, out and 3 constraints per round (t^2, t^4, t^4 * t, each a real R1CS multiplication), constants cycling over the 110 MiMC constants. The paper's constraint counts are used as PARAMETERS, not as results:
- Mint stand-in: 892 rounds = 2,676 constraints exactly (checked in a test and at setup: `ConstraintSystem::num_constraints()` and `is_satisfied()`).
- Transfer stand-in: 2,928 rounds + 2 boolean constraints (b*b = b with b = 0) = 8,786 constraints exactly.
- Proving time depends on the constraint count, the number of witness/instance variables and the QAP domain (arkworks pads: domain 4096 for Mint, 16384 for Transfer, counting the extra input constraints), not on what the circuit means. The real Mint/Transfer circuits have a different sparsity pattern, public-input count (Transfer has 13) and variable count, so these times indicate the order of magnitude for that size only.
- Groth16 verification time depends on the number of public inputs (one G1 scalar multiplication each in the input MSM) and on the fixed pairing work, NOT on the number of constraints (paper l.807-809 says the same). The verify stage therefore uses a tiny circuit (4 rounds = 12 constraints) with 3 public inputs; the full run adds a 13-input row (the paper's Transfer public-input count) as an input-count sensitivity check.
- Fresh randomness: each prove run draws new Groth16 r, s; the 30 witnesses (x0, k) are different. Verify rotates over 8 pre-made proofs.
- arkworks vs gnark: different libraries, language and curve backend; arkworks here is built without `asm` and without `parallel`. The proving numbers are for single-thread arkworks on this machine and must not be compared with the paper's gnark/Apple M3 numbers.

## 5. NOT RUN (and not timed, not estimated)
- The cache MISS path: `SamplePre(A_G, T_G, H(txId), sigma)` with n = 256, m = 8448 (trapdoor Gaussian preimage sampling), l.496-504 step 3. A miss returns `AuditError::CacheMiss`.
- `TrapGen` (key and trapdoor generation, Theorem 4).
- Everything else in L-HCPM outside the audit: LT-Share, the other circuits (Burn, Convert), the smart contract, the Event/Regulator services, gas.
Any L-HCPM audit figure from this crate is therefore a cache-hit figure only. The paper itself separates the hit path O(1) and the miss path O(nm) (l.441-442); the miss path is expected to cost much more and is missing here.

## 6. Framing notes (for the paper text)
- The regulator's audit (Algorithm 2) verifies NO zero-knowledge proof; Groth16 verification is done by the smart contract at transaction time (l.480). `groth16_verify` is reported as a separate stage, not as part of `audit_hit`.
- `groth16_prove_*` is a per-transaction prover cost, not an audit cost.
- Single-thread arkworks; PQZ-Audit proof generation uses all cores by default: disclose.
- All runs are in memory on one machine in one session; no network, no blockchain, no disk.

## 8. SPEC-w16 additions: `--q`, `--params-tag`, `--runs-big`, `--big-above`, `--only-q` (work16)
Default behaviour (no new flag) is unchanged: same stages, same params strings, same instance count (16 / 4 in `--quick`).
- `--q LIST` (comma list, e.g. `1,10,25,50,100,200`): adds, after `audit_hit` and after `groth16_verify`, the stages `audit_hit_q` and `groth16_verify_q`. The Mint and Transfer prove stages are unchanged and still run (use `--only-q` to skip them and the base `audit_hit` / `groth16_verify` rows).
- `audit_hit_q`: `ms` = total time of Q audits (Algorithm 2 cache hit, as in section 1), run one after the other in one thread. Each audit has its own txId (cache lookup), its own ciphertext (131,072 B), its own `r_shared` and `cm_G`; nothing is shared or reused between the Q audits. When `--q` is given, setup makes max(16, max Q) instances (all before timing), so Q different ciphertexts always exist. Run i uses instances (i*Q + k) mod len, k = 0..Q-1, so different runs use different windows when len > Q. All of it is untimed setup: keys, ciphertexts, cache fill. Check after the timer: every one of the Q results equals the true m of its instance.
- `groth16_verify_q`: same circuit as `groth16_verify` (4-round chain, 3 public inputs, prepared vk), `max(8, max Q)` different proofs made before timing, Q verified per timed run with `verify_with_processed_vk`; no early exit; the check is that all Q verified (count == Q). Verification cost does not depend on the number of constraints (section 4), so this is the cost of Q on-chain-style verifications for a 3-input statement. As before it is NOT part of the regulator audit (section 6).
- No coverage `--cov` for L-HCPM: its audit is per transaction (one audit = one transaction), so Q audits are Q transactions. Matching "1000 records per audit" to PQZ-Audit has no counterpart here: one L-HCPM audit covers ONE transaction. Reading the plot as "q audits of 1000 records for PQZ-Audit vs q single-transaction audits for L-HCPM" is the comparison the SPEC asks for; state this when it is shown. Covering 1000 records with L-HCPM would be 1000 audits per PQZ-Audit audit (see `audit_hit_q` with Q = 1000, not run here).
- `--runs-big R` (default 5) and `--big-above X` (default 2000): when Q > X (L-HCPM has no cov; work per run = Q audits), that stage uses R timed runs and 1 warm-up and `;runs=R` is appended to its params. With the default X = 2000 this never triggers for Q <= 200; the smoke/cloud grid used the normal `--runs`.
- `--params-tag TAG`: appended as `;TAG` to the params of EVERY row (comma not allowed), so different sweeps never collide in a merged CSV.
- Cache-hit audit only (section 5 still applies): a cached `delta_G` per audit; the miss path is not run. Single thread. Q audits are sequential, no batching, no pipelining across audits (the paper gives none). Favours neither side beyond what sections 3 and 5 say; the cache holds 1024 + Q entries (64 + Q in `--quick`), a bigger hash map has more cache pressure than the single-audit row but all lookups are hits.
- The warm-up is the usual 3 (or 1 in `--quick`), each warm-up is also a whole Q-audit run.

## 9. e405 addition: `--threads T` (work20; default 1 = the code path of section 8, unchanged)
- Applies ONLY to `audit_hit_q` and `groth16_prove_mint_q`. T > 1: the q items are split into T contiguous ranges (sizes differ by at most 1) and run by T scoped worker threads (`src/par.rs`, no unsafe). The workers (each with its OWN `StdRng::from_entropy()` for Mint) exist and are ready before the timer; a `Barrier` releases them together; the time is the first worker's start to the last worker's end (thread creation and join are not timed). Item k uses the same instance/witness as in the single-thread path ((start + k) mod len); each proof has fresh randomness; nothing is batched or shared between items; every output is checked after the timer. `params` gets `;threads=T`.
- This is a PARALLEL RUN OF INDEPENDENT items, not a parallel L-HCPM: the paper gives no parallel version, and the arkworks crates here are built without `parallel`, so one proof is still one thread. With T > q the extra workers idle. All workers read one shared proving key / cache: memory-bandwidth and cache effects are real and part of the measurement. On the cloud instance 32 vCPU are about 16 physical cores with hyper-threading, so S(32) is not expected to be 32.
- Tests added: `split_ranges...`, `run_split...`, `audit_q_threads_t4...`, `prove_q_threads_t4...` (16 pass, 1 ignored).

## 7. Tests (`cargo test --release`)
primes and q (108 bits); NTT equals schoolbook negacyclic product and round-trips; decryption returns all 4096 coefficients exactly (and a wrong secret key does not); audit accepts the honest case and fails on a wrong cm, a wrong r_shared, a ciphertext of another transaction and a cache miss; MiMC deterministic and input-sensitive; circuit sizes exactly 2,676 and 8,786 and satisfied; Groth16 verify accepts the honest proof (3 and 13 public inputs), rejects every single tampered public input, a proof of another statement and random inputs; a Mint-size proof verifies and does not verify against another statement. New (SPEC-w16): `audit_q_honest_passes_and_tampered_fails` (Q distinct txIds and ciphertexts; all Q honest audits return their m, also for a window wrapping round the list; one tampered `cm_G` makes exactly that audit fail and the other Q-1 pass); `groth16_verify_q_honest_passes_and_tampered_fails` (all Q verify; one tampered public input gives Q-1; two swapped proofs give Q-2). `cargo test --release breakdown -- --ignored --nocapture` prints the time split of one decryption (informational).
