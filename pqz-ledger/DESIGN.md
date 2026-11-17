# DESIGN: pqz-ledger (PROVISIONAL)

All choices are provisional (professor has not chosen the ledger). Paper = `journal2/pqz-audit-journal-main11-professor.tex`
(read-only). Plan = `journal2/EXPERIMENT-PLAN-main11.md`. Nothing in the paper was edited; mismatches are listed in section 5.

## 1. Ledger simulation

- Validators: n >= 4, f = floor((n-1)/3), quorum = floor((n+f)/2)+1 (n=4: 3, n=5: 4, n=7: 5, n=10: 7, n=13: 9). Default n = 4.
- Block: header (height, prev hash, tx Merkle root, state Merkle root, proposer, n_txs; 110 B) + transactions + QC
  (quorum x (2 B validator index + 3309 B ML-DSA-65 signature)). Leader of height h = h mod n.
- Execution is check-then-write per transaction with a journal (begin / commit / rollback). A rejected transaction is not
  in the block. Every validator re-executes and must reach the leader's state root, else it does not vote.
- State Omega-store: key-sorted map, root = Merkle root over leaves H(0x00 || key || value), nodes H(0x01 || l || r)
  (RFC 6962 style), recomputed over all entries per block (O(|state|), not a sparse tree). The path check does not bind the
  tree size; size comes from an authenticated source (G_e in the signed A_e), noted in `hashing.rs`.
- Transactions: `Anchor` (routine epoch anchor), `Authorize` (RID: none -> Authorized), `Consume` (Authorized -> Consumed),
  `CommitRecord` (internal per-record baseline only).
- Contract rules (paper Phase 4, 5, 7):
  - Anchor: e = e_last+1, p_e = Gamma_last, Omega_prev = Omega_last, State[e] unset, Omega recomputed as
    H("PQZA-CAAS" || e || Gamma_e || R_pol || v_auth).
  - Authorize: Priv[RID] unset; State[e] exists; presented Omega equals State[e].Omega; Current mode needs e = e_last.
  - Consume: Priv[RID] = Authorized; predicate hash equals the one stored (see mismatch M3).
- Client read: `read_state` + `verify_read` = QC of the latest header (signatures from >= quorum validators) + Merkle path.
- Bytes are counted as header, tx_body, tx_sig, qc, from the real encodings (`block_bytes_formula` reproduces them exactly; tested).
- `crit_path_ns` (derived): leader time + (quorum-1)-th fastest other validator + QC verification.

## 2. Experiments

- Exp 5(a): q transactions are submitted at one instant, in blocks of at most 100. Latency per transaction = time from submit to
  commit of its block (so later blocks wait for earlier ones). Throughput = q / total time. Systems: `pqz` (q x Authorize) and
  `per_record_baseline` (q x CommitRecord). The paper does not define a "blockchain request"; this is our reading (M5).
- Exp 5(b): `routine_anchor` (write), `routine_read` (light-client read, verified), `authorize`, `consume`: one operation per run, fresh ledger with 3 anchored epochs.
- Bytes per epoch vs N: pqz commits one anchor (root only; N only changes the root), baseline commits N records.
- Timed region = `Ledger::submit` (or read + verify). Client-side signing, ledger setup and key generation are outside it.

## 3. Threshold layer: T_priv, T_rec, T_disc

The paper has three independent threshold key domains with the same (t,n), 1 < t <= n (Phase 1 step 3, Eq. tac-setup,
he-threshold-share, fd-setup). The names T_priv, T_rec, T_disc come from the plan, not from the paper.

| Plan name | Paper object | Implemented | Excluded (needs a decision or a proof system) |
|---|---|---|---|
| T_priv | TA_PQ.Setup / Approve / Combine; Auth_TAC (Phase 5 step 3) | Shamir sharing of a 32 B domain secret: `setup_deal`, `combine` (>= t distinct shares, check hash). Provisional variant: n independent ML-DSA-65 approvals over B_Q, combine = verify t signatures (`multisig`) | threshold signature scheme; public verification of Auth_TAC inside the contract |
| T_rec | HE_PQ.Share(sk_HE,t,n), PartDec, Combine (Phase 1 step 3, Phase 7 step 2) | Shamir sharing of a secret of 32, 1024, 16384 B (stand-ins: the HE key size is unknown) | HE scheme, partial decryption with noise, binding xi_Q |
| T_disc | FD_PQ.Setup / ShareOpen / Combine (Phase 7 step 3) | Shamir sharing of a 32 B domain secret | wrapping of record keys (FD_PQ.Protect), recipient KEM, binding zeta_{Q,i} |

- Field: GF(p), p = 2^127 - 1 (Mersenne). Secrets are cut into 15-byte chunks (120 bits < p); a 32 B secret = 3 field elements per share;
  x = 1..n. Each domain has its own ChaCha20 stream derived from the benchmark seed (independent dealings). Seeds are for benchmarks only.
- Combine uses the first t shares given, checks index range, duplicates and length, and compares H("PQZ-THR-CHECK" || domain || secret) with
  the public check. Plain Shamir has no robustness (no VSS): a wrong share is detected, not corrected or attributed. The check hash is
  safe only for high-entropy secrets (they are random).
- A Shamir reconstruction hands the secret to the combiner. A real threshold signature or threshold decryption never does. The measured
  times are the cost of sharing and reconstruction only: a lower bound for the real operations.
- Not measured: member-side `Approve` / `PartDec` / `ShareOpen` (depend on the schemes). For multisig, `approve_one_member` is one ML-DSA-65 signature.

## 4. Rejection harness

Attacker model: a registered submitter (valid transaction key); only contract rules and the verifier can stop it.
Trials of one variant use distinct RIDs and are committed in batches of up to 100 per block. Each variant has CONTROL operations
(honest counterparts) which must be accepted, so a harness that rejects everything is caught.

| Class | Variant | Rejected by (reason string) | Defence flag |
|---|---|---|---|
| replay of a consumed RID_Q | replay_consume | rid_not_in_authorized_state | single_use |
| | reauthorize_after_consume | rid_already_reserved | reservation_unique |
| | consume_unauthorized | rid_not_in_authorized_state | single_use |
| wrong canonical state | wrong_omega_flipbit | omega_not_canonical_state | omega_equality |
| | wrong_omega_other_epoch (genuine Omega of an older epoch) | omega_not_canonical_state | omega_equality |
| | wrong_omega_forked_policy (Omega over a forked policy root) | omega_not_canonical_state | omega_equality |
| | stale_epoch_current (right Omega, old epoch, Current mode) | epoch_not_current | current_freshness |
| predicate changed after authorization | predicate_changed (consume with another predicate hash) | predicate_hash_mismatch | predicate_binding (M3) |
| | predicate_changed_new_rid (RID re-derived for the changed predicate) | rid_not_in_authorized_state | single_use |
| authenticated block omitted | omit_block (one of G_e blocks left out, honest A_e and sigma_e) | block_domain_not_covered | block_cover |
| | forged_shorter_epoch (self-consistent epoch with G_e-1 blocks, genuine sigma_e) | gamma_not_matching_ledger | anchor_binding |

Mutation tests (feature `mutation`, also in unit tests): switch one flag off, run the whole harness; exactly the variants in the last column
must become accepted (all trials) and all others stay at 0 accepted (`attacks::EXPECTED_FLIPS`). The omission check builds a self-contained
chain: block commitment B = H(e || g || q_start || q_next || count || R_rec || H(S)), epoch root R_e = Merkle root of the B leaves,
A_e = (e, R_e, N_e, G_e, t_e, p_e), sigma_e = ML-DSA-65 over H(A_e), Gamma_e = H(A_e || sigma_e). The verifier reads State[e] from the ledger
with a QC proof, checks Gamma_e and sigma_e (anchor_binding), Merkle membership of each presented block, and that all blocks 1..G_e are present,
contiguous and sum to N_e (block_cover). This is the ledger and Merkle side of Corollary 1. The PQZK relation BlockCover is NOT implemented.

## 5. Mismatches and open points (flagged, paper not changed)

- M1. Paper Eq. (anchor-transaction) `Tx_e = (e, Gamma_e, R_pol, v_auth, Omega_e, Omega_{e-1})` has no p_e, but the contract is said to check p_e = Gamma_last (paper around l. 1373). We added p_e to the transaction.
- M2. T_priv, T_rec, T_disc are not names in the paper (TA_PQ, HE_PQ.Share, FD_PQ are). Paper Eq. (tac-authorization) says "after public verification"; no scheme is given, so the contract here does not verify Auth_TAC. With the multisig variant that would add t ML-DSA verifications per validator (see `threshold.csv`, `combine_verify_t`).
- M3. The paper's Consume check is only Priv[RID] = Authorized (Eq. privileged-state-check). It compares no predicate hash on-chain; a changed predicate changes B_Q and so RID_Q, and the PQZK proof binds C_Q. Our contract additionally stores the predicate hash and compares it (`predicate_binding`): an addition of ours. The variant `predicate_changed_new_rid` is the paper's literal route; `predicate_changed` tests our addition. Without the addition, a consume of an Authorized RID with any predicate is accepted by the ledger and relies on the proof.
- M4. Paper Phase 7: the contract transitions to Consumed "after validating the accepted execution proof". Here Consume carries no proof, and proof verification is not in any ledger timing. If the contract must verify the PQZK proof on-chain, consume latency and bytes change.
- M5. Exp 5 does not define "blockchain request" nor the native operation of Dong et al. Our reading: pqz = Authorize, baseline = CommitRecord. Dong et al. is not implemented.
- M6. Exp 5(b) says "routine canonical-state access". The ledger-side routine operation of Phase 4 is the anchor (a write); an access is a read. Both are measured (`routine_anchor`, `routine_read`); the figure needs one choice.
- M7. The plan lists 12 points for E5(a), 3 for E5(b). We emit 12 for E5(a) and 4 operations for E5(b) (routine counted twice).
- M8. Corollary 1 relies on BlockCover inside the PQZK relation; here coverage is checked directly on headers (no proof).
- M9. Epoch size (G_e, records per block) and N are synthetic; the paper fixes none. The harness uses G_e = 16, 4 records per block, 3 anchored epochs.
- M10. Exp 5(c): per-record baseline at N = 1e5 and 1e6 is a byte formula (checked against measurement at small N), not an executed run.
