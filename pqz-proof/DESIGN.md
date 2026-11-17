# DESIGN: PROVISIONAL hash-based STARK prototype of R_RC, R_Auth, R_Exec

Status: PROVISIONAL. The professor has not chosen the proof system for PQZ-Audit
(`journal2/EXPERIMENT-PLAN-main11.md`, open decision 1). This crate uses winterfell 0.13.1 (hash-based STARK, FRI)
only to get a first measurement of prove time, verify time, proof size and prover memory (plan: Exp 4 and Exp 6).
Nothing here is a claim about the final system. Source of the relations: `journal2/pqz-audit-journal-main11-professor.tex`
(read-only), Phase 3 (record commitment, statement x^RC), Phase 5 (R_Auth, B_Q, C_Q), Phase 6 (R_Exec).

Read section 5 first: it lists what this prototype does NOT prove and what that costs the paper's claim.

## 0. Common construction

- Field: winterfell `f64` base field, p = 2^64 - 2^32 + 1, proofs over its quadratic extension.
- In-circuit hash: Rescue Prime `Rp64_256` from winter-crypto (state 12, rate 8, capacity 4, 7 rounds, S-box x^7), 4-element
  (about 256-bit) digests. One permutation = 8 trace rows (7 round rows plus 1 link row). The AIR round constraint avoids the inverse
  S-box: (INV_MDS (next - ARK2))^7 = MDS cur^7 + ARK1, degree 7.
- Proof commitment hash and Fiat-Shamir: `Sha3_256` (winterfell `DefaultRandomCoin`, Merkle tree of SHA3-256). This is the only place
  SHA3 is used.
- Proof options (`src/prove.rs::default_options`): 40 queries, blowup 8, grinding 16 bits, quadratic extension, FRI folding 8, FRI
  remainder degree 31. The security bits printed by `proofbench` and stored in `raw.csv` are the library's own estimates
  (`Proof::conjectured_security` and `Proof::proven_security`) for these options. The verifier rejects proofs whose conjectured
  estimate is below 80 bits (`AcceptableOptions::MinConjecturedSecurity`).
- Every relation has a public input, a trace (witness) and an AIR. A wrong witness gives a trace that violates a constraint; the
  verifier rejects the proof (tests in `tests/relations.rs`, run with `cargo test --release`).
- Sponge chain instead of Merkle tree for the record set (section 1): an AIR is uniform over rows, so Merkle recomputation with
  non-local links is expensive to express. The chain absorbs the stream (header word, then record words) one word per permutation.

Stream words: 8 field elements `[w0..w7]`. `w7` is the header flag (1 = header or padding word, 0 = record).
Header word: `[e, g, m_b, PID, seq_start_g, 0, 0, 1]` (epoch, block index, number of records in the block, producer id, sequence
number of the first record). Record word: `[PID, e, seq, id, v, b, tag, 0]`. In this prototype `v` is the attribute the predicate
reads (a 32-bit value), `b` is the value that is summed, `tag` stands for the record's commitment/ciphertext material
(random field element, not constrained further).

Chain digest: sponge with capacity `[DOM_CHAIN, n_groups, 0, 0]` where `n_groups` = number of words (so the word count is bound
into the digest); for every word, `rate += word; permute`; digest = rate[0..4] after the last permutation. The reference
implementation of this digest is `data::chain_digest` (library permutation, independent of the circuit).

## 1. R_RC (batched record commitment and block structure)

Paper: pi_i^RC per record proves that the protected representations (AE ciphertext, PS index entry, HE ciphertext) encode the
same attributes as the committed record under the same authenticated metadata (PID, e, seq, ID_i).

What this AIR proves (file `src/rc.rs`, width 26, public input `RcPublic`):

- Public: `digest` D (chain digest of the whole stream), `n_blocks`, `block_size`, and the first header word `header0`.
- Private: all words of the stream.
- Statement: there is a word stream with D as its chain digest (so the digest binds the exact content and the word count
  n_blocks*(block_size+1)) such that
  1. every word's flag is 0 or 1;
  2. every record word has the same PID and epoch as the preceding header (carried in K columns), and its sequence number is the previous
     one plus 1 (the header carries `seq_start - 1` forward, so sequence numbers are continuous across blocks);
  3. every real header announces exactly `block_size` records (`m_b` is `block_size`, or 0 for the padding word), a header can only follow a
     block that has exactly `m_b` records (counter `cnt`), and the number of real headers equals `n_blocks` (counter `hdr`);
  4. the last block is complete (`cnt = mb = block_size` at the last real row).
  Together with the fixed word count this gives exactly `n_blocks * block_size` records. Test: `rc_wrong_record_count_rejected`,
  `rc_dropped_block_with_original_public_rejected`, `rc_merged_blocks_rejected`.

What it does NOT prove: that `tag` (the stand-in for the ciphertext/commitment material) is related to `v` and `b` in any way; that
AE, PS or HE ciphertexts exist or are consistent; the per-record commitment C_i opening; the ML-DSA record signature sigma_i^LP; the
LP credential; the epoch and identifier admissibility against the ledger. Those need relations over the AE/PS/HE schemes, which are
open decisions.

Cost of the deviation: the paper's R_RC is a per-record relation of unknown size (it depends on the HE and PS schemes). This one is a
batched structure check whose cost grows with the number of records through the hash chain only (about one permutation, 8 rows,
per word, plus one per block header). It is a lower bound on a real R_RC, not an estimate of it.

## 2. R_Auth (private authorization and canonical-state binding)

Paper: pi_Q^Auth proves possession of a valid AA-issued credential, S_Q in S_a, E_Q in E_a, [t_s,t_e] in T_a, P_sel and Agg_Q in P_a,
and the privilege level, without revealing the complete policy; the verifier checks the policy leaf against the canonical PB state
(R^pol, v^auth); B_Q binds the request to (D_Q, UID_a, v_a, v^auth, R^pol, Omega).

What this AIR proves (file `src/auth.rs`, width 34, public input `AuthPublic`):

- Public: policy-tree depth d, policy root `R_pol`, binding hash `B_Q`, request digest `D_Q`, `Omega`, `UID_a`, `v_a`, `v_auth`, the request
  scope (spatial range, epoch range, time range, selected predicate code p, required level).
- Private: the policy leaf (12 field elements: UID, v_a, spatial interval, epoch interval, time interval, predicate-code interval,
  level, blinding), its position and the d sibling digests.
- Statement:
  1. the leaf hashes (2 permutations) to a value whose Merkle path (d merge permutations, domain-separated, direction bit boolean)
     ends at `R_pol`; the leaf's UID and v_a equal the public ones;
  2. the request scope lies inside the leaf: for 8 interval ends (lo <= q_lo, q_hi <= hi for spatial, epoch, time) plus p in
     [P_lo, P_hi], and level_Q <= level_a, the difference of the two sides is decomposed into 32 bits (4 bits per row, 9 inequalities);
  3. `B_Q = H(D_Q, UID, v_a, v_auth, R_pol, Omega)` with a domain tag (2 permutations, all inputs public and asserted).
- Tests: scope outside the policy, level too low, wrong sibling, tampered `R_pol`, `B_Q`, `D_Q`, `v_auth`, scope and UID, tampered trace.

What it does NOT prove: credential possession (the AA's signature or credential is replaced by membership of the leaf in the policy tree
under the public root; there is no ML-DSA verification); the request signature sigma_Q; nonce freshness and expiry; that `R_pol` and
`v_auth` are the current ledger values (the verifier must check this against the ledger itself); that `D_Q` is the digest of a real
request; Agg_Q membership; set (not interval) containment. The paper uses sets S_a, E_a, T_a, P_a; here they are intervals over 32-bit
codes, which is a modelling choice that favours the AIR (an interval is one comparison pair, a set is a membership proof).

## 3. R_Exec (predicate execution over the retained records)

Paper: R_Exec = CtxBind and StateValid and BlockCover and PruneValid and PredValid and Complete and ResultValid.

What this AIR proves (file `src/exec.rs`, width 33, public input `ExecPublic`):

- Public: `digest` D (the same chain digest as R_RC), `n_blocks`, `block_size`, predicate threshold `theta` (public, < 2^32), the claimed
  `count` and `sum`, and the context `ctx` (a 4-element value standing for C_Q).
- Private: all words of the stream (again as witness).
- Statement: for the stream with digest D, `count` = number of record words with `v >= theta` and `sum` = sum of `b` over them (as field
  elements, so modulo p; in range for the sizes used). Every record's `v` is range-checked to 32 bits, and the match bit `m` is checked by
  decomposing `d = m (v - theta) + (1 - m)(theta - 1 - v)` into 32 bits, 4 bits per row. Header and padding words (flag 1) never match.
  Running accumulators `cnt` and `sum` are updated once per record and asserted at the last real row.
- `ctx` is not used by any constraint. It is bound only because the public input is hashed into the Fiat-Shamir transcript, so a proof made
  for one `ctx` does not verify for another (test `exec_tampered_public_rejected`). This is a binding by transcript, not a relation.

What it does NOT prove: that the retained set equals the set of records selected by the (private) search token and the block summaries
(PruneValid, BlockCover over epochs: here the circuit reads all N words in digest order and there is no pruning, so the prover work
is linear in N, not in the candidate set); a private predicate (theta is public); the HE aggregation (count and sum are plaintext
stand-ins for Agg over ciphertexts; there is no relation to HE ciphertexts); that each record is consistent with its ciphertexts
(that is R_RC's job in the paper); the Merkle/EAPAT state binding of the paper (here the stream digest D is the only commitment); that the
digest D is the one the ledger holds. Without R_RC the stream structure (which words are headers) is not checked by R_Exec itself: the
words are bound to D, so only a stream with digest D can be used, but D could have been built from a badly formed stream. The two proofs
must therefore be verified together on the same D (the benchmark's "bundle" does this).

## 4. API

`prove_rc`, `verify_rc`; `prove_auth`, `verify_auth`, `honest_auth_instance`; `prove_exec`, `verify_exec`, `exec_public` (all in `src/`).
Three separate proofs, not one merged proof. Reason: the three relations have different shapes and sizes (R_Auth does not depend on N_Q),
and the paper's Phase 7 verifies three proofs. Cost is reported per relation and as a "bundle" (the three verified one after another).
Public inputs are checked by the verifier by recomputation only where the AIR asserts them; everything else (for example that `digest` is
the ledger's digest) is outside the proof.

## 5. Deviations from the paper and what they cost the claim

1. The in-circuit hash is Rescue Prime (algebraic), not SHA3 or SHA-256. The paper's H and its commitments are SHA3-based. A proof about
   a SHA3 tree cannot be reused: the paper's digests are not the digests proven here. Rescue was chosen because it costs 8 rows per
   permutation, while Keccak-f in an AIR needs a bit-level or lookup-heavy layout of many more rows (not measured here, so no ratio is
   claimed). The consequence for the claim: measured prove time and proof size are for an arithmetization-friendly hash. A system that
   must prove statements about the SHA3-based EAPAT or about records hashed with SHA3 pays more, by an amount this crate does not
   measure. The measured numbers are therefore a lower bound for "same relation, SHA3 inside", and not comparable to the paper's cost
   model without that caveat. Rescue Prime is also much younger than SHA3 and has had less cryptanalysis; the library's constants are used
   as they are.
2. No zero-knowledge. Winterfell 0.13.1 has no zero-knowledge mode (no blinding of the trace); the proof opens trace rows at the query
   positions, so witness values can leak. In R_Auth the policy leaf is held constant in 12 columns, so every opened row shows it. The
   proofs here are succinct arguments of knowledge, not ZK proofs. The paper's claims "without revealing the complete authorization policy"
   and the simulation argument for the PQZK relations do not hold for this prototype. Making it ZK needs trace randomization and extra
   blowup; its cost is not included in any measurement.
3. Sponge chain instead of a Merkle tree for the record set. Consequences: (a) the EAPAT as a tree with block summaries and pruning is not
   modelled; (b) opening one record from the digest costs O(N) (chain), not O(log N); (c) R_Exec reads all N words, so its prover cost is
   linear in the retained set N_Q only because the benchmark builds a stream of N_Q retained records. A real system proves the pruned set
   against a tree, so its cost depends on how the candidate set is authenticated; (d) one permutation per record versus about two per record
   for a Merkle tree (leaf plus internal node), so the chain is cheaper than a tree by that factor in the hash part.
4. HE aggregation, AE, PS and ML-DSA are not in the circuits (sections 1 to 3). Count and sum over plaintext values are stand-ins.
5. The predicate is public and a single comparison (`v >= theta`). The paper's predicate is private. A private theta would be an extra
   witness and a different binding.
6. The sizes: records are 8-field-element words with a 32-bit `v`; padding to a power of two trace length (minimum 32 rows) is part of the
   measured cost.
7. Security: the library reports conjectured security for the chosen options (its estimate, assuming its conjectured FRI soundness) and a
   separately printed proven bound. The code and `raw.csv` print both; the README gives the numbers. "Post-quantum" is claimed only in the
   sense that the construction uses only hash functions, Merkle trees and FRI, and no group-based assumption. The printed bit levels are
   the library's estimates; we have not checked how they treat quantum adversaries, so they must not be quoted as a post-quantum security
   level.

## 6. Trace layouts (for review)

R_RC (width 26): columns 0..12 state, 12..20 the word absorbed by the next group (read on link rows only), 20..23 K (PID, epoch,
sequence), 23 cnt, 24 mb, 25 hdr. Periodic columns of period 8: round selector fr (rows 0..6), link selector fl (row 7), 12 + 12
round constants. Row 7 of each group is the link row: capacity kept, rate += next word.

R_Exec (width 33): 0..12 state, 12..20 next word, 20 m, 21 accD, 22 accV, 23..27 and 27..31 4-bit chunks of d and v, 31 cnt, 32 sum.
The decomposition runs over the 8 rows of the group before the record's word is absorbed (4 bits per row, 8 rows give 32 bits).

R_Auth (width 34): 0..12 state, 12..24 leaf (constant), 24 direction bit, 25..29 sibling, 29..33 bit chunk, 33 accumulator. Groups: 2 leaf,
d merge, 2 binding, 9 range checks, then padding. Selectors are full-length periodic columns because the groups differ in role.

Degrees are declared with `TransitionConstraintDegree::with_cycles`; a debug build (`cargo test`) validates them against the actual
degrees (winterfell checks this only in debug builds), and `cargo test --release` runs the same tests with the release prover.

## 7. R_Cover (BlockCover and PruneValid over the block summaries)

Added for review R1 of work5 (task `TASK-cover.md`). The paper's R_Exec contains `BlockCover` ("every g in D_e is accounted for as
pruned or evaluated") and `PruneValid` ("PS.BlockEval(TK_Q, S_{e,g}) = 0 for a pruned block"). `R_Exec` in section 3 has neither. This
section adds a separate relation `R_Cover` (file `src/cover.rs`, width 123, public input `CoverPublic`). It is a separate proof; the
retained blocks are evaluated by the existing `R_Exec` on the retained records only, and that is not re-proven here.

### Statement

Public: `d_s` (chain digest D_S of the G block summaries), `d_flags` (digest D_flags of the flag vector), `g` (G), `k` (number of probed
Bloom positions per block; fixed to 7 in the AIR and checked when the AIR is built), `r` (number of retained blocks).
Witness: for every block g = 1..G the summary S_g (W = 8 words, each below 2^32, so a block filter has 256 bits; bit position p is bit
`p mod 32` of word `p div 32`), the flag f_g in {0,1} (1 = retained), and the k probed positions p_1..p_k (the same k positions for all
blocks; in the prototype they are witness values, not derived from a token).

Constraints (all enforced by the AIR):
1. Summary chain. Sponge with capacity `[DOM_CHAIN, 2G, 0, 0]` over the 2G words `H_1, S_1, H_2, S_2, ..., H_G, S_G`, where the header
   word is `H_g = [DOM_HDR, g, 0, 0, 0, 0, 0, 0]`. Its digest (rate[0..4] after the last permutation) equals the public D_S. The header
   words `H_g` are constrained from the block counter (see 2), so the block index is inside the digest.
2. Coverage. One block = 16 rows = 2 permutations (header group, summary group). A counter column `GG` starts at 1 (asserted), grows by
   exactly 1 at every block boundary (transition), and the assertion `GG = G` is placed at the last row of block G (row 16G-1), where
   the digest assertions are also placed. The header word absorbed for block g+1 must equal `[DOM_HDR, GG+1, 0...]`. So no block can be
   dropped or repeated, and exactly G blocks are covered. Blocks after G (padding up to the power-of-two trace length) are virtual
   blocks with zero summary and flag 1; they sit after the asserted rows and cannot change any asserted value.
3. Flags. `F` is boolean at every row, constant inside a block, and a running count `C` (retained blocks before this block) with
   `CI = C + F` gives the inclusive count; `CI` at row 16G-1 equals the public `r`.
4. PruneValid. For each block, rows 0..6 of the header group are probe rows (row j holds the j-th probe). At a probe row: `sel` is a
   one-hot over the 8 words, `oh` is a one-hot over the 32 bit positions of a word, `bits` is the 32-bit decomposition of the selected
   word `sum_i sel_i * S_g[i]` (so a probed word must be below 2^32), the probed position `32*widx + t` equals the constant column
   `P_j` (the `P_j` columns are constant over the whole trace, which gives the same positions in all blocks), and
   `(1 - F) * sum_t oh_t * bits_t = 0`: a block with f = 0 must have a 0 at EVERY probed position (see "Strength of the check").
   Retained blocks (F = 1) need no bit condition. The summary words seen at the probe rows are forced to equal the words absorbed in the
   chain by a hold constraint on the `R1` columns inside each group (without it the prover could show a different word at the probe
   rows than the one that is absorbed; test `cover_probe_view_forgery_rejected`).
5. D_flags. A second sponge (capacity `[DOM_FLAGS, 2G, 0, 0]`, run in parallel on the same rows) absorbs, per block, the zero word and the
   word `[f_g, 0, 0, 0, 0, 0, 0, 0]`, with `f_g` tied to the column `F`. Its digest equals the public D_flags.

Strength of the check. The task text asks for "f_g = 0 implies every probed bit is 0". That is stronger than the Bloom semantics of the
paper (BlockEval = 0 holds as soon as ONE probed bit is 0). The implementation follows the task text. It is sound (all-zero implies
some-zero) but not complete for honest pruning: an honest block with some probed bits 0 and some 1 can be pruned in the paper but
cannot be proven pruned here. The measured cost is for this stronger check; the "at least one zero" check needs a product over the k
probes and was not built or measured.

### What R_Cover does NOT prove

- That the probed positions are `Hash(TK_Q)` of the real private search token: positions are free witness values (the same k for all
  blocks). A prover may choose positions that make more blocks look prunable; nothing here links them to the request or to C_Q.
- That the summary S_g is the Bloom filter of the block's records, or that D_S is the digest the ledger/EAPAT holds. D_S is a public
  input of this relation and is a sponge digest (Rescue), not the paper's SHA3 EAPAT root; the authentication of the summaries to the
  canonical state is outside this relation.
- That the retained blocks are the ones evaluated by R_Exec: nothing connects `r` or D_flags to R_Exec's stream digest. The two proofs
  must be checked against the same flag vector and the same records by the verifier; this prototype does not do that.
- Anything about the records of a pruned block (no false-negative argument: that a Bloom filter has no false negatives is an
  assumption on the summary construction, not proven).
- Zero knowledge: none (as for the other relations; trace rows are opened at the query positions, so summaries, flags and positions
  can leak).
- It uses Rescue Prime, not SHA3 (section 5, item 1 applies).

### Trace layout (width 123)

0..12 state of sponge 1 (summary chain) | 12..20 `R1` (word absorbed by the next group, constant inside a group) | 20..32 state of
sponge 2 (flag chain) | 32..40 `R2` | 40..47 `P_1..P_7` (constant) | 47 `F` | 48 `C` | 49 `CI` | 50 `GG` | 51..59 `sel` | 59..91 `oh` |
91..123 `bits`. Periodic columns: the 26 chain columns (period 8) plus, with period 16, header-group selector, summary-group
selector, block-end, not-block-end, probe-row, and one selector per probe row j. 161 transition constraints, 36 assertions.
Rows: 16 per block, padded to a power of two (minimum 32).

## 8. R_CoverM (block coverage with Merkle-opened probes over real-size Bloom summaries)

Added for task `TASK-covermerkle.md`. Reason: `R_Cover` (section 7) holds each block summary as 8 words of 32 bits inside the trace and selects
the probed word with a one-hot, so its width grows with the summary. The real search layer (`bench/pqz-eval/src/search.rs`,
`Bloom::for_block(500)`) has about 215,700 bits = 3,370 words of 64 bits = 6,740 limbs of 32 bits per block. `R_CoverM` takes that size.
Decision (provisional, ours, to be disclosed in the paper): the summary of block g is committed by a Rescue Merkle root `M_g`, computed
OUTSIDE the proof. The proof opens only the k = 7 probed limbs against `M_g`. The authentication of `M_g` to the EAPAT is outside the relation
(as for `D_S` in section 7). File `src/covermerkle.rs`, public input `CoverMPublic`, separate proof (as R_Cover). The retained blocks are
evaluated by `R_Exec`, not here.

### Statement

Public: `d_s` (chain digest over the G block roots), `d_flags` (digest of the flag vector, the same function as R_Cover's `flag_digest`),
`g` (G), `k` (= 7, fixed in the AIR and checked when the AIR is built), `r` (number of retained blocks), and the k probed bit positions
`pos_1..pos_k` (public constants of the AIR, the same for all blocks). A bit position p is bit `p mod 32` of limb `p div 32`
(the same convention as R_Cover, `p < 6,740 * 32 = 215,680`). The limb index is also the leaf index in the Merkle tree.
Witness per block g = 1..G: root `M_g` (4 field elements), flag `f_g` in {0,1} (1 = retained), for each probe j the limb value
(a 32-bit word) and its authentication path (13 sibling digests; tree of 8192 leaves = 6,740 real limbs plus zero limbs).

Merkle tree (all hashes are Rescue Prime `Rp64_256`, same as the other relations): leaf digest = rate[0..4] of one permutation of
`[DOM_MLEAF,0,0,0 | limb,0,0,0,0,0,0,0]`; inner node = rate[0..4] of one permutation of `[DOM_MERGE,0,0,0 | left | right]`
(the 2-to-1 compression of R_Auth, `auth::DOM_MERGE`, same rows and same direction convention: bit i of the leaf index = 1 means the
node is the right child). The leaf is hashed with its own domain tag, so an inner digest cannot be used as a leaf.

Constraints (all enforced by the AIR):
1. Chain. A Rescue sponge, capacity `[DOM_CHAIN, 2G, 0, 0]`, absorbs the 2G words `H_1, W_1, ..., H_G, W_G` with the header word
   `H_g = [DOM_HDR, g, 0, ..., 0]` (the same word as R_Cover, `cover::header_word`) and the root word `W_g = [M_g, 0, 0, 0, 0]`.
   Its digest equals the public `d_s`. The reference digest is `data::chain_digest` over those words (library permutation, independent
   of the circuit). `g` in `H_g` is tied to the block counter (2).
2. Coverage. A counter `GG` is asserted to be 1 at row 0, grows by exactly 1 at each block boundary, and is asserted to be G at the first
   row of block G. The header word absorbed in block g is built from `GG`. So no block is dropped or repeated and exactly G blocks are
   chained before the digest row. Blocks after G (padding up to the power-of-two trace length) are virtual blocks with a dummy tree and
   flag 1; they satisfy every constraint, sit after the asserted rows and cannot change any asserted value.
3. Flags. `F` boolean, constant inside a block. `C` counts retained blocks before the current block (`C` at row 0 is 0, steps by `F` at
   each block boundary); `C` at the first row of the virtual block G+1 equals the public `r`. A second sponge (capacity `[DOM_FLAGS, 2G, 0, 0]`)
   absorbs, per block, the zero word and `[f_g, 0, ..., 0]` (exactly R_Cover's flag chain); its digest equals the public `d_flags`.
4. Probe openings. For probe j the limb is decomposed into 32 bits (4 bits per row over 8 rows, the bits are boolean, `limb = sum 2^t bit_t`
   by the accumulator). The limb enters a leaf permutation (the link row of the decomposition group sets the leaf state from the
   accumulator). 13 merge permutations follow; the direction of merge i is the public constant "bit i of the limb index", so the leaf index is
   fixed by the public position. The output digest of the last merge must equal the block root `M_g` (4 columns held constant over the block, the
   same columns that the chain absorbs). A free root is therefore impossible: the root in the chain is the root that every path ends in.
5. PruneValid with the paper's rule. At the row of the decomposition that holds probed bit t of probe j, a running product column `PR`
   (1 at the start of the block) is multiplied by that bit. At the last row of the block `(1 - F) * PR = 0`. So a block with f = 0 needs the
   product over the k probed bits to be 0, that is AT LEAST ONE probed bit is 0. Retained blocks (f = 1) need no condition. This is the
   rule of the paper (`PS.BlockEval = 0` as soon as one probed bit is 0) and is complete for honest pruning. R_Cover required ALL probed bits
   to be 0, so the two relations check different things (section 7, "Strength of the check").

### What R_CoverM does NOT prove

- That a position equals Hash(token): the k positions are public inputs here (public constants of the AIR). In the paper the token is
  private. Public positions also reveal where the token probes. A private position would need witness direction bits (13 per probe, with an
  index recomposition) and a one-hot over the 32 bit positions of the limb; that cost is not built and not measured.
- That the summary is the Bloom filter of the block's records, or that its fill ratio resembles the real one. The measured summaries are
  synthetic (random limbs, retained blocks have all probed bits set, pruned blocks have at least one probed bit 0).
- That `M_g` is the root held by the EAPAT or the ledger (`d_s` is a public input and is a Rescue digest, not the paper's SHA3 root).
- That the retained blocks are the ones R_Exec evaluates (nothing connects `r`, `d_flags` and R_Exec's stream digest).
- Anything about records of a pruned block (no false-negative argument; the Bloom property is an assumption on the summary construction).
- Zero knowledge: none (trace rows, roots, limbs and siblings can leak at the opened query positions).
- Soundness of the AIR: not independently reviewed. Rescue Prime is not SHA3 (section 5, item 1 applies). The 80-bit floor and the
  library's bit estimates are as in the other relations.

### Layout (width 53)

Block = 1024 rows = 128 groups of 8 rows (one Rescue permutation per group). Active groups 0..101, groups 102..127 are padding.
A block is a power of two long so that the selectors are periodic columns of period 1024. The padded trace length is
`next_power_of_two(1024 * (G + 1))` (the extra block holds the row where `C = r` is asserted and is also the first virtual block).

- group 0: chain, header word `H_g`. group 1: chain, root word `W_g`. group 2: flag chain, zero word. group 3: flag chain, `[f_g,0,..]`.
- probe j (j = 0..6): decomposition group `3 + 14j` (the decomposition of probe j runs in the group before its leaf group; for j = 0 that is
  group 3, for j > 0 it is the last merge group of probe j-1; both use columns that this group does not otherwise use), leaf group
  `4 + 14j`, merge groups `5 + 14j .. 17 + 14j` (13 merges). The last merge of probe 6 is group 101.
- One Rescue state `S` (columns 0..12) is shared by all permutations. The states of the two sponges are saved in `CH` (12..24) and
  `FH` (24..36) and held between their groups; at row 0 of a chain group a same-row constraint sets `S = CH + word` (so the sponge is the
  ordinary sponge of R_Cover), and the row after the output row copies `S` into `CH` (resp. `FH`). This keeps one Rescue bank (12 round
  constraints of degree 7) instead of three.
- Columns: 0..12 `S` | 12..24 `CH` | 24..36 `FH` | 36..40 `M` (root, held over the block) | 40..44 `SIB` (sibling, read on the link row before
  a merge) | 44..48 `BD` (4 bits of a chunk) | 48 `ACC` | 49 `F` | 50 `C` | 51 `GG` | 52 `PR`.
- 45 periodic columns (period 1024 except the 24 round-constant columns of period 8), 81 transition constraints, 36 assertions.
  Degrees are declared with `with_cycles`; the maximum is 7 + one periodic factor = 8, equal to the blowup (as the other relations).
- Inner construction not in R_Cover: the leaf link (`limb = 16 * ACC + chunk` at row 7 of the decomposition group sets the leaf state),
  the merge link (as R_Auth, with the direction bit taken from two selector columns instead of a witness column) and the root check.

### Test and measurement design

Tests (`tests/covermerkle.rs`, release only like `tests/cover.rs`; the same reason applies to debug builds): honest accepted; honest edge cases;
pruned block with all k probed bits 1 rejected (control: retained, accepted); pruned block with exactly one 0 among k accepted (paper rule;
also five 0 of seven); wrong Merkle path rejected; limb not matching the root rejected (two ways: witness limb changed, and decomposition bits changed in
the trace only); leaf taken from a different position rejected; dropped block, repeated block index, wrong r, wrong flag vector, modified root, wrong
public digest, wrong k, wrong positions rejected, each with a control where the same item is legal.

Measurements (`src/bin/covermerkle.rs`, results in `results/covermerkle-1/`): for every block the 6,740-limb summary and its Rescue Merkle tree
are built OUTSIDE the timers. To keep that cheap, 6 distinct template summaries (2 for retained blocks, 4 for pruned blocks) are built
once, each of 6,740 random 32-bit limbs plus zero padding to 8192 leaves, with the k probed bits set as the block class needs (all 1 for
retained; a random pattern with at least one 0 for pruned). Every block then replaces one fixed non-probed limb by its own block number and recomputes only
the 14 nodes on that leaf's path. The roots are therefore all distinct, and the 7 authentication paths of the probes of each block are the true paths in
its own tree. The summaries are synthetic: they do not have the density or the structure of a Bloom filter built from tags.

### Notes after implementation (2026-10-31)
- For G = 1 the assertion "GG = G at the first row of block G" is the same assertion as "GG = 1 at row 0"; winterfell refuses duplicate assertions, so it is left out for G = 1 (35 assertions instead of 36). Nothing is weakened: the value is asserted once.
- Measured (results/covermerkle-1): G = 100 and 500 run. G = 2000 (2^21 rows, width 53) did NOT fit the 4 GiB MemAvailable guard on this machine at any of the three r values (recorded as FAILED). G = 8000 was not tried because it has four times more rows than G = 2000. The reason is the trace length: 1024 rows per block (14 Rescue permutations per probe, 7 probes, 4 for the two sponges, and padding to 128 groups).
