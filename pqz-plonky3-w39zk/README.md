# pqz-plonky3-w35: w33 Plonky3 AIRs plus chunked R_RC (D1, D1b, D1c) and R_Exec runs (D4)

Status 2026-11-15: LAPTOP PROTOTYPE, correctness only. Built from `journal2/DESIGN-w35-blockcover.md` (section 3, D1, D1b, D4; section 8, D1c = v3).
All timings from this crate or `../pqz-integrated-w35` are laptop smoke data, not benchmark numbers.
This crate is a copy of `pqz-plonky3-w33` (all w33 AIRs and tests are unchanged and still pass) plus two new modules.
The old w33 text is kept below, from section "w33 text (inherited)". Original README backup: `archive/backups/README.w33-original.md`.

## w35 additions

| file | what |
|---|---|
| `src/chunk.rs` | D1 chunk AIR (`plain::chunk_air`, `prove_chunk`, `verify_chunk`), D1b tag accumulators and D1c header terms, `ChunkLists`, `lists_of`, `alpha_of`, `beta_of`, `alphas_of`, `betas_of`, `acc_native`, `seal`, `plan_chunks`, `honest_chunk_publics`, `state_after`, `tags_of` |
| `src/run.rs` | D4 run AIR (`plain::run_air`, `prove_run`, `verify_run`, `honest_public`) |
| `tests/w35_chunk.rs` | 9 tests (digest equality, IV rule, statement tampering, foreign words, D1b, D1c beta and header terms, header slots 5-6, chunk plan) |
| `tests/w35_run.rs` | 5 tests (run equals reference, statement tampering, foreign stream of the same size, grammar, header slots 5-6 free in the run AIR) |

Test result: `cargo test --release --offline` = 70 passed, 0 failed (36 rejection, 1 security_port, 3 stagec_honest, 2 stagec_reject,
4 stagec_vs_w30, 4 vs_winterfell, 6 w34_native, 9 w35_chunk, 5 w35_run). Before v3 (D1c) it was 68 (8 + 4).

### D1: R_RC chunk AIR

One row = one absorbed word = one Poseidon2 permutation (as w33). A chunk is whole blocks. Public values (43):
`s_in[12], s_out[12], chunk_index, n_blocks_chunk, hdr_before, block_size, total_words, hdr_first[8], alpha[3], acc[3], beta[3]` (46; beta is new in v3).
The states are FULL 12-element states. The rules inside the chunk are the w33 R_RC rules (R3-R7). Chunk 0 starts at the IV
`(0^8, DOM_CHAIN, total_words, 0, 0)` (rule R2b, built into the AIR the verifier makes from the public `chunk_index`, so it is not
something the prover can switch off). The chunked digest is `state[0..4]` of the last chunk's `s_out`.

### D1b: tag fingerprint (the exact constraint)

Three accumulators over word slot 6 (the tag slot) of RECORD rows (h = word slot 7 = header flag):
- row 0: `acc_j = (1 - h) * w6`
- transition: `acc_j' = acc_j * alpha_j + (1 - h') * w6'`
- last row (`idx = n_words_chunk - 1`): `acc_j = public acc_j`

`alpha_j` is a PUBLIC value of the statement, so `acc_j * alpha_j` has degree 1 and `(1 - h') * w6'` has degree 2. The constraint has
degree 2; with the transition selector it is degree 3, the same as the Poseidon2 part (so the quotient degree of the AIR does not grow).
The accumulator is read at the `last` row, not at the end of the padded trace, so padding rows do not matter.
Native value: `acc_j = sum_{r < n} (1-h_r) * w6_r * alpha_j^(n-1-r)` (`acc_native`).

Hash choice (alpha): `alpha_j = blake3("PQZ-w35-alpha" || j || s_in || s_out || chunk meta || hdr_first || len(T) || T)`, first 16 bytes
read little-endian and reduced mod p (p = 2^64 - 2^32 + 1). `T` is the tag list of the chunk that the AA holds. Blake3 was chosen because
it is already the Merkle hash and the transcript hash of this crate, so no new assumption. The reduction of 128 bits mod a 64-bit prime
has bias about 2^-64 (harmless here).
Why it works (sketch, not a formal proof): `s_out` pins the words of the chunk (sponge collision resistance), so the proof fixes a tag
list T'. The AA recomputes alpha from ITS list T. If T != T', the difference polynomial is nonzero of degree < n_rows, and it must vanish
at all three alphas, which are outputs of a hash that also covers T: about (n_rows/p)^3 per hash query (random-oracle model for blake3).
A chunk proof whose alpha is not `H(...)` is refused by the AA (attack A13); a different tag list gives a different alpha and acc
(attack A12). `AaChecks.d1b_alpha` and `d1b_acc` can each catch A12 alone (see `../pqz-integrated-w35/README.md`).

### D1c (v3): header words in the accumulators

v2 left a 64-bit hole: the tag slot of a record is only 64 bits of the descriptor D_i, so a party that finds a second preimage for the
slot (about 2^64 work) could swap the keyword tags of a record without changing the stream. v3 puts the whole header word into the
fingerprint, and the header carries hd_g, a hash of all the descriptors of its block.

Header word (v3) = `[e, g, m_b, pid, seq_start_g, hd_lo, hd_hi, 1]`, `hd_g = SHA3("pqz-w35-hd" || e || g || D_{g,1..B})`, `hd_lo` and `hd_hi` =
u64 LE of bytes 0..8 and 8..16 of hd_g, each mod p (about 127 bits). Three new public betas (46 public values in all). With `h` = word slot 7:
- `hdr_term(w) = w7 * sum_{k=0..6} beta_j^k * w_k`
- row 0: `acc_j = (1 - h) * w6 + hdr_term`
- transition: `acc_j' = acc_j * alpha_j + (1 - h') * w6' + hdr_term'`

Degree: `w7 * w_k * beta^k` is degree 2 (beta is public), so the constraint has degree at most 3 with the transition selector. No new trace column.
alpha and beta both come from blake3 over the same inputs as before plus the chunk's header words, with domain separation
(`"PQZ-w35-alpha"` and `"PQZ-w35-beta"`). The AA rebuilds every header word of the chunk from its own block list and descriptors (e, g, m_b, pid,
seq_start from the block position; hd from its D_i), so the AA checks the header words in full, not only the first one. That gives g and seq_start
continuity, and ties the 127-bit hd_g (hence every descriptor, hence the keyword tags) to the stream. Soundness sketch: as for D1b, about
((n_rows + 7)/p)^3 per hash query (random-oracle model). Tests: `w35_chunk::d1c_beta_and_header_terms_are_constrained`; attacks A14-A16 in
`../pqz-integrated-w35`.

### Header slots 5-6 (before v3: free; v3: bound to hd_g by the AA, not by the AIR)

Header word = `[e, g, m_B, pid, seq_start_g, hd_lo, hd_hi, 1]` in v3 (`[.., 0, 0, 1]` before). No rule of the chunk AIR or of the w33 R_RC forces slots 5 and 6 of a header to 0
(`header_slots_5_and_6_are_not_forced_to_zero` builds a stream with nonzero values there and it proves and verifies). The tag
sum of D1b is masked by `(1 - h)`, but since v3 the header terms of D1c put slots 0..6 of every header into the accumulators, so the AA's
check pins them to `hd_g` and to the block position. The AIR itself still leaves slots 5-6 free (it only proves the header terms equal what the
statement says), and it ties slots 0, 2, 3, 4 of a header to the first record of its block (K = (pid, e, seq_start - 1)) but does NOT enforce `g` or `seq_start`
continuity across blocks: that is now the AA's job (D1c). D4 (the run AIR) uses the same grammar rules and still accepts free header slots 5-6
(`w35_run::run_air_accepts_free_header_slots_5_and_6`), so honest runs over the v3 stream prove.

### D4: R_Exec run AIR (stream grammar)

A run is whole blocks, from a public `s_in` to a public `s_out` (full 12-element states; sigma after the chunk before the run, or the IV).
Public values (42): `s_in[12], s_out[12], hdr_first[8], n_blocks, block_size, n_words, theta, count, sum, ctx[4]`. Rules: R1 permutation;
R2 sponge from the public state; G3-G5 stream grammar (row 0 is the header `hdr_first` of a block of `block_size` records; flag boolean;
header m_B in {0, block_size}; header only after a complete block; (pid, e) constant and seq + 1 inside a block; block counter from 1,
at the last word cnt_g = mb = block_size and hdr = n_blocks); E3 predicate bit (v >= theta) with range checks; E4 running count and
sum from 0; E5 row counter and `last`; E6 at `last` all 12 output elements = `s_out`, count and sum = public values. `ctx` (= C_Q) is a
public value checked natively against the Auth statement (as in w33).

### Not built

- Salt option O1 of the DESIGN: NOT built (as instructed).
- No in-circuit check that a chunk's tags equal the Bloom positions; D1b/D1c only bind the tag column and the header words to the AA's own lists (see `../pqz-integrated-w35/README.md`).
- No timed matrix. The frozen `bench/zkalba-eval` tree and all other crates were not touched.

---

## w33 text (inherited)

# pqz-plonky3-w35: Plonky3 STAGE A spike for R_Exec (laptop, correctness only)

Status: Stage A done (2026-11-14). The AIR proves and verifies; the tests below pass. No timed matrix was run.
Laptop numbers decide GO/NO-GO only and never go into a paper file.
Nothing outside this folder was changed. The only link to other crates is a READ-ONLY path dev-dependency on
`../pqz-proof-w30` (data generator, reference function and the winterfell prover, used by `tests/vs_winterfell.rs`).

## 1. Versions

| item | value |
|---|---|
| Plonky3 crates (p3-air, -uni-stark, -fri, -poseidon2-air, -goldilocks, -koala-bear, -blake3, -merkle-tree, ...) | `=0.8.0`, published 2026-09-23 (52 days before 2026-11-14), not an rc |
| newest release on crates.io | 0.9.0-rc.2 (an rc, NOT used) |
| winterfell (reference, dev-dependency only) | 0.13.1 (as in w30) |
| rustc | 1.99.1 |
| serialisation of proofs | bincode 1 (`Proof` is serde) |

## 2. Configurations

| name | field | challenge field | Poseidon2 | Merkle / transcript | words |
|---|---|---|---|---|---|
| C1 (`c1`) | Goldilocks (64 bit) | degree 2 (about 128 bit) | width 12, rate 8, capacity 4, x^7, HF=4, PR=22, ONE register column (constraint degree 3) | Blake3-256 (`MerkleTreeMmcs` over `SerializingHasher<Blake3>`, cap height 0), Blake3 `HashChallenger` | 8 values, identical to w30 |
| C1r0 (`c1r0`) | as C1 | as C1 | as C1 but 0 registers (constraint degree 7, like winterfell's Rescue degree 7) | as C1 | as C1 |
| C2 (`c2`) | KoalaBear p = 2^31 - 2^24 + 1 | degree 4 (about 124 bit) | width 24, rate 16, capacity 8, x^3, HF=4, PR=23, no register (degree 3) | as C1 | 12 values (limbs, section 5) |
| C1p (Poseidon2 Merkle) | NOT BUILT (optional in the task; skipped) | | | | |

FRI (all configs, `src/variants.rs` `FriOpts::default`): log_blowup 3 (blowup 8), 40 queries, query proof-of-work 16 bits
(commit and batch PoW 0), final polynomial length 2^5 (w30: remainder degree 31), max folding arity 2^3 (w30: folding 8).
Minimum trace height is 64 rows (`MIN_ROWS`, air.rs:30; FRI needs log_height > 5 + 3).
Field cap: the challenge field limits the soundness to about 128 bits (C1) and about 124 bits (C2). State "about 124 bit"
next to every C2 number.
Round constants and permutations are the canonical Plonky3 ones (`GOLDILOCKS_POSEIDON2_RC_12_*`, `KOALABEAR_POSEIDON2_RC_24_*`);
test `trace_permutation_equals_reference` checks every Poseidon2 trace row against `default_goldilocks_poseidon2_12()` /
`default_koalabear_poseidon2_24()`. I did not audit the security margin of these round counts.

## 3. Design (differences from w30 that apply everywhere)

- ONE trace row = ONE absorbed word = ONE full Poseidon2 permutation (w30: 8 rows per word, one Rescue round per row).
- Sponge: rate part of the state = first `rate` elements, capacity = the rest. Row k input = (output of row k-1) + word k on the
  first WLEN rate positions (additive absorb, like w30 exec.rs:127). Row 0 input = word 0 on the rate positions, zeros elsewhere in
  the rate, capacity = [DOM=0x50515a43, n_words, 0, ...]. Digest = the first 4 (C1) or 8 (C2) rate outputs of the permutation of row
  n_words-1 (w30: state[4..8] = first four rate elements after the last real group).
- Every constraint is active on every row (no periodic fl/fr gating, no 8-row cycle).
- Counters `cnt` and `sum` are INCLUSIVE running totals (row k holds the totals including word k). w30 holds exclusive totals and asserts 0 at row 0.
- The row n_words-1 (the claimed end of the stream) is found with a selector (`idx`, `inv`, `last`, `seen`, air.rs:339-357) because
  the prover chooses the trace height (power of two, at least 64, padded with the pad word [0,..,0,1] after the real words).
  winterfell uses a fixed assertion step.
- Data: `src/data.rs` is a copy of w30's generator logic (splitmix64, seed 1, draw order v (32 bit), b (20 bit), tag (% Goldilocks p)).
  `tests/vs_winterfell.rs` proves it equals w30 `Workload::synthetic` word by word.

## 4. Constraint mapping: w30 `src/exec.rs` (winterfell) to `src/air.rs` (Plonky3)

Line numbers: w30 = `../pqz-proof-w30/src/exec.rs`; w33 = `src/air.rs` (as of 2026-11-14). "C1/C2" = MODE 0/1.

### 4.1 Transition constraints

| # | w30 exec.rs | what it checks | w33 air.rs | notes |
|---|---|---|---|---|
| T1 | 84-86, 122 (`round_constraints`, W=12, degree 7, periodic ark) | one Rescue round per row | 240-247 (SubAirBuilder + `Poseidon2Air::eval` on columns 0..P) | NOT the same hash. Poseidon2 constraints come from p3-poseidon2-air 0.8.0 (not our code). Full permutation per row. |
| T2 | 87-89, 123-125 (`fl*(next[j]-cur[j])`, j<4, capacity hold) | capacity part carried between groups | 278-280 (`next.inputs[j] = out[j]`, j in rate..W) | no gating needed. |
| T3 | 87-89, 126-128 (`fl*(next[4+j]-cur[4+j]-R[j])`, j<8) | absorb the word into the rate part | 274-277 (`next.inputs[j] = out[j] + next.word[j]`, j<rate; word only for j<WLEN) | w30 absorbs word k+1 at the link row from column R; here the word of the row itself is the input of that row's permutation. |
| T4 | 90, 139 (`h*(h-1)`) | header flag boolean | 286 | w30 `fl`-gated, here every row. |
| T5 | 91, 140 (`m*(m-1)`) | predicate bit boolean | 287 | same. |
| T6 | 92, 141 (`h*m`) | header => m = 0 | 288 | same. |
| T7 | 93, 142 (`(1-h)*(16*accD + cd - dd)`) | d decomposition, 4 bits per row over 8 rows | C1: 305 (32 bits in ONE row: `(1-h)*(sum_i 2^i bd_i - dd)`). C2: 316-317 (two 16-bit limbs with borrow bit `br`, see section 5) | no accumulator (see T13-T16). `dd` is defined at air.rs:304 (C1) / 313-314 (C2) exactly as w30 exec.rs:135 (d = m(v-theta) + (1-m)(theta-1-v)). |
| T8 | 94, 143 (`(1-h)*(16*accV + cv - v)`) | v decomposition (32-bit range check of v) | C1: 306. C2: 318-319 (two 16-bit limbs, each range-checked) | same range check, 32 bit. |
| T9 | 95, 144 (cnt link) | `cnt' = cnt + m` | 333 (`next.cnt - cnt - next.m`) | inclusive form. First row: 326 (`cnt = m`). |
| T10 | 96, 145 (sum link) | `sum' = sum + m*b` | 335 (`next.sum_k - sum_k - next.m * next.b_k`) | C2: two sum columns (sum of b_lo, sum of b_hi). First row: 327-329. |
| T11 | 97, 146 (accD reset `fl*next[accD]`) | accumulator reset | NONE | no accumulator in w33. |
| T12 | 98, 147 (accV reset) | same | NONE | same. |
| T13 | 99, 148 (cnt hold during Rescue rounds, `fr*`) | cnt constant over the 8-row cycle | NONE | one row per word, nothing to hold. |
| T14 | 100, 149 (sum hold) | same | NONE | same. |
| T15 | 101, 150 (accD update) | accumulator update | NONE | same as T11. |
| T16 | 102, 151 (accV update) | same | NONE | same. |
| T17 | 103-105, 152-154 (8 bit columns boolean) | bd, bv bits are 0/1 | 289-292 (all 64 bit columns bd[0..32], bv[0..32], `x*(x-1)`) | 64 bit columns instead of 8. |

New constraints in w33 with NO w30 counterpart:

| id | w33 air.rs | purpose |
|---|---|---|
| N1 | 311-312 (C2 only) | `br` boolean (borrow bit of the limb subtraction) |
| N2 | 344-346 | `idx` / `last` / `inv` selector: `last = 1` iff `idx == n_words-1` (`(idx-(n-1))*last = 0`, `(idx-(n-1))*inv = 1-last`) |
| N3 | 349-350, 354-355, 357 | `idx = 0` at row 0, `idx' = idx+1`, `seen = last` at row 0, `seen' = seen + last'`, `seen = 1` at the last trace row (so row n_words-1 exists exactly once) |
| N4 | 261-269 (first row) | binds the whole row-0 sponge input: word 0 in the rate part, zeros in the rest of the rate part, capacity [DOM, n_words, 0..]. |

### 4.2 Boundary assertions and public values

| # | w30 exec.rs | w33 air.rs | notes |
|---|---|---|---|
| B1 | 162-164 (capacity of row 0 = `cap_init(n_groups)` = [DOM, n_groups, 0, 0]) | 266-269 (`inputs[rate] = DOM`, `inputs[rate+1] = n_words`, rest of capacity 0) | w30 binds only the capacity; the rate part of row 0 is NOT asserted in w30 (word 0 is not linked there). w33 also binds the rate part (261-265). |
| B2 | 165-167 (accD, accV, cnt, sum = 0 at row 0) | accD/accV: none. cnt, sum: 326-329 (`cnt = m`, `sum_k = m*b_k` at row 0) | the inclusive form makes word 0 (a header, m = 0) count as 0. |
| B3 | 168-172 (digest = `state[4..8]` at row `n_groups*8-1`) | 360-365 (`last * (out_j - pub_digest_j)`, j < 4 (C1) or 8 (C2)) | `last` marks row n_words-1 (N2, N3). `out_j` is the permutation output of that row. |
| B4 | 173 (cnt at last row = public count) | 366-367 (`last * (cnt - pub_count)`) | inclusive count at row n_words-1. |
| B5 | 174 (sum at last row = public sum) | 368-371 (`last * (sum_k - pub_sum_k)`) | C2: two limb sums. |

Public values (w30 `to_elements`, exec.rs:48-58, vs. w33 `ExecPublic::to_values`, air.rs:133-152). All are absorbed into the
Fiat-Shamir transcript (p3-uni-stark 0.8.0 `transcript.rs:598` `observe_public_scalars`). `public_boundary_io()` must be empty in
uni-stark 0.8.0 (prover.rs:109, verifier.rs:138), so values bind only through the constraints below and the transcript.

| public value | w30 | w33 binding in the AIR |
|---|---|---|
| digest (4 / 8 elements) | asserted (B3) | constrained, air.rs:362-365 |
| n_blocks, block_size | not read by an assertion; enter through `n_groups` (B1, B3) | same: only through `n_words = n_blocks*(block_size+1)` (AIR constant, air.rs:267, 344). `n_blocks` and `block_size` themselves are transcript-only. |
| theta | AIR constant (exec.rs:131) and public | AIR constant `self.theta` (air.rs:304, 309-310) and public value. The AIR does not read the public-value cell; the verifier builds the AIR from the same `ExecPublic`, so the two cannot differ. C2: also public as two 16-bit limbs. |
| count | asserted (B4) | constrained, air.rs:366-367 |
| sum | asserted (B5) | constrained, air.rs:368-371 (C2: sum_lo, sum_hi) |
| ctx (4 elements) | transcript only (exec.rs:38) | transcript only. NOT bound by the AIR (same as w30). |
| n_words | (derived) | additional public value, derived from n_blocks, block_size; also an AIR constant. |

## 5. Field and limb choices

C1 (Goldilocks): every word value is one field element; v < 2^32, d < 2^32 range checks are 32 bit columns each (T7, T8), exactly
the w30 statement. d = m(v-theta) + (1-m)(theta-1-v) is a field value; integer equality holds because p is about 2^64 and
|v - theta| < 2^32. theta must be in [1, 2^32) (asserted at air.rs:136, 186).

C2 (KoalaBear, p = 2,130,706,433, about 2^31): word layout `[pid, e, seq, id, v_lo, v_hi, b_lo, b_hi, tag0, tag1, tag2, h]` (12 values; `data.rs` `map_c2`).
- `pid, e, seq, id` are single elements; must be < p (checked in `map_c2`, holds for all workloads here, seq <= 2^24).
- v = v_lo + 2^16 v_hi, both 16-bit limbs, both range-checked by 16 bit columns each (air.rs:318-319).
- theta = theta_lo + 2^16 theta_hi (theta can exceed p, since theta = 2^31 > p; theta is an AIR constant given as two limbs, also two public values).
- Predicate: A_lo = m(v_lo - theta_lo) + (1-m)((theta-1)_lo - v_lo), A_hi likewise on the high limbs. Witness: borrow bit `br` and 16-bit limbs
  d_lo, d_hi (bit columns bd[0..16], bd[16..32]) with `d_lo = A_lo + 2^16 br` (air.rs:316) and `d_hi = A_hi - br` (air.rs:317).
  Then d_lo + 2^16 d_hi = A_lo + 2^16 A_hi = v - theta (m=1) or theta-1-v (m=0), as an INTEGER (all intermediate values are within +-2^17, far below p),
  and d >= 0, so m is the true predicate. 32 bit columns for d and 32 for v, as in C1.
- b = b_lo + 2^10 b_hi (10-bit limbs). NOT range-checked in the circuit (b is not range-checked in w30 either; the digest binds the value).
  Two running sums, sum_lo and sum_hi (public values). Integer sum = sum_lo + 2^10 sum_hi. This is exact only if N * 1023 < p, i.e. N below
  about 2.08 million records. Above that the field sums wrap and the claim becomes ambiguous. The README of any use of C2 must say this.
- tag = tag0 + 2^22 tag1 + 2^43 tag2 (22/21/21 bits). Not range-checked and not used by the predicate (as in w30, where tag is only absorbed).
- The digest is a different hash value than in w30 (Poseidon2 over a different field); only (count, sum) are comparable, and they are compared.

## 6. NOT mirrored / differences / uncertainty (read this before judging soundness)

1. Hash: Poseidon2 (p3-poseidon2-air, canonical Plonky3 constants) instead of Rescue Prime. Its security margin is taken from Plonky3, not checked here.
2. C2 digest is 8 x 31 bits = 248 bits, capacity 8 x 31 bits; C1 is 4 x 64 = 256 bits.
3. Trace shape: 1 row per word instead of 8; no accD/accV accumulators (T11-T16 have no counterpart); direct 32-bit sums instead.
4. Inclusive counters from row 0 instead of w30's exclusive counters with an ignored word 0. The final claimed values are the same (tested).
5. The row-0 rate part is bound in w33 (air.rs:261-265); in w30 it is not asserted. This makes w33 slightly STRICTER than w30 here.
6. The end of the stream is found with the idx/last/seen selector (N2, N3), not a fixed step. The proof carries `degree_bits`; the prover chooses the height;
   the AIR forces `n_words - 1 < height` through `seen`. Rows after `last` are free except that all constraints still hold on them (the pad word makes that satisfiable).
   Their cnt/sum values are never read.
7. Header and pad words skip the range checks (`(1-h)`), as in w30. The flag h is absorbed, so it is bound by the digest; the AIR does not check that headers occur at the
   right positions or that header fields (e, g, m_B, pid, seq_start) are consistent: same as w30.
8. b and tag are not range-checked (same as w30), and in C2 their limbs are free field elements bound only by the digest.
9. n_blocks, block_size, ctx are bound only through the transcript (same as w30 for ctx; for n_blocks and block_size only through n_words).
10. theta and n_words are AIR constants as well as public values (w30: theta likewise).
11. Not zero-knowledge: the configs use `TwoAdicFriPcs` (`p3-fri-0.8.0/src/two_adic_pcs.rs:907`, `const ZK: bool = false`).
12. No recursion and no chunk-proof aggregation here. No C1p.
13. Proof options with fewer than 40 queries are rejected by the verifier because the number of queries is a verifier-side parameter (p3-fri `verifier.rs:657`).
    This holds for a verifier that builds its own `FriParameters`; a verifier that accepts the options from the proof would not be safe (not the case here).
14. In a DEBUG build, `prove` runs p3-air `check_constraints` (prover.rs:114) and panics on a bad trace. The rejection tests therefore need `cargo test --release`.

## 7. ZK mode and recursion (record, not gated)

Zero knowledge, p3 0.8.0 (files under `~/.cargo/registry/src/*/`):
- `p3-fri-0.8.0/src/hiding_pcs.rs:81` `HidingFriPcs` (constructor `new` at :130, `const ZK: bool = true` at :306); the hiding budget check message is at `p3-fri-0.8.0/src/verifier.rs:257` and `hiding_pcs.rs:41`.
- `p3-merkle-tree-0.8.0/src/hiding_mmcs.rs:42` `MerkleTreeHidingMmcs`.
- `p3-fri-0.8.0/src/config.rs:163` `new_testing_zk`, `:211` `new_benchmark_zk`.
- `p3-uni-stark-0.8.0/src/config.rs:61` `StarkConfig::is_zk()` (returns `Pcs::ZK as usize`); `prover.rs:119` the trace domain is doubled when ZK (`log_ext_degree = log_degree + config.is_zk()`).
- Example: `p3-poseidon2-air-0.8.0/examples/prove_poseidon2_baby_bear_keccak_zk.rs` (lines 65, 96, 102).
So a hiding mode EXISTS in 0.8.0. It is NOT enabled in this spike and NOT tested (it needs an RNG and the hiding Merkle MMCS; cost not measured).

Recursion:
- The 0.8.0 set downloaded for this crate has no recursion crate. `p3-uni-stark-0.8.0/src/verifier.rs:158` only mentions "recursive verifiers" in a comment.
- crates.io has `p3-recursion`, `p3-circuit`, `p3-circuit-prover` at 0.1.0 (homepage github.com/Plonky3/Plonky3-recursion). I downloaded them: each `src/lib.rs` is a 3-line placeholder
  (`todo!()` / "Hello, world!"), so the published crates give NO recursion. Whether the git repository Plonky3-recursion works with 0.8.0 was NOT checked (no cloning). Answer: recursion for chunk proofs is not available as a published crate in this spike.

## 8. Tests (all in release mode: `cargo test --release`)

`tests/vs_winterfell.rs` (4 tests, all pass). Method: the w30 library crate is a read-only path dev-dependency; the tests (1) compare our generator with w30
`Workload::synthetic` word by word and `reference_result` with w30's, (2) run the real w30 winterfell `prove_exec` + `verify_exec`, take its (count, sum), then
prove and verify C1, C1r0, C2 (N=1e3) and C1, C2 (N=1e4) and compare (count, integer sum).
- N=1000: count 493, sum 270766858 (winterfell and C1, C1r0, C2 equal). N=10000: count 4958, sum 2593976981 (winterfell, C1, C2 equal).

`tests/rejection.rs`: 27 tests, all pass. Per config (C1, C1r0, C2), N = 1000, 5 trials per category; every test first checks that the honest proof verifies.
| category | trials | result |
|---|---|---|
| one record value changed (v across theta, v low bit, b, tag, seq; witness changed, public honest) | 5 | 5 rejected, all by verifier (VERIFY_FAIL) |
| claimed count changed (+1, +2, +3, +4, -1): (i) prover proves the wrong claim, (ii) honest proof against the wrong claim | 5 + 5 | 10 rejected (VERIFY_FAIL); prover did not fail or panic in release |
| claimed sum changed (same pattern; C2 alternates sum_lo / sum_hi) | 5 + 5 | 10 rejected (VERIFY_FAIL) |
| wrong public digest (different element and offset each trial) | 5 + 5 | 10 rejected (VERIFY_FAIL) |
| one proof byte flipped (positions at 10%, 30%, 50%, 70%, 90% of the proof, different bits) | 5 | 5 rejected, all VERIFY_FAIL; 0 deserialize failures, 0 verifier panics |
| proof options with fewer than 40 queries (1, 10, 20, 30, 39): the proof verifies under its own options and is rejected by the 40-query verifier | 5 | 5 rejected (VERIFY_FAIL) |
| cell tampering of an honest trace (14 cases, 15 for C2): m flipped both ways, a d bit, a v bit, a non-boolean bit (2), cnt, sum, idx, word v, header flag on a record row, sponge rate input, sponge capacity input, `seen` cleared at last row, `last` set on a wrong row, (C2) borrow bit | 14 / 15 | all rejected, no panic |
| `trace_permutation_equals_reference`: every Poseidon2 trace row = reference permutation | 1 | pass |

Run: `cargo test --release -j 8 -- --nocapture --test-threads 2`. Build: `nice -n 15 cargo build --release -j 8`.
Smoke run: `./target/release/spike <c1|c1r0|c2> <n_records>` (one prove + verify, NOT a measurement driver).

## 9. Files

- `Cargo.toml`, `src/lib.rs`
- `src/air.rs` the AIR, trace builder and native sponge
- `src/data.rs` generator, reference result, limb mapping
- `src/variants.rs` the three configs generated from one macro
- `src/bin/spike.rs` smoke driver
- `tests/vs_winterfell.rs`, `tests/rejection.rs`

---

# STAGE C (2026-11-14): R_RC and R_Auth in Plonky3, gates G-C1 and G-C2

Laptop only. Numbers decide the cloud proposal only and never go into a paper file. Plan: `journal2/UPGRADE-w33c-plonky3-port-plan.md`.
Config C1 (section 2) for everything: Goldilocks, degree-2 extension, Poseidon2 width 12, Blake3 Merkle, blowup 8, 40 queries, 16 bit grinding.
One proof per relation over the whole stream (no chunks, no aggregation: `p3-recursion` is a placeholder in 0.8.0). w30 record format (NOT w31): b is an unrestricted field element.

## C.1 Files (stage C)

| file | what |
|---|---|
| `src/rc.rs` | R_RC AIR (`RcAir`), width 266 columns, constraint groups R1..R7 |
| `src/auth.rs` | R_Auth AIR (`AuthAir`), width 318 columns, groups A1..A4, honest instance, native hashes |
| `src/rel.rs` | `plain` (C1, min 64 rows) and `zk` (C1 hiding PCS, min 128 rows for R_Auth) prove / verify wrappers; `guard` turns a verifier panic into a rejection |
| `src/request.rs` | C_Q = H("PQZA-EXEC", B_Q, Auth_Q, RID) with Poseidon2; `verify_request` (link first, then Auth, then Exec) and `verify_bundle` (+ R_RC) |
| `src/bin/pchild3.rs` | timing child (exec, rc, auth, bundle; plain or zk), same READY / run / ROW / IDLE protocol as stage B |
| `w30auth/` | helper crate: w30 R_Auth timing child (the w30 binary has no Auth prove child). Read-only path dependency on `../pqz-proof-w30`, feature `blake3`, own `target/` |
| `scripts/stagec_driver.py`, `scripts/stagec_summary.py` | matrix driver and summary (stage B rules; gate rules written in the header of the summary script before any data) |
| `tests/stagec_honest.rs`, `stagec_reject.rs`, `stagec_vs_w30.rs` | G-C1 tests (section C.3) |
| `results/stageC/` | `gc1_*.csv` (G-C1), `raw/` (G-C2 raw runs, never edited), `summary.md/.json`, `driver-main.log` |
| `../pqz-attack-w33/` | the w30 attack test ported (own crate, its README lists attacks with no meaning in w33) |

Change to a stage B file: `src/air.rs`, in `ExecAir::build_trace` the `assert_eq!(n_words ...)` was removed (replaced by a comment), so the rejection and attack
tests can build a trace for a stream of another length (the trace is then invalid and the verifier rejects). Backup: `archive/backups/air.rs.bak-stageB`.

## C.2 Constraint maps

w30 = `../pqz-proof-w30/src/rc.rs` and `auth.rs` (winterfell, Rescue, 8 rows per group). w33 = `src/rc.rs` and `src/auth.rs` (one Poseidon2 permutation per row, every constraint on every row).
In R_RC row k of w33 = group k of w30; the w30 "link row" constraints of group k become the transition constraints k -> k+1.

### R_RC (width 266; public values: digest[4], n_words, n_blocks, block_size, header0[8])

| group | what it checks | w30 rc.rs | w33 rc.rs |
|---|---|---|---|
| R1 | one hash permutation per row (w30 Rescue round, degree 7; w33 Poseidon2 from p3-poseidon2-air, degree 3 with 1 register) | 92 | 178-183 |
| R2 | sponge link: capacity kept, rate += next word; row 0 input = word 0 + capacity `[DOM_CHAIN, n_words, 0, 0]` | 93-100 (link), 134-138 (cap assertions) | 194-214 |
| R3 | row 0: word = public header0, header flag 1, m_B = block_size; K, cnt, mb, hdr start values | 139-144, 152-154 (header0, K0, cnt/mb/hdr) | 216-230 |
| R4 | flag boolean; a header announces m_B in {0, block_size} | 105, 121 | 232-236 |
| R5 | record checks (pid, epoch, seq+1), K updates, "a header only follows a complete block" (cnt = mb), cnt / mb / hdr updates | 106-111, 122-125 | 238-259 |
| R6 | row counter and the "row n_words-1" selector (w30: fixed assertion step) | (assertion row `last`, 145-148) | 261-279 |
| R7 | at the last row: digest = public digest, cnt = mb = block_size, hdr = n_blocks | 148, 155-157 | 281-290 |
| (hold) | w30 K, cnt, mb, hdr hold constraints on the non-link rows | 112-114, 126-128 | not needed (no 8-row cycle) |

### R_Auth (width 318; 28 public values: depth, r_pol[4], b_q[4], d_q[4], omega[4], uid, v_a, v_auth, scope 8 values)

| group | what it checks | w30 auth.rs | w33 auth.rs |
|---|---|---|---|
| A1 | one hash permutation per row | 209 | 251-256 |
| A2 | row-role flags (leaf1, leaf2, merge, bind1, bind2, nine range rows) and the "row d+2" pin by a counter; policy leaf P held constant; dg = previous digest | 169, 213-214 (P hold), periodic columns 308-344 | 271-312 |
| A3 | hash chain: leaf hash part 1 and 2 (P0..P11), Merkle merge with direction bit D (boolean, left = D ? sib : dg), root = public R_pol, B_Q part 1 and 2 (public d_q, uid, v_a, v_auth, R_pol, omega), B_Q = public b_q | 216-255, 277-304 (assertions) | 314-376 |
| A4 | nine 32-bit range checks (scope inside the policy leaf), bits boolean | 257-274 | 378-390 |

Differences in A4: w30 builds each difference from 4-bit chunks accumulated over rows (acc update 16*acc + chunk, final check, reset); w33 keeps 32 bit columns on every row and checks `sum(bit_k 2^k) = sign*(P - pub)` on the range row. Same statement (difference in [0, 2^32)); other encoding.
A 32-bit difference cannot wrap in Goldilocks (p about 2^64); a scope value of 2^32 or more is refused by the prover in both systems (w30 `assert!` against MAX_ATTR, w33 `build_trace` error).

## C.3 Where w33 is stricter or different from w30 (disclose)

- R_RC R3: the first row checks word[7] = 1 (header flag) and word[2] = block_size as constraints; w30 asserts header0[2] = block_size in `get_assertions` and binds the flag only through header0.
- Capacity of the chain is `[DOM_CHAIN = 0x50515a43, n_words, 0, 0]` at state[8..12] (w30 Rescue: state[0..4]); C_Q capacity is `[11, 0, 0, 0]` at state[8..12]. The hash is Poseidon2, not Rescue: the professor must OK this change.
- The digest of R_RC is not linked to the digest of R_Exec (same as w30): the verifier gets the two digests as public inputs. (w34: now linked natively, see "w34 changes").
- R_Auth ZK needs 128 rows (the hiding PCS fails with `HidingBudgetExceeded` at 64 rows); the plain mode uses 64.
- The scope-inverted case (start > end) is accepted by both systems (same statement). (w34: the Plonky3 verifier now rejects it natively, see "w34 changes".) The w30 prover panics on a scope value of 2^32 or more; in the comparison test that is counted as a refusal.
- Proven security is about 49 bits (unique decoding) for both w30 and w33 at the same FRI parameters; conjectured 127 bits. These are estimator values (`security.rs`), not our proofs.

## C.4 G-C2 timing (laptop only, 2026-11-14)

Raw files: `results/stageC/raw/`; tables, ratios, ZK overhead and security bits: `results/stageC/summary.md` and `summary.json`
(made by `scripts/stagec_summary.py results/stageC/raw`; driver: `scripts/stagec_driver.py`; binary hashes: `results/stageC/raw/binaries.txt`; load1 per run: `results/stageC/raw/load.tsv`).
Verdict by the fixed rule (both BUNDLE2 and BUNDLE3 must pass): PASS. Laptop numbers: they must not go into a paper file.
The R_Auth row is report-only and is a loss for Plonky3 (proof about 3.4x larger, verify about 2x slower).

# w34 changes (2026-11-14, laptop only; plan `journal2/UPGRADE-w34-cloud-plonky3-plan.md` sections 2, 3 and 8)

Backups (before editing): `archive/backups/{request.rs,variants.rs,rel.rs,pchild3.rs,Cargo.toml,README.md}.bak-w34`.
AIR files NOT touched. sha256 before = after (checked before and after the w34 work):
`src/air.rs 00a5381f0173206e...`, `src/rc.rs 5e282b55ae92ff68...`, `src/auth.rs 711604ccda314e76...` (first 16 hex chars; full values in the w34 log of the lead).
Public API is stable: only additions (`NativeChecks`, `check_scope`, `check_stream_link`, `native_bundle_checks`, `native_request_checks`, `verify_request_with`, `verify_bundle_with`, `FriOpts::{std,hi,preset}`, `HI_NUM_QUERIES`, `plain/zk::auth_air_for`). `verify_request` and `verify_bundle` keep their signatures and now run the new checks.

## w34.1 C1: R_RC and R_Exec digests are linked (`src/request.rs:81` `check_stream_link`, called from `native_bundle_checks` at :96, BEFORE any proof is verified in `verify_bundle_with` at :160)
- Equal by construction: R_Exec statement `variants.rs:134` `digest = native_digest(&lay(), &perm(), &words(w))`; R_RC statement `rel.rs:57` `digest = native_digest(&Layout::new(0,12,0), &perm(), words)`; both are the same function (`air.rs:407`) on the same mapped words; the sponge fields used (rate, cap, dig, wlen) of the two layouts are equal (asserted in the test). `n_blocks` and `block_size` come from the same `Workload` / the same words.
- Test `tests/w34_native.rs::digests_equal_by_construction`: seven stream shapes, plain and zk, digest, n_blocks, block_size equal and `check_stream_link` Ok. `stream_link_rejects`: wrong digest / n_blocks / block_size give an error starting with `link: `.
- Checks: `exec_pub.digest == rc_pub.digest`, equal `n_blocks`, equal `block_size`; error prefix `link: `.

## w34.2 C2: scope order (`src/request.rs:69` `check_scope`, called from `native_request_checks` at :110, so `verify_request` and `verify_bundle` both run it)
- Scope public fields: `AuthPublic.scope: ScopeQ` (`src/auth.rs:112-116` struct, `:152` field, public values index 20..25 = `PV_S0`), pairs (start, end): `s` (S range), `e` (epoch range), `t` (time range). `p`, `level` are not ranges.
- The AIR (`RANGES`, `auth.rs:50`) only proves leaf.lo <= start and end <= leaf.hi, so an honest prover can prove start > end inside the leaf (example: leaf s = (500, 4000), statement s = (2000, 1000)). The new check rejects start > end for s, e and t. Verifier only; no AIR change. Error prefix `scope: `.
- Test `scope_order_check`; `checks_on_off_with_real_proofs` (real proofs: ON rejects with `link: ` / `scope: `, OFF accepts).

## w34.3 Test-only switch
`request::NativeChecks { link, scope }` (`request.rs:56`), constants `ON` (production) and `OFF` (both checks off). Production functions use `ON`: `verify_request` = `verify_request_with(NativeChecks::ON, ...)`, `verify_bundle` = `verify_bundle_with(NativeChecks::ON, ...)`. `OFF` exists only for the attack crate (`../pqz-attack-w33`, forms `bundle`, file `raw-*-nochecks.csv`) to show that the two attacks are accepted without the checks. The C_Q link (`check_ctx`) is always on.

## w34.4 C3: preset `fri=hi` (`src/variants.rs:41` `HI_NUM_QUERIES = 102`, `FriOpts::hi()` :49, `FriOpts::preset("std"|"hi")` :53)
log_blowup 3, query_pow_bits 16, final poly 2^5, arity 2^3 (as default), num_queries 102. 102 is the smallest num_queries for which the proven unique-decoding bits of `security.rs` are >= 100 for every relation at every N in {1e3,2e3,5e3,1e4,2e4,5e4,1e5} (searched 1..255 by `src/bin/sectable.rs`, estimator only; test `hi_preset_is_minimal`). Full table (plain and zk, all N): `results/w34-sectable.txt`. Bits (conj / udr / ldr), estimator values:

| N | rel | rows | std (40 q) | hi (102 q) |
|---|---|---|---|---|
| 1e3 | exec, rc | 1024 | 127 / 49 / 73 | 127 / 100 / 86 |
| 1e3 | auth | 64 | 127 / 49 / 74 | 127 / 100 / 94 |
| 2e3 | exec, rc | 2048 | 127 / 49 / 73 | 127 / 100 / 84 |
| 5e3 | exec, rc | 8192 | 127 / 49 / 72 | 127 / 100 / 80 |
| 1e4 | exec, rc | 16384 | 127 / 49 / 71 | 127 / 100 / 78 |
| 2e4 | exec, rc | 32768 | 127 / 49 / 70 | 127 / 100 / 76 |
| 5e4 | exec, rc | 65536 | 127 / 49 / 69 | 127 / 100 / 74 |
| 1e5 | exec, rc | 131072 | 127 / 49 / 69 | 127 / 100 / 72 |
| any | auth | 64 | 127 / 49 / 74 | 127 / 100 / 94 |

zk mode (trace doubled): udr 100 at hi everywhere, ldr 70..90. Caveats: conj is capped at 127; udr 100 is the proven bound of the estimator, not a new proof of ours. Proofs at hi are about 2.4x larger (examples below).
`pchild3 ... fri=std|hi`: default std (output unchanged); label gets the suffix `-hi`; the verifier inside the child uses the same preset (its own `FriOpts`).
Side effect for zk + hi: the hiding PCS fails with `HidingBudgetExceeded { mask_height: 128, num_queries: 102 }` at 128 rows for R_Auth, so the zk R_Auth AIR uses `min_rows` 256 when `num_queries > 40` (`src/rel.rs:47-50` `auth_air_for`, macro arguments at :128-130: plain 64/64, zk 128/256). The std rows are unchanged. The verifier reads the height from the proof (prover side only). Auth is thus 256 rows in zk+hi mode (the table above shows 256 for zk).

## w34.5 C4: `src/bin/pverify3.rs` (verify-only child)
`pverify3 <exec|rc|auth|bundle|request> n=N [block=100] [mode=plain|zk] [fri=std|hi] [reps=25] [depth=10]`.
Proves once (untimed, same code as `pchild3`), then `reps` timed verifications (bytes -> parse -> verify). `bundle` = parse x3 + `native_bundle_checks(ON)` + verify Auth, Exec, RC. `request` (E2) = parse Auth + Exec, `native_request_checks(ON)` (C_Q link + scope; no R_RC, no stream link: the paper's T_PQV excludes R_RC), verify Auth, verify Exec: same body as `request::verify_request`. Output per rep: `VER,<label>,<n>,<rep>,<verify_s>,<bytes>,<conj>,<udr>,<ldr>,<threads>`, then `DONE`; label `<rel>-<mode>[-hi]`; bytes = sum over the proofs; bits = minimum over the proofs; threads = `RAYON_NUM_THREADS`. An honest proof that does not verify exits with code 5.

## w34.6 E3: `pchild3 rcsep n=N block=500 [mode] [fri]` (`src/bin/pchild3.rs`, macro `child_rcsep!`)
G = n/block SEPARATE one-block R_RC proofs (one workload of `block` records, block_size = block, seed 1000+g, each its own statement and proof), proven and verified one after the other in one process. `n` must be a positive multiple of `block` (else exit 2). ROW: label `rcsep-<mode>[-hi]`, n field = N, rows = sum of rows, width = width of one proof, **count field = G**, sum_int = 0, trace_s / prove_s / verify_s / bytes = TOTALS over the G proofs, bits = the estimate (the same for all G). Batched comparison: `pchild3 rc n=N block=500`.
Honest tests (laptop, plain, std, 2 threads; ROW printed only if every proof verified): G=1 (n=500): prove 0.024 s, bytes 123205; G=4: 0.110 s, 495636; G=16: 0.404 s, 1993296; G=64 (n=32000): 1.491 s, verify 0.102 s, 7971424 bytes. Also run: zk + hi G=4 (bytes 1687476). The reject case (n=1000, block=300) exits 2.

## w34.7 Other new files
`src/bin/sectable.rs` (estimator table and the search for the preset; output `results/w34-sectable.txt`), `tests/w34_native.rs` (6 tests), `scripts/w34_smoke.sh` (honest smoke, output `results/w34-smoke.txt`), `Cargo.toml` (two `[[bin]]` entries).

## w34.8 Tests (`cargo test --release`, 2026-11-14)
All pass: 36 (rejection, 4 configs x 9) + 1 (security port vs winterfell) + 3 + 2 + 4 + 4 + 6 (`w34_native`) = 56 passed, 0 failed.

## w34.9 Honest smoke (laptop, 8 threads, NOT for the paper; median of 3; `pchild3 bundle` = prove + verify, `pverify3 bundle` = verify only; raw: `results/w34-smoke.txt`)
Columns: N, mode, fri | trace_s, prove_s (sum of the three proofs), verify_s (pchild3 bundle), bundle bytes | pverify3 bundle verify_s.

| N | mode | fri | trace_s | prove_s | verify_s | bytes | pverify3 |
|---|---|---|---|---|---|---|---|
| 1e3 | plain | std | 0.006 | 0.032 | 0.003 | 407983 | 0.0027 |
| 1e3 | plain | hi | 0.005 | 0.033 | 0.006 | 945119 | 0.0055 |
| 1e3 | zk | std | 0.005 | 0.076 | 0.005 | 578311 | 0.0033 |
| 1e3 | zk | hi | 0.006 | 0.091 | 0.007 | 1382495 | 0.0075 |
| 1e4 | plain | std | 0.080 | 0.321 | 0.006 | 463599 | 0.0034 |
| 1e4 | plain | hi | 0.077 | 0.319 | 0.006 | 1084927 | 0.0054 |
| 1e4 | zk | std | 0.073 | 0.968 | 0.004 | 665959 | 0.0040 |
| 1e4 | zk | hi | 0.071 | 0.988 | 0.011 | 1580895 | 0.0201 |
| 1e5 | plain | std | 0.832 | 4.056 | 0.006 | 516943 | 0.0041 |
| 1e5 | plain | hi | 0.631 | 3.147 | 0.009 | 1210687 | 0.0080 |
| 1e5 | zk | std | 0.604 | 10.830 | 0.005 | 731575 | 0.0053 |
| 1e5 | zk | hi | 0.619 | 10.863 | 0.012 | 1735279 | 0.0121 |

Noise: 3 reps on a laptop with other work at the same time. The pverify3 zk hi verify at 1e4 (0.017-0.020 s in all 3 reps) is slower than at 1e5 (0.012 s) and than the pchild3 value (0.011 s); not explained, most likely machine load; not repeated. Not gated.
`pverify3 request`, honest, 2 threads, median of 3: n=1e3 plain 0.0024 s (276618 bytes), zk 0.0049 s (392450); n=1e4 plain 0.0027 s (305098), zk 0.0055 s (433778); n=1e3 plain hi 0.0048 s (644618).
