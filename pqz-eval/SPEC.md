# pqz-eval: prototype of PQZ-Audit for the evaluation (Stage A)

Paper: `journal2/pqz-audit-journal-main11-professor.tex` (read-only). Plan: `journal2/EXPERIMENT-PLAN-main11.md`.
New crate, not part of the frozen `bench/zkalba-eval`. Rust 2024, no `unsafe`, no network, deterministic (ChaCha seeds).

PROVISIONAL CHOICES (the professor has not chosen; each is written in the paper's limitations when final):
- hash SHA3-256 (`sha3`), AEAD AES-256-GCM (`aes-gcm`), KDF HKDF-SHA3-256 (`hkdf`), KEM ML-KEM-768 (`ml-kem`), signature ML-DSA-65 (`ml-dsa`), HE = BFV (`fhe`), proofs = STARK (`winterfell`, Stage B).
- protected search = keyed-hash tags + block Bloom summary (below). It leaks the search pattern and which blocks match. Say so; do not call it "secure".

## Stage A scope (this task): modules `gen`, `eapat`, `search`, `he`, `bench` and the binary `exp`
Not in Stage A: proofs, ledger, threshold (Stage B/C).

### gen (data generator)
`Record { id:u64, ts:u64, a:u32, b:u32, c:u32, d:u32 }`; domains a in 0..1000, b in 0..2^20, c in 0..1000, d in 0..1000.
`Predicate` P1..P4 exactly as in the paper: P1 A=x; P2 A=x and B>=y; P3 (A=x and B>=y) or C=z; P4 (A=x and B>=y) and (C<z or D=w). Fixed x=7, y=2^19, z=500, w=3.
`gen(n, sigma_count, layout, seed)` returns records where EXACTLY `sigma_count` records satisfy the predicate (all four P1..P4 are true on the same set):
hits have a=x, b>=y, c<z (c != z), d=w; non-hits have a != x and c != z (other attributes random). Hits are `Layout::Clustered` (a contiguous index range starting at a seeded offset; records are ordered by ts = id) or `Layout::Scattered` (uniformly random distinct indices). A unit test checks the hit count for every predicate and layout.

### eapat (Phases 1-2: protected log)
- Epoch master key from seed; per-record key = HKDF-SHA3-256(master, "rec"||id); AES-256-GCM, nonce from id (document uniqueness argument), AAD = id||ts.
- Per record: ciphertext, `tags` (see search), HE ciphertext of `b` (see he) only if requested (a_HE=1).
- Leaf = SHA3-256(id||ciphertext||tags); block = m_B consecutive records; Merkle root per block (binary, SHA3-256, domain-separated leaf/node).
- Block header = (block_index, count, merkle_root, summary_digest, prev_header_hash); header signed with ML-DSA-65. Epoch finalization = hash of all header hashes. `verify_block` and `verify_chain` exist and are tested (tamper a leaf -> fail; drop a block -> fail).
- API returns timing-friendly pieces: `encrypt_record`, `build_block`, `finalize_epoch`; memory: ciphertexts of 10^6 records must fit in 30 GB (keep the HE ciphertexts out of the block store, see he).

### search (protected search; BPS = block summary, RPS = record evaluation)
- Tag(attr, value) = first 16 bytes of SHA3-256(k_s || attr || value_le). Equality attributes (a, c, d): one tag. Numeric attributes (b, c for `<`): dyadic prefix tags over 20 bits: record stores 21 tags (one per prefix length). Range B>=y and C<z are turned into at most 20 dyadic intervals; the trapdoor is the list of their tags. C=z uses the equality tag, C<z the prefix tags (store both).
- Record-level (RPS): `rps_eval(record_tags, trapdoor_formula) -> bool` evaluates the Boolean formula over tag membership. Exact (no false positive).
- Block-level (BPS): per block a Bloom filter over all tags of its records (sized for <=1% false-positive rate at m_B records, k hash functions taken from slices of the tag, no extra hashing). `bps_eval(bloom, formula) -> bool` evaluates the same formula with leaf = "some tag of this leaf is possibly present". Conservative: never false negative. A test must show no false negative for P1..P4, both layouts, and measure the false-positive rate.
- `Formula` enum: Leaf(Vec<Tag>) / And / Or. P1..P4 built by `formula_for(P, key)`.

### he (aggregation)
BFV via `fhe` (degree 2048 or the smallest parameters that hold SUM of 10^6 values below 2^20 without overflow; document the parameters and why). `encrypt(b)`, `add`, `decrypt`. Memory rule: the paper stores one HE ciphertext per record; at 10^6 records that does not fit. Use a POOL of K=1024 pre-encrypted ciphertexts cycled over the records for the timing of `add` (addition time does not depend on the plaintext); the harness states this in its output header. Correctness test: sum of a pool-based selection equals the plaintext sum.

### bench (harness) and binary `exp`
`exp <name> [--n ...] [--runs 30] [--warmup 3] [--out results/]` writes ONE CSV per experiment, appending nothing and overwriting nothing (error if the file exists). Columns: `exp,series,n,mb,sigma,layout,predicate,agg,approach,run,warmup,time_ns,n_blocks,n_retained_blocks,n_q,n_sel`. Raw rows only, no aggregation inside. `results/env.txt` records CPU model, kernel, rustc version, `Cargo.lock` hash, git-free code hash (sha256 of src), seed.
Experiments in Stage A: `exp1` (N in 1e4,5e4,1e5,5e5,1e6; m_B=500; series `sigma1pct` and `fixed_nq1000`), `exp2a` (P1..P4; N=1e6; sigma 1%; approaches `trad_scan` (plaintext), `prot_full_scan` (RPS on all records), `pqz` (BPS on all blocks, RPS on retained blocks); both layouts), `exp2b` (sigma 0.1,1,5,10,25%), `exp2c` (m_B 100,250,500,1000), `exp3a` (selected fraction as 2b; approaches `plain_agg`, `full_he` (adds over all N), `pqz` (adds over n_Q)), `exp3b` (COUNT, SUM, AVG at 1%: COUNT = cardinality, SUM = adds, AVG = adds + one division after decrypt), `exp1_construction` (build time per record split into AEAD, tags, signature, Merkle; storage bytes).
Measurement boundary per experiment: time only the named operation (query = BPS + RPS + result list; aggregation = adds only; no setup, no proof). Use `std::time::Instant` and `std::hint::black_box`. Gate every result: the three approaches must return the SAME selected set on the same input (assert; a mismatch aborts).
A `--smoke` flag runs tiny sizes (N=2000, 3 runs) for tests.

`exp3c` (added 2026-10-31, tests H3: aggregation time versus N; series `n_sweep`): N in 1e4, 5e4, 1e5, 5e5, 1e6; m_B=500; selectivity 1% (sigma = N/100); both layouts; predicate P1; agg SUM; approaches `plain_agg`, `full_he`, `pqz`, same code path, measurement boundary (adds only) and HE pool as `exp3a`; same CSV columns (rows carry mb=500, predicate=P1). Runs follow the `exp3a` rule (`full_he` 10 timed + 1 warm-up, others 30 + 3). Before timing, an untimed gate checks that `trad_scan`, `prot_full_scan` and `pqz` (BPS then RPS) return the same id set for P1 with the generated cardinality; the HE result is then gated against the plaintext sum as in `exp3a`. `--smoke` uses N=2000 only; `--n` runs one N. The full run is not part of `run_full.sh`.

COUNT rule (corrected 2026-10-31 after the paper's text, `pqz-audit-journal-main11-professor.tex` lines 2875-2882): in PQZ-Audit, COUNT is the cardinality n_Q of the verified selected set and needs NO HE aggregation. So `pqz` + COUNT (exp3b and exp3d) times only the cardinality step (`selected.len()` through `black_box`), with no pool `add` and no decrypt; the check that n_Q equals the generator's sigma_count is outside the timed region. `plain_agg` COUNT counts the selected records, as before. `full_he` COUNT is unchanged: homomorphic sum of Enc(1) over all N records; this is our definition of the Full-Domain baseline's COUNT (a choice of ours, not taken from the paper). AVG in `pqz`: adds over the n_Q selected ciphertexts (timed), decrypt, then ONE integer division by n_Q after decrypt (not timed); for n_Q = 0 the paper defines AVG as undefined, and the harness aborts with an error instead of returning 0.

`exp3d` (added 2026-10-31, tests H3 for COUNT: aggregation time versus selected fraction; series `count_sweep`): N=1e6 (`--n` overrides), selected fraction sigma in 0.1, 1, 5, 10, 25% (as `exp3a`), layout clustered, predicate P4, agg COUNT, approaches `plain_agg` and `pqz` ONLY, 30 timed + 3 warm-up. `full_he` is left out on purpose: its cost does not depend on selectivity (it adds over all N) and it costs about 100 s per run. Same code path, measurement boundary and gates as `exp3a`/`exp3b`; `pqz` COUNT follows the COUNT rule below (no HE, cardinality only), so the `pqz` COUNT time is expected to stay flat in sigma: the selected set comes from the plaintext P4 filter (no protected log is built, so the rows carry mb=0 as in `exp3a`; the plan's m_B=500 does not enter an aggregation that never touches blocks), `plain_agg` and `pqz` reduce over this same set, and the run aborts if the set size is not the generator's sigma_count or if the decrypted COUNT differs from it. Same CSV columns. `--smoke` uses N=2000 and 1% only. The full run is not part of `run_full.sh`; use `run_exp3d.sh <results-dir>`.

## Rules
Do not edit anything outside this crate. No `unsafe`. Every module has unit tests; `cargo test --release` must pass. No invented numbers anywhere: the code prints what it measures. Keep `Cargo.lock`. Comments only where the reason is not obvious.
