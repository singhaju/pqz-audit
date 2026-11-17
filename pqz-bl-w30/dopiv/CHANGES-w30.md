# DOPIV w30 (F2): optional Blake3-256, changes against `bench/pqz-bl/dopiv`

Plan: `journal2/UPGRADE-w30-plan.md` section 1 (F2). Reason: our prover now commits with Blake3-256, so the baseline is offered the same lever.
This folder is a copy (`cp -a`) of `bench/pqz-bl/dopiv`; the original is unchanged. No path dependencies existed, nothing to fix.
`FIDELITY.md` is the ORIGINAL text (not edited); where it says "Hash = SHA3-256" read: SHA3-256 by default, Blake3-256 with `--hash blake3`.

## What changed
| file:line | change |
|---|---|
| `Cargo.toml` | `blake3 = "=1.8.7"` (default features; the version in the w29 prover lock) |
| `src/lib.rs:278-298` | `enum HashKind { Sha3, Blake3 }` (`name()`, `parse()`) |
| `src/lib.rs:300` | `blake3_compressions(msg)`: Blake3 compression-call counter (64-byte blocks + parent nodes) |
| `src/lib.rs:307` | `expand_zq(...)` kept with the old signature; it is SHA3 and calls `expand_zq_with` |
| `src/lib.rs:313-355` | `expand_zq_with(kind, ...)`: THE ONLY place a digest is computed. `Sha3` branch = old code verbatim; `Blake3` branch = `blake3::Hasher` over the same bytes (domain, length-prefixed parts, 4-byte counter), 32-byte output, same counter-mode expansion with rejection (word < q) |
| `src/lib.rs:382` | `Instance.hash: HashKind` field |
| `src/lib.rs:397,399,403,413` | H4, H5, H2, H6 call `expand_zq_with(inst.hash / kind, ...)` |
| `src/lib.rs:428-435` | `Instance::setup` unchanged signature (= SHA3); new `setup_with_hash(.., hash)` |
| `src/lib.rs:455,610` | `h5` gets the hash kind (setup planting, verifier step 1) |
| `src/bin/dopiv-bench.rs` | flag `--hash sha3|blake3` (default sha3); `raw_runs.csv` and `opcounts.csv` get a LAST column `hash` (old parsers that read the first columns still work); `eprintln!("hash = ...")` |
| `tests/hash_w30_tests.rs`, `tests/orig_digest.txt` | new tests (below) |

## Every hash call of DOPIV (all in `expand_zq_with`; each switches with `--hash`)
Timed path, `--cov ... --params-tag e4a` (and the same with `--lazy`; `--lazy` only changes the modular reduction, not the hashing):
- `proofgen` (lib.rs:585 `h6`): 1 logical H6 over warrant, v_w, theta_w, xi (about 66 KB at m = 16384). One digest call (the output is one word < q).
- `verify` (lib.rs:610 `h5`, 616 `h4`, 625 `h6`): n = 256 H5 (32 digest calls each: n words), c H4 (32 each), 1 H6. Table 2: (n+c+1) logical Hash; checked by the harness assert.
- `verify_q` (`--q`, not in the e4a jobs): q times the same `verify`.
- `verify_delegation` (lib.rs:665 `h2`): only without `--cov` (default grid), 1 H2.
- Untimed set-up (planting, lib.rs:455 `h5`, 489 `h2`, 515 `h4`): the instance is planted so that the verifier's hashes hold, hence it uses the SAME hash (blake3 run = blake3-planted instance). Not timed.
- `challenge`: no hash (SplitMix64, not cryptographic). Harness: no hash.

## What stays SHA3 (and why)
Nothing in DOPIV's own construction stays SHA3 under `--hash blake3`. DOPIV defines Hash only as "a general hash function"; there is no paper-fixed SHA3 digest.
The `sha3` crate is still linked (used when `--hash sha3`, the default). The counter name `sha3_calls` in `opcounts.csv` and the `Counts.sha3` field keep their name
(old parsers); under `--hash blake3` the column holds Blake3 compression calls (the `hash` column says which). `hash_logical` is identical for both hashes.
Not hashing: the matrix-vector products (mod q), Rng. DART, Dong: not changed (plan).

## Tests (release): `cargo test --release`, 23 pass (16 old + 7 new)
New (`tests/hash_w30_tests.rs`), each for Sha3 and Blake3 (and lazy/each where stated):
- honest proofs verify (5 challenges, both reductions), `proof_verify_full`, delegation.
- changed record word, changed tag entry, changed f / e / xi entry, single-bit flips (3 positions x 3 bits in each of f, e, xi), proof for another challenge, changed warrant, changed v_w: all rejected.
- cross-hash: instance planted under one hash, verified under the other: rejected (proves every H2/H4/H5/H6 call is switched).
- operation counts equal Table 2 (Hash, mul) under both hashes; `expand_zq_with` Blake3 equals a direct `blake3::hash` of the encoded input; the default `expand_zq` is SHA3.
- `sha3_run_digest_is_stable`: for fixed seeds (n=16, m=1024, ell=24, seed 7, rng 99) a digest of all planted data blocks, Q_IDo and the proof (f, e, xi) equals the value from the ORIGINAL crate (`dc749cae842b373a`, in `tests/orig_digest.txt`). The original was built untouched: a small program in the scratchpad depends on `bench/pqz-bl/dopiv` by path, `CARGO_TARGET_DIR=<scratchpad>/dopiv-orig-target` (the old code is deterministic).
- Old binary vs new binary (`--cov 1000 --params-tag e4a --runs 2 --warmup 1`): `opcounts.csv` of the new default run and of `--hash sha3` equal the original's, byte for byte, after dropping the new last column; console lines equal except the new `hash = ...` line and timings; sigma 149 equal.
Smoke (one run each at `--cov 1000`, `--hash sha3`, `--hash blake3`, `blake3 --lazy`): all finish, honest proofs accepted, Table 2 counts asserted. No timing claim is made from these (other builds were running).

## Cloud command lines (same as w20: `bench/cloud-w20/remote_w20.sh`, COVS = 7 points)
`COVS=1000,2000,5000,10000,20000,50000,100000` (ell = 100000 planted blocks, about 10 GB RAM, about 550 s planting; one job per line as in w20). Binary: `target/release/dopiv-bench` of THIS folder. Use a different `--out` per job (the `params` string is the same for both hashes; the `hash` column tells them apart):
```
dopiv-bench --cov 1000,2000,5000,10000,20000,50000,100000 --params-tag e4a --runs 30 --warmup 3 --hash sha3   --out <dir>/dopiv-sha3-e4a
dopiv-bench --cov 1000,2000,5000,10000,20000,50000,100000 --params-tag e4a --runs 30 --warmup 3 --hash blake3 --out <dir>/dopiv-blake3-e4a
dopiv-bench --cov 1000,2000,5000,10000,20000,50000,100000 --lazy --params-tag e4a --runs 30 --warmup 3 --hash sha3   --out <dir>/dopiv-lazy-sha3-e4a
dopiv-bench --cov 1000,2000,5000,10000,20000,50000,100000 --lazy --params-tag e4a --runs 30 --warmup 3 --hash blake3 --out <dir>/dopiv-lazy-blake3-e4a
```
(`--runs-big 5 --big-above 2000` defaults apply as in w20: cov > 2000 gets 5 timed runs, 1 warm-up.) Without `--hash` the old behaviour is the same as `--hash sha3`.

## Disclosures
- Blake3 (SIMD, tree hashing of the 66 KB H6 input) is a different class of speed from SHA3-256; the plan compares against the faster DOPIV form. Report both forms. Choose the Blake3 form of DOPIV only if the measured numbers say so.
- Counter-mode expansion is unchanged for both hashes (a Blake3 XOF output would need fewer compressions than 32 separate digests per n-word hash; not used: we keep the construction identical and change only the digest. This still favours our side, like the SHAKE note in FIDELITY.md).
- The `sha3_calls` column is not comparable across hashes (Keccak permutations vs Blake3 compressions).
