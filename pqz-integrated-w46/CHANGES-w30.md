# CHANGES-w30: end-to-end PQZ-Audit driver `w30` (copy of `bench/pqz-integrated`)

Date 2026-11-14. Laptop only: code, tests and a pass/fail smoke. NO timing claim is made here, and no result in `results/` is a real result.
The code has NOT yet been reviewed by the lead.

## What is this
One process = one run. The SAME records go through every phase of the paper in order; each phase has its own monotonic timer (`std::time::Instant`).
Dependencies by path: `../pqz-proof-w29` (STARKs, both hash features), `../pqz-eval` (data, AES-GCM, 45 keyed tags, Bloom, BPS/RPS), `../pqz-ledger`
(AuditBlock, Chain, ledger simulation). Those folders, `pqz-integrated` and `zkalba-eval` were not changed. From `pqz-integrated` only
`src/sys.rs` and the child-per-run driver pattern are reused; the old R_CoverM code is dropped (see "tie" below).

Files: `src/lib.rs` (stages, gates), `src/bin/w30.rs` (driver + child), `src/sys.rs`, `tests/w30.rs` (14 tests), `Cargo.toml`.

Settings (as in w29): S0 = SHA3 commitment hash + single proofs (default build). S2 = Blake3 commitment hash + linked chunks (at most 4 chunks of
whole blocks; build with `--features blake3`). The binary refuses a setting whose hash does not match the build (exit 2).
Proof options are the library defaults (40 queries, blowup 8, grind 16; env PQZ_QUERIES/PQZ_BLOWUP/PQZ_GRIND may override and are written to `env.txt`).
Layouts: clustered, scattered. sigma = N/100 matching records (1 %), exact. Predicate P1 = (A = x).

**Block size is 500, not 100.** The task text said "block 100". Z = 500 is the paper's block size (`pqz_eval::Z`), and every earlier prototype
number (w25-w29) uses 500; N must be a multiple of 500. Not changed on purpose; tell me if 100 is really wanted (it is the constant `BLOCK` in `src/lib.rs`;
results would no longer be comparable to w29).

## Stages and what each timer includes
All timers are inside the child; `total_s` = sum of the 8 stage timers. Not in the total: `gen_s`, `setup_s`, `gates_s`.
| col | stage | what is inside |
|---|---|---|
| `p3a_s` | P3a log construction | per record: AES-256-GCM encrypt + 45 keyed tags (`encrypt_record`), descriptor D_i, leaf, Bloom block summary (`Bloom::build`), block record root R_rec, AuditBlock B_{e,g} (S-hash), epoch root R_e, word stream of R_RC. Single thread. Ciphertext is hashed and dropped. |
| `p3b_s` | P3b R_RC proof | `rc_pub_s` (public inputs: digest, or link states via the reference sponge) + `rc_trace_s` + `rc_prove_s` (prove + serialise). S2: all chunks, one after the other. |
| `p4a_s` | P4a AA verifies | parse + verify every R_RC proof (S2: all chunks + link checks), min 80 bits. |
| `p4b_s` | P4b epoch commit | `led_seal_s` (A_e, ML-DSA sigma_e by the AA, Gamma_e, Omega_e) + `led_txsign_s` (anchor tx signature) + `led_submit_s` (`Ledger::submit`: leader block, 4 validators execute and vote, quorum certificate checked, state root). pqz-ledger used as a library. |
| `p5_s` | P5 request authorization | `auth_prep_s` (statement from `honest_auth_instance`, d_Q from the predicate, Omega from the ledger, B_Q by `bind_hash`) + `auth_trace_s` + `auth_prove_s`. |
| `p6a_s` | P6a search | `bps_s` (`bps_eval` on every block summary) + `rps_s` (`rps_eval` on the 45 tags of every record of every retained block). Single thread. |
| `p6b_s` | P6b R_Exec proof | `exec_prep_s` (copy of the retained blocks' words + claimed result) + `exec_pub_s` + `exec_trace_s` + `exec_prove_s`, over the retained blocks. |
| `p7_s` | P7 requester | `p7_auth_s` (parse + verify R_Auth) + `p7_exec_s` (parse + verify R_Exec; S2 all chunks + links). |

Also in the row: `wall_s`, peak RSS per stage (`peak_*_kb` = VmHWM after the stage, HWM reset before it), proof sizes, rows, chunks, security bits
(`*_conj_bits`, `*_udr_bits`, `*_ldr_bits`), `gate_ledger_read_s` (see gates).
Difference to w29: there the reference-sponge public inputs were outside the proof timers; here they are inside the stage (columns `*_pub_s`), because the
prover needs them.

## Tie between the search and the proofs, and what is NOT tied
How it is tied:
1. The R_RC stream and the R_Exec stream are built from the real records. Record word = [pid, e, seq, id, v, b, tag, 0] with `id` = record id,
   `v` = THETA (2^31) if the plaintext predicate P1 holds else 0, `b` = attribute b, `tag` = first 8 bytes of D_i (little endian) mod p.
2. R_Exec runs over the words of exactly the blocks BPS retained (headers and records copied word for word from the RC stream). The claimed result
   is (count, sum) = (number of ids the exact search (RPS) selected, sum of their b). R_Exec proves: the hash chain of those words, and the predicate
   (v >= theta, count, sum) over them.
3. R_Exec's context `ctx` = B_Q of the Auth statement; the requester verifies R_Exec against the B_Q of the Auth proof it just verified.
4. Auth's Omega = the Omega_e the contract stored (reduced to 4 field elements, 8 bytes LE mod p each).

Gates (outside the timers; any failure = exit 6 and no ROW):
- selected ids == ids from the PLAINTEXT predicate (a == X); no block holding a hit was pruned by BPS (no false negative).
- claimed (count, sum) == plain reference over the plaintext records == `Workload::reference_result` over the Exec words == the Exec statement.
- the ids of the matching words in the Exec stream == the selected ids; the Exec stream == the retained blocks of the RC stream, word for word.
- every record word equals its record (id, b, v) and its descriptor tag.
- both public digests == the reference hash chain (`chain_digest`) recomputed independently over the RC and the Exec words.
- ledger: anchor accepted; light-client read of State[e] (Merkle path + quorum certificate) verifies and its Omega == the Omega in the Auth statement (`gate_ledger_read_s`, not in the total).
- every verifier accepted (P4a, P7); a rejection is exit 5.

NOT tied (the proofs do not enforce it; the gates above only check it from outside):
- The Exec digest is not linked in-circuit to the RC digest, to R_e or to B_{e,g}. A dishonest CSP could prove R_Exec over other words;
  the test `dropped_hit_block_in_exec_stream_is_caught_by_the_gates` shows that the Exec verifier ACCEPTS a stream with a dropped hit block and only the gates catch it.
- Completeness of the Bloom pruning is not proven (R_CoverM is dropped: this is the coverage gap the paper already discloses).
- The mapping record -> word (v from the attribute, tag from D_i) is outside the proofs. R_RC proves the stream structure only, not the encryption relation.
- Auth's B_Q is the Rescue-based `bind_hash` of w29, not the ledger's SHA3 B_Q; Auth policy, scope and uid are the fixed synthetic values of `honest_auth_instance`
  (only d_Q and Omega are overridden). Omega is a reduction of the ledger bytes, not a hash inside the circuit.
- S2: the chunk public inputs travel next to the proofs and their bytes are not counted in `*_proof_bytes`; the digest the verifier uses comes from the last chunk's public output.

## What is still NOT inside the run
ML-KEM wrapped keys WK_i, the homomorphic ciphertext CT_HE and commitment C_i (not in D_i; no such objects in the prototype); H(pi_i^RC) in D_i (our R_RC is one
batch proof made after the descriptors); per-record LP signatures and per-block header signatures (not computed; only the AA's sigma_e and the anchor
transaction signature are real ML-DSA, inside P4b); Authorize/Consume transactions; network and consensus latency (the ledger is a computation-only simulation,
4 validators); ciphertext storage and transfer; HE/CAAS decryption; the requester's key handling. Key and ledger setup are outside the timers (`setup_s`),
data generation too (`gen_s`). P3a and P6a are single-threaded (a CSP would use many cores there); the proofs use all cores (rayon).
D_i here = SHA3(PID, ID, e, seq, H(CT), H(I_PS)); the paper's D_i has four more terms.

## Tests (release only; winterfell debug builds panic on constant trace columns)
`cargo test --release --offline` (S0 build) and `cargo test --release --offline --features blake3 --target-dir target-blake3` (S2 build): 14 tests each, all pass
(2026-11-14). Both proof modes (single, linked) run in both builds. N = 2000 (4 blocks). Honest runs accepted for clustered/scattered x single/linked; `run_one`
end to end incl. stage sum = total; wrong claimed sum/count/theta rejected by the Exec verifier; a proof for a wrong claimed count does not verify; wrong B_Q rejected;
changed Omega or d_Q in the Auth statement rejected; dropped hit block caught by the gates (while the Exec proof of the smaller stream verifies, see above);
a changed word in the Exec stream caught by the gates; RC/Exec digests equal the reference chain and change with one word; descriptor tag and id tie;
ledger anchor accepted, read gate fails for a wrong Omega, State[1] unchanged after a second anchor; bad arguments (N not a multiple of 500, unknown setting).

## Smoke (pass/fail only)
`nice -n 10`, N = 20000, clustered and scattered, S0 and S2, 1 run each: 4 of 4 runs PASS (all verifiers accepted, all gates passed, `failures.txt` empty).
Folders `results/smoke-S0` and `results/smoke-S2` are smoke output, not results; no time from them is to be used. Cold run, laptop, load not controlled.
An S2 request on the S0 binary exits 2 with a message (checked).

## Build
`cargo build --release --offline` -> `target/release/w30` (S0). `cargo build --release --offline --features blake3 --target-dir target-blake3` -> `target-blake3/release/w30` (S2).
`Cargo.lock` was regenerated offline for the three path dependencies.

## Cloud command line (NOT run; needs the user's go-ahead: instance type, region, cost, teardown)
Build both binaries on the machine, then (all vCPUs = rayon default, do not set RAYON_NUM_THREADS; 3 runs per point, one fresh process per run):
```
for N in 100000 1000000; do
  ./target/release/w30         run --setting S0 --n $N --layouts clustered,scattered --runs 3 --limit-s 14400 --out results/w30-S0-n$N
  ./target-blake3/release/w30  run --setting S2 --n $N --layouts clustered,scattered --runs 3 --limit-s 14400 --out results/w30-S2-n$N
done
```
Run alone on the machine (no other load); the driver kills a child when MemAvailable < 4 GiB or after `--limit-s`; failures are in `failures.txt`.
`--limit-s 14400` (4 h per run) is a guess, not based on a measurement; raise it for S0 at 1e6 if needed.

## Expected memory at N = 1e6 (ESTIMATE from the laptop smoke, to be measured)
Smoke peak RSS at N = 20000: S0 about 1.3 GB for a 2^18-row proof, S2 about 0.66 GB for chunks of 2^17 rows (about 5 KB per trace row; this also fits the older
"about 6 GiB at 2^20 rows" note). RC stream rows at 1e6 = (1e6 + 2000 headers) x 8 = 8.0M, padded to 2^23 = 8.4M.
- S0 (single proof): 2^23 rows x about 5 KB = about 40-45 GiB for R_RC; scattered R_Exec retains nearly all blocks, so about the same. Plan at least 64 GiB free.
- S2 (4 chunks of 500 blocks = 2.0M rows, padded 2^21): about 10-12 GiB per chunk (chunks run one after another), plus about 1-2 GiB base
  (tags 720 MB, descriptors 32 MB, words about 64 MB, records, blooms).
- The older plan used r6i.8xlarge (32 vCPU, 256 GiB) for the 1e6 point; by this estimate both settings fit. N = 1e5: S0 about 5-6 GiB, S2 about 2-3 GiB.
