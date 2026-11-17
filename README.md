# PQZ-Audit: source code of the prototype and the experiments

This folder holds the source code behind the experiments of the paper
"PQZ-Audit" (file `pqz-audit-journal-final2.tex`, 18 pages, Experiments 1-9).
It is a research prototype for a course submission (CSS453).

## What PQZ-Audit is
PQZ-Audit is a scheme for auditing cloud logs while the logs and the audit query stay private.
It combines a protected audit log (keyed-hash search tags, block Bloom filters, BFV homomorphic
aggregation, Merkle-authenticated blocks), post-quantum authentication of the audit request
(ML-DSA-65, ML-KEM-768), a blockchain-held canonical audit state, and STARK proofs
(Plonky3 0.8.0, Goldilocks field, Blake3) that the audit result was computed from the committed log.
The prototype proves the record-consistency and authorization relations and a partial execution relation.
It does not implement zero knowledge in the main experiments or the complete execution relation
(see the paper, Section on limitations).

## Folder table
One folder per Rust crate (or Go component). The folder names are the original names; crates refer
to each other by relative path (for example `../pqz-proof-w30`), so keep the folders side by side.

| Folder | What it is |
|---|---|
| `pqz-eval` | Protected log, search, HE aggregation. Program `exp` (Exp 1, 2, 3) |
| `pqz-proof`, `pqz-proof-w30` | Proof benchmark and ablation (`proofbench`), proof options (`w30`), shared proof library |
| `pqz-ledger` | Ledger (emulated blockchain) benchmark, program `ledgerbench` (Exp 5a) |
| `pqz-ledger-bl-w37` | Per-record ledger baselines v1/v2 (Exp 5) |
| `pqz-ledger-fabric-w45` | Hyperledger Fabric run for Exp 5: chaincode (`pqzcc`), client, configs, `run_all.sh` (Fabric binaries and test-network not included) |
| `pqz-bl/{dong,dopiv,dart,lhcpm}`, `pqz-bl-w30/{dopiv,lhcpm}`, `pqz-bl-par/*`, `pqz-bl-w39/{dart-zk,dart-zk-par}` | Baselines reimplemented from the published algorithms (Dong et al., DOPIV, DART, L-HCPM); `-par` = multithreaded copies; `dart-zk` = DART with its SNARK step |
| `pqz-plonky3-w36`, `-w38`, `-w39zk`, `-w46` | STARK prover/verifier (`pchild3`, `pverify3`, `pzk3`, ...) in the old and the packed format P2r. `-w38` produced Exp 4, `-w46` is the latest |
| `pqz-attack-w36`, `pqz-attack-w38` | Forged-proof tests (Exp 8): old format (w36), packed format (w38) |
| `pqz-integrated-w46` | End-to-end audit programs `w34`, `w35` (Exp 7; `--fmt old|p2r`) |
| `pqz-exp9-w46` | Comparison with ZKSQL, our side (Exp 9) |
| `scripts-exp9-zksql` | Helper scripts used to drive ZKSQL (ZKSQL itself is the authors' code and is not included) |

## Requirements
- Linux x86-64, Rust stable toolchain (edition 2021), `cargo`. The proof crates were built with
  `RUSTFLAGS="-C target-cpu=x86-64-v3"` (AVX2); this is optional but is what the paper used.
- Crates download from crates.io on the first build (`Cargo.lock` is included; use `--locked`).
- Python 3 for the analysis scripts; Go 1.2x and Docker only for the Fabric run.
- The experiments were run on AWS r6i.8xlarge (32 vCPU, 256 GiB). Large cases need a lot of RAM.

## Build
```
cd pqz-eval && cargo build --release --locked
cd pqz-plonky3-w46 && cargo build --release --locked
cd pqz-integrated-w46 && cargo build --release --locked --bin w34 --bin w35
```
Each folder is its own crate (no top-level workspace). Build the ones you need.
Checked for this package: `cargo check --offline --locked --all-targets` passes in all 24 crates.

## Experiments to programs
Commands are taken from the runner scripts used for the paper; `$OUT` is any output folder.
Raw results are not included.

| Exp | Topic | Crate and program | Example command (source) |
|---|---|---|---|
| 1 | Query scalability | `pqz-eval`, `exp` | `exp exp1d --runs 30 --warmup 3 --out $OUT` (cloud-w36b `steps_B.sh`) |
| 2 | Private predicate execution | `pqz-eval`, `exp` | `exp exp2bd --out $OUT`, also `exp2a`, `exp2c` (cloud-w36c `steps_C.sh`) |
| 3 | Private aggregation | `pqz-eval`, `exp` | `exp exp3a`, `exp3b`, `exp3ad` with `--out $OUT` (cloud-w36c `steps_C.sh`) |
| 4 | Proof generation and verification | `pqz-plonky3-w38` (`pchild3`, `pverify3`; ZK mode `pzk3` in `-w39zk`), baselines in `pqz-bl*`, `pqz-bl-w39/dart-zk` | `pchild3 p3-exec,p3-rc fast1 plain trace=seq fmt=p2r ...`, driven by `w39_driver.py` (cloud-w39 `steps_w39.sh`, not included) |
| 5 | Blockchain overhead | `pqz-ledger` (`ledgerbench`), `pqz-ledger-bl-w37`, `pqz-ledger-fabric-w45` | `ledgerbench ...`; Fabric: `bash run_all.sh` (needs a Fabric test network) |
| 6 | Ablation | `pqz-eval` `exp` (block filter, selective HE), `pqz-proof` `proofbench ablation` (RC batching) | `proofbench ablation --out $OUT` (cloud-w36c `steps_C.sh`) |
| 7 | End-to-end audit cost | `pqz-integrated-w46` `w35`, `w34` | `w35 run --setting P3 --n 100000 --layouts <clustered,scattered> --runs 3 --chunk 4 --gap-merge 1 --fmt p2r --out $OUT`; `w34 run --setting P3 --n 100000 --layouts ... --runs 3 --exec-stream whole --fmt p2r --out $OUT` (cloud-w46 `steps_w46.sh`) |
| 8 | Security testing | `pqz-attack-w36` (old format, 34 attacks), `pqz-attack-w38` (packed format) | `bash run-all.sh` in the folder; or `attack run fmt=p2r out=$OUT attack_trials=20 honest_trials=50 n20k=3 n50k=1 h20k=4 h50k=1` then `attack merge $OUT` |
| 9 | Comparison with ZKSQL | `pqz-exp9-w46` (our side), `scripts-exp9-zksql` (ZKSQL side) | `pqz-exp9-w46 export <N> <layout> <csvdir>`; `pqz-exp9-w46 child <kind> n=<N> layout=<L> preset=<P> zk=<0/1> fmt=p2r vreps=<R> run=<tag>` (cloud-w46 `steps_E9.sh`) |

Exact layout names, layouts and flags are in each crate's `README`/`CHANGES-*.md` and in the `--help`
of the program. Exps 7 and 9 in the paper use the packed format P2r (`--fmt p2r`, folder `-w46`);
Exp 4 uses the packed format from `pqz-plonky3-w38`. Exps 1-3, 5, 6 use the older, unchanged crates.
The mapping was made by reading the runner scripts and the paper; the Exp 8 trial counts quoted in the
paper (1180 + 1300 attack trials) were not re-run for this package.

## Notes and limits
- Research prototype. Not audited, not for production use.
- The ledger in Exps 5a-7 is an emulated ledger; Exp 5 also has a run on a real Hyperledger Fabric test
  network on one host (no network latency between nodes). The Fabric binaries, test-network scripts and
  vendored Go modules are not included.
- Numbers in the paper were measured on AWS r6i.8xlarge; other machines give different times.
- Baselines are our own reimplementations from the published algorithms, not the authors' code.
- ZKSQL (Exp 9) is not included; only our side and the helper scripts.
- The packed run proof does not itself check v < 2^32, b < 2^20 or the record grammar; the chunk proofs do
  (stated in the paper's limitations).
- Result data, cloud launch kits, credentials and logs were left out on purpose.

## Demo
`bash demo/run.sh` builds `pqz-integrated-w46` (about 1 minute the first time) and runs one small audit (N = 10,000, packed format P2r) in about 1 second, then prints the main timings. It is the existing program `w35`; the numbers are laptop smoke values, not paper numbers.

- `bash demo/run.sh`: build and run one small audit (N = 10,000) and print the main timings.
- `bash demo/demo.sh`: the talk demo (needs Python `rich`). A hospital access log of 10,000 records: phases 1-7 one panel each, then a menu: attack A2 (the cloud hides a block with matches, REJECTED), the other attacks A1-A7, and predicate examples. `--no-pause`, `--all-attacks`, `--scenario a1..a7`, `--full`. Details: `demo/DEMO-README.md`; saved output: `demo/fallback/`.
- `bash demo/show.sh <key>`: open the code for a phase or topic at the right line (`show.sh list` for keys, `--term` to print it). Map: `demo/CODE-MAP.md`.
- `bash demo/explain.sh`: the same pipeline step by step (10 steps) with real values: records, ciphertext and tags, a block, R_e, chunk proofs, the anchor and Omega, the auth proof, pruning, the run proof, requester check.
- `demo/guide.html`: open in a browser (offline). Clickable guide with 13 sections, diagrams, real outputs and links to the code on GitHub. Arrow keys move between sections.

All demo numbers are from a laptop run and are not paper numbers. The STARKs are plain mode (not zero-knowledge) and the chain is simulated in one process.
