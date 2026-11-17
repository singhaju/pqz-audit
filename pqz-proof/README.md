# pqz-proof (PROVISIONAL)

Hash-based STARK prototypes (winterfell 0.13.1, FRI, Rescue Prime inside the circuit) of the three PQZK relations of
`journal2/pqz-audit-journal-main11-professor.tex`: R_RC, R_Auth, R_Exec. Plan reference: `journal2/EXPERIMENT-PLAN-main11.md`,
Exp 4 (prove/verify cost) and Exp 6 (ablation).

PROVISIONAL means: the professor has not chosen the proof system (open decision 1 in the plan). This crate only gives a first
measurement. It is not a claim about the final system, and it does not prove the paper's relations in full. Read `DESIGN.md`
before quoting any number; its section 5 lists the deviations. The three that matter most:

1. The hash inside the circuit is Rescue Prime (algebraic), not SHA3. Numbers are for an arithmetization-friendly hash.
2. No zero-knowledge: winterfell 0.13.1 has no ZK mode; opened trace rows reveal witness values (R_Auth's policy leaf is constant in
   the trace). These are succinct arguments of knowledge only.
3. The record set is a sequential sponge chain, not the paper's Merkle tree (EAPAT). No pruning, no HE/AE/PS relation, no ML-DSA,
   count and sum are plaintext stand-ins, theta is public.

## Security wording

Winterfell does not offer a default; this crate uses 40 queries, blowup 8, 16 bits grinding, quadratic extension, FRI folding 8,
remainder degree 31 (`src/prove.rs`). `proofbench` prints, for every proof, the library's own estimates: `conjectured_security`
and the two proven bounds (unique-decoding and list-decoding). They are the library's estimates for these options, nothing more.
The verifier accepts only proofs with at least 80 conjectured bits. The construction uses only hash functions (SHA3-256 for the proof's
Merkle trees and Fiat-Shamir, Rescue Prime in the AIR) and no group assumption; this crate does not claim post-quantum security
beyond that, and we have not checked how the library's estimate treats quantum adversaries.

## Layout

- `DESIGN.md`: what each AIR proves, public and private input, what is not proven, deviations.
- `src/rescue.rs`, `src/chain.rs`, `src/data.rs`, `src/prove.rs`: permutation constraints, chain layout, synthetic workload, prover wiring.
- `src/rc.rs`, `src/auth.rs`, `src/exec.rs`: the three AIRs with prove/verify functions.
- `src/bin/proofbench.rs`: benchmark driver. `scripts/summarize.py`: median/min/max per point from `raw.csv`.
- `src/cover.rs`, `src/bin/cover.rs`, `tests/cover.rs` (16 tests, release only), `scripts/summarize_cover.py`: relation R_Cover (BlockCover + PruneValid), see `DESIGN.md` section 7 and `TASK-cover.report.md`; results in `results/cover-1/`, `results/cover-2/`.
- `tests/relations.rs`: 20 tests (`cargo test --release`; `cargo test` in debug also validates the declared constraint degrees).
- `results/<run>/raw.csv`, `env.txt`, `failures.txt`: raw data, machine, and any stopped points.

## How to run

    cargo test --release
    cargo build --release
    ./target/release/proofbench smoke --out results/smoke   # quick check: 1 warm-up + 3 runs per point, N_Q up to 1e4
    ./target/release/proofbench full  --out results/full   # the matrix below
    python3 scripts/summarize.py results/full/raw.csv

Options: `--threads N` (sets RAYON_NUM_THREADS; default is all logical cores), `--only scale` or `--only q`.

Every measurement point runs in a fresh child process (so the peak RSS of a point is not polluted by earlier points). Peak RSS is VmHWM
from `/proc/self/status`, reset with `/proc/self/clear_refs` before each phase (`hwm_reset_ok` column). `prove_peak_rss_kb` covers
witness (trace) construction plus proving; `verify_peak_rss_kb` is measured after resetting again, but memory the allocator still holds
from proving counts in it, so use `verify_rss_baseline_kb` to see that baseline.

## Matrix and run rule

- Scale: R_RC and R_Exec at N_Q in {1e3, 1e4, 1e5} (block size 100). N_Q above 1e5 is refused by the program. R_Auth does not depend on N_Q; it is
  run at policy-tree depth 10 and 20.
- q verifications: at 1e3 records (R_Auth depth 10), q in {1, 10, 25, 50, 100, 200}; "same" = the same proof verified q times, "distinct" =
  q distinct proofs; each for R_RC, R_Auth, R_Exec and the "bundle" (one query = the three proofs). Verification includes parsing the proof
  bytes (`Proof::from_bytes`).
- Run rule, per point: the first run is a probe. If it takes under 60 s: 3 warm-up runs (the probe is the first) and 30 timed runs, rule
  label "30 runs + 3 warm-up". Otherwise: 5 runs in total, no warm-up, the cold probe counted as run 1, rule label "5 runs (...)". The
  `rule` column of every row states which rule applied. The `warmup` column is 1 for warm-up rows; summaries use only `warmup = 0`.
  Smoke runs use "quick(1 warmup+3)" and are not measurements to quote.
- Stops: the driver kills a point if no run finishes for 600 s (a run over 10 min) or if MemAvailable drops under 1.5 GiB (the machine is
  shared), writes the reason to `failures.txt` and skips larger N_Q of that relation.
- Timed region of `scale`: `trace_s` (witness trace construction), `prove_s` (proving), `verify_s` (parse plus verify). Workload generation
  and the reference digest are outside the timers.

## Limits

- Timings were taken on a shared laptop (other jobs were running; `loadavg1` is recorded per row), 22 logical cores, rayon default threads.
  Treat them as indicative, not as clean benchmark numbers.
- The workload is synthetic (uniform 32-bit values). The match fraction does not change the circuit cost: every record runs the same rows.
- Proof sizes are for the default options. Changing the number of queries changes size, time and security linearly or nearly so.
- R_Exec reads all retained records in digest order; its cost follows the retained set N_Q, not the log size N. Pruning against a tree
  (the paper's PruneValid, BlockCover over epochs) is not modelled.
- Verification time here is near-constant in N_Q (logarithmic in trace length) for these sizes; it excludes everything the paper's Phase 7
  verifies outside the three proofs (signatures, ledger checks, HE decryption).
- Nothing here has been reviewed for cryptographic soundness beyond the tests; the AIRs are minimal and have not been audited. Known gaps
  are in `DESIGN.md` (for example `tag` is unconstrained, `ctx` is bound only through Fiat-Shamir).

## Results of the first full run (`results/full-1/`, summary in `results/full-1/summary.txt`)

Machine and settings: `results/full-1/env.txt` (Intel Core Ultra 7 165H, 22 logical cores, rustc 1.99.1, rayon default threads).
The machine was shared: the 1-minute load average recorded per row ranged from 8 to 31, so absolute times are noisy; the spread over the 30
timed runs is in the summary. Every point ran under the rule "30 runs + 3 warm-up" because every run was under 60 s. No point hit the memory
guard or the 10-minute stop (`failures.txt` is empty). Median over 30 runs (min to max in `summary.txt`):

| Relation | N_Q | trace rows | prove (s) | verify (ms) | proof (KiB) | prover peak RSS (MiB) |
|---|---|---|---|---|---|---|
| R_RC | 1e3 | 8192 | 0.072 | 1.42 | 68.1 | 51 |
| R_RC | 1e4 | 131072 | 0.876 | 2.14 | 99.6 | 682 |
| R_RC | 1e5 | 1048576 | 7.53 | 2.17 | 130.0 | 5416 |
| R_Exec | 1e3 | 8192 | 0.075 | 1.54 | 70.4 | 56 |
| R_Exec | 1e4 | 131072 | 0.923 | 2.20 | 102.9 | 809 |
| R_Exec | 1e5 | 1048576 | 8.38 | 2.25 | 133.4 | 6128 |
| R_Auth depth 10 | (none) | 256 | 0.016 | 0.77 | 35.4 | 6 |
| R_Auth depth 20 | (none) | 512 | 0.021 | 1.10 | 43.4 | 8 |

Witness (trace) construction time is separate (`trace_s`, 0.7 s at 1e5). Library estimates for these proofs: conjectured 127 bits;
proven bound 49 bits (unique decoding) and 66 to 74 bits (list decoding), depending on trace length. Only the conjectured figure is
near the usual 128-bit target, and it is the library's conjecture; the proven bounds are lower. If the paper quotes a security level for
this proof system, the options (queries, blowup) must be chosen for the bound it intends to claim.

q verifications at 1e3 records (R_Auth depth 10), per-verification mean over q = 200: R_RC 1.11 ms (same proof) and 1.13 ms (distinct);
R_Exec 1.12 and 1.13 ms; R_Auth 0.67 and 0.66 ms; bundle (three proofs, about 177 KB) 2.97 and 3.20 ms. The mean per verification at q = 200
is not higher than the q = 1 value in any row (up to 12 percent lower, for example bundle, same proof: 2.97 vs 3.37 ms), so no growth with q
is visible; the lower value at larger q is probably warm caches, which we did not test. Full table: `summary.txt`.

## Exp 6 ablation "w/o Batched RC" (`proofbench ablation`)

`proofbench ablation --out <dir> [--threads N] [--quick]` compares one batched R_RC proof over G*500 records (G blocks of m_B = 500, series
`batched`) with G separate R_RC proofs of one 500-record block each, proved and verified one after the other in the same process (series
`per_block`), for G in {1, 4, 16, 64} (`--quick`: G in {1, 4}). It uses the same R_RC AIR and instance builder as `scale rc`, only with block size
500 instead of 100. Per point: fresh child process, 3 warm-up + 30 timed runs (`--quick`: 1 warm-up + 2 runs), raw rows only in `raw.csv` (the
usual columns plus `g_blocks`; `mode` holds the series). For `per_block`, `trace_s`, `prove_s`, `verify_s`, `proof_bytes` and `trace_rows` are sums
over the G proofs and the peak RSS is that of the process (proofs are made one after the other, so it is not the sum). Every proof must verify;
otherwise the child exits and the driver writes the point to `failures.txt`. `python3 scripts/summarize.py results/<run>/raw.csv` adds an ABLATION
table (median, min-max) and the ratio per_block / batched. Caveat: block data is synthetic, the per_block series draws its G blocks from
seeds 1..G while the batched series uses one seed-1 stream (so the two series prove different records of the same shape; circuit cost does
not depend on the values), and the batched proof also checks that block boundaries are consistent across the whole stream (one hash chain),
which G separate proofs do not link to each other.

## Chunked proofs (`chunked`)

`src/bin/chunked.rs`, `scripts/summarize_chunked.py`, results in `results/chunked-1/`, report `TASK-chunked.report.md`: M records proved as M/10^4 separate R_RC or R_Exec proofs (blocks of 500), run for M = 10^5, 10^6 and 993,500 (R_Exec). This is a cost measurement of a chunked decomposition, not the paper's single proof; chunks are not linked to each other.
