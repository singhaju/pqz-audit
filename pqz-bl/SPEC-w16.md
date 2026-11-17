# pqz-bl SPEC-w16: sweeps at the same coverage as PQZ-Audit (work16, entry 388)

User, 2026-11-06: "let's meature it for real and plot it into line"; matched size = 1% of N. Read `SPEC.md` first: all its rules still hold
(one thread, real operations, black_box, verify results, no number from any paper, tests, FIDELITY.md, `raw_runs.csv` header
`baseline,stage,params,run,ms`). Work ONLY inside your own crate directory. Do not change the meaning of any existing stage; ADD options.
Do not delete or rewrite old results. Keep the default behaviour (no new flags) identical to today, so the old grid still runs.

## Why
The baselines were drawn as flat lines at one setting. Dong et al., DOPIV and DART cost depends on the challenge size (and DART proof
generation on the file size), PQZ-Audit on the records it covers. We now measure each baseline at the same coverage points.

## Coverage points (records covered, "cov")
- Exp 1 (N sweep): N in {1e4, 2e4, 5e4, 1e5, 2e5, 5e5, 1e6}; cov = 0.01 N = {100, 200, 500, 1000, 2000, 5000, 10000}.
- Exp 4a (proof generation): cov = N_Q in {1000, 10000, 100000}.
- Exp 4b (verification): cov = 1000 (one audit covers 1000 records) with q audits, q in {1, 10, 25, 50, 100, 200}.
- Papers' own range (already supported; keep): Dong c = 10..100; DOPIV c = 50..600 (and c=350); DART its own N, z grid.

## New CLI (all four crates; same names)
- `--cov LIST` comma list of coverage points (records). Replaces the default grid for the stages below. Dong, DOPIV: c = cov.
- `--q LIST` comma list of q. Adds stage `verify_q`: q INDEPENDENT audits are verified in ONE timed run (q different challenges, q
  different proofs, all made before the timer). `ms` = total time for the q verifications. Check every result is true.
- `--runs-big R` and `--big-above X`: when the work per run is large (cov > X, or q*cov > X), use R timed runs instead of `--runs`
  (default `--runs-big 5`, `--big-above 2000`), warm-up 1. Record the number used in `params` as `runs=R`.
- `--params-tag TAG`: appended to the `params` string so rows from different sweeps never collide.

## Per baseline
- Dong: stages `proofgen` and `verify` at c = cov (s = 3), plus `verify_q`. File size: tags only for the challenged blocks plus enough
  blocks to keep the challenge a random subset (n = max(10*c, 2*c) is fine; say what you use). The paper's cost has no n term; say so.
- DOPIV: `proofgen`, `verify` at c = cov (n=256, q=4294967291, m=16384, `--lazy` as in the main run; ALSO run the default reduction
  when `--no-lazy` is given so both are available), plus `verify_q`. Planting is untimed; plant only the blocks the challenge can pick.
- DART: file of D = ceil(N_file / 200) chunks (one chunk = N*M = 200 blocks with N=20, M=10; use `--file-records N_FILE`, default 1e6,
  so D = 5000), challenge z = max(1, ceil(cov / 200)). Stages `proofgen_nozk`, `verify_nozk`, plus `verify_q` (q different challenges and
  proofs). A second mode `--scale-d` sets D = ceil(cov * 100 / 200) (file = 100 x cov records) so Exp 1 can follow N: for the Exp 1 grid pass
  `--file-records` = N for each N (give a list `--file-records-list` matching `--cov`, one file size per cov). Params must show D and z.
  Still no zk-SNARK (say so in FIDELITY.md again).
- L-HCPM: no cov. Add only `--q LIST`: stage `audit_hit_q` and `groth16_verify_q` = q independent audits / q proofs verified in one run
  (3 public inputs), q different ciphertexts/proofs. Mint and Transfer prove stages unchanged.

## Tests and checks
- `cargo test --release` must pass (existing tests plus one new test per new stage: honest passes, tampered fails).
- Smoke run with the smallest points and `--runs 3`; report the summary lines. Do NOT run the big points (cov 1e4 and above, q*cov large)
  locally in full: estimate the time per run from a small point and report it; these run on the cloud instance.
- Update FIDELITY.md: new stages, what the matched coverage means, the n / D choices, what is still not run.

## Report (final message, at most 30 lines)
Files changed, new flags, tests (copy the lines), smoke summary lines, estimated cloud time per big point, deviations, open questions.
