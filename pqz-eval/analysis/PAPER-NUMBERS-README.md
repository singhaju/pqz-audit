# paper_numbers.py

Writes `out/paper-numbers.md` and `out/paper-numbers.csv`: every number the
journal evaluation section needs, computed from the raw CSVs only. Warm-up rows
are excluded from all statistics. Each row carries its source file and the exact
row filter; `MISSING` means the raw file does not contain the value.

## Run

From this directory:

```
PY="python3"
env PYTHONPATH=. "$PY" paper_numbers.py
env PYTHONPATH=. "$PY" paper_numbers.py --self-check
```

`--self-check` recomputes three numbers per section with the plain `csv` module
(no helper from `common.py`) and prints `OK` or `MISMATCH`; it exits nonzero on
any mismatch.

## What each section reads

| Section | Raw files | Content |
|---|---|---|
| 1 | all eval, proof and ledger CSVs | timed runs and warm-ups per approach/group, per-configuration counts |
| 2 | `pqz-eval/results/{full-1,full-2}` | distinct `N`, `m_B`, selectivity sigma, predicates, layouts, aggregates actually used |
| 3 | `full-1/exp1/exp1.csv`, `pqz-baselines/results-papers-run2/{baseline_costs,baseline_costs_profbigo,unit_costs}.csv` (since entry 372; before: `pqz-baselines/results/`) | query time vs `N` for both series; `N_Q/N` with `N_Q := n_cand`; baseline formula costs and primitive unit costs (model-derived, not measured) |
| 4 | `full-1/exp2{a,b,c}.csv` | latency by predicate (2a), sigma sweep (2b), `m_B` sweep (2c), and `eta_Q = N_Q/N` |
| 5 | `full-1/exp3a.csv`, `full-2/exp3{b,d}.csv` | SUM/AVG/COUNT per approach; `R_HE = 1 - T_pqz/T_full_he` for SUM and AVG; COUNT printed in raw ns, no ratio |
| 6 | `pqz-proof/results/full-2/raw.csv` | prove/verify time, proof bytes, prover/verifier peak RSS; largest workload; verification at `q=1` vs `q=200` |
| 7 | `pqz-ledger/results/full-1/{with-tx-auth,no-tx-auth}/*.csv` | bytes per epoch, transaction latency/throughput, governance ops, threshold operations, with and without tx signatures |
| 8 | `full-1/exp2a.csv`, `full-2/exp3b.csv`, `pqz-proof/results/ablation-1/raw.csv`, `reject-1000.txt` | w/o block filtering, w/o selective HE, w/o batched RC, rejection table |
| 9 | `full-1/exp1_construction/exp1_construction.csv` | per-record construction time and storage per record/block (single run) |

## Conventions

- `N_Q := n_cand`, as in `README.md`; `eta_Q = N_Q/N`.
- Eval times are `time_ns / 1e6` (ms). Ledger latencies are `*_ns / 1e6` (ms).
- Proof times are `prove_s`/`verify_s`/`total_verify_s` times 1000 (ms); RSS is
  `*_rss_kb / 1024` (MiB); proof size is `proof_bytes`.
- Ratios are computed from the two medians named in the row filter.
- `exp1.csv` has only `approach=pqz`; a `MISSING` row states this and points to
  the baseline-cost table instead of inventing per-`N` baseline numbers.
- Baseline costs come from the authors' formulas (`baseline_costs.csv`), not
  from measurements. Rows whose `time_ns` is empty are reported as `MISSING`
  with their `status` in the note.
- `exp1_construction` has one run per approach and no warm-ups; these rows have
  `n=1` and their note says so.
