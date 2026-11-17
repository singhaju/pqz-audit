# pqz-eval analysis

Read-only analysis of the raw CSV files written by `bench/pqz-eval/src/bin/exp.rs`.
It does not build, run or edit the crate.

## Environment (checked 2026-10-30)

Use the project interpreter:

```
python3
```

Installed there: `numpy 2.5.2`, `matplotlib 3.11.1`.
**`pandas` is NOT installed.** These scripts use only the standard `csv` module plus
numpy/matplotlib, so nothing needs to be installed for them to run. If a later script
needs pandas, install it deliberately rather than silently.

## Run

From this directory:

```
PY="python3"
"$PY" fig_exp1.py
"$PY" fig_exp2.py
"$PY" fig_exp3.py
"$PY" hypotheses.py
```

Defaults read the smoke files (`../smoke/s1/exp1.csv`, `../smoke/s2/exp2a.csv`,
`../smoke/s3/exp3a.csv`). Pass real result files explicitly:

```
"$PY" fig_exp1.py /path/to/results/exp1.csv --out /path/to/results/analysis
"$PY" fig_exp2.py /path/to/results/exp2a.csv /path/to/results/exp2b.csv --out out
"$PY" fig_exp3.py /path/to/results/exp3a.csv /path/to/results/exp3b.csv --out out
"$PY" hypotheses.py --exp1 results/exp1.csv --exp2 results/exp2a.csv --exp3 results/exp3a.csv
```

`--min-runs N` sets the minimum number of timed runs required per group (default 3).

## Behaviour

- `common.py` loads a CSV, drops every row with `warmup=1`, coerces numeric columns,
  and groups rows by the experiment's keys. It **refuses** (nonzero exit, explicit
  message) if a file is missing, lacks a required column, has no timed rows, or has any
  group with fewer than `--min-runs` timed rows. It also refuses a missing exp1 series.
- Per group it reports median, min, max and n. Figures draw the median line and the
  min-max band.
- Every figure and its CSV are written to `analysis/out/` (or `--out`). Numbers printed
  in the CSV are recomputed from the raw rows; nothing is estimated.
- Colourblind-safe Okabe-Ito palette, log axes where the range needs it, axes labelled
  with units, no title claims.
- If the input path or its sibling `env.txt` contains `smoke`, or any `n < 10000`, the
  figure is labelled **PROVISIONAL (smoke data)** automatically. This is a data label,
  not a claim.

## Files

| File | Output | Content |
|---|---|---|
| `common.py` | — | loader, warm-up drop, group statistics, fits, palette, saving |
| `fig_exp1.py` | `out/fig_exp1.pdf`, `.csv` | query time vs N for `sigma1pct` and `fixed_nq1000`; log-log slope and R² per series; `n_cand/N` when the column exists |
| `fig_exp2.py` | `out/fig_exp2.pdf`, `.csv` | query time by predicate (and selectivity when ≥2 σ values) for `trad_scan` / `prot_full_scan` / `pqz`, both layouts; least-squares fit `t = G*T_BPS + N_Q*T_RPS` with R² |
| `fig_exp3.py` | `out/fig_exp3.pdf`, `.csv` | aggregation time vs `n_sel` for `plain_agg` / `full_he` / `pqz`, COUNT/SUM/AVG; log-log slopes; `R_HE = 1 - T_pqz/T_full_he` |
| `hypotheses.py` | `out/hypotheses.csv` | every section-1 hypothesis with measured value, threshold, `SUPPORTED` / `REFUTED` / `NOT-ENOUGH-DATA` |

## Model conventions in `fig_exp2.py`

- `N_Q` is `n_cand` (records that receive record-level RPS evaluation).
- `G` is `n_blocks` for `pqz` (BPS over every block) and 0 for `prot_full_scan`
  (no block-summary pass).
- `trad_scan` is excluded from the fit because its per-record cost is a plaintext
  comparison, not protected RPS. It is still plotted.
- No intercept is used. A negative `T_BPS` is flagged as unphysical rather than hidden;
  with collinear smoke points the coefficient is not identified.

## Hypotheses

`hypotheses.py` hard-codes the hypotheses and thresholds of
`journal2/EXPERIMENT-PLAN-main11.md`, section 1, in `HYPOTHESES`, with that path in every
entry. **All thresholds are PROPOSALS** (the plan says so). The plan gives no numeric
tolerance for hypothesis 3; the script uses a local, clearly-labelled tolerance and says
so in the output CSV. Hypotheses 4-7 have no result files yet and report
`NOT-ENOUGH-DATA`. A smoke run can never return `SUPPORTED` or `REFUTED`; it reports
`NOT-ENOUGH-DATA` and still shows the measured value.

## Notes

- No temporary files are written outside this tree (the task forbids `/tmp`).
- The scripts never modify `src/` or the crate's frozen tree.

## hypotheses.py inputs added (2026-10-31)

`--exp3c` (H3 N sweep), `--exp4` (H4, pqz-proof raw.csv), `--exp5` (H5, exp5c csv files), `--reject` / `--reject-mutation` (H7),
`--ablation` (H6; format confirmed on `pqz-proof/results/ablation-1/raw.csv`: config in `mode` = batched/per_block, G in
`g_blocks`, total prove time in `prove_s`; see `TASK-hyp.report.md`). Output: `out/hypotheses.csv` (extra column `details`) and `out/hypotheses.txt`.
H2 also prints an EXPLORATORY per-predicate fit (post hoc, not a test). `fixtures/` holds hand-made FIXTURE files for testing the
`--exp3c` and `--ablation` paths; they are not results.
