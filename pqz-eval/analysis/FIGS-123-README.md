# Figures for Experiments 1, 2, 3 (full data)

These are NEW scripts.  The old `fig_exp1.py`, `fig_exp2.py` and `fig_exp3.py`
are untouched and still default to smoke data.  The scripts below default to
the full-data CSVs and write `out/fig_*_full.pdf`, `out/fig_*_full.png`
(200 dpi) and `out/fig_*_full.csv`.

Every plotted value is the median of timed rows (`warmup=0`); the band or
whisker is the observed min-max.  No raw file, `common.py`, `hypotheses.py`,
`paper_numbers.py`, any `fig_exp4*`/`fig_exp5*`/`fig_exp6*` script, the paper,
or `bench/zkalba-eval` was modified.

## How to run

From `bench/pqz-eval/analysis`:

```
PY="../../../.venv-bench/bin/python"
for s in fig_exp1_full fig_exp2a_full fig_exp2b_full fig_exp3a_full fig_exp3b_full; do
  echo "== $s"
  "$PY" "$s.py" || exit 1
done
"$PY" figs123_selfcheck.py
```

Width is 3.4 in (single IEEE column), base font 7 pt, Okabe-Ito colours.
Log axes use explicit `LogLocator(numticks=12)` so tick labels stay visible at
this width.  `common.load_csv` drops warm-up rows and refuses groups below
`--min-runs` (default 3).

## Provisional rule

A figure gets no PROVISIONAL banner because no plotted group has fewer than 10
timed runs.  The smallest group is `full_he` with exactly 10 timed runs per
point in exp3a and exp3b.  The `common.load_csv` smoke/small-N rule is also
false: these paths contain no "smoke" and every `n` is at least 1e4.

## Figure-by-figure record

### fig_exp1_full - query time versus N
- Source: `results/full-1/exp1/exp1.csv`.
- Rows: `warmup=0`; N in {1e4, 5e4, 1e5, 5e5, 1e6}, approach `pqz`,
  clustered layout, predicate P4; 30 timed runs per (series, N).
- Series: `sigma1pct` (sigma = 1% at every N) and `fixed_nq1000`
  (N_Q = 1000, so sigma = 1000/N; the smallest N is 1e4 and sigma is 10%).
  The figure note `fixed_nq1000 = 10% at N=1e4` is computed from the `n` and
  `sigma` columns.
- Axes: log-log, N (records) versus query time (ms).
- Log-log slope is written to the CSV only, not drawn:
  `sigma1pct` slope 1.004798 (R² 0.993247); `fixed_nq1000` slope 0.100039
  (R² 0.743847).

### fig_exp2a_full - query time by predicate and layout
- Source: `results/full-1/exp2a/exp2a.csv`.
- Rows: `warmup=0`; N=1e6, sigma=1%; predicates P1-P4; layouts clustered and
  scattered; approaches `trad_scan`, `prot_full_scan`, `pqz`; 30 timed runs
  per group.
- Panels: (a) clustered, (b) scattered; log y, query time (ms).
- Note under the scattered panel is computed from the `n_blocks` and
  `n_retained_blocks` columns for scattered `pqz`:
  `scattered layout retains 1987 of 2000 blocks (no pruning)`.
  The CSV also stores an `annotation` row with those two medians.

### fig_exp2b_full - selectivity and block-size sweeps
- Sources: `results/full-1/exp2b/exp2b.csv` (panel a) and
  `results/full-1/exp2c/exp2c.csv` (panel b).
- Rows: `warmup=0`.
  - exp2b: N=1e6, predicate P4, sigma in {0.1, 1, 5, 10, 25}% of N.
  - exp2c: N=1e6, predicate P4, sigma=1%, m_B in {100, 250, 500, 1000}.
  - Both layouts and all three approaches; 30 timed runs per group.
- Panels: (a) query time (ms) versus selectivity σ (% of N), log-log;
  (b) query time (ms) versus block size m_B (records), log-log.
- Line style encodes layout: solid = clustered, dashed = scattered.  Colour
  and marker encode approach.  The figure footer names both source files.

### fig_exp3a_full - SUM time versus selected count
- Source: `results/full-1/exp3a/exp3a.csv`.
- Rows: `warmup=0`, `agg=SUM`, N=1e6; n_sel = sigma·N in
  {1e3, 1e4, 5e4, 1e5, 2.5e5}; approaches `plain_agg`, `full_he`, `pqz`.
  `plain_agg` and `pqz` have 30 timed runs per point; `full_he` has 10.
- Axes: log-log, n_sel (selected records) versus SUM time (ms).
- `full_he` is labelled `full_he (10 runs)` and its 10-run count is in the CSV.
- pqz log-log slope is written to the CSV only: slope 1.003332
  (R² 0.999997).
- Extra hollow marker: the second `full_he` sweep from
  `results/full-2/exp3b/exp3b.csv`, filtered to `agg=SUM`, `sigma=1%`,
  `approach=full_he`, 10 timed runs.  Its n_sel is computed as
  sigma·N = 1e4 and its median is 100670.3 ms.  It is labelled
  `second sweep, same config`.

### fig_exp3b_full - operators at sigma=1%, N=1e6
- Sources: `results/full-2/exp3b/exp3b.csv` and
  `results/full-2/exp3d/exp3d.csv`.
- Top panel rows: exp3b `warmup=0`, N=1e6, sigma=1%; `agg` SUM and AVG;
  approaches `plain_agg`, `full_he`, `pqz`.  `plain_agg` and `pqz` have 30
  timed runs; `full_he` has 10.  Grouped bars on log y (ms) with min-max
  whiskers.
- COUNT panel rows:
  - exp3d `warmup=0`, N=1e6, sigma=1%, `agg=COUNT`, `pqz` and `plain_agg`;
    30 timed runs; values in ns (pqz median 22 ns, plain_agg 23 ns).
  - `full_he` COUNT from exp3b, N=1e6, sigma=1%, 10 timed runs, value in ms
    (median 59077.6 ms).
  - The panel has two y axes (left ns, right ms) because the units differ.
    Its title is exactly `COUNT (ns / ms: timer resolution, no ratio)`.
    pqz COUNT is the cardinality only; no ratio is drawn for COUNT.
- R_HE = 1 - T_pqz / T_full_he is written to the CSV only, for SUM and AVG:
  SUM 0.995111, AVG 0.990129.  No R_HE row exists for COUNT.

## Self-check

`figs123_selfcheck.py` uses only the standard `csv` module and
`statistics.median`.  It recomputes one plotted median per figure from the raw
file and compares it with the figure CSV.  Current result: `all 5 checks OK`.

## Outputs

- `out/fig_exp1_full.{pdf,png,csv}`
- `out/fig_exp2a_full.{pdf,png,csv}`
- `out/fig_exp2b_full.{pdf,png,csv}`
- `out/fig_exp3a_full.{pdf,png,csv}`
- `out/fig_exp3b_full.{pdf,png,csv}`
