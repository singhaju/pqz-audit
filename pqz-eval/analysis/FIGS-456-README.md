# Figures for Experiments 4, 5, 6 (and Exp 1 baselines)

Every number in these figures comes from a raw result file: the plotted value
is the median of timed rows and the band or whisker is the observed min-max.
Warm-up rows are dropped.  No value is scaled, fitted or invented.

## How to run

From `bench/pqz-eval/analysis`:

```
PY="../../.venv-bench/bin/python"
"$PY" fig_exp4a.py
"$PY" fig_exp4b.py
"$PY" fig_exp5a.py
"$PY" fig_exp5b.py
"$PY" fig_exp6a.py
"$PY" fig_exp6b.py
"$PY" fig_exp1_baselines.py
"$PY" figs456_selfcheck.py
```

Each figure script writes `out/<figure>.pdf`, `out/<figure>.png` (200 dpi) and
`out/<figure>.csv`.  The scripts default to the real raw files; `--out` and a
positional CSV path are optional.  Width is 3.4 in (single IEEE column), base
font 7 pt, Okabe-Ito colours.  Log axes use explicit `LogLocator(numticks=12)`
because the shared `common.log_axes` ticks disappear at this figure width.

`common.load_csv` marks a figure provisional when the path contains "smoke" or
a column named `n` has a value below 10000.  These inputs use `n_records` or
`n` values of at least 10000, so no figure carries the PROVISIONAL banner.

## Figure-by-figure record

### fig_exp4a - `fig:exp4-proving`
- Source: `bench/pqz-proof/results/full-2/raw.csv`.
- Rows: `experiment=scale`, `warmup=0`.
- Panels: (a) `prove_s` in ms for `rel=rc` and `rel=exec` vs `n_records`
  (1e3, 1e4, 1e5); (b) `proof_bytes/1024` in KiB; (c)
  `prove_peak_rss_kb/1024` in MiB; (d) `rel=auth` vs policy-tree depth
  (`depth` 10, 20) with prove time (left, linear axis) and proof size (right).
- Choice: panel (d) is linear because prove time spans only 14.8-20.0 ms, less
  than one decade; a log axis there produced unreadable 1.25e1 style labels.
- MISSING: `rel=auth` has no `n_records` (`n_records` is empty).  It is not
  given a fabricated x value in panels (a)-(c); the three CSV rows with
  `series=auth` and `status=MISSING` record this, and panel (d) shows the
  depth sweep instead.

### fig_exp4b - `fig:exp4-verification`
- Source: same raw file, `experiment=q`, `rel=bundle`, `warmup=0`.
- Rows: modes `same` and `distinct`, q in {1, 10, 25, 50, 100, 200}.
- Metric: `total_verify_s` (already seconds) multiplied by 1000 to ms.
- Both modes are drawn: `same` = one proof verified q times; `distinct` = q
  distinct proofs.  The legend gives both meanings.
- Baselines: not drawn.  `bench/pqz-baselines/results/baseline_costs.csv` has
  per-audit verification rows for Dong, DART, L-HCPM and DOPIV, but no
  `formula_text` says that one audit equals one request.  Multiplying a
  per-audit time by q would therefore be invented.  Every such row is listed
  in `out/fig_exp4b.csv` with `status=MISSING` and its per-audit `time_ns`.
  This includes full rows (Dong `tt=gt`, DOPIV both `tm` readings) as well as
  partial/shape-only rows (Dong `tt=omit`, DART, L-HCPM).  The figure note
  carries the required phrase "computed from the authors' draft formula,
  unchecked" for those unplotted baselines.

### fig_exp5a - `fig:exp5-blockchain`
- Source:
  `bench/pqz-ledger/results/full-1/with-tx-auth/exp5a_latency_throughput.csv`.
- Rows: `kind=timed`; `system=pqz` (workload `authorize`) and
  `system=per_record_baseline` (workload `commit_record`).
- Metrics: measured `lat_p50_ns/1e6` in ms (top) and
  `throughput_tx_per_s` (bottom) vs q.
- The `derived_*` columns are not measured, so they are not used.  The note
  states that the ledger is an in-process simulation (no network, consensus
  or concurrency).

### fig_exp5b - `fig:exp5-governance`
- Source:
  `bench/pqz-ledger/results/full-1/with-tx-auth/exp5b_governance.csv`.
- Rows: `kind=timed`; ops `routine_read`, `authorize`, `consume`.
- Metric: `op_latency_ns/1e6` in ms.  Bars are medians; whiskers are min-max.
- Choice: the paper says "routine canonical-state access", so the routine bar
  is `routine_read` (the access path).  `routine_anchor` (the write path) was
  also measured; its median/min/max are in the CSV with
  `status=measured-not-plotted`, not in the bars.

### fig_exp6a - `fig:exp6-ablation`
- Sources: `bench/pqz-eval/results/full-1/exp2a/exp2a.csv` and
  `bench/pqz-eval/results/full-2/exp3b/exp3b.csv`, plus
  `bench/pqz-proof/results/ablation-1/raw.csv`.
- Stage-A filters: N=1e6, sigma=1%, layout `clustered`, predicate `P4`,
  `warmup=0`.  Query component: exp2a `pqz` vs `prot_full_scan`.
  Aggregation component: exp3b `agg=SUM`, `pqz` vs `full_he`.
- Main panel: Full = pqz query + pqz SUM; w/o Block Filtering =
  `prot_full_scan` query + pqz SUM; w/o Selective HE = pqz query + `full_he`
  SUM.  The total is explicitly the sum of two separately measured medians,
  not a joint measurement.  Whiskers add component mins and component maxes.
- RC panel (separate, different scale): ablation rows for `mode=batched` and
  `mode=per_block`, `g_blocks` in {1, 4, 16, 64} (500-32000 records at
  m_B=500), metric `prove_s*1000` in ms.  It is not stacked into the main bar.
- Caveat: `full_he` has only 10 timed rows (1 warm-up); its min (50.9 s)
  makes the w/o Selective HE whisker wide.  All groups still meet the
  minimum of 3 timed runs.

### fig_exp6b - `fig:exp6-relative`
- Sources and filters: identical to fig_exp6a; O_j is computed from the same
  medians.
- Formula: O_j = (T_j - T_Full) / T_Full x 100%.
- Component-level choice: Block Filtering compares query execution only
  (`prot_full_scan` vs `pqz`); Selective HE compares the SUM aggregation only
  (`full_he` vs `pqz`); Batched RC compares RC proof generation only
  (`per_block` vs `batched`) at each G.  This isolates each ablation stage.
  A total-level Block-Filtering O_j would instead be about 16%, because SUM
  aggregation dominates the Full total and dilutes the query difference; that
  alternative is not plotted.
- One line/point per stage: two stage-A points and four RC points (G=1, 4,
  16, 64).  Log x axis.  Whiskers are the min/max of the four combinations
  (T_j min or max) / (T_Full min or max), not a confidence interval.
- Values: Block Filtering 6224.7% (5167.6-7149.7); Selective HE 20356%
  (about 10196-23677); RC G=1 0.06%, G=4 51%, G=16 43%, G=64 47%.

### fig_exp1_baselines - `fig:exp1-scalability`
- Source: `bench/pqz-eval/results/full-1/exp1/exp1.csv`,
  `series=sigma1pct`, `warmup=0`; N in {1e4, 5e4, 1e5, 5e5, 1e6}.
- PQZ series: `time_ns/1e6` in ms, median with min-max band, log-log.
- Baselines: `bench/pqz-baselines/results/baseline_costs.csv`, phase
  `audit`, scheme `Dong et al.`, `status=full`, `interp=grp`, c in
  {1, 10, 25, 50, 100, 200} at s=10.  These are horizontal lines because the
  scheme parameters are fixed by the paper and do not depend on N.  The lines
  are formula sums of measured unit costs, not measurements of Dong's system,
  and the note carries the exact phrase "computed from the authors' draft
  formula, unchecked".
- Not drawn: the `interp=fld` Dong reading (alternative interpretation of the
  same formula, listed in the CSV as `not-plotted (alternative reading)`);
  DART, L-HCPM and DOPIV audit costs, which have no numeric row
  (`shape_only` or `not_computed`) and are listed as MISSING; Dong/DOPIV
  verification rows, which are not the Exp 1 online audit operation.

## MISSING summary

| Figure | Missing item | Why |
|---|---|---|
| exp4a | R_Auth at N_Q in panels a-c | no N_Q sweep exists; only depth 10/20 |
| exp4b | Dong, DART, L-HCPM, DOPIV at q | only per-audit costs; no formula says one audit per request |
| exp5a | none | both systems have all six q values |
| exp5b | none (routine_anchor measured, not plotted) | paper asks for the access path |
| exp6a | none | all six medians and all eight RC medians exist |
| exp6b | none | derived from the same medians |
| exp1 | DART, L-HCPM, DOPIV audit curves | no numeric audit row in baseline_costs.csv |

## Self-check

`figs456_selfcheck.py` uses only the standard `csv` module.  It recomputes
eight plotted values (one per figure, plus the Dong c=200 line) from the raw
files and compares them with the values in the figure CSVs.  It prints
`OK`/`MISMATCH` per check and exits non-zero on any mismatch.  Current result:
`all 8 checks OK`.
