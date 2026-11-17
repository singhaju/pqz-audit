# Dense figures (exp1d, exp2bd, exp3ad)

Wrapper scripts that draw the paper figures from the denser CSVs. The old scripts
(`fig_exp1_baselines.py`, `fig_exp1_full.py`, `fig_exp2b_full.py`, `fig_exp3a_full.py`) are not
changed; the wrappers import them and call their `main()` with other input paths. Style, size and
file names are the same. Output goes to `--out` (default `analysis/out-dense/`, never `out/`).
Each written CSV (median, min, max, n runs per point) gets one extra last column `source`.

Interpreter: `python3`

| script | figures | reads |
|---|---|---|
| `fig_exp1_dense.py` | `fig_exp1_baselines`, `fig_exp1_full` | `results/dense-1/exp1d/exp1d.csv`; baselines: `../pqz-baselines/results-papers-run2/baseline_costs.csv` and `baseline_costs_profbigo.csv` (as before) |
| `fig_exp2b_dense.py` | `fig_exp2b_full` | panel (a): `results/dense-1/exp2bd/exp2bd.csv`; panel (b): `results/full-1/exp2c/exp2c.csv` |
| `fig_exp3a_dense.py` | `fig_exp3a_full` | PQZ-Audit and Plaintext SUM: `results/dense-1/exp3ad/exp3ad.csv`; Full-Domain HE points: `results/full-1/exp3a/exp3a.csv` (SUM, its own sigma values); hollow second-sweep marker: `results/full-2/exp3b/exp3b.csv` |

Run (from this directory; `OUT` is any directory):

```
cd pqz-eval/analysis
PY="python3"
"$PY" fig_exp1_dense.py  --out OUT
"$PY" fig_exp2b_dense.py --out OUT
"$PY" fig_exp3a_dense.py --out OUT
```

Options: `--min-runs N` (default 3, as the old scripts); input overrides `--csv`/`--baselines`/
`--profbigo` (exp1), `--sigma`/`--mb` (exp2b), `--dense`/`--he`/`--second` (exp3a).

## Notes

- Flat baseline lines (exp1 baselines) are `axhline`, so they cover whatever N range the axis has.
  Markers are on every N point of the PQZ-Audit line (the old code already draws a marker per point).
- `fig_exp3a_dense.py` reads one merged input, which it writes to `OUT/exp3a_dense_merged_input.csv`
  (exp3ad SUM rows of plain_agg and pqz, plus full_he SUM rows of full-1 exp3a, copied as text).
  If the N of the two sources differs it prints a WARNING (x axis n_Q = sigma*N would mix two N).
- `source` column of the CSVs: per row, the file the value comes from (exp3a: exp3ad, full-1 exp3a,
  or full-2 exp3b for the hollow marker; exp2b: exp2bd for panel selectivity, exp2c for block_size;
  exp1 baselines: the dense CSV for `query_time` rows, the baseline files for flat lines).
- Old scripts are unaffected: running them on `results/full-1/...` gives the same CSVs as `out/`
  (checked with `diff`, 2026-11-05).
- The old scripts print "PROVISIONAL (smoke data)" on the figure if a group has fewer than 10 timed
  runs (exp1 baselines: N < 10000). Same rule here.
- Tested only on smoke CSVs (N=2000, 3 runs, `--min-runs 1`); not run on dense-1 data.
