"""Dense exp1 figures: fig_exp1_baselines and fig_exp1_full from exp1d.

Reuses fig_exp1_baselines.py and fig_exp1_full.py unchanged (same style, size
and file names); only the input CSV differs.  The baseline lines are flat and
drawn across the whole axis, so they span the new N range.  Adds a `source`
column to both written CSVs.

  python fig_exp1_dense.py --out DIR [--csv exp1d.csv] [--baselines F]
                           [--profbigo F] [--min-runs 3]
"""

from __future__ import annotations

import argparse
import os

import dense_common as dc
import fig_exp1_baselines
import fig_exp1_full

BASE_REL = ("pqz-baselines", "results-papers-run2")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--csv", default=dc.results_path("dense-1/exp1d/exp1d.csv"),
                   help="exp1d raw CSV")
    p.add_argument("--baselines", default=None, help="baseline_costs.csv")
    p.add_argument("--profbigo", default=None, help="baseline_costs_profbigo.csv")
    p.add_argument("--out", default=dc.DEFAULT_OUT, help="output directory")
    p.add_argument("--min-runs", type=int, default=3)
    a = p.parse_args()
    out = os.path.abspath(a.out)
    src = dc.rel(a.csv)

    argv = [a.csv, "--out", out, "--min-runs", str(a.min_runs)]
    if a.baselines:
        argv += ["--baselines", a.baselines]
    if a.profbigo:
        argv += ["--profbigo", a.profbigo]
    dc.call_main(fig_exp1_baselines, argv)
    dc.add_source_column(
        os.path.join(out, "fig_exp1_baselines.csv"),
        lambda r: src if r["metric"] == "query_time" else
        "pqz-baselines/results-papers-run2 (baseline_costs.csv / "
        "baseline_costs_profbigo.csv, as fig_exp1_baselines.py)")

    dc.call_main(fig_exp1_full, [a.csv, "--out", out, "--min-runs", str(a.min_runs)])
    dc.add_source_column(os.path.join(out, "fig_exp1_full.csv"), lambda r: src)


if __name__ == "__main__":
    main()
