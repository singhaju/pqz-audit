"""Dense exp2b figure: fig_exp2b_full with panel (a) from exp2bd.

Reuses fig_exp2b_full.py unchanged.  Panel (a) (selectivity sweep) comes from
exp2bd; panel (b) (block-size sweep) stays from results/full-1/exp2c/exp2c.csv.
Adds a `source` column to the written CSV.

  python fig_exp2b_dense.py --out DIR [--sigma exp2bd.csv] [--mb exp2c.csv]
                            [--min-runs 3]
"""

from __future__ import annotations

import argparse
import os

import dense_common as dc
import fig_exp2b_full


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sigma", default=dc.results_path("dense-1/exp2bd/exp2bd.csv"),
                   help="exp2bd raw CSV (panel a)")
    p.add_argument("--mb", default=dc.results_path("full-1/exp2c/exp2c.csv"),
                   help="exp2c raw CSV (panel b)")
    p.add_argument("--out", default=dc.DEFAULT_OUT, help="output directory")
    p.add_argument("--min-runs", type=int, default=3)
    a = p.parse_args()
    out = os.path.abspath(a.out)
    s_sigma, s_mb = dc.rel(a.sigma), dc.rel(a.mb)
    dc.call_main(fig_exp2b_full, ["--sigma", a.sigma, "--mb", a.mb, "--out", out,
                                  "--min-runs", str(a.min_runs)])
    dc.add_source_column(os.path.join(out, "fig_exp2b_full.csv"),
                         lambda r: s_sigma if r["panel"] == "selectivity" else s_mb)


if __name__ == "__main__":
    main()
