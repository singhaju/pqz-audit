"""Dense exp3a figure: fig_exp3a_full with PQZ-Audit and Plaintext from exp3ad.

Reuses fig_exp3a_full.py unchanged.  That script reads one CSV, so this
wrapper writes a merged input file (`exp3a_dense_merged_input.csv`, kept in
the output directory as a record) made of
  - agg=SUM rows of plain_agg and pqz from exp3ad (dense selectivity points),
  - agg=SUM rows of full_he from results/full-1/exp3a/exp3a.csv (unchanged,
    the sigma values that file has),
and passes the second full_he sweep (hollow marker) as before from
results/full-2/exp3b/exp3b.csv.  Adds a `source` column to the written CSV.
Rows are copied as text; nothing is edited.

  python fig_exp3a_dense.py --out DIR [--dense exp3ad.csv] [--he exp3a.csv]
                            [--second exp3b.csv] [--min-runs 3]
"""

from __future__ import annotations

import argparse
import csv
import os
import sys

import common
import dense_common as dc
import fig_exp3a_full

MERGED = "exp3a_dense_merged_input.csv"


def read_rows(path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        sys.exit(f"refusing: input CSV not found: {path}")
    with open(path, "r", encoding="utf-8", newline="") as h:
        r = csv.DictReader(h)
        return list(r.fieldnames or []), list(r)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dense", default=dc.results_path("dense-1/exp3ad/exp3ad.csv"),
                   help="exp3ad raw CSV (plain_agg, pqz)")
    p.add_argument("--he", default=dc.results_path("full-1/exp3a/exp3a.csv"),
                   help="exp3a raw CSV (full_he points)")
    p.add_argument("--second", default=dc.results_path("full-2/exp3b/exp3b.csv"),
                   help="exp3b raw CSV (hollow second-sweep marker)")
    p.add_argument("--out", default=dc.DEFAULT_OUT, help="output directory")
    p.add_argument("--min-runs", type=int, default=3)
    a = p.parse_args()
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)

    hd, dense = read_rows(a.dense)
    hh, he = read_rows(a.he)
    if hd != hh:
        sys.exit(f"refusing: header of {a.dense} differs from {a.he}")
    dense_keep = [r for r in dense if r["agg"] == "SUM"
                  and r["approach"] in ("plain_agg", "pqz")]
    he_keep = [r for r in he if r["agg"] == "SUM" and r["approach"] == "full_he"]
    if not dense_keep or not he_keep:
        sys.exit("refusing: no SUM plain_agg/pqz rows in dense file or no SUM "
                 "full_he rows in the Full-Domain HE file")
    n_dense = {r["n"] for r in dense_keep}
    n_he = {r["n"] for r in he_keep}
    if n_dense != n_he:
        print(f"WARNING: N differs: dense file {sorted(n_dense)}, full_he file "
              f"{sorted(n_he)}. The x axis (n_Q = sigma*N) mixes two N values; "
              "do not use this figure as a result.", file=sys.stderr)

    merged = os.path.join(out, MERGED)
    with open(merged, "w", encoding="utf-8", newline="") as h:
        w = csv.DictWriter(h, fieldnames=hd)
        w.writeheader()
        w.writerows(dense_keep + he_keep)

    s_dense, s_he, s_second = dc.rel(a.dense), dc.rel(a.he), dc.rel(a.second)
    dc.call_main(fig_exp3a_full, [merged, "--second", a.second, "--out", out,
                                  "--min-runs", str(a.min_runs)])
    dc.add_source_column(
        os.path.join(out, "fig_exp3a_full.csv"),
        lambda r: s_second if r["record_type"] == "second_sweep" else
        (s_he if r["approach"] == "full_he" else s_dense))


if __name__ == "__main__":
    main()
