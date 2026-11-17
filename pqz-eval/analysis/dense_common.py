"""Helpers for the dense-data wrappers (fig_exp1_dense.py, fig_exp2b_dense.py,
fig_exp3a_dense.py).  The existing fig_*.py scripts are NOT changed; the
wrappers call their main() with other input paths and then add a `source`
column to the CSV of plotted values.
"""

from __future__ import annotations

import csv
import os
import sys

import common

RESULTS = os.path.join(common.BASE_DIR, "results")
DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out-dense")


def results_path(rel):
    return os.path.join(RESULTS, rel)


def rel(path):
    """Path relative to bench/pqz-eval when inside it, else as given."""
    path = os.path.abspath(path)
    try:
        r = os.path.relpath(path, common.BASE_DIR)
    except ValueError:
        return path
    return path if r.startswith("..") else r


def call_main(module, argv):
    """Run module.main() as if started with the command-line arguments argv."""
    saved = sys.argv
    sys.argv = [module.__name__ + ".py"] + list(argv)
    try:
        module.main()
    finally:
        sys.argv = saved


def add_source_column(csv_path, source_of):
    """Add a `source` column (last) to a CSV written by an old script.

    source_of(row) -> str.  Everything else in the file stays as written.
    """
    with open(csv_path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    if "source" in fields:
        raise SystemExit(f"{csv_path} already has a source column")
    for row in rows:
        row["source"] = source_of(row)
    common.save_csv(csv_path, fields + ["source"], rows)
