"""Helpers shared by fig_exp1_w15.py, fig_exp4a_w15.py, fig_exp4b_w15.py (and the summary).

All inputs are the raw CSVs of the single cloud instance run in results/cloud-w15/.
Baseline raw_runs.csv files hold only timed runs (columns baseline,stage,params,run,ms).
"""

from __future__ import annotations

import csv
import os

import numpy as np

import common

CLOUD = os.path.join(common.BASE_DIR, "results", "cloud-w15")
EXP1_CSV = os.path.join(CLOUD, "exp1d", "exp1d.csv")
EXP1_REPEAT_CSV = os.path.join(CLOUD, "out2", "exp1d2", "exp1d.csv")
PROOF_CSV = os.path.join(CLOUD, "proof-full", "raw.csv")
OUT_DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(common.BASE_DIR)),
    "journal2", "figures", "results-w15",
)
BASELINE_DIRS = ("dong", "dopiv", "dopiv-lazy", "dart", "lhcpm")


def parse_params(params):
    fields = {}
    for part in params.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    return fields


def load_baseline(name):
    """Return {(stage, params): [ms, ...]} from out2/<name>/raw_runs.csv."""
    path = os.path.join(CLOUD, "out2", name, "raw_runs.csv")
    if not os.path.isfile(path):
        raise SystemExit(f"refusing: missing file {path}")
    groups = {}
    with open(path, "r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            groups.setdefault((row["stage"], row["params"]), []).append(float(row["ms"]))
    return groups


def stats_of(values):
    array = np.asarray(values, dtype=float)
    return {
        "n": int(len(array)), "median": float(np.median(array)),
        "min": float(array.min()), "max": float(array.max()),
    }


def pick(groups, stage, **want):
    """Exactly one (stage, params) group whose parsed fields contain `want`.

    Returns (params_string, stats).  Stops if zero or several match.
    """
    hits = []
    for (st, params), values in groups.items():
        if st != stage:
            continue
        fields = parse_params(params)
        if all(fields.get(key) == str(value) for key, value in want.items()):
            hits.append((params, values))
    if len(hits) != 1:
        raise SystemExit(
            f"refusing: stage={stage} {want} matched {len(hits)} param strings "
            f"({[h[0] for h in hits]})")
    params, values = hits[0]
    return params, stats_of(values)


def pick_exact(groups, stage, params):
    values = groups.get((stage, params))
    if values is None:
        raise SystemExit(f"refusing: no rows for stage={stage} params={params}")
    return stats_of(values)


# Line styles (same as w14): palette index, dash pattern
STYLE = {
    "Dong et al.": (None, (0, (1, 3)), "0.30"),
    "DOPIV": (4, (0, (4, 4)), None),
    "DART (no zk proof)": (2, (0, (2.5, 1.2)), None),
    "L-HCPM": (3, (0, (6, 1.5, 1, 1.5, 1, 1.5)), None),
    "L-HCPM (cache hit)": (3, (0, (6, 1.5, 1, 1.5, 1, 1.5)), None),
}


def line_color(label):
    index, _, grey = STYLE[label]
    return common.PALETTE[index] if index is not None else grey


def line_dash(label):
    return STYLE[label][1]


def fmt(value):
    return f"{value:.10g}"
