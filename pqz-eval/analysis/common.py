"""Shared loading, statistics and plotting helpers for pqz-eval analysis."""

from __future__ import annotations

import csv
import os
import sys

import numpy as np

CSV_COLUMNS = [
    "exp", "series", "n", "mb", "sigma", "layout", "predicate", "agg",
    "approach", "run", "warmup", "time_ns", "n_blocks", "n_retained_blocks",
    "n_cand", "n_sel", "bytes",
]

NUMERIC_COLUMNS = {
    "n", "mb", "sigma", "run", "warmup", "time_ns", "n_blocks",
    "n_retained_blocks", "n_cand", "n_sel", "bytes",
}

PALETTE = [
    "#0072B2", "#D55E00", "#009E73", "#CC79A7", "#E69F00",
    "#56B4E9", "#F0E442", "#000000",
]

MARKERS = ["o", "s", "^", "D", "v", "P", "X", "*"]

TIME_DIVISOR_NS = 1e6
TIME_UNIT = "ms"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def default_csv(relpath):
    return os.path.join(BASE_DIR, relpath)


def _to_number(value):
    if value is None:
        return None
    value = value.strip()
    if value == "":
        return None
    try:
        number = float(value)
    except ValueError:
        return value
    if number.is_integer() and "." not in value and "e" not in value.lower():
        return int(number)
    return number


def _read_env(csv_path):
    env_path = os.path.join(os.path.dirname(os.path.abspath(csv_path)), "env.txt")
    if os.path.isfile(env_path):
        with open(env_path, "r", encoding="utf-8", errors="replace") as handle:
            return env_path, handle.read()
    return None, ""


def load_csv(path, required=(), min_runs=3, group_keys=None, expect_groups=None):
    """Load a raw CSV, drop warm-up rows and refuse files that are too short.

    Returns (rows, meta). Rows are dictionaries with numeric columns coerced.
    """
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        sys.exit(f"refusing to continue: input CSV not found: {path}")

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        header = reader.fieldnames or []
        raw = list(reader)

    missing = [column for column in required if column not in header]
    if missing:
        sys.exit(
            f"refusing {path}: missing required columns {missing}; header is {header}"
        )
    if not raw:
        sys.exit(f"refusing {path}: file has a header but no data rows")

    rows = []
    for row in raw:
        parsed = {key: _to_number(value) for key, value in row.items()}
        rows.append(parsed)

    timed = [row for row in rows if row.get("warmup") in (0, None)]

    if not timed:
        sys.exit(f"refusing {path}: no timed rows after dropping warm-up rows")

    if group_keys:
        groups = {}
        for row in timed:
            key = tuple(row.get(column) for column in group_keys)
            groups.setdefault(key, []).append(row)
        short = {key: len(value) for key, value in groups.items() if len(value) < min_runs}
        if short:
            details = ", ".join(f"{key}: {count}" for key, count in sorted(short.items()))
            sys.exit(
                f"refusing {path}: {len(short)} group(s) have fewer than {min_runs} "
                f"timed runs (group -> rows): {details}"
            )
        if expect_groups is not None:
            expected = set(expect_groups)
            found = set(groups)
            if found != expected:
                missing_groups = sorted(expected - found)
                extra_groups = sorted(found - expected)
                sys.exit(
                    f"refusing {path}: expected groups {sorted(expected)}; "
                    f"missing {missing_groups}, extra {extra_groups}"
                )

    env_path, env_text = _read_env(path)
    smoke_marker = "smoke" in path.lower() or "smoke" in env_text.lower()
    n_values = [row.get("n") for row in timed if isinstance(row.get("n"), (int, float))]
    small_n = any(value is not None and value < 10_000 for value in n_values)
    provisional = smoke_marker or small_n

    meta = {
        "path": path,
        "header": header,
        "env_path": env_path,
        "env_text": env_text,
        "n_raw": len(raw),
        "n_timed": len(timed),
        "provisional": provisional,
    }
    return timed, meta


def group_stats(rows, keys, value="time_ns"):
    groups = {}
    for row in rows:
        key = tuple(row.get(column) for column in keys)
        groups.setdefault(key, []).append(row)

    stats = {}
    for key, members in groups.items():
        values = [row.get(value) for row in members if isinstance(row.get(value), (int, float))]
        if not values:
            continue
        array = np.asarray(values, dtype=float)
        stats[key] = {
            "key": key,
            "n": len(array),
            "median": float(np.median(array)),
            "min": float(array.min()),
            "max": float(array.max()),
            "mean": float(array.mean()),
        }
    return stats


def median_of(rows, keys, value):
    stats = group_stats(rows, keys, value)
    return {key: entry["median"] for key, entry in stats.items()}


def to_ms(time_ns):
    return time_ns / TIME_DIVISOR_NS


def r2_score(observed, predicted):
    observed = np.asarray(observed, dtype=float)
    predicted = np.asarray(predicted, dtype=float)
    residual = observed - predicted
    ss_res = float(np.sum(residual ** 2))
    ss_tot = float(np.sum((observed - observed.mean()) ** 2))
    if ss_tot == 0.0:
        return None
    return 1.0 - ss_res / ss_tot


def loglog_fit(xs, ys):
    pairs = [
        (float(x), float(y)) for x, y in zip(xs, ys)
        if x is not None and y is not None and x > 0 and y > 0
    ]
    if len({x for x, _ in pairs}) < 2:
        return {"slope": None, "intercept": None, "r2": None, "points": len(pairs)}
    x = np.log10([p[0] for p in pairs])
    y = np.log10([p[1] for p in pairs])
    slope, intercept = np.polyfit(x, y, 1)
    predicted = slope * x + intercept
    return {
        "slope": float(slope),
        "intercept": float(intercept),
        "r2": r2_score(y, predicted),
        "points": len(pairs),
    }


def least_squares_costs(g_values, nq_values, time_values):
    """Fit t = T_BPS * G + T_RPS * N_Q with no intercept."""
    g = np.asarray(g_values, dtype=float)
    nq = np.asarray(nq_values, dtype=float)
    t = np.asarray(time_values, dtype=float)
    if len(t) < 2:
        return {"t_bps_ns": None, "t_rps_ns": None, "r2": None, "points": len(t)}
    design = np.column_stack([g, nq])
    if np.linalg.matrix_rank(design) < 2:
        return {"t_bps_ns": None, "t_rps_ns": None, "r2": None, "points": len(t)}
    coefficients, _, _, _ = np.linalg.lstsq(design, t, rcond=None)
    predicted = design @ coefficients
    return {
        "t_bps_ns": float(coefficients[0]),
        "t_rps_ns": float(coefficients[1]),
        "r2": r2_score(t, predicted),
        "points": len(t),
    }


def save_csv(path, fieldnames, rows):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def setup_matplotlib():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "font.size": 9,
        "axes.labelsize": 9,
        "axes.titlesize": 9,
        "legend.fontsize": 7.5,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "axes.grid": True,
        "grid.alpha": 0.25,
        "grid.linewidth": 0.5,
        "figure.dpi": 160,
        "savefig.bbox": "tight",
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    })
    return plt


def band_plot(ax, xs, medians, lows, highs, label, color, marker, linestyle="-"):
    ax.plot(
        xs, medians, linestyle=linestyle, marker=marker, color=color,
        linewidth=1.4, markersize=4, label=label,
    )
    ax.fill_between(xs, lows, highs, color=color, alpha=0.18, linewidth=0)


def log_axes(ax, which="both"):
    from matplotlib.ticker import LogLocator, NullFormatter

    axes = []
    if which in ("both", "x"):
        axes.append(ax.xaxis)
    if which in ("both", "y"):
        axes.append(ax.yaxis)
    for axis in axes:
        axis.set_major_locator(LogLocator(base=10, subs=(1.0, 2.0, 5.0)))
        axis.set_minor_formatter(NullFormatter())


def finish(fig, out_pdf, provisional, source):
    if provisional:
        fig.suptitle("PROVISIONAL (smoke data)", fontsize=9, y=0.995)
    fig.text(0.01, 0.005, f"source: {os.path.basename(source)}", fontsize=6, color="0.35")
    os.makedirs(os.path.dirname(os.path.abspath(out_pdf)), exist_ok=True)
    fig.savefig(out_pdf)
    return out_pdf


def out_dir(cli_value=None):
    directory = cli_value or os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
    os.makedirs(directory, exist_ok=True)
    return directory


def sort_key(value):
    if value is None:
        return (2, "")
    if isinstance(value, (int, float)):
        return (0, value)
    return (1, str(value))
