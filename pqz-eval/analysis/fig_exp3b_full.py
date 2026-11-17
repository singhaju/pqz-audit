"""Figure exp3b (full data): operators at sigma=1%, N=1e6.

Top panel: SUM and AVG grouped bars for plain_agg, full_he and pqz (log y,
min-max whiskers).  Bottom small panel: COUNT from exp3d (pqz and plain_agg in
ns) and exp3b (full_he in ms).  pqz COUNT is the cardinality only, so no ratio
is drawn for COUNT.  R_HE is written to the CSV only for SUM and AVG.
"""

from __future__ import annotations

import argparse
import os

from matplotlib.ticker import LogLocator
from matplotlib.gridspec import GridSpec

import common

APPROACH_ORDER = ["plain_agg", "full_he", "pqz"]
DISPLAY = {"plain_agg": "Plaintext aggregation", "full_he": "Full-Domain HE", "pqz": "PQZ-Audit"}
AGG_ORDER = ["SUM", "AVG"]
FIELDS = [
    "figure", "record_type", "panel", "agg", "approach", "n_runs",
    "median", "min", "max", "unit", "r_he", "provisional", "note",
]


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exp3b", default=None, help="exp3b raw CSV")
    parser.add_argument("--exp3d", default=None, help="exp3d raw CSV")
    parser.add_argument("--out", default=None, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3,
                        help="minimum timed runs per group")
    return parser.parse_args()


def fmt(value):
    return f"{value:.10g}"


def log_ticks(ax, which="both", subs=(1.0, 2.0, 5.0)):
    if which in ("both", "x"):
        ax.xaxis.set_major_locator(
            LogLocator(base=10, subs=subs, numticks=12)
        )
    if which in ("both", "y"):
        ax.yaxis.set_major_locator(
            LogLocator(base=10, subs=subs, numticks=12)
        )


def main():
    args = parse_args()
    exp3b_path = args.exp3b or common.default_csv(
        "results/full-2/exp3b/exp3b.csv"
    )
    exp3d_path = args.exp3d or common.default_csv(
        "results/full-2/exp3d/exp3d.csv"
    )

    exp3b_rows, exp3b_meta = common.load_csv(
        exp3b_path,
        required=("n", "sigma", "agg", "approach", "time_ns", "warmup"),
        min_runs=args.min_runs,
        group_keys=("agg", "approach"),
    )
    exp3b_rows = [
        row for row in exp3b_rows
        if float(row.get("n")) == 1_000_000.0
        and abs(float(row.get("sigma")) - 0.01) < 1e-12
    ]
    if not exp3b_rows:
        raise SystemExit("refusing: no exp3b rows at N=1e6, sigma=1%")
    exp3b_stats = common.group_stats(exp3b_rows, ("agg", "approach"))

    exp3d_rows, exp3d_meta = common.load_csv(
        exp3d_path,
        required=("n", "sigma", "agg", "approach", "time_ns", "warmup"),
        min_runs=args.min_runs,
        group_keys=("agg", "approach"),
    )
    exp3d_rows = [
        row for row in exp3d_rows
        if abs(float(row.get("sigma")) - 0.01) < 1e-12
        and row.get("agg") == "COUNT"
        and row.get("approach") in ("plain_agg", "pqz")
    ]
    if not exp3d_rows:
        raise SystemExit("refusing: no exp3d COUNT rows at sigma=1%")
    exp3d_stats = common.group_stats(exp3d_rows, ("approach",))

    for agg in AGG_ORDER:
        for approach in APPROACH_ORDER:
            entry = exp3b_stats.get((agg, approach))
            if entry is None:
                raise SystemExit(f"refusing: missing exp3b {agg}/{approach}")
    for approach in ("plain_agg", "pqz"):
        if exp3d_stats.get((approach,)) is None:
            raise SystemExit(f"refusing: missing exp3d COUNT/{approach}")
    full_he_count = exp3b_stats.get(("COUNT", "full_he"))
    if full_he_count is None:
        raise SystemExit("refusing: missing exp3b COUNT/full_he")

    all_entries = list(exp3b_stats.values()) + list(exp3d_stats.values())
    provisional = (
        exp3b_meta["provisional"] or exp3d_meta["provisional"]
        or any(entry["n"] < 10 for entry in all_entries)
    )

    rows_out = []
    for agg in AGG_ORDER:
        for approach in APPROACH_ORDER:
            entry = exp3b_stats[(agg, approach)]
            rows_out.append({
                "figure": "exp3b_full",
                "record_type": "bar",
                "panel": "operators",
                "agg": agg,
                "approach": approach,
                "n_runs": entry["n"],
                "median": fmt(common.to_ms(entry["median"])),
                "min": fmt(common.to_ms(entry["min"])),
                "max": fmt(common.to_ms(entry["max"])),
                "unit": "ms",
                "provisional": int(provisional),
                "note": "grouped bar, median of timed rows; whisker min-max",
            })
        pqz = exp3b_stats[(agg, "pqz")]
        full_he = exp3b_stats[(agg, "full_he")]
        r_he = 1.0 - pqz["median"] / full_he["median"]
        rows_out.append({
            "figure": "exp3b_full",
            "record_type": "r_he",
            "panel": "operators",
            "agg": agg,
            "approach": "",
            "n_runs": min(pqz["n"], full_he["n"]),
            "r_he": fmt(r_he),
            "unit": "-",
            "provisional": int(provisional),
            "note": "R_HE = 1 - T_pqz / T_full_he",
        })

    for approach in ("plain_agg", "pqz"):
        entry = exp3d_stats[(approach,)]
        rows_out.append({
            "figure": "exp3b_full",
            "record_type": "count",
            "panel": "COUNT",
            "agg": "COUNT",
            "approach": approach,
            "n_runs": entry["n"],
            "median": fmt(entry["median"]),
            "min": fmt(entry["min"]),
            "max": fmt(entry["max"]),
            "unit": "ns",
            "provisional": int(provisional),
            "note": "exp3d COUNT at sigma=1%; median of timed rows",
        })
    rows_out.append({
        "figure": "exp3b_full",
        "record_type": "count",
        "panel": "COUNT",
        "agg": "COUNT",
        "approach": "full_he",
        "n_runs": full_he_count["n"],
        "median": fmt(common.to_ms(full_he_count["median"])),
        "min": fmt(common.to_ms(full_he_count["min"])),
        "max": fmt(common.to_ms(full_he_count["max"])),
        "unit": "ms",
        "provisional": int(provisional),
        "note": "exp3b COUNT at sigma=1%; median of timed rows",
    })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig = plt.figure(figsize=(7.0, 2.8))
    grid = GridSpec(1, 2, width_ratios=[1.4, 1.0], wspace=0.62, figure=fig)
    ax = fig.add_subplot(grid[0])
    ax_count = fig.add_subplot(grid[1])

    width = 0.26
    for agg_index, agg in enumerate(AGG_ORDER):
        base = agg_index * 4.0
        for approach_index, approach in enumerate(APPROACH_ORDER):
            entry = exp3b_stats[(agg, approach)]
            heights = common.to_ms(entry["median"])
            lows = common.to_ms(entry["min"])
            highs = common.to_ms(entry["max"])
            position = base + approach_index
            ax.bar(
                [position], [heights], width=width,
                color=common.PALETTE[approach_index],
                label=DISPLAY[approach] if agg_index == 0 else None,
                yerr=[[heights - lows], [highs - heights]],
                capsize=2,
                error_kw={"elinewidth": 0.7, "ecolor": "0.3"},
            )
    ax.set_yscale("log")
    common.log_axes(ax, which="y")
    log_ticks(ax, which="y")
    all_lows = [
        common.to_ms(exp3b_stats[(agg, approach)]["min"])
        for agg in AGG_ORDER for approach in APPROACH_ORDER
    ]
    all_highs = [
        common.to_ms(exp3b_stats[(agg, approach)]["max"])
        for agg in AGG_ORDER for approach in APPROACH_ORDER
    ]
    ax.set_ylim(min(all_lows) / 3.0, max(all_highs) * 3.0)
    ax.set_xticks([1.0, 5.0])
    ax.set_xticklabels(AGG_ORDER)
    ax.set_xlim(-0.6, 6.6)
    ax.set_xlabel("Operator")
    ax.set_ylabel("Aggregation time (ms)")
    ax.set_title("(a) SUM and AVG at σ=1%, N=1e6")

    # COUNT panel: two units, no ratio.
    left_positions = [0.0, 1.0]
    left_entries = [exp3d_stats[("plain_agg",)], exp3d_stats[("pqz",)]]
    left_colors = [common.PALETTE[0], common.PALETTE[2]]
    left_heights = [entry["median"] for entry in left_entries]
    left_lows = [entry["min"] for entry in left_entries]
    left_highs = [entry["max"] for entry in left_entries]
    ax_count.bar(
        left_positions, left_heights, width=0.45, color=left_colors,
        yerr=[
            [h - l for h, l in zip(left_heights, left_lows)],
            [h - l for h, l in zip(left_highs, left_heights)],
        ],
        capsize=2, error_kw={"elinewidth": 0.7, "ecolor": "0.3"},
    )
    ax_count.set_ylim(0, max(left_highs) * 1.6)
    ax_count.set_xticks([0.0, 1.0, 2.0])
    ax_count.set_xticklabels([DISPLAY["plain_agg"].replace(" ", "\n"), DISPLAY["pqz"], DISPLAY["full_he"].replace(" ", "\n")])
    ax_count.set_xlim(-0.6, 2.6)
    ax_count.set_ylabel("COUNT time (ns)")

    ax_count_right = ax_count.twinx()
    ax_count_right.bar(
        [2.0], [common.to_ms(full_he_count["median"])], width=0.45,
        color=common.PALETTE[1],
        yerr=[
            [common.to_ms(full_he_count["median"] - full_he_count["min"])],
            [common.to_ms(full_he_count["max"] - full_he_count["median"])],
        ],
        capsize=2, error_kw={"elinewidth": 0.7, "ecolor": "0.3"},
    )
    ax_count_right.set_ylim(
        0, common.to_ms(full_he_count["max"]) * 1.4
    )
    ax_count_right.set_ylabel("Full-Domain HE COUNT (ms)")
    ax_count_right.grid(False)
    ax_count.set_title("(b) COUNT (ns / ms: timer resolution, no ratio)")
    ax_count.text(
        0.02, 0.92, "PQZ-Audit COUNT = cardinality only", transform=ax_count.transAxes,
        fontsize=5.8, color="0.35", ha="left", va="top",
    )

    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", ncol=3, frameon=False,
        bbox_to_anchor=(0.5, 0.995),
    )
    fig.text(
        0.01, 0.01,
        "Bars are medians; whiskers are min-max. Full-Domain HE has 10 timed runs per bar.",
        fontsize=5.4, color="0.35",
    )
    fig.subplots_adjust(top=0.83, bottom=0.22, left=0.075, right=0.90)

    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp3b_full.pdf"), provisional,
        exp3b_path,
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp3b_full.png"), dpi=200)
    plt.close(fig)

    csv_path = os.path.join(directory, "fig_exp3b_full.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (a group has fewer than 10 timed runs)")


if __name__ == "__main__":
    main()
