"""Figure exp2b (full data): selectivity and block-size sweeps.

Panel (a) is the sigma sweep from exp2b, panel (b) the m_B sweep from exp2c.
Both layouts are drawn: solid = clustered, dashed = scattered.  Every plotted
value is the median of timed rows; the band is the observed min-max.
"""

from __future__ import annotations

import argparse
import os

from matplotlib.ticker import LogLocator
from matplotlib.lines import Line2D

import common

APPROACH_ORDER = ["trad_scan", "prot_full_scan", "pqz"]
DISPLAY = {"trad_scan": "Traditional Full Scan", "prot_full_scan": "Protected Full Scan", "pqz": "PQZ-Audit"}
LAYOUT_ORDER = ["clustered", "scattered"]
FIELDS = [
    "figure", "panel", "approach", "layout", "x", "x_label", "n_runs",
    "median_ms", "min_ms", "max_ms", "provisional", "note",
]


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sigma", default=None, help="exp2b raw CSV")
    parser.add_argument("--mb", default=None, help="exp2c raw CSV")
    parser.add_argument("--out", default=None, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3,
                        help="minimum timed runs per group")
    return parser.parse_args()


def fmt(value):
    return f"{value:.10g}"


def log_ticks(ax, which="both"):
    if which in ("both", "x"):
        ax.xaxis.set_major_locator(
            LogLocator(base=10, subs=(1.0, 2.0, 5.0), numticks=12)
        )
    if which in ("both", "y"):
        ax.yaxis.set_major_locator(
            LogLocator(base=10, subs=(1.0, 2.0, 5.0), numticks=12)
        )


def load_sweep(path, key, required, min_runs):
    rows, meta = common.load_csv(
        path, required=required, min_runs=min_runs,
        group_keys=("layout", "approach", key),
    )
    stats = common.group_stats(rows, ("layout", "approach", key))
    return rows, stats, meta


def draw_panel(ax, stats, key, x_scale, x_label):
    for index, approach in enumerate(APPROACH_ORDER):
        for layout in LAYOUT_ORDER:
            entries = sorted(
                (
                    (key_value, entry)
                    for (layout_key, approach_key, key_value), entry in stats.items()
                    if layout_key == layout and approach_key == approach
                ),
                key=lambda item: item[0],
            )
            if not entries:
                continue
            xs = [x_scale(value) for value, _ in entries]
            medians = [common.to_ms(entry["median"]) for _, entry in entries]
            lows = [common.to_ms(entry["min"]) for _, entry in entries]
            highs = [common.to_ms(entry["max"]) for _, entry in entries]
            common.band_plot(
                ax, xs, medians, lows, highs, approach,
                common.PALETTE[index], common.MARKERS[index],
                linestyle="-" if layout == "clustered" else "--",
            )
    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    log_ticks(ax)
    ax.set_xlabel(x_label)
    ax.set_ylabel("Query time (ms)")


def main():
    args = parse_args()
    sigma_path = args.sigma or common.default_csv(
        "results/full-1/exp2b/exp2b.csv"
    )
    mb_path = args.mb or common.default_csv(
        "results/full-1/exp2c/exp2c.csv"
    )
    common_required = ("n", "sigma", "mb", "layout", "approach", "time_ns",
                       "warmup")

    _, sigma_stats, sigma_meta = load_sweep(
        sigma_path, "sigma", common_required, args.min_runs
    )
    _, mb_stats, mb_meta = load_sweep(
        mb_path, "mb", common_required, args.min_runs
    )

    all_stats = list(sigma_stats.items()) + list(mb_stats.items())
    provisional = (
        sigma_meta["provisional"] or mb_meta["provisional"]
        or any(entry["n"] < 10 for _, entry in all_stats)
    )

    rows_out = []
    for panel, stats, scale, unit, source_note in (
        ("selectivity", sigma_stats, lambda value: float(value) * 100.0,
         "% of N", "exp2b sigma sweep"),
        ("block_size", mb_stats, lambda value: float(value),
         "records", "exp2c m_B sweep"),
    ):
        for (layout, approach, key_value), entry in sorted(
            stats.items(),
            key=lambda item: (item[0][1], item[0][0], item[0][2]),
        ):
            x_value = scale(key_value)
            rows_out.append({
                "figure": "exp2b_full",
                "panel": panel,
                "approach": approach,
                "layout": layout,
                "x": fmt(x_value),
                "x_label": unit,
                "n_runs": entry["n"],
                "median_ms": fmt(common.to_ms(entry["median"])),
                "min_ms": fmt(common.to_ms(entry["min"])),
                "max_ms": fmt(common.to_ms(entry["max"])),
                "provisional": int(provisional),
                "note": source_note + "; median of timed rows",
            })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.7))

    draw_panel(
        axes[0], sigma_stats, "sigma",
        lambda value: float(value) * 100.0, "selectivity σ (% of N)",
    )
    axes[0].set_title("(a) selectivity sweep")

    draw_panel(
        axes[1], mb_stats, "mb",
        lambda value: float(value), "block size $m_B$ (records)",
    )
    axes[1].set_title("(b) block-size sweep")

    approach_handles = [
        Line2D([0], [0], color=common.PALETTE[index],
               marker=common.MARKERS[index], linewidth=1.4, markersize=4,
               label=DISPLAY[approach])
        for index, approach in enumerate(APPROACH_ORDER)
    ]
    layout_handles = [
        Line2D([0], [0], color="0.35", linestyle="-", linewidth=1.2,
               label="clustered"),
        Line2D([0], [0], color="0.35", linestyle="--", linewidth=1.2,
               label="scattered"),
    ]
    fig.legend(
        handles=approach_handles + layout_handles, loc="upper center",
        ncol=5, frameon=False, bbox_to_anchor=(0.5, 1.0),
    )
    fig.tight_layout(rect=(0, 0.01, 1, 0.93))

    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp2b_full.pdf"), provisional,
        "exp2b.csv + exp2c.csv",
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp2b_full.png"), dpi=200)
    plt.close(fig)

    csv_path = os.path.join(directory, "fig_exp2b_full.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (a group has fewer than 10 timed runs)")


if __name__ == "__main__":
    main()
