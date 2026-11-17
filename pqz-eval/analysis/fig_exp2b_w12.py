"""Figure exp2b, single column, single panel (w12): selectivity sweep, clustered only.

Copy of fig_exp2b_full.py (run through fig_exp2b_dense.py, i.e. dense data
results/dense-1/exp2bd/exp2bd.csv).  Removed: panel (b) block-size sweep and
the dashed scattered curves.  Every plotted value is the median of timed rows;
the band is min-max.  Writes fig_exp2b_w12.{pdf,png,csv} into
journal2/figures/results-w12/ by default.
"""

from __future__ import annotations

import argparse
import os

from matplotlib.ticker import LogLocator

import common
import dense_common as dc

APPROACH_ORDER = ["trad_scan", "prot_full_scan", "pqz"]
DISPLAY = {"trad_scan": "Traditional Full Scan", "prot_full_scan": "Protected Full Scan", "pqz": "PQZ-Audit"}
LAYOUT = "clustered"
FIELDS = [
    "figure", "panel", "approach", "layout", "x", "x_label", "n_runs",
    "median_ms", "min_ms", "max_ms", "provisional", "note", "source",
]
DEFAULT_OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))),
    "journal2", "figures", "results-w12",
)


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sigma", default=dc.results_path("dense-1/exp2bd/exp2bd.csv"),
                        help="exp2bd raw CSV")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3,
                        help="minimum timed runs per group")
    return parser.parse_args()


def fmt(value):
    return f"{value:.10g}"


def main():
    args = parse_args()
    required = ("n", "sigma", "mb", "layout", "approach", "time_ns", "warmup")
    rows, meta = common.load_csv(
        args.sigma, required=required, min_runs=args.min_runs,
        group_keys=("layout", "approach", "sigma"),
    )
    stats = common.group_stats(rows, ("layout", "approach", "sigma"))
    provisional = meta["provisional"] or any(
        entry["n"] < 10 for entry in stats.values())
    source = dc.rel(args.sigma)

    rows_out = []
    for (layout, approach, key_value), entry in sorted(
        stats.items(), key=lambda item: (item[0][1], item[0][0], item[0][2]),
    ):
        if layout != LAYOUT:
            continue
        rows_out.append({
            "figure": "exp2b_w12",
            "panel": "selectivity",
            "approach": approach,
            "layout": layout,
            "x": fmt(float(key_value) * 100.0),
            "x_label": "% of N",
            "n_runs": entry["n"],
            "median_ms": fmt(common.to_ms(entry["median"])),
            "min_ms": fmt(common.to_ms(entry["min"])),
            "max_ms": fmt(common.to_ms(entry["max"])),
            "provisional": int(provisional),
            "note": "exp2b sigma sweep; median of timed rows",
            "source": source,
        })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 2.6))

    summary = []
    for index, approach in enumerate(APPROACH_ORDER):
        entries = sorted(
            (
                (key_value, entry)
                for (layout_key, approach_key, key_value), entry in stats.items()
                if layout_key == LAYOUT and approach_key == approach
            ),
            key=lambda item: item[0],
        )
        if not entries:
            continue
        xs = [float(value) * 100.0 for value, _ in entries]
        medians = [common.to_ms(entry["median"]) for _, entry in entries]
        lows = [common.to_ms(entry["min"]) for _, entry in entries]
        highs = [common.to_ms(entry["max"]) for _, entry in entries]
        common.band_plot(
            ax, xs, medians, lows, highs, DISPLAY[approach],
            common.PALETTE[index], common.MARKERS[index],
        )
        if approach == "pqz":
            summary = list(zip(xs, medians, lows, highs,
                               [entry["n"] for _, entry in entries]))
    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    for axis in (ax.xaxis, ax.yaxis):
        axis.set_major_locator(
            LogLocator(base=10, subs=(1.0, 2.0, 5.0), numticks=12))
    ax.set_xlabel("selectivity σ (% of N)")
    ax.set_ylabel("Query time (ms)")

    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", ncol=3, frameon=False,
        bbox_to_anchor=(0.5, 1.0), fontsize=5.6, columnspacing=0.9,
        handlelength=1.5, handletextpad=0.4,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.92))

    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp2b_w12.pdf"), provisional,
        "exp2bd.csv",
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp2b_w12.png"), dpi=200)
    plt.close(fig)

    csv_path = os.path.join(directory, "fig_exp2b_w12.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    for x, med, lo, hi, n in summary:
        print(f"PQZ-Audit clustered sigma={x:g}%: median {med:.6g} ms "
              f"(min {lo:.6g}, max {hi:.6g}, n={n})")
    if provisional:
        print("provisional=True (a group has fewer than 10 timed runs)")


if __name__ == "__main__":
    main()
