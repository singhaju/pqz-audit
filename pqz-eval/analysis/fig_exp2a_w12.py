"""Figure exp2a, single column, single panel (w12): clustered layout only.

Copy of fig_exp2a_full.py with panel (b) (scattered) removed.  Same data file
(results/full-1/exp2a/exp2a.csv, first run), same colours, labels and fonts.
Every plotted value is the median of timed rows; the band is min-max.
Writes fig_exp2a_w12.{pdf,png,csv} into journal2/figures/results-w12/ by default.
"""

from __future__ import annotations

import argparse
import os

from matplotlib.ticker import LogLocator

import common

APPROACH_ORDER = ["trad_scan", "prot_full_scan", "pqz"]
DISPLAY = {"trad_scan": "Traditional Full Scan", "prot_full_scan": "Protected Full Scan", "pqz": "PQZ-Audit"}
LAYOUT = "clustered"
PREDICATE_ORDER = ["P1", "P2", "P3", "P4"]
FIELDS = [
    "figure", "record_type", "layout", "predicate", "approach", "sigma",
    "n_runs", "median_ms", "min_ms", "max_ms", "n_blocks_median",
    "n_retained_blocks_median", "provisional", "note",
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
    parser.add_argument("csv", nargs="?", default=None, help="exp2a raw CSV")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3,
                        help="minimum timed runs per group")
    return parser.parse_args()


def fmt(value):
    return f"{value:.10g}"


def main():
    args = parse_args()
    path = args.csv or common.default_csv("results/full-1/exp2a/exp2a.csv")
    rows, meta = common.load_csv(
        path,
        required=("n", "sigma", "layout", "predicate", "approach", "time_ns",
                  "n_blocks", "n_retained_blocks", "warmup"),
        min_runs=args.min_runs,
        group_keys=("layout", "predicate", "approach"),
    )

    keys = ("layout", "predicate", "approach")
    stats = common.group_stats(rows, keys)
    blocks = common.group_stats(rows, keys, value="n_blocks")
    retained = common.group_stats(rows, keys, value="n_retained_blocks")
    sigma_of = {}
    for row in rows:
        sigma_of[(row.get("layout"), row.get("predicate"), row.get("approach"))] = row.get("sigma")
    provisional = any(entry["n"] < 10 for entry in stats.values())

    rows_out = []
    for approach in APPROACH_ORDER:
        for predicate in PREDICATE_ORDER:
            entry = stats.get((LAYOUT, predicate, approach))
            if entry is None:
                continue
            rows_out.append({
                "figure": "exp2a_w12",
                "record_type": "group",
                "layout": LAYOUT,
                "predicate": predicate,
                "approach": approach,
                "sigma": sigma_of.get((LAYOUT, predicate, approach), ""),
                "n_runs": entry["n"],
                "median_ms": fmt(common.to_ms(entry["median"])),
                "min_ms": fmt(common.to_ms(entry["min"])),
                "max_ms": fmt(common.to_ms(entry["max"])),
                "n_blocks_median": fmt(blocks[(LAYOUT, predicate, approach)]["median"]),
                "n_retained_blocks_median": fmt(
                    retained[(LAYOUT, predicate, approach)]["median"]
                ),
                "provisional": int(provisional),
                "note": "median of timed rows",
            })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 2.6))

    for index, approach in enumerate(APPROACH_ORDER):
        entries = [
            (predicate, stats[(LAYOUT, predicate, approach)])
            for predicate in PREDICATE_ORDER
            if (LAYOUT, predicate, approach) in stats
        ]
        entries.sort(key=lambda item: PREDICATE_ORDER.index(item[0]))
        if not entries:
            continue
        xs = [PREDICATE_ORDER.index(predicate) + 1 for predicate, _ in entries]
        medians = [common.to_ms(entry["median"]) for _, entry in entries]
        lows = [common.to_ms(entry["min"]) for _, entry in entries]
        highs = [common.to_ms(entry["max"]) for _, entry in entries]
        common.band_plot(
            ax, xs, medians, lows, highs, DISPLAY[approach],
            common.PALETTE[index], common.MARKERS[index],
        )
    ax.set_yscale("log")
    common.log_axes(ax, which="y")
    ax.yaxis.set_major_locator(
        LogLocator(base=10, subs=(1.0, 2.0, 5.0), numticks=12)
    )
    ax.set_xticks(range(1, 5))
    ax.set_xticklabels(PREDICATE_ORDER)
    ax.set_xlim(0.6, 4.4)
    ax.set_xlabel("Predicate")
    ax.set_ylabel("Query time (ms)")

    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", ncol=3, frameon=False,
        bbox_to_anchor=(0.5, 1.0), fontsize=5.6, columnspacing=0.9,
        handlelength=1.5, handletextpad=0.4,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.92))

    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp2a_w12.pdf"), provisional, path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp2a_w12.png"), dpi=200)
    plt.close(fig)

    csv_path = os.path.join(directory, "fig_exp2a_w12.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    for predicate in PREDICATE_ORDER:
        entry = stats[(LAYOUT, predicate, "pqz")]
        print(f"PQZ-Audit {predicate}: median {common.to_ms(entry['median']):.6g} ms "
              f"(min {common.to_ms(entry['min']):.6g}, max {common.to_ms(entry['max']):.6g}, "
              f"n={entry['n']})")
    if provisional:
        print("provisional=True (a group has fewer than 10 timed runs)")


if __name__ == "__main__":
    main()
