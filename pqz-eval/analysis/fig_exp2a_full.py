"""Figure exp2a (full data): query time by predicate for both layouts.

Every plotted value is the median of timed rows; the band is the observed
min-max.  Warm-up rows are dropped.  The scattered-panel note is computed from
the n_blocks and n_retained_blocks columns, not typed in.
"""

from __future__ import annotations

import argparse
import os

from matplotlib.ticker import LogLocator

import common

APPROACH_ORDER = ["trad_scan", "prot_full_scan", "pqz"]
DISPLAY = {"trad_scan": "Traditional Full Scan", "prot_full_scan": "Protected Full Scan", "pqz": "PQZ-Audit"}
LAYOUT_ORDER = ["clustered", "scattered"]
PREDICATE_ORDER = ["P1", "P2", "P3", "P4"]
FIELDS = [
    "figure", "record_type", "layout", "predicate", "approach", "sigma",
    "n_runs", "median_ms", "min_ms", "max_ms", "n_blocks_median",
    "n_retained_blocks_median", "provisional", "note",
]


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=None, help="exp2a raw CSV")
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

    layouts = [layout for layout in LAYOUT_ORDER if any(key[0] == layout for key in stats)]
    if len(layouts) != 2:
        raise SystemExit(f"refusing: expected both layouts, found {layouts}")

    pivot = stats.get(("scattered", "P4", "pqz"))
    blocks_pqz = blocks.get(("scattered", "P4", "pqz"))
    retained_pqz = retained.get(("scattered", "P4", "pqz"))
    if pivot is None or blocks_pqz is None or retained_pqz is None:
        raise SystemExit("refusing: need scattered pqz rows for the pruning note")
    note_scattered = (
        f"scattered layout retains {retained_pqz['median']:.0f} of "
        f"{blocks_pqz['median']:.0f} blocks (no pruning)"
    )

    rows_out = []
    for layout in layouts:
        for approach in APPROACH_ORDER:
            for predicate in PREDICATE_ORDER:
                entry = stats.get((layout, predicate, approach))
                if entry is None:
                    continue
                rows_out.append({
                    "figure": "exp2a_full",
                    "record_type": "group",
                    "layout": layout,
                    "predicate": predicate,
                    "approach": approach,
                    "sigma": sigma_of.get((layout, predicate, approach), ""),
                    "n_runs": entry["n"],
                    "median_ms": fmt(common.to_ms(entry["median"])),
                    "min_ms": fmt(common.to_ms(entry["min"])),
                    "max_ms": fmt(common.to_ms(entry["max"])),
                    "n_blocks_median": fmt(blocks[(layout, predicate, approach)]["median"]),
                    "n_retained_blocks_median": fmt(
                        retained[(layout, predicate, approach)]["median"]
                    ),
                    "provisional": int(provisional),
                    "note": "median of timed rows",
                })
    rows_out.append({
        "figure": "exp2a_full",
        "record_type": "annotation",
        "layout": "scattered",
        "predicate": "P4",
        "approach": "pqz",
        "n_blocks_median": fmt(blocks_pqz["median"]),
        "n_retained_blocks_median": fmt(retained_pqz["median"]),
        "provisional": int(provisional),
        "note": note_scattered,
    })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.7))

    for column, layout in enumerate(layouts):
        ax = axes[column]
        for index, approach in enumerate(APPROACH_ORDER):
            entries = [
                (predicate, stats[(layout, predicate, approach)])
                for predicate in PREDICATE_ORDER
                if (layout, predicate, approach) in stats
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
        log_ticks(ax, which="y")
        ax.set_xticks(range(1, 5))
        ax.set_xticklabels(PREDICATE_ORDER)
        ax.set_xlim(0.6, 4.4)
        ax.set_xlabel("Predicate")
        ax.set_ylabel("Query time (ms)")
        ax.set_title(f"({chr(97 + column)}) {layout}")

    handles, labels = axes[0].get_legend_handles_labels()
    if handles:
        fig.legend(
            handles, labels, loc="upper center", ncol=3, frameon=False,
            bbox_to_anchor=(0.5, 0.995),
        )
    fig.text(
        0.5, 0.01, note_scattered, ha="center", va="bottom",
        fontsize=5.8, color="0.35",
    )
    fig.tight_layout(rect=(0, 0.03, 1, 0.93))

    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp2a_full.pdf"), provisional, path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp2a_full.png"), dpi=200)
    plt.close(fig)

    csv_path = os.path.join(directory, "fig_exp2a_full.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    print(note_scattered)
    if provisional:
        print("provisional=True (a group has fewer than 10 timed runs)")


if __name__ == "__main__":
    main()
