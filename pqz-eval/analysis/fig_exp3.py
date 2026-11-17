"""Figure for exp3: aggregation time versus selected count and R_HE."""

from __future__ import annotations

import argparse
import os

import common


APPROACH_ORDER = ["plain_agg", "full_he", "pqz"]
AGG_ORDER = ["COUNT", "SUM", "AVG"]

FIELDS = [
    "figure", "record_type", "agg", "approach", "n_sel", "n_cand_median",
    "n_runs", "median_ms", "min_ms", "max_ms", "slope", "r2", "points_fit",
    "r_he", "provisional", "note",
]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="*", help="exp3a / exp3b CSV file(s)")
    parser.add_argument("--out", default=None, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3,
                        help="minimum timed runs per group")
    return parser.parse_args()


def _color(approach):
    index = APPROACH_ORDER.index(approach) if approach in APPROACH_ORDER else 0
    return common.PALETTE[index % len(common.PALETTE)]


def _marker(approach):
    index = APPROACH_ORDER.index(approach) if approach in APPROACH_ORDER else 0
    return common.MARKERS[index % len(common.MARKERS)]


def main():
    args = parse_args()
    paths = args.csv or [common.default_csv("smoke/s3/exp3a.csv")]

    all_rows = []
    provisional = False
    sources = []
    for path in paths:
        rows, meta = common.load_csv(
            path,
            required=("agg", "approach", "n_sel", "time_ns", "warmup"),
            min_runs=args.min_runs,
            group_keys=("agg", "approach", "n_sel"),
        )
        all_rows.extend(rows)
        provisional = provisional or meta["provisional"]
        sources.append(path)

    stats = common.group_stats(all_rows, ("agg", "approach", "n_sel"))
    n_cand_stats = common.group_stats(all_rows, ("agg", "approach", "n_sel"), value="n_cand")
    for key, entry in stats.items():
        if key in n_cand_stats:
            entry["n_cand_median"] = n_cand_stats[key]["median"]

    aggs = [agg for agg in AGG_ORDER if any(key[0] == agg for key in stats)]
    if not aggs:
        aggs = sorted({key[0] for key in stats})

    rows_out = []

    for agg in aggs:
        for approach in APPROACH_ORDER:
            entries = sorted(
                (
                    (key[2], value) for key, value in stats.items()
                    if key[0] == agg and key[1] == approach
                ),
                key=lambda item: common.sort_key(item[0]),
            )
            if not entries:
                continue
            xs = [n_sel for n_sel, _ in entries]
            medians = [common.to_ms(entry["median"]) for _, entry in entries]
            fit = common.loglog_fit(xs, medians)
            note = ""
            if fit["slope"] is None:
                note = "NOT-ENOUGH-DATA: fewer than 2 distinct n_sel values"
            elif fit["points"] == 2:
                note = "slope from 2 points only"
            for (n_sel, entry), median in zip(entries, medians):
                rows_out.append({
                    "figure": "exp3",
                    "record_type": "group",
                    "agg": agg,
                    "approach": approach,
                    "n_sel": n_sel,
                    "n_cand_median": (
                        "" if entry.get("n_cand_median") is None
                        else f"{entry['n_cand_median']:.6g}"
                    ),
                    "n_runs": entry["n"],
                    "median_ms": f"{median:.6g}",
                    "min_ms": f"{common.to_ms(entry['min']):.6g}",
                    "max_ms": f"{common.to_ms(entry['max']):.6g}",
                    "slope": "" if fit["slope"] is None else f"{fit['slope']:.6f}",
                    "r2": "" if fit["r2"] is None else f"{fit['r2']:.6f}",
                    "points_fit": fit["points"],
                    "provisional": int(provisional),
                    "note": note,
                })

    for agg in aggs:
        sel_values = sorted({
            key[2] for key in stats
            if key[0] == agg and key[2] is not None
        })
        for n_sel in sel_values:
            pqz = stats.get((agg, "pqz", n_sel))
            full_he = stats.get((agg, "full_he", n_sel))
            if not pqz or not full_he or full_he["median"] == 0:
                rows_out.append({
                    "figure": "exp3",
                    "record_type": "r_he",
                    "agg": agg,
                    "n_sel": n_sel,
                    "provisional": int(provisional),
                    "note": "NOT-ENOUGH-DATA: need both pqz and full_he at this n_sel",
                })
                continue
            r_he = 1.0 - pqz["median"] / full_he["median"]
            rows_out.append({
                "figure": "exp3",
                "record_type": "r_he",
                "agg": agg,
                "n_sel": n_sel,
                "r_he": f"{r_he:.6g}",
                "provisional": int(provisional),
                "note": "R_HE = 1 - T_pqz / T_full_he",
            })

    plt = common.setup_matplotlib()
    directory = common.out_dir(args.out)

    fig, axes = plt.subplots(
        1, len(aggs), figsize=(4.0 * len(aggs), 3.0), squeeze=False
    )

    for column, agg in enumerate(aggs):
        ax = axes[0][column]
        for approach in APPROACH_ORDER:
            entries = sorted(
                (
                    (key[2], value) for key, value in stats.items()
                    if key[0] == agg and key[1] == approach
                ),
                key=lambda item: common.sort_key(item[0]),
            )
            if not entries:
                continue
            xs = [n_sel for n_sel, _ in entries]
            medians = [common.to_ms(entry["median"]) for _, entry in entries]
            lows = [common.to_ms(entry["min"]) for _, entry in entries]
            highs = [common.to_ms(entry["max"]) for _, entry in entries]
            common.band_plot(
                ax, xs, medians, lows, highs, approach,
                _color(approach), _marker(approach),
            )
        ax.set_xscale("log")
        ax.set_yscale("log")
        common.log_axes(ax)
        ax.set_xlabel("n_sel (selected records)")
        ax.set_ylabel(f"Aggregation time ({common.TIME_UNIT})")
        ax.set_title(f"operator: {agg}", fontsize=8)
        sel_values = sorted({key[2] for key in stats
                             if key[0] == agg and key[2] is not None})
        if len(sel_values) == 1:
            pqz = stats.get((agg, "pqz", sel_values[0]))
            full_he = stats.get((agg, "full_he", sel_values[0]))
            if pqz and full_he and full_he["median"] > 0:
                r_he = 1.0 - pqz["median"] / full_he["median"]
                ax.text(
                    0.02, 0.06, f"R_HE = {r_he:.3f} (single n_sel)",
                    transform=ax.transAxes, fontsize=6.5, color="0.35",
                    ha="left", va="bottom",
                )

    handles, labels = axes[0][0].get_legend_handles_labels()
    if handles:
        fig.legend(
            handles, labels, loc="upper center", ncol=3, frameon=False,
            bbox_to_anchor=(0.5, 0.925),
        )
    fig.tight_layout(rect=(0, 0.02, 1, 0.87))

    pdf = common.finish(fig, os.path.join(directory, "fig_exp3.pdf"), provisional, sources[0])
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp3.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("label: PROVISIONAL (smoke data)")


if __name__ == "__main__":
    main()
