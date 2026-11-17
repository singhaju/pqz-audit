"""Figure for exp2: query time by predicate and selectivity, with cost-fit."""

from __future__ import annotations

import argparse
import os
from collections import Counter

import common


APPROACH_ORDER = ["trad_scan", "prot_full_scan", "pqz"]
LAYOUT_ORDER = ["clustered", "scattered"]
PREDICATE_ORDER = ["P1", "P2", "P3", "P4"]

FIELDS = [
    "figure", "record_type", "layout", "predicate", "approach", "sigma",
    "n_runs", "median_ms", "min_ms", "max_ms", "n_cand_median",
    "scope", "n_points", "t_bps_ns_per_block", "t_rps_ns_per_record", "r2",
    "provisional", "note",
]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="*", help="exp2 CSV file(s)")
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


def _most_common(values, preferred=None):
    if not values:
        return None
    if preferred is not None and preferred in values:
        return preferred
    return Counter(values).most_common(1)[0][0]


def fit_costs(stats, layout_filter=None):
    g_values, nq_values, times, labels = [], [], [], []
    for (layout, predicate, approach, sigma), entry in stats.items():
        if approach not in ("prot_full_scan", "pqz"):
            continue
        if layout_filter is not None and layout != layout_filter:
            continue
        n_cand = entry.get("n_cand_median")
        n_blocks = entry.get("n_blocks_median")
        if n_cand is None:
            continue
        g_value = 0.0 if approach == "prot_full_scan" else float(n_blocks or 0)
        g_values.append(g_value)
        nq_values.append(float(n_cand))
        times.append(entry["median"])
        labels.append((layout, predicate, approach, sigma))
    return common.least_squares_costs(g_values, nq_values, times)


def main():
    args = parse_args()
    paths = args.csv or [
        common.default_csv("smoke/s2/exp2a.csv"),
    ]

    all_rows = []
    provisional = False
    sources = []
    for path in paths:
        rows, meta = common.load_csv(
            path,
            required=("approach", "layout", "predicate", "sigma", "time_ns", "warmup"),
            min_runs=args.min_runs,
            group_keys=("layout", "predicate", "approach", "sigma"),
        )
        all_rows.extend(rows)
        provisional = provisional or meta["provisional"]
        sources.append(path)

    stats = common.group_stats(all_rows, ("layout", "predicate", "approach", "sigma"))
    n_cand_stats = common.group_stats(
        all_rows, ("layout", "predicate", "approach", "sigma"), value="n_cand"
    )
    n_blocks_stats = common.group_stats(
        all_rows, ("layout", "predicate", "approach", "sigma"), value="n_blocks"
    )
    for key, entry in stats.items():
        if key in n_cand_stats:
            entry["n_cand_median"] = n_cand_stats[key]["median"]
        if key in n_blocks_stats:
            entry["n_blocks_median"] = n_blocks_stats[key]["median"]

    layouts = [layout for layout in LAYOUT_ORDER
               if any(key[0] == layout for key in stats)]
    if not layouts:
        layouts = sorted({key[0] for key in stats})

    sigma_values = sorted({key[3] for key in stats if key[3] is not None})
    predicate_values = [pred for pred in PREDICATE_ORDER
                        if any(key[1] == pred for key in stats)]
    sigma_ref = _most_common([key[3] for key in stats])
    predicate_ref = _most_common(
        [key[1] for key in stats], preferred="P4" if "P4" in predicate_values else None
    )
    selectivity_enough = len(sigma_values) >= 2

    plt = common.setup_matplotlib()
    directory = common.out_dir(args.out)

    rows_out = []

    for layout in layouts:
        for (layout_key, predicate, approach, sigma), entry in sorted(
            stats.items(), key=lambda item: (
                common.sort_key(item[0][1]),
                common.sort_key(item[0][2]),
                common.sort_key(item[0][3]),
            )
        ):
            if layout_key != layout or sigma_ref is None or sigma != sigma_ref:
                continue
            rows_out.append({
                "figure": "exp2",
                "record_type": "group",
                "layout": layout,
                "predicate": predicate,
                "approach": approach,
                "sigma": sigma,
                "n_runs": entry["n"],
                "median_ms": f"{common.to_ms(entry['median']):.6g}",
                "min_ms": f"{common.to_ms(entry['min']):.6g}",
                "max_ms": f"{common.to_ms(entry['max']):.6g}",
                "n_cand_median": (
                    "" if entry.get("n_cand_median") is None
                    else f"{entry['n_cand_median']:.6g}"
                ),
                "provisional": int(provisional),
                "note": f"predicate panel; sigma fixed at {sigma_ref}",
            })

    if not selectivity_enough:
        rows_out.append({
            "figure": "exp2",
            "record_type": "group",
            "provisional": int(provisional),
            "note": "NOT-ENOUGH-DATA: fewer than 2 distinct selectivity values, "
                    "selectivity panel not plotted",
        })

    fit_scopes = [("all", None)] + [(layout, layout) for layout in layouts]
    for scope, layout_filter in fit_scopes:
        fit = fit_costs(stats, layout_filter)
        note = ""
        if fit["r2"] is None:
            note = "NOT-ENOUGH-DATA: model not identifiable or fewer than 2 points"
        elif fit["t_bps_ns"] is not None and fit["t_bps_ns"] < 0:
            note = ("WARNING: negative T_BPS is unphysical; likely collinear/noisy "
                    "smoke points, report as not identified")
        rows_out.append({
            "figure": "exp2",
            "record_type": "fit",
            "scope": scope,
            "n_points": fit["points"],
            "t_bps_ns_per_block": (
                "" if fit["t_bps_ns"] is None else f"{fit['t_bps_ns']:.6g}"
            ),
            "t_rps_ns_per_record": (
                "" if fit["t_rps_ns"] is None else f"{fit['t_rps_ns']:.6g}"
            ),
            "r2": "" if fit["r2"] is None else f"{fit['r2']:.6f}",
            "provisional": int(provisional),
            "note": note or "time = G*T_BPS + N_Q*T_RPS, no intercept; "
                            "trad_scan excluded (plaintext per-record cost)",
        })

    cols = 2 if selectivity_enough else 1
    nrows = 2 if selectivity_enough else 1
    fig, axes = plt.subplots(nrows, 2, figsize=(8.0, 2.9 * nrows), squeeze=False)

    for column, layout in enumerate(layouts[:2]):
        ax = axes[0][column]
        for approach in APPROACH_ORDER:
            entries = []
            for (layout_key, predicate, approach_key, sigma), entry in stats.items():
                if layout_key != layout or approach_key != approach:
                    continue
                if sigma_ref is not None and sigma != sigma_ref:
                    continue
                entries.append((predicate, entry))
            entries = [(pred, entry) for pred, entry in entries if pred in PREDICATE_ORDER]
            entries.sort(key=lambda item: PREDICATE_ORDER.index(item[0]))
            if not entries:
                continue
            xs = [PREDICATE_ORDER.index(pred) + 1 for pred, _ in entries]
            medians = [common.to_ms(entry["median"]) for _, entry in entries]
            lows = [common.to_ms(entry["min"]) for _, entry in entries]
            highs = [common.to_ms(entry["max"]) for _, entry in entries]
            common.band_plot(
                ax, xs, medians, lows, highs, approach,
                _color(approach), _marker(approach),
            )
        ax.set_yscale("log")
        common.log_axes(ax, which="y")
        ax.set_xticks(range(1, 5))
        ax.set_xticklabels(PREDICATE_ORDER)
        ax.set_xlim(0.6, 4.4)
        ax.set_xlabel("Predicate")
        ax.set_ylabel(f"Query time ({common.TIME_UNIT})")
        ax.set_title(f"layout: {layout}", fontsize=8)

    if selectivity_enough:
        for column, layout in enumerate(layouts[:2]):
            ax = axes[1][column]
            for approach in APPROACH_ORDER:
                entries = []
                for (layout_key, predicate, approach_key, sigma), entry in stats.items():
                    if layout_key != layout or approach_key != approach:
                        continue
                    if predicate_ref is not None and predicate != predicate_ref:
                        continue
                    if sigma is None or sigma <= 0:
                        continue
                    entries.append((sigma, entry))
                entries.sort(key=lambda item: item[0])
                if not entries:
                    continue
                xs = [sigma * 100.0 for sigma, _ in entries]
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
            ax.set_xlabel("Selectivity σ (% of N)")
            ax.set_ylabel(f"Query time ({common.TIME_UNIT})")
            ax.set_title(f"layout: {layout}, predicate: {predicate_ref}", fontsize=8)
    else:
        fig.text(
            0.99, 0.02, "selectivity: NOT-ENOUGH-DATA (<2 distinct σ values)",
            ha="right", va="bottom", fontsize=6.5, color="0.35",
        )

    all_fit = fit_costs(stats)
    handles, labels = axes[0][0].get_legend_handles_labels()
    if handles:
        fig.legend(
            handles, labels, loc="upper center", ncol=3, frameon=False,
            bbox_to_anchor=(0.5, 0.925),
        )
    if all_fit["r2"] is not None:
        warning = (
            " (negative T_BPS: unidentified)"
            if all_fit["t_bps_ns"] is not None and all_fit["t_bps_ns"] < 0 else ""
        )
        fig.text(
            0.01, 0.055,
            f"cost fit: T_BPS={all_fit['t_bps_ns']:.3g} ns/block, "
            f"T_RPS={all_fit['t_rps_ns']:.3g} ns/record, "
            f"R²={all_fit['r2']:.3f}{warning}",
            fontsize=6.5, color="0.35",
        )
    fig.tight_layout(rect=(0, 0.09, 1, 0.87))

    pdf = common.finish(fig, os.path.join(directory, "fig_exp2.pdf"), provisional, sources[0])
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp2.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("label: PROVISIONAL (smoke data)")


if __name__ == "__main__":
    main()
