"""Figure for exp1: query time versus N for the two PQZ series."""

from __future__ import annotations

import argparse
import os
import sys

import common


SERIES_ORDER = ["sigma1pct", "fixed_nq1000"]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="*", help="exp1 CSV file(s)")
    parser.add_argument("--out", default=None, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3,
                        help="minimum timed runs per (series, n) group")
    return parser.parse_args()


def main():
    args = parse_args()
    paths = args.csv or [common.default_csv("smoke/s1/exp1.csv")]

    all_rows = []
    provisional = False
    sources = []
    for path in paths:
        rows, meta = common.load_csv(
            path,
            required=("series", "n", "time_ns", "warmup"),
            min_runs=args.min_runs,
            group_keys=("series", "n"),
        )
        all_rows.extend(rows)
        provisional = provisional or meta["provisional"]
        sources.append(path)

    series_present = {row.get("series") for row in all_rows}
    missing_series = [s for s in SERIES_ORDER if s not in series_present]
    if missing_series:
        sys.exit(f"refusing to plot: exp1 series missing from input: {missing_series}")

    stats = common.group_stats(all_rows, ("series", "n"))

    plt = common.setup_matplotlib()
    directory = common.out_dir(args.out)

    has_ncand = any(row.get("n_cand") not in (None, "") for row in all_rows)
    panels = 2 if has_ncand else 1
    fig, axes = plt.subplots(1, panels, figsize=(4.0 * panels, 3.0), squeeze=False)
    ax_time = axes[0][0]
    ax_cand = axes[0][1] if has_ncand else None

    out_rows = []
    slope_missing = False
    for index, series in enumerate(SERIES_ORDER):
        entries = sorted(
            ((key[1], value) for key, value in stats.items() if key[0] == series),
            key=lambda item: common.sort_key(item[0]),
        )
        if not entries:
            continue
        color = common.PALETTE[index % len(common.PALETTE)]
        marker = common.MARKERS[index % len(common.MARKERS)]
        xs = [entry[0] for entry in entries]
        medians = [common.to_ms(entry[1]["median"]) for entry in entries]
        lows = [common.to_ms(entry[1]["min"]) for entry in entries]
        highs = [common.to_ms(entry[1]["max"]) for entry in entries]
        common.band_plot(ax_time, xs, medians, lows, highs, series, color, marker)

        fit = common.loglog_fit(xs, medians)
        note = ""
        if fit["slope"] is None:
            note = "NOT-ENOUGH-DATA: fewer than 2 distinct N values"
            slope_missing = True
        elif fit["points"] == 2:
            note = "slope from 2 points only"
        for (n_value, entry), median in zip(entries, medians):
            out_rows.append({
                "figure": "exp1",
                "series": series,
                "n": n_value,
                "n_runs": entry["n"],
                "median_ms": f"{median:.6g}",
                "min_ms": f"{common.to_ms(entry['min']):.6g}",
                "max_ms": f"{common.to_ms(entry['max']):.6g}",
                "slope": "" if fit["slope"] is None else f"{fit['slope']:.6f}",
                "intercept": "" if fit["intercept"] is None else f"{fit['intercept']:.6f}",
                "r2": "" if fit["r2"] is None else f"{fit['r2']:.6f}",
                "points_fit": fit["points"],
                "provisional": int(provisional),
                "note": note,
            })

    ax_time.set_xscale("log")
    ax_time.set_yscale("log")
    common.log_axes(ax_time)
    ax_time.set_xlabel("N (records)")
    ax_time.set_ylabel(f"Query time ({common.TIME_UNIT})")
    ax_time.legend(frameon=False)
    if slope_missing:
        ax_time.text(
            0.98, 0.03, "slope: NOT-ENOUGH-DATA\n(<2 N values per series)",
            transform=ax_time.transAxes, fontsize=6.5, color="0.35",
            ha="right", va="bottom",
        )

    if has_ncand:
        cand_stats = common.group_stats(all_rows, ("series", "n"), value="n_cand")
        for index, series in enumerate(SERIES_ORDER):
            entries = sorted(
                ((key[1], value) for key, value in cand_stats.items() if key[0] == series),
                key=lambda item: common.sort_key(item[0]),
            )
            if not entries:
                continue
            color = common.PALETTE[index % len(common.PALETTE)]
            marker = common.MARKERS[index % len(common.MARKERS)]
            xs = [entry[0] for entry in entries]
            medians = [entry[1]["median"] / entry[0] for entry in entries]
            lows = [entry[1]["min"] / entry[0] for entry in entries]
            highs = [entry[1]["max"] / entry[0] for entry in entries]
            common.band_plot(ax_cand, xs, medians, lows, highs, series, color, marker)
        ax_cand.set_xscale("log")
        common.log_axes(ax_cand, which="x")
        ax_cand.set_xlabel("N (records)")
        ax_cand.set_ylabel("n_cand / N (fraction)")
        ax_cand.legend(frameon=False)
    else:
        for series in SERIES_ORDER:
            out_rows.append({
                "figure": "exp1",
                "series": series,
                "n": "",
                "n_runs": "",
                "median_ms": "",
                "min_ms": "",
                "max_ms": "",
                "slope": "",
                "intercept": "",
                "r2": "",
                "points_fit": 0,
                "provisional": int(provisional),
                "note": "NOT-ENOUGH-DATA: n_cand column absent, n_cand/N not plotted",
            })

    pdf = common.finish(fig, os.path.join(directory, "fig_exp1.pdf"), provisional, sources[0])
    plt.close(fig)

    csv_path = os.path.join(directory, "fig_exp1.csv")
    common.save_csv(csv_path, list(out_rows[0].keys()), out_rows)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("label: PROVISIONAL (smoke data)")


if __name__ == "__main__":
    main()
