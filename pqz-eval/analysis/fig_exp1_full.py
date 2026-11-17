"""Figure exp1 (full data): PQZ query time versus N for the two series.

Every plotted value is the median of timed rows; the band is the observed
min-max.  Warm-up rows are dropped.  The log-log slope is written to the CSV
only, not drawn on the figure.
"""

from __future__ import annotations

import argparse
import os

from matplotlib.ticker import LogLocator

import common

SERIES_ORDER = ["sigma1pct", "fixed_nq1000"]
DISPLAY = {"sigma1pct": "1% selectivity", "fixed_nq1000": "fixed $n_Q$ = 1000"}
FIELDS = [
    "figure", "series", "n", "n_runs", "median_ms", "min_ms", "max_ms",
    "slope", "intercept", "r2", "points_fit", "provisional", "note",
]


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=None, help="exp1 raw CSV")
    parser.add_argument("--out", default=None, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3,
                        help="minimum timed runs per group")
    return parser.parse_args()


def fmt(value):
    return f"{value:.10g}"


def fmt_n(value):
    return f"{value:.0e}".replace("e+0", "e").replace("e+", "e")


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
    path = args.csv or common.default_csv("results/full-1/exp1/exp1.csv")
    rows, meta = common.load_csv(
        path,
        required=("series", "n", "sigma", "time_ns", "warmup"),
        min_runs=args.min_runs,
        group_keys=("series", "n"),
    )

    series_present = {row.get("series") for row in rows}
    missing = [series for series in SERIES_ORDER if series not in series_present]
    if missing:
        raise SystemExit(f"refusing: exp1 series missing from input: {missing}")

    stats = common.group_stats(rows, ("series", "n"))
    provisional = any(entry["n"] < 10 for entry in stats.values())

    rows_out = []
    for series in SERIES_ORDER:
        entries = sorted(
            ((key[1], value) for key, value in stats.items() if key[0] == series),
            key=lambda item: item[0],
        )
        xs = [n_value for n_value, _ in entries]
        medians = [common.to_ms(entry["median"]) for _, entry in entries]
        fit = common.loglog_fit(xs, medians)
        note = ""
        if fit["slope"] is None:
            note = "NOT-ENOUGH-DATA: fewer than 2 distinct N values"
        elif fit["points"] == 2:
            note = "slope from 2 points only"
        for (n_value, entry), median in zip(entries, medians):
            rows_out.append({
                "figure": "exp1_full",
                "series": series,
                "n": int(n_value) if isinstance(n_value, float) else n_value,
                "n_runs": entry["n"],
                "median_ms": fmt(median),
                "min_ms": fmt(common.to_ms(entry["min"])),
                "max_ms": fmt(common.to_ms(entry["max"])),
                "slope": "" if fit["slope"] is None else fmt(fit["slope"]),
                "intercept": (
                    "" if fit["intercept"] is None else fmt(fit["intercept"])
                ),
                "r2": "" if fit["r2"] is None else fmt(fit["r2"]),
                "points_fit": fit["points"],
                "provisional": int(provisional),
                "note": note,
            })

    # The fixed-N_Q series keeps N_Q = 1000, so sigma = 1000/N.  Read the
    # smallest-N sigma from the data instead of typing the percentage.
    fixed_rows = [row for row in rows if row.get("series") == "fixed_nq1000"]
    if not fixed_rows:
        raise SystemExit("refusing: no fixed_nq1000 rows")
    n_small = min(row["n"] for row in fixed_rows)
    sigma_small = [
        float(row["sigma"]) for row in fixed_rows
        if float(row["n"]) == float(n_small) and row.get("sigma") is not None
    ]
    sigma_pct = (sum(sigma_small) / len(sigma_small)) * 100.0
    note_fixed = (
        f"fixed_nq1000 = {sigma_pct:g}% at N={fmt_n(n_small)}"
    )

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 2.9))

    for index, series in enumerate(SERIES_ORDER):
        entries = sorted(
            ((key[1], value) for key, value in stats.items() if key[0] == series),
            key=lambda item: item[0],
        )
        xs = [n_value for n_value, _ in entries]
        medians = [common.to_ms(entry["median"]) for _, entry in entries]
        lows = [common.to_ms(entry["min"]) for _, entry in entries]
        highs = [common.to_ms(entry["max"]) for _, entry in entries]
        common.band_plot(
            ax, xs, medians, lows, highs, DISPLAY[series],
            common.PALETTE[index], common.MARKERS[index],
        )

    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    log_ticks(ax)
    ax.set_xlabel("N (records)")
    ax.set_ylabel("Query time (ms)")
    ax.legend(frameon=False, loc="upper left")
    ax.text(
        0.98, 0.03,
        f"fixed $n_Q$ = 1000 is {sigma_pct:g}% selectivity at N={fmt_n(n_small)}",
        transform=ax.transAxes, fontsize=5.8,
        color="0.35", ha="right", va="bottom",
    )

    fig.tight_layout()
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp1_full.pdf"), provisional, path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp1_full.png"), dpi=200)
    plt.close(fig)

    csv_path = os.path.join(directory, "fig_exp1_full.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (a group has fewer than 10 timed runs)")


if __name__ == "__main__":
    main()
