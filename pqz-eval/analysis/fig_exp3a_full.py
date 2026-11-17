"""Figure exp3a (full data): SUM time versus selected count.

Every plotted value is the median of timed rows; the band is the observed
min-max.  The pqz log-log slope is written to the CSV only.  full_he has ten
timed runs per point.  The second full_he sweep (exp3b SUM at 1%, a different
run with the same configuration) is added as one hollow marker.
"""

from __future__ import annotations

import argparse
import os

from matplotlib.ticker import LogLocator

import common

APPROACH_ORDER = ["plain_agg", "full_he", "pqz"]
DISPLAY = {"plain_agg": "Plaintext aggregation", "full_he": "Full-Domain HE", "pqz": "PQZ-Audit"}
FIELDS = [
    "figure", "record_type", "agg", "approach", "n_sel", "n_runs",
    "median_ms", "min_ms", "max_ms", "slope", "r2", "points_fit",
    "provisional", "note",
]


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=None, help="exp3a raw CSV")
    parser.add_argument("--second", default=None,
                        help="exp3b raw CSV for the second full_he sweep")
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
    path = args.csv or common.default_csv(
        "results/full-1/exp3a/exp3a.csv"
    )
    second_path = args.second or common.default_csv(
        "results/full-2/exp3b/exp3b.csv"
    )

    rows, meta = common.load_csv(
        path,
        required=("agg", "approach", "n_sel", "sigma", "n", "time_ns",
                  "warmup"),
        min_runs=args.min_runs,
        group_keys=("agg", "approach", "n_sel"),
    )
    rows = [row for row in rows if row.get("agg") == "SUM"]
    if not rows:
        raise SystemExit("refusing: no exp3a SUM rows")

    stats = common.group_stats(rows, ("approach", "n_sel"))
    provisional = any(entry["n"] < 10 for entry in stats.values())

    pqz_entries = sorted(
        ((key[1], value) for key, value in stats.items() if key[0] == "pqz"),
        key=lambda item: item[0],
    )
    pqz_xs = [n_sel for n_sel, _ in pqz_entries]
    pqz_ys = [common.to_ms(entry["median"]) for _, entry in pqz_entries]
    pqz_fit = common.loglog_fit(pqz_xs, pqz_ys)

    second_rows, _ = common.load_csv(
        second_path,
        required=("agg", "approach", "sigma", "n", "time_ns", "warmup"),
        min_runs=args.min_runs,
    )
    second_rows = [
        row for row in second_rows
        if row.get("agg") == "SUM"
        and abs(float(row.get("sigma")) - 0.01) < 1e-12
        and row.get("approach") == "full_he"
    ]
    if not second_rows:
        raise SystemExit("refusing: no exp3b SUM full_he rows at sigma=1%")
    second_stats = common.group_stats(second_rows, ("approach",))
    second_entry = second_stats.get(("full_he",))
    if second_entry is None:
        raise SystemExit("refusing: second full_he sweep is missing")
    second_n_sel = float(second_rows[0]["sigma"]) * float(second_rows[0]["n"])

    rows_out = []
    for approach in APPROACH_ORDER:
        entries = sorted(
            ((key[1], value) for key, value in stats.items()
             if key[0] == approach),
            key=lambda item: item[0],
        )
        if not entries:
            continue
        for n_sel, entry in entries:
            is_pqz = approach == "pqz"
            rows_out.append({
                "figure": "exp3a_full",
                "record_type": "group",
                "agg": "SUM",
                "approach": approach,
                "n_sel": n_sel,
                "n_runs": entry["n"],
                "median_ms": fmt(common.to_ms(entry["median"])),
                "min_ms": fmt(common.to_ms(entry["min"])),
                "max_ms": fmt(common.to_ms(entry["max"])),
                "slope": (
                    "" if not is_pqz or pqz_fit["slope"] is None
                    else fmt(pqz_fit["slope"])
                ),
                "r2": (
                    "" if not is_pqz or pqz_fit["r2"] is None
                    else fmt(pqz_fit["r2"])
                ),
                "points_fit": pqz_fit["points"] if is_pqz else "",
                "provisional": int(provisional),
                "note": "median of timed rows",
            })
    rows_out.append({
        "figure": "exp3a_full",
        "record_type": "second_sweep",
        "agg": "SUM",
        "approach": "full_he",
        "n_sel": fmt(second_n_sel),
        "n_runs": second_entry["n"],
        "median_ms": fmt(common.to_ms(second_entry["median"])),
        "min_ms": fmt(common.to_ms(second_entry["min"])),
        "max_ms": fmt(common.to_ms(second_entry["max"])),
        "provisional": int(provisional),
        "note": "second sweep, same config (exp3b SUM at sigma=1%)",
    })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 3.3))

    for index, approach in enumerate(APPROACH_ORDER):
        entries = sorted(
            ((key[1], value) for key, value in stats.items()
             if key[0] == approach),
            key=lambda item: item[0],
        )
        if not entries:
            continue
        xs = [n_sel for n_sel, _ in entries]
        medians = [common.to_ms(entry["median"]) for _, entry in entries]
        lows = [common.to_ms(entry["min"]) for _, entry in entries]
        highs = [common.to_ms(entry["max"]) for _, entry in entries]
        counts = {entry["n"] for _, entry in entries}
        label = DISPLAY[approach]
        if len(counts) == 1:
            label = f"{DISPLAY[approach]} ({counts.pop()} runs)"
        common.band_plot(
            ax, xs, medians, lows, highs, label,
            common.PALETTE[index], common.MARKERS[index],
        )

    ax.plot(
        [second_n_sel], [common.to_ms(second_entry["median"])],
        linestyle="none", marker="o", markersize=6, markerfacecolor="none",
        markeredgecolor=common.PALETTE[1], markeredgewidth=1.2,
        label="second sweep, same config",
    )

    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    log_ticks(ax, subs=(1.0,))
    ax.set_xlabel("selected records $n_Q$ = σ·N")
    ax.set_ylabel("SUM time (ms)")
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", ncol=2, frameon=False,
        bbox_to_anchor=(0.5, 1.0),
    )
    fig.tight_layout(rect=(0, 0.01, 1, 0.88))
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp3a_full.pdf"), provisional, path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp3a_full.png"), dpi=200)
    plt.close(fig)

    csv_path = os.path.join(directory, "fig_exp3a_full.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    print(f"pqz log-log slope={pqz_fit['slope']} r2={pqz_fit['r2']}")
    print(
        f"second sweep: n_sel={second_n_sel:g} "
        f"median={common.to_ms(second_entry['median']):.6g} ms"
    )
    if provisional:
        print("provisional=True (a group has fewer than 10 timed runs)")


if __name__ == "__main__":
    main()
