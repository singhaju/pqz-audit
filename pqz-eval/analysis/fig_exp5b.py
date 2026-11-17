"""Figure exp5b: governance operation latency (routine access, authorize, consume).

Bars are medians of timed runs with min-max whiskers.  The paper says
"routine canonical-state access", so the routine bar is routine_read; the
routine_anchor (write) row is measured too and is listed in the CSV but not
plotted.
"""

from __future__ import annotations

import argparse
import os

import common

OPS = ("routine_read", "authorize", "consume")
OP_LABEL = {
    "routine_read": "routine\naccess",
    "authorize": "privileged\nauthorize",
    "consume": "privileged\nconsume",
}
FIELDS = [
    "figure", "metric", "series", "x", "n_runs", "median", "min", "max",
    "unit", "status", "provisional", "note",
]


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=None,
                        help="exp5b governance CSV")
    parser.add_argument("--out", default=None, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3,
                        help="minimum timed runs per group")
    return parser.parse_args()


def fmt(value):
    return f"{value:.10g}"


def main():
    args = parse_args()
    path = args.csv or os.path.join(
        os.path.dirname(common.BASE_DIR),
        "pqz-ledger", "results", "full-1", "with-tx-auth",
        "exp5b_governance.csv",
    )
    rows, meta = common.load_csv(
        path,
        required=("op", "kind", "op_latency_ns"),
        min_runs=args.min_runs,
    )
    rows = [row for row in rows if row.get("kind") == "timed"]
    if not rows:
        raise SystemExit("refusing: no timed governance rows")

    provisional = meta["provisional"]
    stats = common.group_stats(rows, ("op",), value="op_latency_ns")
    rows_out = []
    for op in OPS:
        entry = stats.get((op,))
        if entry is None:
            rows_out.append({
                "figure": "exp5b", "metric": "op_latency", "series": op,
                "x": op, "n_runs": 0, "median": "", "min": "", "max": "",
                "unit": "ms", "status": "MISSING",
                "provisional": int(provisional),
                "note": "no timed rows for this operation",
            })
            continue
        if entry["n"] < args.min_runs:
            raise SystemExit(
                f"refusing: op={op} has {entry['n']} timed runs"
            )
        rows_out.append({
            "figure": "exp5b", "metric": "op_latency", "series": op,
            "x": op, "n_runs": entry["n"],
            "median": fmt(entry["median"] / 1e6),
            "min": fmt(entry["min"] / 1e6),
            "max": fmt(entry["max"] / 1e6),
            "unit": "ms", "status": "plotted",
            "provisional": int(provisional),
            "note": "median of timed op_latency_ns; routine bar uses the read "
                    "path named by the paper",
        })
    anchor = stats.get(("routine_anchor",))
    if anchor is not None:
        rows_out.append({
            "figure": "exp5b", "metric": "op_latency", "series": "routine_anchor",
            "x": "routine_anchor", "n_runs": anchor["n"],
            "median": fmt(anchor["median"] / 1e6),
            "min": fmt(anchor["min"] / 1e6),
            "max": fmt(anchor["max"] / 1e6),
            "unit": "ms", "status": "measured-not-plotted",
            "provisional": int(provisional),
            "note": "routine anchor (write) measured; paper asks for routine "
                    "canonical-state access, so the read path is plotted",
        })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 2.5))
    plotted = [op for op in OPS if (op,) in stats]
    positions = list(range(len(plotted)))
    medians = [stats[(op,)]["median"] / 1e6 for op in plotted]
    lower = [medians[i] - stats[(op,)]["min"] / 1e6
             for i, op in enumerate(plotted)]
    upper = [stats[(op,)]["max"] / 1e6 - medians[i]
             for i, op in enumerate(plotted)]
    ax.bar(
        positions, medians, color=[common.PALETTE[i] for i in positions],
        width=0.6, yerr=[lower, upper], capsize=3,
        error_kw={"elinewidth": 0.8, "ecolor": "0.3"},
    )
    ax.set_xticks(positions)
    ax.set_xticklabels([OP_LABEL.get(op, op) for op in plotted])
    ax.set_ylabel("latency (ms)")
    for position, median in zip(positions, medians):
        ax.text(position, median * 1.06, f"{median:.2f}",
                ha="center", va="bottom", fontsize=6)
    ax.set_ylim(0, max(
        stats[(op,)]["max"] / 1e6 for op in plotted
    ) * 1.2)
    fig.text(
        0.01, 0.03,
        "Bars: median; whiskers: min-max. Routine bar = routine_read "
        "(canonical-state access).",
        fontsize=5.3, color="0.35",
    )
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp5b.pdf"), provisional, path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp5b.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp5b.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (common.load_csv rule: a group has n < 10000)")


if __name__ == "__main__":
    main()
