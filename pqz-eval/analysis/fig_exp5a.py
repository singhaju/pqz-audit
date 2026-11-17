"""Figure exp5a: ledger latency and throughput versus q.

Only measured columns are used (lat_p50_ns, throughput_tx_per_s); the
derived_* columns are computed estimates and are not plotted.  The ledger is an
in-process simulation, not a network or consensus measurement.
"""

from __future__ import annotations

import argparse
import os

from matplotlib.ticker import LogLocator

import common

SYSTEM_ORDER = ("pqz", "per_record_baseline")
SYSTEM_LABEL = {
    "pqz": "PQZ-Audit (authorize)",
    "per_record_baseline": "per-record baseline (commit_record)",
}
FIELDS = [
    "figure", "metric", "series", "x", "n_runs", "median", "min", "max",
    "unit", "status", "provisional", "note",
]
NOTE = "in-process simulation; measured columns only, derived_* not used"


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=None,
                        help="exp5a latency/throughput CSV")
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
    path = args.csv or os.path.join(
        os.path.dirname(common.BASE_DIR),
        "pqz-ledger", "results", "full-1", "with-tx-auth",
        "exp5a_latency_throughput.csv",
    )
    rows, meta = common.load_csv(
        path,
        required=("system", "workload", "q", "kind", "lat_p50_ns",
                  "throughput_tx_per_s"),
        min_runs=args.min_runs,
    )
    rows = [row for row in rows if row.get("kind") == "timed"]
    rows = [row for row in rows if row.get("system") in SYSTEM_ORDER]
    if not rows:
        raise SystemExit("refusing: no timed ledger rows for the known systems")

    provisional = meta["provisional"]
    latency = common.group_stats(rows, ("system", "q"), value="lat_p50_ns")
    throughput = common.group_stats(
        rows, ("system", "q"), value="throughput_tx_per_s"
    )
    qs = sorted({key[1] for key in latency if key[1] is not None})
    rows_out = []
    for system in SYSTEM_ORDER:
        for q in qs:
            entry = latency.get((system, q))
            if entry is None:
                rows_out.append({
                    "figure": "exp5a", "metric": "lat_p50", "series": system,
                    "x": q, "n_runs": 0, "median": "", "min": "", "max": "",
                    "unit": "ms", "status": "MISSING",
                    "provisional": int(provisional),
                    "note": f"no timed rows for system={system}, q={q}",
                })
                continue
            if entry["n"] < args.min_runs:
                raise SystemExit(
                    f"refusing: {system} q={q} has {entry['n']} timed runs"
                )
            rows_out.append({
                "figure": "exp5a", "metric": "lat_p50", "series": system,
                "x": q, "n_runs": entry["n"],
                "median": fmt(entry["median"] / 1e6),
                "min": fmt(entry["min"] / 1e6),
                "max": fmt(entry["max"] / 1e6),
                "unit": "ms", "status": "plotted",
                "provisional": int(provisional), "note": NOTE,
            })
            tp = throughput[(system, q)]
            rows_out.append({
                "figure": "exp5a", "metric": "throughput", "series": system,
                "x": q, "n_runs": tp["n"],
                "median": fmt(tp["median"]), "min": fmt(tp["min"]),
                "max": fmt(tp["max"]), "unit": "tx/s", "status": "plotted",
                "provisional": int(provisional), "note": NOTE,
            })
    for system in SYSTEM_ORDER:
        if not any(key[0] == system for key in latency):
            rows_out.append({
                "figure": "exp5a", "metric": "lat_p50", "series": system,
                "x": "", "n_runs": 0, "median": "", "min": "", "max": "",
                "unit": "ms", "status": "MISSING",
                "provisional": int(provisional),
                "note": f"system={system} is absent from the raw file",
            })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, axes = plt.subplots(2, 1, figsize=(3.4, 3.3), sharex=True)
    for index, system in enumerate(SYSTEM_ORDER):
        entries = sorted(
            ((q, latency[(system, q)]) for q in qs if (system, q) in latency),
            key=lambda item: item[0],
        )
        if not entries:
            continue
        xs = [q for q, _ in entries]
        common.band_plot(
            axes[0], xs,
            [entry["median"] / 1e6 for _, entry in entries],
            [entry["min"] / 1e6 for _, entry in entries],
            [entry["max"] / 1e6 for _, entry in entries],
            SYSTEM_LABEL[system], common.PALETTE[index],
            common.MARKERS[index],
        )
        tp_entries = sorted(
            ((q, throughput[(system, q)]) for q in qs
             if (system, q) in throughput),
            key=lambda item: item[0],
        )
        common.band_plot(
            axes[1], [q for q, _ in tp_entries],
            [entry["median"] for _, entry in tp_entries],
            [entry["min"] for _, entry in tp_entries],
            [entry["max"] for _, entry in tp_entries],
            SYSTEM_LABEL[system], common.PALETTE[index],
            common.MARKERS[index],
        )
    for ax in axes:
        ax.set_xscale("log")
        ax.set_yscale("log")
        common.log_axes(ax)
        log_ticks(ax)
    axes[0].set_ylabel("latency p50 (ms)")
    axes[1].set_ylabel("throughput (tx/s)")
    axes[1].set_xlabel("audit requests q")
    axes[0].legend(frameon=False, loc="best")
    fig.text(
        0.01, 0.025,
        "In-process simulation, no network or consensus.",
        fontsize=5.3, color="0.35",
    )
    fig.tight_layout(rect=(0, 0.07, 1, 1))
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp5a.pdf"), provisional, path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp5a.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp5a.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (common.load_csv rule: a group has n < 10000)")


if __name__ == "__main__":
    main()
