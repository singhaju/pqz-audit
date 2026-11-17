"""Figure exp6b (w18 copy of fig_exp6b.py): relative overhead O_j of each ablation.

Inputs from the w18 folder (--results, env W18_RESULTS, else bench/pqz-eval/results/cloud-w18):
  <results>/exp2a/exp2a.csv, <results>/<--exp3b-job>/exp3b.csv (default exp3b-r1 = primary run),
  <results>/exp3a/exp3a.csv (second Full-Domain HE sweep, same cell), <results>/proofbench-ablation/raw.csv.
Writes fig_exp6b_w18.{pdf,png,csv} into --out, env W18_OUT, else journal2/figures/results-w18/.
Differences against fig_exp6b.py: paths from the w18 folder; the exp3a rows are also filtered to
agg == SUM (the file has only SUM, so no value changes); a missing RC cell is a refusal (exit).

O_j = (T_j - T_Full) / T_Full * 100, computed from the same medians as
fig_exp6a.  The whisker is the range obtained from the component min/max
values, not a confidence interval.
"""

from __future__ import annotations

import argparse
import os
import sys

from matplotlib.ticker import LogLocator

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I drops the script folder
import common  # noqa: E402
import w18_common as WC  # noqa: E402

DEFAULT_OUT = os.path.join(WC.ROOT, "journal2", "figures", "results-w18")

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
    parser.add_argument("--results", default=None, help="results folder (default cloud-w18)")
    parser.add_argument("--exp3b-job", default="exp3b-r1", help="exp3b-r1 (primary) or exp3b-r2 (repeat)")
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


def require(entry, minimum, label):
    if entry is None:
        raise SystemExit(f"refusing: missing group {label}")
    if entry["n"] < minimum:
        raise SystemExit(
            f"refusing: {label} has {entry['n']} timed runs (< {minimum})"
        )


def relative(tj, tf):
    return (tj - tf) / tf * 100.0


def relative_range(tj, tf):
    values = [
        relative(tj["min"], tf["min"]), relative(tj["min"], tf["max"]),
        relative(tj["max"], tf["min"]), relative(tj["max"], tf["max"]),
    ]
    return min(values), max(values)


def main():
    args = parse_args()
    need = [("exp2a", "exp2a.csv"), (args.exp3b_job, "exp3b.csv"), ("exp3a", "exp3a.csv"),
            ("proofbench-ablation", "raw.csv")]
    res = WC.Results(WC.results_dir(args.results))
    res.preflight(need)
    for job, fname in need:
        res.rd(job, fname)  # refuses on rows with note FAILED
    exp2a_path = res.p("exp2a", "exp2a.csv")
    exp3b_path = res.p(args.exp3b_job, "exp3b.csv")
    ablation_path = res.p("proofbench-ablation", "raw.csv")
    args.out = WC.out_dir(args.out, DEFAULT_OUT)

    exp2a_rows, exp2a_meta = common.load_csv(
        exp2a_path,
        required=("n", "sigma", "layout", "predicate", "approach", "time_ns",
                  "warmup"),
        min_runs=args.min_runs,
    )
    exp2a_rows = [
        row for row in exp2a_rows
        if row.get("n") == 1_000_000
        and abs(float(row.get("sigma") or 0.0) - 0.01) < 1e-12
        and row.get("layout") == "clustered"
        and row.get("predicate") == "P4"
        and row.get("approach") in ("pqz", "prot_full_scan")
    ]
    query = common.group_stats(exp2a_rows, ("approach",), value="time_ns")

    exp3b_rows, exp3b_meta = common.load_csv(
        exp3b_path,
        required=("n", "sigma", "layout", "predicate", "agg", "approach",
                  "time_ns", "warmup"),
        min_runs=args.min_runs,
    )
    exp3b_rows = [
        row for row in exp3b_rows
        if row.get("n") == 1_000_000
        and abs(float(row.get("sigma") or 0.0) - 0.01) < 1e-12
        and row.get("layout") == "clustered"
        and row.get("predicate") == "P4"
        and row.get("agg") == "SUM"
        and row.get("approach") in ("pqz", "full_he")
    ]
    aggregation = common.group_stats(exp3b_rows, ("approach",), value="time_ns")

    # second Full-Domain HE sweep (exp3a SUM at 1%): same configuration, measured in
    # a different run; shown next to exp3b because the two medians differ by 2x
    exp3a_path = res.p("exp3a", "exp3a.csv")
    exp3a_rows, _ = common.load_csv(
        exp3a_path,
        required=("n", "sigma", "layout", "predicate", "agg", "approach", "time_ns",
                  "warmup"),
        min_runs=args.min_runs,
    )
    exp3a_rows = [
        row for row in exp3a_rows
        if row.get("n") == 1_000_000
        and row.get("agg") == "SUM"
        and abs(float(row.get("sigma") or 0.0) - 0.01) < 1e-12
        and row.get("layout") == "clustered"
        and row.get("predicate") == "P4"
        and row.get("approach") in ("pqz", "full_he")
    ]
    aggregation_a = common.group_stats(exp3a_rows, ("approach",), value="time_ns")

    abl_rows, abl_meta = common.load_csv(
        ablation_path,
        required=("mode", "g_blocks", "prove_s", "warmup"),
        min_runs=args.min_runs,
    )
    abl_rows = [row for row in abl_rows
                if row.get("mode") in ("batched", "per_block")]
    abl = common.group_stats(abl_rows, ("mode", "g_blocks"), value="prove_s")

    for key, label in (
        (("pqz",), "exp2a pqz clustered P4"),
        (("prot_full_scan",), "exp2a prot_full_scan clustered P4"),
    ):
        require(query.get(key), args.min_runs, label)
    for key in (("pqz",), ("full_he",)):
        require(aggregation.get(key), args.min_runs, f"{args.exp3b_job} {key[0]} SUM")
        require(aggregation_a.get(key), args.min_runs, f"exp3a {key[0]} SUM")

    provisional = (
        exp2a_meta["provisional"] or exp3b_meta["provisional"]
        or abl_meta["provisional"]
    )
    q_pqz = query[("pqz",)]
    q_full = query[("prot_full_scan",)]
    a_pqz = aggregation[("pqz",)]
    a_he = aggregation[("full_he",)]

    rows_out = []
    single = [
        ("w/o Block Filtering (query only)", q_full, q_pqz,
         "query: prot_full_scan vs pqz, clustered layout"),
        ("w/o Selective HE (SUM only, exp3b)", a_he, a_pqz,
         "SUM aggregation: full_he vs pqz, exp3b sweep"),
        ("w/o Selective HE (SUM only, exp3a)", aggregation_a[("full_he",)],
         aggregation_a[("pqz",)],
         "SUM aggregation: full_he vs pqz, exp3a sweep (same configuration)"),
    ]
    for name, tj, tf, note in single:
        median = relative(tj["median"], tf["median"])
        low, high = relative_range(tj, tf)
        rows_out.append({
            "figure": "exp6b_w18", "metric": "O_pct", "series": name,
            "x": "", "n_runs": min(tj["n"], tf["n"]),
            "median": fmt(median), "min": fmt(low), "max": fmt(high),
            "unit": "%", "status": "plotted",
            "provisional": int(provisional),
            "note": note + "; range from component min/max",
        })
        rows_out.append({
            "figure": "exp6b_w18", "metric": "T_j", "series": name, "x": "",
            "n_runs": tj["n"], "median": fmt(tj["median"] / 1e6),
            "min": fmt(tj["min"] / 1e6), "max": fmt(tj["max"] / 1e6),
            "unit": "ms", "status": "context",
            "provisional": int(provisional), "note": "component for O_j",
        })
        rows_out.append({
            "figure": "exp6b_w18", "metric": "T_full", "series": name, "x": "",
            "n_runs": tf["n"], "median": fmt(tf["median"] / 1e6),
            "min": fmt(tf["min"] / 1e6), "max": fmt(tf["max"] / 1e6),
            "unit": "ms", "status": "context",
            "provisional": int(provisional), "note": "component for O_j",
        })

    gs = sorted({key[1] for key in abl if key[1] is not None})
    rc_points = []
    for g in gs:
        tj = abl.get(("per_block", g))
        tf = abl.get(("batched", g))
        if tj is None or tf is None:
            raise SystemExit(f"REFUSING: need both batched and per_block ablation rows at G={g}")
        require(tj, args.min_runs, f"per_block G={g}")
        require(tf, args.min_runs, f"batched G={g}")
        median = relative(tj["median"], tf["median"])
        low, high = relative_range(tj, tf)
        rc_points.append((g, median, low, high))
        rows_out.append({
            "figure": "exp6b_w18", "metric": "O_pct", "series": "w/o Batched RC",
            "x": g, "n_runs": min(tj["n"], tf["n"]),
            "median": fmt(median), "min": fmt(low), "max": fmt(high),
            "unit": "%", "status": "plotted",
            "provisional": int(provisional),
            "note": "per_block vs batched RC prove time; range from min/max",
        })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(7.0, 2.6))  # layout: wide, full-width

    plot_rows = []
    for name, tj, tf, _ in single:
        median = relative(tj["median"], tf["median"])
        low, high = relative_range(tj, tf)
        plot_rows.append((name, median, low, high, common.PALETTE[0]))
    for g, median, low, high in rc_points:
        plot_rows.append(
            (f"w/o batched RC, prove only (G={g})", median, low, high, common.PALETTE[2])
        )
    if not plot_rows:
        raise SystemExit("refusing: no ablation rows to plot")

    positions = list(range(len(plot_rows)))
    medians = [row[1] for row in plot_rows]
    lows = [row[2] for row in plot_rows]
    highs = [row[3] for row in plot_rows]
    colors = [row[4] for row in plot_rows]
    for position, median, low, high, color in plot_rows:
        ax.errorbar(
            median, position,
            xerr=[[median - low], [high - median]],
            fmt="o", color=color, markersize=4.2,
            elinewidth=0.8, capsize=3,
        )
        value = f"{median:,.0f}%" if median >= 1 else f"{median:.2f}%"
        ax.annotate(value, (max(high, median), position),
                    textcoords="offset points", xytext=(4, 0), fontsize=5.8,
                    va="center", ha="left")
    ax.axhline(1.5, color="0.75", linestyle=":", linewidth=0.7)
    ax.set_yticks(positions)
    ax.set_yticklabels([row[0] for row in plot_rows])
    ax.set_ylim(-0.6, len(plot_rows) - 0.4)
    ax.invert_yaxis()
    ax.set_xscale("log")
    common.log_axes(ax, which="x")
    log_ticks(ax, which="x")
    ax.set_xlim(1e-2, 1e7)
    ax.set_xlabel("O_j (%)")
    ax.grid(axis="y", visible=False)

    fig.text(
        0.01, 0.03,
        "O_j = (T_j-T_Full)/T_Full x 100%, on the affected component only "
        "(not total time); whiskers: component min/max.",
        fontsize=5.3, color="0.35",
    )
    fig.tight_layout(rect=(0, 0.07, 1, 1))
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp6b_w18.pdf"), provisional, exp2a_path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp6b_w18.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp6b_w18.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (common.load_csv rule: a group has n < 10000)")


if __name__ == "__main__":
    main()
