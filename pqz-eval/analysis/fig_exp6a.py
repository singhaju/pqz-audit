"""Figure exp6a: component-stacked ablation at N=1e6, plus the RC ablation.

The main panel stacks two separately measured medians (query execution and SUM
aggregation) for Full, w/o Block Filtering and w/o Selective HE.  It is not a
measured joint total.  The batched-RC ablation lives on a different scale and
is drawn in its own small panel.
"""

from __future__ import annotations

import argparse
import os

from matplotlib.ticker import LogLocator

import common

CONFIG_ORDER = ("Full", "w/o Block Filtering", "w/o Selective HE")
TICK_LABEL = {
    "Full": "Full",
    "w/o Block Filtering": "w/o block\nfiltering",
    "w/o Selective HE": "w/o selective\nHE",
}
FIELDS = [
    "figure", "metric", "series", "x", "n_runs", "median", "min", "max",
    "unit", "status", "provisional", "note",
]
NOTE_SPLIT = (
    "stacked total = query median + aggregation median, measured separately; "
    "not a joint measurement; whiskers sum component min/max"
)


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exp2a", default=None, help="exp2a CSV")
    parser.add_argument("--exp3b", default=None, help="exp3b CSV")
    parser.add_argument("--ablation", default=None, help="ablation raw CSV")
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


def main():
    args = parse_args()
    exp2a_path = args.exp2a or common.default_csv(
        "results/full-1/exp2a/exp2a.csv"
    )
    exp3b_path = args.exp3b or common.default_csv(
        "results/full-2/exp3b/exp3b.csv"
    )
    ablation_path = args.ablation or os.path.join(
        os.path.dirname(common.BASE_DIR),
        "pqz-proof", "results", "ablation-1", "raw.csv",
    )

    exp2a_rows, exp2a_meta = common.load_csv(
        exp2a_path,
        required=("n", "mb", "sigma", "layout", "predicate", "approach",
                  "time_ns", "warmup"),
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

    abl_rows, abl_meta = common.load_csv(
        ablation_path,
        required=("mode", "g_blocks", "prove_s", "warmup"),
        min_runs=args.min_runs,
    )
    abl_rows = [row for row in abl_rows
                if row.get("mode") in ("batched", "per_block")]
    abl = common.group_stats(abl_rows, ("mode", "g_blocks"), value="prove_s")

    require(query.get(("pqz",)), args.min_runs, "exp2a pqz clustered P4")
    require(query.get(("prot_full_scan",)), args.min_runs,
            "exp2a prot_full_scan clustered P4")
    require(aggregation.get(("pqz",)), args.min_runs, "exp3b pqz SUM")
    require(aggregation.get(("full_he",)), args.min_runs, "exp3b full_he SUM")

    provisional = (
        exp2a_meta["provisional"] or exp3b_meta["provisional"]
        or abl_meta["provisional"]
    )
    q_pqz = query[("pqz",)]
    q_full = query[("prot_full_scan",)]
    a_pqz = aggregation[("pqz",)]
    a_he = aggregation[("full_he",)]
    configs = {
        "Full": (q_pqz, a_pqz),
        "w/o Block Filtering": (q_full, a_pqz),
        "w/o Selective HE": (q_pqz, a_he),
    }

    rows_out = []
    for name in CONFIG_ORDER:
        q_entry, a_entry = configs[name]
        for metric, entry, source in (
            ("query", q_entry, "exp2a clustered P4, N=1e6, sigma=1%"),
            ("aggregation", a_entry, "exp3b SUM, N=1e6, sigma=1%"),
        ):
            rows_out.append({
                "figure": "exp6a", "metric": metric, "series": name,
                "x": "", "n_runs": entry["n"],
                "median": fmt(entry["median"] / 1e6),
                "min": fmt(entry["min"] / 1e6),
                "max": fmt(entry["max"] / 1e6),
                "unit": "ms", "status": "plotted",
                "provisional": int(provisional), "note": source,
            })
        rows_out.append({
            "figure": "exp6a", "metric": "total", "series": name,
            "x": "", "n_runs": min(q_entry["n"], a_entry["n"]),
            "median": fmt((q_entry["median"] + a_entry["median"]) / 1e6),
            "min": fmt((q_entry["min"] + a_entry["min"]) / 1e6),
            "max": fmt((q_entry["max"] + a_entry["max"]) / 1e6),
            "unit": "ms", "status": "plotted",
            "provisional": int(provisional), "note": NOTE_SPLIT,
        })

    gs = sorted({key[1] for key in abl if key[1] is not None})
    for mode in ("batched", "per_block"):
        for g in gs:
            entry = abl.get((mode, g))
            if entry is None:
                rows_out.append({
                    "figure": "exp6a", "metric": "rc_prove_s", "series": mode,
                    "x": g, "n_runs": 0, "median": "", "min": "", "max": "",
                    "unit": "ms", "status": "MISSING",
                    "provisional": int(provisional),
                    "note": "no timed rows for this mode/G",
                })
                continue
            require(entry, args.min_runs, f"ablation {mode} G={g}")
            rows_out.append({
                "figure": "exp6a", "metric": "rc_prove_s", "series": mode,
                "x": g, "n_runs": entry["n"],
                "median": fmt(entry["median"] * 1000.0),
                "min": fmt(entry["min"] * 1000.0),
                "max": fmt(entry["max"] * 1000.0),
                "unit": "ms", "status": "plotted",
                "provisional": int(provisional),
                "note": "batched RC proof generation, separate scale",
            })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    # layout: two panels side by side for a full-width figure, (a) a bit wider
    fig, (ax, ax_rc) = plt.subplots(
        1, 2, figsize=(7.0, 2.7), gridspec_kw={"width_ratios": [1.25, 1.0]}
    )
    positions = list(range(len(CONFIG_ORDER)))
    floor = 1e-3  # ms, keeps stacked bars legal on a log axis
    q_med = [configs[name][0]["median"] / 1e6 for name in CONFIG_ORDER]
    a_med = [configs[name][1]["median"] / 1e6 for name in CONFIG_ORDER]
    ax.bar(
        positions, [q - floor for q in q_med], bottom=floor,
        color=common.PALETTE[0], width=0.58, label="query execution",
    )
    ax.bar(
        positions, a_med, bottom=q_med,
        color=common.PALETTE[1], width=0.58, label="SUM aggregation",
    )
    totals = [q + a for q, a in zip(q_med, a_med)]
    total_low = [
        (q_entry["min"] + a_entry["min"]) / 1e6
        for q_entry, a_entry in (configs[name] for name in CONFIG_ORDER)
    ]
    total_high = [
        (q_entry["max"] + a_entry["max"]) / 1e6
        for q_entry, a_entry in (configs[name] for name in CONFIG_ORDER)
    ]
    ax.errorbar(
        positions, totals,
        yerr=[[t - low for t, low in zip(totals, total_low)],
              [high - t for t, high in zip(totals, total_high)]],
        fmt="none", ecolor="0.25", elinewidth=0.8, capsize=3,
    )
    ax.set_yscale("log")
    ax.set_ylim(floor, max(total_high) * 3)
    common.log_axes(ax, which="y")
    log_ticks(ax, which="y")
    ax.set_xticks(positions)
    ax.set_xticklabels([TICK_LABEL[name] for name in CONFIG_ORDER])
    ax.set_ylabel("total online time (ms)")
    ax.set_title("(a) stage-A ablations, N=1e6", fontsize=7.5)
    ax.legend(frameon=False, loc="upper left")

    for index, mode in enumerate(("batched", "per_block")):
        entries = sorted(
            ((g, abl[(mode, g)]) for g in gs if (mode, g) in abl),
            key=lambda item: item[0],
        )
        common.band_plot(
            ax_rc, [g for g, _ in entries],
            [entry["median"] * 1000.0 for _, entry in entries],
            [entry["min"] * 1000.0 for _, entry in entries],
            [entry["max"] * 1000.0 for _, entry in entries],
            mode.replace("_", "-"), common.PALETTE[2 + index], common.MARKERS[index],
        )
    ax_rc.set_xscale("log")
    ax_rc.set_yscale("log")
    common.log_axes(ax_rc)
    log_ticks(ax_rc)
    ax_rc.set_xlabel("G (blocks of $m_B$=500)")
    ax_rc.set_ylabel("RC prove time (ms)")
    ax_rc.set_title("(b) batched RC ablation: separate scale", fontsize=7.5)
    ax_rc.legend(frameon=False, loc="upper left")

    fig.text(
        0.01, 0.025,
        "Main: sum of separately measured medians (query + SUM aggregation), "
        "not a joint total.\nRC panel: proof generation only; its scale "
        "(ms) differs from panel (a).",
        fontsize=5.3, color="0.35",
    )
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp6a.pdf"), provisional, exp2a_path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp6a.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp6a.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (common.load_csv rule: a group has n < 10000)")


if __name__ == "__main__":
    main()
