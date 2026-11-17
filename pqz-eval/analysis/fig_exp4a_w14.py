"""Figure exp4a (w14, minimal): proof generation versus N_Q, one curve per scheme.

Copy of fig_exp4a_w14.py (same data: pqz-proof/results/full-2/raw.csv) with
  - ONE PQZ-Audit curve: R_Exec (the full execution proof), median, band = min-max;
  - ONE L-HCPM flat line: proof-generation time REPORTED by the L-HCPM paper
    (param_set "Mint" in baseline_costs_profbigo.csv; Apple M3, fixed transaction
    circuit, not scaled to N_Q, not our measurement).
DART proof generation has no cost in its paper, so it is not drawn.
Writes fig_exp4a_w14.{pdf,png,csv} into journal2/figures/results-w14/ by default.
"""

from __future__ import annotations

import argparse
import csv
import os

from matplotlib.ticker import LogLocator

import common

RELS = ("exec",)
FIELDS = [
    "figure", "metric", "series", "x", "n_runs", "median", "min", "max",
    "unit", "status", "provisional", "note",
]
# L-HCPM reported proof times: (CSV param_set, legend label, dash pattern)
LHCPM_LINES = (
    ("Mint", "L-HCPM", (0, (6, 1.5, 1, 1.5, 1, 1.5))),
)
LHCPM_COLOR_INDEX = 3
DEFAULT_OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))),
    "journal2", "figures", "results-w14",
)


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=None,
                        help="pqz-proof scale raw CSV")
    parser.add_argument("--profbigo", default=None,
                        help="baseline_costs_profbigo.csv")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3,
                        help="minimum timed runs per group")
    return parser.parse_args()


def fmt(value):
    return f"{value:.10g}"


def main():
    args = parse_args()
    path = args.csv or os.path.join(
        os.path.dirname(common.BASE_DIR),
        "pqz-proof", "results", "full-2", "raw.csv",
    )
    prof_path = args.profbigo or os.path.join(
        os.path.dirname(common.BASE_DIR),
        "pqz-baselines", "results-papers-run2", "baseline_costs_profbigo.csv",
    )
    rows, meta = common.load_csv(
        path,
        required=("experiment", "rel", "n_records", "depth", "prove_s",
                  "proof_bytes", "prove_peak_rss_kb", "warmup"),
        min_runs=args.min_runs,
    )
    rows = [row for row in rows if row.get("experiment") == "scale"]
    if not rows:
        raise SystemExit("refusing: no experiment=scale rows")

    keys = ("rel", "n_records", "depth")
    prove = common.group_stats(rows, keys, value="prove_s")

    provisional = meta["provisional"]
    rows_out = []
    for rel in RELS:
        entries = sorted(
            ((key[1], prove[key]) for key in prove
             if key[0] == rel and key[1] is not None),
            key=lambda item: item[0],
        )
        if not entries:
            raise SystemExit(f"refusing: no scale rows for rel={rel}")
        for n_records, entry in entries:
            if entry["n"] < args.min_runs:
                raise SystemExit(
                    f"refusing: {rel} N_Q={n_records} has {entry['n']} timed "
                    f"runs (< {args.min_runs})")
            rows_out.append({
                "figure": "exp4a_w14", "metric": "prove_s", "series": rel,
                "x": n_records, "n_runs": entry["n"],
                "median": fmt(entry["median"] * 1000.0),
                "min": fmt(entry["min"] * 1000.0),
                "max": fmt(entry["max"] * 1000.0),
                "unit": "ms", "status": "plotted", "provisional": int(provisional),
                "note": "median of timed scale rows",
            })

    # L-HCPM reported proof-generation times: flat reference lines.
    with open(prof_path, "r", encoding="utf-8", newline="") as handle:
        prof_rows = list(csv.DictReader(handle))
    lhcpm_lines = []
    for param_set, label, dash in LHCPM_LINES:
        match = [row for row in prof_rows
                 if (row["scheme"], row["phase"], row["param_set"])
                 == ("L-HCPM", "proof", param_set)]
        if len(match) != 1:
            raise SystemExit(f"refusing: L-HCPM proof {param_set} not found once")
        row = match[0]
        time_ms = float(row["time_ns"]) / 1e6
        lhcpm_lines.append((label, time_ms, dash))
        rows_out.append({
            "figure": "exp4a_w14", "metric": "prove_s",
            "series": f"L-HCPM {param_set} (reported)", "x": "", "n_runs": 0,
            "median": fmt(time_ms), "min": "", "max": "",
            "unit": "ms", "status": "plotted", "provisional": int(provisional),
            "note": (f"flat reference line in panel (a); {row['source']}; "
                     f"fixed transaction circuit, not scaled to the audited "
                     f"workload N_Q; not a measurement by us; "
                     f"status in profbigo file: {row['status']}"),
        })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    colors = {"exec": common.PALETTE[0]}
    labels = {"exec": "PQZ-Audit"}

    for rel in RELS:
        xs = sorted({key[1] for key in prove
                     if key[0] == rel and key[1] is not None})
        medians = [prove[(rel, x, None)]["median"] * 1000.0 for x in xs]
        lows = [prove[(rel, x, None)]["min"] * 1000.0 for x in xs]
        highs = [prove[(rel, x, None)]["max"] * 1000.0 for x in xs]
        common.band_plot(
            ax, xs, medians, lows, highs, labels[rel],
            colors[rel], common.MARKERS[0],
        )
        print(f"{labels[rel]}: " + "; ".join(
            f"N_Q={x}: {m:.6g} ms" for x, m in zip(xs, medians)))
    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    for axis in (ax.xaxis, ax.yaxis):
        axis.set_major_locator(
            LogLocator(base=10, subs=(1.0, 2.0, 5.0), numticks=12))
    ax.set_xlabel("N_Q (records)")
    ax.set_ylabel("prove time (ms)")

    for label, time_ms, dash in lhcpm_lines:
        ax.axhline(time_ms, color=common.PALETTE[LHCPM_COLOR_INDEX],
                   linestyle=dash, linewidth=1.1, label=label)
        ax.text(0.97, time_ms, f"{time_ms:g} ms",
                transform=ax.get_yaxis_transform(),
                ha="right", va="bottom", fontsize=5.6, color="#8A4A6E")

    handles, labels_ = ax.get_legend_handles_labels()
    fig.legend(
        handles, labels_, loc="upper center", ncol=2, frameon=False,
        bbox_to_anchor=(0.5, 1.0), fontsize=5.6, columnspacing=0.8,
        handlelength=1.6, handletextpad=0.4,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp4a_w14.pdf"), provisional, path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp4a_w14.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp4a_w14.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (common.load_csv rule: a group has n < 10000)")


if __name__ == "__main__":
    main()
