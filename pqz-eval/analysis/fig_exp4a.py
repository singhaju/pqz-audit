"""Figure exp4a: prover-side scalability versus N_Q, plus the R_Auth depth sweep.

Every plotted value is the median of timed rows; the band is min-max.  R_Auth
has no N_Q sweep in the raw file (it is run at policy-tree depth 10 and 20),
so it is shown in its own depth panel instead of being given a fabricated N_Q.

Panel (a) also carries two flat reference lines for the proof-generation times
REPORTED by the L-HCPM paper (Mint 22 ms, Transfer 55 ms, Apple M3, not our
hardware), read from pqz-baselines/results-papers-run2/baseline_costs_profbigo.csv.
They are fixed transaction circuits and are not scaled to the audited workload.
DART is not drawn: it gives no proof-generation value.
"""

from __future__ import annotations

import argparse
import csv
import os

from matplotlib.ticker import LogLocator

import common

RELS = ("rc", "exec")
FIELDS = [
    "figure", "metric", "series", "x", "n_runs", "median", "min", "max",
    "unit", "status", "provisional", "note",
]
# L-HCPM reported proof times: (CSV param_set, legend label, dash pattern)
LHCPM_LINES = (
    ("Mint", "L-HCPM Mint", (0, (6, 1.5, 1, 1.5, 1, 1.5))),
    ("Transfer", "L-HCPM Transfer", (0, (1, 1.3))),
)
LHCPM_COLOR_INDEX = 3
MISSING_AUTH = (
    "R_Auth does not depend on N_Q; it is run at policy-tree depth 10 and 20 "
    "(see the depth panel)"
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


def check(entry, minimum, label):
    if entry["n"] < minimum:
        raise SystemExit(
            f"refusing: {label} has {entry['n']} timed runs (< {minimum})"
        )


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
    size = common.group_stats(rows, keys, value="proof_bytes")
    rss = common.group_stats(rows, keys, value="prove_peak_rss_kb")

    provisional = meta["provisional"]
    rows_out = []

    # Panels (a)-(c): R_RC and R_Exec versus N_Q.
    plotted = []
    for rel in RELS:
        entries = sorted(
            ((key[1], prove[key]) for key in prove
             if key[0] == rel and key[1] is not None),
            key=lambda item: item[0],
        )
        if not entries:
            raise SystemExit(f"refusing: no scale rows for rel={rel}")
        for n_records, entry in entries:
            check(entry, args.min_runs, f"{rel} N_Q={n_records}")
            rows_out.append({
                "figure": "exp4a", "metric": "prove_s", "series": rel,
                "x": n_records, "n_runs": entry["n"],
                "median": fmt(entry["median"] * 1000.0),
                "min": fmt(entry["min"] * 1000.0),
                "max": fmt(entry["max"] * 1000.0),
                "unit": "ms", "status": "plotted", "provisional": int(provisional),
                "note": "median of timed scale rows",
            })
            rows_out.append({
                "figure": "exp4a", "metric": "proof_bytes", "series": rel,
                "x": n_records, "n_runs": size[(rel, n_records, None)]["n"],
                "median": fmt(size[(rel, n_records, None)]["median"] / 1024.0),
                "min": fmt(size[(rel, n_records, None)]["min"] / 1024.0),
                "max": fmt(size[(rel, n_records, None)]["max"] / 1024.0),
                "unit": "KiB", "status": "plotted", "provisional": int(provisional),
                "note": "proof_bytes / 1024",
            })
            rows_out.append({
                "figure": "exp4a", "metric": "proof_peak_rss", "series": rel,
                "x": n_records, "n_runs": rss[(rel, n_records, None)]["n"],
                "median": fmt(rss[(rel, n_records, None)]["median"] / 1024.0),
                "min": fmt(rss[(rel, n_records, None)]["min"] / 1024.0),
                "max": fmt(rss[(rel, n_records, None)]["max"] / 1024.0),
                "unit": "MiB", "status": "plotted", "provisional": int(provisional),
                "note": "prove_peak_rss_kb / 1024",
            })
        plotted.append(rel)

    # Panel (d): R_Auth versus policy-tree depth.
    auth_entries = sorted(
        ((key[2], prove[key]) for key in prove
         if key[0] == "auth" and key[2] is not None),
        key=lambda item: item[0],
    )
    if not auth_entries:
        raise SystemExit("refusing: no R_Auth depth rows")
    for depth, entry in auth_entries:
        check(entry, args.min_runs, f"auth depth={depth}")
        bytes_entry = size[("auth", None, depth)]
        rows_out.append({
            "figure": "exp4a", "metric": "prove_s", "series": "auth",
            "x": depth, "n_runs": entry["n"],
            "median": fmt(entry["median"] * 1000.0),
            "min": fmt(entry["min"] * 1000.0),
            "max": fmt(entry["max"] * 1000.0),
            "unit": "ms", "status": "plotted", "provisional": int(provisional),
            "note": "R_Auth depth sweep, no N_Q",
        })
        rows_out.append({
            "figure": "exp4a", "metric": "proof_bytes", "series": "auth",
            "x": depth, "n_runs": bytes_entry["n"],
            "median": fmt(bytes_entry["median"] / 1024.0),
            "min": fmt(bytes_entry["min"] / 1024.0),
            "max": fmt(bytes_entry["max"] / 1024.0),
            "unit": "KiB", "status": "plotted", "provisional": int(provisional),
            "note": "R_Auth depth sweep, proof_bytes / 1024",
        })
    for metric in ("prove_s", "proof_bytes", "proof_peak_rss"):
        rows_out.append({
            "figure": "exp4a", "metric": metric, "series": "auth",
            "x": "", "n_runs": 0, "median": "", "min": "", "max": "",
            "unit": "", "status": "MISSING", "provisional": int(provisional),
            "note": MISSING_AUTH,
        })

    # L-HCPM reported proof-generation times: flat reference lines (appended rows).
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
            "figure": "exp4a", "metric": "prove_s",
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
    # layout: one wide row (a)(b)(c)(d) for a full-width figure
    fig, axes_row = plt.subplots(1, 4, figsize=(7.0, 2.3))
    axes = [[axes_row[0], axes_row[1]], [axes_row[2], axes_row[3]]]
    colors = {"rc": common.PALETTE[0], "exec": common.PALETTE[2]}
    labels = {"rc": "R_RC", "exec": "R_Exec"}

    for rel in RELS:
        xs = sorted({key[1] for key in prove
                     if key[0] == rel and key[1] is not None})
        for ax, stats, scale, unit in (
            (axes[0][0], prove, 1000.0, "prove time (ms)"),
            (axes[0][1], size, 1.0 / 1024.0, "proof size (KiB)"),
            (axes[1][0], rss, 1.0 / 1024.0, "peak RSS (MiB)"),
        ):
            medians = [stats[(rel, x, None)]["median"] * scale for x in xs]
            lows = [stats[(rel, x, None)]["min"] * scale for x in xs]
            highs = [stats[(rel, x, None)]["max"] * scale for x in xs]
            common.band_plot(
                ax, xs, medians, lows, highs, labels[rel],
                colors[rel], common.MARKERS[RELS.index(rel)],
            )
            ax.set_xscale("log")
            ax.set_yscale("log")
            common.log_axes(ax)
            log_ticks(ax)
            ax.set_xlabel("N_Q (records)")
            ax.set_ylabel(unit)

    for label, time_ms, dash in lhcpm_lines:
        axes[0][0].axhline(time_ms, color=common.PALETTE[LHCPM_COLOR_INDEX],
                           linestyle=dash, linewidth=1.1, label=label)
        axes[0][0].text(0.97, time_ms, f"{time_ms:g} ms",
                        transform=axes[0][0].get_yaxis_transform(),
                        ha="right", va="bottom", fontsize=5.6,
                        color="#8A4A6E")
    axes[0][0].set_title("(a) proof generation")
    axes[0][1].set_title("(b) proof size")
    axes[1][0].set_title("(c) prover peak memory")
    legend_loc = {axes[0][0]: "upper left", axes[0][1]: "lower right",
                  axes[1][0]: "upper left"}
    for ax in (axes[0][0], axes[0][1], axes[1][0]):
        ax.legend(frameon=False, loc=legend_loc[ax])

    # (d) R_Auth: no N_Q axis; depth is the independent variable.
    ax = axes[1][1]
    depths = [depth for depth, _ in auth_entries]
    medians = [entry["median"] * 1000.0 for _, entry in auth_entries]
    lows = [entry["min"] * 1000.0 for _, entry in auth_entries]
    highs = [entry["max"] * 1000.0 for _, entry in auth_entries]
    common.band_plot(ax, depths, medians, lows, highs, "prove time",
                     common.PALETTE[3], "o")
    ax.set_xscale("linear")
    ax.set_yscale("linear")
    ax.set_ylim(0, max(highs) * 1.35)
    ax.set_xticks(depths)
    ax.set_xticklabels([str(depth) for depth in depths])
    ax.set_xlabel("policy-tree depth")
    ax.set_ylabel("prove time (ms)")
    ax2 = ax.twinx()
    ax2.grid(False)
    ax2.plot(
        depths,
        [size[("auth", None, depth)]["median"] / 1024.0 for depth in depths],
        color=common.PALETTE[4], marker="s", linestyle="--", linewidth=1.2,
        markersize=3.5, label="proof size",
    )
    ax2.set_ylabel("proof size (KiB)")
    ax2.set_ylim(0, max(
        size[("auth", None, depth)]["max"] / 1024.0 for depth in depths
    ) * 1.25)
    ax.set_title("(d) R_Auth vs depth")
    handles, labels_ = ax.get_legend_handles_labels()
    handles2, labels2 = ax2.get_legend_handles_labels()
    ax.legend(handles + handles2, labels_ + labels2, frameon=False,
              loc="upper left")

    fig.text(
        0.01, 0.012,
        "R_Auth is a depth sweep (no N_Q). Proof sizes in KiB, memory in MiB.  "
        "Pink lines in (a): L-HCPM, reported by its paper (Apple M3),\n"
        "fixed circuit, not scaled to N_Q: Mint 22 ms, Transfer 55 ms; not a "
        "measurement by us.  DART is not drawn (no proof-generation value).",
        fontsize=5.5, color="0.35",
    )
    fig.tight_layout(rect=(0, 0.09, 1, 1))
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp4a.pdf"), provisional, path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp4a.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp4a.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (common.load_csv rule: a group has n < 10000)")


if __name__ == "__main__":
    main()
