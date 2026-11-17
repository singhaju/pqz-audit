"""Figure exp3a (w18 copy of fig_exp3a_w17.py): SUM time versus selected count.

PQZ-Audit and Plaintext aggregation from <results>/exp3ad/exp3ad.csv, Full-Domain HE from
<results>/exp3a/exp3a.csv (SUM rows, copied as text into a temporary merged input).
Results folder: --results, env W18_RESULTS, else bench/pqz-eval/results/cloud-w18.
Writes fig_exp3a_w18.{pdf,png,csv} into --out, env W18_OUT, else journal2/figures/results-w18/.
Refuses (exit 2) when a job folder or csv is missing, empty or failed.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import tempfile

from matplotlib.ticker import LogLocator

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I drops the script folder
import common  # noqa: E402
import dense_common as dc  # noqa: E402
import w18_common as WC  # noqa: E402

APPROACH_ORDER = ["plain_agg", "full_he", "pqz"]
DISPLAY = {"plain_agg": "Plaintext aggregation", "full_he": "Full-Domain HE", "pqz": "PQZ-Audit"}
FIELDS = [
    "figure", "record_type", "agg", "approach", "n_sel", "n_runs",
    "median_ms", "min_ms", "max_ms", "slope", "r2", "points_fit",
    "provisional", "note", "source",
]
DEFAULT_OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))),
    "journal2", "figures", "results-w18",
)


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def read_rows(path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        sys.exit(f"refusing: input CSV not found: {path}")
    with open(path, "r", encoding="utf-8", newline="") as h:
        r = csv.DictReader(h)
        return list(r.fieldnames or []), list(r)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default=None, help="results folder (default cloud-w18)")
    parser.add_argument("--out", default=None, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3,
                        help="minimum timed runs per group")
    return parser.parse_args()


def fmt(value):
    return f"{value:.10g}"


def main():
    args = parse_args()
    res = WC.Results(WC.results_dir(args.results))
    res.preflight([("exp3ad", "exp3ad.csv"), ("exp3a", "exp3a.csv")])
    res.rd("exp3ad", "exp3ad.csv")  # refuses on rows with note FAILED
    res.rd("exp3a", "exp3a.csv")
    args.dense = res.p("exp3ad", "exp3ad.csv")
    args.he = res.p("exp3a", "exp3a.csv")
    args.out = WC.out_dir(args.out, DEFAULT_OUT)
    hd, dense = read_rows(args.dense)
    hh, he = read_rows(args.he)
    if hd != hh:
        sys.exit(f"refusing: header of {args.dense} differs from {args.he}")
    dense_keep = [r for r in dense if r["agg"] == "SUM"
                  and r["approach"] in ("plain_agg", "pqz")]
    he_keep = [r for r in he if r["agg"] == "SUM" and r["approach"] == "full_he"]
    if not dense_keep or not he_keep:
        sys.exit("refusing: no SUM plain_agg/pqz rows in dense file or no SUM "
                 "full_he rows in the Full-Domain HE file")
    n_dense = {r["n"] for r in dense_keep}
    n_he = {r["n"] for r in he_keep}
    if n_dense != n_he:
        print(f"WARNING: N differs: dense {sorted(n_dense)}, full_he {sorted(n_he)}; "
              "x axis mixes two N.", file=sys.stderr)

    s_dense, s_he = dc.rel(args.dense), dc.rel(args.he)
    with tempfile.TemporaryDirectory() as tmp:
        merged = os.path.join(tmp, "exp3a_w18_merged_input.csv")
        with open(merged, "w", encoding="utf-8", newline="") as h:
            w = csv.DictWriter(h, fieldnames=hd)
            w.writeheader()
            w.writerows(dense_keep + he_keep)
        rows, meta = common.load_csv(
            merged,
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
    pqz_fit = common.loglog_fit(
        [n for n, _ in pqz_entries],
        [common.to_ms(e["median"]) for _, e in pqz_entries])

    rows_out = []
    for approach in APPROACH_ORDER:
        entries = sorted(
            ((key[1], value) for key, value in stats.items()
             if key[0] == approach),
            key=lambda item: item[0],
        )
        for n_sel, entry in entries:
            is_pqz = approach == "pqz"
            rows_out.append({
                "figure": "exp3a_w18",
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
                "source": s_he if approach == "full_he" else s_dense,
            })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 2.6))

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

    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    for axis in (ax.xaxis, ax.yaxis):
        axis.set_major_locator(LogLocator(base=10, subs=(1.0,), numticks=12))
    ax.set_xlabel("selected records $n_Q$ = σ·N")
    ax.set_ylabel("SUM time (ms)")
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper center", ncol=2, frameon=False,
        bbox_to_anchor=(0.5, 1.0),
    )
    fig.tight_layout(rect=(0, 0, 1, 0.86))
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp3a_w18.pdf"), provisional,
        "exp3ad.csv + exp3a.csv",
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp3a_w18.png"), dpi=200)
    plt.close(fig)

    csv_path = os.path.join(directory, "fig_exp3a_w18.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    print(f"pqz log-log slope={pqz_fit['slope']} r2={pqz_fit['r2']}")
    if provisional:
        print("provisional=True (a group has fewer than 10 timed runs)")


if __name__ == "__main__":
    main()
