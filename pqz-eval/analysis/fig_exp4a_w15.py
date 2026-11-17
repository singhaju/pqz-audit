"""Figure exp4a (w15): proof generation versus audited workload N_Q, one line per scheme.

All data measured on one cloud instance (results/cloud-w15):
  - PQZ-Audit: proof-full/raw.csv, experiment=scale, rel=exec (R_Exec prove time),
    warm-up rows excluded, median with min-max band.
  - DART: out2/dart proofgen_nozk, M=10;N=40;z=100;D=400, flat line (median).
  - L-HCPM: out2/lhcpm groth16_prove_mint (2676 constraints), flat line (median).
Writes fig_exp4a_w15.{pdf,png,csv} into journal2/figures/results-w15/ by default.
"""

from __future__ import annotations

import argparse
import os

from matplotlib.ticker import LogLocator

import common
import w15_common as w

FIELDS = [
    "figure", "metric", "series", "x", "n_runs", "median", "min", "max",
    "unit", "status", "provisional", "note",
]
RELS = ("exec",)
TEXT_COLOR = {"DART (no zk proof)": "#007552", "L-HCPM": "#8A4A6E"}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=w.PROOF_CSV, help="proof-full raw CSV")
    parser.add_argument("--out", default=w.OUT_DEFAULT, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3)
    return parser.parse_args()


def main():
    args = parse_args()
    path = args.csv
    rows, meta = common.load_csv(
        path,
        required=("experiment", "rel", "n_records", "depth", "prove_s",
                  "proof_bytes", "prove_peak_rss_kb", "warmup"),
        min_runs=args.min_runs)
    rows = [row for row in rows if row.get("experiment") == "scale"]
    if not rows:
        raise SystemExit("refusing: no experiment=scale rows")
    keys = ("rel", "n_records", "depth")
    prove = common.group_stats(rows, keys, value="prove_s")
    provisional = meta["provisional"]

    dart = w.load_baseline("dart")
    lhcpm = w.load_baseline("lhcpm")
    lines = []
    params, st = w.pick(dart, "proofgen_nozk", M=10, N=40, z=100, D=400)
    lines.append(("DART (no zk proof)", "dart proofgen_nozk", params, st))
    params, st = w.pick(lhcpm, "groth16_prove_mint", constraints=2676)
    lines.append(("L-HCPM", "lhcpm groth16_prove_mint", params, st))

    rows_out = []
    xs_all = {}
    for rel in RELS:
        entries = sorted(
            ((key[1], prove[key]) for key in prove
             if key[0] == rel and key[1] is not None), key=lambda item: item[0])
        if not entries:
            raise SystemExit(f"refusing: no scale rows for rel={rel}")
        xs_all[rel] = entries
        for n_records, entry in entries:
            if entry["n"] < args.min_runs:
                raise SystemExit(f"refusing: {rel} N_Q={n_records} has {entry['n']} runs")
            rows_out.append({
                "figure": "exp4a_w15", "metric": "prove_s", "series": rel,
                "x": n_records, "n_runs": entry["n"],
                "median": w.fmt(entry["median"] * 1000.0),
                "min": w.fmt(entry["min"] * 1000.0),
                "max": w.fmt(entry["max"] * 1000.0),
                "unit": "ms", "status": "plotted", "provisional": int(provisional),
                "note": "measured, median of timed scale rows (warm-up excluded)",
            })
    for label, where, params, st in lines:
        rows_out.append({
            "figure": "exp4a_w15", "metric": "prove_s", "series": label,
            "x": "", "n_runs": st["n"], "median": w.fmt(st["median"]),
            "min": w.fmt(st["min"]), "max": w.fmt(st["max"]), "unit": "ms",
            "status": "plotted", "provisional": int(provisional),
            "note": (f"flat reference line, fixed circuit/parameters, no N_Q "
                     f"dependence; measured, median of raw runs; {where}; params={params}"),
        })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    all_values = []
    for rel in RELS:
        xs = [x for x, _ in xs_all[rel]]
        medians = [e["median"] * 1000.0 for _, e in xs_all[rel]]
        lows = [e["min"] * 1000.0 for _, e in xs_all[rel]]
        highs = [e["max"] * 1000.0 for _, e in xs_all[rel]]
        all_values += medians + lows + highs
        common.band_plot(ax, xs, medians, lows, highs, "PQZ-Audit",
                         common.PALETTE[0], common.MARKERS[0])
        print("PQZ-Audit: " + "; ".join(
            f"N_Q={x}: {m:.6g} ms" for x, m in zip(xs, medians)))
    for label, _, _, st in lines:
        all_values.append(st["median"])
        ax.axhline(st["median"], color=w.line_color(label), linestyle=w.line_dash(label),
                   linewidth=1.0, label=label, zorder=3)
        print(f"{label}: median {st['median']:.6g} ms (min {st['min']:.6g}, "
              f"max {st['max']:.6g}, n={st['n']})")
    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    for axis in (ax.xaxis, ax.yaxis):
        axis.set_major_locator(LogLocator(base=10, subs=(1.0, 2.0, 5.0), numticks=12))
    ax.set_ylim(min(all_values) / 2.0, max(all_values) * 2.0)
    ax.set_xlabel("N_Q (records)")
    ax.set_ylabel("prove time (ms)")
    handles, labels_ = ax.get_legend_handles_labels()
    order = ["PQZ-Audit", "DART (no zk proof)", "L-HCPM"]
    pairs = dict(zip(labels_, handles))
    fig.legend([pairs[k] for k in order], order, loc="upper center", ncol=3,
               frameon=False, bbox_to_anchor=(0.5, 1.0), fontsize=5.6,
               columnspacing=0.8, handlelength=2.4, handletextpad=0.4)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    pdf = os.path.join(directory, "fig_exp4a_w15.pdf")
    fig.savefig(pdf)
    fig.savefig(os.path.join(directory, "fig_exp4a_w15.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp4a_w15.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")


if __name__ == "__main__":
    main()
