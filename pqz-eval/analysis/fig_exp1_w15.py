"""Figure exp1 (w15): PQZ-Audit query time versus N plus ONE flat line per baseline scheme.

All data measured on one cloud instance (results/cloud-w15):
  - PQZ-Audit: exp1d/exp1d.csv, series sigma1pct, median with min-max band.
  - Baselines (flat, median of the 30 timed runs in out2/<name>/raw_runs.csv):
      Dong et al.   dong        proofgen        s=3;c=100
      DOPIV         dopiv-lazy  proofgen        c=350, m=16384 (red=lazy)
      DART          dart        proofgen_nozk   M=10;N=40;z=100;D=400
      L-HCPM        lhcpm       audit_hit
Writes fig_exp1_w15.{pdf,png,csv} into journal2/figures/results-w15/ by default.
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


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=w.EXP1_CSV, help="exp1 CSV")
    parser.add_argument("--out", default=w.OUT_DEFAULT, help="output directory")
    parser.add_argument("--min-runs", type=int, default=3)
    return parser.parse_args()


def log_ticks(ax):
    for axis in (ax.xaxis, ax.yaxis):
        axis.set_major_locator(LogLocator(base=10, subs=(1.0, 2.0, 5.0), numticks=12))


def main():
    args = parse_args()
    path = args.csv
    rows, meta = common.load_csv(
        path, required=("series", "n", "time_ns", "warmup"), min_runs=args.min_runs)
    rows = [row for row in rows if row.get("series") == "sigma1pct"]
    if not rows:
        raise SystemExit("refusing: no series=sigma1pct rows")
    stats = common.group_stats(rows, ("n",), value="time_ns")
    ns = sorted(key[0] for key in stats if key[0] is not None)
    for n in ns:
        if stats[(n,)]["n"] < args.min_runs:
            raise SystemExit(f"refusing: N={n} has {stats[(n,)]['n']} timed runs")
    provisional = meta["provisional"]

    # Baselines: (label, params string, stats)
    dong = w.load_baseline("dong")
    dopiv = w.load_baseline("dopiv-lazy")
    dart = w.load_baseline("dart")
    lhcpm = w.load_baseline("lhcpm")
    lines = []
    params, st = w.pick(dong, "proofgen", s=3, c=100)
    lines.append(("Dong et al.", "dong proofgen", params, st))
    params, st = w.pick(dopiv, "proofgen", c=350, m=16384, red="lazy")
    lines.append(("DOPIV", "dopiv-lazy proofgen", params, st))
    params, st = w.pick(dart, "proofgen_nozk", M=10, N=40, z=100, D=400)
    lines.append(("DART (no zk proof)", "dart proofgen_nozk", params, st))
    params, st = w.pick(lhcpm, "audit_hit")
    lines.append(("L-HCPM (cache hit)", "lhcpm audit_hit", params, st))

    rows_out = []
    for n in ns:
        entry = stats[(n,)]
        rows_out.append({
            "figure": "exp1_w15", "metric": "query_time",
            "series": "sigma1pct (pqz)", "x": n, "n_runs": entry["n"],
            "median": w.fmt(entry["median"] / 1e6),
            "min": w.fmt(entry["min"] / 1e6), "max": w.fmt(entry["max"] / 1e6),
            "unit": "ms", "status": "plotted", "provisional": int(provisional),
            "note": "measured, clustered layout, P4, sigma=1%",
        })
    for label, where, params, st in lines:
        rows_out.append({
            "figure": "exp1_w15", "metric": "baseline_time",
            "series": label, "x": "", "n_runs": st["n"],
            "median": w.fmt(st["median"]), "min": w.fmt(st["min"]),
            "max": w.fmt(st["max"]), "unit": "ms", "status": "plotted",
            "provisional": int(provisional),
            "note": (f"flat line, no N dependence; measured, median of raw runs; "
                     f"{where}; params={params}"),
        })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 3.3))
    medians = [stats[(n,)]["median"] / 1e6 for n in ns]
    lows = [stats[(n,)]["min"] / 1e6 for n in ns]
    highs = [stats[(n,)]["max"] / 1e6 for n in ns]
    common.band_plot(ax, ns, medians, lows, highs, "PQZ-Audit",
                     common.PALETTE[0], "o")
    for label, _, _, st in lines:
        ax.axhline(st["median"], color=w.line_color(label), linestyle=w.line_dash(label),
                   linewidth=0.9, label=label, zorder=3)
    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    log_ticks(ax)
    values = medians + lows + highs + [st["median"] for _, _, _, st in lines]
    ax.set_ylim(min(values) / 2.0, max(values) * 3.0)
    ax.set_xlabel("N (records)")
    ax.set_ylabel("query time (ms)")
    order = ["PQZ-Audit", "Dong et al.", "DOPIV", "DART (no zk proof)", "L-HCPM (cache hit)"]
    handles, labels = ax.get_legend_handles_labels()
    pairs = dict(zip(labels, handles))
    fig.legend([pairs[k] for k in order], order, frameon=False, loc="lower left",
               bbox_to_anchor=(0.01, 0.0), fontsize=5.8, handlelength=3.0,
               labelspacing=0.35, ncol=2, columnspacing=0.8)
    fig.tight_layout(rect=(0, 0.16, 1, 1))
    pdf = os.path.join(directory, "fig_exp1_w15.pdf")
    fig.savefig(pdf)
    fig.savefig(os.path.join(directory, "fig_exp1_w15.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp1_w15.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    for n, m in zip(ns, medians):
        print(f"PQZ-Audit N={n}: median {m:.6g} ms")
    for label, _, _, st in lines:
        print(f"{label}: median {st['median']:.6g} ms (min {st['min']:.6g}, "
              f"max {st['max']:.6g}, n={st['n']})")
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")


if __name__ == "__main__":
    main()
