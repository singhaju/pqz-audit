"""Figure exp4b (w15): verification cost for q audit requests (R_Bundle).

All data measured on one cloud instance (results/cloud-w15):
  - PQZ-Audit: proof-full/raw.csv, experiment=q, rel=bundle, mode=distinct
    (q distinct proofs), total_verify_s, warm-up rows excluded, median with min-max band.
  - Baselines: q x median of ONE verification (out2/<name>/raw_runs.csv):
      Dong et al.   dong        verify        s=3;c=100
      DOPIV         dopiv-lazy  verify        c=350, m=16384 (red=lazy)
      DART          dart        verify_nozk   M=10;N=40;z=100;D=400
      L-HCPM        lhcpm       groth16_verify  public_inputs=3
Writes fig_exp4b_w15.{pdf,png,csv} into journal2/figures/results-w15/ by default.
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
QS = (1, 10, 25, 50, 100, 200)


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
        path, required=("experiment", "rel", "q", "mode", "total_verify_s", "warmup"),
        min_runs=args.min_runs)
    rows = [row for row in rows if row.get("experiment") == "q"
            and row.get("rel") == "bundle" and row.get("mode") == "distinct"]
    if not rows:
        raise SystemExit("refusing: no experiment=q, rel=bundle, mode=distinct rows")
    stats = common.group_stats(rows, ("q",), value="total_verify_s")
    qs = sorted(key[0] for key in stats)
    if tuple(qs) != QS:
        raise SystemExit(f"refusing: q values {qs} differ from {QS}")
    provisional = meta["provisional"]

    dong = w.load_baseline("dong")
    dopiv = w.load_baseline("dopiv-lazy")
    dart = w.load_baseline("dart")
    lhcpm = w.load_baseline("lhcpm")
    lines = []
    params, st = w.pick(dong, "verify", s=3, c=100)
    lines.append(("Dong et al.", "dong verify", params, st))
    params, st = w.pick(dopiv, "verify", c=350, m=16384, red="lazy")
    lines.append(("DOPIV", "dopiv-lazy verify", params, st))
    params, st = w.pick(dart, "verify_nozk", M=10, N=40, z=100, D=400)
    lines.append(("DART (no zk proof)", "dart verify_nozk", params, st))
    params, st = w.pick(lhcpm, "groth16_verify", public_inputs=3)
    lines.append(("L-HCPM", "lhcpm groth16_verify", params, st))

    rows_out = []
    for q in qs:
        entry = stats[(q,)]
        if entry["n"] < args.min_runs:
            raise SystemExit(f"refusing: bundle distinct q={q} has {entry['n']} runs")
        rows_out.append({
            "figure": "exp4b_w15", "metric": "total_verify_s",
            "series": "distinct (pqz)", "x": q, "n_runs": entry["n"],
            "median": w.fmt(entry["median"] * 1000.0),
            "min": w.fmt(entry["min"] * 1000.0),
            "max": w.fmt(entry["max"] * 1000.0),
            "unit": "ms", "status": "plotted", "provisional": int(provisional),
            "note": "measured, q distinct proofs, rel=bundle (warm-up excluded)",
        })
    for label, where, params, st in lines:
        for q in qs:
            rows_out.append({
                "figure": "exp4b_w15", "metric": "baseline_total_verify_s",
                "series": label, "x": q, "n_runs": st["n"],
                "median": w.fmt(q * st["median"]), "min": "", "max": "",
                "unit": "ms", "status": "plotted", "provisional": int(provisional),
                "note": (f"q x median of one verification ({w.fmt(st['median'])} ms; "
                         f"per-run min {w.fmt(st['min'])}, max {w.fmt(st['max'])}); "
                         f"measured; {where}; params={params}"),
            })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 3.1))
    medians = [stats[(q,)]["median"] * 1000.0 for q in qs]
    lows = [stats[(q,)]["min"] * 1000.0 for q in qs]
    highs = [stats[(q,)]["max"] * 1000.0 for q in qs]
    common.band_plot(ax, qs, medians, lows, highs, "PQZ-Audit",
                     common.PALETTE[0], common.MARKERS[0])
    for label, _, _, st in lines:
        ax.plot(qs, [q * st["median"] for q in qs], color=w.line_color(label),
                linestyle=w.line_dash(label), linewidth=0.9, label=label, zorder=3)
    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    for axis in (ax.xaxis, ax.yaxis):
        axis.set_major_locator(LogLocator(base=10, subs=(1.0, 2.0, 5.0), numticks=12))
    ax.set_xlabel("audit requests q")
    ax.set_ylabel("total verification time (ms)")
    order = ["PQZ-Audit", "Dong et al.", "DOPIV", "DART (no zk proof)", "L-HCPM"]
    handles, labels = ax.get_legend_handles_labels()
    pairs = dict(zip(labels, handles))
    fig.legend([pairs[k] for k in order], order, frameon=False, loc="lower left",
               bbox_to_anchor=(0.0, 0.0), fontsize=5.8, handlelength=3.0,
               labelspacing=0.35, ncol=2, columnspacing=0.8)
    fig.tight_layout(rect=(0, 0.16, 1, 1))
    pdf = os.path.join(directory, "fig_exp4b_w15.pdf")
    fig.savefig(pdf)
    fig.savefig(os.path.join(directory, "fig_exp4b_w15.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp4b_w15.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    for q, m in zip(qs, medians):
        print(f"PQZ-Audit q={q}: median {m:.6g} ms")
    for label, _, _, st in lines:
        print(f"{label}: one verify median {st['median']:.6g} ms "
              f"(min {st['min']:.6g}, max {st['max']:.6g}, n={st['n']})")
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")


if __name__ == "__main__":
    main()
