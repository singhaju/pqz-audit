"""Figure exp4b (w14, minimal): verification cost for q audit requests (R_Bundle).

Copy of fig_exp4b.py with the same numbers but ONE line per scheme:
  - PQZ-Audit: the "q distinct proofs" curve (measured, the conservative mode).
  - Dong et al.: q x per-audit cost, c=100, s=3 (paper formula, our unit costs).
  - DOPIV: q x per-audit cost, verify_integrity, c=350, m=16384, T_M=zq_mul.
  - DART: q x per-audit cost, z=100, professor's table cell, constant 1
    (T_ZKV omitted: LOWER BOUND).
  - L-HCPM: q x Groth16 verification time REPORTED by the paper (about 0.82 ms, Apple M3).
One audit = one request.  None of the baseline lines is a measurement of the baseline system.
Writes fig_exp4b_w14.{pdf,png,csv} into journal2/figures/results-w14/ by default.
"""

from __future__ import annotations

import argparse
import csv
import os

from matplotlib.ticker import LogLocator

import common

MODE_ORDER = ("distinct",)
MODE_LABEL = {
    "same": "one proof verified q times",
    "distinct": "q distinct proofs",
}
DEFAULT_OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))),
    "journal2", "figures", "results-w14",
)
FIELDS = [
    "figure", "metric", "series", "x", "n_runs", "median", "min", "max",
    "unit", "status", "provisional", "note",
]
BASELINE_LABEL = ("baseline line = q x per-audit verification cost; the plan says one audit "
                  "per request; not a measurement of the baseline system")
PLOT_LABEL = {
    "distinct": "PQZ-Audit",
}
# Baseline lines: (series, scheme, phase, param_set, file, legend label, palette index, dash)
#   file "run2" = baseline_costs.csv, "prof" = baseline_costs_profbigo.csv
BASELINE_LINES = (
    ("Dong et al. verify c=100 s=3", "Dong et al.", "verify",
     "c=100;s=3;reading=paper_mixed;tt=gt", "run2",
     "Dong et al.", None, (0, (1, 3)), "0.30",
     "computed from the paper's formula with unit costs measured by us"),
    ("DOPIV verify_integrity c=350 m=16384 (T_M=zq_mul)", "DOPIV", "verify_integrity",
     "c=350;n=256;m=16384;tm=zq_mul", "prof",
     "DOPIV", 4, (0, (4, 4)), None,
     "computed from the paper's formula with unit costs measured by us (m=16384 re-computed in prof_bigo.py)"),
    ("DART verify z=100 (lower bound)", "DART", "verify",
     "z=100;tp=pairing;te=g1_exp", "prof",
     "DART", 2, (0, (2.5, 1.2)), None,
     "professor's table, constant 1, our parameters; T_ZKV omitted, lower bound"),
    ("L-HCPM verify (Groth16)", "L-HCPM", "verify", "groth16", "prof",
     "L-HCPM", 3, (0, (6, 1.5, 1, 1.5, 1, 1.5)), None,
     "reported by the paper (Groth16 median about 0.82 ms, Apple M3, gnark/BN254)"),
)


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=None,
                        help="pqz-proof q raw CSV")
    parser.add_argument("--baselines", default=None,
                        help="baseline_costs.csv")
    parser.add_argument("--profbigo", default=None,
                        help="baseline_costs_profbigo.csv")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output directory")
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


def read_baselines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return list(csv.DictReader(handle))


def main():
    args = parse_args()
    path = args.csv or os.path.join(
        os.path.dirname(common.BASE_DIR),
        "pqz-proof", "results", "full-2", "raw.csv",
    )
    baseline_path = args.baselines or os.path.join(
        os.path.dirname(common.BASE_DIR),
        "pqz-baselines", "results-papers-run2", "baseline_costs.csv",
    )
    prof_path = args.profbigo or os.path.join(
        os.path.dirname(common.BASE_DIR),
        "pqz-baselines", "results-papers-run2", "baseline_costs_profbigo.csv",
    )
    rows, meta = common.load_csv(
        path,
        required=("experiment", "rel", "q", "mode", "total_verify_s", "warmup"),
        min_runs=args.min_runs,
    )
    rows = [
        row for row in rows
        if row.get("experiment") == "q" and row.get("rel") == "bundle"
    ]
    if not rows:
        raise SystemExit("refusing: no experiment=q, rel=bundle rows")

    stats = common.group_stats(rows, ("mode", "q"), value="total_verify_s")
    provisional = meta["provisional"]
    rows_out = []
    qs = sorted({key[1] for key in stats if key[1] is not None})
    modes = [mode for mode in MODE_ORDER
             if any(key[0] == mode for key in stats)]
    for mode in modes:
        for q in qs:
            entry = stats.get((mode, q))
            if entry is None:
                rows_out.append({
                    "figure": "exp4b_w14", "metric": "total_verify_s",
                    "series": mode, "x": q, "n_runs": 0,
                    "median": "", "min": "", "max": "",
                    "unit": "ms", "status": "MISSING",
                    "provisional": int(provisional),
                    "note": f"no timed rows for mode={mode}, q={q}",
                })
                continue
            if entry["n"] < args.min_runs:
                raise SystemExit(
                    f"refusing: bundle {mode} q={q} has {entry['n']} timed runs"
                )
            rows_out.append({
                "figure": "exp4b_w14", "metric": "total_verify_s",
                "series": mode, "x": q, "n_runs": entry["n"],
                "median": fmt(entry["median"] * 1000.0),
                "min": fmt(entry["min"] * 1000.0),
                "max": fmt(entry["max"] * 1000.0),
                "unit": "ms", "status": "plotted",
                "provisional": int(provisional),
                "note": MODE_LABEL.get(mode, mode),
            })
    for mode in MODE_ORDER:
        if mode not in modes:
            rows_out.append({
                "figure": "exp4b_w14", "metric": "total_verify_s",
                "series": mode, "x": "", "n_runs": 0,
                "median": "", "min": "", "max": "", "unit": "ms",
                "status": "MISSING", "provisional": int(provisional),
                "note": f"mode={mode} is absent from the raw file",
            })

    # Baseline lines: q x per-audit verification cost (one audit = one request).
    tables = {"run2": read_baselines(baseline_path),
              "prof": read_baselines(prof_path)}

    def find_row(which, scheme, phase, param_set):
        for row in tables[which]:
            if (row.get("scheme", "").strip('"'), row.get("phase", "").strip('"'),
                    row.get("param_set", "").strip('"')) == (scheme, phase, param_set):
                return row
        raise SystemExit(
            f"refusing: no row {scheme}/{phase}/{param_set} in the {which} file")

    base_lines = []
    for (name, scheme, phase, param_set, which, label, color, dash, grey,
         how) in BASELINE_LINES:
        row = find_row(which, scheme, phase, param_set)
        per_audit_ms = float(row["time_ns"]) / 1e6
        base_lines.append((name, per_audit_ms, label, color, dash, grey))
        for q in qs:
            rows_out.append({
                "figure": "exp4b_w14", "metric": "baseline_total_verify_s",
                "series": name, "x": q, "n_runs": 0,
                "median": fmt(q * per_audit_ms), "min": "", "max": "",
                "unit": "ms", "status": "plotted",
                "provisional": int(provisional),
                "note": (f"q x per-audit cost {fmt(per_audit_ms)} ms; {how}; "
                         f"param_set={param_set}; status in source file="
                         f"{row.get('status')}; {BASELINE_LABEL}"),
            })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 3.1))
    for index, mode in enumerate(modes):
        entries = sorted(
            ((q, stats[(mode, q)]) for q in qs if (mode, q) in stats),
            key=lambda item: item[0],
        )
        xs = [q for q, _ in entries]
        medians = [entry["median"] * 1000.0 for _, entry in entries]
        lows = [entry["min"] * 1000.0 for _, entry in entries]
        highs = [entry["max"] * 1000.0 for _, entry in entries]
        common.band_plot(
            ax, xs, medians, lows, highs,
            PLOT_LABEL.get(mode, mode),
            common.PALETTE[0], common.MARKERS[0],
        )
    for name, per_audit_ms, label, color, dash, grey in base_lines:
        ax.plot(qs, [q * per_audit_ms for q in qs],
                color=(common.PALETTE[color] if color is not None else grey),
                linestyle=dash, linewidth=0.9, label=label, zorder=3)
    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    log_ticks(ax)
    ax.set_xlabel("audit requests q")
    ax.set_ylabel("total verification time (ms)")
    handles, labels = ax.get_legend_handles_labels()
    order = ["PQZ-Audit", "Dong et al.", "DART", "L-HCPM", "DOPIV"]
    pairs = dict(zip(labels, handles))
    fig.legend([pairs[k] for k in order], order, frameon=False, loc="lower left",
               bbox_to_anchor=(0.0, 0.0), fontsize=5.8, handlelength=3.0,
               labelspacing=0.35, ncol=3, columnspacing=0.8)
    fig.tight_layout(rect=(0, 0.12, 1, 1))
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp4b_w14.pdf"), provisional, path
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp4b_w14.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp4b_w14.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (common.load_csv rule: a group has n < 10000)")


if __name__ == "__main__":
    main()
