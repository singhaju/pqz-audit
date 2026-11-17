"""Figure exp1 (w14, minimal): PQZ-Audit query time versus N plus ONE flat line per baseline scheme.

Copy of fig_exp1_w14.py with the same numbers, but only these lines:
  - PQZ-Audit (measured, band = min-max).
  - Dong et al.: proof-generation formula, c=100, s=3, summed from unit costs we measured.
  - DOPIV audit: professor's table cell, constant 1, c=350, m=16384, T_M=zq_mul.
  - DART audit: professor's table cell, constant 1, z=100, N=40.
  - L-HCPM audit, cache hit: decryption time REPORTED by the paper (Apple M3) + our SHA3-256 cost.
The paper caption states the source of each line.  Writes fig_exp1_w14.{pdf,png,csv}
into journal2/figures/results-w14/ by default.
"""

from __future__ import annotations

import argparse
import csv
import os

from matplotlib.ticker import LogLocator

import common

DEFAULT_OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))),
    "journal2", "figures", "results-w14",
)
FIELDS = [
    "figure", "metric", "series", "x", "n_runs", "median", "min", "max",
    "unit", "status", "provisional", "note",
]
BASELINE_LABEL = "computed by us from the formula of the original paper (checked against the paper) and unit costs measured by us"
DONG_S = 3
DONG_C = (100,)

PROF_LABEL = "professor's table, constant 1, our parameters"
REPORTED_LABEL = "decryption reported by the L-HCPM paper (Apple M3) + our SHA3-256 cost"
# New baseline lines: (series name, scheme, phase, param_set in baseline_costs_profbigo.csv,
#                      legend label, colour index in common.PALETTE, dash pattern)
PROF_LINES = (
    ("DOPIV audit c=350 m=16384 (T_M=zq_mul)", "DOPIV", "audit",
     "c=350;m=16384;n=256;q=4294967291;tm=zq_mul",
     "DOPIV", 4, (0, (4, 4))),
    ("DART audit z=100 N=40", "DART", "audit", "z=100;N=40;tf=fr_mul",
     "DART", 2, (0, (2.5, 1.2))),
    ("L-HCPM audit cache hit", "L-HCPM", "audit", "cache_hit",
     "L-HCPM", 3, (0, (6, 1.5, 1, 1.5, 1, 1.5))),
)


def strip_source(fig, pdf):
    for text in fig.texts:
        if text.get_text().startswith("source:"):
            text.remove()
    fig.savefig(pdf)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="?", default=None, help="exp1 CSV")
    parser.add_argument("--baselines", default=None, help="baseline_costs.csv")
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
        return [
            {key: (value.strip('"') if isinstance(value, str) else value)
             for key, value in row.items()}
            for row in csv.DictReader(handle)
        ]


def main():
    args = parse_args()
    path = args.csv or common.default_csv("results/full-1/exp1/exp1.csv")
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
        required=("series", "n", "time_ns", "warmup"),
        min_runs=args.min_runs,
    )
    rows = [row for row in rows if row.get("series") == "sigma1pct"]
    if not rows:
        raise SystemExit("refusing: no series=sigma1pct rows")

    stats = common.group_stats(rows, ("n",), value="time_ns")
    ns = sorted(key[0] for key in stats if key[0] is not None)
    for n in ns:
        if stats[(n,)]["n"] < args.min_runs:
            raise SystemExit(
                f"refusing: N={n} has {stats[(n,)]['n']} timed runs"
            )
    provisional = meta["provisional"]

    baselines = read_baselines(baseline_path)
    prof_rows = read_baselines(prof_path)
    dong = []
    for row in baselines:
        scheme = row.get("scheme", "")
        phase = row.get("phase", "")
        if scheme == "Dong et al." and phase == "proof":
            if row.get("status") != "full":
                continue
            params = row.get("param_set", "")
            fields = dict(
                part.split("=", 1) for part in params.split(";") if "=" in part
            )
            if int(fields.get("s", "0")) != DONG_S:
                continue
            dong.append({
                "c": int(fields.get("c", "0")),
                "time_ms": float(row["time_ns"]) / 1e6,
                "param_set": params,
            })
    found = sorted(item["c"] for item in dong)
    for c in DONG_C:
        if c not in found:
            raise SystemExit(f"refusing: no Dong proof row for c={c}, s={DONG_S}")

    rows_out = []
    for n in ns:
        entry = stats[(n,)]
        rows_out.append({
            "figure": "exp1_w14", "metric": "query_time",
            "series": "sigma1pct (pqz)", "x": n, "n_runs": entry["n"],
            "median": fmt(entry["median"] / 1e6),
            "min": fmt(entry["min"] / 1e6),
            "max": fmt(entry["max"] / 1e6),
            "unit": "ms", "status": "plotted",
            "provisional": int(provisional),
            "note": "clustered layout, P4, sigma=1%",
        })
    for item in sorted(dong, key=lambda entry: entry["c"]):
        if item["c"] in DONG_C:
            status = "plotted"
            note = (f"Dong et al. proof-generation formula (same operation "
                    f"counts as the audit cell), c={item['c']}, s={DONG_S}; "
                    + BASELINE_LABEL + "; fixed parameters, no N dependence; "
                    + f"param_set={item['param_set']}")
        else:
            continue
        rows_out.append({
            "figure": "exp1_w14", "metric": "baseline_time",
            "series": f"Dong et al. proof c={item['c']} s={DONG_S}",
            "x": "", "n_runs": 0,
            "median": fmt(item["time_ms"]), "min": "", "max": "",
            "unit": "ms", "status": status,
            "provisional": int(provisional), "note": note,
        })
    # Baselines from the professor's table (constant 1, our parameters) and the
    # L-HCPM reported value; flat lines, independent of N.
    def find_prof(scheme, phase, param_set):
        for row in prof_rows:
            if (row.get("scheme"), row.get("phase"),
                    row.get("param_set")) == (scheme, phase, param_set):
                return row
        raise SystemExit(
            f"refusing: no row {scheme}/{phase}/{param_set} in {prof_path}")

    prof_lines = []
    drawn = set()
    for name, scheme, phase, param_set, label, color, dash in PROF_LINES:
        row = find_prof(scheme, phase, param_set)
        drawn.add((scheme, phase, param_set))
        time_ms = float(row["time_ns"]) / 1e6
        prof_lines.append((name, time_ms, label, color, dash))
        rows_out.append({
            "figure": "exp1_w14", "metric": "baseline_time",
            "series": name, "x": "", "n_runs": 0,
            "median": fmt(time_ms), "min": "", "max": "",
            "unit": "ms", "status": "plotted",
            "provisional": int(provisional),
            "note": (f"flat line, no N dependence; formula {row['formula_text']}; "
                     f"values used: {row['values_used']}; source: {row['source']}; "
                     f"status in profbigo file: {row['status']}; {row['note']}"),
        })

    plt = common.setup_matplotlib()
    plt.rcParams.update({
        "font.size": 7, "axes.labelsize": 7, "axes.titlesize": 7.5,
        "legend.fontsize": 6.2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    })
    directory = common.out_dir(args.out)
    fig, ax = plt.subplots(figsize=(3.4, 3.3))
    common.band_plot(
        ax, ns,
        [stats[(n,)]["median"] / 1e6 for n in ns],
        [stats[(n,)]["min"] / 1e6 for n in ns],
        [stats[(n,)]["max"] / 1e6 for n in ns],
        "PQZ-Audit", common.PALETTE[0], "o",
    )
    for item in sorted(dong, key=lambda entry: entry["c"]):
        if item["c"] not in DONG_C:
            continue
        ax.axhline(item["time_ms"], color="0.30", linestyle=(0, (1, 3)),
                   linewidth=0.9, label="Dong et al.", zorder=3)
    for name, time_ms, label, color, dash in prof_lines:
        ax.axhline(time_ms, color=common.PALETTE[color], linestyle=dash,
                   linewidth=0.9, label=label, zorder=2)
    ax.set_xscale("log")
    ax.set_yscale("log")
    common.log_axes(ax)
    log_ticks(ax)
    ax.set_ylim(0.006, 400)
    ax.set_xlabel("N (records)")
    ax.set_ylabel("query time (ms)")
    handles, labels = ax.get_legend_handles_labels()
    order = ["PQZ-Audit", "Dong et al.", "DART", "L-HCPM", "DOPIV"]
    pairs = dict(zip(labels, handles))
    fig.legend([pairs[k] for k in order], order, frameon=False, loc="lower left",
               bbox_to_anchor=(0.01, 0.0), fontsize=5.8, handlelength=3.0,
               labelspacing=0.35, ncol=3, columnspacing=0.8)
    fig.tight_layout(rect=(0, 0.12, 1, 1))
    pdf = common.finish(
        fig, os.path.join(directory, "fig_exp1_w14.pdf"),
        provisional, path,
    )
    strip_source(fig, pdf)
    fig.savefig(os.path.join(directory, "fig_exp1_w14.png"), dpi=200)
    plt.close(fig)
    csv_path = os.path.join(directory, "fig_exp1_w14.csv")
    common.save_csv(csv_path, FIELDS, rows_out)
    print(f"wrote {pdf}")
    print(f"wrote {csv_path}")
    if provisional:
        print("provisional=True (common.load_csv rule: a group has n < 10000)")


if __name__ == "__main__":
    main()
