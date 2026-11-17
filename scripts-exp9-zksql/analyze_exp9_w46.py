# w46 copy of analyze_exp9.py (w36b): the only change is that the PQZ group kind carries '-p2r' for fmt=p2r rows (whole mode), so old and packed rows are never mixed.
#!/usr/bin/env python3
"""Exp 9 (w36) analysis. stdlib only; run as:  python3 -I analyze_exp9.py <results dir> [<results dir> ...] [--csv out.csv]
Reads
  PQZ   : every line "ROW k=v ..." in files named *.rows, *.rows.txt or rows_pqz*.txt under the given folders (status=ok rows; status=FAILED rows are counted and listed)
  ZKSQL : <dir>/zksql/N<N>_<layout>/run<NN>_timed/{alice.out,alice.err,bob.out,ok}   (warm runs are ignored; a run with ok != 1 is counted as failed and NOT used)
Per group: runs, median, p90, min; NOISY = p90 / min > 1.15 (applies to the time columns of the group).
Two ratios per row, both = ZKSQL / PQZ (> 1 means PQZ is faster); WIN > 1.05, LOSE < 0.95, else TIE; every row is printed, losses included:
  A (the w34 M6 convention, favours ZKSQL): ZKSQL query_s (RESULT_QUERY_S: running the plan on the committed table)   / PQZ prove_s (per-query prover work, no R_Auth)
  B (everything the party does per request): ZKSQL commit_s + query_s + teardown_s (table read from PostgreSQL + VOLE commit + plan + finalize/cheat check; the one-off
    VOLE/OT setup RESULT_SETUP_S is excluded)   / PQZ prove_incl_auth_s (per-query prover work + the R_Auth proof)
PQZ ingest (chunk proofs, AA check, Bloom filters) is never part of either ratio; it is printed in its own column (cover mode).
Result check: every PQZ row must have (result_count, result_sum) == (ref_count, ref_sum), and across systems the reference of (N, layout) must be the same; ZKSQL ok = 1
already means its revealed (count, sum) equal the PQZ reference (exp9_run_one.sh). Any difference is printed as RESULT MISMATCH and the exit code is 1.
LAPTOP output must be labelled by the caller: this script prints the label given with --label (default none)."""
import glob, math, os, re, statistics, sys

NOISY = 1.15
WIN, LOSE = 1.05, 0.95


def med(v): return statistics.median(v) if v else float("nan")
def p90(v):
    if not v: return float("nan")
    s = sorted(v); return s[min(len(s) - 1, math.ceil(0.9 * (len(s) - 1)))]
def fnum(x, d=3): return "nan" if x != x else ("%.*f" % (d, x))


def parse_rows(paths):
    ok, bad = [], []
    for p in paths:
        for line in open(p, errors="replace"):
            if not line.startswith("ROW "): continue
            d = dict(kv.split("=", 1) for kv in line.split()[1:] if "=" in kv)
            d["_file"] = p
            (ok if d.get("status") == "ok" else bad).append(d)
    return ok, bad


def read_zk(root):
    runs, failed = {}, []
    # cloud layout: zksql/N<N>_<layout>/run<NN>_timed ; laptop smoke layout: results/n<N>_<layout>/run<i>
    dirs = sorted(glob.glob(os.path.join(root, "zksql", "N*_*", "run*_timed"))) + sorted(glob.glob(os.path.join(root, "results", "n*_*", "run*")))
    for d in dirs:
        cell = os.path.basename(os.path.dirname(d)); m = re.match(r"[Nn](\d+)_(\w+)", cell)
        n, lay = int(m.group(1)), m.group(2)
        try: okline = open(os.path.join(d, "ok")).read().strip()
        except OSError: okline = "0 no_ok_file"
        if not okline.startswith("1"):
            failed.append((cell, os.path.basename(d), okline)); continue
        def get(f, key):
            for l in open(os.path.join(d, f), errors="replace"):
                if l.startswith(key + " "): return float(l.split()[1])
            return float("nan")
        def tm(f):
            for l in open(os.path.join(d, f), errors="replace"):
                if l.startswith("TM "):
                    return dict(kv.split("=", 1) for kv in l.split()[2:] if "=" in kv)
            return {}
        a = tm("alice.err")
        r = dict(query=get("alice.out", "RESULT_QUERY_S"), commit=get("alice.out", "RESULT_COMMIT_S"), teardown=get("alice.out", "RESULT_TEARDOWN_S"),
                 setup=get("alice.out", "RESULT_SETUP_S"), sent=get("alice.out", "RESULT_TOTAL_SENT_BYTES_PRE_FINALIZE"),
                 rss=float(a.get("maxrss_kb", "nan")), wall=float(a.get("wall_s", "nan")))
        r["full"] = r["commit"] + r["query"] + r["teardown"]
        runs.setdefault((n, lay), []).append(r)
    return runs, failed


def label(x):
    if x != x: return "n/a"
    return "WIN" if x > WIN else ("LOSE" if x < LOSE else "TIE")


def main():
    args = [a for a in sys.argv[1:]]
    csv = None; lab = ""
    if "--csv" in args: i = args.index("--csv"); csv = args[i + 1]; del args[i:i + 2]
    if "--label" in args: i = args.index("--label"); lab = args[i + 1]; del args[i:i + 2]
    if not args:
        print(__doc__); return 2
    files = []
    for d in args:
        for pat in ("*.rows", "*.rows.txt", "rows_pqz*.txt"):
            files += glob.glob(os.path.join(d, "**", pat), recursive=True)
    files = sorted(set(files))
    pq, pq_bad = parse_rows(files)
    zk, zk_failed = {}, []
    for d in args:
        z, f = read_zk(d)
        for k, v in z.items(): zk.setdefault(k, []).extend(v)
        zk_failed += f
    if lab: print("*** %s ***" % lab)
    print("PQZ rows ok: %d, FAILED: %d (files: %d); ZKSQL ok runs: %d, failed runs: %d" % (len(pq), len(pq_bad), len(files), sum(len(v) for v in zk.values()), len(zk_failed)))
    rc = 0
    for r in pq_bad: print("PQZ FAILED  mode=%s n=%s %s preset=%s zk=%s threads_env=%s: %s" % (r.get("mode"), r.get("n"), r.get("layout"), r.get("preset"), r.get("zk"), r.get("rayon_threads_env"), r.get("msg", "")))
    for c, run, why in zk_failed: print("ZKSQL FAILED %s %s: %s" % (c, run, why))
    # result equality
    for r in pq:
        if (r.get("result_count"), r.get("result_sum")) != (r.get("ref_count"), r.get("ref_sum")):
            print("RESULT MISMATCH (PQZ) %s" % {k: r.get(k) for k in ("mode", "n", "layout", "preset", "zk", "fmt", "run")}); rc = 1
    refs = {}
    for r in pq: refs.setdefault((int(r["n"]), r["layout"]), set()).add((r["ref_count"], r["ref_sum"]))
    for k, v in refs.items():
        if len(v) != 1: print("RESULT MISMATCH: reference differs between runs for N=%d %s: %s" % (k[0], k[1], v)); rc = 1
    if rc == 0: print("results: every PQZ run equals its plain reference; every counted ZKSQL run (ok=1) equals the same reference")

    # group PQZ
    groups = {}
    for r in pq:
        key = (int(r["n"]), r["layout"], r["preset"], "zk" if r["zk"] == "1" else "plain", "1" if r.get("rayon_threads_env") == "1" else "all", r["mode"] + ("-p2r" if r.get("fmt") == "p2r" else ""))
        groups.setdefault(key, []).append(r)
    def col(rs, k): return [float(r[k]) for r in rs if k in r]
    hdr = ("N", "layout", "preset", "mode", "thr", "kind", "runs", "prove_s", "p90/min", "NOISY", "incl_auth", "openings", "trace", "prove", "verify_ms", "KB_req", "blocks", "RSS_MB",
           "ingest_s", "ZKq_s", "ZKfull_s", "ZKruns", "A:ZKq/PQZ", "A", "B:ZKfull/PQZ+auth", "B")
    print("\n" + "\t".join(hdr)); rows = []
    for key in sorted(groups, key=lambda k: (k[0], k[1], k[5], k[3], k[2], k[4])):
        n, lay, pre, mode, thr, kind = key; rs = groups[key]
        ps = col(rs, "prove_s"); pa = col(rs, "prove_incl_auth_s")
        noisy = (p90(ps) / min(ps) > NOISY) if ps and min(ps) > 0 else False
        z = zk.get((n, lay), [])
        zq = med([x["query"] for x in z]); zf = med([x["full"] for x in z])
        ra = zq / med(ps) if ps else float("nan"); rb = zf / med(pa) if pa else float("nan")
        row = (n, lay, pre, mode, thr, kind, len(rs), fnum(med(ps)), fnum(p90(ps) / min(ps) if ps and min(ps) > 0 else float("nan"), 2), "NOISY" if noisy else "-", fnum(med(pa)),
               fnum(med(col(rs, "openings_s"))), fnum(med(col(rs, "exec_trace_s"))), fnum(med(col(rs, "exec_prove_s"))), fnum(med(col(rs, "verify_ms_med")), 2),
               fnum(med(col(rs, "bytes_requester")) / 1024, 1), "%s/%s" % (rs[0].get("retained_blocks"), rs[0].get("blocks_total")), fnum(max(col(rs, "peak_rss_process_kb")) / 1024, 0),
               fnum(med(col(rs, "ingest_total_s")), 2) if kind.startswith("cover") else "-", fnum(zq), fnum(zf), len(z), fnum(ra, 2), label(ra), fnum(rb, 2), label(rb))
        rows.append(row); print("\t".join(str(x) for x in row))
    # ZKSQL alone
    print("\nZKSQL alone (Alice, single thread, own core; times in s; noisy = p90/min of query_s > %.2f)" % NOISY)
    print("N\tlayout\truns\tquery_s\tp90/min\tNOISY\tcommit_s\tteardown_s\tsetup_s(excluded)\tfull_s\tMB_sent\tRSS_MB")
    for (n, lay) in sorted(zk):
        z = zk[(n, lay)]; q = [x["query"] for x in z]
        print("\t".join(str(x) for x in (n, lay, len(z), fnum(med(q)), fnum(p90(q) / min(q) if min(q) > 0 else float("nan"), 2), "NOISY" if min(q) > 0 and p90(q) / min(q) > NOISY else "-",
              fnum(med([x["commit"] for x in z])), fnum(med([x["teardown"] for x in z])), fnum(med([x["setup"] for x in z])), fnum(med([x["full"] for x in z])),
              fnum(med([x["sent"] for x in z]) / 1e6, 2), fnum(max(x["rss"] for x in z) / 1024, 0))))
    cnt = {"WIN": 0, "TIE": 0, "LOSE": 0, "n/a": 0}
    for r in rows: cnt[r[23]] += 1
    print("\nA-ratio summary over %d rows: WIN %d, TIE %d, LOSE %d, n/a %d (ZKSQL data missing for that N/layout)" % (len(rows), cnt["WIN"], cnt["TIE"], cnt["LOSE"], cnt["n/a"]))
    if csv:
        with open(csv, "w") as f:
            f.write(",".join(hdr) + "\n")
            for r in rows: f.write(",".join(str(x) for x in r) + "\n")
    return rc


sys.exit(main())
