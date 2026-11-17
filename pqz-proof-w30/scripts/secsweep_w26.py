#!/usr/bin/env python3
"""w26 security-vs-cost driver (NEW file; edits nothing else). Drives the children of src/bin/pilot.rs (binary bin/pilot-sha3).

Question: how do proof size, bundle verification time and proof generation time change when the PROVEN (unique-decoding)
security of the STARK proofs is raised above 49 bits? Only the number of queries varies (blowup 8, grind 16, SHA3-256).
The library setting is chosen with PQZ_QUERIES in the environment of a fresh child; the default setting has no PQZ_* variable.

  python3 scripts/secsweep_w26.py env
  python3 scripts/secsweep_w26.py bundle  --cpu 10 [--rounds 6] [--warm 10] [--timed 20]
  python3 scripts/secsweep_w26.py prove   [--sizes 5000,20000] [--warm 3] [--timed 10]
  python3 scripts/secsweep_w26.py summary          (reads results/sec-w26/*.raw.csv, writes summary files; raw files are never modified)

bundle: ROUNDS rounds. In each round ONE FRESH child per setting is started (pinned with taskset to the single cpu given),
  runs WARM warm-up and TIMED timed bundle verifications (rc + auth + exec, n=1000, parse + verify), the settings interleaved
  one run each per repetition with the starting setting rotating. Timed runs per setting = ROUNDS * TIMED.
prove: one fresh child per setting (all cores, rayon), R_Exec at n = each size, WARM warm-up + TIMED timed runs, interleaved
  round-robin with a rotating start.

Raw output (appended, never edited): results/sec-w26/bundle.raw.csv, prove_n<N>.raw.csv. Each data line = driver columns +
the child's ROW line without the word ROW. Lines starting with '#' are comments (READY lines, round statistics, waits).
"""
import argparse
import csv
import os
import select
import statistics
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin", "pilot-sha3")
OUT = os.environ.get("SECSWEEP_W26_OUT") or os.path.join(ROOT, "results", "sec-w26")  # override only for smoke tests
NCPU = os.cpu_count() or 1
RUN_TIMEOUT = 300.0

# label -> PQZ_QUERIES (None = default build, no PQZ_* variable at all). Chosen from results/sec-w26/secsweep.txt.
SETTINGS = [("q40", None), ("q58", "58"), ("q78", "78"), ("q102", "102"), ("q113", "113")]

BUNDLE_HDR = "kind,n,depth,hash,queries,blowup,grind,total_s,t_rc,t_auth,t_exec,bytes_total,b_rc,b_auth,b_exec,conj,udr,ldr"
PROVE_HDR = "kind,rel,n,block,hash,queries,blowup,grind,trace_rows,trace_s,prove_s,verify_s,proof_bytes,conj,udr,ldr,vmrss_kb"
DRV_BUNDLE = "label,round,rep,phase,t_unix,load1_before,procs_running,cpu_khz,"
DRV_PROVE = "label,rep,phase,t_unix,load1_before,load1_after,memavail_kb_before,busy_cores_before,quiet_ok,"


def log(msg):
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


def loadavg():
    f = open("/proc/loadavg").read().split()
    return float(f[0]), int(f[3].split("/")[0])


def memavail_kb():
    for l in open("/proc/meminfo"):
        if l.startswith("MemAvailable:"):
            return int(l.split()[1])
    return -1


def cpu_khz(cpu):
    try:
        return int(open(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq").read())
    except Exception:
        return -1


def per_cpu_times():
    d = {}
    for l in open("/proc/stat"):
        if l.startswith("cpu") and l[3].isdigit():
            p = l.split()
            v = [int(x) for x in p[1:]]
            d[int(p[0][3:])] = (sum(v), v[3] + v[4])
    return d


def busy_cores(window=0.3):
    a = per_cpu_times()
    time.sleep(window)
    b = per_cpu_times()
    tot = sum(b[c][0] - a[c][0] for c in a)
    idle = sum(b[c][1] - a[c][1] for c in a)
    return 0.0 if tot <= 0 else NCPU * (1.0 - idle / tot)


def siblings(cpu):
    s = open(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list").read().strip()
    out = []
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def wait_load(limit=3.0, max_wait=240.0, tag=""):
    """Quiet rule: wait while the 1-minute load average is above `limit`. Returns (load1_at_start, waited_s, timed_out)."""
    t0 = time.time()
    waited = 0.0
    while loadavg()[0] > limit and waited < max_wait:
        time.sleep(3.0)
        waited = time.time() - t0
    l = loadavg()[0]
    if waited > 0:
        log(f"{tag} waited {waited:.0f}s for load1 <= {limit}; now {l}")
    return l, waited, l > limit


class Child:
    def __init__(self, label, queries, args, cpu=None, trim=False):
        self.label = label
        env = {k: v for k, v in os.environ.items() if not k.startswith("PQZ_") and k != "PILOT_TRIM"}
        if queries is not None:
            env["PQZ_QUERIES"] = queries
        if trim:
            env["PILOT_TRIM"] = "1"
        cmd = [BIN, "child"] + args
        if cpu is not None:
            cmd = ["taskset", "-c", str(cpu)] + cmd
        self.err = open(os.path.join(OUT, "child-stderr.log"), "ab")
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err, env=env)
        self.buf = b""

    def readline(self, timeout=RUN_TIMEOUT):
        deadline = time.time() + timeout
        fd = self.p.stdout.fileno()
        while b"\n" not in self.buf:
            left = deadline - time.time()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                raise TimeoutError(self.label)
            chunk = os.read(fd, 65536)
            if not chunk:
                raise EOFError(self.label)
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode()

    def ready(self):
        while True:
            l = self.readline()
            if l.startswith("READY,"):
                return l

    def run(self):
        self.p.stdin.write(b"run\n")
        self.p.stdin.flush()
        row = None
        while True:
            l = self.readline()
            if l.startswith("ROW,"):
                row = l
            elif l == "IDLE":
                return row

    def close(self):
        try:
            self.p.stdin.write(b"quit\n")
            self.p.stdin.flush()
            self.p.wait(timeout=20)
        except Exception:
            self.p.kill()
        try:
            self.err.close()
        except Exception:
            pass


def cmd_env(cpu):
    os.makedirs(OUT, exist_ok=True)
    model = ""
    for l in open("/proc/cpuinfo"):
        if l.startswith("model name"):
            model = l.split(":", 1)[1].strip()
            break

    def rd(p):
        try:
            return open(p).read().strip()
        except Exception:
            return "n/a"

    lines = [f"date: {time.strftime('%Y-%m-%d %H:%M:%S %z')}", f"cpu: {model}; logical cores: {NCPU}"]
    for p in ["/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "/sys/devices/system/cpu/intel_pstate/status",
              "/sys/devices/system/cpu/intel_pstate/no_turbo", "/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference"]:
        lines.append(f"{p}: {rd(p)}")
    if cpu is not None:
        lines.append(f"pinned cpu for bundle timing: {cpu} (thread siblings {siblings(cpu)}), cpuinfo_max_freq kHz "
                     f"{rd(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq')}")
    lines.append("kernel: " + subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip())
    lines.append("loadavg now: " + open("/proc/loadavg").read().strip())
    lines.append(f"MemAvailable kB: {memavail_kb()}")
    sha = subprocess.run(["sha256sum", BIN], capture_output=True, text=True).stdout.split()[0]
    lines.append(f"binary: bin/pilot-sha3 sha256 {sha[:16]} (built 2026-11-10 17:25, not rebuilt by w26)")
    with open(os.path.join(OUT, "env.txt"), "a") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def cmd_bundle(a):
    os.makedirs(OUT, exist_ok=True)
    cpu = a.cpu
    sib = [c for c in siblings(cpu) if c != cpu]
    path = os.path.join(OUT, "bundle.raw.csv")
    new = not os.path.exists(path)
    labels = [s[0] for s in SETTINGS]
    q = dict(SETTINGS)
    K = len(labels)
    with open(path, "a") as f:
        if new:
            f.write(DRV_BUNDLE + BUNDLE_HDR + "\n")
        f.write(f"# bundle run: cpu {cpu} siblings {sib} rounds {a.rounds} warm {a.warm} timed/round {a.timed} start {time.strftime('%F %T')}\n")
        for rnd in range(a.rounds):
            l1, waited, to = wait_load(tag=f"round {rnd}")
            f.write(f"# ROUND {rnd} start load1={l1} waited_s={waited:.0f} wait_timed_out={int(to)} busy_cores={busy_cores():.2f}\n")
            f.flush()
            # fresh child per setting; the start order rotates with the round
            order0 = labels[rnd % K:] + labels[:rnd % K]
            kids = {}
            for lab in order0:
                kids[lab] = Child(lab, q[lab], ["bundle", "n=1000", "depth=10"], cpu=cpu)
                r = kids[lab].ready()
                f.write(f"# READY round {rnd} {lab}: {r}\n")
            f.flush()
            t_a = per_cpu_times()
            for rep in range(a.warm + a.timed):
                phase = "warm" if rep < a.warm else "timed"
                order = labels[(rep + rnd) % K:] + labels[:(rep + rnd) % K]
                for lab in order:
                    l1, pr = loadavg()
                    khz = cpu_khz(cpu)
                    row = kids[lab].run()
                    if row is None:
                        f.write(f"# NOROW {lab} round {rnd} rep {rep}\n")
                        continue
                    f.write(f"{lab},{rnd},{rep},{phase},{time.time():.2f},{l1},{pr},{khz},{row[4:]}\n")
                f.flush()
            t_b = per_cpu_times()

            def busy(c):
                return 100.0 * (1 - (t_b[c][1] - t_a[c][1]) / max(1, t_b[c][0] - t_a[c][0]))
            others = [c for c in t_a if c != cpu]
            tot_o = sum(t_b[c][0] - t_a[c][0] for c in others)
            idle_o = sum(t_b[c][1] - t_a[c][1] for c in others)
            f.write(f"# ROUND {rnd} end load1={loadavg()[0]} pinned_cpu_busy_pct={busy(cpu):.1f} "
                    f"sibling_busy_pct={';'.join(f'{busy(c):.1f}' for c in sib)} other_cpus_avg_busy_pct={100*(1-idle_o/max(1,tot_o)):.1f}\n")
            f.flush()
            for k in kids.values():
                k.close()
            log(f"bundle round {rnd + 1}/{a.rounds} done (load1 {loadavg()[0]})")


def cmd_prove(a):
    os.makedirs(OUT, exist_ok=True)
    labels = [s[0] for s in SETTINGS]
    q = dict(SETTINGS)
    K = len(labels)
    for n in [int(x) for x in a.sizes.split(",")]:
        path = os.path.join(OUT, f"prove_n{n}.raw.csv")
        new = not os.path.exists(path)
        l1, waited, to = wait_load(tag=f"prove n={n}")
        kids = {}
        with open(path, "a") as f:
            if new:
                f.write(DRV_PROVE + PROVE_HDR + "\n")
            f.write(f"# prove rel=exec n={n} warm {a.warm} timed {a.timed} start {time.strftime('%F %T')} load1={l1} "
                    f"waited_s={waited:.0f} wait_timed_out={int(to)} MemAvailable_kB={memavail_kb()}\n")
            for lab in labels:
                kids[lab] = Child(lab, q[lab], ["prove", "rel=exec", f"n={n}", "block=100"], trim=True)
            for lab in labels:
                f.write(f"# READY {lab}: {kids[lab].ready()}\n")
            f.flush()
            for rep in range(a.warm + a.timed):
                phase = "warm" if rep < a.warm else "timed"
                order = labels[rep % K:] + labels[:rep % K]
                for lab in order:
                    t0 = time.time()
                    b = busy_cores()
                    while b >= 5.0 and time.time() - t0 < 20:
                        time.sleep(1.0)
                        b = busy_cores()
                    ok = 1 if b < 5.0 else 0
                    lb, mem = loadavg()[0], memavail_kb()
                    row = kids[lab].run()
                    la = loadavg()[0]
                    if row is None:
                        f.write(f"# NOROW {lab} rep {rep}\n")
                        continue
                    f.write(f"{lab},{rep},{phase},{time.time():.1f},{lb},{la},{mem},{b:.2f},{ok},{row[4:]}\n")
                    f.flush()
                log(f"prove n={n}: rep {rep + 1}/{a.warm + a.timed} done (load1 {loadavg()[0]})")
            for k in kids.values():
                k.close()


# ---------------------------------------------------------------------------------------------------------------
def read_raw(path):
    rows, hdr = [], None
    for line in open(path):
        if line.startswith("#"):
            continue
        if hdr is None:
            hdr = next(csv.reader([line]))
            continue
        rows.append(dict(zip(hdr, next(csv.reader([line])))))
    return rows


def med(v):
    return statistics.median(v)


def cmd_summary(a):
    out = []
    labels = [s[0] for s in SETTINGS]
    # ---- bundle
    bp = os.path.join(OUT, "bundle.raw.csv")
    sumrows = []
    if os.path.exists(bp):
        rows = [r for r in read_raw(bp) if r["phase"] == "timed"]
        out.append("BUNDLE VERIFICATION (rc+auth+exec, n=1000, parse+verify), pinned single core")
        by = {lab: [r for r in rows if r["label"] == lab] for lab in labels}
        tot = {lab: [float(r["total_s"]) * 1000 for r in by[lab]] for lab in labels}
        rounds = sorted({int(r["round"]) for r in rows})
        # per-round medians for the ratio range
        rmed = {lab: {rd: med([float(r["total_s"]) * 1000 for r in by[lab] if int(r["round"]) == rd]) for rd in rounds} for lab in labels}
        # paired per-repetition ratio (same round and rep)
        key = lambda r: (int(r["round"]), int(r["rep"]))
        base = {key(r): float(r["total_s"]) for r in by["q40"]}
        for lab in labels:
            if not by[lab]:
                continue
            r0 = by[lab][0]
            pr = [float(r["total_s"]) / base[key(r)] for r in by[lab] if key(r) in base]
            rr = [rmed[lab][rd] / rmed["q40"][rd] for rd in rounds]
            m = med(tot[lab])
            s = dict(label=lab, queries=r0["queries"], conj=r0["conj"], udr=r0["udr"], ldr=r0["ldr"], n_timed=len(tot[lab]),
                     median_ms=m, min_ms=min(tot[lab]), max_ms=max(tot[lab]), ratio_of_medians=m / med(tot["q40"]),
                     paired_ratio_median=med(pr), paired_ratio_min=min(pr), paired_ratio_max=max(pr),
                     round_ratio_min=min(rr), round_ratio_max=max(rr),
                     t_rc_ms=med([float(r["t_rc"]) * 1000 for r in by[lab]]), t_auth_ms=med([float(r["t_auth"]) * 1000 for r in by[lab]]),
                     t_exec_ms=med([float(r["t_exec"]) * 1000 for r in by[lab]]),
                     bytes_total=r0["bytes_total"], b_rc=r0["b_rc"], b_auth=r0["b_auth"], b_exec=r0["b_exec"],
                     load1_min=min(float(r["load1_before"]) for r in by[lab]), load1_max=max(float(r["load1_before"]) for r in by[lab]))
            sumrows.append(s)
            out.append(f"{lab}: q={s['queries']} udr={s['udr']} ldr={s['ldr']} conj={s['conj']} n={s['n_timed']} median {m:.3f} ms "
                       f"(min {s['min_ms']:.3f} max {s['max_ms']:.3f}) ratio {s['ratio_of_medians']:.2f} paired {s['paired_ratio_median']:.2f} "
                       f"({s['paired_ratio_min']:.2f}-{s['paired_ratio_max']:.2f}) per-round ratio {s['round_ratio_min']:.2f}-{s['round_ratio_max']:.2f} "
                       f"bytes {s['bytes_total']} (rc {s['b_rc']} auth {s['b_auth']} exec {s['b_exec']}) load1 {s['load1_min']}-{s['load1_max']}")
        with open(os.path.join(OUT, "bundle.summary.csv"), "w", newline="") as f:
            if sumrows:
                w = csv.DictWriter(f, fieldnames=list(sumrows[0].keys()))
                w.writeheader()
                w.writerows(sumrows)
    # ---- prove
    for n in (5000, 20000):
        pp = os.path.join(OUT, f"prove_n{n}.raw.csv")
        if not os.path.exists(pp):
            continue
        rows = [r for r in read_raw(pp) if r["phase"] == "timed"]
        out.append(f"PROVE R_Exec n={n}: trace+prove (trace_s + prove_s), all cores")
        by = {lab: sorted([r for r in rows if r["label"] == lab], key=lambda r: int(r["rep"])) for lab in labels}
        tm = lambda r: (float(r["trace_s"]) + float(r["prove_s"])) * 1000
        base = {int(r["rep"]): tm(r) for r in by["q40"]}
        ps = []
        for lab in labels:
            if not by[lab]:
                continue
            v = [tm(r) for r in by[lab]]
            pr = [tm(r) / base[int(r["rep"])] for r in by[lab] if int(r["rep"]) in base]
            r0 = by[lab][0]
            m = med(v)
            s = dict(label=lab, n=n, queries=r0["queries"], conj=r0["conj"], udr=r0["udr"], ldr=r0["ldr"], n_timed=len(v), median_ms=m,
                     min_ms=min(v), max_ms=max(v), ratio_of_medians=m / med([tm(r) for r in by["q40"]]), paired_ratio_median=med(pr),
                     paired_ratio_min=min(pr), paired_ratio_max=max(pr), proof_bytes=r0["proof_bytes"],
                     verify_ms_allcores=med([float(r["verify_s"]) * 1000 for r in by[lab]]),
                     load1_min=min(float(r["load1_before"]) for r in by[lab]), load1_max=max(float(r["load1_before"]) for r in by[lab]),
                     quiet_ok_runs=sum(int(r["quiet_ok"]) for r in by[lab]))
            ps.append(s)
            out.append(f"{lab}: q={s['queries']} udr={s['udr']} n={s['n_timed']} median {m:.0f} ms (min {s['min_ms']:.0f} max {s['max_ms']:.0f}) "
                       f"ratio {s['ratio_of_medians']:.2f} paired {s['paired_ratio_median']:.2f} ({s['paired_ratio_min']:.2f}-{s['paired_ratio_max']:.2f}) "
                       f"bytes {s['proof_bytes']} quiet_ok {s['quiet_ok_runs']}/{s['n_timed']} load1 {s['load1_min']}-{s['load1_max']}")
        with open(os.path.join(OUT, f"prove_n{n}.summary.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(ps[0].keys()))
            w.writeheader()
            w.writerows(ps)
    txt = "\n".join(out) + "\n"
    with open(os.path.join(OUT, "summary.txt"), "w") as f:
        f.write(txt)
    print(txt)


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd")
    e = sp.add_parser("env")
    e.add_argument("--cpu", type=int, default=None)
    b = sp.add_parser("bundle")
    b.add_argument("--cpu", type=int, required=True)
    b.add_argument("--rounds", type=int, default=6)
    b.add_argument("--warm", type=int, default=10)
    b.add_argument("--timed", type=int, default=20)
    p = sp.add_parser("prove")
    p.add_argument("--sizes", default="5000,20000")
    p.add_argument("--warm", type=int, default=3)
    p.add_argument("--timed", type=int, default=10)
    sp.add_parser("summary")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    if a.cmd == "env":
        cmd_env(a.cpu)
    elif a.cmd == "bundle":
        cmd_bundle(a)
    elif a.cmd == "prove":
        cmd_prove(a)
    elif a.cmd == "summary":
        cmd_summary(a)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
