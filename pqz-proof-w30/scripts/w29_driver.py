#!/usr/bin/env python3
"""w29 matrix driver (NEW file; edits nothing else). Drives the children of src/bin/w29.rs (binaries bin/w29-sha3, bin/w29-blake3).

Settings (prove):  S0 = SHA3 single   S1 = Blake3 single   S2 = Blake3 + linked chunks   S3 = SHA3 + linked chunks
Proof options are the library default (40 queries, blowup 8, grind 16); no PQZ_* variable is passed to any child.

  python3 scripts/w29_driver.py env
  python3 scripts/w29_driver.py prove   [--rels exec,rc] [--sizes 5000,10000,20000,50000,100000] [--block 100] [--warm 3] [--timed 10]
  python3 scripts/w29_driver.py verify  [--cpu 10] [--rounds 1] [--warm 10] [--timed 25] [--kinds bundle3,pair2,rc1,execchunk,execsingle] [--big-n 50000]
  python3 scripts/w29_driver.py summary         (reads <OUT>/*.raw.csv, writes summary files; raw files are never modified)

prove : for every (rel, N_Q) ONE FRESH child per setting (all cores, rayon), WARM warm-up + TIMED timed runs, the four settings
        interleaved round-robin (one run each per repetition) with the starting setting rotating. Timing columns: trace_s (trace
        building, summed over chunks) and prove_s (proving only, summed over chunks); the verify_s column is information only.
verify: for every kind, a FRESH child per hash (pinned with taskset to --cpu), WARM warm-up + TIMED timed runs per process, the two
        hashes interleaved with a rotating start; --rounds R repeats this with fresh processes (the brief asks for one round).
        kinds: bundle3 = rc+auth+exec single at N_Q=1000 (block 100), pair2 = auth+exec single at 1000, rc1 = rc alone at 1000,
        execchunk / execsingle = R_Exec at --big-n (default 50000, --block, default 100), chunked (<= 4 chunks) / single.

The load average is read before each child is started (comment line '# START ...') and before each run (column load1_before).
Raw output (appended, never edited): <OUT>/prove_<rel>_n<N>.raw.csv, <OUT>/verify_<kind>.raw.csv. Lines starting with '#' are comments.
OUT = results/w29 by default; the environment variable W29_OUT overrides it (used for smoke runs outside results/).
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
BINS = {"sha3": os.path.join(ROOT, "bin", "w29-sha3"), "blake3": os.path.join(ROOT, "bin", "w29-blake3")}
OUT = os.environ.get("W29_OUT") or os.path.join(ROOT, "results", "w29")
NCPU = os.cpu_count() or 1
RUN_TIMEOUT = 900.0

# label -> (hash, mode)
SETTINGS = [("S0", "sha3", "single"), ("S1", "blake3", "single"), ("S2", "blake3", "linked"), ("S3", "sha3", "linked")]

# child ROW line without the word ROW
PROVE_HDR = ("row,rel,n,block,mode,hash,queries,blowup,grind,chunks,rows,rows_each,trace_s,prove_s,verify_s,proof_bytes,"
             "conj,udr,ldr,vmrss_kb")
VERIFY_HDR = "row,kind,n,block,hash,queries,blowup,grind,n_proofs,total_s,bytes_total,sizes,conj,udr,ldr"
DRV_PROVE = "label,rep,phase,t_unix,load1_before,load1_after,memavail_kb_before,busy_cores_before,quiet_ok,"
DRV_VERIFY = "label,hashsel,round,rep,phase,t_unix,load1_before,procs_running,cpu_khz,"
VERIFY_KINDS = ["bundle3", "pair2", "rc1", "execchunk", "execsingle"]


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
    def __init__(self, label, hash_, args, cpu=None, trim=False):
        self.label = label
        env = {k: v for k, v in os.environ.items() if not k.startswith("PQZ_") and k != "PILOT_TRIM"}
        if trim:
            env["PILOT_TRIM"] = "1"
        cmd = [BINS[hash_], "child"] + args
        if cpu is not None:
            cmd = ["taskset", "-c", str(cpu)] + cmd
        self.load_at_start = loadavg()[0]
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
            self.p.wait(timeout=30)
        except Exception:
            self.p.kill()
        try:
            self.err.close()
        except Exception:
            pass


def sha256(path):
    try:
        return subprocess.run(["sha256sum", path], capture_output=True, text=True).stdout.split()[0]
    except Exception:
        return "n/a"


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

    def run(c):
        try:
            return subprocess.run(c, capture_output=True, text=True).stdout.strip()
        except Exception:
            return "n/a"

    lines = [f"date: {time.strftime('%Y-%m-%d %H:%M:%S %z')}", f"cpu: {model}; logical cores: {NCPU}"]
    for p in ["/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "/sys/devices/system/cpu/intel_pstate/status",
              "/sys/devices/system/cpu/intel_pstate/no_turbo", "/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference"]:
        lines.append(f"{p}: {rd(p)}")
    if cpu is not None:
        lines.append(f"pinned cpu for verify timing: {cpu} (thread siblings {siblings(cpu)}), cpuinfo_max_freq kHz "
                     f"{rd(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq')}")
    lines.append("kernel: " + run(["uname", "-r"]))
    lines.append("rustc: " + run(["rustc", "--version"]))
    lines.append("loadavg now: " + open("/proc/loadavg").read().strip())
    lines.append(f"MemTotal/MemAvailable kB: {[l.split()[1] for l in open('/proc/meminfo') if l.startswith(('MemTotal', 'MemAvailable'))]}")
    for h, b in BINS.items():
        lines.append(f"binary: bin/w29-{h} sha256 {sha256(b)}")
    lines.append("proof options: default_options() = 40 queries, blowup 8, grind 16, no PQZ_* variable; max 4 chunks (split::plan_split)")
    with open(os.path.join(OUT, "w29-env.txt"), "a") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def cmd_prove(a):
    os.makedirs(OUT, exist_ok=True)
    K = len(SETTINGS)
    labels = [s[0] for s in SETTINGS]
    for rel in a.rels.split(","):
        for n in [int(x) for x in a.sizes.split(",")]:
            path = os.path.join(OUT, f"prove_{rel}_n{n}.raw.csv")
            new = not os.path.exists(path)
            l1, waited, to = wait_load(tag=f"prove {rel} n={n}")
            kids = {}
            with open(path, "a") as f:
                if new:
                    f.write(DRV_PROVE + PROVE_HDR + "\n")
                f.write(f"# prove rel={rel} n={n} block={a.block} warm {a.warm} timed {a.timed} start {time.strftime('%F %T')} "
                        f"load1={l1} waited_s={waited:.0f} wait_timed_out={int(to)} MemAvailable_kB={memavail_kb()}\n")
                for lab, h, mode in SETTINGS:
                    f.write(f"# START {lab} ({h},{mode}) load1_at_process_start={loadavg()[0]}\n")
                    kids[lab] = Child(lab, h, ["prove", f"rel={rel}", f"n={n}", f"block={a.block}", f"mode={mode}"], trim=True)
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
                    log(f"prove {rel} n={n}: rep {rep + 1}/{a.warm + a.timed} done (load1 {loadavg()[0]})")
                for k in kids.values():
                    k.close()


def cmd_verify(a):
    os.makedirs(OUT, exist_ok=True)
    cpu = a.cpu
    sib = [c for c in siblings(cpu) if c != cpu]
    hashes = ["sha3", "blake3"]
    for kind in a.kinds.split(","):
        path = os.path.join(OUT, f"verify_{kind}.raw.csv")
        new = not os.path.exists(path)
        extra = [f"n={a.big_n}", f"block={a.block}"] if kind in ("execchunk", "execsingle") else []
        with open(path, "a") as f:
            if new:
                f.write(DRV_VERIFY + VERIFY_HDR + "\n")
            f.write(f"# verify kind={kind} cpu {cpu} siblings {sib} rounds {a.rounds} warm {a.warm} timed {a.timed} "
                    f"start {time.strftime('%F %T')}\n")
            for rnd in range(a.rounds):
                l1, waited, to = wait_load(tag=f"verify {kind} round {rnd}")
                f.write(f"# ROUND {rnd} start load1={l1} waited_s={waited:.0f} wait_timed_out={int(to)} busy_cores={busy_cores():.2f}\n")
                order0 = hashes[rnd % 2:] + hashes[:rnd % 2]
                kids = {}
                for h in order0:
                    f.write(f"# START {kind} {h} load1_at_process_start={loadavg()[0]}\n")
                    kids[h] = Child(f"{kind}-{h}", h, ["verify", f"kind={kind}"] + extra, cpu=cpu)
                    f.write(f"# READY round {rnd} {h}: {kids[h].ready()}\n")
                f.flush()
                for rep in range(a.warm + a.timed):
                    phase = "warm" if rep < a.warm else "timed"
                    order = hashes[(rep + rnd) % 2:] + hashes[:(rep + rnd) % 2]
                    for h in order:
                        l1, pr = loadavg()
                        khz = cpu_khz(cpu)
                        row = kids[h].run()
                        if row is None:
                            f.write(f"# NOROW {kind} {h} round {rnd} rep {rep}\n")
                            continue
                        f.write(f"{kind},{h},{rnd},{rep},{phase},{time.time():.2f},{l1},{pr},{khz},{row[4:]}\n")
                    f.flush()
                for k in kids.values():
                    k.close()
                log(f"verify {kind} round {rnd + 1}/{a.rounds} done (load1 {loadavg()[0]})")


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
    desc = {s[0]: f"{s[1]}/{s[2]}" for s in SETTINGS}
    files = sorted(os.listdir(OUT)) if os.path.isdir(OUT) else []
    # ---- prove
    for fn in files:
        if not (fn.startswith("prove_") and fn.endswith(".raw.csv")):
            continue
        rows = [r for r in read_raw(os.path.join(OUT, fn)) if r["phase"] == "timed"]
        if not rows:
            continue
        rel, n = rows[0]["rel"], rows[0]["n"]
        out.append(f"PROVE R_{rel.capitalize()} N_Q={n} block={rows[0]['block']}: prove_s = proving only (sum over chunks), all cores")
        by = {lab: sorted([r for r in rows if r["label"] == lab], key=lambda r: int(r["rep"])) for lab in labels}
        pm = lambda r: float(r["prove_s"]) * 1000
        base = {lab: {int(r["rep"]): pm(r) for r in by[lab]} for lab in labels}
        sums = []
        for lab in labels:
            if not by[lab]:
                continue
            v = [pm(r) for r in by[lab]]
            r0 = by[lab][0]
            s = dict(label=lab, setting=desc[lab], rel=rel, n=n, chunks=r0["chunks"], rows_each=r0["rows_each"], n_timed=len(v),
                     median_prove_ms=med(v), min_prove_ms=min(v), max_prove_ms=max(v),
                     median_trace_ms=med([float(r["trace_s"]) * 1000 for r in by[lab]]),
                     proof_bytes=r0["proof_bytes"], conj=r0["conj"], udr=r0["udr"], ldr=r0["ldr"],
                     load1_min=min(float(r["load1_before"]) for r in by[lab]), load1_max=max(float(r["load1_before"]) for r in by[lab]),
                     quiet_ok_runs=sum(int(r["quiet_ok"]) for r in by[lab]))
            for ref, name in (("S0", "vs_S0"), ("S1", "vs_S1")):
                pr = [pm(r) / base[ref][int(r["rep"])] for r in by[lab] if int(r["rep"]) in base[ref]]
                s["paired_ratio_" + name] = med(pr) if pr else float("nan")
            sums.append(s)
            out.append(f"{lab} {desc[lab]}: chunks {s['chunks']} rows {s['rows_each']} n={s['n_timed']} prove median {s['median_prove_ms']:.0f} ms "
                       f"(min {s['min_prove_ms']:.0f} max {s['max_prove_ms']:.0f}) trace {s['median_trace_ms']:.0f} ms "
                       f"paired vs S0 {s['paired_ratio_vs_S0']:.2f} vs S1 {s['paired_ratio_vs_S1']:.2f} bytes {s['proof_bytes']} "
                       f"conj/udr/ldr {s['conj']}/{s['udr']}/{s['ldr']} quiet_ok {s['quiet_ok_runs']}/{s['n_timed']} "
                       f"load1 {s['load1_min']}-{s['load1_max']}")
        with open(os.path.join(OUT, fn.replace(".raw.csv", ".summary.csv")), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(sums[0].keys()))
            w.writeheader()
            w.writerows(sums)
    # ---- verify
    vs = []
    for fn in files:
        if not (fn.startswith("verify_") and fn.endswith(".raw.csv")):
            continue
        rows = [r for r in read_raw(os.path.join(OUT, fn)) if r["phase"] == "timed"]
        if not rows:
            continue
        kind = rows[0]["label"]
        out.append(f"VERIFY {kind} (parse + verify), pinned single core")
        for h in ("sha3", "blake3"):
            rr = [r for r in rows if r["hashsel"] == h]
            if not rr:
                continue
            v = [float(r["total_s"]) * 1000 for r in rr]
            r0 = rr[0]
            s = dict(kind=kind, hash=h, n=r0["n"], n_proofs=r0["n_proofs"], n_timed=len(v), median_ms=med(v), min_ms=min(v), max_ms=max(v),
                     bytes_total=r0["bytes_total"], sizes=r0["sizes"], conj=r0["conj"], udr=r0["udr"], ldr=r0["ldr"],
                     load1_min=min(float(r["load1_before"]) for r in rr), load1_max=max(float(r["load1_before"]) for r in rr))
            vs.append(s)
            out.append(f"{kind} {h}: proofs {s['n_proofs']} n={s['n_timed']} median {s['median_ms']:.3f} ms (min {s['min_ms']:.3f} max {s['max_ms']:.3f}) "
                       f"bytes {s['bytes_total']} ({s['sizes']}) conj/udr/ldr {s['conj']}/{s['udr']}/{s['ldr']} load1 {s['load1_min']}-{s['load1_max']}")
    if vs:
        with open(os.path.join(OUT, "verify.summary.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(vs[0].keys()))
            w.writeheader()
            w.writerows(vs)
        m = {(s["kind"], s["hash"]): s["median_ms"] for s in vs}
        for h in ("sha3", "blake3"):
            if ("execchunk", h) in m and ("execsingle", h) in m:
                out.append(f"VERIFY ratio exec chunked / single ({h}): {m[('execchunk', h)] / m[('execsingle', h)]:.2f}")
    txt = "\n".join(out) + "\n"
    with open(os.path.join(OUT, "summary.txt"), "w") as f:
        f.write(txt)
    print(txt)


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd")
    e = sp.add_parser("env")
    e.add_argument("--cpu", type=int, default=10)
    p = sp.add_parser("prove")
    p.add_argument("--rels", default="exec,rc")
    p.add_argument("--sizes", default="5000,10000,20000,50000,100000")
    p.add_argument("--block", type=int, default=100)  # lead, entry 436: 100 = block size of the paper's cloud runs (cloud-w20 raw.csv)
    p.add_argument("--warm", type=int, default=3)
    p.add_argument("--timed", type=int, default=10)
    v = sp.add_parser("verify")
    v.add_argument("--cpu", type=int, default=10)
    v.add_argument("--rounds", type=int, default=1)
    v.add_argument("--warm", type=int, default=10)
    v.add_argument("--timed", type=int, default=25)
    v.add_argument("--kinds", default=",".join(VERIFY_KINDS))
    v.add_argument("--big-n", dest="big_n", type=int, default=50000)
    v.add_argument("--block", type=int, default=100)  # lead, entry 436: block size of execchunk/execsingle (was fixed at 500)
    sp.add_parser("summary")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    if a.cmd == "env":
        cmd_env(a.cpu)
    elif a.cmd == "prove":
        cmd_prove(a)
    elif a.cmd == "verify":
        cmd_verify(a)
    elif a.cmd == "summary":
        cmd_summary(a)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
