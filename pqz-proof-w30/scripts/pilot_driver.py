#!/usr/bin/env python3
"""w25 pilot driver (NEW file in the copy). Drives the children of src/bin/pilot.rs.

One fresh child process per measurement point (a point = build x queries/blowup/grind x size). All children of one
experiment are started first and then asked, round-robin, for one run each per repetition (the starting point rotates
with the repetition number), so slow drifts of the shared laptop hit all points alike.

Raw output: results/pilot-1/<name>.raw.csv. Every line = driver columns + the child's ROW line without the word ROW,
unmodified. Driver columns: label,rep,phase,t_unix,load1_before,load1_after,memavail_kb_before,busy_cores_before,quiet_ok.

  python3 scripts/pilot_driver.py env
  python3 scripts/pilot_driver.py m1            # R_Exec prove, 4 sizes x 4 settings
  python3 scripts/pilot_driver.py m2            # bundle verify at 1000 records, 4 settings
  python3 scripts/pilot_driver.py side          # block 100 vs 500 at N_Q=20000, default build
  python3 scripts/pilot_driver.py m3 BEST       # R_RC prove at N_Q=20000: default vs BEST
  python3 scripts/pilot_driver.py l3 BEST       # chunk split vs single proof for BEST
  python3 scripts/pilot_driver.py dp            # only the trace-row DP (no timing)
"""
import os
import select
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
OUT = os.path.join(ROOT, "results", "pilot-1")
NCPU = os.cpu_count() or 1
RUN_TIMEOUT = 300.0  # a point whose single run takes longer than 5 minutes is skipped

# label -> (binary, extra environment). The default build gets no PQZ_* variable at all.
SETTINGS = {
    "sha3-b8-q40": ("pilot-sha3", {}),
    "blake3-b8-q40": ("pilot-blake3", {}),
    "sha3-b16-q37": ("pilot-sha3", {"PQZ_QUERIES": "37", "PQZ_BLOWUP": "16"}),
    "blake3-b16-q37": ("pilot-blake3", {"PQZ_QUERIES": "37", "PQZ_BLOWUP": "16"}),
}
ORDER = ["sha3-b8-q40", "blake3-b8-q40", "sha3-b16-q37", "blake3-b16-q37"]

PROVE_HDR = "kind,rel,n,block,hash,queries,blowup,grind,trace_rows,trace_s,prove_s,verify_s,proof_bytes,conj,udr,ldr,vmrss_kb"
BUNDLE_HDR = "kind,n,depth,hash,queries,blowup,grind,total_s,t_rc,t_auth,t_exec,bytes_total,b_rc,b_auth,b_exec,conj,udr,ldr"
CHUNKS_HDR = ("kind,rel,block,label,n_chunks,hash,queries,blowup,grind,rows_sum,rows_each,trace_s_sum,prove_s_sum,"
              "prove_total_wall,verify_total,bytes_sum,conj,udr,ldr,vmrss_kb")
DRV_HDR = "label,rep,phase,t_unix,load1_before,load1_after,memavail_kb_before,busy_cores_before,quiet_ok"


def log(msg):
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


def load1():
    return open("/proc/loadavg").read().split()[0]


def memavail_kb():
    for l in open("/proc/meminfo"):
        if l.startswith("MemAvailable:"):
            return int(l.split()[1])
    return -1


def cpu_times():
    f = open("/proc/stat").readline().split()[1:]
    v = [int(x) for x in f]
    idle = v[3] + v[4]
    return sum(v), idle


def busy_cores(window=0.5):
    t0, i0 = cpu_times()
    time.sleep(window)
    t1, i1 = cpu_times()
    dt = t1 - t0
    if dt <= 0:
        return 0.0
    return NCPU * (1.0 - (i1 - i0) / dt)


def wait_quiet(max_wait=20.0, limit=5.0):
    """Wait until fewer than `limit` cores are busy (instantaneous). Returns (busy_cores, quiet_ok)."""
    t0 = time.time()
    while True:
        b = busy_cores()
        if b < limit:
            return b, 1
        if time.time() - t0 > max_wait:
            return b, 0
        time.sleep(1.0)


def wait_load(limit=4.0, max_wait=120.0):
    t0 = time.time()
    while float(load1()) >= limit and time.time() - t0 < max_wait:
        time.sleep(2.0)
    log(f"start load1={load1()} busy_cores={busy_cores():.2f}")


class Child:
    def __init__(self, label, binname, env_extra, args, trim=False):
        self.label = label
        env = {k: v for k, v in os.environ.items() if not k.startswith("PQZ_") and k != "PILOT_TRIM"}
        env.update(env_extra)
        if trim:
            env["PILOT_TRIM"] = "1"
        errpath = os.path.join(OUT, "child-stderr.log")
        self.err = open(errpath, "ab")
        self.p = subprocess.Popen([os.path.join(BIN, binname), "child"] + args, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=self.err, env=env)
        self.buf = b""

    def readline(self, timeout):
        deadline = time.time() + timeout
        fd = self.p.stdout.fileno()
        while b"\n" not in self.buf:
            left = deadline - time.time()
            if left <= 0:
                raise TimeoutError(self.label)
            r = select.select([fd], [], [], left)[0]
            if not r:
                raise TimeoutError(self.label)
            chunk = os.read(fd, 65536)
            if not chunk:
                raise EOFError(self.label)
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode()

    def ready(self, timeout=RUN_TIMEOUT):
        while True:
            l = self.readline(timeout)
            if l.startswith("READY,"):
                return l

    def run(self, timeout=RUN_TIMEOUT):
        self.p.stdin.write(b"run\n")
        self.p.stdin.flush()
        row = None
        while True:
            l = self.readline(timeout)
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


def interleave(name, hdr, children, warm, timed, quiet_every=1):
    """children: dict label -> Child (already started). Writes results/pilot-1/<name>.raw.csv (appends)."""
    path = os.path.join(OUT, name + ".raw.csv")
    new = not os.path.exists(path)
    labels = list(children.keys())
    ready = {}
    for lab in labels:
        try:
            ready[lab] = children[lab].ready()
        except Exception as e:
            log(f"FAILED to start {lab}: {e!r}")
            children[lab].close()
            del children[lab]
    labels = list(children.keys())
    with open(path, "a") as f:
        if new:
            f.write(DRV_HDR + "," + hdr + "\n")
        for lab in labels:
            f.write("# READY " + ready[lab] + "\n")
        for rep in range(warm + timed):
            phase = "warm" if rep < warm else "timed"
            order = labels[rep % len(labels):] + labels[:rep % len(labels)]
            for lab in order:
                if lab not in children:
                    continue
                if rep % quiet_every == 0:
                    b, ok = wait_quiet()
                else:
                    b, ok = busy_cores(0.2), -1
                l_before, mem = load1(), memavail_kb()
                try:
                    row = children[lab].run()
                except Exception as e:
                    log(f"SKIPPED point {lab} (rep {rep}): {e!r} (limit {RUN_TIMEOUT:.0f} s per run)")
                    f.write(f"# SKIPPED {lab} rep {rep} {e!r}\n")
                    children[lab].p.kill()
                    del children[lab]
                    continue
                l_after = load1()
                if row is None:
                    log(f"no ROW from {lab}")
                    continue
                f.write(f"{lab},{rep},{phase},{time.time():.1f},{l_before},{l_after},{mem},{b:.2f},{ok},{row[4:]}\n")
                f.flush()
            log(f"{name}: rep {rep + 1}/{warm + timed} done (load1 {load1()})")
    for c in children.values():
        c.close()


def run_group(name, hdr, specs, warm, timed, quiet_every=1, trim=False):
    """specs: list of (label, binname, env_extra, args)."""
    wait_load()
    children = {}
    for lab, binname, env_extra, args in specs:
        children[lab] = Child(lab, binname, env_extra, args, trim=trim)
    interleave(name, hdr, children, warm, timed, quiet_every)


def prove_specs(rel, n, block, labels):
    return [(lab, SETTINGS[lab][0], SETTINGS[lab][1], ["prove", f"rel={rel}", f"n={n}", f"block={block}"])
            for lab in labels]


def cmd_env():
    os.makedirs(OUT, exist_ok=True)
    lines = []
    model = ""
    for l in open("/proc/cpuinfo"):
        if l.startswith("model name"):
            model = l.split(":", 1)[1].strip()
            break
    lines.append(f"date: {time.strftime('%Y-%m-%d %H:%M:%S %z')}")
    lines.append(f"cpu: {model}; logical cores: {NCPU}")
    for p in ["/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "/sys/devices/system/cpu/intel_pstate/status",
              "/sys/devices/system/cpu/intel_pstate/no_turbo", "/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference"]:
        try:
            lines.append(f"{p}: {open(p).read().strip()}")
        except Exception:
            lines.append(f"{p}: n/a")
    lines.append("kernel: " + subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip())
    lines.append("loadavg now: " + open("/proc/loadavg").read().strip())
    lines.append(f"MemTotal/MemAvailable kB: {open('/proc/meminfo').readline().split()[1]} / {memavail_kb()}")
    lines.append("rustc: " + subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip())
    lines.append("cargo: " + subprocess.run(["cargo", "--version"], capture_output=True, text=True).stdout.strip())
    top = "."
    g = lambda *a: subprocess.run(["git", "-C", top] + list(a), capture_output=True, text=True).stdout.strip()
    lines.append("git HEAD: " + g("rev-parse", "--short", "HEAD") + " on branch " + g("rev-parse", "--abbrev-ref", "HEAD"))
    lines.append("git status of bench/pqz-proof (original crate; empty = unchanged): [" + g("status", "--short", "bench/pqz-proof") + "]")
    lines.append("bench/pqz-proof-w25 is an untracked copy; edits listed in CHANGES-w25.md")
    lines.append("binaries: " + ", ".join(sorted(os.listdir(BIN))))
    sha = subprocess.run(["sha256sum"] + [os.path.join(BIN, b) for b in sorted(os.listdir(BIN))], capture_output=True, text=True).stdout
    lines.append("sha256 of binaries (first 16 hex):")
    for l in sha.strip().splitlines():
        h, p = l.split(None, 1)
        lines.append(f"  {h[:16]}  {os.path.basename(p)}")
    with open(os.path.join(OUT, "env.txt"), "a") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def cmd_m1():
    for n, warm, timed in [(5000, 3, 10), (10000, 3, 10), (20000, 3, 10), (50000, 1, 5)]:
        log(f"=== M1 exec n={n}")
        run_group("m1_exec_prove", PROVE_HDR, prove_specs("exec", n, 100, ORDER), warm, timed, trim=(n >= 50000))


def cmd_m2():
    log("=== M2 bundle verify, 1000 records")
    specs = [(lab, SETTINGS[lab][0], SETTINGS[lab][1], ["bundle", "n=1000", "depth=10"]) for lab in ORDER]
    run_group("m2_bundle_verify", BUNDLE_HDR, specs, 3, 50, quiet_every=10)


def cmd_side():
    log("=== side check: block 100 vs 500, exec n=20000, default build")
    wait_load()
    children = {}
    for blk in (100, 500):
        lab = f"sha3-b8-q40-block{blk}"
        children[lab] = Child(lab, "pilot-sha3", {}, ["prove", "rel=exec", "n=20000", f"block={blk}"])
    interleave("side_block_exec20000", PROVE_HDR, children, 1, 5)


def cmd_m3(best):
    log(f"=== M3 rc n=20000: default vs {best}")
    labs = ["sha3-b8-q40"] + ([best] if best != "sha3-b8-q40" else [])
    run_group("m3_rc_prove", PROVE_HDR, prove_specs("rc", 20000, 100, labs), 3, 10)


# ---- L3: trace-row split -------------------------------------------------------------------------------
WORDS_PER_BLOCK = 501  # block 500 -> 501 words per block (src/data.rs); one word = 8 rows (GROUP, src/exec.rs)
ROWS_PER_WORD = 8


def padded(k_blocks):
    rows = k_blocks * WORDS_PER_BLOCK * ROWS_PER_WORD
    p = 32
    while p < rows:
        p *= 2
    return p


def best_split(blocks, max_chunks=4):
    INF = 10 ** 18
    f = [[INF] * (blocks + 1) for _ in range(max_chunks + 1)]
    arg = [[0] * (blocks + 1) for _ in range(max_chunks + 1)]
    f[0][0] = 0
    for c in range(1, max_chunks + 1):
        for b in range(1, blocks + 1):
            for k in range(1, b + 1):
                v = f[c - 1][b - k] + padded(k)
                if v < f[c][b]:
                    f[c][b] = v
                    arg[c][b] = k
    c_best = min(range(1, max_chunks + 1), key=lambda c: (f[c][blocks], c))
    parts = []
    b, c = blocks, c_best
    while c > 0:
        k = arg[c][b]
        parts.append(k)
        b -= k
        c -= 1
    return f[c_best][blocks], sorted(parts, reverse=True)


def cmd_dp():
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "l3_dp.csv")
    with open(path, "w") as f:
        f.write("n_q,blocks_of_500,single_padded_rows,best_chunks,blocks_per_chunk,rows_per_chunk,split_padded_rows_sum,ratio_rows_single_over_split\n")
        for nq in (5000, 10000, 20000, 50000, 100000):
            blocks = nq // 500
            single = padded(blocks)
            tot, parts = best_split(blocks)
            f.write(f"{nq},{blocks},{single},{len(parts)},{'+'.join(map(str, parts))},{'+'.join(str(padded(k)) for k in parts)},{tot},{single / tot:.4f}\n")
    print(open(path).read())


def split_for(nq):
    return best_split(nq // 500)[1]


def cmd_l3(best):
    cmd_dp()
    for nq in (10000, 20000, 50000):
        parts = split_for(nq)
        log(f"=== L3 n={nq} split {parts} build {best}")
        wait_load()
        binname, envx = SETTINGS[best]
        children = {
            f"{best}-single": Child(f"{best}-single", binname, envx, ["prove", "rel=exec", f"n={nq}", "block=500"], trim=(nq >= 50000)),
            f"{best}-split": Child(f"{best}-split", binname, envx,
                                    ["chunks", "rel=exec", "block=500", "blocks=" + ",".join(map(str, parts))], trim=(nq >= 50000)),
        }
        # one raw file per kind (different columns); interleave() needs one header, so give each child its own file via two passes
        single = {f"{best}-single": children.pop(f"{best}-single")}
        split = children
        run_pair(nq, single, split)


def run_pair(nq, single, split):
    """Interleave one 'single' child and one 'split' child; the two kinds have different columns, so they go to two files."""
    s_lab, s_child = list(single.items())[0]
    c_lab, c_child = list(split.items())[0]
    p_single = os.path.join(OUT, "l3_single.raw.csv")
    p_split = os.path.join(OUT, "l3_chunks.raw.csv")
    for p, hdr in ((p_single, PROVE_HDR), (p_split, CHUNKS_HDR)):
        if not os.path.exists(p):
            with open(p, "w") as f:
                f.write(DRV_HDR + "," + hdr + "\n")
    kids = [(s_lab, s_child, p_single), (c_lab, c_child, p_split)]
    for lab, ch, p in kids:
        r = ch.ready()
        with open(p, "a") as f:
            f.write("# READY " + r + "\n")
    warm, timed = 1, 5
    alive = {lab for lab, _, _ in kids}
    for rep in range(warm + timed):
        phase = "warm" if rep < warm else "timed"
        order = kids[rep % 2:] + kids[:rep % 2]
        for lab, ch, p in order:
            if lab not in alive:
                continue
            b, ok = wait_quiet()
            l_before, mem = load1(), memavail_kb()
            try:
                row = ch.run()
            except Exception as e:
                log(f"SKIPPED point {lab} (rep {rep}): {e!r}")
                with open(p, "a") as f:
                    f.write(f"# SKIPPED {lab} n={nq} rep {rep} {e!r}\n")
                ch.p.kill()
                alive.discard(lab)
                continue
            l_after = load1()
            with open(p, "a") as f:
                f.write(f"{lab}-n{nq},{rep},{phase},{time.time():.1f},{l_before},{l_after},{mem},{b:.2f},{ok},{row[4:]}\n")
        log(f"l3 n={nq}: rep {rep + 1}/{warm + timed} (load1 {load1()})")
    for _, ch, _ in kids:
        ch.close()


def main():
    os.makedirs(OUT, exist_ok=True)
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return
    if a[0] == "env":
        cmd_env()
    elif a[0] == "m1":
        cmd_m1()
    elif a[0] == "m1n":
        # re-run of ONE size into its own file: m1n N NAME [warm timed]
        w, t = (int(a[3]), int(a[4])) if len(a) > 4 else (3, 10)
        run_group(a[2], PROVE_HDR, prove_specs("exec", int(a[1]), 100, ORDER), w, t, trim=(int(a[1]) >= 50000))
    elif a[0] == "m2":
        cmd_m2()
    elif a[0] == "side":
        cmd_side()
    elif a[0] == "m3":
        cmd_m3(a[1])
    elif a[0] == "l3":
        cmd_l3(a[1])
    elif a[0] == "dp":
        cmd_dp()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
