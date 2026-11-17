#!/usr/bin/env python3
"""peakrss.py OUTFILE CMD...: run CMD (stdout/stderr passed through), then write wall time and peak RSS (KiB) of the child to OUTFILE.
/usr/bin/time is not installed on this laptop; ru_maxrss of RUSAGE_CHILDREN is the same number as `time -v`."""
import resource, subprocess, sys, time
out, cmd = sys.argv[1], sys.argv[2:]
t = time.time()
rc = subprocess.call(cmd)
w = time.time() - t
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
open(out, "w").write(f"exit={rc}\nwall_s={w:.2f}\nmax_rss_kib={ru.ru_maxrss}\n")
sys.exit(rc)
