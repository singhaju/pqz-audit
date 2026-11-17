import sys, os, time, resource, subprocess
# usage: tm_w32.py <label> cmd...   ; runs the child, prints wall, user, sys, maxrss(KB) and the return code of the child to stderr as one "TM" line.
# (same as bench/zksql-feas/tm.py plus a start stamp; stdlib only, python 3.9 ok)
t = time.time()
p = subprocess.Popen(sys.argv[2:])
rc = p.wait()
r = resource.getrusage(resource.RUSAGE_CHILDREN)
sys.stderr.write("TM %s wall_s=%.3f user_s=%.2f sys_s=%.2f maxrss_kb=%d rc=%d start_epoch=%.1f\n" % (sys.argv[1], time.time() - t, r.ru_utime, r.ru_stime, r.ru_maxrss, rc, t))
sys.exit(0)
