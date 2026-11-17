import csv, statistics as s, collections, sys
rows = list(csv.DictReader(open(sys.argv[1])))
g = collections.OrderedDict()
for r in rows:
    g.setdefault((r['system'], int(r['N']), int(r['batch'])), []).append(r)
def f(v, d=2): return f"{s.median(v):.{d}f} ({min(v):.{d}f}-{max(v):.{d}f})"
print("system N batch runs failed/timedout lat_s bytes_added blocks txs")
for (sy, n, b), rs in g.items():
    bad = sum(int(r['failed_tx']) + int(r['timed_out_tx']) for r in rs)
    print(sy, n, b, len(rs), bad, f([float(r['latency_s']) for r in rs], 2),
          f([int(r['bytes_added']) for r in rs], 0), f([int(r['blocks_added']) for r in rs], 0), rs[0]['tx_count'])
