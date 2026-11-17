# run an analysis script with all matplotlib figure heights multiplied by a factor (no source change)
import sys, os, runpy, matplotlib
sys.path.insert(0, os.getcwd())
matplotlib.use("Agg")
import matplotlib.pyplot as plt
f = float(sys.argv[1]); script = sys.argv[2]; sys.argv = [script] + sys.argv[3:]
_sub, _fig = plt.subplots, plt.figure
def sc(fs):
    return (fs[0], fs[1]*f) if fs is not None else fs
def subplots(*a, **k):
    if "figsize" in k: k["figsize"] = sc(k["figsize"])
    return _sub(*a, **k)
def figure(*a, **k):
    if "figsize" in k: k["figsize"] = sc(k["figsize"])
    return _fig(*a, **k)
plt.subplots, plt.figure = subplots, figure
runpy.run_path(script, run_name="__main__")
