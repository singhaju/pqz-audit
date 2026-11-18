#!/usr/bin/env python3
"""PQZ-Audit live demo: hospital EHR access-log audit (insider data theft).

Every number, hash, ACCEPT/REJECT and error text on screen comes from the real library code, run by the
Rust program pqz-integrated-w46/src/bin/demo_scenarios.rs (JSON Lines on stdout). Nothing is hard-coded here.

Run from anywhere:
    bash demo/demo.sh                      # TALK mode: intro, then ONE audit menu on one page (full story, questions, attacks)
    bash demo/demo.sh --full               # S1 with every table, then ONE attack from a menu
    bash demo/demo.sh --scenario a2        # skip the menu, one scenario (s1 a1..a7 search)
    bash demo/demo.sh --all-attacks        # A1..A7 and one results table
    bash demo/demo.sh --no-pause           # no ENTER pauses (S1 then A2, no menu)
"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CRATE = ROOT / "pqz-integrated-w46"
BIN = CRATE / "target" / "release" / "demo_scenarios"

SCEN = {
    "s1": "S1  Honest audit: all phases, ACCEPT, result compared with the plaintext",
    "a1": "A1  Cloud changes the result (count / sum)",
    "a2": "A2  Cloud hides a block that contains matches   (recommended for the talk)",
    "a3": "A3  Bad or missing Bloom opening for a skipped block",
    "a4": "A4  A stored record is changed after anchoring",
    "a5": "A5  Authorization bound to a different epoch / Omega",
    "a6": "A6  Authorization for a different query (d_Q)",
    "a7": "A7  Forged or tampered ledger anchor",
    "search": "S   Search layer only: compound predicates, no proof",
}
ATTACKS = ["a1", "a2", "a3", "a4", "a5", "a6", "a7"]
RECOMMENDED = "a2"

ACTION_CODES = "1 VIEW, 2 EDIT, 3 PRINT, 4 LOGIN, 5 LOGOUT, 6 ORDER_MEDICATION, 7 EXPORT_RECORDS"
# Action codes in plain words: (code, name, meaning, typical b in this synthetic log, why an auditor may ask about it)
ACTION_INFO = [
    (1, "VIEW_CHART", "open and read one patient's chart", "1-3 (sometimes 20-79: a ward list)", "snooping on a famous patient"),
    (2, "EDIT_CHART", "change a chart (notes, vital signs)", "1", "who changed a record"),
    (3, "PRINT", "print a record on paper", "1-2", "paper copies leaving the hospital"),
    (4, "LOGIN", "start a session", "0 (no patient touched)", "logins at odd hours"),
    (5, "LOGOUT", "end a session", "0", "session length"),
    (6, "ORDER_MEDICATION", "order a drug for a patient", "1", "drug misuse"),
    (7, "EXPORT_RECORDS", "download many patients' records to a file", "2-29 or 150-899", "data theft (our story: only staff 417)"),
]
LAST = {}  # values of the main (action = 7) run, shown again in the proved-audit questions for comparison
DEPT_CODES = "101 ER, 118 ICU, 140 Admissions/Records, 205 Oncology, 220 Radiology, 310 Pharmacy, 330 Laboratory, 500 Psychiatry"

# Plain-words card per attack: (what the cheater does, why a real cheater would do it, what catches it)
ATTACK_INFO = {
    "a1": ("The cloud changes the answer: it says COUNT or SUM is one more than the truth. In A1c it also edits the "
           "proof's public numbers so that everything adds up.",
           "Make the insider look smaller or bigger than they are (hide or frame someone).",
           "The claimed result must equal the sum over the proved runs; in A1c the R_Exec proof no longer verifies."),
    "a2": ("The cloud hides the block with the EXPORT records (block 14 when N = 10,000) and says it was skipped because nothing matched.",
           "Hide the insider completely: the auditor would get COUNT 0.",
           "A skipped block needs a Bloom opening that shows the query is NOT in it. That block's filter says the query may be "
           "there, so it cannot be shown absent."),
    "a3": ("The cloud fakes the 'nothing here' evidence for the hit block: copies the openings of an empty block, shows real "
           "openings whose bits are 1, flips one bit, or leaves the openings out.",
           "Same goal as A2, but with forged evidence instead of no evidence.",
           "Each opening must have a Merkle path to the anchored Bloom root, and the opened bits must be 0."),
    "a4": ("Someone edits a stored record after the epoch was anchored (for example, makes an export smaller) and "
           "rebuilds all blocks and proofs from the edited data.",
           "Change history after the fact, so the log tells a different story.",
           "The block list must rebuild the root R_e that is anchored on the blockchain; edited data gives another root."),
    "a5": ("An old authorization (made for an earlier epoch state Omega_0) is replayed for the new audit.",
           "Run an audit that was never approved for this log state, or reuse an old approval.",
           "The proofs are tied to the authorization; the ledger gate and the contract reject an Omega that is not "
           "the current one. (A5b shows the proofs alone are consistent; the ledger check is what stops it.)"),
    "a6": ("An authorization granted for one query (P1) is used for a different query.",
           "Get approval for a harmless query, then run a more revealing one.",
           "The query digest d_Q is bound into the proofs, and the contract checks the predicate hash on Consume."),
    "a7": ("The blockchain anchor is forged: an edited block header, too few validator votes (2 of 4), an edited "
           "stored value, or a fake anchor transaction.",
           "Make the auditor trust a fake 'official' log state.",
           "The light-client read needs a quorum certificate (3 of 4 votes) and a Merkle path; the contract recomputes Omega."),
}
# Where each attack changes something (phase key), in plain words.
ATTACK_AT = {
    "a1": ("6", "the cloud changes the claimed result (COUNT or SUM + 1); in A1c it also edits the run's public numbers"),
    "a2": ("6", "the cloud drops the block with the matches (block 14) and says it was skipped"),
    "a3": ("6", "the cloud fakes the 'nothing here' openings for the block with the matches"),
    "a4": ("3a", "a stored record is edited AFTER the anchor, and all blocks and proofs are rebuilt from the edited data"),
    "a5": ("5", "an old authorization, bound to the earlier state Omega_0, is replayed"),
    "a6": ("5", "the authorization granted for query P1 is used for a different query"),
    "a7": ("4", "the blockchain anchor is forged (header, votes, stored entry, or anchor transaction)"),
}
# Phase in which each counted check rejects. Phase 4: anchor transaction and the light-client read of the anchor;
# Phase 5: ledger gate and Authorize on the contract; Phase 6: the cloud cannot even build the evidence;
# Phase 7: requester checks (native checks, proof verification) and Consume on the contract.
CATCH_AT = {"A1a": "7", "A1b": "7", "A1c": "7", "A2a": "6", "A2b": "7", "A3a": "7", "A3b": "7", "A3c": "7",
            "A3d": "7", "A4a": "7", "A4b": "7", "A5a": "7", "A5c": "5", "A5d": "5", "A6a": "7", "A6b": "7",
            "A7a": "4", "A7b": "4", "A7c": "4", "A7d": "4"}
PHASE_NAMES = {"1": "Init", "2": "Register", "3a": "Encrypt", "3b": "Blocks", "4": "Anchor", "5": "Authorize",
               "6": "Execute", "7": "Verify"}
FOOT = "Timings: this laptop, one run, not a paper number."

# The Rust program names the four record fields a, b, c, d. On screen we use words:
# a = action code, b = patients (number of patient records touched), c = department, d = staff id.
# Display only: the values, hashes and verdicts are unchanged, and the query keys sent to Rust stay a/b/c/d.
import re
_WORDS = [
    (r"SUM\(b\)", "SUM(patients)"),
    (r"\bsum of b\b", "total patients"),
    (r"\baction a = ", "action = "),
    (r"\bstaff d = ", "staff = "),
    (r"\bdepartment c = ", "department = "),
    (r"\bdept c = ", "dept = "),
    (r"\bpatients b ", "patients "),
    (r"\ba = ([0-9xX])\b", r"action = \1"),
    (r"\bd = ([0-9]+)", r"staff = \1"),
    (r"\bc = ([0-9]+)", r"dept = \1"),
    (r"\bb (>=|<=|>|<) ([0-9]+)", r"patients \1 \2"),
    (r"\bb ([0-9]+) -> ([0-9]+)", r"patients \1 -> \2"),
]


def words(x):
    if not isinstance(x, str):
        return x
    for pat, new in _WORDS:
        x = re.sub(pat, new, x)
    return x

con = Console(highlight=False)
PAUSE = True


def pause(msg="ENTER to continue"):
    if PAUSE:
        try:
            con.input(f"[dim]  ({msg}) [/dim]")
        except EOFError:
            pass


def build():
    t = time.time()
    with con.status("[cyan]cargo build --release --locked --bin demo_scenarios ...", spinner="dots"):
        r = subprocess.run(["cargo", "build", "--release", "--locked", "--bin", "demo_scenarios"],
                           cwd=CRATE, capture_output=True, text=True)
    if r.returncode != 0:
        con.print(r.stderr[-3000:])
        sys.exit("build failed")
    con.print(f"[green]built[/green] demo_scenarios in {time.time() - t:.1f} s (cargo, --locked)")


def run_events(sc, n, extra=()):
    p = subprocess.Popen([str(BIN), "--scenario", sc, "--n", str(n), *extra], stdout=subprocess.PIPE, text=True, cwd=CRATE)
    for line in p.stdout:
        line = line.strip()
        if line.startswith("{"):
            yield json.loads(line)
    if p.wait() != 0:
        sys.exit(f"demo_scenarios exited with {p.returncode}")


def fmt_t(t):
    if t is None:
        return "-"
    return f"{t * 1000:.1f} ms" if t < 1 else f"{t:.2f} s"


def table_of(tb):
    t = Table(title=tb["caption"], box=box.SIMPLE_HEAD, title_style="bold", title_justify="left", header_style="cyan")
    for h in tb["headers"]:
        t.add_column(h, overflow="fold")
    for r in tb["rows"]:
        t.add_row(*[words(x) for x in r])
    return t


def show_phase(e):
    g = Table.grid(padding=(0, 2))
    g.add_column(style="cyan", no_wrap=False, max_width=34)
    g.add_column(overflow="fold")
    for k, v in e["items"]:
        g.add_row(k, words(v))
    parts = [g]
    for tb in e["tables"]:
        parts.append(Text(""))
        parts.append(table_of(tb))
    if e["note"]:
        parts.append(Text(""))
        parts.append(Text("Note: " + words(e["note"]), style="yellow"))
    sub = f"time {fmt_t(e['time_s'])}" if e["time_s"] is not None else ""
    ok = e["status"] == "ok"
    ph = e["phase"]
    con.print(Panel(__import__("rich.console", fromlist=["Group"]).Group(*parts),
                    title=f"[bold]Phase {ph}[/bold]  {words(e['title'])}", subtitle=sub,
                    border_style="green" if ok else "red", box=box.ROUNDED, padding=(1, 2)))


def show_check(e):
    rej = e["status"] == "reject"
    g = Table.grid(padding=(0, 2))
    g.add_column(style="cyan", max_width=30)
    g.add_column(overflow="fold")
    for k, v in e["items"]:
        g.add_row(k, words(v))
    verdict = "REJECTED" if rej else "ACCEPTED"
    style = "bold red" if rej else "bold green"
    g.add_row("verifier says", Text(f"{verdict}: {words(e['detail'])}", style=style))
    if not e["counts"]:
        g.add_row("", Text("(information step, not counted in the attack verdict)", style="dim"))
    con.print(Panel(g, title=f"[bold]{words(e['title'])}[/bold]", subtitle=f"time {fmt_t(e['time_s'])}",
                    border_style="red" if rej and e["counts"] else "yellow", box=box.ROUNDED, padding=(0, 2)))


def banner(sc):
    if sc == "s1":
        body = ("Hospital EHR access log. An insider (staff 417, night shift) exports patient records in a burst. "
                "The cloud stores the encrypted log. An auditor asks: how many EXPORT_RECORDS actions, and how many "
                "patient records in total? The answer must come with proofs the auditor can check.\n\n"
                "[yellow]Honest labels:[/yellow] the blockchain is an in-process simulation (4 validators, no network); STARK proofs are "
                "plain mode, not zero-knowledge; all timings are from this laptop, one run.")
    else:
        body = "Honest setup first (control: ACCEPT), then ONE thing is changed and the real verifier is called."
    con.print(Panel(body, title=f"[bold]{SCEN[sc]}[/bold]", border_style="blue"))


def run_scenario(sc, n, quiet=False):
    """Returns dict(expected, observed, time, rows, first_reject, phases)."""
    if not quiet:
        banner(sc)
        pause("ENTER to start")
    t0 = time.time()
    out = {"sc": sc, "phases": [], "first_reject": "", "expected": "", "observed": "", "time": None, "wall": 0}
    for e in run_events(sc, n):
        if e["kind"] == "phase":
            out["phases"].append((e["phase"], e["title"], e["time_s"]))
            if not quiet:
                show_phase(e)
                pause()
        elif e["kind"] == "check":
            if e["status"] == "reject" and e["counts"] and not out["first_reject"]:
                out["first_reject"] = e["detail"]
            if not quiet:
                show_check(e)
        elif e["kind"] == "result":
            d = dict(e["items"])
            out["expected"], out["observed"], out["time"] = d["expected"], d["observed"], e["time_s"]
            out["ok"] = e["status"] == "ok"
    out["wall"] = time.time() - t0
    if not quiet:
        col = "green" if out.get("ok") else "red"
        con.print(Panel(f"expected: {out['expected']}\nobserved: [{col}]{out['observed']}[/{col}]",
                        title="Result", border_style=col))
    return out


def phase_table(out):
    t = Table(title="S1 per-phase time", box=box.SIMPLE_HEAD, header_style="cyan")
    t.add_column("phase")
    t.add_column("what", overflow="fold")
    t.add_column("time", justify="right")
    tot = 0.0
    for ph, title, tm in out["phases"]:
        t.add_row(ph, title.split(":")[0], fmt_t(tm))
        tot += tm or 0
    t.add_row("", "[bold]sum of phases[/bold]", f"[bold]{fmt_t(tot)}[/bold]")
    return t


def summary(outs):
    t = Table(title="Summary", box=box.ROUNDED, header_style="cyan")
    t.add_column("scenario")
    t.add_column("expected")
    t.add_column("observed", overflow="fold")
    t.add_column("first rejecting check", overflow="fold")
    t.add_column("time", justify="right")
    for o in outs:
        col = "green" if o.get("ok") else "red"
        t.add_row(o["sc"], o["expected"], f"[{col}]{o['observed']}[/{col}]", o["first_reject"] or "-",
                  fmt_t(o["time"] if o["time"] is not None else o["wall"]))
    con.print(t)
    for o in outs:
        if o["sc"] == "s1":
            con.print(phase_table(o))
    if any(o["sc"] == "s1" for o in outs):
        con.print("[dim]S1 total in the summary is wall time; it includes the one-time BFV pool setup, which is not in any phase.[/dim]")
    con.print(f"[dim]{FOOT}[/dim]")


def menu():
    con.print(Rule("Choose an attack (the cloud or a forger changes ONE thing; the verifier must REJECT)"))
    for k in ATTACKS + ["search"]:
        con.print(f"  [bold]{k}[/bold]  {SCEN[k][4:]}")
    con.print("  [bold]all[/bold] all attacks, one table      [bold]q[/bold] quit")
    try:
        a = con.input(f"[cyan]attack [{RECOMMENDED}]: [/cyan]").strip().lower() or RECOMMENDED
    except EOFError:
        a = "q"
    return a


# ---------------------------------------------------------------------------------------------- TALK mode
def collect(sc, n, extra=()):
    with con.status(f"[cyan]running {sc} on the real library ...", spinner="dots"):
        return list(run_events(sc, n, extra))


def kv(items, key_start):
    for k, v in items:
        if k.startswith(key_start):
            return v
    return ""


def panel(title, lines, t, ok=True, extra=None):
    g = Table.grid(padding=(0, 2))
    g.add_column(style="cyan", no_wrap=True)
    g.add_column(overflow="fold")
    for k, v in lines:
        g.add_row(k, words(v))
    parts = [g]
    if extra is not None:
        parts += [Text(""), extra]
    from rich.console import Group
    con.print(Panel(Group(*parts), title=f"[bold]{words(title)}[/bold]", subtitle=f"time {fmt_t(t)}" if t is not None else "",
                    border_style="green" if ok else "red", box=box.ROUNDED, padding=(0, 2)))


def short_row(r):
    # r = id, time, action, b, dept, staff, hit
    return [r[0], r[1][11:], r[2].split(" ", 1)[1].split("_")[0], r[3], r[4].split(" ")[0], r[5]]


def talk_intro(n):
    g = n // 500
    body = ("[bold]Story:[/bold] a hospital keeps its EHR access log in the cloud, encrypted. An insider (staff 417) "
            "exports patient records in a burst. The auditor must find out, without the cloud being trusted.\n\n"
            "[bold]Main question (question 1 in the menu):[/bold] how many EXPORT_RECORDS actions (action = 7) happened in this epoch, and how many "
            "patient records did they export in total? In query terms: COUNT and SUM(patients) where action = 7.\n"
            "Each log record has four fields: [bold]action[/bold] (what was done, a code 1-7), [bold]patients[/bold] "
            "(how many patient records it touched), [bold]department[/bold] and [bold]staff[/bold] id.\n"
            "So action = 7 means \"bulk export of patient records\". The action codes:\n\n"
            f"[bold]Log:[/bold] N = {n:,} records, {g} blocks of 500.\n\n"
            "[yellow]Honest labels:[/yellow] blockchain = in-process simulation (4 validators, no network); STARK proofs = plain mode, "
            "not zero-knowledge; timings = this laptop, one run.\n\n"
            "[bold]How to use:[/bold] one audit menu below. Questions 1-10 are the normal cases and every one shows "
            "Phases 1-7 (question 1 in full, the others as a one-screen recap). Questions 11-15 add another proved "
            "action, the attacks, and your own query. The menu comes back after every answer.")
    from rich.console import Group
    head, tail = body.split("The action codes:\n\n")
    con.print(Panel(Group(Text.from_markup(head + "The action codes:"), action_table(), Text.from_markup(tail)),
                    title="[bold]PQZ-Audit demo[/bold]", border_style="blue", padding=(1, 2)))


def action_table(counts=None):
    t = Table(box=box.SIMPLE_HEAD, header_style="cyan", padding=(0, 1))
    t.add_column("code", style="bold")
    t.add_column("action")
    t.add_column("meaning", max_width=40, overflow="fold")
    t.add_column("patients touched", max_width=22, overflow="fold")
    if counts:
        t.add_column("records in this log", justify="right")
    t.add_column("an auditor may ask about", max_width=30, overflow="fold", style="dim")
    for code, name, meaning, b, why in ACTION_INFO:
        row = [str(code), name, meaning, b]
        if counts:
            row.append(f"{int(counts.get(str(code), 0)):,}")
        row.append(why)
        t.add_row(*row, style="bold red" if code == 7 else None)
    return t


PHASE_CACHE = {}


def phase_events(n):
    if n not in PHASE_CACHE:
        PHASE_CACHE[n] = collect("s1", n)
    return PHASE_CACHE[n]


def phase_values(evs):
    ph = {}
    for e in evs:
        if e["kind"] == "phase":
            ph.setdefault(e["phase"], []).append(e)
    hist = next((tb for tb in ph["2"][0]["tables"] if "histogram" in tb["caption"]), None)
    if hist:
        LAST["hist"] = {r[0]: r[2] for r in hist["rows"]}
    LAST["omega"] = kv(ph["4"][0]["items"], "Omega_e")
    LAST["dq"] = kv(ph["5"][0]["items"], "public: d_Q")
    return ph


def phases_recap(n, note):
    """One compact screen with Phases 1-7, shown before every non-story question."""
    evs = phase_events(n)
    ph = phase_values(evs)
    e6 = ph["6"][0]
    rows = e6["tables"][0]["rows"]
    skipped = sum(1 for r in rows if r[2] == "SKIPPED")
    claimed = kv(e6["items"], "claimed result")
    e7 = ph["7"][0]
    verdict = kv(e7["items"], "requester verdict")
    match = kv(e7["items"], "comparison")
    g = n // 500
    facts = [
        ("1", "Initialization", "keys and a ledger with 4 validators; quorum 3", "Omega_0 (genesis) set; epoch 1"),
        ("2", "Registration", "build the plain log; only the hospital sees it", f"{n:,} records, {g} blocks of 500; staff 417 burst"),
        ("3", "Protect + block (3a/3b)", "encrypt and tag every record, then commit blocks and prove the parts belong together", f"AES-256-GCM + 45 tags; {g} blocks with Bloom summaries; AA check passed"),
        ("4", "Anchor", "write one epoch root to the chain", "Omega_e anchored by 3 of 4 validators"),
        ("5", "Authorize", "the auditor proves the right to ask", "R_Auth proof accepted"),
        ("6", "Execute", "skip blocks whose summary says no match; run the predicate; prove the run", f"P1 action = 7; {len(rows) - skipped} of {len(rows)} blocks opened, {skipped} skipped; {claimed}; R_Exec"),
        ("7", "Verify", "the requester checks the proofs and compares with the plain log", f"{verdict}; verified = plaintext; {match}"),
    ]
    t = Table(box=box.SIMPLE_HEAD, header_style="cyan",
              title="Phases 1-7 at a glance: the same pipeline behind every question", title_justify="left")
    t.add_column("phase", style="bold", justify="right")
    t.add_column("name")
    t.add_column("what it does", max_width=40, overflow="fold")
    t.add_column("result in this run", max_width=50, overflow="fold")
    for row in facts:
        t.add_row(*row)
    from rich.console import Group
    con.print(Panel(Group(t, Text(""), Text.from_markup(f"[yellow]{note}[/yellow]")),
                    title="[bold]Phase 1-7 recap[/bold]", border_style="blue", padding=(0, 1)))
    pause()


def split_phases(evs):
    ph = {}
    for e in evs:
        if e["kind"] == "phase":
            ph.setdefault(e["phase"], []).append(e)
    return ph


def mk(marks, key):
    """Extra red lines and a title note for a phase hit by an attack (marks: phase key -> list of (label, text))."""
    m = (marks or {}).get(key, [])
    if not m:
        return [], "", True
    labs = [lab for lab in ("ATTACK", "REJECTED") if any(l == lab for l, _ in m)]
    note = ("  [bold red]<- " + " + ".join(labs) + " HERE[/bold red]") if labs else ""
    head = [("[dim]above[/dim]", "[dim]the honest run; red lines below = the attack[/dim]")]
    return head + [(f"[bold red]{lab}[/bold red]" if lab != "note" else "[yellow]note[/yellow]",
                    f"[red]{txt}[/red]" if lab != "note" else f"[yellow]{txt}[/yellow]") for lab, txt in m], note, not labs


def show_p1_4(ph, tag="", marks=None):
    """Phases 1-4 panels (shared by every question)."""
    e = ph["1"][0]
    panel("Phase 1  Initialization" + tag, [("ledger", kv(e["items"], "ledger")), ("Omega_0", kv(e["items"], "Omega_0")),
                                       ("epoch / log", kv(e["items"], "epoch e"))], e["time_s"])
    pause()
    # phase 2: 3 normal + 3 insider export rows (taken from the real tables)
    e = ph["2"][0]
    normal = [r for r in e["tables"][0]["rows"] if r[6] == "-"][:3]
    hits = [r for r in e["tables"][1]["rows"] if r[6] == "HIT"][:3]
    t = Table(box=box.SIMPLE_HEAD, header_style="cyan", title="Plaintext log rows (only the hospital sees these)",
              title_justify="left")
    for h in ["id", "time", "action", "patients", "dept", "staff"]:
        t.add_column(h)
    for r in normal:
        t.add_row(*short_row(r))
    for r in hits:
        t.add_row(*[f"[bold red]{x}[/bold red]" for x in short_row(r)])
    panel("Phase 2  Registration (plain log)" + tag, [("insider burst", kv(e["items"], "log generation"))], e["time_s"], extra=t)
    pause()
    # phase 3a
    e = ph["3a"][0]
    r0 = e["tables"][0]["rows"][0]
    x, note, ok = mk(marks, "3a")
    panel("Phase 3a  Encrypt and tag (what the cloud stores)" + tag + note,
          [("row 0 as the cloud sees it", f"ciphertext {r0[1]}  ({r0[2]} bytes), {r0[3]} search tags"),
           ("whole epoch", kv(e["items"], "whole epoch")), ("key holder check", kv(e["items"], "decrypt check"))] + x, e["time_s"], ok=ok)
    pause()
    # phase 3b
    e = ph["3b"][0]
    nb = len(e["tables"][0]["rows"])
    panel("Phase 3b  Blocks, R_RC proofs, AA check" + tag,
          [("blocks", f"{nb} blocks, each with a Bloom summary; R_e = {kv(e['items'], 'R_e')}"),
           ("R_RC proofs", kv(e["items"], "R_RC proofs")), ("AA check", kv(e["items"], "AA check").split(":")[0])], e["time_s"])
    pause()
    # phase 4
    e = ph["4"][0]
    x, note, ok = mk(marks, "4")
    panel("Phase 4  Anchor on the (simulated) blockchain" + tag + note,
          [("Omega_e", kv(e["items"], "Omega_e")[:24] + "..."), ("ledger block", kv(e["items"], "ledger block")),
           ("light-client read", kv(e["items"], "light-client"))] + x, e["time_s"], ok=ok)
    pause()


def talk_phases(n, evs=None, pred="P1: action = 7 (EXPORT_RECORDS)", marks=None, tag=""):
    if evs is None:
        evs = phase_events(n)
        ph = phase_values(evs)
    else:
        ph = split_phases(evs)
    res = [e for e in evs if e["kind"] == "result"][0]
    total = 0.0
    for e in evs:
        if e["kind"] == "phase" and e["time_s"] and not (e["phase"] == "6" and e is ph["6"][1]):
            total += e["time_s"]
    show_p1_4(ph, tag, marks)
    # phase 5
    e = ph["5"][0]
    x, note, ok = mk(marks, "5")
    panel("Phase 5  Authorization proof R_Auth" + tag + note,
          [("request", kv(e["items"], "request")), ("R_Auth proof", kv(e["items"], "R_Auth proof")),
           ("verifier", kv(e["items"], "verify_auth_stage"))] + x, e["time_s"], ok=ok)
    pause()
    # phase 6
    e, he = ph["6"][0], ph["6"][1]
    rows = e["tables"][0]["rows"]
    skipped = sum(1 for r in rows if r[2] == "SKIPPED")
    x, note, ok = mk(marks, "6")
    panel("Phase 6  Pruning and execution proof" + tag + note,
          [("predicate", pred),
           ("pruning", f"{len(rows)} blocks: {len(rows) - skipped} opened, {skipped} skipped by their Bloom summaries (zero-bit openings)"),
           ("claimed result", kv(e["items"], "claimed result")), ("R_Exec proof", kv(e["items"], "R_Exec")),
           ("homomorphic add", kv(he["items"], "what is added").split(",")[0] + " added under encryption")] + x, e["time_s"], ok=ok)
    pause()
    # phase 7
    e = ph["7"][0]
    ok = kv(e["items"], "comparison") == "MATCH"
    x, note, ok7 = mk(marks, "7")
    if not ok7:
        x = x + [("[bold red]verdict now[/bold red]", "[bold white on red] REJECTED [/bold white on red]")]
    panel("Phase 7  Requester verifies" + tag + note,
          [("honest verdict" if marks else "verdict", "[bold green]" + kv(e["items"], "requester verdict") + "[/bold green]"),
           ("verified result", kv(e["items"], "verified result")),
           ("plaintext reference", kv(e["items"], "plain reference")),
           ("comparison", ("[bold green]" if ok else "[bold red]") + kv(e["items"], "comparison") + ("[/bold green]" if ok else "[/bold red]"))] + x,
          e["time_s"], ok=ok and ok7)
    if not marks:
        con.print(f"[dim]Sum of phase times {fmt_t(total)} (BFV pool setup excluded). {FOOT}[/dim]")
    pause()


def talk_attack(sc, n, extra=(), evs=None, card=True):
    evs = evs if evs is not None else collect(sc, n, extra)
    setup = [e for e in evs if e["kind"] == "phase"][0]
    checks = [e for e in evs if e["kind"] == "check"]
    res = [e for e in evs if e["kind"] == "result"][0]
    counted = [c for c in checks if c["counts"]]
    first = next((c for c in counted if c["status"] == "reject"), None)
    what, why, catch = ATTACK_INFO[sc]
    if card:
        con.print(Panel(f"[bold]{SCEN[sc]}[/bold]\n\n"
                        f"[bold]What the cheater does:[/bold] {what}\n"
                        f"[bold]Why (real world):[/bold] {why}\n"
                        f"[bold]What should catch it:[/bold] {catch}\n\n"
                        f"[dim]Honest setup first: {words(kv(setup['items'], 'control'))}[/dim]",
                        border_style="blue", padding=(0, 1)))
    g = Table.grid(padding=(0, 2))
    g.add_column(style="cyan", max_width=8)
    g.add_column(overflow="fold")
    for c in checks:
        mark = "" if c["counts"] else " (information, not counted)"
        g.add_row("changed" if c["counts"] else "[dim]info[/dim]", words(f"{c['title']}{mark}\n[dim]{kv(c['items'], 'what the attacker')}[/dim]"))
    from rich.console import Group
    ok = res["status"] == "ok"
    big = Text(" REJECTED " if ok else " ACCEPTED (unexpected) ", style="bold white on red" if ok else "bold black on yellow")
    big.stylize("underline", 0, 0)
    parts = [g, Text(""), Align.center(big) if False else big,
             Text(words(f"first rejecting check: {first['detail'] if first else '-'}"), style="bold red"),
             Text("rejected in phase: " + ", ".join(sorted({CATCH_AT.get(c['title'].split(':')[0], '7') for c in counted
                                                             if c['status'] == 'reject'})) + f"  (attack acts in phase {ATTACK_AT[sc][0]})",
                  style="bold red"),
             Text(f"Honest setup first: {words(kv(setup['items'], 'control'))}", style="dim"),
             Text(f"{sum(1 for c in counted if c['status'] == 'reject')} of {len(counted)} counted checks rejected. "
                  f"Time {fmt_t(res['time_s'])} including the honest setup.", style="dim")]
    con.print(Panel(Group(*parts), title=f"[bold]What the attacker changed, and the verifier's answer[/bold]",
                    border_style="red" if ok else "yellow", box=box.HEAVY, padding=(1, 2)))
    pause()


def attack_marks(sc, evs):
    """Phase key -> red lines: where the attack acts, and every counted check that rejects (with its phase)."""
    at, txt = ATTACK_AT[sc]
    marks = {at: [("ATTACK", txt)]}
    for c in evs:
        if c["kind"] != "check":
            continue
        cid = c["title"].split(":")[0]
        if c["counts"] and c["status"] == "reject":
            marks.setdefault(CATCH_AT.get(cid, "7"), []).append(
                ("REJECTED", f"{cid}: {c['title'].split(':', 1)[1].strip()} -> {c['detail']}"))
        elif not c["counts"] and "control" not in cid:
            marks.setdefault("7", []).append(("note", f"{cid} (information, not counted): {c['detail']}"))
    return marks


def attack_phases(sc, n, extra=()):
    """An attack shown phase by phase like question 1: the honest Phases 1-7, with red marks where the
    attacker acts and where each check rejects. Then the verifier's answer panel."""
    what, why, catch = ATTACK_INFO[sc]
    at = ATTACK_AT[sc][0]
    con.print(Panel(f"[bold]{SCEN[sc]}[/bold]\n\n"
                    f"[bold]What the cheater does:[/bold] {what}\n"
                    f"[bold]Why (real world):[/bold] {why}\n"
                    f"[bold]What should catch it:[/bold] {catch}\n\n"
                    f"[yellow]Next: Phases 1-7 of the honest audit (question 1). A red panel marks where the attacker acts "
                    f"(Phase {at}) and where each check rejects.[/yellow]",
                    border_style="blue", padding=(0, 1)))
    pause()
    evs = collect(sc, n, extra)
    marks = attack_marks(sc, evs)
    honest = collect("s1", n, extra) if extra else None
    talk_phases(n, honest, marks=marks, tag="")
    talk_attack(sc, n, extra, evs=evs, card=False)


def attack_matrix(n):
    """All seven attacks against the seven phases: where each one acts, and where it is rejected."""
    keys = ["1", "2", "3a", "3b", "4", "5", "6", "7"]
    t = Table(box=box.SIMPLE_HEAD, header_style="cyan", title_justify="left",
              title="All seven attacks against Phases 1-7 (ATTACK = where the cheater acts, REJECT = where a check stops it)")
    t.add_column("attack", style="bold")
    for k in keys:
        t.add_column(f"P{k}\n{PHASE_NAMES[k]}", justify="center", max_width=11, overflow="fold")
    t.add_column("checks rejected", justify="center")
    t.add_column("result", justify="center")
    for sc in ATTACKS:
        evs = collect(sc, n)
        m = attack_marks(sc, evs)
        counted = [c for c in evs if c["kind"] == "check" and c["counts"]]
        rej = sum(1 for c in counted if c["status"] == "reject")
        cells = []
        for k in keys:
            labs = [lab for lab, _ in m.get(k, [])]
            c = []
            if "ATTACK" in labs:
                c.append("[bold yellow]ATTACK[/bold yellow]")
            if "REJECTED" in labs:
                c.append(f"[bold red]REJECT x{labs.count('REJECTED')}[/bold red]")
            cells.append("\n".join(c) or "[dim].[/dim]")
        res = [e for e in evs if e["kind"] == "result"][0]
        t.add_row(sc.upper(), *cells, f"{rej} of {len(counted)}",
                  "[bold green]all rejected[/bold green]" if res["status"] == "ok" else "[bold yellow]check[/bold yellow]")
    con.print(t)
    con.print("[dim]Phase 4 = anchor transaction and the light-client read of the anchor; Phase 5 = ledger gate and Authorize on the "
              "contract; Phase 6 = the cloud cannot even build the evidence; Phase 7 = the requester's checks and Consume. "
              "Every attack is caught in or before Phase 7; nothing is accepted.[/dim]")


def attack_table():
    t = Table(box=box.SIMPLE_HEAD, header_style="cyan", title="The seven attacks (each changes ONE thing, then the real verifier runs)",
              title_justify="left")
    t.add_column("key", style="bold")
    t.add_column("what the cheater does", max_width=52, overflow="fold")
    t.add_column("what should catch it", max_width=46, overflow="fold")
    for k in ATTACKS:
        t.add_row(k, ATTACK_INFO[k][0], ATTACK_INFO[k][2])
    con.print(t)


def ask(prompt, default=""):
    try:
        v = con.input(f"[cyan]{prompt}[/cyan] [dim][{default or 'any'}][/dim]: ").strip()
    except EOFError:
        v = ""
    return v or default


DEPT_ALIASES = {
    "er": 101, "icu": 118, "admissions": 140, "admissions/records": 140, "records": 140,
    "oncology": 205, "radiology": 220, "pharmacy": 310, "laboratory": 330, "lab": 330,
    "psychiatry": 500,
}
QUERY_KEYS = ("a", "d", "c", "bmin", "bmax")
# (what the auditor wants, query, COUNT, SUM, AVG, blocks opened): real answers from demo_scenarios --scenario custom, N = 10,000
QUERY_EXAMPLES = [
    ("all exports and patients exported", "action = EXPORT", "20", "6,324", "316.2", "1 of 20"),
    ("only big exports", "action = EXPORT AND patients > 100", "14", "6,213", "443.8", "1 of 20"),
    ("only small exports", "action = EXPORT AND patients <= 100", "6", "111", "18.5", "1 of 20"),
    ("everything the insider did", "staff = 417", "27", "6,329", "234.4", "1 of 20"),
    ("did the insider also view charts?", "staff = 417 AND action = VIEW_CHART", "3", "3", "1.0", "1 of 20"),
    ("a normal staff member", "staff = 123", "15", "135", "9.0", "9 of 20"),
    ("who opened Psychiatry records", "dept = Psychiatry", "3", "3", "1.0", "1 of 20"),
    ("exports of Psychiatry records (none)", "action = EXPORT AND dept = Psychiatry", "0", "0", "undefined", "0 of 20"),
    ("ward lists (chart views of 20+ patients)", "action = VIEW_CHART AND patients >= 20", "551", "27,640", "50.2", "20 of 20"),
    ("chart views in the ICU", "action = VIEW_CHART AND dept = ICU", "745", "5,331", "7.2", "20 of 20"),
    ("logins (touch no patient)", "action = LOGIN", "1,152", "0", "0.0", "20 of 20"),
]


def parse_query(raw):
    """Turn 'action = EXPORT AND staff = 417 AND patients >= 101' (or the short form 'a=7, d=417, bmin=101')
    into the canonical key=value list the Rust program expects. Conditions are joined by AND only."""
    text = raw.strip()
    text = re.sub(r"^\s*where\s+", "", text, flags=re.I)
    text = text.replace("≥", ">=").replace("≤", "<=").replace("==", "=")
    if re.search(r"\bor\b", text, flags=re.I):
        raise ValueError("OR is not supported in this box (AND only). OR examples: bash demo/demo.sh --scenario search")
    items = [x.strip() for x in re.split(r"\s+and\s+|[,;]|&&", text, flags=re.I) if x.strip()]
    if not items:
        raise ValueError("give at least one condition, for example action = 7")
    got, bmin, bmax = {}, None, None
    for item in items:
        m = re.fullmatch(r"([A-Za-z_]+)\s*(>=|<=|=|>|<)\s*(.+)", item)
        if not m:
            raise ValueError(f"{item!r} is not a condition; write field op value, for example action = 7 or patients >= 101")
        key, op, val = m.group(1).lower(), m.group(2), m.group(3).strip()
        key = {"action": "a", "staff": "d", "dept": "c", "department": "c", "patients": "b", "patient": "b",
               "min": "bmin", "max": "bmax", "patients_min": "bmin", "patients_max": "bmax"}.get(key, key)
        if key in ("bmin", "bmax"):
            if op != "=":
                raise ValueError(f"use {key}=N (or patients {op} N)")
            key, op = "b", (">=" if key == "bmin" else "<=")
        if key not in ("a", "d", "c", "b"):
            raise ValueError(f"unknown field {m.group(1)!r}; use action, staff, dept, patients (or a, d, c, bmin, bmax)")
        if key != "b" and op != "=":
            raise ValueError(f"{m.group(1)} takes only '=' (ranges are for patients)")
        if key == "a":
            if not val.isdigit():
                want = val.lower().replace("_records", "").replace(" ", "")
                code = next((str(c) for c, name, *_ in ACTION_INFO
                             if name.lower().replace("_records", "") == want), None)
                if code is None:
                    raise ValueError(f"unknown action {val!r}; use 1-7 or EXPORT, VIEW, ...")
                val = code
            if not 1 <= int(val) <= 7:
                raise ValueError("action code must be 1-7")
        elif key == "c":
            if not val.isdigit():
                code = DEPT_ALIASES.get(val.lower().replace(" ", ""))
                if code is None:
                    raise ValueError(f"unknown department {val!r}; use a code 101-500 or its name")
                val = str(code)
        elif not val.isdigit():
            raise ValueError(f"{m.group(1)} must be a number")
        v = int(val)
        if key == "b":
            lo, hi = {"=": (v, v), ">=": (v, None), ">": (v + 1, None), "<=": (None, v), "<": (None, v - 1)}[op]
            if lo is not None:
                bmin = lo if bmin is None else max(bmin, lo)
            if hi is not None:
                if hi < 0:
                    raise ValueError("patients < 0 matches nothing")
                bmax = hi if bmax is None else min(bmax, hi)
        else:
            got[key] = str(v)
    if bmin is not None and bmin > 0:
        got["bmin"] = str(bmin)
    if bmax is not None:
        got["bmax"] = str(bmax)
    if bmin is not None and bmax is not None and bmin > bmax:
        raise ValueError("patients range is empty (min > max)")
    if not got:
        raise ValueError("give at least one condition, for example action = 7")
    return [f"{k}={got[k]}" for k in QUERY_KEYS if k in got]


def agg_line(sel):
    """'20 records, sum of b = 6324 (...)' -> 'COUNT = 20 records, SUM = 6,324 patients, AVG = 316.2 patients per record'.
    AVG = SUM / COUNT, as the report defines it (undefined when COUNT = 0)."""
    m = re.match(r"\s*(\d+) records?, sum of b = (\d+)", sel)
    if not m:
        return words(sel)
    c, t = int(m.group(1)), int(m.group(2))
    avg = f"{t / c:,.1f} patients per record" if c else "undefined (no record matches)"
    return f"COUNT = {c:,} records, SUM = {t:,} patients, AVG = {avg}  (search layer, not proved)"


def talk_custom(n):
    con.print(Rule("Question 15 · Your own query (search layer)"))
    guide = (
        "[bold]How to write a query[/bold]  (like a SQL WHERE clause, conditions joined by AND)\n"
        "  [bold]action[/bold] = 7         action code 1-7 or a name (7 = EXPORT)\n"
        "  [bold]staff[/bold] = 417        staff id\n"
        "  [bold]dept[/bold] = 500         department: 101 ER, 118 ICU, 140 Admissions/Records, 205 Oncology, 220 Radiology, 310 Pharmacy, 330 Laboratory, 500 Psychiatry (or its name)\n"
        "  [bold]patients[/bold] >= 101    patients touched; operators =, >=, >, <=, <\n"
        "Short form also works: a=7, d=417, c=500, bmin=101, bmax=100 (comma = AND).\n"
        "OR is not in this box: compound OR queries are shown with  bash demo/demo.sh --scenario search\n\n"
        "Every answer gives [bold]COUNT[/bold] (how many records), [bold]SUM[/bold] (total patients touched) "
        "and [bold]AVG[/bold] (SUM / COUNT, patients per record). Examples to copy are in the table below.\n\n"
        "Leave a condition out to mean 'any'. The answer is checked against the plain log. "
        "Search layer only: for a proved answer use question 1, 9, 10 or 11."
    )
    con.print(Panel(guide, title="[bold]Query syntax and examples[/bold]", border_style="blue", padding=(0, 2)))
    et = Table(box=box.SIMPLE, header_style="cyan", title="Examples to type (real answers at N = 10,000)", title_justify="left")
    for h, j in (("auditor wants to know", "left"), ("type this", "left"), ("COUNT", "right"), ("SUM patients", "right"),
                 ("AVG", "right"), ("blocks opened", "right")):
        et.add_column(h, justify=j)
    for row in QUERY_EXAMPLES:
        et.add_row(*row)
    con.print(et)
    raw = ask("query (Enter = action = EXPORT AND patients > 100)", "action = EXPORT AND patients > 100")
    try:
        parts = parse_query(raw)
    except ValueError as exc:
        con.print(f"[red]{exc}[/red]")
        return
    query_phases(n, parts, question=f"your query: {raw}")


def show_query(n, parts, question=None, lesson=None):
    """Run one search-layer query (keys a, d, c, bmin, bmax as the Rust program expects) and show the answer."""
    evs = collect("custom", n, ("--q", ",".join(parts)))
    e = next(x for x in evs if x["kind"] == "phase" and x["phase"] == "Q*")
    rows = e["tables"][0]["rows"]
    opened = [r[0] for r in rows if not r[2].startswith("SKIPPED")]
    chk = kv(e["items"], "plaintext reference").split("-> ")[-1]
    sel = e["tables"][1]["rows"]
    st = Table(box=box.SIMPLE, header_style="cyan")
    for h in ["id", "time", "action", "patients", "dept", "staff"]:
        st.add_column(h)
    for r in sel:
        st.add_row(*short_row(r))
    from rich.console import Group
    head = [Text.from_markup(f"[bold magenta]Auditor asks:[/bold magenta] [bold]{question}[/bold]")] if question else []
    tail = [Text.from_markup(f"[bold]What this shows:[/bold] {lesson}")] if lesson else []
    body = Group(
        *head,
        Text.from_markup(f"[bold]{words(e['title'])}[/bold]"),
        Text.from_markup(f"result: [bold]{agg_line(kv(e['items'], 'selected'))}[/bold]"),
        Text.from_markup(f"blocks opened: [bold]{len(opened)} of {len(rows)}[/bold]"
                         + (f" (blocks {', '.join(opened[:10])}{' ...' if len(opened) > 10 else ''})" if opened else "")
                         + f"; the other {len(rows) - len(opened)} are skipped by their Bloom summary"),
        Text.from_markup("plaintext check: " + ("[green]MATCH[/green]" if chk == "MATCH" else f"[red]{chk}[/red]")
                         + "  [dim](the same condition run on the plain log)[/dim]"),
        Text(""), st if sel else Text("no record matches", style="dim"),
        *tail,
        Text("Rare condition -> few blocks opened. Common condition -> most blocks opened. "
             "Search layer only (no proof). For a proved result, pick question 1, 9, 10 or 11.", style="yellow"))
    con.print(Panel(body, title="[bold]Your query on the encrypted log[/bold]", border_style="green", padding=(0, 2)))
    pause()


def query_phases(n, parts, question=None, lesson=None):
    """A search-layer question shown phase by phase: Phases 1-4 are the same protected, anchored log as
    question 1 (reused, not rebuilt); Phases 5-7 are the real run of THIS query. No proof for this path."""
    if question:
        con.print(f"[bold magenta]Auditor asks:[/bold magenta] [bold]{question}[/bold]")
    ph = phase_values(phase_events(n))
    show_p1_4(ph, tag="  [dim](same log and anchor as question 1)[/dim]")
    evs = collect("custom", n, ("--q", ",".join(parts)))
    e = next(x for x in evs if x["kind"] == "phase" and x["phase"] == "Q*")
    rows = e["tables"][0]["rows"]
    opened = [r[0] for r in rows if not r[2].startswith("SKIPPED")]
    chk = kv(e["items"], "plaintext reference").split("-> ")[-1]
    sel = e["tables"][1]["rows"]
    panel("Phase 5  Request: the query becomes a search token",
          [("query", words(e["title"]).replace("Your query: ", "")),
           ("search token", kv(e["items"], "trapdoor") + " (the cloud sees tags, not the values)"),
           ("R_Auth proof", "[yellow]not run on this path: in the prototype, R_Auth and R_Exec cover the proved predicate action = x only[/yellow]")],
          None)
    pause()
    grid = " ".join(("[bold green]" + r[0] + "[/bold green]") if not r[2].startswith("SKIPPED") else ("[dim]" + r[0] + "[/dim]") for r in rows)
    panel("Phase 6  Execution: skip blocks, test records",
          [("pruning", f"{len(rows)} blocks: [bold]{len(opened)} opened[/bold], {len(rows) - len(opened)} skipped by their Bloom summaries"),
           ("blocks", grid + "  [dim](green = opened)[/dim]"),
           ("result", agg_line(kv(e["items"], "selected"))),
           ("R_Exec proof", "[yellow]not made on this path (search layer)[/yellow]")],
          e["time_s"])
    pause()
    st = Table(box=box.SIMPLE, header_style="cyan", title="Selected records (plaintext shown only because this is a demo)", title_justify="left")
    for h in ["id", "time", "action", "patients", "dept", "staff"]:
        st.add_column(h)
    for r in sel:
        st.add_row(*short_row(r))
    ok = chk == "MATCH"
    panel("Phase 7  Check the answer",
          [("plaintext check", ("[bold green]MATCH[/bold green]" if ok else f"[bold red]{chk}[/bold red]") + "  (the same condition run on the plain log)"),
           ("verdict", "[yellow]search answer, checked against the plain log; no proof to verify on this path[/yellow]")]
          + ([("what this shows", lesson)] if lesson else []),
          None, ok=ok, extra=st if sel else None)
    pause()


def proved_phases(n, v, question=None, lesson=None):
    """A proved question for action = v, shown phase by phase like question 1 (the epoch is rebuilt for v)."""
    name = next(a[1] for a in ACTION_INFO if str(a[0]) == v)
    if question:
        con.print(f"[bold magenta]Auditor asks:[/bold magenta] [bold]{question}[/bold]")
    talk_phases(n, collect("s1", n, ("--x", v)), pred=f"P1: action = {v} ({name})")
    if lesson:
        con.print(f"[yellow][bold]What this shows:[/bold] {lesson} Note: x is fixed when the log is built, so the epoch was rebuilt and re-anchored for action = {v}.[/yellow]")


def talk_proved(n):
    con.print(Rule("Full proved audit for another action: phases 1 to 7 again, with P1 = (action = x)"))
    con.print(action_table(LAST.get("hist")))
    v = ask("action code x for the proved audit (1-7)", "3")
    if v not in ("1", "2", "3", "4", "5", "6", "7"):
        con.print(f"[red]{v!r} is not an action code 1-7[/red]")
        return
    proved_phases(n, v, question=f"How many {next(a[1] for a in ACTION_INFO if str(a[0]) == v)} actions were there? (proved)")
    if ask("let the cloud cheat on this answer (claim one more, attack A1)? y/n", "y").lower().startswith("y"):
        attack_phases("a1", n, ("--x", v))


def run_proved(n, v, offer_attack=True, question=None, lesson=None):
    """Phases 1-7 again with P1 = (action = v): rebuild, anchor, prove, verify."""
    name = next(a[1] for a in ACTION_INFO if str(a[0]) == v)
    if question:
        con.print(f"[bold magenta]Auditor asks:[/bold magenta] [bold]{question}[/bold]")
    evs = collect("s1", n, ("--x", v))
    ph = {}
    for e in evs:
        if e["kind"] == "phase":
            ph.setdefault(e["phase"], []).append(e)
    res = [e for e in evs if e["kind"] == "result"][0]
    e6, e7 = ph["6"][0], ph["7"][0]
    rows = e6["tables"][0]["rows"]
    skipped = sum(1 for r in rows if r[2] == "SKIPPED")
    total = sum(e["time_s"] or 0 for e in evs if e["kind"] == "phase" and e is not ph["6"][1])
    omega, dq = kv(ph["4"][0]["items"], "Omega_e"), kv(ph["5"][0]["items"], "public: d_Q")
    ok = res["status"] == "ok"
    match = kv(e7["items"], "comparison")
    lines = [
        ("question", f"COUNT and SUM(patients) where action = {v} ({name})"),
        ("phases 1-4", f"log rebuilt and anchored again for action = {v}: new Omega_e {omega[:16]}..."
                       + (" (differs from the action = 7 run)" if LAST.get("omega") and LAST["omega"] != omega else "")),
        ("phase 5 R_Auth", kv(ph["5"][0]["items"], "verify_auth_stage")),
        ("phase 6 pruning", f"{len(rows)} blocks: {len(rows) - skipped} opened, {skipped} skipped"),
        ("phase 6 R_Exec", kv(e6["items"], "R_Exec")),
        ("claimed result", kv(e6["items"], "claimed result")),
        ("phase 7 verdict", ("[bold green]" if ok else "[bold red]") + kv(e7["items"], "requester verdict") + ("[/bold green]" if ok else "[/bold red]")),
        ("verified result", kv(e7["items"], "verified result")),
        ("plaintext reference", kv(e7["items"], "plain reference")),
        ("comparison", ("[bold green]" if match == "MATCH" else "[bold red]") + match + ("[/bold green]" if match == "MATCH" else "[/bold red]")),
    ]
    panel(f"Proved audit for action = {v} ({name})", lines, total, ok=ok and match == "MATCH")
    notes = [f"[bold]What this shows:[/bold] {lesson}"] if lesson else []
    if skipped == 0:
        notes.append(f"{name} is a common action, so every block may contain it and nothing is skipped. "
                     "Only EXPORT (action = 7) is rare in this log, so only action = 7 shows block skipping.")
    notes.append("Honest limits: x is fixed when the log is built (v_of puts the value into the log), so a new action needs a "
                 "rebuilt and re-anchored epoch, as done here.")
    if LAST.get("dq") and LAST["dq"] == dq:
        notes.append("The authorization hashes the text 'P1: A = x', not the value of x: d_Q is the same as in the action = 7 run.")
    con.print("[yellow]" + "\n".join(notes) + "[/yellow]")
    pause()
    if offer_attack and ask("let the cloud cheat on this answer (claim one more, attack A1)? y/n", "y").lower().startswith("y"):
        attack_phases("a1", n, ("--x", v))


# ONE audit menu, shown at the start and after every answer. Ordered like the story:
# the main proved audit, follow-ups on the insider, normal activity for comparison,
# other proved audits, can the cloud cheat, your own query.
# kinds: ("story",) full Phases 1-7 for action = 7; ("q", parts) search layer; ("x", code) proved audit;
# ("fn", name) a helper below. Expected answers (N = 10,000): DEMO-README.md.
MENU = [
    ("Question 1 · the insider story (proved, full Phases 1-7)", [
        ("How many EXPORT_RECORDS actions were there, and how many patient records did they export in total?",
         ("story",),
         "the full audit: protect, anchor, authorize, run, prove, verify. In this log every export belongs to staff 417's burst."),
    ]),
    ("Questions 2-5 · follow up on the insider (Phase 1-7 recap + search)", [
        ("Did the insider make big exports, more than 100 patients each?", ("q", ["a=7", "bmin=101"]),
         "a rare condition: the Bloom summaries let the cloud skip almost every block."),
        ("Did the insider make small exports, 100 patients or fewer?", ("q", ["a=7", "bmax=100"]),
         "a range on the patients field, not only equality."),
        ("What else did the insider, staff 417, do in this epoch?", ("q", ["d=417"]),
         "a question about a person instead of an action: all their records, not only the exports."),
        ("Did the insider export any Psychiatry (department 500) records?", ("q", ["a=7", "c=500"]),
         "a question whose honest answer is 'none'. The empty answer is also checked against the plain log."),
    ]),
    ("Questions 6-8 · compare with normal activity (Phase 1-7 recap + search)", [
        ("What did an ordinary staff member (staff 123) do?", ("q", ["d=123"]),
         "a normal user's records are spread over the epoch, so many more blocks are opened than for the insider."),
        ("Who opened records in Psychiatry (department 500)?", ("q", ["c=500"]),
         "a sensitive department: only a few records, so only a few blocks are opened."),
        ("How many chart views touched 50 or more patients?", ("q", ["a=1", "bmin=50"]),
         "a common condition: every block may match, so nothing is skipped. Pruning helps only rare conditions."),
    ]),
    ("Questions 9-10 · other proved audits (Phases 1-7 for another action)", [
        ("How many prints were there? (proved)", ("x", "3"),
         "a common action: the proof still verifies, but no block is skipped."),
        ("How many logins were there? (proved)", ("x", "4"),
         "a login touches no patient records, so SUM(patients) = 0 is the correct proved answer."),
    ]),
    ("Questions 11-15 · extra: another proved action, attacks, your own query", [
        ("Any action code you choose (proved)", ("fn", "proved"), None),
        ("A2: the cloud hides a block that has matches (Phases 1-7, red = where it is caught)", ("fn", "a2"), None),
        ("Choose an attack A1-A7, shown phase by phase", ("fn", "pick"), None),
        ("All 7 attacks: which phase each one hits and where it is rejected", ("fn", "all"), None),
        ("Build your own query: action, staff, department, patients (Phase 1-7 recap + search)", ("fn", "custom"), None),
    ]),
]


def menu_table():
    flat = []
    t = Table(box=box.SIMPLE_HEAD, header_style="cyan", show_header=False, padding=(0, 1))
    t.add_column("key", style="bold", justify="right")
    t.add_column("question", overflow="fold", max_width=68)
    t.add_column("query", style="dim", overflow="fold", max_width=34)
    for group, items in MENU:
        t.add_row("", f"[bold underline]{group}[/bold underline]", "")
        for q, kind, lesson in items:
            flat.append((q, kind, lesson))
            if kind[0] == "q":
                qtxt = words(" AND ".join(p.replace("=", " = ").replace("bmin = ", "b >= ").replace("bmax = ", "b <= ")
                                          for p in kind[1]))
            elif kind[0] == "x":
                qtxt = f"proved: action = {kind[1]}"
            elif kind[0] == "story":
                qtxt = "proved: action = 7 (the story)"
            else:
                qtxt = ""
            t.add_row(str(len(flat)), q, qtxt)
    return flat, t


def run_item(n, item):
    q, kind, lesson = item
    k = kind[0]
    if k == "story":
        con.print(f"[bold magenta]Auditor asks:[/bold magenta] [bold]{q}[/bold]")
        talk_phases(n)
    elif k == "q":
        query_phases(n, kind[1], question=q, lesson=lesson)
    elif k == "x":
        proved_phases(n, kind[1], question=q, lesson=lesson)
    elif kind[1] == "proved":
        talk_proved(n)
    elif kind[1] == "a2":
        attack_phases("a2", n)
    elif kind[1] == "pick":
        attack_table()
        try:
            a = con.input("[cyan]attack a1-a7: [/cyan]").strip().lower()
        except EOFError:
            a = ""
        if a in ATTACKS:
            attack_phases(a, n)
        else:
            con.print(f"[red]{a!r} is not an attack name[/red]")
    elif kind[1] == "all":
        attack_table()
        attack_matrix(n)
        pause()
    elif kind[1] == "custom":
        talk_custom(n)


def talk(n, no_pause):
    talk_intro(n)
    if no_pause:
        talk_phases(n)
        talk_attack(RECOMMENDED, n)
        return
    flat, t = menu_table()
    while True:
        con.print(Rule("Audit menu: pick a question (Enter = 1, q = quit)"))
        con.print(t)
        try:
            k = con.input(f"[cyan]question 1-{len(flat)} [1]: [/cyan]").strip().lower() or "1"
        except EOFError:
            return
        if k == "q":
            return
        if not k.isdigit() or not 1 <= int(k) <= len(flat):
            con.print(f"[red]{k!r} is not a number from the list[/red]")
            continue
        run_item(n, flat[int(k) - 1])


def main():
    global PAUSE
    ap = argparse.ArgumentParser(description="PQZ-Audit live demo")
    ap.add_argument("--scenario", "-s", choices=list(SCEN))
    ap.add_argument("--all-attacks", action="store_true", help="run A1..A7 and show one results table")
    ap.add_argument("--full", action="store_true", help="full view (every table) instead of the short talk mode")
    ap.add_argument("--no-pause", action="store_true", help="no ENTER pauses")
    ap.add_argument("--n", type=int, default=10000, help="log size, multiple of 500, >= 2000 (default 10000, as on slide 27)")
    a = ap.parse_args()
    PAUSE = not a.no_pause
    con.print(Panel("[bold]PQZ-Audit[/bold]: privacy-preserving, post-quantum, verifiable audit-log queries\n"
                    "Use case: hospital EHR access log, insider data theft", border_style="blue"))
    build()
    if not (a.all_attacks or a.scenario or a.full):
        talk(a.n, a.no_pause)
        return
    outs = []
    if a.all_attacks:
        for sc in ATTACKS:
            con.print(f"[dim]running {sc} ...[/dim]")
            outs.append(run_scenario(sc, a.n, quiet=True))
        summary(outs)
        return
    if a.scenario:
        outs.append(run_scenario(a.scenario, a.n))
        summary(outs)
        return
    outs.append(run_scenario("s1", a.n))
    if a.no_pause:
        outs.append(run_scenario(RECOMMENDED, a.n))
    else:
        pause("ENTER for the attack menu")
        while True:
            c = menu()
            if c == "q":
                break
            if c == "all":
                for sc in ATTACKS:
                    outs.append(run_scenario(sc, a.n, quiet=True))
                break
            if c not in SCEN or c == "s1":
                con.print("[red]unknown choice[/red]")
                continue
            outs.append(run_scenario(c, a.n))
            break
    summary(outs)


if __name__ == "__main__":
    main()
