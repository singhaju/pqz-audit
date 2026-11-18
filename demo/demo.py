#!/usr/bin/env python3
"""PQZ-Audit live demo: hospital EHR access-log audit (insider data theft).

Every number, hash, ACCEPT/REJECT and error text on screen comes from the real library code, run by the
Rust program pqz-integrated-w46/src/bin/demo_scenarios.rs (JSON Lines on stdout). Nothing is hard-coded here.

Run from anywhere:
    bash demo/demo.sh                      # TALK mode: one short panel per phase, then a menu (attack, predicates)
    bash demo/demo.sh --full               # S1 with every table, then ONE attack from a menu
    bash demo/demo.sh --scenario a2        # skip the menu, one scenario (s1 a1..a7 search)
    bash demo/demo.sh --all-attacks        # A1..A7 and one results table
    bash demo/demo.sh --no-pause           # no ENTER pauses (S1 then A2, no menu)
"""
import argparse
import json
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
FOOT = "Timings: this laptop, one run, not a paper number."

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
        t.add_row(*r)
    return t


def show_phase(e):
    g = Table.grid(padding=(0, 2))
    g.add_column(style="cyan", no_wrap=False, max_width=34)
    g.add_column(overflow="fold")
    for k, v in e["items"]:
        g.add_row(k, v)
    parts = [g]
    for tb in e["tables"]:
        parts.append(Text(""))
        parts.append(table_of(tb))
    if e["note"]:
        parts.append(Text(""))
        parts.append(Text("Note: " + e["note"], style="yellow"))
    sub = f"time {fmt_t(e['time_s'])}" if e["time_s"] is not None else ""
    ok = e["status"] == "ok"
    ph = e["phase"]
    con.print(Panel(__import__("rich.console", fromlist=["Group"]).Group(*parts),
                    title=f"[bold]Phase {ph}[/bold]  {e['title']}", subtitle=sub,
                    border_style="green" if ok else "red", box=box.ROUNDED, padding=(1, 2)))


def show_check(e):
    rej = e["status"] == "reject"
    g = Table.grid(padding=(0, 2))
    g.add_column(style="cyan", max_width=30)
    g.add_column(overflow="fold")
    for k, v in e["items"]:
        g.add_row(k, v)
    verdict = "REJECTED" if rej else "ACCEPTED"
    style = "bold red" if rej else "bold green"
    g.add_row("verifier says", Text(f"{verdict}: {e['detail']}", style=style))
    if not e["counts"]:
        g.add_row("", Text("(information step, not counted in the attack verdict)", style="dim"))
    con.print(Panel(g, title=f"[bold]{e['title']}[/bold]", subtitle=f"time {fmt_t(e['time_s'])}",
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
        g.add_row(k, v)
    parts = [g]
    if extra is not None:
        parts += [Text(""), extra]
    from rich.console import Group
    con.print(Panel(Group(*parts), title=f"[bold]{title}[/bold]", subtitle=f"time {fmt_t(t)}" if t is not None else "",
                    border_style="green" if ok else "red", box=box.ROUNDED, padding=(0, 2)))


def short_row(r):
    # r = id, time, action, b, dept, staff, hit
    return [r[0], r[1][11:], r[2].split(" ", 1)[1].split("_")[0], r[3], r[4].split(" ")[0], r[5]]


def talk_intro(n):
    g = n // 500
    body = ("[bold]Story:[/bold] a hospital keeps its EHR access log in the cloud, encrypted. An insider (staff 417) "
            "exports patient records in a burst. The auditor must find out, without the cloud being trusted.\n\n"
            "[bold]Question:[/bold] COUNT and SUM(b) of the EXPORT_RECORDS actions (a = 7) in this epoch.\n"
            "Each record is (a, b, c, d): a = action code, b = number of patient records touched, c = department, d = staff id.\n"
            f"[dim]Action codes: {ACTION_CODES}. So a = 7 means \"bulk export of patient records\".[/dim]\n\n"
            f"[bold]Log:[/bold] N = {n:,} records, {g} blocks of 500.\n\n"
            "[yellow]Honest labels:[/yellow] blockchain = in-process simulation (4 validators, no network); STARK proofs = plain mode, "
            "not zero-knowledge; timings = this laptop, one run.")
    con.print(Panel(body, title="[bold]PQZ-Audit demo[/bold]", border_style="blue", padding=(1, 2)))


def talk_phases(n):
    evs = collect("s1", n)
    ph = {}
    for e in evs:
        if e["kind"] == "phase":
            ph.setdefault(e["phase"], []).append(e)
    res = [e for e in evs if e["kind"] == "result"][0]
    total = 0.0
    for e in evs:
        if e["kind"] == "phase" and e["time_s"] and not (e["phase"] == "6" and e is ph["6"][1]):
            total += e["time_s"]
    # phase 1
    e = ph["1"][0]
    panel("Phase 1  Initialization", [("ledger", kv(e["items"], "ledger")), ("Omega_0", kv(e["items"], "Omega_0")),
                                       ("epoch / log", kv(e["items"], "epoch e"))], e["time_s"])
    pause()
    # phase 2: 3 normal + 3 insider export rows (taken from the real tables)
    e = ph["2"][0]
    normal = [r for r in e["tables"][0]["rows"] if r[6] == "-"][:3]
    hits = [r for r in e["tables"][1]["rows"] if r[6] == "HIT"][:3]
    t = Table(box=box.SIMPLE_HEAD, header_style="cyan", title="Plaintext log rows: a = action, b = patients, c = dept, d = staff",
              title_justify="left")
    for h in ["id", "time", "a", "b", "c", "d"]:
        t.add_column(h)
    for r in normal:
        t.add_row(*short_row(r))
    for r in hits:
        t.add_row(*[f"[bold red]{x}[/bold red]" for x in short_row(r)])
    panel("Phase 2  Registration (plain log)", [("insider burst", kv(e["items"], "log generation"))], e["time_s"], extra=t)
    pause()
    # phase 3a
    e = ph["3a"][0]
    r0 = e["tables"][0]["rows"][0]
    panel("Phase 3a  Encrypt and tag (what the cloud stores)",
          [("row 0 as the cloud sees it", f"ciphertext {r0[1]}  ({r0[2]} bytes), {r0[3]} search tags"),
           ("whole epoch", kv(e["items"], "whole epoch")), ("key holder check", kv(e["items"], "decrypt check"))], e["time_s"])
    pause()
    # phase 3b
    e = ph["3b"][0]
    nb = len(e["tables"][0]["rows"])
    panel("Phase 3b  Blocks, R_RC proofs, AA check",
          [("blocks", f"{nb} blocks, each with a Bloom summary; R_e = {kv(e['items'], 'R_e')}"),
           ("R_RC proofs", kv(e["items"], "R_RC proofs")), ("AA check", kv(e["items"], "AA check").split(":")[0])], e["time_s"])
    pause()
    # phase 4
    e = ph["4"][0]
    panel("Phase 4  Anchor on the (simulated) blockchain",
          [("Omega_e", kv(e["items"], "Omega_e")[:24] + "..."), ("ledger block", kv(e["items"], "ledger block")),
           ("light-client read", kv(e["items"], "light-client"))], e["time_s"])
    pause()
    # phase 5
    e = ph["5"][0]
    panel("Phase 5  Authorization proof R_Auth",
          [("request", kv(e["items"], "request")), ("R_Auth proof", kv(e["items"], "R_Auth proof")),
           ("verifier", kv(e["items"], "verify_auth_stage"))], e["time_s"])
    pause()
    # phase 6
    e, he = ph["6"][0], ph["6"][1]
    rows = e["tables"][0]["rows"]
    skipped = sum(1 for r in rows if r[2] == "SKIPPED")
    panel("Phase 6  Pruning and execution proof",
          [("predicate", "P1: a = 7 (EXPORT_RECORDS)"),
           ("pruning", f"{len(rows)} blocks: {len(rows) - skipped} opened, {skipped} skipped by their Bloom summaries (zero-bit openings)"),
           ("claimed result", kv(e["items"], "claimed result")), ("R_Exec proof", kv(e["items"], "R_Exec")),
           ("homomorphic add", kv(he["items"], "what is added").split(",")[0] + " added under encryption")], e["time_s"])
    pause()
    # phase 7
    e = ph["7"][0]
    ok = kv(e["items"], "comparison") == "MATCH"
    panel("Phase 7  Requester verifies",
          [("verdict", "[bold green]" + kv(e["items"], "requester verdict") + "[/bold green]"),
           ("verified result", kv(e["items"], "verified result")),
           ("plaintext reference", kv(e["items"], "plain reference")),
           ("comparison", ("[bold green]" if ok else "[bold red]") + kv(e["items"], "comparison") + ("[/bold green]" if ok else "[/bold red]"))],
          e["time_s"], ok=ok)
    con.print(f"[dim]Sum of phase times {fmt_t(total)} (BFV pool setup excluded). {FOOT}[/dim]")
    pause()


def talk_attack(sc, n):
    evs = collect(sc, n)
    setup = [e for e in evs if e["kind"] == "phase"][0]
    checks = [e for e in evs if e["kind"] == "check"]
    res = [e for e in evs if e["kind"] == "result"][0]
    counted = [c for c in checks if c["counts"]]
    first = next((c for c in counted if c["status"] == "reject"), None)
    what, why, catch = ATTACK_INFO[sc]
    con.print(Panel(f"[bold]{SCEN[sc]}[/bold]\n\n"
                    f"[bold]What the cheater does:[/bold] {what}\n"
                    f"[bold]Why (real world):[/bold] {why}\n"
                    f"[bold]What should catch it:[/bold] {catch}\n\n"
                    f"[dim]Honest setup first: {kv(setup['items'], 'control')}[/dim]",
                    border_style="blue", padding=(0, 1)))
    g = Table.grid(padding=(0, 2))
    g.add_column(style="cyan", max_width=8)
    g.add_column(overflow="fold")
    for c in checks:
        mark = "" if c["counts"] else " (information, not counted)"
        g.add_row("changed" if c["counts"] else "[dim]info[/dim]", f"{c['title']}{mark}\n[dim]{kv(c['items'], 'what the attacker')}[/dim]")
    from rich.console import Group
    ok = res["status"] == "ok"
    big = Text(" REJECTED " if ok else " ACCEPTED (unexpected) ", style="bold white on red" if ok else "bold black on yellow")
    big.stylize("underline", 0, 0)
    parts = [g, Text(""), Align.center(big) if False else big,
             Text(f"first rejecting check: {first['detail'] if first else '-'}", style="bold red"),
             Text(f"{sum(1 for c in counted if c['status'] == 'reject')} of {len(counted)} counted checks rejected. "
                  f"Time {fmt_t(res['time_s'])} including the honest setup.", style="dim")]
    con.print(Panel(Group(*parts), title=f"[bold]What the attacker changed, and the verifier's answer[/bold]",
                    border_style="red" if ok else "yellow", box=box.HEAVY, padding=(1, 2)))
    pause()


def talk_predicates(n):
    evs = collect("search", n)
    t = Table(box=box.SIMPLE_HEAD, header_style="cyan", title="Predicate examples: SEARCH LAYER ONLY, no proof (the R_Exec proof covers a = 7 only)",
              title_justify="left")
    t.add_column("predicate", max_width=46, overflow="fold")
    t.add_column("hits", justify="right")
    t.add_column("blocks opened", justify="right")
    t.add_column("plaintext check")
    for e in evs:
        if e["kind"] == "phase" and e["phase"].startswith("Q"):
            rows = e["tables"][0]["rows"]
            skipped = sum(1 for r in rows if r[2].startswith("SKIPPED"))
            hits = kv(e["items"], "selected").split(" records")[0]
            chk = kv(e["items"], "plaintext reference").split("-> ")[-1]
            t.add_row(e["title"], hits, f"{len(rows) - skipped} of {len(rows)}", ("[green]" if chk == "MATCH" else "[red]") + chk)
    con.print(t)
    con.print("[yellow]Why search only: the execution proof's predicate is fixed to a = 7 when the log is built (v_of). "
              "Opened = block kept by its Bloom summary; the others are skipped.[/yellow]")
    pause()


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


def talk_custom(n):
    con.print(Rule("Your own query (search layer only, no proof)"))
    con.print(f"[dim]a = action: {ACTION_CODES}\nc = department: {DEPT_CODES}\n"
              "d = staff id (100..999; the insider is 417)   b = patients touched (export burst: up to ~900)\n"
              "Leave a field empty for 'any'.[/dim]")
    parts = []
    for key, prompt, default in [("a", "action a", "7"), ("d", "staff d", ""), ("c", "department c", ""),
                                 ("bmin", "at least b patients", ""), ("bmax", "at most b patients", "")]:
        v = ask(prompt, default)
        if v:
            if not v.isdigit():
                con.print(f"[red]{v!r} is not a number; ignored[/red]")
                continue
            parts.append(f"{key}={v}")
    if not parts:
        con.print("[red]no condition given[/red]")
        return
    evs = collect("custom", n, ("--q", ",".join(parts)))
    e = next(x for x in evs if x["kind"] == "phase" and x["phase"] == "Q*")
    rows = e["tables"][0]["rows"]
    opened = [r[0] for r in rows if not r[2].startswith("SKIPPED")]
    chk = kv(e["items"], "plaintext reference").split("-> ")[-1]
    sel = e["tables"][1]["rows"]
    st = Table(box=box.SIMPLE, header_style="cyan")
    for h in ["id", "time", "action", "b", "dept", "staff"]:
        st.add_column(h)
    for r in sel:
        st.add_row(*short_row(r))
    from rich.console import Group
    body = Group(
        Text.from_markup(f"[bold]{e['title']}[/bold]"),
        Text.from_markup(f"result: [bold]{kv(e['items'], 'selected')}[/bold]"),
        Text.from_markup(f"blocks opened: [bold]{len(opened)} of {len(rows)}[/bold]"
                         + (f" (blocks {', '.join(opened[:10])}{' ...' if len(opened) > 10 else ''})" if opened else "")
                         + f"; the other {len(rows) - len(opened)} are skipped by their Bloom summary"),
        Text.from_markup("plaintext check: " + ("[green]MATCH[/green]" if chk == "MATCH" else f"[red]{chk}[/red]")
                         + "  [dim](the same condition run on the plain log)[/dim]"),
        Text(""), st if sel else Text("no record matches", style="dim"),
        Text("Rare condition -> few blocks opened. Common condition -> most blocks opened. "
             "Search layer only: the end-to-end proof in this prototype covers a = 7.", style="yellow"))
    con.print(Panel(body, title="[bold]Your query on the encrypted log[/bold]", border_style="green", padding=(0, 2)))
    pause()


def talk_menu():
    con.print(Rule("What next?"))
    con.print("  [bold]1[/bold] attack A2: the cloud hides a block with matches   [dim](Enter)[/dim]")
    con.print("  [bold]2[/bold] choose another attack (list with explanations)")
    con.print("  [bold]3[/bold] predicate examples (search layer only, no proof)")
    con.print("  [bold]4[/bold] all attacks, one table")
    con.print("  [bold]5[/bold] your own query: pick action, staff, department, patients (search layer)")
    con.print("  [bold]q[/bold] quit")
    try:
        return con.input("[cyan]choice [1]: [/cyan]").strip().lower() or "1"
    except EOFError:
        return "q"


def talk(n, no_pause):
    talk_intro(n)
    pause("ENTER to start")
    talk_phases(n)
    if no_pause:
        talk_attack(RECOMMENDED, n)
        return
    while True:
        c = talk_menu()
        if c == "q":
            return
        if c == "1":
            talk_attack("a2", n)
        elif c == "2":
            attack_table()
            try:
                k = con.input("[cyan]attack: [/cyan]").strip().lower()
            except EOFError:
                k = ""
            if k in ATTACKS:
                talk_attack(k, n)
        elif c == "3":
            talk_predicates(n)
        elif c == "5":
            talk_custom(n)
        elif c == "4":
            attack_table()
            outs = []
            for sc in ATTACKS:
                outs.append(run_scenario(sc, n, quiet=True))
            summary(outs)
            pause()
        else:
            con.print("[red]unknown choice[/red]")


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
