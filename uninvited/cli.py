"""Command line: python -m uninvited <command>"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path

from . import __version__, ai, collect, report as rpt

if os.name == "nt":
    os.system("")  # enable ANSI colours in the Windows console
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

C = {"dim": "\033[2m", "b": "\033[1m", "r": "\033[0m", "red": "\033[91m", "grn": "\033[92m",
     "yel": "\033[93m", "mag": "\033[95m", "cyn": "\033[96m", "org": "\033[38;5;214m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}

VERDICT_STYLE = {
    "investigate": ("red", "POLTERGEIST"), "lay_to_rest": ("mag", "ZOMBIE"), "optional": ("org", "UNINVITED"),
    "unknown": ("yel", "UNKNOWN"), "unexplained": ("dim", "UNEXAMINED"), "keep": ("grn", "FRIENDLY"),
    "dormant": ("dim", "SLEEPING"), "windows": ("dim", "WINDOWS"),
}


def _c(color: str, text: str) -> str:
    return f"{C[color]}{text}{C['r']}"


def _scan(days: int, model: str | None) -> dict:
    print(_c("dim", "Scanning startup items and the event log (read-only)..."), flush=True)
    raw = collect.scan(days=days)
    report = rpt.build(raw, model)
    rpt.save(report)
    return report


def _current(args) -> dict:
    report = None if getattr(args, "rescan", False) else rpt.load()
    return report or _scan(getattr(args, "days", 30), getattr(args, "model", None))


def print_wakes(w: dict) -> None:
    print(_c("b", f"\n🌙 Night wakers — last {w['window_days']} days of the System log"))
    print(f"  Left standby {_c('b', str(w['exits']))} times; {_c('org', str(w['not_you']))} of them weren't you "
          f"({w['night_exits']} between midnight and 6 AM, {w['night_not_you']} not you).")
    if w.get("standby_hours"):
        print(f"  {w['standby_hours']} h in standby, but awake for {_c('org', str(w.get('awake_hours')))} h of it "
              f"(deep sleep {w.get('deep_sleep_pct')}% of the time).")
    if w.get("hours_on_battery"):
        print(f"  On battery it lost {w['battery_drained_pct']}% while 'asleep' over {w['hours_on_battery']} h "
              f"({w['drain_pct_per_hour']}% per hour).")
    for reason, count in list(w["reasons"].items())[:8]:
        note = w["reason_notes"].get(reason) or ("Undocumented reason code." if reason.isdigit() else "")
        print(f"   {count:>4} × {reason:<42} {_c('dim', note[:80])}")
    for tip in w.get("tips") or []:
        print(_c("cyn", f"  ➜ {tip['title']}: ") + textwrap.shorten(tip["text"], 220))


def print_entries(report: dict, show_all: bool = False) -> None:
    entries = [e for e in report["entries"] if show_all or e.get("verdict") not in ("windows", "dormant")]
    order = ["investigate", "lay_to_rest", "unknown", "unexplained", "optional", "keep", "dormant", "windows"]
    entries.sort(key=lambda e: (order.index(e.get("verdict", "unknown")), (e.get("display_name") or "").lower()))
    s = report["summary"]
    print(_c("b", f"\n👻 Uninvited guests — {s['guests']} things start on their own "
                  f"(+{s['windows']} parts of Windows, {s['dormant']} already switched off)"))
    for e in entries:
        color, label = VERDICT_STYLE.get(e.get("verdict"), ("dim", e.get("verdict", "").upper()))
        ex = e.get("explanation") or {}
        what = ex.get("product") or e.get("publisher") or ""
        mem = f" · {e['running']['mb']:.0f} MB now" if e.get("running") else ""
        print(f"  {_c(color, f'{label:<11}')} {ai.anonymize(e.get('display_name') or '')[:44]:<44} "
              f"{_c('dim', (what + mem)[:48])}")
        if e.get("verdict") in ("investigate", "lay_to_rest"):
            print(_c("dim", f"              {e.get('verdict_reason')}"))


def cmd_scan(args) -> int:
    report = _scan(args.days, args.model)
    print_wakes(report["wakes"])
    print_entries(report, args.all)
    if args.json:
        Path(args.json).write_text(json.dumps(rpt.to_public(report), indent=1, default=str), encoding="utf-8")
        print(_c("dim", f"\nSaved {args.json}"))
    left = report["summary"]["unexplained"]
    if left:
        print(_c("dim", f"\n{left} items not examined yet. Run: python -m uninvited explain   (or open the UI: python -m uninvited serve)"))
    return 0


def cmd_explain(args) -> int:
    report = _current(args)
    client = ai.Ollama(args.model)
    if not client.pick_model():
        print(_c("red", "No Gemma model found in Ollama. Install Ollama and run: ollama pull gemma4:e4b"))
        return 2
    print(_c("dim", f"Asking {client.model} on this machine (nothing leaves it)..."))

    def progress(i, n, e):
        ex = e.get("explanation") or {}
        color, label = VERDICT_STYLE.get(e.get("verdict"), ("dim", "?"))
        print(f"  [{i}/{n}] {_c(color, f'{label:<11}')} {(e.get('display_name') or '')[:40]:<40} → {ex.get('product', e.get('explain_error', ''))}", flush=True)

    rpt.explain_all(report, client, progress, include_dormant=args.include_dormant)
    rpt.save(report)
    print_entries(report)
    return 0


def cmd_wakes(args) -> int:
    report = _current(args)
    print_wakes(report["wakes"])
    if args.story:
        story = ai.narrate_wakes(report["wakes"], ai.Ollama(args.model))
        print(_c("b", f"\n📜 {story['headline']}"))
        print(textwrap.fill(story["story"], 100, initial_indent="  ", subsequent_indent="  "))
        print(_c("dim", f"  (written by {story['source']}; numbers checked against the event log)"))
    return 0


def cmd_lookup(args) -> int:
    from . import lookup

    report = _current(args)
    entry = next((e for e in report["entries"] if e["id"] == args.id), None)
    if not entry:
        print(f"No entry {args.id}")
        return 2
    result = lookup.web_lookup(entry, ai.Ollama(args.model))
    print(json.dumps({k: v for k, v in result.items() if k != "raw"}, indent=1, default=str))
    return 0


def cmd_seance(args) -> int:
    report = _current(args)
    out = ai.seance(args.question, report["entries"], report["wakes"], ai.Ollama(args.model))
    print(textwrap.fill(out["answer"], 100))
    if out["cited_ids"]:
        print(_c("dim", "Sources: " + ", ".join(out["cited_ids"])))
    if out["unverified_numbers"] or out["invented_ids"]:
        print(_c("yel", f"Unverified: numbers {out['unverified_numbers']} ids {out['invented_ids']}"))
    return 0


def cmd_export(args) -> int:
    report = _current(args)
    data = rpt.anonymized_export(report)
    Path(args.out).write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
    print(f"Wrote {args.out}. Open it and check it before you share it: no paths, usernames or machine name are included.")
    return 0


def cmd_serve(args) -> int:
    from . import server

    server.serve(args.port, open_browser=not args.no_browser, model=args.model)
    return 0


def cmd_watch(args) -> int:
    from . import watch

    return watch.main(args)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="uninvited", description="What's haunting your laptop? Local, read-only, explained by Gemma.")
    p.add_argument("--version", action="version", version=f"uninvited {__version__}")
    p.add_argument("--model", default=None, help="Ollama model (default: gemma4:e4b-it-qat, falls back to other Gemma 4 tags)")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan startup items and wake history (no AI needed)")
    s.add_argument("--days", type=int, default=30)
    s.add_argument("--all", action="store_true", help="also list Windows' own items")
    s.add_argument("--json", help="also write the report to this file")
    s.set_defaults(func=cmd_scan)

    e = sub.add_parser("explain", help="ask the local Gemma model what each item is")
    e.add_argument("--rescan", action="store_true")
    e.add_argument("--include-dormant", action="store_true", help="also explain items that are switched off")
    e.set_defaults(func=cmd_explain)

    w = sub.add_parser("wakes", help="who woke the laptop")
    w.add_argument("--story", action="store_true", help="let Gemma write the night report (numbers are checked)")
    w.add_argument("--rescan", action="store_true")
    w.set_defaults(func=cmd_wakes)

    lk = sub.add_parser("lookup", help="opt-in: search the web (SerpApi) for an item Gemma doesn't know")
    lk.add_argument("id")
    lk.set_defaults(func=cmd_lookup)

    se = sub.add_parser("seance", help="ask your laptop a question")
    se.add_argument("question")
    se.set_defaults(func=cmd_seance)

    ex = sub.add_parser("export", help="write an anonymised summary you can share")
    ex.add_argument("--out", default="uninvited-summary.json")
    ex.set_defaults(func=cmd_export)

    sv = sub.add_parser("serve", help="open the local web UI")
    sv.add_argument("--port", type=int, default=8666)
    sv.add_argument("--no-browser", action="store_true")
    sv.set_defaults(func=cmd_serve)

    wt = sub.add_parser("watch", help="Night Watch: durable overnight watcher (needs Temporal)")
    wt.add_argument("--interval", type=int, default=15, help="minutes between checks")
    wt.add_argument("--explain-all", action="store_true", help="run a durable explain-everything workflow instead")
    wt.add_argument("--worker-only", action="store_true", help="only run the worker (workflow already started)")
    wt.add_argument("--status", action="store_true", help="show the running watch")
    wt.add_argument("--stop", action="store_true", help="stop the watch")
    wt.set_defaults(func=cmd_watch)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        args = p.parse_args(["scan"] + (argv or sys.argv[1:]))
    return args.func(args)
