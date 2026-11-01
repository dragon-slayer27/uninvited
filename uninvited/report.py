"""Turn a raw scan into the report the CLI and the web UI show."""

from __future__ import annotations

import json
import ntpath
import threading
import time
from collections import Counter
from typing import Callable

from . import ai, lookup, rules, wakes
from .config import home

REPORT_FILE = "report.json"
_lock = threading.Lock()


def _display(entry: dict) -> dict:
    """What the UI needs, with the user's name scrubbed from paths."""
    f = entry.get("file") or {}
    return {
        "id": entry["id"],
        "kind": entry.get("kind"),
        "scope": entry.get("scope"),
        "name": ai.anonymize(entry.get("display_name") or entry.get("name") or ""),
        "location": ai.anonymize(entry.get("location") or ""),
        "description": entry.get("description") or "",
        "command": ai.anonymize(entry.get("command") or ""),
        "target": ai.anonymize(entry.get("target") or ""),
        "file_name": ntpath.basename(entry.get("target") or ""),
        "file_description": f.get("description") or "",
        "file_exists": bool(f.get("exists")),
        "signature": f.get("sigStatus"),
        "publisher": entry.get("publisher") or "",
        "hardware": entry.get("hardware"),
        "enabled": entry.get("enabled"),
        "state": entry.get("state"),
        "trigger": entry.get("trigger"),
        "wake_to_run": entry.get("wake_to_run"),
        "running": entry.get("running"),
        "flags": entry.get("flags") or [],
        "decoded": entry.get("decoded"),
        "is_windows": entry.get("is_windows"),
        "zombie": entry.get("zombie"),
        "verdict": entry.get("verdict"),
        "verdict_reason": entry.get("verdict_reason"),
        "explanation": entry.get("explanation"),
        "lookup": entry.get("lookup"),
        "lookup_query": lookup.build_query(entry),
        "planted": bool(entry.get("planted")),
        "commands": rules.commands(entry),
    }


def build(scan: dict, model: str | None = None) -> dict:
    """Analyse a raw scan. Uses cached explanations only; never calls the model."""
    client = ai.Ollama(model)
    client_model = client.pick_model() or client.model
    entries = scan.get("entries") or []
    signatures_ok = scan.get("signatures_ok", True)
    for e in entries:
        rules.analyze(e, signatures_ok)
        cached = ai.explain_cache().get(ai.cache_key(e, client_model))
        e["explanation"] = cached
        e["verdict"], e["verdict_reason"] = rules.decide(e, cached)
    report = {
        "collected_at": scan.get("collected_at"),
        "machine": scan.get("machine") or {},
        "model": client_model,
        "signatures_ok": signatures_ok,
        "wakes": wakes.analyze(scan),
        "entries": entries,
        "errors": scan.get("errors") or [],
    }
    report["summary"] = summarize(report)
    return report


def summarize(report: dict) -> dict:
    entries = report.get("entries") or []
    verdicts = Counter(e.get("verdict") for e in entries)
    guests = [e for e in entries if e.get("verdict") not in ("windows",)]
    active = [e for e in guests if e.get("verdict") != "dormant"]
    running_mb = sum((e.get("running") or {}).get("mb", 0) for e in active
                     if e.get("verdict") in ("optional", "unknown", "unexplained", "investigate"))
    return {
        "total": len(entries),
        "windows": verdicts.get("windows", 0),
        "guests": len(active),
        "dormant": verdicts.get("dormant", 0),
        "verdicts": dict(verdicts),
        "zombies": verdicts.get("lay_to_rest", 0),
        "poltergeists": verdicts.get("investigate", 0),
        "optional": verdicts.get("optional", 0),
        "unexplained": verdicts.get("unexplained", 0),
        "optional_running_mb": round(running_mb, 1),
    }


def to_public(report: dict) -> dict:
    out = {k: v for k, v in report.items() if k != "entries"}
    out["entries"] = [_display(e) for e in report.get("entries") or []]
    return out


def save(report: dict) -> None:
    path = home() / REPORT_FILE
    with _lock:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
        tmp.replace(path)


def load() -> dict | None:
    try:
        return json.loads((home() / REPORT_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def needs_explaining(entry: dict) -> bool:
    if entry.get("is_windows") or entry.get("verdict") == "windows":
        return False
    if entry.get("unresolved") and not entry.get("description"):
        return False
    return entry.get("explanation") is None and entry.get("enabled", True)


def explain_entry(report: dict, entry: dict, client: ai.Ollama) -> dict:
    ex = ai.explain(entry, client)
    entry["explanation"] = ex
    entry["verdict"], entry["verdict_reason"] = rules.decide(entry, ex)
    report["summary"] = summarize(report)
    return entry


def explain_all(report: dict, client: ai.Ollama | None = None,
                progress: Callable[[int, int, dict], None] | None = None,
                include_dormant: bool = False) -> dict:
    client = client or ai.Ollama()
    todo = [e for e in report["entries"]
            if needs_explaining(e) or (include_dormant and not e.get("is_windows") and e.get("explanation") is None)]
    # Entries running the same program share a cache entry, so order by identity to reuse answers.
    todo.sort(key=ai.identity)
    started = time.time()
    for i, e in enumerate(todo, 1):
        try:
            explain_entry(report, e, client)
        except ai.ModelError as exc:
            e["explain_error"] = str(exc)
        if progress:
            progress(i, len(todo), e)
    report["explained_seconds"] = round(time.time() - started, 1)
    report["summary"] = summarize(report)
    return report


def anonymized_export(report: dict) -> dict:
    """What a friend can safely share: no paths, no usernames, no machine name."""
    entries = []
    for e in report.get("entries") or []:
        if e.get("verdict") == "windows":
            continue
        ex = e.get("explanation") or {}
        entries.append({
            "kind": e.get("kind"),
            "name": ai.anonymize(e.get("display_name") or e.get("name") or ""),
            "publisher": e.get("publisher"),
            "product": ex.get("product"),
            "category": ex.get("category"),
            "verdict": e.get("verdict"),
            "enabled": e.get("enabled"),
            "running_mb": (e.get("running") or {}).get("mb"),
            "zombie": e.get("zombie"),
            "flags": [f["id"] for f in e.get("flags") or []],
        })
    w = dict(report.get("wakes") or {})
    w.pop("night_events", None)
    return {
        "tool": "uninvited",
        "machine": {"manufacturer": (report.get("machine") or {}).get("manufacturer"),
                    "model": (report.get("machine") or {}).get("model"),
                    "os": (report.get("machine") or {}).get("os")},
        "summary": report.get("summary"),
        "wakes": w,
        "entries": entries,
    }
