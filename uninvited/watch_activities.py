"""Temporal activities for Night Watch. Plain synchronous functions, run in a thread pool by the worker."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from temporalio import activity

from . import ai, collect, report as rpt, rules, wakes
from .config import home


@dataclass
class WatchState:
    interval_minutes: int = 15
    started: str = ""
    workflow_id: str = ""
    known_ids: list[str] = field(default_factory=list)
    last_event_time: str = ""
    checks: int = 0
    exits: int = 0
    not_you: int = 0
    events: list[dict] = field(default_factory=list)
    new_entries: list[dict] = field(default_factory=list)


@dataclass
class Snapshot:
    entry_ids: list[str]
    events: list[dict]
    latest_event_time: str
    taken_at: str


@dataclass
class ExplainRequest:
    entry_id: str
    source: str = "snapshot"  # "snapshot" for Night Watch, "report" for explain-all


def night_dir():
    d = home() / "night"
    d.mkdir(parents=True, exist_ok=True)
    return d


@activity.defn
def take_snapshot(since: str) -> Snapshot:
    """Read-only scan: startup entries plus standby exits newer than `since`."""
    raw = collect.scan(days=2)
    report = rpt.build(raw)
    (night_dir() / "snapshot.json").write_text(json.dumps(report, default=str), encoding="utf-8")
    ids = sorted(e["id"] for e in report["entries"] if not e.get("is_windows"))
    since_dt = wakes.parse_time(since) if since else None
    events, latest = [], None
    for s in wakes.sessions(raw.get("standby") or []):
        end = s.get("end")
        if not end:
            continue
        latest = end if latest is None or end > latest else latest
        if since_dt is None or end > since_dt:
            events.append({"time": s["local_end"].strftime("%Y-%m-%d %H:%M"), "reason": s["reason"], "class": s["class"]})
    return Snapshot(entry_ids=ids, events=events,
                    latest_event_time=latest.isoformat() if latest else (since or ""),
                    taken_at=datetime.now(timezone.utc).isoformat())


@activity.defn
def explain_entry(req: ExplainRequest) -> dict:
    """Ask the local model about one entry. Failures (Ollama down, timeouts) raise, so Temporal retries."""
    if req.source == "report":
        report = rpt.load() or {}
    else:
        report = json.loads((night_dir() / "snapshot.json").read_text(encoding="utf-8"))
    entry = next((e for e in report.get("entries") or [] if e["id"] == req.entry_id), None)
    if entry is None:
        return {"id": req.entry_id, "missing": True}
    client = ai.Ollama()
    if not client.pick_model():
        raise RuntimeError(f"Ollama is not answering at {client.host} (attempt {activity.info().attempt}); will retry")
    explanation = ai.explain(entry, client)
    verdict, reason = rules.decide(entry, explanation)
    if req.source == "report":
        entry["explanation"], entry["verdict"], entry["verdict_reason"] = explanation, verdict, reason
        report["summary"] = rpt.summarize(report)
        rpt.save(report)
    return {
        "id": entry["id"],
        "name": ai.anonymize(entry.get("display_name") or entry.get("name") or ""),
        "publisher": entry.get("publisher"),
        "product": explanation.get("product"),
        "category": explanation.get("category"),
        "verdict": verdict,
        "attempt": activity.info().attempt,
    }


@activity.defn
def list_pending() -> list[str]:
    report = rpt.load()
    if report is None:
        report = rpt.build(collect.scan())
        rpt.save(report)
    return [e["id"] for e in report["entries"] if rpt.needs_explaining(e)]


@activity.defn
def write_night_report(state: WatchState) -> str:
    now = datetime.now().astimezone()
    started = wakes.parse_time(state.started)
    since = started.astimezone().strftime("%a %H:%M") if started else "the start"
    if state.checks <= 1:
        headline = "Night Watch is on duty"
    else:
        headline = f"{state.exits} standby exits since {since}; {state.not_you} were not you"
        if state.new_entries:
            headline += f"; {len(state.new_entries)} new uninvited guest{'s' if len(state.new_entries) != 1 else ''}"
    data = {
        "headline": headline,
        "started": started.astimezone().strftime("%Y-%m-%d %H:%M") if started else None,
        "last_check": now.strftime("%Y-%m-%d %H:%M"),
        "checks": state.checks,
        "interval_minutes": state.interval_minutes,
        "exits": state.exits,
        "not_you": state.not_you,
        "events": state.events[-50:],
        "new_entries": state.new_entries,
        "workflow_id": state.workflow_id,
    }
    path = night_dir() / "latest.json"
    path.write_text(json.dumps(data, indent=1), encoding="utf-8")
    log = night_dir() / f"night-{now:%Y-%m-%d}.md"
    with log.open("a", encoding="utf-8") as fh:
        fh.write(f"- {now:%H:%M} check {state.checks}: {headline}\n")
        for ev in state.events[-5:] if state.checks > 1 else []:
            fh.write(f"    - {ev['time']} {ev['reason']} ({ev['class']})\n")
    return str(path)
