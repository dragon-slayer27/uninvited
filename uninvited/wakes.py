"""Who woke the laptop? Modern Standby sessions and sleep wakes from the System event log."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone

# Reason codes observed in Kernel-Power 506/507 events. Message text is used when present
# (it is localised), the code table is the fallback.
KNOWN_REASONS = {
    1: "Power Button",
    5: "AC/DC Display Burst",
    11: "Screen Off Request",
    12: "Idle Timeout",
    15: "Lid",
    20: "Sleep, Hibernate, or Shutdown",
    28: "AC/DC Display Burst Suppressed",
    31: "Input Keyboard",
    33: "Input Touchpad",
    55: "Austerity Battery Drain Budget Exceeded",
}

CLASS_TEXT = {
    "you": "You: lid, keyboard, touchpad or power button",
    "charger": "The charger was plugged in or pulled out",
    "windows": "Windows itself",
    "unknown": "An undocumented reason code",
}

REASON_NOTES = {
    "austerity battery drain budget exceeded": "The laptop used more battery while 'asleep' than Windows allows, so Windows stepped in and clamped down on standby.",
    "sleep, hibernate, or shutdown": "Standby ended because Windows moved on to hibernate or shut down.",
    "ac/dc display burst": "The charger was plugged in or pulled out, which lit the screen for a moment.",
    "ac/dc display burst suppressed": "The charger was plugged in or pulled out; Windows noted it without lighting the screen.",
    "input keyboard": "A key was pressed.",
    "input touchpad": "The touchpad was touched.",
    "lid": "The lid was opened.",
    "power button": "The power button was pressed.",
}

NIGHT_START, NIGHT_END = 0, 6  # local hours [0, 6)


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)  # .NET writes 7 fractional digits
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _num(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def reason_of(event: dict) -> tuple[int | None, str]:
    data = event.get("data") or {}
    code = _num(data.get("Reason"))
    code = int(code) if code is not None else None
    text = (event.get("reasonText") or "").strip()
    if not text or text.isdigit():
        text = KNOWN_REASONS.get(code, str(code) if code is not None else "unknown")
    return code, text


def classify(text: str) -> str:
    t = (text or "").lower()
    if not t or t.isdigit() or t == "unknown":
        return "unknown"
    if t.startswith("input") or t in ("lid", "power button") or "user" in t:
        return "you"
    if "ac/dc" in t or "charger" in t or "power source" in t:
        return "charger"
    return "windows"


def sessions(standby_events: list[dict]) -> list[dict]:
    """Pair every 'entering standby' (506) with the following 'exiting standby' (507)."""
    events = sorted((e for e in standby_events or [] if e.get("time")), key=lambda e: e["time"])
    out: list[dict] = []
    pending: dict | None = None
    for ev in events:
        if ev.get("id") == 506:
            pending = ev
        elif ev.get("id") == 507:
            out.append(_session(pending, ev))
            pending = None
    for i, s in enumerate(out):
        nxt = out[i + 1] if i + 1 < len(out) else None
        s["awake_after_s"] = None
        if nxt and nxt.get("start") and s.get("end"):
            s["awake_after_s"] = max(0.0, (nxt["start"] - s["end"]).total_seconds())
    return out


def _session(enter: dict | None, leave: dict) -> dict:
    d = leave.get("data") or {}
    ed = (enter or {}).get("data") or {}
    end = parse_time(leave.get("time"))
    start = parse_time(enter.get("time")) if enter else None
    dur_us = _num(d.get("DurationInUs"))
    duration_s = dur_us / 1e6 if dur_us else ((end - start).total_seconds() if (start and end) else 0.0)
    drips_us = _num(d.get("DripsResidencyInUs"))
    active_us = _num(d.get("ActiveResidencyInUs"))
    full = _num(d.get("BatteryFullChargeCapacityOnExit")) or _num(ed.get("BatteryFullChargeCapacityOnEnter"))
    cap_in = _num(ed.get("BatteryRemainingCapacityOnEnter"))
    cap_out = _num(d.get("BatteryRemainingCapacityOnExit"))
    on_ac = str(d.get("PowerStateAc", "")).lower() == "true"
    drained_pct = None
    if not on_ac and cap_in and cap_out is not None and full and cap_in >= cap_out:
        drained_pct = (cap_in - cap_out) / full * 100
    code, text = reason_of(leave)
    _, enter_text = reason_of(enter) if enter else (None, "")
    local_end = end.astimezone() if end else None
    return {
        "start": start,
        "end": end,
        "local_end": local_end,
        "hour": local_end.hour if local_end else None,
        "night": bool(local_end and NIGHT_START <= local_end.hour < NIGHT_END),
        "duration_s": duration_s,
        "drips_pct": min(100.0, drips_us / dur_us * 100) if (drips_us is not None and dur_us) else None,
        "active_s": active_us / 1e6 if active_us is not None else None,
        "on_ac": on_ac,
        "drained_pct": drained_pct,
        "battery_health_pct": _num(d.get("FullChargeCapacityRatio")),
        "lid_closed": str(d.get("LidOpenState", "")).lower() == "false",
        "code": code,
        "reason": text,
        "enter_reason": enter_text,
        "class": classify(text),
    }


def analyze(scan: dict, now: datetime | None = None) -> dict:
    sess = sessions(scan.get("standby") or [])
    now = now or parse_time(scan.get("collected_at")) or datetime.now(timezone.utc)
    start = parse_time(scan.get("log_start"))
    if sess and sess[0].get("end") and (start is None or sess[0]["end"] < start):
        start = sess[0]["start"] or sess[0]["end"]
    days = max(((now - start).total_seconds() / 86400) if start else 0.0, 0.0)

    by_class = Counter(s["class"] for s in sess)
    night = [s for s in sess if s["night"]]
    night_by_class = Counter(s["class"] for s in night)
    hist = {c: [0] * 24 for c in CLASS_TEXT}
    for s in sess:
        if s["hour"] is not None:
            hist[s["class"]][s["hour"]] += 1
    reasons = Counter(s["reason"] for s in sess)

    battery = [s for s in sess if s["drained_pct"] is not None and s["duration_s"] >= 15 * 60]
    hours_on_battery = sum(s["duration_s"] for s in battery) / 3600
    drained_total = sum(s["drained_pct"] for s in battery)
    long_battery = [s for s in battery if s["duration_s"] >= 3600]
    worst = max(long_battery, key=lambda s: s["drained_pct"] / (s["duration_s"] / 3600), default=None)
    total_s = sum(s["duration_s"] for s in sess)
    drips_weighted = [s for s in sess if s["drips_pct"] is not None and s["duration_s"] > 0]
    drips_avg = (sum(s["drips_pct"] * s["duration_s"] for s in drips_weighted)
                 / sum(s["duration_s"] for s in drips_weighted)) if drips_weighted else None
    active_min = sum((s["active_s"] or 0) for s in sess) / 60

    austerity = [s for s in sess if "austerity" in s["reason"].lower()]
    austerity_nights = sorted({s["local_end"].date().isoformat() for s in austerity if s["local_end"] and s["night"]})
    unknown_codes = Counter(str(s["code"]) for s in sess if s["class"] == "unknown")
    lid_closed_input = [s for s in sess if s["reason"].lower().startswith("input") and s["lid_closed"]]
    brief_night = [s for s in night if s["class"] in ("you", "unknown") and s["awake_after_s"] is not None and s["awake_after_s"] < 60]

    sleep_wakes = scan.get("sleep_wakes") or []
    wake_sources = Counter((w.get("source") or "Unknown") for w in sleep_wakes)
    health = next((s["battery_health_pct"] for s in reversed(sess) if s.get("battery_health_pct")), None)

    timers = scan.get("wake_timers") or {}
    tips = _tips(len(austerity), len(lid_closed_input), timers, unknown_codes, scan.get("wake_armed") or [])

    def _round(x, n=1):
        return round(x, n) if x is not None else None

    return {
        "window_days": _round(days, 1),
        "window_start": start.isoformat() if start else None,
        "exits": len(sess),
        "by_class": dict(by_class),
        "not_you": len(sess) - by_class.get("you", 0),
        "night_exits": len(night),
        "night_by_class": dict(night_by_class),
        "night_not_you": len(night) - night_by_class.get("you", 0),
        "hist": hist,
        "reasons": dict(reasons.most_common()),
        "reason_notes": {r: REASON_NOTES.get(r.lower(), "") for r in reasons},
        "standby_hours": _round(total_s / 3600, 1),
        "hours_on_battery": _round(hours_on_battery, 1),
        "battery_drained_pct": _round(drained_total, 1),
        "drain_pct_per_hour": _round(drained_total / hours_on_battery, 2) if hours_on_battery > 0 else None,
        "worst_session": _brief(worst),
        "deep_sleep_pct": _round(drips_avg, 1),
        "awake_minutes": _round(active_min, 1),
        "awake_hours": _round(active_min / 60, 1),
        "awake_share_pct": _round(active_min / 60 / (total_s / 3600) * 100, 1) if total_s else None,
        "austerity_count": len(austerity),
        "austerity_nights": austerity_nights,
        "unknown_codes": dict(unknown_codes),
        "lid_closed_input": len(lid_closed_input),
        "brief_night_wakes": len(brief_night),
        "sleep_wakes": len(sleep_wakes),
        "sleep_wake_sources": dict(wake_sources),
        "battery_health_pct": _round(health, 0),
        "wake_armed": scan.get("wake_armed") or [],
        "wake_timers": timers,
        "tips": tips,
        "night_events": [_brief(s) for s in night][-60:],
        "class_text": CLASS_TEXT,
    }


def _brief(s: dict | None) -> dict | None:
    if not s:
        return None
    return {
        "time": s["local_end"].strftime("%Y-%m-%d %H:%M") if s.get("local_end") else None,
        "reason": s["reason"],
        "class": s["class"],
        "minutes_asleep": round(s["duration_s"] / 60, 1),
        "drained_pct": round(s["drained_pct"], 2) if s.get("drained_pct") is not None else None,
        "drain_pct_per_hour": (round(s["drained_pct"] / (s["duration_s"] / 3600), 2)
                               if s.get("drained_pct") is not None and s["duration_s"] > 0 else None),
        "deep_sleep_pct": round(s["drips_pct"], 1) if s.get("drips_pct") is not None else None,
        "lid_closed": s.get("lid_closed"),
        "on_ac": s.get("on_ac"),
    }


def _tips(austerity: int, lid_closed_input: int, timers: dict, unknown: Counter, armed: list[str]) -> list[dict]:
    tips = []
    if austerity:
        tips.append({
            "id": "austerity",
            "title": "Find what keeps it busy while asleep",
            "text": (f"Windows had to clamp down on standby {austerity} times because it was draining battery. "
                     "Run 'powercfg /sleepstudy' in an admin terminal: its report lists the apps and devices active in each sleep session. "
                     "If you carry the laptop in a bag, set it to hibernate after a while on battery "
                     "(Settings > System > Power & battery)."),
        })
    if lid_closed_input:
        keyboards = [a for a in armed if "keyboard" in a.lower()]
        who = keyboards[0] if keyboards else "your keyboard"
        tips.append({
            "id": "lid-closed-input",
            "title": "Keys pressed while the lid was shut",
            "text": (f"{lid_closed_input} wakes came from keyboard or touchpad input while the lid was closed: an external keyboard, "
                     "or something pressing keys in a bag. Device Manager > Keyboards > "
                     f"{who} > Power Management > untick 'Allow this device to wake the computer'."),
        })
    if timers and timers.get("dc") == 1:
        tips.append({
            "id": "wake-timers",
            "title": "Wake timers are allowed on battery",
            "text": "Scheduled tasks may wake the laptop while it runs on battery. Control Panel > Power Options > Change plan settings > Advanced > Sleep > Allow wake timers > On battery: Disable.",
        })
    if unknown:
        codes = ", ".join(sorted(unknown))
        tips.append({
            "id": "unknown-codes",
            "title": "Reasons nobody has documented",
            "text": f"Windows recorded {sum(unknown.values())} standby exits with reason code {codes}, which has no public description. Uninvited reports it and does not guess.",
        })
    return tips
