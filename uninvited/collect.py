"""Collect everything that starts on its own, plus the wake history, into plain dicts."""

from __future__ import annotations

import hashlib
import ntpath
import os
import re
from pathlib import Path

from . import cmdline
from .config import home
from .ps import run_script

try:
    import winreg  # type: ignore
except ImportError:  # non-Windows (tests use fixtures)
    winreg = None  # type: ignore

RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "run", "user", "Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "runonce", "user", None),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "run", "machine", "Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "runonce", "machine", None),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "run", "machine", "Run32"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "runonce", "machine", None),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "run", "user", None),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "run", "machine", None),
]
APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"


def entry_id(kind: str, location: str, name: str) -> str:
    digest = hashlib.sha1(f"{kind}|{location}|{name}".lower().encode("utf-8")).hexdigest()
    return "E" + digest[:8]


# ---------------------------------------------------------------- registry
def _hive(name: str):
    return winreg.HKEY_CURRENT_USER if name == "HKCU" else winreg.HKEY_LOCAL_MACHINE


def _values(hive: str, path: str) -> list[tuple[str, object, int]]:
    if winreg is None:
        return []
    try:
        key = winreg.OpenKey(_hive(hive), path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except OSError:
        return []
    out = []
    with key:
        i = 0
        while True:
            try:
                out.append(winreg.EnumValue(key, i))
            except OSError:
                break
            i += 1
    return out


def _approved(hive: str, sub: str) -> dict[str, bool]:
    """Task Manager's enable/disable switch. Odd first byte = disabled."""
    states = {}
    for name, data, _ in _values(hive, APPROVED + "\\" + sub):
        if isinstance(data, (bytes, bytearray)) and data:
            states[name.lower()] = not (data[0] & 1)
    return states


def _reg_string(hive: str, path: str, value: str = "") -> str | None:
    if winreg is None:
        return None
    try:
        key = winreg.OpenKey(_hive(hive), path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except OSError:
        return None
    with key:
        try:
            data, _ = winreg.QueryValueEx(key, value)
        except OSError:
            return None
    return data if isinstance(data, str) else None


def _com_dll(class_id: str) -> str | None:
    if not class_id or winreg is None:
        return None
    for hive, path in (("HKLM", rf"Software\Classes\CLSID\{class_id}\InprocServer32"),
                       ("HKCU", rf"Software\Classes\CLSID\{class_id}\InprocServer32")):
        dll = _reg_string(hive, path)
        if dll:
            return cmdline.expand(dll)
    return None


def registry_entries() -> list[dict]:
    entries = []
    approvals = {
        ("HKCU", "Run"): _approved("HKCU", "Run"),
        ("HKLM", "Run"): _approved("HKLM", "Run"),
        ("HKLM", "Run32"): _approved("HKLM", "Run32"),
    }
    for hive, path, kind, scope, approved_sub in RUN_KEYS:
        for name, data, _type in _values(hive, path):
            if not isinstance(data, str) or not data.strip():
                continue
            location = f"{hive}\\{path}"
            exe, args, target = cmdline.target_of(data)
            enabled = True
            if approved_sub:
                enabled = approvals.get((hive, approved_sub), {}).get(name.lower(), True)
            entries.append({
                "id": entry_id(kind, location, name),
                "kind": kind,
                "scope": scope,
                "location": location,
                "name": name,
                "display_name": name,
                "description": "",
                "command": data,
                "exe": exe,
                "args": args,
                "target": target,
                "enabled": enabled,
                "state": "Enabled" if enabled else "Disabled",
                "trigger": "every time you sign in" if kind == "run" else "once, at your next sign-in",
                "wake_to_run": False,
            })
    return entries


# ---------------------------------------------------------------- triggers
_DURATION = re.compile(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?")


def human_duration(iso: str | None) -> str:
    if not iso:
        return ""
    m = _DURATION.fullmatch(iso)
    if not m:
        return iso
    d, h, mi, s = (int(x) if x else 0 for x in m.groups())
    parts = []
    for value, unit in ((d, "day"), (h, "hour"), (mi, "minute"), (s, "second")):
        if value:
            parts.append(f"{value} {unit}{'s' if value != 1 else ''}")
    return " ".join(parts)


def _clock(start: str | None) -> str:
    if not start:
        return ""
    m = re.search(r"T(\d{2}):(\d{2})", start)
    return f"{m.group(1)}:{m.group(2)}" if m else ""


def describe_triggers(triggers: list[dict]) -> str:
    phrases = []
    for t in triggers or []:
        if not t.get("enabled", True):
            continue
        kind = (t.get("type") or "").lower()
        at = _clock(t.get("start"))
        if kind == "logon":
            p = "when you sign in"
        elif kind == "boot":
            p = "when Windows starts"
        elif kind == "daily":
            p = f"every day at {at}" if at else "every day"
        elif kind == "weekly":
            p = f"every week at {at}" if at else "every week"
        elif kind == "monthly" or kind == "monthlydow":
            p = "every month"
        elif kind == "time":
            p = f"at {at}" if at else "at a set time"
        elif kind == "idle":
            p = "when the PC is idle"
        elif kind == "event":
            p = "when Windows logs a specific event"
        elif kind == "sessionstatechange":
            p = "when you lock, unlock or switch user"
        elif kind == "registration":
            p = "when the task is installed or updated"
        else:
            p = "on a custom trigger"
        every = human_duration(t.get("interval"))
        if every:
            p += f", repeating every {every}"
        phrases.append(p)
    return "; ".join(dict.fromkeys(phrases)) or "only when another program asks"


# ---------------------------------------------------------------- assemble
def _task_entries(tasks: list[dict]) -> list[dict]:
    entries = []
    for t in tasks or []:
        actions = t.get("actions") or []
        exec_action = next((a for a in actions if a.get("type") == "exec"), None)
        com_action = next((a for a in actions if a.get("type") == "com"), None)
        if exec_action:
            # Some vendors store Execute with doubled quotes (""C:\...exe""); normalise first.
            execute = (exec_action.get("execute") or "").strip().strip('"').strip()
            arguments = exec_action.get("arguments") or ""
            command = f'"{execute}"' if " " in execute else execute
            command = f"{command} {arguments}".strip()
            exe, args, target = cmdline.target_of(command)
        elif com_action:
            dll = _com_dll(com_action.get("classId") or "")
            command = f"COM handler {com_action.get('classId')}"
            exe, args, target = (dll or ""), "", (dll or "")
        else:
            continue
        location = t.get("path") or "\\"
        state = t.get("state") or ""
        entries.append({
            "id": entry_id("task", location, t.get("name") or ""),
            "kind": "task",
            "scope": "machine" if (t.get("runAs") or "").upper() in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") else "user",
            "location": location,
            "name": t.get("name") or "",
            "display_name": t.get("name") or "",
            "description": t.get("description") or "",
            "author": t.get("author") or "",
            "command": command,
            "exe": exe,
            "args": args,
            "target": target,
            "enabled": state.lower() != "disabled",
            "state": state,
            "trigger": describe_triggers(t.get("triggers") or []),
            "wake_to_run": bool(t.get("wakeToRun")),
            "run_as": t.get("runAs") or "",
            "task_info": t.get("info"),
        })
    return entries


def _service_entries(services: list[dict]) -> list[dict]:
    entries = []
    for s in services or []:
        command = s.get("pathName") or ""
        exe, args, target = cmdline.target_of(command)
        if ntpath.basename(exe).lower() == "svchost.exe":
            dll = _reg_string("HKLM", rf"SYSTEM\CurrentControlSet\Services\{s.get('name')}\Parameters", "ServiceDll")
            if dll:
                target = cmdline.expand(dll)
        entries.append({
            "id": entry_id("service", "services", s.get("name") or ""),
            "kind": "service",
            "scope": "machine",
            "location": "Services",
            "name": s.get("name") or "",
            "display_name": s.get("displayName") or s.get("name") or "",
            "description": s.get("description") or "",
            "command": command,
            "exe": exe,
            "args": args,
            "target": target,
            "enabled": True,
            "state": s.get("state") or "",
            "trigger": "when Windows starts" + (" (delayed)" if s.get("delayed") else ""),
            "wake_to_run": False,
            "run_as": s.get("startName") or "",
            "pid": s.get("processId") or 0,
        })
    return entries


def _startup_entries(items: list[dict]) -> list[dict]:
    entries = []
    approvals = {"user": _approved("HKCU", "StartupFolder"), "machine": _approved("HKLM", "StartupFolder")}
    for it in items or []:
        file = it.get("file") or ""
        target_raw = it.get("target") or file
        command = (f'"{target_raw}" {it.get("arguments") or ""}').strip()
        exe, args, target = cmdline.target_of(command)
        fname = ntpath.basename(file)
        enabled = approvals.get(it.get("scope") or "user", {}).get(fname.lower(), True)
        entries.append({
            "id": entry_id("startup", it.get("folder") or "", fname),
            "kind": "startup",
            "scope": it.get("scope") or "user",
            "location": it.get("folder") or "",
            "name": it.get("name") or fname,
            "display_name": it.get("name") or fname,
            "description": "",
            "command": command,
            "exe": exe,
            "args": args,
            "target": target,
            "shortcut": file,
            "enabled": enabled,
            "state": "Enabled" if enabled else "Disabled",
            "trigger": "every time you sign in",
            "wake_to_run": False,
        })
    return entries


_SQUIRREL = re.compile(r'--processStart\s+"?([^"\s]+\.exe)', re.IGNORECASE)
# Generic hosts: a running cmd.exe or svchost.exe says nothing about *this* entry.
_GENERIC = cmdline.HOSTS | {"svchost.exe", "dllhost.exe", "taskhostw.exe", "explorer.exe"}


def _attach_running(entries: list[dict], processes: list[dict]) -> None:
    by_pid = {p.get("id"): p for p in processes or []}
    by_path: dict[str, list[dict]] = {}
    for p in processes or []:
        if p.get("path"):
            by_path.setdefault(cmdline.norm(p["path"]), []).append(p)
    for e in entries:
        hits: list[dict] = []
        if not e.get("enabled"):
            e["running"] = None
            continue
        if e.get("pid"):
            shared = ntpath.basename(e.get("exe") or "").lower() == "svchost.exe"
            if e["pid"] in by_pid and not shared:
                hits.append(by_pid[e["pid"]])
        elif ntpath.basename(e.get("target") or "").lower() not in _GENERIC:
            hits = list(by_path.get(cmdline.norm(e.get("target") or ""), []))
            exe_generic = ntpath.basename(e.get("exe") or "").lower() in _GENERIC
            if not hits and e.get("exe") and e.get("exe") != e.get("target") and not exe_generic:
                hits = list(by_path.get(cmdline.norm(e["exe"]), []))
            m = _SQUIRREL.search(e.get("args") or "")
            if m and e.get("exe"):
                folder = cmdline.norm(ntpath.dirname(e["exe"]))
                wanted = m.group(1).lower()
                hits += [p for path, ps in by_path.items() for p in ps
                         if path.startswith(folder) and ntpath.basename(path) == wanted]
        if hits:
            mb = sum((p.get("ws") or 0) for p in hits) / (1024 * 1024)
            e["running"] = {"pids": sorted({p.get("id") for p in hits}), "mb": round(mb, 1)}
        else:
            e["running"] = None


def _attach_file_info(entries: list[dict], workdir: Path) -> None:
    import json

    paths: dict[str, str] = {}
    for e in entries:
        t = e.get("target") or ""
        if t:
            paths.setdefault(cmdline.norm(t), t)
    infos: dict = {}
    if paths:
        listing = workdir / "paths.json"
        listing.write_text(json.dumps(list(paths.values())), encoding="utf-8")
        raw = run_script("fileinfo.ps1", workdir, InPath=str(listing)) or {}
        listing.unlink(missing_ok=True)
        infos = {cmdline.norm(k): v for k, v in raw.items()}
    for e in entries:
        e["file"] = infos.get(cmdline.norm(e.get("target") or ""), {"exists": False})


def scan(days: int = 30) -> dict:
    """Collect a full raw inventory of this machine (read-only)."""
    workdir = home() / "tmp"
    workdir.mkdir(parents=True, exist_ok=True)
    raw = run_script("collect.ps1", workdir, Days=days) or {}
    entries = registry_entries()
    entries += _startup_entries(raw.get("startupFolder") or [])
    entries += _task_entries(raw.get("tasks") or [])
    entries += _service_entries(raw.get("services") or [])
    _attach_running(entries, raw.get("processes") or [])
    _attach_file_info(entries, workdir)
    return {
        "collected_at": raw.get("collectedAt"),
        "machine": raw.get("machine") or {},
        "entries": entries,
        "standby": raw.get("standby") or [],
        "sleep_wakes": raw.get("sleepWakes") or [],
        "log_start": raw.get("logStart"),
        "wake_armed": raw.get("wakeArmed") or [],
        "wake_timers": raw.get("wakeTimers"),
        "errors": raw.get("errors") or [],
        "user": os.environ.get("USERNAME", ""),
        "days": days,
    }
