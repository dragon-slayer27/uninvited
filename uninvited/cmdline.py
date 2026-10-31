"""Turn Windows command lines into the file that actually runs."""

from __future__ import annotations

import ntpath
import os
import re
import shutil

EXEC_EXT = (
    ".exe", ".com", ".bat", ".cmd", ".lnk", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".dll", ".msi", ".scr", ".cpl", ".py", ".pyw", ".jar",
)

# Programs that run *another* file. For these, the interesting target is the argument.
HOSTS = {
    "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe",
    "pwsh.exe", "cmd.exe", "conhost.exe", "msiexec.exe", "javaw.exe", "java.exe", "python.exe",
    "pythonw.exe",
}

_PAYLOAD_EXT = r"(?:dll|ocx|cpl|js|jse|vbs|vbe|wsf|hta|ps1|bat|cmd|exe|py|pyw|jar|msi|sct)"
_PAYLOAD = re.compile(
    rf'"([^"]+\.{_PAYLOAD_EXT})"|((?:[a-zA-Z]:|%[A-Za-z_()]+%|\\\\)[^\s",]*\.{_PAYLOAD_EXT})\b',
    re.IGNORECASE,
)
_CLEANUP = re.compile(r"(?:^|[\s&|])(?:del|erase|rd|rmdir)\s", re.IGNORECASE)


def windir() -> str:
    return os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"


def expand(path: str) -> str:
    """Expand %VARS% and the NT-style prefixes used by services."""
    p = (path or "").strip().strip('"').strip()
    low = p.lower()
    if low.startswith("\\systemroot\\"):
        p = windir() + p[len("\\SystemRoot"):]
    elif low.startswith("system32\\"):
        p = ntpath.join(windir(), p)
    elif p.startswith("\\??\\"):
        p = p[4:]
    return ntpath.expandvars(p)


def split_command(command: str) -> tuple[str, str]:
    """Split a command line into (executable, arguments) roughly like CreateProcess does."""
    s = (command or "").strip()
    if not s:
        return "", ""
    if s.startswith('"'):
        end = s.find('"', 1)
        if end == -1:
            return expand(s[1:]), ""
        return expand(s[1:end]), s[end + 1:].strip()
    parts = s.split(" ")
    for i in range(1, len(parts) + 1):
        candidate = " ".join(parts[:i])
        if candidate.lower().endswith(EXEC_EXT):
            return expand(candidate), " ".join(parts[i:]).strip()
    return expand(parts[0]), " ".join(parts[1:]).strip()


def resolve(exe: str) -> str:
    """Make a bare program name absolute (cmd.exe -> C:\\Windows\\System32\\cmd.exe)."""
    if not exe:
        return ""
    if ntpath.isabs(exe) or exe.startswith("\\\\"):
        return exe
    name = exe if ntpath.splitext(exe)[1] else exe + ".exe"
    for folder in (ntpath.join(windir(), "System32"), windir()):
        candidate = ntpath.join(folder, name)
        if os.path.exists(candidate):
            return candidate
    found = shutil.which(name)
    return found or ntpath.join(windir(), "System32", name)


def payload(exe: str, args: str) -> str | None:
    """For host programs (rundll32, wscript, powershell -File ...) return the file they run."""
    name = ntpath.basename(exe).lower()
    if name not in HOSTS:
        return None
    if name == "cmd.exe" and _CLEANUP.search(" " + args):
        return None  # "cmd /c del <file>" deletes a file, it doesn't run it
    m = _PAYLOAD.search(args or "")
    if not m:
        return None
    return expand(m.group(1) or m.group(2))


def target_of(command: str) -> tuple[str, str, str]:
    """Return (executable, arguments, effective target file)."""
    exe, args = split_command(command)
    exe = resolve(exe)
    inner = payload(exe, args)
    return exe, args, inner or exe


def norm(path: str) -> str:
    return ntpath.normcase(ntpath.normpath(path)) if path else ""
