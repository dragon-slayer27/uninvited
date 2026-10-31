"""Deterministic judgement. The model explains; this module decides."""

from __future__ import annotations

import base64
import ntpath
import re

from . import cmdline

# ------------------------------------------------------------------ signer
_DN = re.compile(r'(?:^|,)\s*([A-Za-z]+)=("(?:[^"]|"")*"|[^,]*)')


def parse_dn(subject: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in _DN.findall(subject or ""):
        value = value.strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1].replace('""', '"')
        out.setdefault(key.upper(), value)
    return out


def publisher(file_info: dict) -> str:
    dn = parse_dn(file_info.get("signer"))
    return dn.get("O") or dn.get("CN") or ""


OS_SIGNERS = {"microsoft windows", "microsoft windows publisher"}
WHQL_SIGNER = "microsoft windows hardware compatibility publisher"
WINDOWS_TASK_ROOTS = ("\\microsoft\\windows\\", "\\softlanding\\")

# ------------------------------------------------------------------ paths
SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "winlogon.exe", "services.exe",
    "rundll32.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "smss.exe", "wininit.exe",
    "spoolsv.exe", "taskmgr.exe", "searchindexer.exe", "runtimebroker.exe",
}


def path_class(path: str) -> str:
    low = cmdline.norm(path)
    if not low:
        return "none"
    win = cmdline.norm(cmdline.windir())
    if "\\appdata\\local\\temp\\" in low or low.startswith(win + "\\temp\\") or re.match(r"^[a-z]:\\temp\\", low):
        return "temp"
    if "\\$recycle.bin\\" in low:
        return "recycle"
    if low.startswith(win + "\\"):
        return "windows"
    if re.match(r"^[a-z]:\\program files( \(x86\))?\\", low):
        return "program-files"
    if "\\users\\public\\" in low:
        return "public"
    if "\\downloads\\" in low:
        return "downloads"
    if "\\appdata\\" in low:
        return "appdata"
    if re.match(r"^[a-z]:\\programdata\\", low):
        return "programdata"
    return "other"


USER_WRITABLE = {"temp", "recycle", "public", "downloads", "appdata", "programdata", "other"}

# ------------------------------------------------------------ command lines
CMD_PATTERNS = [
    ("encoded-powershell",
     re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b.*\s[-/]e(?:c|nc|ncodedcommand|ncoded|ncode|nco)?\s+[A-Za-z0-9+/=]{16,}", re.I),
     "Runs a PowerShell script disguised as base64 text."),
    ("powershell-download",
     re.compile(r"\b(?:powershell|pwsh)\b.*(?:downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient|start-bitstransfer)", re.I),
     "Downloads something from the internet every time it runs."),
    ("powershell-iex",
     re.compile(r"\b(?:powershell|pwsh)\b.*\b(?:iex|invoke-expression)\b", re.I),
     "Executes text as code (Invoke-Expression)."),
    ("mshta-script",
     re.compile(r"\bmshta(?:\.exe)?\b.*(?:https?:|javascript:|vbscript:)", re.I),
     "Uses mshta to run script code from a web address or an inline script."),
    ("rundll32-script",
     re.compile(r"\brundll32(?:\.exe)?\b.*(?:javascript:|vbscript:|https?:)", re.I),
     "Uses rundll32 to run script code."),
    ("regsvr32-remote",
     re.compile(r"\bregsvr32(?:\.exe)?\b.*(?:/i:\s*https?:|scrobj\.dll)", re.I),
     "Uses regsvr32 to load a script from the web, a well-known abuse trick."),
    ("certutil-download",
     re.compile(r"\bcertutil(?:\.exe)?\b.*(?:-urlcache|-decode)", re.I),
     "Uses certutil to download or unpack a file."),
    ("bitsadmin-transfer",
     re.compile(r"\bbitsadmin(?:\.exe)?\b.*/transfer", re.I),
     "Uses bitsadmin to download a file."),
]
_HIDDEN = re.compile(r"\s[-/]w(?:indowstyle)?\s+hidden\b", re.I)
_B64 = re.compile(r"\s[-/]e(?:c|nc|ncodedcommand|ncoded|ncode|nco)?\s+([A-Za-z0-9+/=]{16,})", re.I)
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe"}


def decode_powershell(command: str) -> str | None:
    m = _B64.search(command or "")
    if not m:
        return None
    blob = m.group(1)
    blob += "=" * (-len(blob) % 4)
    try:
        return base64.b64decode(blob).decode("utf-16-le", errors="replace")[:2000]
    except (ValueError, base64.binascii.Error):
        return None


# ------------------------------------------------------------------ analysis
def _flag(fid: str, severity: str, text: str) -> dict:
    return {"id": fid, "severity": severity, "text": text}


def analyze(entry: dict) -> dict:
    """Add facts that code can establish on its own: windows/zombie/flags/decoded payload."""
    f = entry.get("file") or {}
    target = entry.get("target") or ""
    cn = parse_dn(f.get("signer")).get("CN", "").lower()
    valid = bool(f.get("exists") and f.get("sigStatus") == "Valid")
    location = (entry.get("location") or "").lower()
    in_windows_tasks = entry.get("kind") == "task" and location.startswith(WINDOWS_TASK_ROOTS)
    pclass = path_class(target)
    signer_org = publisher(f)
    whql = valid and cn == WHQL_SIGNER
    microsoft_signed = valid and "microsoft" in signer_org.lower() and not whql

    # Drivers are signed by Microsoft's hardware programme; the vendor is in the file's version info.
    entry["publisher"] = (f.get("company") or signer_org) if whql else signer_org
    entry["hardware"] = bool(whql)
    entry["is_windows"] = bool(
        (valid and (f.get("isOsBinary") or cn in OS_SIGNERS))
        or (microsoft_signed and pclass == "windows")
        or (in_windows_tasks and (not f.get("exists") or microsoft_signed))
    )
    entry["unresolved"] = not target
    entry["zombie"] = bool(target and not f.get("exists") and not entry["is_windows"])

    flags: list[dict] = []
    command = entry.get("command") or ""
    for fid, pattern, text in CMD_PATTERNS:
        if pattern.search(command):
            flags.append(_flag(fid, "high", text))
    decoded = decode_powershell(command) if any(x["id"] == "encoded-powershell" for x in flags) else None
    if decoded:
        entry["decoded"] = decoded

    pclass = path_class(target)
    name = ntpath.basename(target).lower()
    if f.get("exists"):
        status = f.get("sigStatus")
        if status not in ("Valid", "NotSigned", None, ""):
            flags.append(_flag("bad-signature", "high", f"Its digital signature does not check out (Windows says: {status})."))
        if pclass in ("temp", "recycle"):
            flags.append(_flag("runs-from-temp", "high", "Runs a file from a temporary or deleted-files folder, where installers don't leave things that should start every day."))
        if name in SYSTEM_NAMES and pclass != "windows" and not microsoft_signed:
            flags.append(_flag("masquerade", "high", f"Uses the name of a Windows system file ({name}) but lives outside the Windows folder."))
        if location.startswith("\\microsoft\\") and entry.get("kind") == "task" and not (microsoft_signed or entry["is_windows"]):
            flags.append(_flag("hidden-in-windows-tasks", "high", "Sits among Windows' own scheduled tasks, but the file is not from Microsoft."))
        if status == "NotSigned":
            if pclass in USER_WRITABLE:
                flags.append(_flag("unsigned-user-folder", "medium", "Not digitally signed, and it lives in a folder that any program can write to."))
            else:
                flags.append(_flag("unsigned", "low", "Not digitally signed by its publisher."))
    host = ntpath.basename(entry.get("exe") or "").lower()
    if host in SCRIPT_HOSTS and target and target != entry.get("exe") and pclass in USER_WRITABLE and not entry["zombie"]:
        flags.append(_flag("script-from-user-folder", "medium", f"{host} runs a script from a folder any program can write to."))
    if _HIDDEN.search(command) and host in {"powershell.exe", "pwsh.exe"}:
        flags.append(_flag("hidden-window", "low", "Runs with its window hidden."))
    if entry.get("wake_to_run"):
        flags.append(_flag("wakes-pc", "low", "Allowed to wake the PC from sleep to run."))
    entry["flags"] = flags
    entry["path_class"] = pclass
    return entry


# ------------------------------------------------------------------ verdicts
VERDICTS = {
    # id: (ghost name, short action)
    "investigate": ("Poltergeist", "Investigate"),
    "lay_to_rest": ("Zombie", "Lay it to rest"),
    "optional": ("Uninvited guest", "Your call"),
    "unknown": ("Unknown spirit", "Look it up"),
    "keep": ("Friendly ghost", "Keep"),
    "dormant": ("Sleeping", "Already off"),
    "windows": ("House spirit", "Part of Windows"),
    "unexplained": ("Unexamined", "Ask Gemma"),
}

KEEP_REASONS = {
    "updater": "It installs security fixes for an app you have. Turning it off leaves that app unpatched.",
    "security": "It protects this PC.",
    "driver-helper": "It supports your hardware (sound, touchpad, keys, graphics). Turning it off can break those features.",
    "windows-component": "Part of Windows.",
}
OPTIONAL_REASONS = {
    "cloud-sync": "Syncs files in the background. Keep it if you rely on it; otherwise it can start when you open it.",
    "chat-social": "A chat or meeting app. It works fine if you open it yourself when you need it.",
    "browser": "Pre-loads or updates a browser behind the scenes. The browser still works if you open it yourself.",
    "dev-tool": "A developer tool or server. Start it when you need it instead of at every boot.",
    "vpn-network": "A VPN or network tool. Keep it if you want it connected automatically.",
    "vendor-utility": "A laptop-maker extra. Only useful if you use that feature.",
    "exam-proctoring": "Exam or lock-down software. Only needed on exam days.",
    "game-launcher": "A game launcher. Games still work when you open it yourself.",
    "media": "A media app. It works when you open it yourself.",
    "productivity": "An app that is handy, but doesn't need to start before you ask for it.",
}
KEEP_CATEGORIES = set(KEEP_REASONS)


def decide(entry: dict, explanation: dict | None = None) -> tuple[str, str]:
    """Return (verdict, reason). Hard facts first; the model's category only matters at the end."""
    flags = entry.get("flags") or []
    high = [x for x in flags if x["severity"] == "high"]
    medium = [x for x in flags if x["severity"] == "medium"]
    if entry.get("is_windows") and not high:
        return "windows", "Part of Windows itself."
    if high:
        return "investigate", high[0]["text"]
    if entry.get("zombie"):
        return "lay_to_rest", "The program it tries to start no longer exists. It does nothing except fail every time."
    if not entry.get("enabled", True):
        return "dormant", "It is switched off already, so it will not start."
    if medium:
        return "investigate", medium[0]["text"]
    if entry.get("kind") == "runonce":
        return "keep", "Runs once at your next sign-in to finish an install or clean-up, then removes itself."
    if entry.get("unresolved"):
        return "unknown", "Windows doesn't say which program this runs."
    if not explanation:
        return "unexplained", "Not examined yet."
    category = explanation.get("category") or "unknown"
    if category == "unknown" or explanation.get("confidence") == "low":
        return "unknown", "The local model doesn't recognise it with confidence."
    if category in KEEP_CATEGORIES:
        return "keep", KEEP_REASONS[category]
    return "optional", OPTIONAL_REASONS.get(category, "Handy, but it doesn't need to start before you ask for it.")


# ------------------------------------------------------------------ commands
def _reg_escape(text: str) -> str:
    return text.replace('"', '\\"')


def commands(entry: dict) -> dict:
    """How to turn it off and how to undo that. Uninvited never runs these itself."""
    kind = entry.get("kind")
    name = entry.get("name") or ""
    location = entry.get("location") or ""
    admin = entry.get("scope") != "user"
    if kind == "run":
        if entry.get("zombie"):
            off = f'reg delete "{location}" /v "{name}" /f'
            undo = f'reg add "{location}" /v "{name}" /t REG_SZ /d "{_reg_escape(entry.get("command") or "")}" /f'
            how = "Delete the leftover registry value."
        else:
            hive = location.split("\\", 1)[0]
            sub = "Run32" if "wow6432node" in location.lower() else "Run"
            key = f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\{sub}"
            off = f'reg add "{key}" /v "{name}" /t REG_BINARY /d 030000000000000000000000 /f'
            undo = f'reg add "{key}" /v "{name}" /t REG_BINARY /d 020000000000000000000000 /f'
            how = "Same as Task Manager > Startup apps > Disable."
    elif kind == "startup":
        shortcut = entry.get("shortcut") or ""
        base = ntpath.basename(shortcut)
        off = (f'New-Item -ItemType Directory -Force "$env:USERPROFILE\\Uninvited-Graveyard" | Out-Null; '
               f'Move-Item -LiteralPath "{shortcut}" -Destination "$env:USERPROFILE\\Uninvited-Graveyard\\"')
        undo = f'Move-Item -LiteralPath "$env:USERPROFILE\\Uninvited-Graveyard\\{base}" -Destination "{ntpath.dirname(shortcut)}\\"'
        how = "Move the shortcut out of the Startup folder (PowerShell)."
    elif kind == "task":
        tn = f"{location}{name}"
        if entry.get("zombie"):
            off = f'schtasks /Query /TN "{tn}" /XML > "%USERPROFILE%\\uninvited-task-backup.xml" && schtasks /Delete /TN "{tn}" /F'
            undo = f'schtasks /Create /TN "{tn}" /XML "%USERPROFILE%\\uninvited-task-backup.xml"'
            how = "Back up the task, then delete it (Command Prompt)."
        else:
            off = f'schtasks /Change /TN "{tn}" /DISABLE'
            undo = f'schtasks /Change /TN "{tn}" /ENABLE'
            how = "Disable the scheduled task (Command Prompt)."
    elif kind == "service":
        off = f'sc.exe config "{name}" start= demand'
        undo = f'sc.exe config "{name}" start= auto'
        how = "Switch the service to Manual: it starts only when something needs it."
        admin = True
    else:
        return {"how": "Nothing to do: it removes itself after running once.", "off": "", "undo": "", "admin": False}
    return {"how": how, "off": off, "undo": undo, "admin": admin}
