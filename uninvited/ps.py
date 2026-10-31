"""Run the bundled PowerShell scripts and read their JSON output."""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path

from .config import PACKAGE_DIR

SCRIPTS = PACKAGE_DIR / "scripts"
CREATE_NO_WINDOW = 0x08000000


class PowerShellError(RuntimeError):
    pass


def run_script(name: str, workdir: Path, timeout: int = 240, **params: object) -> object:
    """Run scripts/<name> with -Param value pairs plus -OutPath, return the parsed JSON it wrote."""
    out = workdir / f"ps-{uuid.uuid4().hex}.json"
    cmd = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(SCRIPTS / name),
    ]
    for key, value in params.items():
        cmd += [f"-{key}", str(value)]
    cmd += ["-OutPath", str(out)]
    flags = CREATE_NO_WINDOW if os.name == "nt" else 0
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=flags)
    if not out.exists():
        detail = (proc.stderr or proc.stdout or "").strip()[:800]
        raise PowerShellError(f"{name} produced no output (exit {proc.returncode}). {detail}")
    try:
        text = out.read_text(encoding="utf-8-sig").strip()
        return json.loads(text) if text else None
    finally:
        out.unlink(missing_ok=True)
