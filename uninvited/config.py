"""Paths and settings. Everything is overridable with environment variables or a .env file."""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent


def load_dotenv() -> None:
    """Minimal .env loader (no dependency). Existing environment variables win."""
    for candidate in (Path.cwd() / ".env", PROJECT_DIR / ".env"):
        if not candidate.is_file():
            continue
        for raw in candidate.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and value and key not in os.environ:
                os.environ[key] = value


load_dotenv()

DEFAULT_MODEL = os.environ.get("UNINVITED_MODEL", "gemma4:e4b-it-qat")
FALLBACK_MODELS = ("gemma4:e4b-it-qat", "gemma4:e4b", "gemma4", "gemma4:e2b")


def ollama_host() -> str:
    host = os.environ.get("UNINVITED_OLLAMA", "") or os.environ.get("OLLAMA_HOST", "") or "127.0.0.1:11434"
    host = host.strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    # OLLAMA_HOST is often the *bind* address of the server (0.0.0.0); talk to localhost instead.
    return host.replace("://0.0.0.0", "://127.0.0.1")


def home() -> Path:
    """Where Uninvited keeps its small cache and reports."""
    configured = os.environ.get("UNINVITED_HOME")
    if configured:
        base = Path(configured)
    else:
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "Uninvited"
    base.mkdir(parents=True, exist_ok=True)
    return base


def serpapi_key() -> str | None:
    return os.environ.get("SERPAPI_KEY") or os.environ.get("SERPAPI_API_KEY") or None


TEMPORAL_ADDRESS = os.environ.get("UNINVITED_TEMPORAL", "127.0.0.1:7233")
TASK_QUEUE = "uninvited-night-watch"
