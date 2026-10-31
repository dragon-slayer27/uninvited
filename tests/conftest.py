import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("UNINVITED_HOME", str(tmp_path / "home"))
    from uninvited import ai

    ai._EXPLAIN_CACHE = None
    yield tmp_path / "home"
    ai._EXPLAIN_CACHE = None


class FakeOllama:
    """Replays scripted model answers and records every prompt."""

    def __init__(self, answers, model="fake-gemma"):
        self.answers = list(answers)
        self.model = model
        self.host = "http://fake"
        self.prompts = []

    def pick_model(self):
        return self.model

    def chat_json(self, system, user, schema, num_predict=400, temperature=0.0):
        self.prompts.append(user)
        answer = self.answers.pop(0)
        return dict(answer), {"model": self.model, "seconds": 0.01, "prompt_tokens": 1, "output_tokens": 1}


@pytest.fixture
def fake_ollama():
    return FakeOllama


def make_entry(**over):
    entry = {
        "id": "E00000001",
        "kind": "run",
        "scope": "user",
        "location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "name": "Thing",
        "display_name": "Thing",
        "description": "",
        "command": r'"C:\Program Files\Thing\thing.exe" --background',
        "exe": r"C:\Program Files\Thing\thing.exe",
        "args": "--background",
        "target": r"C:\Program Files\Thing\thing.exe",
        "enabled": True,
        "state": "Enabled",
        "trigger": "every time you sign in",
        "wake_to_run": False,
        "running": None,
        "file": {"exists": True, "sigStatus": "Valid", "sigType": "Authenticode", "isOsBinary": False,
                 "signer": "CN=Thing Corp, O=Thing Corp, C=US", "company": "Thing Corp", "description": "Thing"},
    }
    entry.update(over)
    return entry


@pytest.fixture
def entry_factory():
    return make_entry


os.environ.setdefault("NO_COLOR", "1")
