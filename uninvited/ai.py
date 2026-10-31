"""Gemma, running locally through Ollama, explains. It never decides."""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
import threading
import time
import unicodedata
import urllib.error
import urllib.request

from . import config

PROMPT_VERSION = "2026-11-01.3"

CATEGORIES = [
    "updater", "security", "driver-helper", "vendor-utility", "cloud-sync", "chat-social", "browser",
    "dev-tool", "vpn-network", "exam-proctoring", "game-launcher", "media", "productivity",
    "windows-component", "unknown",
]

EXPLAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "product": {"type": "string"},
        "vendor": {"type": "string"},
        "category": {"type": "string", "enum": CATEGORIES},
        "what_it_does": {"type": "string"},
        "why_at_startup": {"type": "string"},
        "if_disabled": {"type": "string"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": ["product", "vendor", "category", "what_it_does", "why_at_startup", "if_disabled", "confidence"],
}

EXPLAIN_SYSTEM = """You are Uninvited, a calm expert who explains Windows startup items to people who are not technical.
You get FACTS about one item that starts automatically on a Windows laptop. Reply in JSON.

Rules:
1. Base your answer on the FACTS. Use general knowledge only to recognise well-known software and what it is for.
2. If you do not recognise it, set product to "unknown", category to "unknown" and confidence to "low". Never invent a purpose.
3. vendor is the company that makes the software. The digital signature is the strongest clue.
4. Do not tell the person to keep, disable or remove anything, and do not call anything malware or a virus. Other checks decide that.
5. what_it_does: at most 2 short sentences in plain English. why_at_startup: 1 sentence. if_disabled: 1 sentence about what the person would notice.

Category guide:
- updater: only installs updates for an app
- security: antivirus or firewall
- driver-helper: needed for sound, touchpad, keyboard keys, graphics, battery or other hardware to work
- vendor-utility: laptop-maker extras such as diagnostics, analytics, screen sharing, recovery or app stores
- cloud-sync: OneDrive, Dropbox, Google Drive and similar
- chat-social: chat, call or meeting apps
- browser: a web browser or its pre-loader
- dev-tool: developer tools, databases, containers, local servers, AI runtimes, Linux subsystems
- vpn-network: VPNs and network tools
- exam-proctoring: exam lock-down software
- game-launcher, media, productivity (office apps and their helpers)
- windows-component: part of Windows itself
- unknown: you do not recognise it"""

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["keep", "optional", "remove", "investigate"]},
        "reason": {"type": "string"},
    },
    "required": ["verdict", "reason"],
}

VERDICT_SYSTEM = """You help people clean up what starts automatically on their Windows laptop.
Given FACTS about one startup item, decide what the person should do:
keep = needed or protective; optional = harmless, fine to turn off; remove = leftover or useless; investigate = suspicious.
Reply in JSON with a verdict and a one-sentence reason."""

NARRATE_SCHEMA = {
    "type": "object",
    "properties": {"headline": {"type": "string"}, "story": {"type": "string"}},
    "required": ["headline", "story"],
}

NARRATE_SYSTEM = """You write the morning report of a laptop's night, like a ghost hunter's log, for a student.
You get STATS measured from the Windows event log. Write a headline (max 14 words) and a story (3 to 4 sentences).
Rules: use ONLY numbers that appear in STATS, exactly as written. Do not do arithmetic. Do not give advice.
Be vivid but accurate: the laptop leaving standby is not a person; 'undocumented code' means nobody knows."""

GROUNDED_SCHEMA = {
    "type": "object",
    "properties": {
        "product": {"type": "string"},
        "vendor": {"type": "string"},
        "category": {"type": "string", "enum": CATEGORIES},
        "what_it_does": {"type": "string"},
        "citations": {"type": "array", "items": {"type": "integer"}},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": ["product", "vendor", "category", "what_it_does", "citations", "confidence"],
}

GROUNDED_SYSTEM = """You identify a Windows startup item using ONLY the numbered web search results provided.
Cite the result numbers you used in "citations". If the results do not identify it, set product to "unknown",
category to "unknown", confidence to "low" and citations to []. Do not tell the person what to do with it."""

SEANCE_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}, "cited_ids": {"type": "array", "items": {"type": "string"}}},
    "required": ["answer", "cited_ids"],
}

SEANCE_SYSTEM = """You are the medium at a seance with a laptop. Answer the question using ONLY the RECORDS and STATS given.
Cite every record you rely on by its id (like E1a2b3c4d) in cited_ids. If the records do not answer it, say so.
Keep it under 90 words, plain English, a little spooky. Never claim something is malware unless a record says 'investigate'."""


class ModelError(RuntimeError):
    pass


# ---------------------------------------------------------------- client
class Ollama:
    def __init__(self, model: str | None = None, host: str | None = None, timeout: int = 600):
        self.host = (host or config.ollama_host()).rstrip("/")
        self.model = model or config.DEFAULT_MODEL
        self.timeout = timeout

    def models(self) -> list[str]:
        try:
            with urllib.request.urlopen(self.host + "/api/tags", timeout=5) as r:
                return [m["name"] for m in json.loads(r.read()).get("models", [])]
        except (urllib.error.URLError, OSError, ValueError):
            return []

    def pick_model(self) -> str | None:
        available = self.models()
        if self.model in available:
            return self.model
        for name in config.FALLBACK_MODELS:
            if name in available:
                self.model = name
                return name
        return None

    def chat_json(self, system: str, user: str, schema: dict, num_predict: int = 400,
                  temperature: float = 0.0) -> tuple[dict, dict]:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "think": False,
            "format": schema,
            "keep_alive": "30m",
            "options": {"temperature": temperature, "num_predict": num_predict, "num_ctx": 4096, "seed": 7},
        }
        req = urllib.request.Request(self.host + "/api/chat", data=json.dumps(body).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        started = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.loads(r.read())
        except (urllib.error.URLError, OSError) as exc:
            raise ModelError(f"Ollama is not reachable at {self.host}: {exc}") from exc
        content = (resp.get("message") or {}).get("content") or ""
        try:
            data = json.loads(content)
        except ValueError as exc:
            raise ModelError(f"Model returned invalid JSON: {content[:200]}") from exc
        stats = {
            "model": self.model,
            "seconds": round(time.time() - started, 2),
            "prompt_tokens": resp.get("prompt_eval_count"),
            "output_tokens": resp.get("eval_count"),
        }
        return data, stats


# ---------------------------------------------------------------- facts
KIND_TEXT = {
    "run": "Registry Run key: starts every time you sign in",
    "runonce": "Registry RunOnce key: runs once at the next sign-in",
    "startup": "Shortcut in the Startup folder: starts every time you sign in",
    "task": "Scheduled task",
    "service": "Windows service that starts with Windows",
}


def anonymize(text: str) -> str:
    """Scrub the user's profile path, username, PC name and account SID."""
    if not text:
        return text
    profile = os.environ.get("USERPROFILE") or ""
    user = os.environ.get("USERNAME") or ""
    computer = os.environ.get("COMPUTERNAME") or ""
    out = text
    if profile:
        out = re.sub(re.escape(profile), "%USERPROFILE%", out, flags=re.IGNORECASE)
    if user and len(user) > 2:
        out = re.sub(r"(?i)\\users\\" + re.escape(user) + r"(?=\\|$)", r"\\Users\\<you>", out)
        out = re.sub(re.escape(user), "<you>", out, flags=re.IGNORECASE)
    if computer and len(computer) > 2:
        out = re.sub(re.escape(computer), "<this-pc>", out, flags=re.IGNORECASE)
    return re.sub(r"S-1-5-21-\d+-\d+-\d+-\d+", "S-1-5-21-<you>", out)


def facts(entry: dict, findings: bool = True) -> str:
    """The prompt's view of one entry. `findings` adds what the rules found (off for the naive baseline)."""
    f = entry.get("file") or {}
    lines = [f"Kind: {KIND_TEXT.get(entry.get('kind'), entry.get('kind'))}",
             f"Entry name: {anonymize(entry.get('display_name') or entry.get('name') or '')}"]
    if entry.get("description"):
        lines.append(f"Description written by Windows or the vendor: {entry['description'][:300]}")
    if entry.get("kind") == "task":
        lines.append(f"Task folder: {anonymize(entry.get('location') or '')}")
        if entry.get("author"):
            lines.append(f"Task author: {anonymize(entry['author'])}")
    lines.append(f"Command: {anonymize(entry.get('command') or '')[:400]}")
    if entry.get("target"):
        lines.append(f"File: {ntpath.basename(entry['target'])}")
    for key, label in (("description", "File description"), ("product", "Product name"),
                       ("company", "Company in file properties"), ("version", "Version")):
        if f.get(key):
            lines.append(f"{label}: {f[key]}")
    if f.get("exists"):
        signer = entry.get("publisher") or "nobody"
        status = f.get("sigStatus") or "unknown"
        if entry.get("hardware"):
            lines.append(f"Digital signature: {status}, signed through Microsoft's hardware driver programme for {signer}")
            lines.append("Installed as part of a hardware driver package")
        else:
            lines.append(f"Digital signature: {status}, signed by {signer}")
    else:
        lines.append("The file does not exist on disk")
    lines.append(f"Runs: {entry.get('trigger') or 'unknown'}")
    running = entry.get("running")
    lines.append(f"Running right now: yes, using {running['mb']} MB of memory" if running else "Running right now: no")
    serious = [x for x in entry.get("flags") or [] if x.get("severity") in ("high", "medium")]
    if findings and serious:
        lines.append("Automatic checks found: " + " ".join(x["text"] for x in serious))
    if findings and entry.get("decoded"):
        lines.append(f"Decoded PowerShell script: {entry['decoded'][:500]}")
    return "FACTS\n" + "\n".join(lines)


def identity(entry: dict) -> str:
    """Entries that run the same program share one explanation."""
    f = entry.get("file") or {}
    if entry.get("target"):
        base = ntpath.basename(entry["target"]).lower()
        return "|".join([base, entry.get("publisher") or "", f.get("description") or "", f.get("product") or ""])
    return "|".join([entry.get("kind") or "", entry.get("name") or ""])


# ---------------------------------------------------------------- guards
_SUFFIX = {"inc", "llc", "ltd", "corporation", "corp", "co", "gmbh", "sa", "ag", "the", "limited",
           "communications", "computer", "america", "technologies", "technology", "software", "systems", "group"}


def _tokens(name: str) -> set[str]:
    text = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode().lower()
    return {t for t in re.split(r"[^a-z0-9]+", text) if len(t) >= 3 and t not in _SUFFIX}


def vendor_matches(vendor: str, *references: str) -> bool | None:
    """None when there is nothing to compare against."""
    refs = [r for r in references if r]
    vt = _tokens(vendor)
    if not refs or not vt or vendor.strip().lower() == "unknown":
        return None
    for ref in refs:
        for a in vt:
            for b in _tokens(ref):
                if a == b or (len(a) >= 4 and a in b) or (len(b) >= 4 and b in a):
                    return True
    return False


_SCARY = re.compile(r"\b(malware|virus|trojan|spyware|ransomware|malicious|hack(?:er|ed|ing)?|dangerous|infected)\b", re.I)
_ADVICE = re.compile(r"\b(you should|we recommend|i recommend|it is (?:safe|recommended) to|(?:safe|okay|ok|fine) to (?:disable|remove|delete|uninstall))\b", re.I)


def _strip_sentences(text: str, pattern: re.Pattern) -> tuple[str, bool]:
    sentences = re.split(r"(?<=[.!?])\s+", text or "")
    kept = [s for s in sentences if not pattern.search(s)]
    return " ".join(kept).strip(), len(kept) != len(sentences)


# ---------------------------------------------------------------- cache
class Cache:
    def __init__(self, name: str):
        self.path = config.home() / name
        self.lock = threading.Lock()
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}

    def get(self, key: str):
        return self.data.get(key)

    def put(self, key: str, value) -> None:
        with self.lock:
            self.data[key] = value
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
            os.replace(tmp, self.path)


_EXPLAIN_CACHE: Cache | None = None


def explain_cache() -> Cache:
    global _EXPLAIN_CACHE
    if _EXPLAIN_CACHE is None:
        _EXPLAIN_CACHE = Cache("explanations.json")
    return _EXPLAIN_CACHE


def cache_key(entry: dict, model: str) -> str:
    return hashlib.sha1(f"{PROMPT_VERSION}|{model}|{identity(entry)}".lower().encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- tasks
def explain(entry: dict, client: Ollama | None = None, use_cache: bool = True) -> dict:
    """Explain one entry. Returns the explanation with guard notes and timing."""
    client = client or Ollama()
    key = cache_key(entry, client.model)
    if use_cache:
        hit = explain_cache().get(key)
        if hit:
            return hit
    user = facts(entry)
    data, stats = client.chat_json(EXPLAIN_SYSTEM, user, EXPLAIN_SCHEMA)
    notes: list[str] = []
    refs = (entry.get("publisher") or "", (entry.get("file") or {}).get("company") or "")
    ok = vendor_matches(data.get("vendor", ""), *refs)
    if ok is False:
        notes.append(f"vendor-mismatch: model said '{data.get('vendor')}', signature says '{refs[0] or refs[1]}'")
        retry_user = user + f"\n\nCheck: the digital signature says the publisher is '{refs[0] or refs[1]}'. Correct your answer if needed."
        data2, stats2 = client.chat_json(EXPLAIN_SYSTEM, retry_user, EXPLAIN_SCHEMA)
        stats["seconds"] += stats2["seconds"]
        if vendor_matches(data2.get("vendor", ""), *refs) is False:
            data2["vendor"] = refs[0] or refs[1]
            data2["confidence"] = "low"
            notes.append("vendor-overridden-by-signature")
        else:
            notes.append("vendor-fixed-on-retry")
        data = data2
    flagged = any(x["severity"] in ("high", "medium") for x in entry.get("flags") or [])
    for field in ("what_it_does", "why_at_startup", "if_disabled"):
        text = data.get(field, "")
        text, advised = _strip_sentences(text, _ADVICE)
        if advised:
            notes.append(f"advice-removed:{field}")
        if not flagged:
            text, scared = _strip_sentences(text, _SCARY)
            if scared:
                notes.append(f"scare-words-removed:{field}")
        data[field] = text
    result = {**data, "notes": notes, "stats": stats, "prompt_version": PROMPT_VERSION}
    explain_cache().put(key, result)
    return result


def direct_verdict(entry: dict, client: Ollama) -> tuple[dict, dict]:
    """The 'let the model decide' baseline, used only for evaluation. Raw facts, no rule findings."""
    return client.chat_json(VERDICT_SYSTEM, facts(entry, findings=False), VERDICT_SCHEMA, num_predict=160)


def _allowed_numbers(stats: dict) -> set[str]:
    allowed: set[str] = set()

    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
        elif isinstance(v, bool):
            return
        elif isinstance(v, (int, float)):
            for form in {v, round(v), round(v, 1)}:
                allowed.add(str(form))
                if isinstance(form, float) and form.is_integer():
                    allowed.add(str(int(form)))
        elif isinstance(v, str):
            for n in re.findall(r"\d+(?:\.\d+)?", v):
                allowed.add(n)

    walk(stats)
    return allowed


def numbers_ok(text: str, stats: dict) -> tuple[bool, list[str]]:
    allowed = _allowed_numbers(stats)
    found = re.findall(r"(?<![\w.])\d+(?:\.\d+)?", text or "")
    bad = [n for n in found if n not in allowed]
    return not bad, bad


def wake_stats_for_story(w: dict) -> dict:
    keys = ["window_days", "exits", "not_you", "night_exits", "night_not_you", "standby_hours", "awake_hours",
            "awake_share_pct", "deep_sleep_pct", "austerity_count", "battery_drained_pct", "drain_pct_per_hour",
            "battery_health_pct"]
    stats = {k: w.get(k) for k in keys if w.get(k) is not None}
    stats["nights_with_austerity"] = len(w.get("austerity_nights") or [])
    stats["undocumented_exits"] = sum((w.get("unknown_codes") or {}).values())
    stats["by_cause"] = w.get("by_class")
    return stats


def fallback_story(w: dict) -> dict:
    s = wake_stats_for_story(w)
    headline = f"{s.get('not_you', 0)} of {s.get('exits', 0)} standby exits weren't you"
    story = (f"Over the last {s.get('window_days')} days the laptop spent {s.get('standby_hours')} hours in standby, "
             f"but it was really awake for {s.get('awake_hours')} of them. "
             f"Windows had to clamp down on battery drain {s.get('austerity_count')} times, on {s.get('nights_with_austerity')} different nights. "
             f"{s.get('undocumented_exits')} exits carry a reason code nobody has documented.")
    return {"headline": headline, "story": story, "source": "template"}


def narrate_wakes(w: dict, client: Ollama | None = None, attempts: int = 2) -> dict:
    client = client or Ollama()
    stats = wake_stats_for_story(w)
    user = "STATS\n" + json.dumps(stats, indent=1)
    rejected: list[str] = []
    for _ in range(attempts):
        try:
            data, info = client.chat_json(NARRATE_SYSTEM, user, NARRATE_SCHEMA, num_predict=260, temperature=0.4)
        except ModelError:
            break
        ok, bad = numbers_ok(data.get("headline", "") + " " + data.get("story", ""), stats)
        if ok:
            return {**data, "source": client.model, "stats": info, "rejected_numbers": rejected}
        rejected += bad
        user += f"\n\nYour last answer used numbers that are not in STATS: {', '.join(bad)}. Use only STATS numbers."
    out = fallback_story(w)
    out["rejected_numbers"] = rejected
    return out


def grounded_explain(entry: dict, results: list[dict], client: Ollama | None = None) -> dict:
    client = client or Ollama()
    numbered = "\n".join(f"[{i}] {r.get('title', '')} ({r.get('source') or r.get('link', '')}): {r.get('snippet', '')}"
                         for i, r in enumerate(results, 1))
    user = facts(entry) + "\n\nSEARCH RESULTS\n" + (numbered or "(none)")
    data, stats = client.chat_json(GROUNDED_SYSTEM, user, GROUNDED_SCHEMA, num_predict=320)
    cites = [c for c in data.get("citations") or [] if isinstance(c, int)]
    valid = [c for c in cites if 1 <= c <= len(results)]
    data["citations"] = valid
    data["grounded"] = bool(valid) and len(valid) == len(cites)
    if not data["grounded"]:
        data["confidence"] = "low"
    data["stats"] = stats
    return data


def seance(question: str, entries: list[dict], wake_summary: dict, client: Ollama | None = None) -> dict:
    client = client or Ollama()
    words = {w for w in re.findall(r"[a-z0-9]{3,}", question.lower())}

    def score(e: dict) -> int:
        text = " ".join(str(e.get(k) or "") for k in ("name", "display_name", "publisher", "trigger", "verdict"))
        text += " " + " ".join(str((e.get("explanation") or {}).get(k) or "") for k in ("product", "what_it_does", "category"))
        return sum(1 for w in words if w in text.lower())

    candidates = [e for e in entries if e.get("verdict") not in ("windows",)]
    ranked = sorted(candidates, key=score, reverse=True)[:12]
    records = []
    for e in ranked:
        ex = e.get("explanation") or {}
        records.append(f"{e['id']}: {e.get('display_name')} | {ex.get('product') or e.get('publisher')} | "
                       f"verdict={e.get('verdict')} | runs {e.get('trigger')} | "
                       f"{'running, ' + str(e['running']['mb']) + ' MB' if e.get('running') else 'not running'} | "
                       f"{ex.get('what_it_does') or ''}")
    stats = wake_stats_for_story(wake_summary)
    user = (f"QUESTION: {question}\n\nRECORDS\n" + "\n".join(records) + "\n\nSTATS\n" + json.dumps(stats))
    data, info = client.chat_json(SEANCE_SYSTEM, user, SEANCE_SCHEMA, num_predict=260, temperature=0.2)
    known = {e["id"] for e in entries}
    raw_ids = [c for c in data.get("cited_ids") or [] if isinstance(c, str)]
    data["cited_ids"] = [c for c in raw_ids if c in known]
    data["invented_ids"] = [c for c in raw_ids if c not in known]
    ok, bad = numbers_ok(data.get("answer", ""), {"stats": stats, "records": records})
    data["unverified_numbers"] = bad
    data["stats"] = info
    return data
