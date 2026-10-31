"""Opt-in web lookup through SerpApi, for items the local model does not recognise.

Only the file name and the publisher leave the machine. Never paths, usernames or other entries.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import urllib.error
import urllib.parse
import urllib.request

from . import ai, config

ENDPOINT = "https://serpapi.com/search.json"


def build_query(entry: dict) -> str:
    name = ntpath.basename(entry.get("target") or "") or ai.anonymize(entry.get("name") or "")
    pub = entry.get("publisher") or (entry.get("file") or {}).get("company") or ""
    query = f'"{name}"'
    if pub:
        query += f" {pub}"
    return query + " startup"


def search(query: str, key: str, num: int = 6) -> list[dict]:
    params = {"engine": "google", "q": query, "num": str(num), "hl": "en", "api_key": key}
    url = ENDPOINT + "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise LookupError(f"SerpApi said {exc.code}: {detail}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise LookupError(f"Could not reach SerpApi: {exc}") from exc
    if data.get("error"):
        raise LookupError(data["error"])
    results = []
    for item in (data.get("organic_results") or [])[:num]:
        link = item.get("link") or ""
        results.append({
            "title": item.get("title") or "",
            "link": link,
            "snippet": item.get("snippet") or "",
            "source": item.get("source") or urllib.parse.urlparse(link).netloc,
        })
    return results


def web_lookup(entry: dict, client: ai.Ollama | None = None, key: str | None = None) -> dict:
    key = key or config.serpapi_key()
    if not key:
        return {"error": "No SERPAPI_KEY set. Add SERPAPI_KEY=... to a .env file to enable web lookups."}
    query = build_query(entry)
    cache = ai.Cache("lookups.json")
    cache_id = hashlib.sha1(query.lower().encode("utf-8")).hexdigest()
    hit = cache.get(cache_id)
    try:
        if hit:
            results = hit["results"]
        else:
            results = search(query, key)
            cache.put(cache_id, {"query": query, "results": results})
    except LookupError as exc:
        return {"query_sent": query, "error": str(exc)}
    try:
        explanation = ai.grounded_explain(entry, results, client)
    except ai.ModelError as exc:
        return {"query_sent": query, "results": results, "error": str(exc)}
    return {"query_sent": query, "results": results, "explanation": explanation,
            "engine": "Google results via SerpApi", "cached": bool(hit)}
