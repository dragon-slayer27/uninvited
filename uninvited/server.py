"""Local web UI. Binds to 127.0.0.1 only and loads nothing from the internet."""

from __future__ import annotations

import json
import threading
import traceback
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import ai, collect, config, report as rpt, rules

WEB = config.PACKAGE_DIR / "web"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


class State:
    def __init__(self, model: str | None, demo: bool = False):
        self.lock = threading.RLock()
        self.client = ai.Ollama(model)
        self.model_ready = bool(self.client.pick_model())
        self.demo = demo
        self.report = rpt.load()
        if self.report is not None and demo:
            self._add_planted(self.report)
        self.job = {"running": False, "done": 0, "total": 0, "current": "", "error": None}
        self.story = (self.report or {}).get("story")
        self.seances: dict[str, dict] = {}

    def _add_planted(self, report: dict) -> None:
        """Demo mode: mix the evaluation's planted ghosts into the real report, clearly marked."""
        path = config.PROJECT_DIR / "eval" / "planted.json"
        try:
            planted = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for p in planted:
            e = rules.analyze(dict(p["entry"]))
            e["planted"] = True
            e["explanation"] = ai.explain_cache().get(ai.cache_key(e, self.client.model))
            e["verdict"], e["verdict_reason"] = rules.decide(e, e["explanation"])
            report["entries"].append(e)
        report["summary"] = rpt.summarize(report)

    def current(self) -> dict:
        with self.lock:
            if self.report is None:
                self.report = rpt.build(collect.scan(), self.client.model)
                rpt.save(self.report)
                if self.demo:
                    self._add_planted(self.report)
            return self.report

    def rescan(self) -> dict:
        fresh = rpt.build(collect.scan(), self.client.model)
        with self.lock:
            fresh["story"] = None
            rpt.save(fresh)
            if self.demo:
                self._add_planted(fresh)
            self.report, self.story = fresh, None
            self.seances = {}
        return fresh

    def find(self, entry_id: str) -> dict | None:
        return next((e for e in self.current()["entries"] if e["id"] == entry_id), None)

    def start_explain_all(self) -> None:
        with self.lock:
            if self.job["running"]:
                return
            self.job = {"running": True, "done": 0, "total": 0, "current": "", "error": None}
        threading.Thread(target=self._explain_all, daemon=True).start()

    def _explain_all(self) -> None:
        def progress(i, n, e):
            self.job.update(done=i, total=n, current=e.get("display_name") or e.get("name"))

        try:
            report = self.current()
            rpt.explain_all(report, self.client, progress)
            with self.lock:
                rpt.save(report)
        except Exception as exc:  # surfaced in the UI
            self.job["error"] = str(exc)
        finally:
            self.job["running"] = False


def make_handler(state: State):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Uninvited"

        def log_message(self, fmt, *args):  # keep the console quiet
            pass

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            return host in ALLOWED_HOSTS

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, code: int = 200) -> None:
            self._send(code, json.dumps(data, default=str).encode("utf-8"), "application/json")

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                return json.loads(raw or b"{}")
            except ValueError:
                return {}

        def _payload(self) -> dict:
            r = state.current()
            data = rpt.to_public(r)
            data["job"] = state.job
            data["story"] = state.story
            data["ai"] = {"model": state.client.model, "ready": state.model_ready}
            data["web_lookup"] = bool(config.serpapi_key())
            data["night_watch"] = _latest_night()
            return data

        def do_GET(self):
            if not self._host_ok():
                return self._json({"error": "forbidden host"}, 403)
            path = urlparse(self.path).path
            if path in STATIC:
                name, ctype = STATIC[path]
                return self._send(200, (WEB / name).read_bytes(), ctype)
            if path == "/api/report":
                return self._json(self._payload())
            if path == "/api/job":
                return self._json(state.job)
            return self._json({"error": "not found"}, 404)

        def do_POST(self):
            if not self._host_ok():
                return self._json({"error": "forbidden host"}, 403)
            # Exact type check: "text/plain;x=application/json" is CORS-safelisted and must not pass.
            if self.headers.get_content_type() != "application/json":
                return self._json({"error": "JSON only"}, 415)
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).hostname not in ALLOWED_HOSTS:
                return self._json({"error": "cross-origin request refused"}, 403)
            path = urlparse(self.path).path
            body = self._body()
            try:
                if path == "/api/scan":
                    state.rescan()
                    return self._json(self._payload())
                if path == "/api/explain":
                    entry = state.find(body.get("id", ""))
                    if not entry:
                        return self._json({"error": "unknown id"}, 404)
                    with state.lock:
                        rpt.explain_entry(state.current(), entry, state.client)
                        rpt.save(state.current())
                    return self._json(rpt._display(entry))
                if path == "/api/explain-all":
                    state.start_explain_all()
                    return self._json(state.job)
                if path == "/api/story":
                    story = ai.narrate_wakes(state.current()["wakes"], state.client)
                    with state.lock:
                        state.story = story
                        state.current()["story"] = story
                        rpt.save(state.current())
                    return self._json(story)
                if path == "/api/lookup":
                    from . import lookup

                    entry = state.find(body.get("id", ""))
                    if not entry:
                        return self._json({"error": "unknown id"}, 404)
                    result = lookup.web_lookup(entry, state.client)
                    with state.lock:
                        entry["lookup"] = result
                        rpt.save(state.current())
                    return self._json(rpt._display(entry))
                if path == "/api/seance":
                    question = (body.get("question") or "").strip()[:300]
                    if not question:
                        return self._json({"error": "ask something"}, 400)
                    key = question.lower()
                    if key not in state.seances:
                        r = state.current()
                        state.seances[key] = ai.seance(question, r["entries"], r["wakes"], state.client)
                    return self._json(state.seances[key])
            except ai.ModelError as exc:
                return self._json({"error": str(exc)}, 503)
            except Exception as exc:
                traceback.print_exc()
                return self._json({"error": str(exc)}, 500)
            return self._json({"error": "not found"}, 404)

    return Handler


def _latest_night() -> dict | None:
    path = config.home() / "night" / "latest.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def serve(port: int = 8666, open_browser: bool = True, model: str | None = None, demo: bool = False) -> None:
    state = State(model, demo)
    if state.report is None:
        print("First run: scanning (read-only), about 20 seconds...")
        state.current()
    if demo:
        print("Demo mode: the evaluation's planted ghosts are mixed in and marked 'planted for the demo'.")
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    url = f"http://127.0.0.1:{port}/"
    print(f"Uninvited is listening on {url} (this computer only). Ctrl+C to stop.")
    if not state.model_ready:
        print("Note: no Gemma model found in Ollama, so explanations are off. Run: ollama pull gemma4:e4b")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
