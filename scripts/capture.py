"""Capture README/post screenshots and a captioned demo video with headless Microsoft Edge.

    python scripts/capture.py --shots     # needs `uninvited serve` on :8666 and `uninvited serve --demo` on :8667
    python scripts/capture.py --video

Dev-only helper (pip install playwright); uses the Edge that ships with Windows, no browser download.
"""

from __future__ import annotations

import argparse
import json
import shutil
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "docs" / "img"
REAL = "http://127.0.0.1:8666/"
DEMO = "http://127.0.0.1:8667/"
TEMPORAL = "http://127.0.0.1:8233/namespaces/default/workflows/uninvited-night-watch"
NO_STICKY = ".top{position:static !important} .fog{display:none}"
QUESTION = "Why does my laptop wake up at night?"


def post(base: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(body or {}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())


def ready(page: Page, url: str) -> None:
    page.goto(url)
    page.wait_for_selector(".entry", timeout=60000)
    page.add_style_tag(content=NO_STICKY)
    page.wait_for_timeout(600)


def shots(browser) -> None:
    IMG.mkdir(parents=True, exist_ok=True)
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
    page = ctx.new_page()

    ready(page, REAL)
    page.screenshot(path=str(IMG / "dashboard.png"))
    page.locator("#hero").screenshot(path=str(IMG / "hero.png"))
    page.locator("#wakers").screenshot(path=str(IMG / "night-wakers.png"))

    page.fill("#question", QUESTION)
    page.click("#seance-form button")
    page.wait_for_selector("#answer p", timeout=300000)
    page.wait_for_timeout(400)
    page.locator("#seance").screenshot(path=str(IMG / "seance.png"))

    page.fill("#search", "mysql")
    page.wait_for_timeout(300)
    page.locator(".entry").first.locator("text=How to turn it off").click()
    page.locator(".entry").first.screenshot(path=str(IMG / "card-mysql.png"))
    page.fill("#search", "")

    page.click("text=Uninvited guest")
    page.wait_for_timeout(300)
    box = page.locator("#cards").bounding_box()
    page.screenshot(path=str(IMG / "guests.png"), full_page=True,
                    clip={"x": box["x"] - 10, "y": box["y"] - 70, "width": box["width"] + 20, "height": 900})

    ready(page, DEMO)
    page.click("text=Poltergeist")
    page.wait_for_timeout(300)
    page.locator(".entry", has_text="OneDriveUpdate").screenshot(path=str(IMG / "card-poltergeist.png"))
    page.locator("#graveyard").screenshot(path=str(IMG / "graveyard.png"))
    ctx.close()


def caption(page: Page, text: str, wait: float = 3.5) -> None:
    page.evaluate("""(t) => {
        let c = document.getElementById('cap');
        if (!c) { c = document.createElement('div'); c.id = 'cap';
          c.style.cssText = 'position:fixed;left:50%;bottom:28px;transform:translateX(-50%);max-width:1100px;'
            + 'background:rgba(10,10,16,.92);color:#fff;border:1px solid #ff9f1c;border-radius:12px;'
            + 'padding:14px 22px;font:600 22px system-ui;z-index:99;text-align:center;box-shadow:0 8px 30px #000';
          document.body.appendChild(c); }
        c.textContent = t; }""", text)
    page.wait_for_timeout(int(wait * 1000))


def scroll_to(page: Page, selector: str) -> None:
    page.evaluate("(s) => document.querySelector(s).scrollIntoView({behavior: 'smooth', block: 'start'})", selector)
    page.wait_for_timeout(1200)


def video(browser) -> None:
    out = ROOT / "docs" / "video"
    out.mkdir(parents=True, exist_ok=True)
    post(REAL, "/api/seance", {"question": QUESTION})  # warm the answer so the video doesn't wait on the model
    ctx = browser.new_context(viewport={"width": 1280, "height": 720}, record_video_dir=str(out),
                              record_video_size={"width": 1280, "height": 720})
    page = ctx.new_page()
    ready(page, REAL)
    caption(page, "Uninvited: what's haunting this laptop? Read-only, and the AI runs on the laptop.", 4)
    scroll_to(page, "#hero")
    caption(page, "My laptop left standby 233 times in 9 days. 72 of those weren't me.", 4)
    caption(page, "It spent 156 h 'asleep', but was really awake for 17 of them. Windows stepped in 46 times.", 4.5)
    scroll_to(page, "#wakers")
    caption(page, "Every exit, by hour. Orange is Windows itself. Red is a reason code nobody documented.", 4.5)
    scroll_to(page, "#reasons")
    caption(page, "Reasons come from the event fields, so this works in any Windows language.", 4)
    scroll_to(page, "#guests")
    caption(page, "58 things start without asking. Gemma explains each one. Plain rules decide.", 4)
    page.click("text=Uninvited guest")
    page.wait_for_timeout(800)
    page.mouse.wheel(0, 500)
    caption(page, "A MySQL server, an exam browser's service, ASUS screen-sharing... all optional.", 4)
    page.fill("#search", "mysql")
    page.wait_for_timeout(500)
    page.locator(".entry").first.locator("text=How to turn it off").click()
    caption(page, "It never changes your system. It gives you the command, and the undo.", 4.5)
    page.fill("#search", "")
    ready(page, DEMO)
    page.click("text=Poltergeist")
    page.wait_for_timeout(500)
    page.locator(".entry", has_text="OneDriveUpdate").scroll_into_view_if_needed()
    caption(page, "Planted for the demo: a hidden PowerShell downloader posing as OneDrive.", 4.5)
    caption(page, "The rules catch and decode it. Asked alone, Gemma said 'keep'.", 4.5)
    scroll_to(page, "#graveyard")
    caption(page, "Zombies: startup entries whose program is gone.", 3.5)
    ready(page, REAL)
    scroll_to(page, "#seance")
    page.fill("#question", QUESTION)
    page.click("#seance-form button")
    page.wait_for_selector("#answer p", timeout=300000)
    caption(page, "Séance: ask your laptop. Answers cite the entries they use; numbers are checked.", 5)
    page.goto(TEMPORAL)
    page.wait_for_timeout(2500)
    caption(page, "Night Watch runs on Temporal. With the model down, it retried 8 times, then recovered.", 5)
    caption(page, "Gemma 4 E4B on an Intel Arc iGPU, via Ollama. Nothing left this laptop.", 4)
    path = page.video.path()
    ctx.close()
    final = out / "uninvited-demo.webm"
    shutil.move(path, final)
    print(f"video: {final}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--shots", action="store_true")
    p.add_argument("--video", action="store_true")
    args = p.parse_args()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="msedge", headless=True)
        if args.shots:
            shots(browser)
        if args.video:
            video(browser)
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
