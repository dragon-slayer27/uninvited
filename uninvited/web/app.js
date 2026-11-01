"use strict";
// All entry data is inserted with textContent (never innerHTML): startup items are untrusted input.

const $ = (s) => document.querySelector(s);
const VERDICTS = {
  investigate: { ghost: "Poltergeist", action: "Investigate", color: "#ff5c7a" },
  lay_to_rest: { ghost: "Zombie", action: "Lay it to rest", color: "#c49bff" },
  unknown: { ghost: "Unknown spirit", action: "Look it up", color: "#ffd166" },
  unexplained: { ghost: "Unexamined", action: "Ask Gemma", color: "#8a8796" },
  optional: { ghost: "Uninvited guest", action: "Your call", color: "#ff9f1c" },
  keep: { ghost: "Friendly ghost", action: "Keep", color: "#5be49b" },
  dormant: { ghost: "Sleeping", action: "Already off", color: "#6f7a99" },
  windows: { ghost: "House spirit", action: "Part of Windows", color: "#5b5867" },
};
const ORDER = ["investigate", "lay_to_rest", "unknown", "unexplained", "optional", "keep", "dormant", "windows"];
const KIND = { run: "Registry · at sign-in", runonce: "Registry · once", startup: "Startup folder", task: "Scheduled task", service: "Service" };
const CLASS_COLORS = { you: "#7fe3d1", charger: "#9aa5ff", windows: "#ff9f1c", unknown: "#ff5c7a" };
const CATEGORY = {
  "updater": "an updater", "security": "security software", "driver-helper": "a hardware helper",
  "vendor-utility": "a laptop-maker extra", "cloud-sync": "cloud sync", "chat-social": "a chat app", "browser": "a browser helper",
  "dev-tool": "a developer tool", "vpn-network": "a VPN or network tool", "exam-proctoring": "exam software",
  "game-launcher": "a game launcher", "media": "a media app", "productivity": "an office app helper",
  "windows-component": "part of Windows", "unknown": "unknown",
};
const EXAMPLES = [
  "Why does my laptop wake up at night?",
  "What could I turn off so it starts faster?",
  "Which of these use the most memory right now?",
  "Is anything here suspicious?",
];

const state = { report: null, filter: "guests", q: "", open: new Set() };

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add("hidden"), 4000);
}

function busy(button, label) {
  button.disabled = true;
  button.replaceChildren(h("span", { class: "spin" }), label);
}

async function load() {
  state.report = await api("/api/report");
  render();
  if (state.report.job && state.report.job.running) pollJob();
}

function render() {
  const r = state.report;
  renderHeader(r);
  renderHero(r);
  renderStory(r);
  renderChart(r.wakes);
  renderReasons(r.wakes);
  renderTips(r.wakes);
  renderFilters(r);
  renderCards(r);
  renderTombs(r);
  renderWatch(r);
}

// ------------------------------------------------------------------ header + hero
function renderHeader(r) {
  const chip = $("#model-chip");
  if (r.ai.ready) {
    chip.className = "chip ok";
    chip.textContent = `🧠 ${r.ai.model} · on this laptop`;
  } else {
    chip.className = "chip warn";
    chip.textContent = "No local model found (ollama pull gemma4:e4b)";
  }
  $("#foot-model").textContent = r.ai.ready
    ? `Explanations by ${r.ai.model} through Ollama on this laptop. Nothing leaves it unless you press “Ask the web”.`
    : "Install Ollama and a Gemma 4 model to get explanations. The scan itself needs no AI.";
  $("#explain-all").disabled = !r.ai.ready;
  if (r.signatures_ok === false && !$("#sig-chip")) {
    $(".chips").prepend(h("span", { id: "sig-chip", class: "chip warn", title: "Windows could not verify its own files' signatures, so Uninvited trusts the Windows folder and skips signature checks" }, "⚠ signatures unavailable"));
  }
}

function stat(cls, value, unit, label, sub) {
  return h("div", { class: `stat ${cls}` },
    h("div", { class: "k" }, value ?? "–", unit ? h("small", {}, ` ${unit}`) : null),
    h("div", { class: "l" }, label),
    h("div", { class: "s" }, sub));
}

function renderHero(r) {
  const w = r.wakes;
  const s = r.summary;
  const nights = (w.austerity_nights || []).length;
  const days = Math.round(w.window_days || 0);
  const guests = stat("purple", s.guests, "", "things start without asking", `${s.zombies} zombies · ${s.poltergeists} poltergeists · ${s.optional} optional`);
  if (w.mode === "classic-sleep" || w.mode === "none") {
    $("#hero").replaceChildren(
      stat("orange", w.exits, "", `times woken from sleep in ${days} days`, `${w.not_you} weren't you`),
      stat("teal", w.night_exits, "", "wakes between midnight and 6 AM", `${w.night_not_you} weren't you`),
      stat("red", w.timer_wakes || 0, "", "wakes asked for by scheduled tasks", "wake timers"),
      guests);
    return;
  }
  $("#hero").replaceChildren(
    stat("orange", w.exits, "", `times out of standby in ${days} days`, `${w.not_you} weren't you · ${w.night_exits} between midnight and 6 AM`),
    stat("teal", w.awake_hours, "h", "awake while 'asleep'", `out of ${w.standby_hours} h in standby · deep sleep ${w.deep_sleep_pct ?? "?"}% of the time`),
    stat("red", w.austerity_count, "", "times Windows had to step in", `standby used more battery than allowed · on ${nights} night${nights === 1 ? "" : "s"}`),
    guests,
  );
}

// ------------------------------------------------------------------ wakes
function renderStory(r) {
  const el = $("#story");
  const st = r.story;
  const btn = h("button", { class: "btn small", onclick: writeStory }, st ? "Write it again" : "Write the night report");
  btn.disabled = !r.ai.ready;
  if (!st) {
    el.replaceChildren(h("h3", {}, "The night report"),
      h("p", { class: "body muted" }, "Gemma turns the measurements into a short story. Every number it writes is checked against the event log; if one doesn't match, the story is rejected."),
      btn);
    return;
  }
  const checked = st.source === "template"
    ? "Gemma's numbers failed the check · plain template shown"
    : "✓ every number checked against the log";
  el.replaceChildren(h("h3", {}, "The night report"),
    h("p", { class: "headline" }, st.headline),
    h("p", { class: "body" }, st.story),
    h("div", {}, h("span", { class: "badge-check" }, checked), h("span", { class: "muted small" }, `written by ${st.source} `), btn));
}

async function writeStory(ev) {
  busy(ev.currentTarget, "Gemma is writing…");
  try {
    state.report.story = await api("/api/story", {});
  } catch (e) {
    toast(e.message);
  }
  renderStory(state.report);
}

function renderChart(w) {
  const NS = "http://www.w3.org/2000/svg";
  const W = 720, H = 190, pad = 20, bw = (W - pad * 2) / 24;
  const classes = ["you", "charger", "windows", "unknown"];
  const totals = Array.from({ length: 24 }, (_, i) => classes.reduce((a, c) => a + ((w.hist[c] || [])[i] || 0), 0));
  const max = Math.max(1, ...totals);
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const add = (tag, attrs, text) => {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    if (text) e.textContent = text;
    svg.append(e);
    return e;
  };
  add("rect", { x: pad, y: 4, width: bw * 6, height: H - 30, fill: "rgba(154,165,255,0.08)", rx: 6 });
  add("text", { x: pad + 8, y: 20, fill: "#9b97a8", "font-size": 11 }, "midnight to 6 AM");
  for (let i = 0; i < 24; i++) {
    let y = H - 26;
    for (const c of classes) {
      const n = (w.hist[c] || [])[i] || 0;
      if (!n) continue;
      const hgt = (n / max) * (H - 54);
      y -= hgt;
      const bar = add("rect", { x: pad + i * bw + 2, y, width: bw - 4, height: Math.max(hgt, 1), fill: CLASS_COLORS[c], rx: 2 });
      const tip = document.createElementNS(NS, "title");
      tip.textContent = `${String(i).padStart(2, "0")}:00 · ${n} × ${w.class_text[c]}`;
      bar.append(tip);
    }
    if (i % 3 === 0) add("text", { x: pad + i * bw + bw / 2, y: H - 8, fill: "#9b97a8", "font-size": 11, "text-anchor": "middle" }, `${String(i).padStart(2, "0")}:00`);
  }
  $("#chart").replaceChildren(svg);
  $("#legend").replaceChildren(...classes.map((c) =>
    h("span", {}, h("i", { style: `background:${CLASS_COLORS[c]}` }), `${w.class_text[c]} (${w.by_class[c] || 0})`)));
}

function classOf(reason) {
  const t = reason.toLowerCase();
  if (/^\d+$/.test(t) || t === "unknown") return "unknown";
  if (t.startsWith("timer")) return "windows";
  if (t.startsWith("input") || t === "lid" || t === "power button" || /keyboard|mouse|touchpad|hid/.test(t)) return "you";
  if (t.includes("ac/dc")) return "charger";
  return "windows";
}

function renderReasons(w) {
  // Sort explicitly: JS puts integer-like keys such as "16777220" first in object order.
  const rows = Object.entries(w.reasons || {}).sort((a, b) => b[1] - a[1]).map(([reason, n]) => {
    const note = w.reason_notes[reason] || (/^\d+$/.test(reason) ? "A reason code Windows logs but nobody has documented." : "");
    return h("tr", {},
      h("td", { class: "n" }, n),
      h("td", {}, h("span", { class: "dot", style: `background:${CLASS_COLORS[classOf(reason)]}` }), reason, h("div", { class: "why" }, note)));
  });
  $("#reasons").replaceChildren(...rows);
}

function renderTips(w) {
  const tips = (w.tips || []).map((t) => h("div", { class: "tip" }, h("b", {}, t.title), h("span", {}, t.text)));
  $("#tips").replaceChildren(...(tips.length ? tips : [h("p", { class: "muted" }, "Nothing unusual. Sleep well.")]));
  const armed = (w.wake_armed || []).join(", ") || "none";
  const timers = w.wake_timers || {};
  const t = (v) => (v === 0 ? "blocked" : v === 1 ? "allowed" : v === 2 ? "important only" : "unknown");
  $("#armed").textContent = `Devices allowed to wake this laptop: ${armed}. Wake timers: ${t(timers.ac)} on the charger, ${t(timers.dc)} on battery.`;
}

// ------------------------------------------------------------------ guests
function visible(r) {
  const q = state.q.toLowerCase();
  return r.entries
    .filter((e) => {
      if (state.filter === "guests") return !["windows", "dormant"].includes(e.verdict);
      if (state.filter === "all") return true;
      return e.verdict === state.filter;
    })
    .filter((e) => !q || [e.name, e.publisher, e.file_name, (e.explanation || {}).product, (e.explanation || {}).what_it_does]
      .some((x) => (x || "").toLowerCase().includes(q)))
    .sort((a, b) => ORDER.indexOf(a.verdict) - ORDER.indexOf(b.verdict) || a.name.localeCompare(b.name));
}

function renderFilters(r) {
  const counts = {};
  for (const e of r.entries) counts[e.verdict] = (counts[e.verdict] || 0) + 1;
  const guests = r.entries.filter((e) => !["windows", "dormant"].includes(e.verdict)).length;
  const items = [["guests", "Starting on their own", guests]].concat(
    ORDER.filter((v) => counts[v]).map((v) => [v, VERDICTS[v].ghost, counts[v]]));
  $("#filters").replaceChildren(...items.map(([key, label, n]) =>
    h("button", { class: `filter ${state.filter === key ? "on" : ""}`, onclick: () => { state.filter = key; renderFilters(r); renderCards(r); } }, label, h("b", {}, n))));
}

function signatureText(e) {
  if (!e.file_exists) return e.target ? "the file is gone" : "no file (Windows component)";
  if (e.signature === "Valid") return e.hardware ? `valid · driver package for ${e.publisher}` : `valid · ${e.publisher}`;
  return e.signature === "NotSigned" ? "not signed" : `${e.signature}`;
}

function renderCards(r) {
  const list = visible(r);
  $("#cards").replaceChildren(...(list.length ? list.map(card) : [h("p", { class: "empty" }, "Nothing here.")]));
}

function card(e) {
  const v = VERDICTS[e.verdict] || VERDICTS.unknown;
  const ex = e.explanation || {};
  const who = [ex.product, e.publisher].filter(Boolean).filter((x, i, a) => a.indexOf(x) === i).join(" · ") || e.file_name;
  const flags = (e.flags || []).filter((f) => f.severity !== "low" || f.id === "wakes-pc");
  return h("article", { class: "entry", id: `card-${e.id}`, style: `--v:${v.color}` },
    h("div", { class: "row" },
      h("div", { class: "verdict" }, v.ghost, " ", h("span", {}, `· ${v.action}`)),
      h("span", { class: "kind" }, KIND[e.kind] || e.kind)),
    e.planted ? h("div", { class: "planted" }, "🧪 Planted for the demo: not on this laptop") : null,
    h("h4", {}, e.name),
    h("div", { class: "who" }, who),
    ex.what_it_does ? h("p", { class: "what" }, ex.what_it_does)
      : e.description ? h("p", { class: "what muted" }, e.description) : null,
    h("div", { class: "meta" },
      h("div", {}, h("b", {}, "Starts: "), e.trigger || "?"),
      ex.if_disabled ? h("div", {}, h("b", {}, "If you turn it off: "), ex.if_disabled) : null,
      h("div", {}, h("b", {}, "Signature: "), signatureText(e)),
      e.running ? h("div", { class: "mem" }, `Running now · ${Math.round(e.running.mb)} MB of memory`) : null),
    ...flags.map((f) => h("div", { class: `flag ${f.severity}` }, f.text)),
    e.decoded ? h("div", { class: "decoded" }, `Decoded script:\n${e.decoded}`) : null,
    h("div", { class: "reason" }, h("b", {}, "Why this verdict: "), e.verdict_reason,
      h("em", {}, ex.category
        ? `Decided by rules. Gemma only said it is ${CATEGORY[ex.category] || ex.category} (${ex.confidence} confidence).`
        : "Decided by rules, from facts Windows reports.")),
    lookupBlock(e),
    actions(e));
}

function lookupBlock(e) {
  const l = e.lookup;
  if (!l) return null;
  if (l.error) return h("div", { class: "lookup" }, `Web lookup failed: ${l.error}`);
  const g = l.explanation || {};
  const after = l.verdict && VERDICTS[l.verdict] ? `${VERDICTS[l.verdict].ghost} · ${VERDICTS[l.verdict].action}` : null;
  return h("div", { class: "lookup" },
    h("div", {}, h("b", {}, "From the web: "), g.what_it_does && g.what_it_does !== "unknown" ? g.what_it_does : "No clear answer."),
    h("div", { class: "muted small" }, g.grounded ? `Grounded in results ${g.citations.join(", ")}` : "Not grounded: the model could not cite the results"),
    after ? h("div", { class: "small" }, h("b", {}, "With the web's answer, the rules say: "), after) : null,
    h("ol", {}, ...(l.results || []).map((x) => h("li", {}, h("a", { href: x.link, target: "_blank", rel: "noopener noreferrer" }, x.title)))),
    h("div", {}, "Only this left your laptop: ", h("span", { class: "sent" }, l.query_sent)));
}

function actions(e) {
  const r = state.report;
  const row = h("div", { class: "actions" });
  const wrap = h("div", { class: "actions-wrap" }, row);
  if (!e.explanation && !e.is_windows && r.ai.ready) {
    row.append(h("button", { class: "btn small", onclick: (ev) => explainOne(e.id, ev.currentTarget) }, "Ask Gemma"));
  }
  if (["unknown", "unexplained"].includes(e.verdict) && r.web_lookup && !e.lookup) {
    row.append(h("button", { class: "btn small quiet", onclick: (ev) => lookupOne(e, ev.currentTarget) }, "Ask the web"));
  } else if (r.web_lookup && !e.lookup && !e.is_windows && e.explanation) {
    row.append(h("button", { class: "btn small link", onclick: (ev) => lookupOne(e, ev.currentTarget) }, "Double-check on the web"));
  }
  // Panels live below the link row, full width, so long commands can never push past the card.
  const c = e.commands || {};
  if (c.off) {
    const box = h("div", { class: "cmds" },
      h("p", { class: "cmd-how" }, c.how, c.admin ? h("span", { class: "admin" }, "run as administrator") : null),
      cmdBlock("Turn off", c.off), cmdBlock("Undo", c.undo));
    row.append(toggle("How to turn it off", box, `cmd-${e.id}`));
    wrap.append(box);
  }
  const det = h("div", { class: "details" },
    h("div", {}, h("b", {}, "Command: "), e.command || "?"),
    h("div", {}, h("b", {}, "Where: "), e.location || "?"),
    e.description ? h("div", {}, h("b", {}, "Windows says: "), e.description) : null,
    (ex => ex && ex.notes && ex.notes.length ? h("div", {}, h("b", {}, "Guard notes: "), ex.notes.join("; ")) : null)(e.explanation));
  row.append(toggle("Details", det, `det-${e.id}`));
  wrap.append(det);
  return wrap;
}

function toggle(label, panel, key) {
  const open = state.open.has(key);
  panel.classList.toggle("hidden", !open);
  const btn = h("button", { class: "btn small link", "aria-expanded": String(open) }, label);
  btn.addEventListener("click", () => {
    const nowOpen = !panel.classList.toggle("hidden");
    btn.setAttribute("aria-expanded", String(nowOpen));
    if (nowOpen) state.open.add(key); else state.open.delete(key);
  });
  return btn;
}

function cmdBlock(label, text) {
  const copy = h("button", {
    class: "btn small quiet",
    onclick: () => navigator.clipboard.writeText(text).then(() => toast("Copied"), () => toast("Copy failed: select the text instead")),
  }, "Copy");
  return h("div", { class: "cmd" },
    h("div", { class: "cmd-head" }, h("span", { class: "lbl" }, label), copy),
    h("pre", { class: "cmd-code" }, text));
}

function replaceEntry(updated) {
  const list = state.report.entries;
  const i = list.findIndex((x) => x.id === updated.id);
  if (i >= 0) list[i] = updated;
}

async function explainOne(id, button) {
  busy(button, "Gemma is thinking…");
  try {
    replaceEntry(await api("/api/explain", { id }));
    state.report = await api("/api/report");
    render();
  } catch (e) {
    toast(e.message);
    button.disabled = false;
    button.textContent = "Ask Gemma";
  }
}

async function lookupOne(e, button) {
  if (!confirm(`Search the web for this item?\n\nExactly this text leaves your laptop (through SerpApi):\n${e.lookup_query}\n\nNo paths, usernames or other entries are sent.`)) return;
  busy(button, "Searching…");
  try {
    replaceEntry(await api("/api/lookup", { id: e.id }));
    renderCards(state.report);
  } catch (err) {
    toast(err.message);
    button.disabled = false;
    button.textContent = "Ask the web";
  }
}

async function pollJob() {
  const box = $("#progress");
  box.classList.remove("hidden");
  const btn = $("#explain-all");
  btn.disabled = true;
  for (;;) {
    const job = await api("/api/job");
    const pct = job.total ? Math.round((job.done / job.total) * 100) : 0;
    box.querySelector(".bar span").style.width = `${pct}%`;
    box.querySelector("p").textContent = job.running
      ? `Gemma is examining ${job.done + 1} of ${job.total || "?"}: ${job.current || "…"}`
      : job.error ? `Stopped: ${job.error}` : `Done: ${job.done} examined.`;
    if (!job.running) break;
    await new Promise((r) => setTimeout(r, 1500));
    if (job.done % 3 === 0) { state.report = await api("/api/report"); renderCards(state.report); renderFilters(state.report); }
  }
  btn.disabled = false;
  state.report = await api("/api/report");
  render();
  setTimeout(() => box.classList.add("hidden"), 3000);
}

// ------------------------------------------------------------------ graveyard / seance / watch
function renderTombs(r) {
  const zombies = r.entries.filter((e) => e.verdict === "lay_to_rest");
  const windowsGhosts = r.entries.filter((e) => e.is_windows && e.target && !e.file_exists);
  const tombs = zombies.map((e) => h("div", { class: "tomb" },
    h("div", { class: "rip" }, "R.I.P."),
    h("h4", {}, e.name),
    h("p", {}, `It still tries to start ${e.file_name || "a program"} ${e.trigger}. That file is gone.`),
    e.planted ? h("div", { class: "planted" }, "🧪 planted for the demo") : null));
  const note = windowsGhosts.length
    ? h("p", { class: "muted" }, `Even Windows keeps ${windowsGhosts.length} of its own: ${windowsGhosts.map((e) => e.name).join(", ")}. Those are Microsoft's to bury.`)
    : null;
  $("#tombs").replaceChildren(...(tombs.length ? tombs : [h("p", { class: "empty" }, "No zombies on this laptop. Somebody uninstalled things properly.")]), ...(note ? [note] : []));
}

function renderExamples() {
  $("#examples").replaceChildren(...EXAMPLES.map((q) => h("button", { type: "button", onclick: () => { $("#question").value = q; ask(); } }, q)));
}

async function ask(ev) {
  if (ev) ev.preventDefault();
  const q = $("#question").value.trim();
  if (!q) return;
  const box = $("#answer");
  box.classList.remove("hidden");
  box.replaceChildren(h("span", { class: "spin" }), "The medium is listening…");
  try {
    const a = await api("/api/seance", { question: q });
    const cites = (a.cited_ids || []).map((id) => {
      if (id === "WAKES") return h("button", { class: "cite", onclick: () => $("#wakers").scrollIntoView({ behavior: "smooth" }) }, "Wake log");
      const e = state.report.entries.find((x) => x.id === id);
      return h("button", { class: "cite", onclick: () => jump(id) }, e ? e.name : id);
    });
    const warn = (a.unverified_numbers || []).length || (a.invented_ids || []).length
      ? h("div", { class: "flag medium" }, `Unverified in this answer: ${[...(a.unverified_numbers || []), ...(a.invented_ids || [])].join(", ")}`)
      : null;
    box.replaceChildren(...[h("p", {}, a.answer), warn, h("div", {}, ...cites)].filter(Boolean));
  } catch (e) {
    box.replaceChildren(h("p", { class: "muted" }, e.message));
  }
}

function jump(id) {
  state.filter = "all";
  state.q = "";
  $("#search").value = "";
  renderFilters(state.report);
  renderCards(state.report);
  const el = document.getElementById(`card-${id}`);
  if (el) {
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.add("highlight");
    setTimeout(() => el.classList.remove("highlight"), 2500);
  }
}

function renderWatch(r) {
  const n = r.night_watch;
  const el = $("#watch");
  if (!n) {
    el.replaceChildren(
      h("p", {}, "Night Watch is not running. Start it before you close the lid:"),
      h("div", { class: "cmd" }, h("code", {}, "python -m uninvited watch")),
      h("p", { class: "muted small" }, "It runs as a Temporal workflow: every few minutes it reads new standby events and new startup items, asks Gemma about anything new, and survives sleep, reboots and Ollama crashes."));
    return;
  }
  el.replaceChildren(...[
    h("p", {}, h("b", {}, n.headline || "Night Watch report")),
    h("p", { class: "muted" }, `Watching since ${n.started || "?"} · last check ${n.last_check || "?"} · ${n.checks || 0} checks · workflow ${n.workflow_id || ""}`),
    n.story ? h("p", {}, n.story) : null,
    ...(n.new_entries || []).map((x) => h("div", { class: "flag medium" }, `New since the watch began: ${x.name} (${x.product || x.publisher || "unknown"}, ${VERDICTS[x.verdict] ? VERDICTS[x.verdict].ghost.toLowerCase() : x.verdict})`)),
    h("p", { class: "muted small" }, `Standby exits seen during the watch: ${n.exits || 0} (${n.not_you || 0} not you).`),
  ].filter(Boolean));
}

// ------------------------------------------------------------------ wiring
$("#search").addEventListener("input", (e) => { state.q = e.target.value; renderCards(state.report); });
$("#seance-form").addEventListener("submit", ask);
$("#explain-all").addEventListener("click", async () => { await api("/api/explain-all", {}); pollJob(); });
$("#rescan").addEventListener("click", async (ev) => {
  const b = ev.currentTarget;
  busy(b, "Scanning…");
  try { state.report = await api("/api/scan", {}); render(); toast("Fresh scan done"); } catch (e) { toast(e.message); }
  b.disabled = false;
  b.textContent = "Rescan";
});
renderExamples();
load().catch((e) => toast(e.message));
