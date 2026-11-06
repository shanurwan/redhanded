// Everything a package controlled (commands, hostnames, request bodies) is
// inserted with textContent, never as HTML. Attacker hostnames are never links.
"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
};
const decode = (b64) => {
  try {
    const s = new TextDecoder().decode(Uint8Array.from(atob(b64 || ""), (c) => c.charCodeAt(0)));
    return s.length > 180 ? `${s.slice(0, 180)}…` : s;
  } catch { return ""; }
};
const reduceMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
const TOKEN_NAMES = { aws_access_key_id: "AWS access key", aws_secret_access_key: "AWS secret key", github_token: "GitHub token", npm_token: "npm token",
  ssh_private_key: "SSH key", wallet_private_key: "wallet key", metadata_access_key_id: "cloud metadata key", metadata_secret: "cloud metadata secret" };
const isHarness = (argv) => { const s = argv.join(" "); return s.includes("/work/.rh/") || (/(^| )npm( |$)|\/usr\/local\/bin\/npm/.test(s) && argv.includes("rebuild")); };

// ---------------------------------------------------------------- the attack, told from its own evidence

function story(view) {
  const r = view.report, out = [{ tag: "PLANT", h: "Fake credentials planted", d: "AWS, GitHub and npm, made for this scan only" }];
  const evs = [r.evidence || {}, (r.microvm && r.microvm.evidence) || {}];
  const all = (k) => [...new Set(evs.flatMap((e) => e[k] || []))];
  const cmd = (evs[0].execs || []).filter(([a]) => !isHarness(a)).map(([a]) => a).find((a) => a.join(" ").length > 3);
  out.push({ tag: "RUN", h: "Install script ran", d: cmd ? cmd.join(" ").slice(0, 110) : `npm install ${r.package}@${r.version}` });
  for (const p of all("bait_reads").slice(0, 2)) out.push({ tag: "READ", bad: true, h: "Read a bait credential", d: p });
  for (const s of all("token_uses")) out.push({ tag: "USED", bad: true, h: `Used the stolen ${s} token`, d: `sent to the fake ${s} API, which has no route out` });
  const stolen = all("exfil_matches");
  if (stolen.length) out.push({ tag: "STOLE", bad: true, h: `${stolen.length === 1 ? "A fake credential" : `${stolen.length} fake credentials`} left the sandbox`, d: stolen.slice(0, 3).map((t) => TOKEN_NAMES[t] || t).join(", ") });
  if (!stolen.length && !all("token_uses").length) {
    for (const w of all("writes").slice(0, 2)) out.push({ tag: "WROTE", bad: true, h: "Wrote outside its own folder", d: w });
    for (const c of all("connects").slice(0, 2)) out.push({ tag: "CALLED", bad: true, h: "Tried to reach out", d: c });
  }
  return out;
}

let playToken = 0;
async function play(view) {
  const run = ++playToken, r = view.report;
  $("r-pkg").textContent = `${r.package}@${r.version}`;
  $("r-check").hidden = true;
  const list = $("r-steps");
  list.replaceChildren();
  const add = (s) => {
    const li = el("li", s.bad ? "bad" : "");
    li.append(el("span", "tag", s.tag));
    const t = el("div", "txt");
    t.append(el("b", "", s.h));
    if (s.d) t.append(el("code", "", s.d));
    li.append(t);
    list.append(li);
  };
  const steps = story(view).slice(0, 6);
  const wait = reduceMotion() ? 0 : 620;
  for (const s of steps) {
    add(s);
    if (wait) await new Promise((res) => setTimeout(res, wait));
    if (run !== playToken) return;
  }
  $("r-why").textContent = `${r.verdict} in ${Math.round(r.seconds)} seconds`;
  $("r-link").href = `#${r.scan_id}`;
  $("r-check").hidden = false;
}

// ---------------------------------------------------------------- evidence sheet

function network(capture) {
  const asked = new Set((capture || []).filter((c) => c.kind !== "dns").map((c) => c.host));
  const out = [];
  for (const c of capture || []) {
    if (c.kind === "dns") { if (c.headers && c.headers.answer && !asked.has(c.host)) out.push(["DNS", c.host, true]); }
    else if (c.kind === "http") { const b = decode(c.bytes); out.push(["TRAPPED", `${c.detail}  ${c.host}${b ? `\n${b}` : ""}`, true]); }
    else if (c.kind === "tls") { if (c.host && !out.some((o) => o[1].includes(c.host))) out.push(["TLS", c.host, true]); }
    else out.push(["TRAPPED", `port ${c.detail} ${decode(c.bytes)}`, true]);
  }
  return out;
}
function behaviour(ev, capture) {
  const out = [];
  for (const [argv] of ev.execs || []) if (!isHarness(argv)) out.push(["RAN", argv.join(" ").slice(0, 400)]);
  for (const p of ev.bait_reads || []) out.push(["READ", p, true]);
  for (const t of ev.exfil_matches || []) out.push(["STOLE", TOKEN_NAMES[t] || t, true]);
  for (const s of ev.token_uses || []) out.push(["USED", `stolen ${s} token, on the fake ${s} API`, true]);
  out.push(...network(capture));
  for (const p of ev.writes || []) out.push(["WROTE", p]);
  if (ev.deadline_killed) out.push(["KILLED", "still running at the deadline"]);
  return out;
}
function agentSteps(run) {
  const out = [];
  for (const t of run || []) {
    for (const c of t.calls || []) {
      let args = {};
      try { args = JSON.parse(c.arguments); } catch { /* cut off by the record limit */ }
      out.push({ tag: c.tool === "bash" ? "RAN" : c.tool === "read_file" ? "READ" : "WROTE", text: String(args.command || args.path || c.arguments).slice(0, 220) });
    }
  }
  return out;
}
function agentRow(step) {
  const li = el("li", step.bad ? "bad" : "");
  li.append(el("span", "tag", step.tag), el("code", "", step.text));
  return li;
}
function showSheet(view) {
  const r = view.report, ev = r.evidence || {};
  $("s-pkg").textContent = r.agent ? `Skill: ${r.package}` : `${r.package}@${r.version}`;
  $("s-id").textContent = `${r.integrity.slice(0, 32)}…  ·  scan ${r.scan_id}  ·  ${r.seconds}s`;
  $("s-verdict").textContent = r.verdict;
  $("s-verdict").className = `verdict v-${r.verdict}`;
  const ex = view.explanation && view.explanation.text;
  $("s-explain").hidden = !ex;
  $("s-explain").textContent = ex || "";
  const like = view.explanation && view.explanation.similar;
  $("s-like").hidden = !like;
  if (like) $("s-like").textContent = `Behaves like ${like.package}@${like.version}${like.incident ? `, ${like.incident}` : ""}${like.date ? `, ${like.date}` : ""}. Found in Vultr Vector Store, checked against recorded behaviour.`;
  const rows = [{ head: "Rules" }, ...(r.reasons || []).map((w) => [w.split(":")[0], w.replace(/^\w+: /, ""), !w.startsWith("REVIEW")])];
  if (!(r.reasons || []).length) rows.push(["CLEAN", "No rule fired"]);
  rows.push({ head: r.agent ? "What the agent's work did, in the gVisor sandbox" : "In the gVisor sandbox" }, ...behaviour(r.agent ? { ...ev, execs: [] } : ev, view.capture));
  if (r.microvm) rows.push({ head: "In the microVM, own kernel" }, ...behaviour(r.microvm.evidence || {}, view.microvm_capture));
  $("s-events").replaceChildren(...rows.map((row) => {
    if (row.head) return el("li", "head", row.head);
    const li = el("li", row[2] ? "bad" : "");
    li.append(el("span", "tag", row[0]), el("code", "", row[1]));
    return li;
  }));
  const box = $("s-agent");
  box.hidden = !r.agent;
  box.replaceChildren();
  if (r.agent) {
    box.append(el("h3", "", "What the agent did"), el("p", "note", r.agent.task));
    const list = el("ol", "agent-run");
    for (const step of agentSteps(r.agent.run).slice(0, 14)) list.append(agentRow(step));
    box.append(list);
  }
  $("s-files").replaceChildren(el("span", "", "Evidence files"), ...view.files.map((f) => {
    const a = el("a", "", f);
    a.href = `/api/scans/${encodeURIComponent(r.scan_id)}/files/${encodeURIComponent(f)}`;
    return a;
  }));
  $("sheet").hidden = false;
  document.body.style.overflow = "hidden";
  $("s-close").focus();
}
function closeSheet() {
  $("sheet").hidden = true;
  document.body.style.overflow = "";
  if (/^#rh-/.test(location.hash)) history.replaceState(null, "", location.pathname);
}
async function route() {
  const id = location.hash.slice(1);
  if (id.startsWith("rh-")) {
    try { showSheet(await api(`/api/scans/${encodeURIComponent(id)}`)); } catch (e) { job(e.message, true); }
  } else if (!$("sheet").hidden) closeSheet();
}

// ---------------------------------------------------------------- page data

function bars(box, items, classOf) {
  const max = Math.max(1, ...items.map((i) => i[1]));
  box.replaceChildren(...items.map(([label, n, shown]) => {
    const row = el("div", `bar ${classOf ? classOf(label) : ""}`), track = el("div"), fill = el("i");
    fill.style.width = `${(n / max) * 100}%`;
    track.append(fill);
    row.append(el("span", "", label), track, el("b", "", shown || String(n)));
    return row;
  }));
}
function renderResults(res) {
  if (!res || !res.scanned) return;
  const blocked = res.critical + res.high;
  const pct = (n) => `${Math.round((n / res.scanned) * 100)}%`;
  const stat = (v, l) => { const d = el("div"); d.append(el("b", "", v), el("span", "", l)); return d; };
  $("stats").replaceChildren(
    stat(String(res.scanned), "real malicious npm packages run, held out"),
    stat(pct(blocked), "would have blocked the merge"),
    stat(`${res.benign_block} of ${res.benign_total}`, "popular clean packages blocked"),
    stat(`${Math.round(res.p50_seconds)} s`, "typical scan"),
    ...(res.sweep && res.sweep.scanned ? [stat(res.sweep.scanned.toLocaleString(), `new npm releases scanned so far, ${res.sweep.blocked} blocked`)] : []),
    ...(res.cost_per_scan ? [stat(res.cost_per_scan, "compute per scan on VX1")] : []));
  $("stats").hidden = false;
  $("res-sub").textContent = res.source;
  bars($("res-bars"), [["CRITICAL: caught stealing", res.critical], ["HIGH: blocked", res.high], ["REVIEW: sent to a person", res.review], ["CLEAN: got through", res.clean]],
       (l) => l.split(":")[0]);
  bars($("res-misses"), (res.misses || []).map((m) => [m.cause, m.count]));
  $("res-note").textContent = res.note || "";
  if (res.sweep && res.sweep.note) {
    $("res-sweep").textContent = `On live npm: ${res.sweep.scanned.toLocaleString()} new releases scanned, ${res.sweep.blocked} blocked. ${res.sweep.note}`;
    $("res-sweep").hidden = false;
  }
  $("results").hidden = false;
}
function renderGate(res) {
  const s = res && res.showcase;
  if (!s) return;
  if (s.diff) {
    $("g-diff-title").textContent = `${s.diff.package}  ${s.diff.from} → ${s.diff.to}`;
    $("g-diff").replaceChildren(...s.diff.changes.slice(0, 7).map((c) => {
      const li = el("li");
      li.append(el("span", "plus", "+"), el("span", "dim", c.kind.replace("_", " ")), el("code", "", c.what));
      return li;
    }));
    $("g-diff-stat").textContent = s.diff.stat || "";
  }
  if (s.skill) {
    $("g-skill-title").textContent = s.skill.name;
    $("g-skill").replaceChildren(...s.skill.steps.map(agentRow));
    $("g-skill-stat").textContent = s.skill.stat || "";
  }
  if (s.fix) {
    $("g-fix-title").textContent = `${s.fix.package}  ${s.fix.blocked} → ${s.fix.pinned}`;
    $("g-fix").replaceChildren(...s.fix.steps.map(agentRow));
    $("g-fix-stat").textContent = s.fix.stat || "";
  }
  $("gate").hidden = false;
}
function renderIncidents(list) {
  $("incidents").replaceChildren(...list.map((r) => {
    const c = el("button", "card");
    c.type = "button";
    const top = el("div", "card-top");
    top.append(el("span", "date", r.date || (r.verdict === "CLEAN" ? "Clean control" : "")), el("span", `pill v-${r.verdict}`, r.verdict));
    c.append(top, el("b", "", r.title), el("code", "", r.kind === "skill" ? `skill: ${r.package}` : `${r.package}@${r.version}`), el("p", "", r.summary));
    c.addEventListener("click", () => { location.hash = r.scan_id; });
    return c;
  }));
}
function job(text, err) {
  const j = $("job");
  j.hidden = false;
  j.className = err ? "job err" : "job";
  j.textContent = text;
}
function showCompare(r) {
  const j = $("job");
  j.hidden = false;
  j.className = "job";
  const head = el("div", "cmp-head");
  head.append(el("code", "", `${r.package}  ${r.previous_version || "first release"} → ${r.version}`), el("span", `pill v-${r.verdict}`, r.verdict));
  const list = el("ul", "diff");
  for (const c of r.changes || []) {
    const li = el("li");
    li.append(el("span", "plus", "+"), el("span", "dim", c.kind.replace("_", " ")), el("code", "", String(c.what)));
    list.append(li);
  }
  const box = [head, r.changes && r.changes.length ? list : el("p", "note", r.note || "Nothing new compared with the version before.")];
  if (r.scan_id) { const a = el("a", "", "See the evidence"); a.href = `#${r.scan_id}`; box.push(a); }
  j.replaceChildren(...box);
}
async function start(body, label, path = "/api/scan") {
  const btn = document.querySelector("#scan-form button");
  btn.disabled = true;
  job(`Starting ${label}…`);
  try {
    const { job: id } = await api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const t0 = Date.now();
    for (;;) {
      const j = await api(`/api/jobs/${id}`);
      const secs = Math.round((Date.now() - t0) / 1000);
      if (j.state === "error") throw new Error(j.error);
      if (j.state === "done") {
        if (j.kind === "compare") return showCompare(j.result);
        job(`${label}: ${j.verdict}${j.cached ? " (these exact bytes were scanned before)" : ""}`);
        location.hash = j.scan_id;
        return;
      }
      job(j.state === "queued" ? `${label}: waiting for a free machine… ${secs}s` : path === "/api/skill" ? `${label}: an agent is using it… ${secs}s` : `${label}: running on a fresh machine… ${secs}s`);
      await new Promise((r) => setTimeout(r, 1200));
    }
  } catch (e) { job(e.message, true); } finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", async () => {
  $("scan-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("pkg").value.trim();
    if (!v) return;
    if (mode === "compare") {
      const at = v.lastIndexOf("@");
      if (at <= 0) return job("Give an exact version, like left-pad@1.3.0", true);
      return start({ name: v.slice(0, at), version: v.slice(at + 1) }, v, "/api/compare");
    }
    start({ package: v }, v);
  });
  $("skill-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("skill-md").value;
    if (v.trim()) start({ skill_md: v }, "This skill", "/api/skill");
  });
  let mode = "package";
  for (const b of document.querySelectorAll(".mode")) {
    b.addEventListener("click", () => {
      mode = b.dataset.mode;
      for (const o of document.querySelectorAll(".mode")) { o.classList.toggle("on", o === b); o.setAttribute("aria-selected", String(o === b)); }
      $("scan-form").hidden = mode === "skill";
      $("skill-form").hidden = mode !== "skill";
      $("samples").hidden = mode !== "package";
      $("pkg").placeholder = mode === "compare" ? "left-pad@1.3.0" : "left-pad or left-pad@1.3.0";
    });
  }
  $("s-close").addEventListener("click", closeSheet);
  $("sheet").addEventListener("click", (e) => { if (e.target === $("sheet")) closeSheet(); });
  addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("sheet").hidden) closeSheet(); });
  addEventListener("hashchange", route);
  const mcp = JSON.stringify({ mcpServers: { redhanded: { type: "http", url: `${location.origin}/mcp` } } }, null, 2);
  $("mcp-code").textContent = mcp;
  $("mcp-copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(mcp); $("mcp-copy").textContent = "Copied"; } catch { $("mcp-copy").textContent = "Select and copy"; }
  });

  api("/api/results").then((res) => { renderResults(res); renderGate(res); }).catch(() => {});
  api("/api/status").then((s) => {
    $("samples").replaceChildren(...["left-pad@1.3.0", "is-odd@3.0.1"].map((p) => {
      const c = el("button", "chip", p); c.type = "button"; c.addEventListener("click", () => start({ package: p }, p)); return c;
    }), ...s.zoo.filter((z) => ["network-tool", "hides-from-sandbox", "talks-to-agents"].includes(z)).map((z) => {
      const c = el("button", "chip", `sample: ${z}`); c.type = "button"; c.addEventListener("click", () => start({ zoo: z }, z)); return c;
    }));
  }).catch(() => {});
  try {
    const replays = await api("/api/replays");
    renderIncidents(replays);
    const hero = replays.find((r) => r.hero) || replays.find((r) => r.verdict === "CRITICAL") || replays[0];
    if (hero) {
      const view = await api(`/api/scans/${encodeURIComponent(hero.scan_id)}`);
      if (hero.date) $("r-kicker").textContent = `${hero.incident || "Real attack"}, ${hero.date}`;
      $("r-again").addEventListener("click", () => play(view));
      play(view);
    }
  } catch { $("incidents").textContent = "Recorded attacks are unavailable right now."; }
  route();
});
