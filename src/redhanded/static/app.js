// Everything a package controlled (commands, hostnames, request bodies) is
// inserted with textContent, never as HTML.
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
    return s.length > 200 ? `${s.slice(0, 200)}…` : s;
  } catch { return ""; }
};

// RedHanded's own commands are not the package's doing.
const isHarness = (argv) => argv.includes("/work/.rh/load.js") ||
  (argv.includes("rebuild") && argv.some((a) => a === "npm" || a.endsWith("/npm")));

function trapped(capture) {
  const requested = new Set(capture.filter((c) => c.kind !== "dns").map((c) => c.host));
  const out = [];
  for (const c of capture) {
    if (c.kind === "dns") {
      if (c.headers && c.headers.answer && !requested.has(c.host)) out.push(["Trapped", `DNS ${c.host}`, true]);
    } else if (c.kind === "http") {
      const body = decode(c.bytes);
      out.push(["Trapped", `${c.detail} ${c.host}${body ? `\n${body}` : ""}`, true]);
    } else {
      out.push(["Trapped", c.kind === "tls" ? `TLS ${c.host}` : `port ${c.detail}`, true]);
    }
  }
  return out;
}

function behaviour(ev, capture) {
  const out = [];
  for (const [argv] of ev.execs || []) if (!isHarness(argv)) out.push(["Ran", argv.join(" ")]);
  out.push(...trapped(capture));
  for (const p of ev.bait_reads || []) out.push(["Read", p, true]);
  for (const t of ev.exfil_matches || []) out.push(["Stole", t, true]);
  for (const s of ev.token_uses || []) out.push(["Used", `stolen token on fake ${s}`, true]);
  for (const p of ev.writes || []) out.push(["Wrote", p]);
  if (ev.deadline_killed) out.push(["Killed", "still running at the deadline"]);
  return out;
}

function show(view) {
  const r = view.report, ev = r.evidence || {};
  $("scan-view").hidden = false;
  $("name").textContent = `${r.package} ${r.version}`;
  document.title = `${r.package} · RedHanded`;
  $("verdict").textContent = r.verdict;
  $("verdict").className = r.verdict;
  $("explanation").textContent = (view.explanation && view.explanation.text) || "";

  const rows = [];
  if (r.microvm) rows.push({ tier: "gVisor" });
  rows.push(...behaviour(ev, view.capture || []));
  if (r.microvm) {
    rows.push({ tier: "microVM" });
    rows.push(...behaviour(r.microvm.evidence || {}, view.microvm_capture || []));
    rows.push({ tier: "Verdict" });
  }
  for (const why of r.reasons || []) rows.push(["Rule", why.replace(/^\w+: /, ""), !why.startsWith("REVIEW")]);

  const list = $("events");
  list.replaceChildren(...rows.map((row, i) => {
    const li = el("li", row.tier ? "tier" : row[2] ? "bad" : "");
    li.style.setProperty("--at", `${i * 0.06}s`);
    if (row.tier) li.textContent = row.tier;
    else li.append(el("b", "", row[0]), el("code", "", row[1]));
    return li;
  }));

  $("files").replaceChildren(...view.files.map((f) => {
    const a = el("a", "", f);
    a.href = `/api/scans/${encodeURIComponent(r.scan_id)}/files/${encodeURIComponent(f)}`;
    return a;
  }));
}

let current = null;
const items = new Map();

function row(item) {
  const a = el("a");
  a.href = `#${item.scan_id || ""}`;
  a.append(el("span", `dot ${item.verdict || "running"}`), el("span", "", item.title));
  item.node = a;
  return a;
}

function mark() {
  for (const [id, item] of items) {
    if (id === current) item.node.setAttribute("aria-current", "true");
    else item.node.removeAttribute("aria-current");
  }
  const item = items.get(current);
  $("run").hidden = !(item && item.live);
}

async function open(id) {
  current = id;
  mark();
  show(await api(`/api/scans/${encodeURIComponent(id)}`));
}

function route() {
  const id = location.hash.slice(1);
  if (id) open(id).catch((e) => { $("scan-view").hidden = false; $("name").textContent = e.message; });
}

async function detonate(body, title) {
  const pending = { title, verdict: null };
  $("list").prepend(row(pending));
  pending.node.removeAttribute("href");
  try {
    const { job } = await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    for (;;) {
      const j = await api(`/api/jobs/${job}`);
      if (j.state === "error") throw new Error(j.error);
      if (j.state === "done") {
        pending.scan_id = j.scan_id;
        pending.live = body;
        pending.node.href = `#${j.scan_id}`;
        pending.node.firstChild.className = `dot ${j.verdict}`;
        items.set(j.scan_id, pending);
        location.hash = j.scan_id;
        return;
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
  } catch (e) {
    pending.node.firstChild.className = "dot";
    pending.node.lastChild.textContent = `${title}: ${e.message}`;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  $("scan").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("pkg").value.trim();
    if (v) { $("pkg").value = ""; detonate({ package: v }, v); }
  });
  $("run").addEventListener("click", () => {
    const item = items.get(current);
    if (item && item.live) detonate(item.live, item.title);
  });
  $("agent").addEventListener("click", async () => {
    const config = { mcpServers: { redhanded: { type: "http", url: `${location.origin}/mcp` } } };
    await navigator.clipboard.writeText(JSON.stringify(config, null, 2));
    $("agent").textContent = "Copied";
    setTimeout(() => { $("agent").textContent = "Copy MCP config"; }, 1500);
  });
  addEventListener("hashchange", route);

  const replays = await api("/api/replays");
  for (const r of replays) {
    items.set(r.scan_id, r);
    $("list").append(row(r));
  }
  if (location.hash.length > 1) route();
  else if (replays.length) history.replaceState(null, "", `#${replays[0].scan_id}`), route();
});
