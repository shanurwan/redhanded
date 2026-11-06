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

function decode(b64) {
  if (!b64) return "";
  try {
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const s = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return s.length > 240 ? s.slice(0, 240) + "…" : s;
  } catch { return "(binary)"; }
}

function isHarness(argv) {
  const s = argv.join(" ");
  return s.includes("/work/.rh/") || (/(^| )npm( |$)|\/usr\/local\/bin\/npm/.test(s) && argv.includes("rebuild"));
}

function network(capture) {
  const out = [];
  for (const c of capture || []) {
    if (c.kind === "dns") {
      if (!c.headers || !c.headers.answer) continue;
      out.push({ k: "net", h: `DNS lookup: ${c.host}`, d: `answered by the sinkhole with ${c.headers.answer}`,
                 caught: "the real resolver never saw it" });
    } else if (c.kind === "http") {
      const body = decode(c.bytes);
      out.push({ k: "net", h: `${c.detail} → ${c.host}`, d: body ? `body: ${body}` : "",
                 caught: "caught by the sinkhole, which has no route out" });
    } else if (c.kind === "tls") {
      out.push({ k: "net", h: `TLS connection → ${c.host}`, d: "server name read from the handshake",
                 caught: "caught by the sinkhole, which has no route out" });
    } else {
      out.push({ k: "net", h: `Raw connection on port ${c.detail}`, d: decode(c.bytes),
                 caught: "caught by the sinkhole, which has no route out" });
    }
  }
  return out;
}

// The replay is the scan's own evidence, in the order the story makes sense.
function steps(view) {
  const r = view.report, ev = r.evidence || {}, out = [];
  out.push({ k: "", h: "Sandbox up, bait planted", d: "gVisor, own network namespace; fake credentials in /home/dev" });
  out.push({ k: "", h: "npm ran the package's install scripts", d: `npm rebuild ${r.package} --foreground-scripts` });
  for (const [argv, declared] of ev.execs || []) {
    if (isHarness(argv)) continue;
    out.push({ k: declared ? "" : "warn", h: declared ? "Install script ran a command" : "Code started a process",
               d: argv.join(" ") });
  }
  out.push({ k: "", h: "Loaded the package like an app would", d: `require("${r.package}")` });
  out.push(...network(view.capture));
  for (const p of ev.bait_reads || []) out.push({ k: "bad", h: "Read a bait credential", d: p });
  for (const t of ev.exfil_matches || []) out.push({ k: "bad", h: "Bait credential found in outbound traffic", d: t });
  for (const s of ev.token_uses || []) out.push({ k: "bad", h: "Used a stolen token", d: `against the fake ${s} endpoint` });
  for (const p of ev.writes || []) out.push({ k: "bad", h: "Wrote outside its own folder", d: p,
                                              caught: "into gVisor's in-memory overlay, discarded after the scan" });
  if (ev.deadline_killed) out.push({ k: "warn", h: "Still running at the deadline", d: "sandbox killed" });
  if (r.microvm) {
    const m = r.microvm.evidence || {};
    out.push({ k: "", h: "Ran the same bytes again in a microVM", d: "its own kernel, fresh fake credentials" });
    for (const [argv] of m.execs || []) if (!isHarness(argv)) out.push({ k: "warn", h: "Code started a process", d: argv.join(" ") });
    out.push(...network(view.microvm_capture));
    for (const p of m.bait_reads || []) out.push({ k: "bad", h: "Read a bait credential", d: p });
    for (const t of m.exfil_matches || []) out.push({ k: "bad", h: "Bait credential found in outbound traffic", d: t });
    for (const x of m.token_uses || []) out.push({ k: "bad", h: "Used a stolen token", d: `against the fake ${x} endpoint` });
    for (const p of m.writes || []) out.push({ k: "bad", h: "Wrote outside its own folder", d: p, caught: "inside the microVM, discarded after the scan" });
  }
  out.push({ k: "verdict", h: `Verdict: ${r.verdict}`, d: (r.reasons || []).join("\n") || "no rule fired" });
  return out;
}

let animation = 0, firstOpen = true;
function show(view) {
  const r = view.report;
  $("viewer").hidden = false;
  $("v-pkg").textContent = `${r.package}@${r.version}`;
  $("v-integrity").textContent = `${r.integrity.slice(0, 40)}…  scan ${r.scan_id}`;
  const v = $("v-verdict");
  v.textContent = r.verdict;
  v.className = `verdict v-${r.verdict}`;

  const tl = $("v-timeline");
  tl.replaceChildren();
  const run = ++animation;
  const items = steps(view).map((s) => {
    const li = el("li", s.k ? `k-${s.k}` : "");
    li.append(el("div", "h", s.h));
    if (s.d) li.append(el("div", "d", s.d));
    if (s.caught) li.append(el("div", "caught", s.caught));
    tl.append(li);
    return li;
  });
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  items.forEach((li, i) => setTimeout(() => { if (run === animation) li.classList.add("on"); }, reduce ? 0 : 280 * i));

  const ex = view.explanation;
  $("v-explain").hidden = !(ex && ex.text);
  if (ex && ex.text) {
    $("v-explain-label").textContent =
      `Explained by Vultr Serverless Inference (${ex.model}). The rules above set the verdict; this text cannot change it.`;
    $("v-explain-text").textContent = ex.text;
  }

  const sb = r.sandbox || {}, facts = $("v-facts");
  facts.replaceChildren();
  const fact = (label, value) => { const s = el("span"); s.append(el("b", "", String(value)), ` ${label}`); facts.append(s); };
  fact("seconds", r.seconds);
  if (view.meta && view.meta.full_syscall_log) fact("syscalls recorded", view.meta.full_syscall_log.lines.toLocaleString());
  else if (sb.syscall_lines) fact("syscalls recorded", sb.syscall_lines.toLocaleString());
  fact("sinkhole records", sb.sinkhole_records ?? (view.capture || []).length);
  fact("unparsed log lines", sb.unparsed ?? 0);

  const files = $("v-files");
  files.replaceChildren(el("span", "dim", "Evidence:"));
  for (const f of view.files) {
    const a = el("a", "", f);
    a.href = `/api/scans/${encodeURIComponent(r.scan_id)}/files/${encodeURIComponent(f)}`;
    files.append(a);
  }
  if (view.meta && view.meta.full_syscall_log) {
    files.append(el("span", "dim mono", `full log sha256 ${view.meta.full_syscall_log.sha256.slice(0, 16)}…`));
  }
  if (!firstOpen) $("viewer").scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
  firstOpen = false;
}

async function open(scanId) {
  show(await api(`/api/scans/${encodeURIComponent(scanId)}`));
}

async function loadReplays() {
  const box = $("replays");
  const list = await api("/api/replays");
  for (const r of list) {
    const b = el("button", "replay");
    b.type = "button";
    b.setAttribute("role", "listitem");
    b.setAttribute("aria-pressed", "false");
    const t = el("div", "t");
    t.append(el("span", "", r.title), el("span", `badge v-${r.verdict}`, r.verdict));
    b.append(t, el("div", "s", r.summary));
    b.addEventListener("click", () => {
      box.querySelectorAll(".replay").forEach((x) => x.setAttribute("aria-pressed", "false"));
      b.setAttribute("aria-pressed", "true");
      open(r.scan_id).catch((e) => alert(e.message));
    });
    box.append(b);
  }
  if (list.length) box.firstChild.click();
}

async function loadStatus() {
  try {
    const s = await api("/api/status");
    const st = $("status");
    st.replaceChildren(`${s.host} · rules ${s.rules} · `,
      el("span", s.scans_open ? "open" : "closed", s.scans_open ? "live scans open" : "live scans paused"));
    const zoo = $("zoo");
    zoo.replaceChildren();
    for (const name of s.zoo) {
      const c = el("button", "chip", name);
      c.type = "button";
      c.addEventListener("click", () => start({ zoo: name }));
      zoo.append(c);
    }
  } catch { $("status").textContent = "status unavailable"; }
}

async function start(body) {
  const job = $("job"), btn = document.querySelector("#scan-form button");
  job.hidden = false;
  job.className = "job";
  job.textContent = "Submitting…";
  btn.disabled = true;
  try {
    const { job: id } = await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" },
                                                  body: JSON.stringify(body) });
    const started = Date.now();
    for (;;) {
      const j = await api(`/api/jobs/${id}`);
      const secs = Math.round((Date.now() - started) / 1000);
      if (j.state === "queued") job.textContent = `Queued, ${j.ahead} ahead of you… ${secs}s`;
      else if (j.state === "running") job.textContent = `Detonating ${j.target} in a fresh gVisor sandbox… ${secs}s`;
      else if (j.state === "error") throw new Error(j.error);
      else {
        job.textContent = `${j.target}: ${j.verdict}${j.cached ? " (same bytes scanned before, cached verdict)" : ""}`;
        await open(j.scan_id);
        break;
      }
      await new Promise((r) => setTimeout(r, 1500));
    }
  } catch (e) {
    job.className = "job err";
    job.textContent = e.message;
  } finally {
    btn.disabled = false;
    loadStatus();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("scan-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("pkg").value.trim();
    if (v) start({ package: v });
  });
  loadStatus();
  loadReplays().catch(() => { $("replays").textContent = "Replays unavailable."; });
});
