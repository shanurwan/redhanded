"""Who has used the service, counted without keeping who they are.

A person is a keyed hash of address and browser. The key stays on this machine, so the hash cannot be
reversed or matched elsewhere, and deleting the key and the database removes all of it. No cookies.
Counting must never get in the way of the site, so every failure here is swallowed.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path

BOTS = re.compile(r"bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|discord|slack|linkedin|embedly|headless|curl|wget|python-|go-http|node-fetch|scan", re.I)
_SOURCE = re.compile(r"^[a-z0-9-]{1,24}$")
VISIT_GAP_S = 1800
MAX_ROWS = 200_000
OWN_REPOS = ("shanurwan/redhanded-demo", "shanurwan/redhanded")
_LABELS = {"scan": "Package scans", "compare": "Version comparisons", "repair": "Repairs", "skill": "Skill runs", "lockfile": "Lockfile checks", "mcp": "Agent (MCP) calls", "action": "PR checks"}
_SCHEMA = """
create table if not exists events(at real, kind text, who text);
create table if not exists people(who text primary key, first_at real, source text, last_visit real);
create table if not exists mine(ip text primary key);
create index if not exists ev_kind on events(kind);
"""


def repo_id(repo: str) -> str:
    return hashlib.sha256(repo.encode()).hexdigest()[:32]


class Usage:
    def __init__(self, data_dir: str, clock=time.time):
        self.root, self.clock = Path(data_dir), clock
        self._lock = threading.Lock()
        self.db = self.root / "usage.sqlite3"
        self.key = self._secret("usage.key")
        self.token = self._secret("stats.token")
        with self._connect() as c:
            c.executescript(_SCHEMA)

    def _secret(self, name: str) -> str:
        p = self.root / name
        if not p.exists():
            p.touch(mode=0o600)
            p.write_text(secrets.token_urlsafe(24))
        return p.read_text().strip()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db, timeout=3)

    def _hash(self, text: str) -> str:
        return hmac.new(self.key.encode(), text.encode(), hashlib.sha256).hexdigest()[:32]

    def _person(self, ip: str, agent: str, repo: str = "") -> tuple[str, str]:
        return (f"repo:{repo}" if repo else self._hash(f"{ip}|{agent}")), self._hash(ip)

    def _skip(self, c, ip_hash: str, agent: str, repo: str) -> bool:
        if repo:
            return repo in {repo_id(r) for r in OWN_REPOS}
        if BOTS.search(agent or "") or not agent:
            return True
        return c.execute("select 1 from mine where ip=?", (ip_hash,)).fetchone() is not None

    def visit(self, ip: str, agent: str, source: str | None) -> None:
        """Sent by the page's own script, which link previews do not run. A return within half an hour is the same visit."""
        try:
            who, ip_hash = self._person(ip, agent)
            source = source if source and _SOURCE.match(source) else "direct"
            now = self.clock()
            with self._lock, self._connect() as c:
                if self._skip(c, ip_hash, agent, ""):
                    return
                row = c.execute("select last_visit from people where who=?", (who,)).fetchone()
                if row is None:
                    c.execute("insert into people values(?,?,?,?)", (who, now, source, now))
                else:
                    c.execute("update people set last_visit=? where who=?", (now, who))
                if (row is None or now - (row[0] or 0) >= VISIT_GAP_S) and self._room(c):
                    c.execute("insert into events values(?,?,?)", (now, "visit", who))
        except (sqlite3.Error, OSError):
            pass

    def used(self, kind: str, ip: str, agent: str, repo: str = "") -> None:
        try:
            who, ip_hash = self._person(ip, agent, repo)
            now = self.clock()
            with self._lock, self._connect() as c:
                if self._skip(c, ip_hash, "" if repo else (agent if "redhanded" not in (agent or "") else "client"), repo) or not self._room(c):
                    return
                c.execute("insert or ignore into people values(?,?,?,?)", (who, now, "repo" if repo else "direct", None))
                c.execute("insert into events values(?,?,?)", (now, kind, who))
        except (sqlite3.Error, OSError):
            pass

    def _room(self, c) -> bool:
        return c.execute("select count(*) from events").fetchone()[0] < MAX_ROWS

    def allowed(self, token: str | None) -> bool:
        return bool(token) and secrets.compare_digest(token.encode(), self.token.encode())

    def exclude(self, ip: str) -> None:
        """Whoever opens the private page is the owner: that address stops counting, and its past stops counting too."""
        try:
            with self._lock, self._connect() as c:
                c.execute("insert or ignore into mine values(?)", (self._hash(ip),))
        except (sqlite3.Error, OSError):
            pass

    def numbers(self) -> dict:
        with self._lock, self._connect() as c:
            one = lambda q, *a: c.execute(q, a).fetchone()[0] or 0
            used = "kind<>'visit'"
            out = {
                "visits": one("select count(*) from events where kind='visit'"),
                "visitors": one("select count(distinct who) from events where kind='visit'"),
                "users": one(f"select count(distinct who) from events where {used}"),
                "runs": one(f"select count(*) from events where {used}"),
                "integrations": one("select count(distinct who) from events where kind in ('mcp','action')"),
                "since": one("select min(at) from events"),
                "kinds": c.execute(f"select kind,count(*),count(distinct who) from events where {used} group by kind order by 2 desc").fetchall(),
                "sources": c.execute(f"""select p.source,
                       count(distinct case when e.kind='visit' then e.who end),
                       count(distinct case when e.kind<>'visit' then e.who end)
                       from events e join people p on p.who=e.who group by p.source order by 2 desc, 3 desc""").fetchall(),
                "days": c.execute("select date(at,'unixepoch'),count(distinct who) from events group by 1 order by 1").fetchall(),
            }
        return out

    def page(self, host: str) -> str:
        n = self.numbers()
        e = html.escape
        tile = lambda v, l, hot="": f'<div class="t {hot}"><b>{int(v):,}</b><span>{e(l)}</span></div>'
        src = "".join(f"<tr><td>{e(str(s))}</td><td>{int(a):,}</td><td>{int(b):,}</td></tr>" for s, a, b in n["sources"]) or '<tr><td colspan="3">Nothing yet</td></tr>'
        kin = "".join(f"<tr><td>{e(_LABELS.get(k, k))}</td><td>{int(a):,}</td><td>{int(b):,}</td></tr>" for k, a, b in n["kinds"]) or '<tr><td colspan="3">Nothing yet</td></tr>'
        top = max([d[1] for d in n["days"]] or [1])
        day = "".join(f'<div class="d"><i style="height:{max(4, round(v / top * 120))}px"></i><b>{v}</b><span>{e(k[5:])}</span></div>' for k, v in n["days"])
        since = time.strftime("%d %b %Y", time.gmtime(n["since"])) if n["since"] else "not yet"
        at = time.strftime("%d %b %Y, %H:%M UTC", time.gmtime(self.clock()))
        return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RedHanded usage</title>
<style>:root{{--b:#070b14;--s:#121b2c;--l:#26344e;--t:#f3f6fb;--m:#8b99b1;--r:#ff3b47}}*{{box-sizing:border-box}}body{{margin:0;background:var(--b);color:var(--t);font:16px/1.5 Inter,'Segoe UI',system-ui,sans-serif;padding:40px max(16px,4vw)}}
main{{max-width:1040px;margin:auto}}h1{{font-size:30px;margin:0;letter-spacing:-.02em}}h1 em{{color:var(--r);font-style:normal}}p{{color:var(--m);margin:6px 0 28px}}
.g{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:28px}}.t{{background:var(--s);border:1px solid var(--l);border-radius:14px;padding:20px}}.t b{{display:block;font-size:44px;line-height:1.1;letter-spacing:-.03em}}.t span{{color:var(--m);font-size:14px}}.hot b{{color:var(--r)}}
.two{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px;margin-bottom:28px}}section{{background:var(--s);border:1px solid var(--l);border-radius:14px;padding:20px;min-width:0}}h2{{font-size:17px;margin:0 0 12px}}
table{{width:100%;border-collapse:collapse;font-size:15px}}th{{color:var(--m);font-weight:500;text-align:right;padding:6px 0}}th:first-child,td:first-child{{text-align:left}}td{{text-align:right;padding:8px 0;border-top:1px solid var(--l)}}
.days{{display:flex;gap:10px;align-items:flex-end;overflow-x:auto;min-height:170px}}.d{{display:flex;flex-direction:column;align-items:center;font-size:12px;color:var(--m);min-width:38px}}.d i{{display:block;width:24px;background:var(--r);border-radius:4px 4px 0 0}}.d b{{color:var(--t)}}
small{{color:var(--m)}}</style><main><h1>Red<em>Handed</em> usage</h1><p>{e(host)} · counting since {since} · as of {at}</p>
<div class="g">{tile(n['users'], 'unique users who ran something', 'hot')}{tile(n['runs'], 'runs by those users', 'hot')}{tile(n['integrations'], 'agents and repos connected', 'hot')}{tile(n['visitors'], 'unique visitors')}{tile(n['visits'], 'visits')}</div>
<div class="two"><section><h2>Where they came from</h2><table><tr><th>Channel</th><th>Visitors</th><th>Users</th></tr>{src}</table></section><section><h2>What they ran</h2><table><tr><th>Action</th><th>Runs</th><th>Users</th></tr>{kin}</table></section></div>
<section><h2>Unique people per day</h2><div class="days">{day or '<small>Nothing yet</small>'}</div></section>
<p style="margin-top:22px"><small>A person is a keyed hash of address and browser, so one person on two devices counts twice. Known bots, link previews and this page's owner are left out. No cookies, and no addresses stored.</small></p></main></html>"""
