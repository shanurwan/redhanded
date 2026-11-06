"""The site and its API: one queue behind the page, the PR check and hosted MCP.

One process, standard library only. Scans run one at a time on a single worker
thread, behind a short queue, a per-address rate limit and the spend guard, so
a busy demo slows down instead of running up a bill. Every page is built from
the files a scan writes, and those files can be downloaded.
"""
from __future__ import annotations

import base64
import binascii
import collections
import glob
import gzip
import json
import os
import queue
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Callable

from . import __version__, mcp_http
from .agenttext import AgentTextCheck
from .explain import Explainer
from .runner import ScanConfig, ScanError, _get, scan_local
from .service import ADVICE, SCAN_ID, Cache, InputError, Service, validate
from .spend import GuardState, StateFile
from .verdict import RULES_VERSION

JOB_ID = re.compile(r"^[0-9a-f]{16}$")
ZOO_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
# Published name -> where it lives in a scan folder, then in a replay folder.
SCAN_FILES = {
    "report.json": ("application/json", ["report.json"]),
    "capture.jsonl": ("application/x-ndjson", ["capture.jsonl"]),
    "explain.json": ("application/json", ["explain.json"]),
    "syscalls-excerpt.txt": ("text/plain; charset=utf-8", ["syscalls-excerpt.txt"]),
    "microvm-capture.jsonl": ("application/x-ndjson", ["microvm/capture.jsonl", "microvm-capture.jsonl"]),
    "microvm-console.txt": ("text/plain; charset=utf-8", ["microvm/log/console.txt", "microvm-console.txt"]),
}
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8"),
          "/llms.txt": ("llms.txt", "text/plain; charset=utf-8")}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; base-uri 'none'; "
                               "form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
MAX_BODY = 4 << 20       # a lockfile pair or a small tarball
MAX_TARBALL = 2 << 20
MAX_LOCKFILE_SCANS = 5


class Refused(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


@dataclass
class WebConfig:
    data_dir: str = field(default_factory=lambda: os.path.expanduser(os.environ.get("RH_WEB_DATA", "~/rh-dev/web")))
    replays_dir: str = field(default_factory=lambda: os.environ.get("RH_REPLAYS", "replays"))
    zoo_dir: str = field(default_factory=lambda: os.environ.get("RH_ZOO", "zoo"))
    host_label: str = field(default_factory=lambda: os.environ.get("RH_HOST_LABEL", "dev server"))
    guard_state: str = field(default_factory=lambda: os.path.expanduser(
        os.environ.get("RH_GUARD_STATE", "~/rh-dev/web/guard-state.json")))
    trust_proxy: bool = field(default_factory=lambda: os.environ.get("RH_TRUST_PROXY") == "1")
    scans_per_hour: int = field(default_factory=lambda: int(os.environ.get("RH_SCANS_PER_HOUR", "12")))
    max_queue: int = 8


@dataclass
class Job:
    id: str
    kind: str                 # npm | zoo | tarball | lockfile
    target: str
    payload: object = None    # tarball bytes or lockfile pair; never sent back
    state: str = "queued"     # queued | running | done | error
    created: float = field(default_factory=time.time)
    scan_id: str | None = None
    verdict: str | None = None
    cached: bool = False
    error: str | None = None
    result: dict | None = None

    def view(self) -> dict:
        return {k: getattr(self, k) for k in ("id", "kind", "target", "state", "scan_id", "verdict",
                                              "cached", "error", "result")}


class RateLimit:
    def __init__(self, per_hour: int, clock: Callable[[], float] = time.time):
        self.per_hour, self.clock = per_hour, clock
        self._hits: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()

    def take(self, who: str) -> bool:
        now = self.clock()
        with self._lock:
            hits = self._hits[who]
            while hits and now - hits[0] > 3600:
                hits.popleft()
            if len(hits) >= self.per_hour:
                return False
            hits.append(now)
            return True


def resolve_spec(spec: str, registry: str) -> tuple[str, str]:
    """'name', 'name@1.2.3' or '@scope/name@1.2.3' -> (name, exact version). Bare names use latest."""
    spec = spec.strip()
    at = spec.rfind("@")
    name, version = (spec[:at], spec[at + 1:]) if at > 0 else (spec, "")
    if not version:
        validate(name, "0.0.0")
        meta = json.loads(_get(f"{registry}/{urllib.parse.quote(name, safe='@')}/latest", 5 << 20))
        version = str(meta.get("version", ""))
    validate(name, version)
    return name, version


class Scanner:
    """The queue and its single worker."""

    def __init__(self, cfg: WebConfig, service: Service, explainer: Explainer | None = None,
                 limiter: RateLimit | None = None, local_scan: Callable = scan_local,
                 clock: Callable[[], float] = time.time):
        self.cfg, self.service, self.explainer = cfg, service, explainer
        self.limiter = limiter or RateLimit(cfg.scans_per_hour)
        self._local_scan, self._clock = local_scan, clock
        self.jobs: dict[str, Job] = {}
        self._queue: queue.Queue[Job] = queue.Queue(maxsize=cfg.max_queue)
        self._lock = threading.Lock()

    @property
    def roots(self) -> list[str]:
        return [self.cfg.replays_dir, self.service.cfg.scans_dir]

    def guard_allows(self) -> bool:
        # Fails closed: a missing or stale guard state means no scans.
        return StateFile(self.cfg.guard_state).allows(GuardState.STOP_TIER2, self._clock())

    def start(self, kind: str, target: str, payload: object, who: str) -> Job:
        """Every way in comes through here, so the guard and the limit apply to all of them."""
        if not self.guard_allows():
            raise Refused(503, "scans are paused by the spend guard")
        if kind == "zoo":
            if not (ZOO_NAME.match(target) and (Path(self.cfg.zoo_dir) / target / "package.json").is_file()):
                raise Refused(400, f"no Zoo sample called {target!r}")
        elif kind == "npm" and not 0 < len(target.strip()) <= 260:
            raise Refused(400, "give a package like left-pad or left-pad@1.3.0")
        if not self.limiter.take(who):
            raise Refused(429, f"limit is {self.cfg.scans_per_hour} scans an hour per address")
        job = Job(id=secrets.token_hex(8), kind=kind, target=target.strip(), payload=payload)
        try:
            self._queue.put_nowait(job)
        except queue.Full:
            raise Refused(503, "the queue is full; try again in a minute") from None
        with self._lock:
            self.jobs[job.id] = job
            self._forget_old()
        return job

    def wait(self, job: Job, timeout: float = 280.0) -> Job:
        deadline = self._clock() + timeout
        while job.state in ("queued", "running") and self._clock() < deadline:
            time.sleep(0.25)
        return job

    def _forget_old(self) -> None:
        cutoff = self._clock() - 6 * 3600
        for jid in [j.id for j in self.jobs.values() if j.created < cutoff and j.state in ("done", "error")]:
            del self.jobs[jid]

    def _finish_scan(self, job: Job, scan_id: str, cached: bool) -> None:
        scan_dir = Path(self.service.cfg.scans_dir) / scan_id
        if self.explainer:
            write_explanation(scan_dir, self.explainer)
        job.result = answer(scan_dir, cached)
        job.scan_id, job.verdict, job.cached = scan_id, job.result["verdict"], cached

    def run_one(self, job: Job) -> None:
        job.state = "running"
        try:
            if not self.guard_allows():
                raise ScanError("scans are paused by the spend guard")
            if job.kind == "zoo":
                report = self._local_scan(Path(self.cfg.zoo_dir) / job.target, self.service.cfg)
                self._finish_scan(job, report.scan_id, False)
            elif job.kind == "tarball":
                out = self.service.check_tarball(job.payload)
                self._finish_scan(job, out["scan_id"], out["cached"])
            elif job.kind == "lockfile":
                old, new = job.payload
                job.result = self.service.check_lockfile(old, new, max_scans=MAX_LOCKFILE_SCANS)
                job.verdict = job.result["worst_verdict"]
            else:
                name, version = resolve_spec(job.target, self.service.cfg.registry)
                out = self.service.check(name, version)
                self._finish_scan(job, out["scan_id"], out["cached"])
            job.state = "done"
        except (InputError, ScanError) as e:
            job.state, job.error = "error", str(e)
        except Exception as e:  # never let one bad job stop the worker
            job.state, job.error = "error", f"scan failed ({type(e).__name__})"
        finally:
            job.payload = None

    def serve_forever(self) -> None:
        while True:
            self.run_one(self._queue.get())


def answer(scan_dir: Path, cached: bool = False) -> dict:
    report = json.loads((scan_dir / "report.json").read_text())
    explain_path = scan_dir / "explain.json"
    explanation = json.loads(explain_path.read_text()).get("text") if explain_path.is_file() else None
    return {"package": report["package"], "version": report["version"], "integrity": report["integrity"],
            "verdict": report["verdict"], "advice": ADVICE[report["verdict"]], "reasons": report["reasons"],
            "explanation": explanation, "scan_id": report["scan_id"], "cached": cached,
            "url": f"/#{report['scan_id']}"}


def write_explanation(scan_dir: Path, explainer: Explainer) -> dict | None:
    path = scan_dir / "explain.json"
    if path.is_file():
        return json.loads(path.read_text())
    report_path = scan_dir / "report.json"
    if not report_path.is_file():
        return None
    out = explainer.explain(json.loads(report_path.read_text()))
    if out.get("text"):
        out["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        path.write_text(json.dumps(out, indent=1))
    return out


def find_scan(scan_id: str, roots: list[str]) -> Path | None:
    if not SCAN_ID.match(scan_id):
        return None
    for root in roots:
        d = Path(root) / scan_id
        if (d / "report.json").is_file():
            return d
    return None


def _scan_file(scan_dir: Path, name: str) -> Path | None:
    for rel in SCAN_FILES.get(name, (None, []))[1]:
        if (scan_dir / rel).is_file():
            return scan_dir / rel
    return None


def load_capture(path: Path | None, limit: int = 200) -> list[dict]:
    if not path:
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines()[:limit]:
        r = json.loads(line)
        out.append({k: r.get(k) for k in ("kind", "host", "detail", "headers")} | {"bytes": r.get("data", "")})
    return out


def scan_view(scan_dir: Path) -> dict:
    explain = _scan_file(scan_dir, "explain.json")
    files = [n for n in SCAN_FILES if _scan_file(scan_dir, n)]
    if glob.glob(str(scan_dir / "log" / "*.boot.txt")):
        files.append("syscalls.log.gz")
    return {
        "report": json.loads((scan_dir / "report.json").read_text()),
        "capture": load_capture(_scan_file(scan_dir, "capture.jsonl")),
        "microvm_capture": load_capture(_scan_file(scan_dir, "microvm-capture.jsonl")),
        "explanation": json.loads(explain.read_text()) if explain else None,
        "meta": json.loads((scan_dir / "meta.json").read_text()) if (scan_dir / "meta.json").is_file() else None,
        "files": files,
    }


def list_replays(replays_dir: str) -> list[dict]:
    out = []
    for meta_path in sorted(Path(replays_dir).glob("rh-*/meta.json")):
        meta = json.loads(meta_path.read_text())
        report = json.loads((meta_path.parent / "report.json").read_text())
        pkg = report["package"]
        live = {"zoo": pkg[len("rh-zoo-"):]} if pkg.startswith("rh-zoo-") else {"package": f"{pkg}@{report['version']}"}
        out.append({"scan_id": report["scan_id"], "package": pkg, "version": report["version"],
                    "verdict": report["verdict"], "title": meta.get("title", pkg),
                    "summary": meta.get("summary", ""), "order": meta.get("order", 99), "live": live})
    return sorted(out, key=lambda r: (r["order"], r["scan_id"]))


def _tarball(body: dict) -> bytes:
    try:
        data = base64.b64decode(body["tarball"], validate=True)
    except (binascii.Error, TypeError, ValueError):
        raise Refused(400, "tarball must be base64") from None
    if not 0 < len(data) <= MAX_TARBALL:
        raise Refused(413, "tarball is over the 2 MB limit")
    return data


def make_handler(cfg: WebConfig, scanner: Scanner):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"redhanded/{__version__}"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # one line per request, no query strings
            print(f"{self.client()} {self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}",
                  flush=True)

        def client(self) -> str:
            if cfg.trust_proxy and self.client_address[0] == "127.0.0.1":
                fwd = self.headers.get("X-Forwarded-For", "")
                if fwd:
                    return fwd.split(",")[0].strip()
            return self.client_address[0]

        def send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (SECURITY_HEADERS | (extra or {})).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def json(self, status: int, obj) -> None:
            self.send(status, json.dumps(obj).encode(), "application/json", {"Cache-Control": "no-store"})

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path in STATIC:
                name, ctype = STATIC[path]
                body = resources.files("redhanded").joinpath("static", name).read_bytes()
                return self.send(200, body, ctype, {"Cache-Control": "no-cache"})
            if path == "/healthz":
                return self.json(200, {"ok": True, "rules": RULES_VERSION, "scans_open": scanner.guard_allows()})
            if path == "/api/status":
                return self.json(200, {"version": __version__, "rules": RULES_VERSION, "host": cfg.host_label,
                                       "scans_open": scanner.guard_allows(), "queued": scanner._queue.qsize(),
                                       "zoo": sorted(p.parent.name for p in Path(cfg.zoo_dir).glob("*/package.json")),
                                       "explainer": scanner.explainer.model if scanner.explainer else None})
            if path == "/api/replays":
                return self.json(200, list_replays(cfg.replays_dir))
            if path == "/mcp":
                return self.json(405, {"error": "this MCP endpoint is POST only"})
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[:2] == ["api", "jobs"] and JOB_ID.match(parts[2]):
                job = scanner.jobs.get(parts[2])
                return self.json(200, job.view()) if job else self.json(404, {"error": "no such job"})
            if len(parts) >= 3 and parts[:2] == ["api", "scans"]:
                scan_dir = find_scan(parts[2], scanner.roots)
                if not scan_dir:
                    return self.json(404, {"error": "no such scan"})
                if len(parts) == 3:
                    return self.json(200, scan_view(scan_dir))
                if len(parts) == 5 and parts[3] == "files":
                    return self.file(scan_dir, parts[4])
            self.json(404, {"error": "not found"})

        def file(self, scan_dir: Path, name: str) -> None:
            disposition = {"Content-Disposition": f'attachment; filename="{scan_dir.name}-{name}"'}
            path = _scan_file(scan_dir, name)
            if path:
                return self.send(200, path.read_bytes(), SCAN_FILES[name][0], disposition)
            logs = sorted(glob.glob(str(scan_dir / "log" / "*.boot.txt")))
            if name == "syscalls.log.gz" and logs:
                body = gzip.compress(b"".join(Path(p).read_bytes() for p in logs), compresslevel=6)
                return self.send(200, body, "application/gzip", disposition)
            self.json(404, {"error": "no such file"})

        def body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= MAX_BODY:
                self.close_connection = True      # the body stays unread
                raise Refused(413, "request too large")
            try:
                body = json.loads(self.rfile.read(length))
            except ValueError:
                raise Refused(400, "send JSON") from None
            if not isinstance(body, dict):
                raise Refused(400, "send a JSON object")
            return body

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            try:
                if path not in ("/api/scan", "/api/lockfile", "/mcp"):
                    self.close_connection = True
                    raise Refused(404, "not found")
                body = self.body()
                if path == "/mcp":
                    reply = mcp_http.handle(body, scanner, self.client())
                    if reply is None:
                        return self.send(202, b"", "application/json")
                    return self.json(200, reply)
                self.json(202, {"job": submit(scanner, path, body, self.client()).id})
            except Refused as e:
                self.json(e.status, {"error": str(e)})

    return Handler


def submit(scanner: Scanner, path: str, body: dict, who: str) -> Job:
    if path == "/api/lockfile":
        new, old = body.get("new_lockfile"), body.get("old_lockfile") or None
        if not isinstance(new, str) or not isinstance(old, (str, type(None))):
            raise Refused(400, 'send {"new_lockfile": "...", "old_lockfile": "..."}')
        return scanner.start("lockfile", "package-lock.json", (old, new), who)
    if "tarball" in body:
        return scanner.start("tarball", "uploaded package", _tarball(body), who)
    kind, target = ("zoo", body.get("zoo")) if "zoo" in body else ("npm", body.get("package"))
    if not isinstance(target, str):
        raise Refused(400, 'send {"package": "name@version"}, {"zoo": "sample"} or {"tarball": "<base64>"}')
    return scanner.start(kind, target, None, who)


def main(host: str = "127.0.0.1", port: int = 8080) -> None:
    cfg = WebConfig()
    Path(cfg.data_dir).mkdir(parents=True, exist_ok=True)
    scan_cfg = ScanConfig(text_reviewer=AgentTextCheck.from_env())
    service = Service(Cache(os.environ.get("RH_CACHE", str(Path(cfg.data_dir) / "verdicts.sqlite3"))), scan_cfg)
    scanner = Scanner(cfg, service, Explainer.from_env())
    threading.Thread(target=scanner.serve_forever, name="scan-worker", daemon=True).start()
    server = ThreadingHTTPServer((host, port), make_handler(cfg, scanner))
    print(f"redhanded web on http://{host}:{port} (microVM tier: {'on' if scan_cfg.microvm_ready() else 'off'})", flush=True)
    server.serve_forever()
