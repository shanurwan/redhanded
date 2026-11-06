"""The demo site: recorded catches to replay, and a live scan anyone can start.

One process, standard library only. Scans run one at a time on a single worker
thread, behind a short queue, a per-address rate limit and the spend guard, so
a busy demo slows down instead of running up a bill. Every page is built from
the same files a scan writes, and those files can be downloaded, so a replay
is checkable rather than a recording of a screen.
"""
from __future__ import annotations

import collections
import gzip
import glob
import json
import os
import queue
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Callable

from . import __version__
from .explain import Explainer
from .runner import ScanConfig, ScanError, _get, scan_local
from .service import SCAN_ID, Cache, InputError, Service, validate
from .spend import GuardState, StateFile
from .verdict import RULES_VERSION

JOB_ID = re.compile(r"^[0-9a-f]{16}$")
ZOO_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SCAN_FILES = {"report.json": "application/json", "capture.jsonl": "application/x-ndjson",
              "explain.json": "application/json", "syscalls-excerpt.txt": "text/plain; charset=utf-8"}
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8")}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; base-uri 'none'; "
                               "form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
MAX_BODY = 4096


@dataclass
class WebConfig:
    data_dir: str = field(default_factory=lambda: os.path.expanduser(os.environ.get("RH_WEB_DATA", "~/rh-dev/web")))
    replays_dir: str = field(default_factory=lambda: os.environ.get("RH_REPLAYS", "replays"))
    zoo_dir: str = field(default_factory=lambda: os.environ.get("RH_ZOO", "zoo"))
    guard_state: str = field(default_factory=lambda: os.path.expanduser(
        os.environ.get("RH_GUARD_STATE", "~/rh-dev/web/guard-state.json")))
    host_label: str = field(default_factory=lambda: os.environ.get("RH_HOST_LABEL", "dev server"))
    trust_proxy: bool = field(default_factory=lambda: os.environ.get("RH_TRUST_PROXY") == "1")
    scans_per_hour: int = field(default_factory=lambda: int(os.environ.get("RH_SCANS_PER_HOUR", "12")))
    max_queue: int = 8


@dataclass
class Job:
    id: str
    kind: str                 # npm | zoo
    target: str
    state: str = "queued"     # queued | running | done | error
    created: float = field(default_factory=time.time)
    scan_id: str | None = None
    verdict: str | None = None
    cached: bool = False
    error: str | None = None


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

    def __init__(self, cfg: WebConfig, service: Service, explainer: Explainer | None,
                 local_scan: Callable = scan_local, clock: Callable[[], float] = time.time):
        self.cfg, self.service, self.explainer = cfg, service, explainer
        self._local_scan, self._clock = local_scan, clock
        self.jobs: dict[str, Job] = {}
        self._queue: queue.Queue[Job] = queue.Queue(maxsize=cfg.max_queue)
        self._lock = threading.Lock()

    def guard_allows(self) -> bool:
        # Fails closed: a missing or stale guard state means no scans.
        return StateFile(self.cfg.guard_state).allows(GuardState.STOP_TIER2, self._clock())

    def submit(self, kind: str, target: str) -> Job:
        if kind == "zoo":
            if not (ZOO_NAME.match(target) and (Path(self.cfg.zoo_dir) / target / "package.json").is_file()):
                raise InputError(f"no Zoo sample called {target!r}")
        else:
            target = target.strip()
            if not 0 < len(target) <= 260:
                raise InputError("give a package like left-pad or left-pad@1.3.0")
        job = Job(id=secrets.token_hex(8), kind=kind, target=target)
        try:
            self._queue.put_nowait(job)
        except queue.Full:
            raise InputError("the scan queue is full; try again in a minute") from None
        with self._lock:
            self.jobs[job.id] = job
            self._forget_old()
        return job

    def position(self, job: Job) -> int:
        with self._lock:
            return sum(1 for j in self.jobs.values() if j.state == "queued" and j.created < job.created)

    def _forget_old(self) -> None:
        cutoff = self._clock() - 6 * 3600
        for jid in [j.id for j in self.jobs.values() if j.created < cutoff and j.state in ("done", "error")]:
            del self.jobs[jid]

    def run_one(self, job: Job) -> None:
        job.state = "running"
        try:
            if not self.guard_allows():
                raise ScanError("live scans are paused by the spend guard")
            if job.kind == "zoo":
                report = asdict(self._local_scan(Path(self.cfg.zoo_dir) / job.target, self.service.cfg))
                job.scan_id, job.verdict = report["scan_id"], report["verdict"]
            else:
                name, version = resolve_spec(job.target, self.service.cfg.registry)
                answer = self.service.check(name, version)
                job.scan_id, job.verdict, job.cached = answer["scan_id"], answer["verdict"], answer["cached"]
            if self.explainer and job.scan_id:
                write_explanation(Path(self.service.cfg.scans_dir) / job.scan_id, self.explainer)
            job.state = "done"
        except (InputError, ScanError) as e:
            job.state, job.error = "error", str(e)
        except Exception as e:  # never let one bad job stop the worker
            job.state, job.error = "error", f"scan failed ({type(e).__name__})"

    def serve_forever(self) -> None:
        while True:
            self.run_one(self._queue.get())


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


def load_capture(scan_dir: Path, limit: int = 200) -> list[dict]:
    path = scan_dir / "capture.jsonl"
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines()[:limit]:
        r = json.loads(line)
        out.append({k: r.get(k) for k in ("kind", "at", "host", "detail", "headers")} | {"bytes": r.get("data", "")})
    return out


def scan_view(scan_dir: Path) -> dict:
    report = json.loads((scan_dir / "report.json").read_text())
    meta_path, explain_path = scan_dir / "meta.json", scan_dir / "explain.json"
    files = [n for n in SCAN_FILES if (scan_dir / n).is_file()]
    if glob.glob(str(scan_dir / "log" / "*.boot.txt")):
        files.append("syscalls.log.gz")
    return {
        "report": report,
        "capture": load_capture(scan_dir),
        "explanation": json.loads(explain_path.read_text()) if explain_path.is_file() else None,
        "meta": json.loads(meta_path.read_text()) if meta_path.is_file() else None,
        "files": files,
    }


def list_replays(replays_dir: str) -> list[dict]:
    out = []
    for meta_path in sorted(Path(replays_dir).glob("rh-*/meta.json")):
        meta = json.loads(meta_path.read_text())
        report = json.loads((meta_path.parent / "report.json").read_text())
        out.append({"scan_id": report["scan_id"], "package": report["package"], "version": report["version"],
                    "verdict": report["verdict"], "title": meta.get("title", report["package"]),
                    "summary": meta.get("summary", ""), "order": meta.get("order", 99)})
    return sorted(out, key=lambda r: (r["order"], r["scan_id"]))


def make_handler(cfg: WebConfig, scanner: Scanner, limiter: RateLimit):
    roots = [cfg.replays_dir, scanner.service.cfg.scans_dir]

    class Handler(BaseHTTPRequestHandler):
        server_version = f"redhanded/{__version__}"
        sys_version = ""

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
                return self.json(200, {"ok": True})
            if path == "/api/status":
                return self.json(200, {"version": __version__, "rules": RULES_VERSION, "host": cfg.host_label,
                                       "scans_open": scanner.guard_allows(),
                                       "queued": scanner._queue.qsize(),
                                       "zoo": sorted(p.parent.name for p in Path(cfg.zoo_dir).glob("*/package.json")),
                                       "explainer": scanner.explainer.model if scanner.explainer else None})
            if path == "/api/replays":
                return self.json(200, list_replays(cfg.replays_dir))
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[:2] == ["api", "jobs"] and JOB_ID.match(parts[2]):
                job = scanner.jobs.get(parts[2])
                if not job:
                    return self.json(404, {"error": "no such job"})
                return self.json(200, asdict(job) | {"ahead": scanner.position(job) if job.state == "queued" else 0})
            if len(parts) >= 3 and parts[:2] == ["api", "scans"]:
                scan_dir = find_scan(parts[2], roots)
                if not scan_dir:
                    return self.json(404, {"error": "no such scan"})
                if len(parts) == 3:
                    return self.json(200, scan_view(scan_dir))
                if len(parts) == 5 and parts[3] == "files":
                    return self.file(scan_dir, parts[4])
            self.json(404, {"error": "not found"})

        def file(self, scan_dir: Path, name: str) -> None:
            disposition = {"Content-Disposition": f'attachment; filename="{scan_dir.name}-{name}"'}
            if name in SCAN_FILES and (scan_dir / name).is_file():
                return self.send(200, (scan_dir / name).read_bytes(), SCAN_FILES[name], disposition)
            logs = sorted(glob.glob(str(scan_dir / "log" / "*.boot.txt")))
            if name == "syscalls.log.gz" and logs:
                body = gzip.compress(b"".join(Path(p).read_bytes() for p in logs), compresslevel=6)
                return self.send(200, body, "application/gzip", disposition)
            self.json(404, {"error": "no such file"})

        def do_POST(self):
            if urllib.parse.urlsplit(self.path).path != "/api/scan":
                return self.json(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= MAX_BODY:
                return self.json(413, {"error": "request too large"})
            try:
                body = json.loads(self.rfile.read(length))
                kind, target = ("zoo", body["zoo"]) if "zoo" in body else ("npm", body["package"])
                if not isinstance(target, str):
                    raise KeyError
            except (ValueError, KeyError, TypeError):
                return self.json(400, {"error": 'send {"package": "name@version"} or {"zoo": "sample"}'})
            if not scanner.guard_allows():
                return self.json(503, {"error": "live scans are paused by the spend guard; replays still work"})
            if not limiter.take(self.client()):
                return self.json(429, {"error": f"limit is {cfg.scans_per_hour} live scans an hour per address"})
            try:
                job = scanner.submit(kind, target)
            except InputError as e:
                return self.json(400, {"error": str(e)})
            self.json(HTTPStatus.ACCEPTED, {"job": job.id})

    return Handler


def main(host: str = "127.0.0.1", port: int = 8080) -> None:
    cfg = WebConfig()
    Path(cfg.data_dir).mkdir(parents=True, exist_ok=True)
    scan_cfg = ScanConfig()
    service = Service(Cache(os.environ.get("RH_CACHE", str(Path(cfg.data_dir) / "verdicts.sqlite3"))), scan_cfg)
    scanner = Scanner(cfg, service, Explainer.from_env())
    threading.Thread(target=scanner.serve_forever, name="scan-worker", daemon=True).start()
    server = ThreadingHTTPServer((host, port), make_handler(cfg, scanner, RateLimit(cfg.scans_per_hour)))
    print(f"redhanded web on http://{host}:{port} (replays: {cfg.replays_dir}, scans: {scan_cfg.scans_dir})",
          flush=True)
    server.serve_forever()
