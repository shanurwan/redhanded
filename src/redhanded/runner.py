"""Detonate one npm package in a baited gVisor sandbox wired only to the sinkhole.

Two halves. The outer half runs as an ordinary user: it fetches and verifies
the package, plants the bait, then reads the logs and decides. The inner half
runs under `unshare -rn` (root only inside a fresh user namespace) and builds
two network namespaces: one for the sandbox, whose only route leads to the
other, where the sinkhole listens and from which there is no route at all.
"""
from __future__ import annotations

import base64
import glob
import hashlib
import io
import json
import os
import posixpath
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .evidence import build
from .honeytokens import HoneytokenSet
from .sinkhole import Capture, NamePool, Record
from .trace import parse
from .verdict import decide

SANDBOX_IP = "172.31.255.2"
GATEWAY_IP = "172.31.255.1"
RESOLVER_IP = "10.66.0.1"
POOL_NET = "10.66.0.0/16"
METADATA_IP = "169.254.169.254"
HOME = "/home/dev"
WORK = "/work"
MAX_TARBALL = 50 << 20
MAX_UNPACKED = 200 << 20
MAX_FILES = 20_000

_HARNESS = """\
cd /work
echo "== lifecycle scripts"
npm rebuild "$RH_PACKAGE" --foreground-scripts --ignore-scripts=false
echo "== exit $?"
echo "== load"
node /work/.rh/load.js "$RH_PACKAGE"
echo "== exit $?"
"""
_LOADER = """\
// Load the package the way an application would, so import-time code runs.
const name = process.argv[2];
try { require(name); console.log("loaded"); }
catch (e) { console.log("load failed: " + (e && e.code || e)); }
setTimeout(() => process.exit(0), 3000);   // give timers and pending sockets a moment
"""


class ScanError(RuntimeError):
    pass


def _env_path(var: str, default: str) -> str:
    return os.path.expanduser(os.environ.get(var, default))


@dataclass
class ScanConfig:
    runsc: str = field(default_factory=lambda: _env_path("RH_RUNSC", "~/bin/runsc"))
    rootfs: str = field(default_factory=lambda: _env_path("RH_ROOTFS", "~/rh-dev/rootfs"))
    scans_dir: str = field(default_factory=lambda: _env_path("RH_SCANS", "~/rh-dev/scans"))
    registry: str = "https://registry.npmjs.org"
    deadline_s: float = 120.0


# ---------------------------------------------------------------- fetch

def _get(url: str, limit: int) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "redhanded"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise ScanError(f"{url} is larger than {limit} bytes")
    return data


def check_integrity(data: bytes, integrity: str) -> None:
    algo, _, want = integrity.partition("-")
    if algo != "sha512":
        raise ScanError(f"refusing integrity algorithm {algo!r}; need sha512")
    got = base64.b64encode(hashlib.sha512(data).digest()).decode()
    if got != want:
        raise ScanError("tarball does not match its sha512 integrity")


def safe_unpack(data: bytes, dest: Path) -> int:
    """Unpack an npm tarball into dest, stripping the top folder. Rejects anything odd."""
    dest.mkdir(parents=True, exist_ok=True)
    total = files = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar:
            parts = m.name.split("/", 1)
            rel = posixpath.normpath(parts[1]) if len(parts) == 2 else ""
            if not rel or rel == ".":
                continue
            if rel.startswith(("/", "../")) or rel == ".." or "\x00" in rel:
                raise ScanError(f"unsafe path in tarball: {m.name!r}")
            target = dest / rel
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not m.isfile():
                continue                       # links and devices are never extracted
            files += 1
            total += m.size
            if files > MAX_FILES or total > MAX_UNPACKED:
                raise ScanError("tarball unpacks too large")
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(m)
            with open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            os.chmod(target, 0o755 if m.mode & 0o111 else 0o644)
    return files


def fetch(name: str, version: str, registry: str, want_integrity: str | None = None) -> tuple[dict, bytes]:
    meta = json.loads(_get(f"{registry}/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(version)}", 5 << 20))
    dist = meta.get("dist", {})
    integrity = dist.get("integrity", "")
    if want_integrity and want_integrity != integrity:
        raise ScanError("registry integrity differs from the lockfile")
    data = _get(dist["tarball"], MAX_TARBALL)
    check_integrity(data, integrity)
    return meta, data


# ---------------------------------------------------------------- prepare

def _spec(scan: Path, name: str, tokens: HoneytokenSet) -> dict:
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": HOME,
        "USER": "dev",
        "RH_PACKAGE": name,
        "CI": "true",
        "npm_config_cache": f"{HOME}/.npm",
        "npm_config_userconfig": "/dev/null",   # npm itself never reads the bait .npmrc
        "npm_config_update_notifier": "false",
        "npm_config_fund": "false",
        "npm_config_audit": "false",
        **tokens.env(),
    }
    bind = lambda src, dst, ro=False: {"destination": dst, "type": "bind", "source": str(src),
                                       "options": ["rbind", "ro" if ro else "rw"]}
    return {
        "ociVersion": "1.0.0",
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh", f"{WORK}/.rh/run.sh"],
            "env": [f"{k}={v}" for k, v in env.items()],
            "cwd": WORK,
            "capabilities": {k: [] for k in ("bounding", "effective", "inheritable", "permitted", "ambient")},
            "noNewPrivileges": True,
        },
        "root": {"path": "", "readonly": False},      # set by prepare()
        "hostname": "dev-laptop",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "mode=755"]},
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev"]},
            bind(scan / "home", HOME),
            bind(scan / "work", WORK),
            bind(scan / "resolv.conf", "/etc/resolv.conf", ro=True),
        ],
        "linux": {
            "namespaces": [{"type": t} for t in ("pid", "ipc", "uts", "mount")]
                          + [{"type": "network", "path": "NETNS"}],
        },
    }


def prepare(scan: Path, name: str, version: str, tarball: bytes, tokens: HoneytokenSet, rootfs: str) -> None:
    for d in ("home", "work/node_modules", "work/.rh", "bundle", "log", "state"):
        (scan / d).mkdir(parents=True, exist_ok=True)
    safe_unpack(tarball, scan / "work" / "node_modules" / name)
    (scan / "work" / "package.json").write_text(json.dumps(
        {"name": "rh-scan", "version": "0.0.0", "private": True, "dependencies": {name: version}}))
    (scan / "work" / ".rh" / "run.sh").write_text(_HARNESS)
    (scan / "work" / ".rh" / "load.js").write_text(_LOADER)
    (scan / "resolv.conf").write_text(f"nameserver {RESOLVER_IP}\n")
    tokens.plant(scan / "home")
    (scan / "metadata.json").write_text(json.dumps(tokens.metadata_credentials()))
    spec = _spec(scan, name, tokens)
    spec["root"]["path"] = rootfs
    (scan / "bundle" / "config.json").write_text(json.dumps(spec, indent=1))


# ---------------------------------------------------------------- inner (inside unshare -rn)

def _sh(*cmd: str) -> None:
    subprocess.run(cmd, check=True, capture_output=True, timeout=20)


def inner(scan: Path, runsc: str, deadline_s: float) -> int:
    result = {"deadline_killed": False, "exit_code": None, "errors": []}
    holder = sink = None
    started = time.monotonic()
    try:
        _sh("ip", "link", "set", "lo", "up")
        holder = subprocess.Popen(["unshare", "-n", "sleep", str(int(deadline_s) + 120)])
        k = str(holder.pid)
        for _ in range(50):
            if os.readlink(f"/proc/{k}/ns/net") != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(0.02)
        _sh("ip", "link", "add", "rh0", "type", "veth", "peer", "name", "rh1")
        _sh("ip", "link", "set", "rh1", "netns", k)
        _sh("ip", "addr", "add", f"{SANDBOX_IP}/30", "dev", "rh0")
        _sh("ip", "link", "set", "rh0", "up")
        _sh("ip", "route", "add", "default", "via", GATEWAY_IP)
        ns = ("nsenter", "-t", k, "-n")
        _sh(*ns, "ip", "link", "set", "lo", "up")
        _sh(*ns, "ip", "addr", "add", f"{GATEWAY_IP}/30", "dev", "rh1")
        _sh(*ns, "ip", "link", "set", "rh1", "up")
        _sh(*ns, "ip", "route", "add", "local", POOL_NET, "dev", "lo")
        _sh(*ns, "ip", "route", "add", "local", f"{METADATA_IP}/32", "dev", "lo")
        _sh(*ns, "ip", "addr", "add", f"{RESOLVER_IP}/32", "dev", "lo")

        ready = scan / "sinkhole.ready"
        sink = subprocess.Popen([*ns, sys.executable, "-m", "redhanded.sinkhole",
                                 "--capture", str(scan / "capture.jsonl"),
                                 "--metadata", str(scan / "metadata.json"), "--ready", str(ready)],
                                stdout=open(scan / "log" / "sinkhole.out", "wb"), stderr=subprocess.STDOUT)
        for _ in range(250):
            if ready.exists():
                break
            time.sleep(0.02)
        else:
            raise ScanError("sinkhole did not start")

        cfg_path = scan / "bundle" / "config.json"
        cfg = json.loads(cfg_path.read_text())
        cfg["linux"]["namespaces"][-1]["path"] = f"/proc/{os.getpid()}/ns/net"
        cfg_path.write_text(json.dumps(cfg, indent=1))

        cid = scan.name
        base = [runsc, "--root", str(scan / "state"), "--ignore-cgroups", "--network=sandbox",
                "--overlay2=all:memory", "--strace", "--strace-log-size=4096",
                "--debug", f"--debug-log={scan / 'log'}/"]
        proc = subprocess.Popen([*base, "run", "--bundle", str(scan / "bundle"), cid],
                                stdout=open(scan / "log" / "sandbox.out", "wb"), stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            result["exit_code"] = proc.wait(timeout=max(deadline_s - (time.monotonic() - started), 1))
        except subprocess.TimeoutExpired:
            result["deadline_killed"] = True
            subprocess.run([*base, "kill", "--all", cid, "KILL"], capture_output=True, timeout=10)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
        subprocess.run([*base, "delete", "--force", cid], capture_output=True, timeout=20)
    except (ScanError, subprocess.SubprocessError, OSError) as e:
        result["errors"].append(str(e))
    finally:
        if sink and sink.poll() is None:
            sink.send_signal(signal.SIGTERM)
            try:
                sink.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sink.kill()
        if holder and holder.poll() is None:
            holder.kill()
        result["seconds"] = round(time.monotonic() - started, 2)
        (scan / "inner.json").write_text(json.dumps(result))
    return 0 if not result["errors"] else 1


# ---------------------------------------------------------------- outer

@dataclass
class Report:
    scan_id: str
    package: str
    version: str
    integrity: str
    verdict: str
    reasons: list[str]
    container_aware: bool
    seconds: float
    evidence: dict = field(default_factory=dict)
    sandbox: dict = field(default_factory=dict)


def pack_dir(src: Path) -> tuple[str, str, bytes]:
    """Pack a local package folder the way `npm pack` lays it out. Returns (name, version, tarball)."""
    manifest = json.loads((src / "package.json").read_text(encoding="utf-8"))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(src.rglob("*")):
            if path.is_file() and not path.is_symlink() and "node_modules" not in path.parts:
                tar.add(path, arcname="package/" + path.relative_to(src).as_posix(), recursive=False)
    return manifest["name"], manifest["version"], buf.getvalue()


def scan(name: str, version: str, cfg: ScanConfig | None = None, want_integrity: str | None = None) -> Report:
    cfg = cfg or ScanConfig()
    meta, tarball = fetch(name, version, cfg.registry, want_integrity)
    return detonate(name, version, tarball, meta["dist"]["integrity"], cfg)


def scan_local(src: Path, cfg: ScanConfig | None = None) -> Report:
    name, version, tarball = pack_dir(src)
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    return detonate(name, version, tarball, integrity, cfg or ScanConfig())


def detonate(name: str, version: str, tarball: bytes, integrity: str, cfg: ScanConfig) -> Report:
    started = time.monotonic()
    scan_id = f"rh-{time.strftime('%Y%m%d-%H%M%S')}-{os.urandom(3).hex()}"
    scan_dir = Path(cfg.scans_dir) / scan_id
    tokens = HoneytokenSet.generate(scan_id)
    prepare(scan_dir, name, version, tarball, tokens, cfg.rootfs)

    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    inner_cmd = ["unshare", "-rn", sys.executable, "-m", "redhanded.runner", "inner",
                 str(scan_dir), cfg.runsc, str(cfg.deadline_s)]
    try:
        subprocess.run(inner_cmd, env=env, timeout=cfg.deadline_s + 90, capture_output=True)
    except subprocess.TimeoutExpired:
        pass
    inner_result = json.loads((scan_dir / "inner.json").read_text()) if (scan_dir / "inner.json").exists() \
        else {"errors": ["sandbox supervisor did not report"], "deadline_killed": True}

    lines: list[str] = []
    for path in sorted(glob.glob(str(scan_dir / "log" / "*.boot.txt"))):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines.extend(f)
    trace = parse(lines)
    cap = scan_dir / "capture.jsonl"
    records = [Record.from_json(l) for l in cap.read_text().splitlines()] if cap.exists() else []
    pool = NamePool.from_records(records)
    ev = build(trace, records, pool, tokens, HOME, f"{WORK}/node_modules/{name}", RESOLVER_IP)
    ev.deadline_killed = bool(inner_result.get("deadline_killed"))
    ev.incomplete.extend(inner_result.get("errors", []))
    if trace.lines == 0:
        ev.incomplete.append("no syscall log from the sandbox")
    decision = decide(ev)

    report = Report(
        scan_id=scan_id, package=name, version=version, integrity=integrity,
        verdict=decision.label, reasons=list(decision.reasons), container_aware=decision.container_aware,
        seconds=round(time.monotonic() - started, 2),
        evidence={k: v for k, v in asdict(ev).items() if k != "stats"} | {"stats_count": len(ev.stats)},
        sandbox={**inner_result, "syscall_lines": trace.lines, "unparsed": trace.unparsed,
                 "sinkhole_records": len(records)},
    )
    (scan_dir / "report.json").write_text(json.dumps(asdict(report), indent=1))
    return report


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["inner"]:
        return inner(Path(argv[1]), argv[2], float(argv[3]))
    raise SystemExit("usage: python -m redhanded.runner inner <scan_dir> <runsc> <deadline_s>")


if __name__ == "__main__":
    raise SystemExit(main())
