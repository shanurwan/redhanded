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
import re
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
from typing import Callable

from .agenttext import read_package_text
from .evidence import build
from .behaviour import manifest_summary
from .honeytokens import AI_TOOL_DIR, HoneytokenSet, plant_ai_tools
from .sinkhole import Capture, NamePool, Record, make_ca
from .trace import parse
from .verdict import Verdict, combine_microvm, decide, flag_agent_text

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
MAX_DEPS = 400 << 20
_PLAIN_RANGE = re.compile(r"^[\^~<>=* ]*[0-9x*][0-9A-Za-z.\-+* |<>=^~]*$|^latest$|^\*$")
_PLAIN_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")

_HARNESS = """\
cd /work
export NODE_OPTIONS=--require=/work/.rh/stub.js
echo "== lifecycle scripts"
npm rebuild --foreground-scripts --ignore-scripts=false
echo "== exit $?"
echo "== load"
node /work/.rh/load.js "$RH_PACKAGE"
echo "== exit $?"
"""
# Old malware often dies on a dependency that was since removed from npm, before it does anything.
# Only code inside the package tree gets a stand-in, so npm's own optional requires still fail normally.
STUB = """\
const Module = require("module");
const load = Module._load;
function standIn() {
  const fn = function () { return proxy; };
  const proxy = new Proxy(fn, {
    get: (t, k) => (k === Symbol.toPrimitive ? () => "" : k === "then" || k === "__esModule" ? undefined : k === "prototype" ? t.prototype : proxy),
    apply: () => proxy,
    construct: () => proxy,
  });
  return proxy;
}
Module._load = function (request, parent, isMain) {
  try { return load.call(this, request, parent, isMain); }
  catch (e) {
    const from = (parent && parent.filename) || "";
    if (e && e.code === "MODULE_NOT_FOUND" && !/^[./]|^node:/.test(request) && from.includes("/node_modules/") && !from.startsWith("/usr/local/lib/node_modules/")) return standIn();
    throw e;
  }
};
// The same for import. A named import from a stand-in still fails to link: this covers default imports.
if (Module.registerHooks) {
  Module.registerHooks({
    resolve(specifier, context, next) {
      try { return next(specifier, context); }
      catch (e) {
        const from = context.parentURL || "";
        if (e && e.code === "ERR_MODULE_NOT_FOUND" && !/^[./]|^node:|^file:|^data:/.test(specifier) && from.includes("/node_modules/") && !from.includes("/usr/local/lib/node_modules/")) {
          return { url: "data:text/javascript,const f=function(){return p};const p=new Proxy(f,{get:(t,k)=>k===Symbol.toPrimitive?()=>'':k==='then'?undefined:p,apply:()=>p,construct:()=>p});export default p;", shortCircuit: true };
        }
        throw e;
      }
    },
  });
}
"""
_LOADER = """\
// Use the package the way an application would, so code behind an import or a call runs.
const { spawnSync } = require("child_process");
const path = require("path");
const name = process.argv[2];
const root = path.join("/work/node_modules", name);
const run = spawnSync(process.execPath, ["/work/.rh/exercise.js", name], { encoding: "utf8", timeout: 8000, maxBuffer: 1 << 22 });
process.stdout.write((run.stdout || "") + (run.stderr || ""));
if (run.error && run.error.code === "ETIMEDOUT" && !/^(loaded|load failed)/m.test(run.stdout || "")) console.log("RH-LOAD-HANG");
let pkg = {};
try { pkg = require(path.join(root, "package.json")); } catch (e) {}
const bins = typeof pkg.bin === "string" ? [pkg.bin] : Object.values(pkg.bin || {});
for (const bin of bins.slice(0, 3)) {
  spawnSync(process.execPath, [path.join(root, String(bin)), "--help"], { stdio: "inherit", timeout: 4000 });
}
"""
_EXERCISER = """\
const name = process.argv[2];
process.on("uncaughtException", () => {});
process.on("unhandledRejection", () => {});
function exercise(mod) {
  const seen = new Set();
  const call = (fn) => { try { const r = fn(); if (r && r.catch) r.catch(() => {}); } catch (e) {} };
  const targets = typeof mod === "function" ? [mod] : [];
  for (const key of Object.keys(mod || {}).slice(0, 40)) {
    let v; try { v = mod[key]; } catch (e) { continue; }
    if (typeof v === "function" && !seen.has(v)) { seen.add(v); targets.push(v); }
  }
  targets.forEach(call);
  console.log("exercised " + targets.length);
}
(async () => {
  let mod;
  try { mod = require(name); console.log("loaded"); }
  catch (e) {
    try { mod = await import(name); console.log("loaded"); }
    catch (e2) { console.log("load failed: " + (e2 && e2.code || e2)); }
  }
  if (mod) exercise(mod);
  setTimeout(() => process.exit(0), 3000);   // give timers and pending sockets a moment
})();
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
    fc_bin: str = field(default_factory=lambda: _env_path("RH_FC_BIN", ""))
    fc_kernel: str = field(default_factory=lambda: _env_path("RH_FC_KERNEL", ""))
    fc_rootfs: str = field(default_factory=lambda: _env_path("RH_FC_ROOTFS", ""))
    text_reviewer: Callable[[str], bool] | None = None

    def microvm_ready(self) -> bool:
        return all(p and os.path.isfile(p) for p in (self.fc_bin, self.fc_kernel, self.fc_rootfs)) \
            and os.access("/dev/kvm", os.R_OK | os.W_OK)


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
        "PATH": f"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:{HOME}/{AI_TOOL_DIR}",
        "HOME": HOME,
        "USER": "dev",
        "RH_PACKAGE": name,
        "HOSTNAME": tokens.machine_name or "dev-laptop",
        "NODE_EXTRA_CA_CERTS": "/etc/ssl/certs/ca-certificates.crt",
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
        "hostname": tokens.machine_name or "dev-laptop",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "mode=755"]},
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev"]},
            bind(scan / "home", HOME),
            bind(scan / "work", WORK),
            bind(scan / "resolv.conf", "/etc/resolv.conf", ro=True),
            *([bind(scan / "ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt", ro=True)] if (scan / "ca-bundle.crt").is_file() else []),
        ],
        "linux": {
            "namespaces": [{"type": t} for t in ("pid", "ipc", "uts", "mount")]
                          + [{"type": "network", "path": "NETNS"}],
        },
    }


def fetch_deps(tarball: bytes, into: Path, rootfs: str, registry: str, timeout: float = 150.0) -> str:
    """The package's registry dependencies, fetched outside the sandbox with scripts off.

    Scanned alone, real malware dies on `Cannot find module 'axios'` before it does anything.
    Only plain version ranges are kept: no git, URL, file or alias specs. Returns a short note.
    """
    node = Path(rootfs) / "usr/local/bin/node"
    cli = Path(rootfs) / "usr/local/lib/node_modules/npm/bin/npm-cli.js"
    if not (node.is_file() and cli.is_file()):
        return "no npm available"
    try:
        with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
            member = next((m for m in tar if m.isfile() and m.name.count("/") == 1 and m.name.endswith("/package.json")), None)
            manifest = json.loads(tar.extractfile(member).read()) if member else {}
    except (tarfile.TarError, OSError, ValueError, EOFError):
        return "unreadable manifest"
    wanted = {k: v for k, v in (manifest.get("dependencies") or {}).items()
              if isinstance(v, str) and _PLAIN_RANGE.match(v) and _PLAIN_NAME.match(k)}
    if not wanted:
        return "no dependencies"
    into.mkdir(parents=True, exist_ok=True)
    (into / "package.json").write_text(json.dumps({"name": "rh-deps", "version": "0.0.0", "private": True, "dependencies": wanted}))
    env = {"PATH": "/usr/bin:/bin", "HOME": str(into), "npm_config_cache": str(into / ".npm"), "npm_config_registry": registry,
           "npm_config_ignore_scripts": "true", "npm_config_update_notifier": "false"}
    try:
        p = subprocess.run([str(node), str(cli), "install", "--ignore-scripts", "--omit=dev", "--omit=optional", "--omit=peer", "--no-audit",
                            "--no-fund", "--no-package-lock", "--loglevel=error"],
                           cwd=into, env=env, capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        shutil.rmtree(into / "node_modules", ignore_errors=True)
        return "dependency fetch timed out"
    shutil.rmtree(into / ".npm", ignore_errors=True)
    size = sum(f.stat().st_size for f in (into / "node_modules").rglob("*") if f.is_file() and not f.is_symlink()) if (into / "node_modules").is_dir() else 0
    if size > MAX_DEPS:
        shutil.rmtree(into / "node_modules", ignore_errors=True)
        return "dependencies over the size limit"
    if p.returncode == 0:
        return f"{len(wanted)} dependencies fetched"
    fetched = 0
    for dep, spec in list(wanted.items())[:25]:
        (into / "package.json").write_text(json.dumps({"name": "rh-deps", "version": "0.0.0", "private": True, "dependencies": {dep: spec}}))
        try:
            one = subprocess.run([str(node), str(cli), "install", "--ignore-scripts", "--omit=dev", "--omit=optional", "--omit=peer", "--no-audit", "--no-fund",
                                  "--no-package-lock", "--no-save", "--loglevel=error"], cwd=into, env=env, capture_output=True, timeout=45)
            fetched += one.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            pass
    shutil.rmtree(into / ".npm", ignore_errors=True)
    return f"{fetched} of {len(wanted)} dependencies available"


def trust_bundle(scan: Path, trust_from: str) -> None:
    """The sandbox trusts this scan's root, the way a laptop behind a corporate proxy does."""
    try:
        ca = make_ca(scan / "tls")
    except (subprocess.SubprocessError, OSError):
        return
    base = Path(trust_from) / "etc/ssl/certs/ca-certificates.crt"
    (scan / "ca-bundle.crt").write_bytes((base.read_bytes() if base.is_file() else b"") + ca.read_bytes())


def prepare(scan: Path, name: str, version: str, tarball: bytes, tokens: HoneytokenSet, rootfs: str, deps: Path | None = None,
            trust_from: str | None = None) -> None:
    for d in ("home", "work/node_modules", "work/.rh", "bundle", "log", "state"):
        (scan / d).mkdir(parents=True, exist_ok=True)
    safe_unpack(tarball, scan / "work" / "node_modules" / name)
    (scan / "work" / "package.json").write_text(json.dumps(
        {"name": "rh-scan", "version": "0.0.0", "private": True, "dependencies": {name: version}}))
    (scan / "work" / ".rh" / "run.sh").write_text(_HARNESS)
    (scan / "work" / ".rh" / "load.js").write_text(_LOADER)
    (scan / "work" / ".rh" / "exercise.js").write_text(_EXERCISER)
    (scan / "work" / ".rh" / "stub.js").write_text(STUB)
    if deps and (deps / "node_modules").is_dir():
        # cp, not move: the second tier uses the same tree. Never over the package under test.
        for entry in (deps / "node_modules").iterdir():
            target = scan / "work" / "node_modules" / entry.name
            if entry.name.startswith("@"):
                target.mkdir(exist_ok=True)
                for sub_entry in entry.iterdir():
                    if not (target / sub_entry.name).exists():
                        subprocess.run(["cp", "-a", str(sub_entry), str(target)], check=False, capture_output=True, timeout=120)
            elif not target.exists():
                subprocess.run(["cp", "-a", str(entry), str(target)], check=False, capture_output=True, timeout=120)
    (scan / "resolv.conf").write_text(f"nameserver {RESOLVER_IP}\n")
    trust_bundle(scan, trust_from or rootfs)
    tokens.plant(scan / "home")
    plant_ai_tools(scan / "home")
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
                                 "--metadata", str(scan / "metadata.json"), "--ready", str(ready),
                                 *(["--tls-dir", str(scan / "tls")] if (scan / "tls").is_dir() else []),
                                 *(["--mirror", os.environ["RH_MIRROR"]] if os.environ.get("RH_MIRROR") else []),
                                 *(["--model-socket", str(scan / "model.sock")] if (scan / "model.sock").exists() else [])],
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
    microvm: dict | None = None
    manifest: dict = field(default_factory=dict)
    agent: dict | None = None


def _read_manifest(path: Path) -> dict:
    try:
        return manifest_summary(json.loads(path.read_text(encoding="utf-8", errors="replace")))
    except (OSError, ValueError):
        return {}


def tarball_identity(data: bytes) -> tuple[str, str]:
    """(name, version) from an npm-layout tarball, without unpacking it."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar:
                if member.isfile() and member.name.count("/") == 1 and member.name.endswith("/package.json") \
                        and member.size <= 1 << 20:
                    manifest = json.loads(tar.extractfile(member).read())
                    return str(manifest.get("name", "")), str(manifest.get("version", ""))
    except (tarfile.TarError, OSError, ValueError, EOFError) as e:
        raise ScanError(f"not a package tarball: {e}") from e
    raise ScanError("no package.json at the top of the tarball")


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


def detonate(name: str, version: str, tarball: bytes, integrity: str, cfg: ScanConfig, mode=None) -> Report:
    """`mode` is what changes when the thing under test is an agent skill rather than a package."""
    started = time.monotonic()
    scan_id = f"rh-{time.strftime('%Y%m%d-%H%M%S')}-{os.urandom(3).hex()}"
    scan_dir = Path(cfg.scans_dir) / scan_id
    tokens = HoneytokenSet.generate(scan_id)
    deps = scan_dir / "deps"
    deps_note = fetch_deps(tarball, deps, cfg.rootfs, cfg.registry)
    prepare(scan_dir, name, version, tarball, tokens, cfg.rootfs, deps)
    manifest = _read_manifest(scan_dir / "work" / "node_modules" / name / "package.json")
    if mode:
        mode.arm(scan_dir, tokens)

    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    inner_cmd = ["unshare", "-rn", sys.executable, "-m", "redhanded.runner", "inner",
                 str(scan_dir), cfg.runsc, str(cfg.deadline_s)]
    try:
        subprocess.run(inner_cmd, env=env, timeout=cfg.deadline_s + 90, capture_output=True)
    except subprocess.TimeoutExpired:
        pass
    if mode:
        mode.close(scan_dir)
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
    sandbox_out = scan_dir / "log" / "sandbox.out"
    if sandbox_out.is_file() and b"RH-LOAD-HANG" in sandbox_out.read_bytes()[-(1 << 20):]:
        ev.load_hang = True
    if trace.lines == 0:
        ev.incomplete.append("no syscall log from the sandbox")
    if mode:
        mode.after(ev, scan_dir)
    decision = mode.decide(ev, scan_dir) if mode else decide(ev)

    microvm = None
    # gVisor names itself in uname and dmesg, so waiting for a package to look suspicious
    # would miss the simplest evader. Every package runs twice unless it is already blocked.
    if decision.verdict < Verdict.HIGH and not ev.deadline_killed and cfg.microvm_ready():
        from . import microvm as tier2
        second = tier2.detonate(name, version, tarball, scan_dir / "microvm", cfg, deps, mode)
        decision = (mode.combine if mode else combine_microvm)(decision, ev, second.decision, second.evidence)
        microvm = second.summary()
    if cfg.text_reviewer and cfg.text_reviewer(read_package_text(scan_dir / "work" / "node_modules" / name)):
        decision = flag_agent_text(decision)

    report = Report(
        scan_id=scan_id, package=name, version=version, integrity=integrity,
        verdict=decision.label, reasons=list(decision.reasons), container_aware=decision.container_aware,
        seconds=round(time.monotonic() - started, 2),
        evidence={k: v for k, v in asdict(ev).items() if k != "stats"} | {"stats_count": len(ev.stats)},
        sandbox={**inner_result, "syscall_lines": trace.lines, "unparsed": trace.unparsed,
                 "sinkhole_records": len(records), "dependencies": deps_note},
        microvm=microvm, manifest=manifest, agent=mode.summary(scan_dir) if mode else None,
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
