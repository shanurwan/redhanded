"""Second detonation of every package: a Firecracker microVM.

gVisor names itself in uname and dmesg. The guest has its own kernel, so a package
that stays quiet under gVisor shows itself here. Its only network
device is a tap in a namespace that holds the sinkhole and nothing else, so
there is no route out. Runs without root, inside `unshare -rn`, on any host with
/dev/kvm, such as a Vultr VX1 instance.

There is no syscall log from a guest. The sinkhole is outside the guest and is
the evidence to trust. Files written and bait read are reported over the serial
console by the guest itself, so they can only add to a verdict: a package that
hides them, or stops the report, ends up no better than one that left no trace.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .evidence import build, contacted
from .honeytokens import HoneytokenSet
from .runner import GATEWAY_IP, HOME, METADATA_IP, POOL_NET, RESOLVER_IP, WORK, ScanConfig, ScanError, _spec, _sh, prepare
from .sinkhole import NamePool, Record
from .trace import TraceFacts
from .verdict import Decision, Evidence, decide

TAP = "rhtap0"
GUEST_MAC = "06:00:AC:1F:FF:02"
MAX_CONSOLE = 2 << 20
BOOT_ARGS = "console=ttyS0 quiet reboot=k panic=1 pci=off ip=off init=/sbin/rh-init"


@dataclass
class MicroVMResult:
    decision: Decision
    evidence: Evidence
    seconds: float
    sandbox: dict = field(default_factory=dict)

    def summary(self) -> dict:
        ev = {k: v for k, v in asdict(self.evidence).items() if k != "stats"}
        return {"verdict": self.decision.label, "reasons": list(self.decision.reasons),
                "seconds": self.seconds, "evidence": ev, "sandbox": self.sandbox}


def parse_console(text: str) -> tuple[list[str], list[str], bool]:
    """(files written, files read, whether the guest finished its report)."""
    writes, reads, finished = [], [], False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("RH-WRITE "):
            writes.append(line[len("RH-WRITE "):])
        elif line.startswith("RH-READ "):
            reads.append(line[len("RH-READ "):])
        elif line == "RH-REPORT-END":
            finished = True
    return writes, reads, finished


def _env_file(scan: Path, name: str, tokens: HoneytokenSet) -> None:
    env = dict(e.split("=", 1) for e in _spec(scan, name, tokens)["process"]["env"])
    (scan / "scan-fs" / "env.sh").write_text("".join(f"export {k}={shlex.quote(v)}\n" for k, v in env.items()))


def _build_scan_drive(scan: Path) -> None:
    """Package, harness and bait, as a read-only drive for the guest to copy from."""
    fs = scan / "scan-fs"
    fs.mkdir(exist_ok=True)
    os.rename(scan / "work", fs / "work")
    os.rename(scan / "home", fs / "home")
    if (scan / "ca-bundle.crt").is_file():
        shutil.copyfile(scan / "ca-bundle.crt", fs / "ca-bundle.crt")     # the certificate, never the key


def _keep_console(proc: subprocess.Popen, path: Path) -> None:
    """A guest flooding its console gets the VM killed, not the disk filled."""
    kept = 0
    with open(path, "wb") as out:
        for chunk in iter(lambda: proc.stdout.read(65536), b""):
            kept += len(chunk)
            if kept > MAX_CONSOLE:
                os.killpg(proc.pid, signal.SIGKILL)
                return
            out.write(chunk)
            out.flush()


def inner(scan: Path, deadline_s: float) -> int:
    """Runs inside `unshare -rn`. This namespace holds the tap and the sinkhole, and nothing else."""
    cfg = json.loads((scan / "vm.json").read_text())
    result = {"deadline_killed": False, "exit_code": None, "errors": []}
    sink = None
    started = time.monotonic()
    try:
        _sh("ip", "link", "set", "lo", "up")
        _sh("ip", "tuntap", "add", "dev", TAP, "mode", "tap")
        _sh("ip", "addr", "add", f"{GATEWAY_IP}/30", "dev", TAP)
        _sh("ip", "link", "set", TAP, "up")
        _sh("ip", "route", "add", "local", POOL_NET, "dev", "lo")
        _sh("ip", "route", "add", "local", f"{METADATA_IP}/32", "dev", "lo")
        _sh("ip", "addr", "add", f"{RESOLVER_IP}/32", "dev", "lo")

        ready = scan / "sinkhole.ready"
        sink = subprocess.Popen([sys.executable, "-m", "redhanded.sinkhole", "--capture", str(scan / "capture.jsonl"),
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

        proc = subprocess.Popen([cfg["firecracker"], "--no-api", "--config-file", str(scan / "fc.json")],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True)
        threading.Thread(target=_keep_console, args=(proc, scan / "log" / "console.txt"), daemon=True).start()
        try:
            result["exit_code"] = proc.wait(timeout=max(deadline_s - (time.monotonic() - started), 1))
        except subprocess.TimeoutExpired:
            result["deadline_killed"] = True
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
    except (ScanError, subprocess.SubprocessError, OSError) as e:
        result["errors"].append(str(e))
    finally:
        if sink and sink.poll() is None:
            sink.send_signal(signal.SIGTERM)
            try:
                sink.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sink.kill()
        result["seconds"] = round(time.monotonic() - started, 2)
        (scan / "inner.json").write_text(json.dumps(result))
    return 0 if not result["errors"] else 1


def detonate(name: str, version: str, tarball: bytes, scan: Path, cfg: ScanConfig, deps: Path | None = None, mode=None) -> MicroVMResult:
    started = time.monotonic()
    tokens = HoneytokenSet.generate(scan.parent.name + "-microvm")
    prepare(scan, name, version, tarball, tokens, cfg.fc_rootfs, deps, trust_from=cfg.rootfs)
    if mode:
        mode.arm(scan, tokens)
    _build_scan_drive(scan)
    _env_file(scan, name, tokens)
    used = sum(f.stat().st_size for f in (scan / "scan-fs").rglob("*") if f.is_file() and not f.is_symlink())
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-d", str(scan / "scan-fs"), str(scan / "scan.ext4"),
                    f"{(used >> 20) * 2 + 300}M"], check=True, capture_output=True, timeout=120)
    subprocess.run(["cp", "--sparse=always", cfg.fc_rootfs, str(scan / "root.ext4")],
                   check=True, capture_output=True, timeout=60)
    (scan / "fc.json").write_text(json.dumps({
        "boot-source": {"kernel_image_path": cfg.fc_kernel, "boot_args": BOOT_ARGS},
        "drives": [
            {"drive_id": "root", "path_on_host": str(scan / "root.ext4"), "is_root_device": True, "is_read_only": False},
            {"drive_id": "scan", "path_on_host": str(scan / "scan.ext4"), "is_root_device": False, "is_read_only": True},
        ],
        "machine-config": {"vcpu_count": 2, "mem_size_mib": 2048},
        "network-interfaces": [{"iface_id": "eth0", "guest_mac": GUEST_MAC, "host_dev_name": TAP}],
    }))
    (scan / "vm.json").write_text(json.dumps({"firecracker": cfg.fc_bin}))

    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    try:
        subprocess.run(["unshare", "-rn", sys.executable, "-m", "redhanded.microvm", str(scan), str(cfg.deadline_s)],
                       env=env, timeout=cfg.deadline_s + 60, capture_output=True)
    except subprocess.TimeoutExpired:
        pass
    if mode:
        mode.close(scan)
    inner_path = scan / "inner.json"
    result = json.loads(inner_path.read_text()) if inner_path.exists() \
        else {"errors": ["microVM supervisor did not report"], "deadline_killed": True}

    console = scan / "log" / "console.txt"
    writes, reads, finished = parse_console(console.read_text(errors="replace")) if console.exists() else ([], [], False)
    cap = scan / "capture.jsonl"
    records = [Record.from_json(l) for l in cap.read_text().splitlines()] if cap.exists() else []
    ev = build(TraceFacts(opened=reads, writes=writes), records, NamePool.from_records(records), tokens, HOME,
               f"{WORK}/node_modules/{name}", RESOLVER_IP)
    ev.deadline_killed = bool(result.get("deadline_killed"))
    ev.incomplete.extend(result.get("errors", []))
    if not finished and not ev.deadline_killed:
        ev.incomplete.append("the microVM guest did not finish its report")
    if mode:
        mode.after(ev, scan)
    decision = mode.decide(ev, scan) if mode else decide(ev)
    for bulky in ("root.ext4", "scan.ext4", "scan-fs"):       # 700 MB per scan otherwise
        subprocess.run(["rm", "-rf", str(scan / bulky)], capture_output=True, timeout=30)
    return MicroVMResult(decision, ev, round(time.monotonic() - started, 2),
                         {**result, "sinkhole_records": len(records), "guest_report_finished": finished})


if __name__ == "__main__":
    raise SystemExit(inner(Path(sys.argv[1]), float(sys.argv[2])))
