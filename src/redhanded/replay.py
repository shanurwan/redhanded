"""Turn a recorded scan into a replay the demo site can show and anyone can check.

A replay keeps the scan's own report and sinkhole capture unchanged, plus the
syscall lines that carry the story (process starts, connections, bait and
container checks). The full gVisor log is too large to commit, so the replay
records its sha256 and line count; the live site serves full logs for scans
it ran itself.
"""
from __future__ import annotations

import glob
import hashlib
import json
import re
import shutil
from pathlib import Path

KEEP = re.compile(r" X (?:execve|execveat|connect|sendto|sendmsg)\(|"
                  r"/home/dev/|/\.dockerenv|/run/\.containerenv|/proc/1/|/proc/vz|/proc/xen")
# The bait is fake, but it is shaped like real credentials on purpose, and secret
# scanners cannot tell. Excerpts name the honeytoken instead of carrying it.
TOKEN_SHAPES = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bnpm_[A-Za-z0-9]{36}\b|\bgh[pousr]_[A-Za-z0-9]{36}\b")
BAIT_ENV = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "NPM_TOKEN", "GITHUB_TOKEN")
MAX_LINES = 600
MAX_LINE = 600


def _bait_values(scan_dir: Path) -> dict[str, str]:
    spec = scan_dir / "bundle" / "config.json"
    if not spec.is_file():
        return {}
    env = dict(e.split("=", 1) for e in json.loads(spec.read_text())["process"].get("env", []) if "=" in e)
    return {env[k]: k for k in BAIT_ENV if env.get(k)}


def redact(line: str, bait: dict[str, str]) -> str:
    for value, name in bait.items():
        line = line.replace(value, f"<honeytoken:{name}>")
    return TOKEN_SHAPES.sub("<honeytoken>", line)


def export(scan_dir: Path, out_root: Path, title: str, summary: str, order: int = 99) -> Path:
    report = json.loads((scan_dir / "report.json").read_text())
    out = out_root / report["scan_id"]
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(scan_dir / "report.json", out / "report.json")
    if (scan_dir / "explain.json").is_file():
        shutil.copyfile(scan_dir / "explain.json", out / "explain.json")
    if (scan_dir / "capture.jsonl").is_file():
        lines = (scan_dir / "capture.jsonl").read_text().splitlines()
        (out / "capture.jsonl").write_text("".join(redact(l, _bait_values(scan_dir)) + "\n" for l in lines))

    micro = scan_dir / "microvm"
    micro_bait = _bait_values(micro)
    if (micro / "capture.jsonl").is_file():
        lines = (micro / "capture.jsonl").read_text().splitlines()
        (out / "microvm-capture.jsonl").write_text("".join(redact(l, micro_bait) + "\n" for l in lines))
    if (micro / "log" / "console.txt").is_file():
        console = (micro / "log" / "console.txt").read_text(errors="replace")
        (out / "microvm-console.txt").write_text("\n".join(redact(l, micro_bait) for l in console.splitlines()) + "\n")
    bait = _bait_values(scan_dir)
    digest, total, kept = hashlib.sha256(), 0, []
    for path in sorted(glob.glob(str(scan_dir / "log" / "*.boot.txt"))):
        with open(path, "rb") as f:
            for raw in f:
                digest.update(raw)
                total += 1
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if len(kept) < MAX_LINES and KEEP.search(line):
                    kept.append(redact(line, bait)[:MAX_LINE])
    (out / "syscalls-excerpt.txt").write_text("\n".join(kept) + "\n", encoding="utf-8")
    meta = {"title": title, "summary": summary, "order": order,
            "full_syscall_log": {"sha256": digest.hexdigest(), "lines": total, "excerpt_lines": len(kept)}}
    (out / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    return out
