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
MAX_LINES = 600
MAX_LINE = 600


def export(scan_dir: Path, out_root: Path, title: str, summary: str, order: int = 99) -> Path:
    report = json.loads((scan_dir / "report.json").read_text())
    out = out_root / report["scan_id"]
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(scan_dir / "report.json", out / "report.json")
    for optional in ("capture.jsonl", "explain.json"):
        if (scan_dir / optional).is_file():
            shutil.copyfile(scan_dir / optional, out / optional)

    digest, total, kept = hashlib.sha256(), 0, []
    for path in sorted(glob.glob(str(scan_dir / "log" / "*.boot.txt"))):
        with open(path, "rb") as f:
            for raw in f:
                digest.update(raw)
                total += 1
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if len(kept) < MAX_LINES and KEEP.search(line):
                    kept.append(line[:MAX_LINE])
    (out / "syscalls-excerpt.txt").write_text("\n".join(kept) + "\n", encoding="utf-8")
    meta = {"title": title, "summary": summary, "order": order,
            "full_syscall_log": {"sha256": digest.hexdigest(), "lines": total, "excerpt_lines": len(kept)}}
    (out / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    return out
