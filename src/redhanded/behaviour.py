"""What a new version does that the version before it never did.

Both versions run in the same sandbox, and the difference is the evidence. A hijacked
release often looks ordinary on its own terms; next to the release before it, the new
domain, the new install script and the first read of a credential file stand out.
"""
from __future__ import annotations

import posixpath
import re

from .explain import _is_harness
from .verdict import BENIGN_HOSTS, NET_TOOLS, Verdict, _domain

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")
_ORDINARY = frozenset({"node", "sh", "bash", "dash", "env", "npm", "npx", "node-gyp", "make", "cc", "gcc", "g++", "ld", "as",
                       "python", "python3", "uname", "cat", "ls", "rm", "mkdir", "cp", "mv", "sed", "grep", "git"})
_SKIP_WRITES = ("/work/", "/home/dev/.npm/", "/home/dev/.cache/", "/tmp/", "/var/tmp/", "/root/.npm/")
_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def _key(version: str) -> tuple[int, int, int] | None:
    m = _SEMVER.match(version)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def older_versions(versions: list[str], target: str) -> list[str]:
    """Released versions below the target, closest first. Prereleases are never a baseline."""
    want = _key(target.split("-", 1)[0].split("+", 1)[0])
    if not want:
        return []
    keyed = [(k, v) for v in versions if (k := _key(v)) and k < want]
    return [v for _, v in sorted(keyed, reverse=True)]


def manifest_summary(manifest: dict) -> dict:
    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    deps = manifest.get("dependencies") if isinstance(manifest.get("dependencies"), dict) else {}
    return {"scripts": {k: str(scripts[k])[:300] for k in LIFECYCLE if k in scripts}, "dependencies": sorted(map(str, deps))[:500]}


def profile(report: dict) -> dict:
    """One version's behaviour as comparable facts, from both runs."""
    sides = [report.get("evidence") or {}, (report.get("microvm") or {}).get("evidence") or {}]
    connects = [c for ev in sides for c in ev.get("connects", [])]
    commands = set()
    for ev in sides:
        for argv, _ in ev.get("execs", []):
            if argv and not _is_harness(argv):
                exe = posixpath.basename(argv[0])
                if exe not in _ORDINARY:
                    commands.add(exe)
    manifest = report.get("manifest") or {}
    return {
        "domains": sorted({_domain(c) for c in connects if c not in BENIGN_HOSTS}),
        "bait": sorted({p for ev in sides for p in ev.get("bait_reads", [])}),
        "commands": sorted(commands),
        "writes": sorted({p for ev in sides for p in ev.get("writes", []) if not p.startswith(_SKIP_WRITES)}),
        "scripts": sorted(manifest.get("scripts", {})),
        "dependencies": sorted(manifest.get("dependencies", [])),
    }


def diff(old: dict, new: dict) -> list[dict]:
    """Everything the new version does that the old one did not."""
    a, b = profile(old), profile(new)
    labels = {"scripts": "install_script", "domains": "domain", "bait": "bait_read", "commands": "command",
              "writes": "write", "dependencies": "dependency"}
    return [{"kind": kind, "what": what} for field, kind in labels.items() for what in sorted(set(b[field]) - set(a[field]))]


def judge(base: Verdict, changes: list[dict]) -> tuple[Verdict, list[str]]:
    """Only ever raises. A new dependency alone is normal and stays a note."""
    kinds = {c["kind"] for c in changes}
    level, reasons = base, []

    def shown(kind: str) -> str:
        return ", ".join(c["what"] for c in changes if c["kind"] == kind)[:200]

    net_tools = [c["what"] for c in changes if c["kind"] == "command" and c["what"] in NET_TOOLS]
    if "install_script" in kinds and kinds & {"domain", "bait_read"} or ("bait_read" in kinds and "domain" in kinds):
        level = max(level, Verdict.HIGH)
        reasons.append(f"HIGH: new in this version: {shown('install_script') or shown('bait_read')} and contact with {shown('domain') or shown('bait_read')}")
    else:
        for kind, label in (("install_script", "an install script"), ("domain", "contact with"), ("bait_read", "a first read of")):
            if kind in kinds:
                level = max(level, Verdict.REVIEW)
                reasons.append(f"REVIEW: new in this version: {label} {shown(kind)}")
        if net_tools:
            level = max(level, Verdict.REVIEW)
            reasons.append(f"REVIEW: new in this version: runs {', '.join(net_tools)}")
    return level, reasons
