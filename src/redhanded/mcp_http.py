"""Hosted MCP over stateless HTTP: POST one JSON-RPC message, get one JSON reply.

No install for the agent, and no second way in: tool calls use the same queue,
spend guard and rate limit as the page. `redhanded mcp` is the same set of tools
for someone running their own sandbox host.
"""
from __future__ import annotations

import json
import os

from . import __version__
from .service import INSTRUCTIONS, InputError, validate

PROTOCOLS = ("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26")
READ = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
TOOLS = [
    {"name": "check_package",
     "description": "Verdict for one exact npm package version. Returns verdict (CLEAN, REVIEW, HIGH, CRITICAL), "
                    "advice (allow, review, block), reasons and a scan_id. A package not scanned before runs a "
                    "scan, which takes seconds to a few minutes.",
     "inputSchema": {"type": "object", "required": ["name", "version"],
                     "properties": {"name": {"type": "string"}, "version": {"type": "string"}}},
     "annotations": READ},
    {"name": "check_lockfile_change",
     "description": "Verdicts for every package that a package-lock.json change adds or updates. Pass the full "
                    "text of the new lockfile and, if there is one, the old lockfile. Returns the worst verdict, "
                    "merge advice and one entry per changed package.",
     "inputSchema": {"type": "object", "required": ["new_lockfile"],
                     "properties": {"new_lockfile": {"type": "string"}, "old_lockfile": {"type": "string"}}},
     "annotations": READ},
    {"name": "compare_versions",
     "description": "Run a new version and the one before it, and return what the new one does that the old one never "
                    "did: new domains, install scripts, credential reads, commands. Includes the verdict and advice.",
     "inputSchema": {"type": "object", "required": ["name", "version"],
                     "properties": {"name": {"type": "string"}, "version": {"type": "string"},
                                    "previous_version": {"type": "string"}, "integrity": {"type": "string"}}},
     "annotations": READ},
    {"name": "find_safe_version",
     "description": "After a block: an agent walks the older versions, runs them in the sandbox, and returns the closest "
                    "one the rules call CLEAN, with each step it took and what the blocked version added.",
     "inputSchema": {"type": "object", "required": ["name", "blocked_version"],
                     "properties": {"name": {"type": "string"}, "blocked_version": {"type": "string"}, "integrity": {"type": "string"}}},
     "annotations": READ},
    {"name": "check_skill",
     "description": "Before installing an agent skill: a real agent uses it on a baited machine, twice if needed, and fixed "
                    "rules read what happened. Pass SKILL.md and any other files by relative path. Takes up to a few minutes.",
     "inputSchema": {"type": "object", "required": ["files"],
                     "properties": {"files": {"type": "object", "description": "relative path to file text; must include SKILL.md",
                                              "additionalProperties": {"type": "string"}}}},
     "annotations": READ},
    {"name": "get_scan_report",
     "description": "Full evidence for a scan: files read and written, processes, network attempts, timing.",
     "inputSchema": {"type": "object", "required": ["scan_id"], "properties": {"scan_id": {"type": "string"}}},
     "annotations": READ},
]


def _ok(id_, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _err(id_, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _call(name: str, args: dict, scanner, who: str) -> dict:
    from .web import find_scan, scan_view
    if name == "get_scan_report":
        scan_dir = find_scan(str(args.get("scan_id", "")), scanner.roots)
        if not scan_dir:
            raise InputError("no report for that scan id")
        return scan_view(scan_dir)["report"]
    if name == "compare_versions":
        package, version = str(args.get("name", "")), str(args.get("version", ""))
        validate(package, version)
        job = scanner.start("compare", f"{package}@{version}", {"previous": args.get("previous_version"), "integrity": args.get("integrity")}, who)
    elif name == "find_safe_version":
        package, version = str(args.get("name", "")), str(args.get("blocked_version", ""))
        validate(package, version)
        job = scanner.start("repair", f"{package}@{version}", {"integrity": args.get("integrity")}, who)
    elif name == "check_skill":
        files = args.get("files")
        if not isinstance(files, dict):
            raise InputError("files must map relative paths to file text, and include SKILL.md")
        job = scanner.start("skill", "agent skill", files, who)
    elif name == "check_package":
        package, version = str(args.get("name", "")), str(args.get("version", ""))
        validate(package, version)
        job = scanner.start("npm", f"{package}@{version}", None, who)
    else:
        new, old = args.get("new_lockfile"), args.get("old_lockfile") or None
        if not isinstance(new, str) or not isinstance(old, (str, type(None))):
            raise InputError("new_lockfile must be the text of a package-lock.json")
        job = scanner.start("lockfile", "package-lock.json", (old, new), who)
    scanner.wait(job, 420.0 if job.kind in ("skill", "repair") else 280.0)
    if job.state != "done":
        raise InputError(job.error or "the scan is still running; try again in a minute")
    return _with_links(job.result)


def _with_links(out: dict) -> dict:
    """Agents get links they can follow, not paths relative to a page they are not on."""
    site = os.environ.get("RH_PUBLIC_URL", "").rstrip("/")
    for r in [out, *out.get("packages", [])]:
        if r.get("scan_id"):
            r["url"] = f"{site}/#{r['scan_id']}"
    return out


def handle(msg: dict, scanner, who: str) -> dict | None:
    """One JSON-RPC message in, one reply out, or None for a notification."""
    from .web import Refused
    method, id_, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if id_ is None:
        return None
    if method == "initialize":
        asked = params.get("protocolVersion")
        return _ok(id_, {"protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
                         "capabilities": {"tools": {}},
                         "serverInfo": {"name": "redhanded", "title": "RedHanded", "version": __version__},
                         "instructions": INSTRUCTIONS})
    if method == "ping":
        return _ok(id_, {})
    if method == "tools/list":
        return _ok(id_, {"tools": TOOLS})
    if method != "tools/call":
        return _err(id_, -32601, f"unknown method {method}")
    name, args = params.get("name"), params.get("arguments") or {}
    if name not in {t["name"] for t in TOOLS} or not isinstance(args, dict):
        return _err(id_, -32602, f"unknown tool {name}")
    try:
        out = _call(name, args, scanner, who)
    except (InputError, Refused) as e:
        return _ok(id_, {"content": [{"type": "text", "text": str(e)}], "isError": True})
    return _ok(id_, {"content": [{"type": "text", "text": json.dumps(out)}], "structuredContent": out, "isError": False})
