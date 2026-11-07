#!/usr/bin/env python3
"""Stop a coding agent installing a package that has not proved itself. A PreToolUse hook for Claude Code.

MCP only helps when the agent decides to ask. This sits in front of the shell, so it does not depend on that.
The agent reads the refusal, including the version that proved clean, and can carry on with that one.

If RedHanded cannot answer, the install goes ahead with a warning, unless RH_GUARD_STRICT=1.
Standard library only. Exit code 2 is how a hook refuses a command.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import time
import urllib.error
import urllib.request

SERVER = os.environ.get("RH_SERVER", "https://45-32-140-228.sslip.io").rstrip("/")
STRICT = os.environ.get("RH_GUARD_STRICT") == "1"
WAIT_S = float(os.environ.get("RH_GUARD_WAIT", "280"))
BLOCK = {"HIGH", "CRITICAL"}
_MANAGERS = {"npm": {"install", "i", "add"}, "pnpm": {"add", "install", "i"}, "yarn": {"add"}, "bun": {"add", "install", "i"}}
_SPEC = re.compile(r"^(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+(?:@[\w.~^*+-]+)?$", re.I)
_SPLIT = re.compile(r"&&|\|\||;|\|")


def packages(command: str) -> list[str]:
    """The registry packages a shell command would install. A bare `npm install` names none, so it is not checked here."""
    found: list[str] = []
    for part in _SPLIT.split(command):
        try:
            words = shlex.split(part)
        except ValueError:
            continue
        while words and ("=" in words[0] or words[0] in ("sudo", "env", "npx", "exec")):
            words = words[1:]
        if len(words) < 2 or words[0] not in _MANAGERS:
            continue
        rest = words[1:]
        if rest[0] == "global":      # yarn global add x
            rest = rest[1:]
        if not rest or rest[0] not in _MANAGERS[words[0]]:
            continue
        for w in rest[1:]:
            # A path, a URL or a git source is not a registry package; a version range is left for the server to resolve.
            if not w.startswith("-") and _SPEC.match(w) and not w.startswith((".", "/")):
                found.append(w)
    return found


def call(path: str, body: dict | None = None, timeout: float = 30) -> dict:
    req = urllib.request.Request(SERVER + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", "User-Agent": "redhanded-guard"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def wait(job: str, until: float) -> dict:
    while time.time() < until:
        j = call(f"/api/jobs/{job}")
        if j.get("state") in ("done", "error"):
            return j
        time.sleep(3)
    return {"state": "error", "error": "timed out waiting for a verdict"}


def safe_version(name: str, version: str, until: float) -> str | None:
    """Ask the repair agent for a version that proved clean. No answer is an answer: the refusal still stands."""
    try:
        j = wait(call("/api/repair", {"name": name, "version": version})["job"], until)
        result = j.get("result") or {}
        return (result.get("pinned") or {}).get("version")
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        return None


def check(spec: str, until: float) -> tuple[bool, str]:
    """(allowed, message). The message is for the agent."""
    j = wait(call("/api/scan", {"package": spec})["job"], until)
    if j.get("state") != "done":
        return not STRICT, f"RedHanded gave no verdict for {spec}: {j.get('error')}"
    r = j.get("result") or {}
    verdict = j.get("verdict") or r.get("verdict")
    if verdict not in BLOCK:
        return True, f"RedHanded: {spec} is {verdict}." + (" Worth a human look: " + "; ".join(r.get("reasons", [])[:2]) if verdict == "REVIEW" else "")
    name, version = r.get("package"), r.get("version")
    why = "; ".join(x.split(": ", 1)[-1] for x in r.get("reasons", []) if x.startswith(("HIGH", "CRITICAL")))[:400]
    lines = [f"BLOCKED by RedHanded: {name}@{version} is {verdict}. When it ran on a baited machine it: {why}.", f"Evidence: {SERVER}{r.get('url', '/')}"]
    safe = safe_version(name, version, until)
    lines.append(f"{name}@{safe} ran in the same sandbox and proved clean. Install that exact version instead." if safe else
                 "No older version has proved clean yet. Do not install this package without asking the user.")
    return False, "\n".join(lines)


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    if event.get("tool_name") not in ("Bash", "PowerShell"):
        return 0
    specs = packages((event.get("tool_input") or {}).get("command", ""))
    until = time.time() + WAIT_S
    for spec in specs:
        try:
            allowed, message = check(spec, until)
        except (urllib.error.URLError, OSError, ValueError) as e:
            allowed, message = not STRICT, f"RedHanded could not be reached for {spec}: {e}"
        print(message, file=sys.stderr)
        if not allowed:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
