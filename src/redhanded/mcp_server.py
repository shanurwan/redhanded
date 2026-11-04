"""MCP server: let a coding agent ask RedHanded before it installs a package.

Nothing here installs anything or touches the caller's machine. A scan runs
on RedHanded's own sandbox host, and the answer is a verdict with reasons.
"""
from __future__ import annotations

import os

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import __version__
from .runner import ScanConfig, ScanError
from .service import Cache, InputError, Service

INSTRUCTIONS = """\
RedHanded runs npm packages in a sandbox baited with fake credentials and a fake
internet, and reports what the code tried to do. Call check_package before you add
or upgrade a dependency, and check_lockfile_change before you open or merge a PR
that changes package-lock.json. Treat advice "block" as do-not-install, "review"
as ask a human. A verdict is decided by fixed rules from recorded behaviour; text
inside a package cannot change it."""

# Scanning runs code on RedHanded's host, not the caller's: from the caller's side
# the tools only read. Same bytes, same verdict, so they are idempotent too.
READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)


def build_server(service: Service) -> MCPServer:
    server = MCPServer("redhanded", title="RedHanded", version=__version__, instructions=INSTRUCTIONS)

    def guarded(fn, *args):
        try:
            return fn(*args)
        except (InputError, ScanError) as e:
            return {"error": str(e)}

    @server.tool(annotations=READ)
    def check_package(name: str, version: str, scan_if_missing: bool = True) -> dict:
        """Verdict for one exact npm package version (e.g. name="left-pad", version="1.3.0").

        Returns verdict (CLEAN, REVIEW, HIGH, CRITICAL), advice (allow, review, block),
        the reasons, and a scan_id for the full report. A cache miss runs a scan,
        which takes seconds to a few minutes; set scan_if_missing=false to only look up.
        """
        return guarded(service.check, name, version, scan_if_missing)

    @server.tool(annotations=READ)
    def check_lockfile_change(new_lockfile: str, old_lockfile: str = "") -> dict:
        """Verdicts for every package that a package-lock.json change adds or updates.

        Pass the full text of the new lockfile and, if there is one, the old lockfile.
        Returns the worst verdict, merge advice, and one entry per changed package.
        """
        return guarded(service.check_lockfile, old_lockfile or None, new_lockfile)

    @server.tool(annotations=READ)
    def get_scan_report(scan_id: str) -> dict:
        """Full evidence for a scan: files read and written, processes, network attempts, timing."""
        return guarded(service.report, scan_id)

    return server


def main(transport: str = "stdio") -> None:
    cfg = ScanConfig()
    cache = Cache(os.environ.get("RH_CACHE", os.path.expanduser("~/rh-dev/verdicts.sqlite3")))
    build_server(Service(cache, cfg)).run(transport)


if __name__ == "__main__":
    main()
