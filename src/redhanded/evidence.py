"""Join what the host saw into one Evidence record for the verdict rules.

Inputs come only from outside the sandbox: the gVisor syscall log, the
sinkhole's records, and the honeytokens planted for this scan.
"""
from __future__ import annotations

import ipaddress
import posixpath

from .honeytokens import AI_TOOL_DIR, AI_TOOLS, HoneytokenSet
from .matcher import Matcher
from .sinkhole import NamePool, Record
from .trace import TraceFacts
from .verdict import Evidence

# Fake services the sinkhole impersonates. A token presented to one of these
# in an auth header is a use of a stolen credential, not just a copy of it.
TOKEN_SERVICES = {
    "registry.npmjs.org": "npm",
    "api.github.com": "GitHub",
    "github.com": "GitHub",
    "sts.amazonaws.com": "AWS",
}
AUTH_HEADERS = ("authorization", "x-amz-security-token", "x-npm-auth", "private-token")
# Writes here are an install doing its job, not persistence.
_SCRATCH_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/", "/proc/")


def _loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _payload(rec: Record) -> bytes:
    head = "\n".join(f"{k}: {v}" for k, v in rec.headers.items())
    return f"{rec.detail}\n{head}\n".encode() + rec.data


def contacted(records: list[Record]) -> list[str]:
    """Every destination that reached the sinkhole, by name. The same measure in both tiers."""
    hosts = {r.host for r in records if r.host}
    hosts |= {f"port {r.detail}" for r in records if r.kind == "raw" and not r.host}
    return sorted(hosts)


def build(trace: TraceFacts, records: list[Record], pool: NamePool, tokens: HoneytokenSet,
          home: str, package_root: str, resolver_ip: str) -> Evidence:
    ev = Evidence()
    matcher = Matcher(tokens.values())
    machine = Matcher({"machine_name": tokens.machine_name}) if tokens.machine_name else None

    for rec in records:
        if machine and (machine.find_dns(rec.host) or machine.find(_payload(rec))):
            ev.machine_leaks.append(rec.host or f"port {rec.detail}")
        if rec.kind == "dns":
            ev.exfil_matches.extend(m.token for m in matcher.find_dns(rec.host))
        elif rec.kind == "tls":
            ev.exfil_matches.extend(m.token for m in matcher.find_dns(rec.host))
            if rec.host:
                ev.connects.append(rec.host)
        elif rec.kind == "http":
            ev.http_requests.append(f"{rec.host} {rec.detail}"[:300])
            service = TOKEN_SERVICES.get(rec.host.split(":", 1)[0].lower())
            auth = "\n".join(v for k, v in rec.headers.items() if k in AUTH_HEADERS).encode()
            used = {m.token for m in matcher.find(auth)} if service else set()
            if used:
                ev.token_uses.append(service)
            ev.exfil_matches.extend(m.token for m in matcher.find(_payload(rec)) if m.token not in used)
        elif rec.kind == "raw":
            ev.exfil_matches.extend(m.token for m in matcher.find(rec.data))

    for ip, port in trace.connects:
        if (ip == resolver_ip and port == 53) or _loopback(ip):
            continue
        ev.connects.append(pool.name_of(ip) or ip)

    bait = tokens.bait_paths(home)
    ev.bait_reads = sorted(set(trace.opened) & bait)

    root = package_root.rstrip("/") + "/"
    npm_cache = posixpath.join(home, ".npm") + "/"
    ev.writes = sorted({
        p for p in trace.writes
        if not p.startswith((root, npm_cache) + _SCRATCH_PREFIXES)
    })
    ev.stats = sorted(set(trace.probes))
    ev.execs = list(trace.execs)
    calls = [" ".join(argv)[:300] for argv, _ in trace.execs if argv and posixpath.basename(argv[0]) in AI_TOOLS]
    called = {c.split(" ", 1)[0].rsplit("/", 1)[-1] for c in calls}
    # The microVM has no syscall log, so there a call shows up as the tool having been read.
    stubs = {posixpath.join(home, AI_TOOL_DIR, t): t for t in AI_TOOLS}
    ev.ai_tool_calls = [c.split(" ", 1)[0].rsplit("/", 1)[-1] + (" " + c.split(" ", 1)[1] if " " in c else "") for c in calls] \
        + sorted({stubs[p] for p in trace.opened if p in stubs and stubs[p] not in called})

    ev.machine_leaks = sorted(set(ev.machine_leaks))
    ev.connects.extend(contacted(records))
    ev.exfil_matches = sorted(set(ev.exfil_matches))
    ev.token_uses = sorted(set(ev.token_uses))
    ev.connects = sorted(set(ev.connects))
    return ev
