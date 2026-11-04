"""Join what the host saw into one Evidence record for the verdict rules.

Inputs come only from outside the sandbox: the gVisor syscall log, the
sinkhole's records, and the honeytokens planted for this scan.
"""
from __future__ import annotations

import posixpath

from .honeytokens import HoneytokenSet
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


def _payload(rec: Record) -> bytes:
    head = "\n".join(f"{k}: {v}" for k, v in rec.headers.items())
    return f"{rec.detail}\n{head}\n".encode() + rec.data


def build(trace: TraceFacts, records: list[Record], pool: NamePool, tokens: HoneytokenSet,
          home: str, package_root: str, resolver_ip: str) -> Evidence:
    ev = Evidence()
    matcher = Matcher(tokens.values())

    for rec in records:
        if rec.kind == "dns":
            ev.exfil_matches.extend(m.token for m in matcher.find_dns(rec.host))
        elif rec.kind == "tls":
            ev.exfil_matches.extend(m.token for m in matcher.find_dns(rec.host))
            if rec.host:
                ev.connects.append(rec.host)
        elif rec.kind == "http":
            service = TOKEN_SERVICES.get(rec.host.split(":", 1)[0].lower())
            auth = "\n".join(v for k, v in rec.headers.items() if k in AUTH_HEADERS).encode()
            used = {m.token for m in matcher.find(auth)} if service else set()
            if used:
                ev.token_uses.append(service)
            ev.exfil_matches.extend(m.token for m in matcher.find(_payload(rec)) if m.token not in used)
        elif rec.kind == "raw":
            ev.exfil_matches.extend(m.token for m in matcher.find(rec.data))

    for ip, port in trace.connects:
        if ip == resolver_ip and port == 53:
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

    ev.exfil_matches = sorted(set(ev.exfil_matches))
    ev.token_uses = sorted(set(ev.token_uses))
    ev.connects = sorted(set(ev.connects))
    return ev
