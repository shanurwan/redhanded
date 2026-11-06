import base64

from redhanded.evidence import build
from redhanded.honeytokens import HoneytokenSet
from redhanded.sinkhole import NamePool, Record
from redhanded.trace import TraceFacts
from redhanded.verdict import Verdict, decide

HOME = "/home/dev"
PKG = "/work/node_modules/left-pad"
RESOLVER = "10.66.0.2"


def scan(trace=None, records=(), tokens=None, pool=None):
    tokens = tokens or HoneytokenSet.generate("t1")
    ev = build(trace or TraceFacts(), list(records), pool or NamePool(), tokens, HOME, PKG, RESOLVER)
    return ev, decide(ev)


def test_quiet_install_is_clean():
    pool = NamePool()
    registry = pool.address("registry.npmjs.org")
    trace = TraceFacts(opened=[f"{PKG}/package.json"], writes=[f"{PKG}/build/out.js", f"{HOME}/.npm/_cacache/x"],
                       connects=[(RESOLVER, 53), (registry, 443)])
    ev, d = scan(trace, [Record("dns", 0, "10.66.0.20", "registry.npmjs.org", "A")], pool=pool)
    assert ev.connects == ["registry.npmjs.org"] and ev.writes == []
    assert d.verdict == Verdict.CLEAN


def test_token_in_a_request_body_is_critical():
    t = HoneytokenSet.generate("t2")
    body = base64.b64encode(f"k={t.aws_secret_access_key}".encode())
    rec = Record("http", 0, "10.66.0.20", "collector.example.invalid", "POST /", {"host": "collector.example.invalid"}, body)
    ev, d = scan(records=[rec], tokens=t)
    assert ev.exfil_matches == ["aws_secret_access_key"]
    assert d.verdict == Verdict.CRITICAL


def test_token_presented_to_the_fake_registry_is_a_use():
    t = HoneytokenSet.generate("t3")
    rec = Record("http", 0, "10.66.0.20", "registry.npmjs.org", "PUT /some-pkg",
                 {"host": "registry.npmjs.org", "authorization": f"Bearer {t.npm_token}"})
    ev, d = scan(records=[rec], tokens=t)
    assert ev.token_uses == ["npm"] and ev.exfil_matches == []
    assert d.verdict == Verdict.CRITICAL


def test_token_in_dns_labels_is_critical():
    t = HoneytokenSet.generate("t4")
    h = t.github_token.encode().hex()
    rec = Record("dns", 0, "10.66.0.20", f"{h[:60]}.{h[60:]}.q.example.invalid", "A")
    ev, d = scan(records=[rec], tokens=t)
    assert "github_token" in ev.exfil_matches and d.verdict == Verdict.CRITICAL


def test_bait_read_then_network_is_high():
    pool = NamePool()
    ip = pool.address("cdn.example.invalid")
    trace = TraceFacts(opened=[f"{HOME}/.aws/credentials", f"{PKG}/index.js"], connects=[(ip, 443)])
    ev, d = scan(trace, pool=pool)
    assert ev.bait_reads == [f"{HOME}/.aws/credentials"]
    assert ev.connects == ["cdn.example.invalid"]
    assert d.verdict == Verdict.HIGH


def test_shell_profile_write_is_high_but_package_writes_are_not():
    trace = TraceFacts(writes=[f"{HOME}/.bashrc", f"{PKG}/dist/a.js", "/tmp/npm-1/x"])
    ev, d = scan(trace)
    assert ev.writes == [f"{HOME}/.bashrc"]
    assert d.verdict == Verdict.HIGH


def test_unknown_connect_by_ip_is_review():
    ev, d = scan(TraceFacts(connects=[("203.0.113.9", 8080)]))
    assert ev.connects == ["203.0.113.9"] and d.verdict == Verdict.REVIEW


def test_tls_server_name_counts_as_a_connect():
    ev, d = scan(records=[Record("tls", 0, "10.66.0.20", "telemetry.example.invalid", "443")])
    assert ev.connects == ["telemetry.example.invalid"] and d.verdict == Verdict.REVIEW
