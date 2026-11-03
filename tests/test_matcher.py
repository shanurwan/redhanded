import base64
import gzip
import json
import urllib.parse
import zlib

import pytest

from redhanded.honeytokens import HoneytokenSet
from redhanded.matcher import Matcher


@pytest.fixture
def tokens():
    return HoneytokenSet.generate("scan-test")


@pytest.fixture
def matcher(tokens):
    return Matcher(tokens.values())


def names(found):
    return {m.token for m in found}


def test_raw(tokens, matcher):
    body = json.dumps({"k": tokens.aws_access_key_id, "h": "runner-01"}).encode()
    assert "aws_access_key_id" in names(matcher.find(body))


@pytest.mark.parametrize("prefix", [b"", b"x", b"xy", b'{"d":"'])
def test_base64_any_alignment(tokens, matcher, prefix):
    payload = base64.b64encode(prefix + tokens.github_token.encode() + b"|tail")
    assert "github_token" in names(matcher.find(b"data=" + payload))


def test_base64url(tokens, matcher):
    payload = base64.urlsafe_b64encode(b"??>>" + tokens.aws_secret_access_key.encode())
    assert "aws_secret_access_key" in names(matcher.find(payload))


def test_hex(tokens, matcher):
    assert "npm_token" in names(matcher.find(tokens.npm_token.encode().hex().encode()))


def test_url_encoded(tokens, matcher):
    body = ("t=" + urllib.parse.quote(tokens.aws_secret_access_key, safe="")).encode()
    assert "aws_secret_access_key" in names(matcher.find(body))


def test_gzip_body(tokens, matcher):
    body = gzip.compress(json.dumps({"env": tokens.env()}).encode())
    assert {"aws_access_key_id", "github_token", "npm_token"} <= names(matcher.find(body))


def test_raw_deflate_inside_base64(tokens, matcher):
    c = zlib.compressobj(wbits=-15)
    blob = c.compress(tokens.wallet_private_key.encode()) + c.flush()
    found = matcher.find(b"x=" + base64.b64encode(blob))
    assert "wallet_private_key" in names(found)


def test_dns_hex_split_across_labels(tokens, matcher):
    h = tokens.aws_access_key_id.encode().hex()
    qname = ".".join(h[i : i + 20] for i in range(0, len(h), 20)) + ".exfil-demo.invalid."
    assert "aws_access_key_id" in names(matcher.find_dns(qname))


def test_dns_base32(tokens, matcher):
    enc = base64.b32encode(tokens.github_token.encode()).decode().rstrip("=").lower()
    qname = ".".join(enc[i : i + 30] for i in range(0, len(enc), 30)) + ".t.invalid"
    assert "github_token" in names(matcher.find_dns(qname))


def test_clean_traffic_has_no_match(matcher):
    body = b'GET /lodash/-/lodash-4.17.21.tgz HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n'
    assert matcher.find(body) == set()
    assert matcher.find_dns("registry.npmjs.org.") == set()


def test_fresh_values_per_scan():
    a, b = HoneytokenSet.generate("a"), HoneytokenSet.generate("b")
    assert not set(a.values().values()) & set(b.values().values())
