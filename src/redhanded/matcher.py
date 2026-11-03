"""Find honeytokens in captured traffic, however the package encoded them.

Covers raw, base64 (standard and URL-safe, any byte alignment), hex,
URL encoding, gzip/zlib/deflate bodies, nested encodings, and secrets
split across DNS labels.
"""
from __future__ import annotations

import base64
import re
import urllib.parse
import zlib
from dataclasses import dataclass

MIN_FRAGMENT = 12           # shorter fragments risk false matches
MAX_INFLATE = 8 * 1024 * 1024
MAX_DEPTH = 3

_B64_RUN = re.compile(rb"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(rb"(?:[0-9a-fA-F]{2}){8,}")


@dataclass(frozen=True)
class Match:
    token: str       # honeytoken name, e.g. "aws_access_key_id"
    encoding: str    # how it was found, e.g. "gzip>base64"


def _b64_fragments(raw: bytes, urlsafe: bool) -> list[bytes]:
    """Substrings that appear in the base64 of any buffer containing `raw`, at each alignment."""
    out = []
    for shift in range(3):
        enc = base64.b64encode(b"\x00" * shift + raw)
        first = 1 if shift else 0
        full = (shift + len(raw)) // 3
        frag = enc[4 * first : 4 * full]
        if urlsafe:
            frag = frag.translate(bytes.maketrans(b"+/", b"-_"))
        if len(frag) >= MIN_FRAGMENT:
            out.append(frag)
    return out


def _b32_fragments(raw: bytes) -> list[bytes]:
    out = []
    for shift in range(5):
        enc = base64.b32encode(b"\x00" * shift + raw)
        first = 1 if shift else 0
        full = (shift + len(raw)) // 5
        frag = enc[8 * first : 8 * full].lower()
        if len(frag) >= MIN_FRAGMENT:
            out.append(frag)
    return out


class Matcher:
    def __init__(self, tokens: dict[str, str]):
        self._patterns: list[tuple[str, str, bytes]] = []
        self._dns_patterns: list[tuple[str, str, bytes]] = []
        for name, value in tokens.items():
            raw = value.encode()
            self._patterns.append((name, "raw", raw))
            self._patterns.append((name, "hex", raw.hex().encode()))
            self._patterns.append((name, "hex", raw.hex().upper().encode()))
            for frag in _b64_fragments(raw, urlsafe=False):
                self._patterns.append((name, "base64", frag))
            for frag in _b64_fragments(raw, urlsafe=True):
                self._patterns.append((name, "base64url", frag))
            # DNS is case-insensitive and labels split the value, so compare lowercase, dots removed.
            self._dns_patterns.append((name, "dns-raw", raw.lower()))
            self._dns_patterns.append((name, "dns-hex", raw.hex().encode()))
            for frag in _b32_fragments(raw):
                self._dns_patterns.append((name, "dns-base32", frag))
            for frag in _b64_fragments(raw, urlsafe=True):
                self._dns_patterns.append((name, "dns-base64url", frag.lower()))

    def find(self, data: bytes) -> set[Match]:
        found: set[Match] = set()
        self._scan(data, "", 0, found)
        return found

    def find_dns(self, qname: str) -> set[Match]:
        flat = qname.rstrip(".").replace(".", "").lower().encode()
        return {Match(n, enc) for n, enc, pat in self._dns_patterns if pat in flat}

    def _scan(self, data: bytes, via: str, depth: int, found: set[Match]) -> None:
        for name, enc, pat in self._patterns:
            if pat in data:
                found.add(Match(name, via + enc))
        if depth >= MAX_DEPTH:
            return
        for label, layer in self._layers(data):
            if layer and layer != data:
                self._scan(layer, f"{via}{label}>", depth + 1, found)

    @staticmethod
    def _layers(data: bytes):
        if b"%" in data or b"+" in data:
            yield "url", urllib.parse.unquote_to_bytes(data.replace(b"+", b" "))
        for start in _compressed_starts(data):
            inflated = _inflate(data[start:])
            if inflated:
                yield "gzip" if data[start] == 0x1F else "zlib", inflated
        if not _looks_textual(data):
            # Raw deflate has no header bytes; try it on any binary buffer, such as a decoded layer.
            inflated = _inflate(data, raw_only=True)
            if inflated:
                yield "deflate", inflated
        for run in _B64_RUN.findall(data):
            decoded = _b64decode_loose(run)
            if decoded:
                yield "base64", decoded
        for run in _HEX_RUN.findall(data):
            yield "hex", bytes.fromhex(run.decode())


def _compressed_starts(data: bytes) -> list[int]:
    starts = [m.start() for m in re.finditer(rb"\x1f\x8b", data)]
    starts += [m.start() for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", data)]
    return starts[:16]


def _looks_textual(data: bytes) -> bool:
    sample = data[:512]
    return all(32 <= b < 127 or b in (9, 10, 13) for b in sample)


def _inflate(blob: bytes, raw_only: bool = False) -> bytes | None:
    for wbits in ((-15,) if raw_only else (47, -15)):   # 47: gzip or zlib header; -15: raw deflate
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(blob, MAX_INFLATE)
            if out:
                return out
        except zlib.error:
            continue
    return None


def _b64decode_loose(run: bytes) -> bytes | None:
    s = run.rstrip(b"=").replace(b"-", b"+").replace(b"_", b"/")
    s += b"=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except ValueError:
        return None
