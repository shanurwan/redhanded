"""Attack memory: which recorded real attack does this behaviour resemble?

The behaviour of real attacks, never their code, is kept in a Vultr Vector Store
collection. Search finds the nearest ones. The API gives no score, so a match is
only kept if the behaviour really overlaps, measured here, which stops it from
naming an attack that merely sounds alike. It adds context for a reviewer and
has no effect on the verdict.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Callable

from .explain import DEFAULT_BASE_URL
from .verdict import _collector, _domain

COLLECTION = "rh_attacks"
MIN_OVERLAP = 0.5
MIN_TRAITS = 3
Call = Callable[[str, str, str, dict | None, float], dict]


def _call(method: str, url: str, key: str, body: dict | None, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(1 << 22)
    return json.loads(raw) if raw else {}


def traits(reasons: list[str], bait_reads: list[str], token_uses: list[str], exfil: list[str], connects: list[str]) -> set[str]:
    """What a package did, in terms that do not change from one scan to the next."""
    out = {f"read {p.replace('/home/dev/', '~/')}" for p in bait_reads}
    out |= {f"used stolen {s} token" for s in token_uses}
    out |= {f"sent {t}" for t in exfil}
    for c in connects:
        name = _collector(c)
        if name:
            out.add(f"called collector {name}")
        elif c in ("api.github.com", "registry.npmjs.org", "169.254.169.254") or c.startswith("sts."):
            out.add(f"called {'sts.amazonaws.com' if c.startswith('sts.') else c}")
    for why in reasons:
        text = why.split(": ", 1)[-1]
        if text.startswith("spawned "):
            out.add(text)
        elif text.startswith("wrote persistence path"):
            out.add(f"wrote shell profile {text.rsplit('/', 1)[-1]}")
        elif text.startswith("modified the runtime toolchain"):
            out.add("modified the toolchain")
        elif text.startswith("sent this machine"):
            out.add("sent the machine name")
        elif text.startswith("ran inline code"):
            out.add("ran inline code")
    return out


def report_traits(report: dict) -> set[str]:
    evs = [report.get("evidence") or {}, (report.get("microvm") or {}).get("evidence") or {}]
    join = lambda k: sorted({x for e in evs for x in e.get(k, [])})
    return traits(report.get("reasons", []), join("bait_reads"), join("token_uses"), join("exfil_matches"), join("connects"))


def as_item(entry: dict) -> str:
    """One searchable passage. The last line says which attack it is."""
    known = {k: entry.get(k, "") for k in ("package", "version", "incident", "date")}
    return ". ".join(sorted(entry["traits"])) + "\nknown: " + json.dumps(known)


def _parse(content: str) -> tuple[set[str], dict] | None:
    body, sep, tail = content.rpartition("\nknown: ")
    try:
        return set(body.split(". ")), json.loads(tail) if sep else None
    except ValueError:
        return None


class AttackMemory:
    def __init__(self, api_key: str, base_url: str = DEFAULT_BASE_URL, collection: str = COLLECTION, call: Call = _call, timeout: float = 15.0):
        self.key, self.base, self.collection, self._call, self.timeout = api_key, base_url.rstrip("/"), collection, call, timeout

    @classmethod
    def from_env(cls) -> "AttackMemory | None":
        key = os.environ.get("VULTR_INFERENCE_API_KEY", "")
        return cls(key, os.environ.get("VULTR_INFERENCE_BASE_URL", DEFAULT_BASE_URL)) if key else None

    def _url(self, path: str = "") -> str:
        return f"{self.base}/vector_store{path}"

    def seed(self, entries: list[dict]) -> int:
        try:
            self._call("POST", self._url(), self.key, {"name": self.collection}, self.timeout)
        except urllib.error.HTTPError:
            pass      # it already exists
        added = 0
        for entry in entries:
            self._call("POST", self._url(f"/{self.collection}/items"), self.key, {"content": as_item(entry)[:1900]}, self.timeout)
            added += 1
        return added

    def closest(self, report: dict) -> dict | None:
        """The recorded attack this most resembles, or None. Never raises."""
        mine = report_traits(report)
        if len(mine) < MIN_TRAITS:
            return None
        try:
            out = self._call("POST", self._url(f"/{self.collection}/search"), self.key, {"input": ". ".join(sorted(mine))}, self.timeout)
        except Exception:
            return None
        best, score = None, 0.0
        for hit in out.get("results", []):
            parsed = _parse(str(hit.get("content", "")))
            if not parsed or not parsed[1] or parsed[1].get("package") == report.get("package"):
                continue
            theirs, known = parsed
            overlap = len(mine & theirs) / len(mine | theirs)
            named = 0.01 if known.get("incident") else 0.0     # on a tie, the attack people have heard of
            if overlap >= MIN_OVERLAP and overlap + named > score:
                best, score = {**known, "overlap": round(overlap, 2)}, overlap + named
        return best
