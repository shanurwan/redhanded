"""The questions an agent or a CI job asks RedHanded, behind one small API.

A verdict belongs to exact bytes: the cache key is the tarball's sha512 plus
the rules version, so the same package always gets the same recorded answer,
and changing a rule never serves a verdict the new rules did not make.
"""
from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import time
import urllib.parse
from dataclasses import asdict
from pathlib import Path
from typing import Callable

from . import lockdiff
from .runner import Report, ScanConfig, ScanError, _get, scan
from .verdict import RULES_VERSION, Verdict

NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SCAN_ID = re.compile(r"^rh-\d{8}-\d{6}-[0-9a-f]{6}$")
ADVICE = {"CLEAN": "allow", "REVIEW": "review", "HIGH": "block", "CRITICAL": "block"}


class InputError(ValueError):
    pass


def validate(name: str, version: str) -> None:
    if not (0 < len(name) <= 214 and NAME.match(name)):
        raise InputError(f"not a valid npm package name: {name!r}")
    if not VERSION.match(version):
        raise InputError(f"give an exact version like 1.2.3, not {version!r}")


class Cache:
    """One short-lived connection per call: MCP runs sync tools on worker threads."""

    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS verdicts (
                integrity TEXT NOT NULL, rules TEXT NOT NULL, package TEXT NOT NULL, version TEXT NOT NULL,
                verdict TEXT NOT NULL, report TEXT NOT NULL, scanned_at REAL NOT NULL,
                PRIMARY KEY (integrity, rules))""")

    @contextlib.contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=30)
        try:
            with db:
                yield db
        finally:
            db.close()

    def get(self, integrity: str) -> dict | None:
        with self._db() as db:
            row = db.execute("SELECT report, scanned_at FROM verdicts WHERE integrity = ? AND rules = ?",
                             (integrity, RULES_VERSION)).fetchone()
        return {**json.loads(row[0]), "scanned_at": row[1]} if row else None

    def put(self, report: Report) -> None:
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO verdicts VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (report.integrity, RULES_VERSION, report.package, report.version, report.verdict,
                        json.dumps(asdict(report)), time.time()))


def registry_integrity(name: str, version: str, registry: str) -> str:
    meta = json.loads(_get(f"{registry}/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(version)}", 5 << 20))
    integrity = meta.get("dist", {}).get("integrity", "")
    if not integrity.startswith("sha512-"):
        raise ScanError(f"{name}@{version} has no sha512 integrity in the registry")
    return integrity


class Service:
    def __init__(self, cache: Cache, cfg: ScanConfig | None = None,
                 scanner: Callable[..., Report] = scan,
                 resolve: Callable[[str, str, str], str] = registry_integrity):
        self.cache, self.cfg = cache, cfg or ScanConfig()
        self._scan, self._resolve = scanner, resolve

    def check(self, name: str, version: str, scan_if_missing: bool = True, integrity: str | None = None) -> dict:
        validate(name, version)
        integrity = integrity or self._resolve(name, version, self.cfg.registry)
        hit = self.cache.get(integrity)
        if hit:
            return self._answer(hit, cached=True)
        if not scan_if_missing:
            return {"package": name, "version": version, "integrity": integrity, "verdict": None,
                    "advice": "unknown", "cached": False, "note": "not scanned yet"}
        report = self._scan(name, version, self.cfg, integrity)
        self.cache.put(report)
        return self._answer(asdict(report), cached=False)

    def check_lockfile(self, old: str | None, new: str, max_scans: int = 10) -> dict:
        try:
            changes = lockdiff.diff(json.loads(old) if old else None, json.loads(new))
        except (ValueError, lockdiff.LockfileError) as e:
            raise InputError(f"could not read the lockfile: {e}") from e
        results, scanned = [], 0
        for c in changes:
            allow_scan = scanned < max_scans
            try:
                r = self.check(c.name, c.new_version, scan_if_missing=allow_scan, integrity=c.integrity or None)
            except (InputError, ScanError) as e:
                r = {"package": c.name, "version": c.new_version, "verdict": None, "advice": "unknown",
                     "note": str(e)}
            scanned += bool(r.get("cached") is False and r.get("verdict"))
            results.append({**r, "previous_version": c.old_version, "has_install_script": c.has_install_script})
        known = [Verdict[r["verdict"]] for r in results if r.get("verdict")]
        worst = max(known, default=Verdict.CLEAN).name
        unknown = sum(r.get("verdict") is None for r in results)
        advice = ADVICE[worst] if not unknown or worst in ("HIGH", "CRITICAL") else "review"
        return {"changed": len(results), "worst_verdict": worst, "unscanned": unknown,
                "advice": advice, "packages": results}

    def report(self, scan_id: str) -> dict:
        if not SCAN_ID.match(scan_id):
            raise InputError("not a RedHanded scan id")
        path = Path(self.cfg.scans_dir) / scan_id / "report.json"
        if not path.is_file():
            raise InputError(f"no report for {scan_id}")
        return json.loads(path.read_text())

    @staticmethod
    def _answer(report: dict, cached: bool) -> dict:
        return {
            "package": report["package"], "version": report["version"], "integrity": report["integrity"],
            "verdict": report["verdict"], "advice": ADVICE[report["verdict"]], "reasons": report["reasons"],
            "container_aware": report["container_aware"], "scan_id": report["scan_id"],
            "rules": RULES_VERSION, "cached": cached,
        }
