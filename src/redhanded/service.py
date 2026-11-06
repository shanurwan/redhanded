"""The questions an agent or a CI job asks RedHanded, behind one small API.

A verdict belongs to exact bytes: the cache key is the tarball's sha512 plus
the rules version, so the same package always gets the same recorded answer,
and changing a rule never serves a verdict the new rules did not make.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import re
import sqlite3
import time
import urllib.parse
from dataclasses import asdict
from pathlib import Path
from typing import Callable

from . import behaviour, lockdiff
from . import repair
from .runner import Report, ScanConfig, ScanError, _get, detonate, scan, tarball_identity
from .verdict import RULES_VERSION, Verdict

NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SCAN_ID = re.compile(r"^rh-\d{8}-\d{6}-[0-9a-f]{6}$")
INSTRUCTIONS = """\
RedHanded makes new code prove itself before an agent trusts it. It runs npm packages
and agent skills on a disposable machine baited with fake credentials and a fake
internet, and reports what they tried to do. Call check_package or compare_versions
before you add or upgrade a dependency, check_lockfile_change before you open or merge
a PR that changes package-lock.json, check_skill before you install a skill, and
find_safe_version after a block. Treat advice "block" as do-not-install, "review" as ask
a human. Fixed rules decide from recorded behaviour; text under test cannot change it."""
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

    def check_tarball(self, tarball: bytes) -> dict:
        """An uploaded package: same bytes, same verdict, like any other."""
        name, version = tarball_identity(tarball)
        validate(name, version)
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
        hit = self.cache.get(integrity)
        if hit:
            return self._answer(hit, cached=True)
        report = detonate(name, version, tarball, integrity, self.cfg)
        self.cache.put(report)
        return self._answer(asdict(report), cached=False)

    def versions(self, name: str) -> list[str]:
        data = json.loads(_get(f"{self.cfg.registry}/{urllib.parse.quote(name, safe='@')}", 60 << 20))
        return list(data.get("versions", {}))

    def _full_report(self, name: str, version: str, integrity: str | None = None) -> dict:
        """The stored evidence for a version, scanning it if it has none yet."""
        out = self.check(name, version, integrity=integrity)
        report = self.cache.get(out["integrity"])
        if report is None:
            raise ScanError(f"no stored report for {name}@{version}")
        return report

    def changes_between(self, name: str, old_version: str, new_version: str, new_integrity: str | None = None) -> list[dict]:
        return behaviour.diff(self._full_report(name, old_version), self._full_report(name, new_version, new_integrity))

    def compare(self, name: str, new_version: str, previous: str | None = None, integrity: str | None = None) -> dict:
        """The new version's verdict, plus everything it does that the version before it never did."""
        validate(name, new_version)
        if previous:
            validate(name, previous)
        else:
            older = behaviour.older_versions(self.versions(name), new_version)
            if not older:
                out = self.check(name, new_version, integrity=integrity)
                return {**out, "previous_version": None, "changes": [], "note": "no earlier release to compare with"}
            previous = older[0]
        out = self.check(name, new_version, integrity=integrity)
        changes = self.changes_between(name, previous, new_version, integrity)
        level, why = behaviour.judge(Verdict[out["verdict"]], changes)
        return {**out, "verdict": level.name, "advice": ADVICE[level.name], "reasons": [*out["reasons"], *why],
                "version_alone": out["verdict"], "previous_version": previous, "changes": changes}

    def repair(self, name: str, blocked: str, integrity: str | None = None) -> dict:
        validate(name, blocked)
        return repair.from_env(name, blocked, self.versions(name),
                               lambda n, v: self.check(n, v),
                               lambda n, a, b, i: self.changes_between(n, a, b, i), integrity).run()

    def check_lockfile(self, old: str | None, new: str, max_scans: int = 10) -> dict:
        try:
            changes = lockdiff.diff(json.loads(old) if old else None, json.loads(new))
        except (ValueError, lockdiff.LockfileError) as e:
            raise InputError(f"could not read the lockfile: {e}") from e
        results, scanned = [], 0
        # The budget goes first to what runs code on install, then to the shallowest packages.
        for c in sorted(changes, key=lambda c: (not c.has_install_script, c.path.count("node_modules/"), c.path)):
            allow_scan = scanned < max_scans
            try:
                r = self.check(c.name, c.new_version, scan_if_missing=allow_scan, integrity=c.integrity or None)
            except (InputError, ScanError) as e:
                r = {"package": c.name, "version": c.new_version, "verdict": None, "advice": "unknown",
                     "note": str(e)}
            scanned += bool(r.get("cached") is False and r.get("verdict"))
            # What the update changed is the strongest signal for a hijack, while there is budget to run the old one too.
            if c.old_version and r.get("verdict") in ("CLEAN", "REVIEW") and scanned < max_scans:
                try:
                    known = self.cache.get(r["integrity"]) is not None
                    changes = self.changes_between(c.name, c.old_version, c.new_version, c.integrity or None) if known else []
                    level, why = behaviour.judge(Verdict[r["verdict"]], changes)
                    scanned += 1
                    r = {**r, "verdict": level.name, "advice": ADVICE[level.name], "reasons": [*r.get("reasons", []), *why], "changes": changes}
                except Exception as e:  # a comparison adds evidence; failing one must not lose the verdict
                    r = {**r, "changes_note": f"could not compare with {c.old_version}: {type(e).__name__}"}
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
