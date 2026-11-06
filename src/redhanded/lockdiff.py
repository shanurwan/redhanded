"""Work out which packages a PR adds or changes, from package-lock.json alone.

We read only the lockfile, never the customer's own source code.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Change:
    name: str
    path: str                 # lockfile key, e.g. node_modules/a/node_modules/b
    old_version: str | None   # None when newly added
    new_version: str
    integrity: str | None     # sha512-... from the lockfile
    resolved: str | None
    has_install_script: bool

    @property
    def spec(self) -> str:
        return f"{self.name}@{self.new_version}"


class LockfileError(ValueError):
    pass


def _packages(lock: dict) -> dict[str, dict]:
    version = lock.get("lockfileVersion")
    if version not in (2, 3):
        raise LockfileError(f"unsupported lockfileVersion {version!r}; need npm 7 or later (v2/v3)")
    pkgs = lock.get("packages")
    if not isinstance(pkgs, dict):
        raise LockfileError("lockfile has no 'packages' map")
    return {k: v for k, v in pkgs.items() if k and isinstance(v, dict) and not v.get("link")}


def _name(path: str, entry: dict) -> str:
    return entry.get("name") or path.rsplit("node_modules/", 1)[-1]


def diff(old: dict | None, new: dict) -> list[Change]:
    """Packages that are new, or whose version or integrity changed."""
    before = _packages(old) if old else {}
    after = _packages(new)
    changes = []
    for path in sorted(after):
        entry = after[path]
        if "version" not in entry or "node_modules/" not in path:
            continue
        prev = before.get(path)
        if prev and prev.get("version") == entry["version"] and prev.get("integrity") == entry.get("integrity"):
            continue
        changes.append(Change(
            name=_name(path, entry),
            path=path,
            old_version=prev.get("version") if prev else None,
            new_version=entry["version"],
            integrity=entry.get("integrity"),
            resolved=entry.get("resolved"),
            has_install_script=bool(entry.get("hasInstallScript")),
        ))
    return changes
