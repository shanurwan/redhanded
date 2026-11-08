#!/usr/bin/env python3
"""PR check: send what the pull request changes to RedHanded and fail on block.

Standard library only. Registry packages go by lockfile, and only by lockfile. A
package vendored into the repo and linked from the lockfile has no bytes on the
registry, so it is packed and uploaded. An answer that never arrives fails the check,
and so does a package with no current evidence.

Each verdict comes back signed. The check verifies every signature with openssl and
fails on one that does not hold or says something else, and on a server key other
than REDHANDED_KEY_ID when that is set. The signed statements go into the SARIF.
"""
import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

BLOCK = {"HIGH", "CRITICAL"}
TIMEOUT_S = 15 * 60


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True).stdout


def call(server: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(server + path, data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json", "User-Agent": "redhanded-action",
                                          # Lets the service count connected repos. A hash, so it never learns the name.
                                          "X-RedHanded-Repo": hashlib.sha256(os.environ.get("GITHUB_REPOSITORY", "").encode()).hexdigest()[:32]})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def pack(folder: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(folder.rglob("*")):
            if path.is_file() and not path.is_symlink() and "node_modules" not in path.parts:
                tar.add(path, arcname="package/" + path.relative_to(folder).as_posix(), recursive=False)
    return buf.getvalue()


def changed_vendored(lock: dict, base: str) -> list[Path]:
    """Linked packages in the lockfile whose folder this PR touches."""
    out = []
    for entry in lock.get("packages", {}).values():
        target = entry.get("resolved") if entry.get("link") else None
        if target and git("diff", "--name-only", f"origin/{base}...HEAD", "--", target).strip():
            out.append(Path(target))
    return out


def wait(server: str, job: str) -> dict:
    deadline = time.monotonic() + TIMEOUT_S
    while time.monotonic() < deadline:
        j = call(server, f"/api/jobs/{job}")
        if j["state"] in ("done", "error"):
            return j
        time.sleep(3)
    return {"state": "error", "error": "timed out waiting for a verdict"}


def server_key(server: str) -> dict | None:
    try:
        return call(server, "/api/key")
    except urllib.error.HTTPError as e:
        return None if e.code == 404 else {"error": f"key answered {e.code}"}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"error": str(e)}


def check_signature(key: dict, r: dict) -> str:
    """'' when the verdict is signed by `key` and the signature says what the answer says, else why not."""
    s = r.get("signed")
    if not isinstance(s, dict):
        return "the verdict is not signed"
    try:
        payload, sig = base64.b64decode(s["payload"]), base64.b64decode(s["signature"])
        with tempfile.TemporaryDirectory() as d:
            files = {"k": key["pem"].encode(), "p": payload, "s": sig}
            for name, data in files.items():
                Path(d, name).write_bytes(data)
            p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f"{d}/k", "-rawin",
                                "-in", f"{d}/p", "-sigfile", f"{d}/s"], capture_output=True)
        if p.returncode:
            return "the signature does not match"
        statement = json.loads(payload)
    except FileNotFoundError:
        return "openssl is needed to check the signature"
    except (KeyError, ValueError, TypeError):
        return "the signature cannot be read"
    wrong = [k for k in ("package", "version", "integrity", "verdict") if statement.get(k) != r.get(k)]
    return f"the signed {', '.join(wrong)} differs from the answer" if wrong else ""


def sarif(rows: list, server: str, statements: dict | None = None) -> dict:
    """The verdicts as SARIF, so they can sit in GitHub code scanning and an audit trail. CLEAN is not a finding."""
    level = {"CRITICAL": "error", "HIGH": "error", "REVIEW": "warning", "ERROR": "warning", "UNSCANNED": "warning"}
    results = []
    for package, verdict, why, link in rows:
        if verdict in level:
            text = f"{package} is {verdict}" + (f": {why}" if why else "") + (f" Evidence: {link}" if link else "")
            result = {"ruleId": f"redhanded/{verdict.lower()}", "level": level[verdict], "message": {"text": text},
                      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}}}]}
            if (statements or {}).get(package):
                result["properties"] = {"redhanded_signed": statements[package]}
            results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "RedHanded", "informationUri": server,
                            "rules": [{"id": f"redhanded/{k.lower()}", "shortDescription": {"text": f"RedHanded verdict: {k}"}} for k in level]}},
        "results": results}]}


def main() -> int:
    server = sys.argv[1].rstrip("/")
    base = os.environ.get("GITHUB_BASE_REF", "main")
    if not Path("package-lock.json").is_file():
        print("no package-lock.json")
        return 0
    new = Path("package-lock.json").read_text()
    old = git("show", f"origin/{base}:package-lock.json")

    rows, failed, blocked, statements = [], False, [], {}
    key = server_key(server)
    pin = os.environ.get("REDHANDED_KEY_ID", "").strip()
    if key is None or "error" in key or (pin and key.get("key_id") != pin):
        why = "it has no signing key" if key is None else key.get("error") or f"its key is {key.get('key_id')}, not {pin}"
        rows.append(("signing key", "ERROR", f"cannot check signatures: {why}", ""))
        failed, key = True, None

    def signed(r: dict) -> str:
        if key is None:
            return ""
        why = check_signature(key, r)
        if not why and r.get("signed"):
            statements[f"{r['package']}@{r['version']}"] = r["signed"]
        return why
    for folder in changed_vendored(json.loads(new), base):
        try:
            job = call(server, "/api/scan", {"tarball": base64.b64encode(pack(folder)).decode()})["job"]
            j = wait(server, job)
        except (urllib.error.URLError, OSError, ValueError) as e:
            j = {"state": "error", "error": str(e)}
        if j["state"] != "done":
            rows.append((str(folder), "ERROR", j.get("error", ""), ""))
            failed = True
            continue
        r = j["result"]
        bad = signed(r)
        rows.append((f"{r['package']}@{r['version']}", "ERROR" if bad else r["verdict"], bad or "; ".join(r["reasons"]), server + r["url"]))
        failed |= r["verdict"] in BLOCK or bool(bad)

    try:
        j = wait(server, call(server, "/api/lockfile", {"new_lockfile": new, "old_lockfile": old})["job"])
    except (urllib.error.URLError, OSError, ValueError) as e:
        j = {"state": "error", "error": str(e)}
    if j["state"] != "done":
        rows.append(("package-lock.json", "ERROR", j.get("error", ""), ""))
        failed = True
    else:
        for r in j["result"]["packages"]:
            verdict = r.get("verdict") or "UNSCANNED"
            link = f"{server}/#{r['scan_id']}" if r.get("scan_id") else ""
            bad = signed(r) if r.get("verdict") else ""
            if bad:
                rows.append((f"{r['package']}@{r['version']}", "ERROR", bad, link))
                failed = True
                continue
            rows.append((f"{r['package']}@{r['version']}", verdict, "; ".join(r.get("reasons", [])) or r.get("note", ""), link))
            new_script = os.environ.get("REDHANDED_STRICT") == "true" and any(c.get("kind") == "install_script" for c in r.get("changes", []))
            failed |= verdict in BLOCK or new_script or verdict == "UNSCANNED"    # no current evidence, no pass
            if verdict == "REVIEW":
                print(f"::warning title=RedHanded asks for a person::{r['package']}@{r['version']}: {link or 'see the table'}")
            if verdict in BLOCK or new_script:
                blocked.append({"name": r["package"], "version": r["version"], "integrity": r.get("integrity")})

    if blocked:
        Path(os.environ.get("RUNNER_TEMP", "."), "redhanded-blocked.json").write_text(json.dumps(blocked))
    lines = ["| Package | Verdict | Why | Evidence |", "|---|---|---|---|"]
    lines += [f"| {p} | {v} | {w.replace('|', '/')} | {f'[open]({u})' if u else ''} |" for p, v, w, u in rows]
    table = "\n".join(lines) if rows else "No dependency changes."
    unscanned = sum(1 for _, v, _, _ in rows if v == "UNSCANNED")
    if unscanned:
        table += f"\n\n{unscanned} packages have no current evidence, so this check fails. Finished scans are kept, so running it again covers more of them."
    if statements:
        table += f"\n\n{len(statements)} verdicts signed by key {key['key_id']} and checked. Anyone can check them again from the SARIF."
    print(table)
    Path(os.environ.get("REDHANDED_SARIF", "redhanded.sarif")).write_text(json.dumps(sarif(rows, server, statements), indent=1))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(table + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
