#!/usr/bin/env python3
"""Lab only. GuardDog (Datadog's open-source static scanner) on the exact sets the reader and sandbox were measured on.

Malicious: the 898 holdout paths in /lab/out/reader-holdout.jsonl. Clean: the 154 popular packages in
reader-benign_test.jsonl and the recent CLEAN releases in reader-watch.jsonl. Nothing is run, only scanned.
Writes /lab/out/guarddog-<set>.jsonl, one row per package: flagged = GuardDog reported any rule hit.
"""
import concurrent.futures as cf, json, shutil, subprocess, sys, tarfile, tempfile, urllib.request
from pathlib import Path

GD = "/lab/gd/bin/guarddog"


def scan(root: Path) -> dict:
    p = subprocess.run([GD, "npm", "scan", str(root), "--output-format", "json"], capture_output=True, text=True, timeout=600)
    try:
        out = json.loads(p.stdout)
    except Exception:
        return {"state": "failed", "note": (p.stderr or p.stdout)[-300:]}
    res = out.get("results") or {}
    hits = sorted(k for k, v in res.items() if v)
    threat = [h for h in hits if not h.startswith("capability-")]
    return {"state": "scanned", "issues": out.get("issues", 0), "rules": hits, "flagged": bool(threat), "flagged_any": bool(hits)}


def mal_row(path: str) -> dict:
    row = {"path": path, "kind": "compromised" if "/compromised_lib/" in path else "intent"}
    tmp = tempfile.mkdtemp(prefix="g-", dir="/lab/tmp")
    try:
        Path(tmp, "s.zip").write_bytes(subprocess.run(["git", "-c", "safe.directory=/lab/dataset", "-C", "/lab/dataset", "cat-file", "blob", f"HEAD:{path}"], capture_output=True, timeout=60).stdout)
        subprocess.run(["unzip", "-q", "-o", "-P", "infected", f"{tmp}/s.zip", "-d", f"{tmp}/x"], capture_output=True, timeout=120)
        ms = sorted((m for m in Path(tmp, "x").rglob("package.json") if "node_modules" not in m.parts), key=lambda x: len(x.parts))
        if not ms:
            return {**row, "state": "no_package_json"}
        return {**row, **scan(ms[0].parent)}
    except Exception as e:
        return {**row, "state": "failed", "note": type(e).__name__}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def npm_row(item) -> dict:
    name, version, kind = item
    row = {"name": name, "version": version, "kind": kind}
    tmp = tempfile.mkdtemp(prefix="g-", dir="/lab/tmp")
    try:
        req = urllib.request.Request(f"https://registry.npmjs.org/{name.replace('/', '%2F')}/{version}", headers={"User-Agent": "rh-lab"})
        with urllib.request.urlopen(req, timeout=30) as r:
            meta = json.load(r)
        with urllib.request.urlopen(meta["dist"]["tarball"], timeout=60) as r:
            Path(tmp, "p.tgz").write_bytes(r.read())
        with tarfile.open(f"{tmp}/p.tgz") as t:
            t.extractall(f"{tmp}/x", filter="data")
        root = next(p.parent for p in sorted(Path(tmp, "x").rglob("package.json"), key=lambda x: len(x.parts)))
        return {**row, **scan(root)}
    except Exception as e:
        return {**row, "state": "failed", "note": type(e).__name__}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def rows(f):
    return [json.loads(l) for l in open(f"/lab/out/{f}.jsonl") if l.strip()]


SET = sys.argv[1]
if SET == "malicious":
    todo, fn = sorted({r["path"] for r in rows("reader-holdout")}), mal_row
elif SET == "popular":
    todo, fn = sorted({(r["name"], r.get("version") or "latest", "popular") for r in rows("reader-benign_test") if r.get("name")}), npm_row
else:
    todo, fn = sorted({(r["name"], r["version"], "recent") for r in rows("reader-watch") if r.get("name") and r.get("version")}), npm_row
OUT = Path(f"/lab/out/guarddog-{SET}.jsonl")
OUT.write_text("")
print(SET, "todo", len(todo), flush=True)
with OUT.open("a") as out, cf.ThreadPoolExecutor(6) as ex:
    for i, row in enumerate(ex.map(fn, todo)):
        out.write(json.dumps(row) + "\n")
        out.flush()
        if i % 100 == 0:
            print(i, flush=True)
print("done", SET, flush=True)
