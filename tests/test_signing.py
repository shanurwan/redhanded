import base64
import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

from redhanded.signing import Signer, verify
from tests.test_web import get, post, set_guard, site  # noqa: F401  (the site fixture)

spec = importlib.util.spec_from_file_location("check_s", Path(__file__).parent.parent / "action" / "check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

ANSWER = {"package": "left-pad", "version": "1.3.0", "integrity": "sha512-abc", "verdict": "CLEAN",
          "rules": "2026-11-07.5", "scan_id": "rh-20261108-120000-000001"}


def test_key_is_made_once_private_and_kept(tmp_path):
    a = Signer.at(tmp_path / "k" / "signing.key")
    b = Signer.at(tmp_path / "k" / "signing.key")
    assert a.key_id == b.key_id and len(a.key_id) == 16
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "k" / "signing.key").stat().st_mode) == 0o600


def test_signature_holds_and_any_change_breaks_it(tmp_path):
    s = Signer.at(tmp_path / "signing.key", clock=lambda: 0)
    signed = s.sign(ANSWER)
    assert signed["statement"]["signed_at"] == "1970-01-01T00:00:00Z"
    assert verify(s.public()["key"], signed, ANSWER)["verdict"] == "CLEAN"
    # The payload is what was signed: a forged verdict inside it fails.
    forged = json.loads(base64.b64decode(signed["payload"]))
    forged["verdict"] = "CLEAN" if ANSWER["verdict"] != "CLEAN" else "HIGH"
    with pytest.raises(ValueError, match="does not match"):
        verify(s.public()["key"], {**signed, "payload": base64.b64encode(json.dumps(forged).encode()).decode()})
    # An answer that says something other than its statement fails.
    with pytest.raises(ValueError, match="verdict"):
        verify(s.public()["key"], signed, {**ANSWER, "verdict": "HIGH"})
    # Another key fails.
    with pytest.raises(ValueError, match="does not match"):
        verify(Signer.at(tmp_path / "other.key").public()["key"], signed)


def test_nothing_to_sign_without_a_verdict_on_known_bytes(tmp_path):
    s = Signer.at(tmp_path / "signing.key")
    assert s.sign({**ANSWER, "verdict": None}) is None
    assert s.sign({**ANSWER, "integrity": ""}) is None


def test_site_signs_each_verdict_and_publishes_its_key(site, tmp_path):  # noqa: F811
    base, scanner, cfg, calls = site
    status, _, _ = get(base + "/api/key")
    assert status == 404
    scanner.signer = Signer.at(tmp_path / "signing.key")
    set_guard(cfg.guard_state)
    _, body = post(base + "/api/scan", {"package": "left-pad@1.3.0"})
    scanner.run_one(scanner._queue.get_nowait())
    job = json.loads(get(f"{base}/api/jobs/{body['job']}")[2])
    key = json.loads(get(base + "/api/key")[2])
    statement = verify(key["key"], job["result"]["signed"], job["result"])
    assert (statement["package"], statement["verdict"], statement["key_id"]) == ("left-pad", "CLEAN", key["key_id"])


def test_pr_check_verifies_with_openssl(tmp_path):
    s = Signer.at(tmp_path / "signing.key")
    row = {**ANSWER, "signed": s.sign(ANSWER)}
    assert check.check_signature(s.public(), row) == ""
    assert "differs" in check.check_signature(s.public(), {**row, "verdict": "HIGH"})
    assert "does not match" in check.check_signature(Signer.at(tmp_path / "other.key").public(), row)
    assert check.check_signature(s.public(), ANSWER) == "the verdict is not signed"


def run_check(monkeypatch, tmp_path, key, packages, pin=""):
    (tmp_path / "package-lock.json").write_text('{"packages": {}}')
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setenv("REDHANDED_KEY_ID", pin)
    monkeypatch.setattr("sys.argv", ["check.py", "http://rh"])
    monkeypatch.setattr(check, "git", lambda *a: "")

    def call(server, path, body=None):
        if path == "/api/key":
            return key
        return {"job": "j"} if body else {"state": "done", "result": {"packages": packages}}
    monkeypatch.setattr(check, "call", call)
    return check.main()


def test_pr_check_fails_on_unsigned_or_unpinned_and_keeps_statements(monkeypatch, tmp_path):
    s = Signer.at(tmp_path / "signing.key")
    good = [{**ANSWER, "reasons": [], "signed": s.sign(ANSWER)}]
    assert run_check(monkeypatch, tmp_path, s.public(), good) == 0
    sarif = json.loads((tmp_path / "redhanded.sarif").read_text())
    assert sarif["runs"][0]["results"] == []          # CLEAN is not a finding
    assert run_check(monkeypatch, tmp_path, s.public(), good, pin=s.key_id) == 0
    assert run_check(monkeypatch, tmp_path, s.public(), good, pin="0" * 16) == 1
    assert run_check(monkeypatch, tmp_path, s.public(), [{**ANSWER, "reasons": []}]) == 1
    assert run_check(monkeypatch, tmp_path, {"error": "down"}, good) == 1
    blocked = {**ANSWER, "verdict": "HIGH"}
    rows = [{**blocked, "reasons": ["stole a key"], "signed": s.sign(blocked)}]
    assert run_check(monkeypatch, tmp_path, s.public(), rows) == 1
    result = json.loads((tmp_path / "redhanded.sarif").read_text())["runs"][0]["results"][0]
    assert verify(s.public()["key"], result["properties"]["redhanded_signed"])["verdict"] == "HIGH"
