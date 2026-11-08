import importlib.util
import io
import tarfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("check", Path(__file__).parent.parent / "action" / "check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def test_pack_uses_npm_layout_and_skips_node_modules(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("")
    with tarfile.open(fileobj=io.BytesIO(check.pack(tmp_path)), mode="r:gz") as tar:
        assert tar.getnames() == ["package/package.json"]


def test_unanswered_scan_fails_closed(monkeypatch):
    monkeypatch.setattr(check, "TIMEOUT_S", 0)
    assert check.wait("http://unused", "job")["state"] == "error"


def test_no_current_evidence_fails_the_check(monkeypatch, tmp_path):
    (tmp_path / "package-lock.json").write_text('{"packages": {}}')
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setattr("sys.argv", ["check.py", "http://rh"])
    monkeypatch.setattr(check, "git", lambda *a: "")
    monkeypatch.setattr(check, "server_key", lambda s: {"key_id": "k"})    # signatures have their own tests
    monkeypatch.setattr(check, "check_signature", lambda k, r: "")
    packages = [{"package": "a", "version": "1.0.0", "verdict": None, "note": "evidence expired, it must run again"}]
    monkeypatch.setattr(check, "call", lambda s, p, b=None: {"job": "j"} if b else {"state": "done", "result": {"packages": packages}})
    assert check.main() == 1
    packages[0].update(verdict="CLEAN", reasons=[])
    assert check.main() == 0


rspec = importlib.util.spec_from_file_location("repair_action", Path(__file__).parent.parent / "action" / "repair.py")
repair_action = importlib.util.module_from_spec(rspec)
rspec.loader.exec_module(repair_action)


def test_fix_pr_body_shows_what_was_added_and_each_step():
    body = repair_action.body_for({"name": "p", "version": "2.0.0"}, {
        "pinned": {"version": "1.9.0", "scan_id": "rh-1"}, "decided_by": "agent",
        "new_in_blocked_version": [{"kind": "install_script", "what": "postinstall"}, {"kind": "domain", "what": "x.dev`"}],
        "steps": [{"tool": "check_version", "args": {"version": "1.9.0"}, "result": {"verdict": "CLEAN"}},
                  {"tool": "pin_version", "args": {"version": "1.9.0"}, "result": {"pinned": "1.9.0"}}]}, "https://rh")
    assert "`p@2.0.0`" in body and "install script: `postinstall`" in body and "`x.dev`" in body
    assert "Ran 1.9.0 in the sandbox: **CLEAN**" in body and "https://rh/#rh-1" in body


def test_repair_does_nothing_without_a_token(monkeypatch, tmp_path):
    monkeypatch.delenv("REDHANDED_TOKEN", raising=False)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr("sys.argv", ["repair.py", "https://rh"])
    assert repair_action.main() == 0


def test_sarif_lists_findings_and_leaves_out_clean():
    out = check.sarif([("a@1.0.0", "CRITICAL", "stole keys", "http://rh/#x"), ("b@1.0.0", "CLEAN", "", ""), ("c@1.0.0", "UNSCANNED", "no evidence", "")], "http://rh")
    results = out["runs"][0]["results"]
    assert out["version"] == "2.1.0" and [r["ruleId"] for r in results] == ["redhanded/critical", "redhanded/unscanned"]
    assert results[0]["level"] == "error" and "http://rh/#x" in results[0]["message"]["text"]
    ids = {r["id"] for r in out["runs"][0]["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in results} <= ids
