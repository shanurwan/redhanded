import importlib.util
import io
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("guard", Path(__file__).parent.parent / "hooks" / "redhanded_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


@pytest.mark.parametrize("command,expect", [
    ("npm install cline@2.3.0", ["cline@2.3.0"]),
    ("npm i -g openclaw@latest", ["openclaw@latest"]),
    ("cd app && npm install --save-dev @scope/pkg@1.2.3 left-pad", ["@scope/pkg@1.2.3", "left-pad"]),
    ("pnpm add a; yarn add b; bun add c; yarn global add d", ["a", "b", "c", "d"]),
    ("sudo npm install x", ["x"]),
    ("CI=1 npm install y", ["y"]),
    ("npm install", []),
    ("npm install ./local", []),
    ("npm install https://evil.dev/x.tgz", []),
    ("npm test", []),
    ("echo npm install x", []),
    ("git commit -m 'npm install x'", []),
])
def test_it_finds_what_a_command_would_install(command, expect):
    assert guard.packages(command) == expect


def _run(monkeypatch, capsys, command, answers, strict=False):
    calls = []

    def call(path, body=None, timeout=30):
        calls.append((path, body))
        return answers(path, body)
    monkeypatch.setattr(guard, "call", call)
    monkeypatch.setattr(guard, "STRICT", strict)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})))
    code = guard.main()
    return code, capsys.readouterr().err, calls


def _server(verdict, pinned=None):
    def answers(path, body):
        if path == "/api/scan":
            return {"job": "scan"}
        if path == "/api/repair":
            return {"job": "repair"}
        if path == "/api/jobs/scan":
            return {"state": "done", "verdict": verdict, "result": {"package": "cline", "version": "2.3.0", "verdict": verdict, "url": "/#rh-1", "reasons": [f"{verdict}: installed another program on the whole machine"]}}
        return {"state": "done", "result": {"pinned": {"version": pinned} if pinned else None}}
    return answers


def test_a_blocked_package_is_refused_and_the_agent_told_what_to_use(monkeypatch, capsys):
    code, err, _ = _run(monkeypatch, capsys, "npm install cline@2.3.0", _server("HIGH", "2.2.3"))
    assert code == 2 and "BLOCKED" in err and "whole machine" in err and "cline@2.2.3" in err and "/#rh-1" in err


def test_with_no_clean_version_the_agent_is_told_to_ask(monkeypatch, capsys):
    code, err, _ = _run(monkeypatch, capsys, "npm install cline@2.3.0", _server("CRITICAL"))
    assert code == 2 and "asking the user" in err


def test_a_clean_package_goes_ahead(monkeypatch, capsys):
    code, _, calls = _run(monkeypatch, capsys, "npm install cline@2.3.0", _server("CLEAN"))
    assert code == 0 and not any(p == "/api/repair" for p, _ in calls)


def test_commands_that_install_nothing_never_call_out(monkeypatch, capsys):
    code, _, calls = _run(monkeypatch, capsys, "npm test", _server("HIGH"))
    assert code == 0 and calls == []


def test_when_the_service_is_down_it_warns_unless_strict(monkeypatch, capsys):
    def down(path, body):
        raise OSError("unreachable")
    assert _run(monkeypatch, capsys, "npm install x", down)[0] == 0
    assert _run(monkeypatch, capsys, "npm install x", down, strict=True)[0] == 2


def test_powershell_is_watched_too(monkeypatch, capsys):
    monkeypatch.setattr(guard, "call", lambda p, b=None, timeout=30: _server("HIGH", "2.2.3")(p, b))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "PowerShell", "tool_input": {"command": "npm install cline@2.3.0"}})))
    assert guard.main() == 2
