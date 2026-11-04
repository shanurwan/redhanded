import io
import json

import pytest

from redhanded.cli import cmd_budget, load_env
from redhanded.spend import (AccountSnapshot, GuardPolicy, GuardState, StateFile, VultrClient,
                             VultrError, evaluate, running_costs)


def fake_api(routes: dict[str, list[dict] | dict], status: int = 200):
    """Transport serving canned JSON; a list value is served page by page."""
    seen: list[str] = []

    def send(method, url, headers, body):
        assert headers["Authorization"] == "Bearer sekrit-key"
        seen.append(url)
        path = url.split("/v2", 1)[1].split("?", 1)[0]
        value = routes[path]
        if isinstance(value, list):
            cursor = url.split("cursor=", 1)[1] if "cursor=" in url else "0"
            value = value[int(cursor)]
        return status, json.dumps(value).encode()

    return send, seen


def account(balance, pending):
    return {"account": {"balance": balance, "pending_charges": pending}}


def test_remaining_credit_counts_pending_charges():
    send, _ = fake_api({"/account": account(-200.0, 12.5)})
    snap = AccountSnapshot.read(VultrClient("sekrit-key", transport=send), now=0)
    assert snap.remaining_credit == pytest.approx(187.5)


@pytest.mark.parametrize("balance,pending,state", [
    (-200.0, 0.0, GuardState.OK),
    (-200.0, 119.99, GuardState.OK),
    (-200.0, 120.0, GuardState.STOP_TIER2),
    (-80.0, 10.0, GuardState.STOP_TIER2),     # an invoice already moved $120 out of credit
    (-200.0, 160.0, GuardState.PAUSE_ALL),
    (-10.0, 0.0, GuardState.PAUSE_ALL),
])
def test_thresholds(balance, pending, state):
    d = evaluate(GuardPolicy(), AccountSnapshot(balance, pending, taken_at=100), now=100)
    assert d.state == state


def test_fails_closed_without_a_fresh_reading():
    policy = GuardPolicy()
    assert evaluate(policy, None, now=0).state == GuardState.PAUSE_ALL
    stale = AccountSnapshot(-200.0, 0.0, taken_at=0)
    assert evaluate(policy, stale, now=policy.max_staleness_s + 1).state == GuardState.PAUSE_ALL


def test_bad_policy_rejected():
    with pytest.raises(ValueError):
        GuardPolicy(stop_tier2_at=170, pause_all_at=160)


def test_http_error_does_not_leak_the_key():
    send, _ = fake_api({"/account": {"error": "Unauthorized IP address"}}, status=401)
    with pytest.raises(VultrError) as e:
        VultrClient("sekrit-key", transport=send).get("/account")
    assert "401" in str(e.value) and "sekrit-key" not in str(e.value)


def test_empty_key_refused():
    with pytest.raises(VultrError):
        VultrClient("")


def test_running_costs_follows_pagination():
    send, seen = fake_api({
        "/plans": [{"plans": [{"id": "vc2-2c-4gb", "monthly_cost": 20.16}], "meta": {"links": {"next": ""}}}],
        "/instances": [
            {"instances": [{"id": "a", "label": "control", "plan": "vc2-2c-4gb"}], "meta": {"links": {"next": "1"}}},
            {"instances": [{"id": "b", "label": "", "plan": "vc2-2c-4gb"}], "meta": {"links": {"next": ""}}},
        ],
        "/blocks": [{"blocks": [], "meta": {"links": {"next": ""}}}],
    })
    costs = running_costs(VultrClient("sekrit-key", transport=send))
    assert [c.label for c in costs] == ["control", "b"]
    assert costs[0].hourly == pytest.approx(0.03)
    assert any("cursor=1" in u for u in seen)


def test_state_file_gates_work(tmp_path):
    sf = StateFile(str(tmp_path / "guard.json"))
    assert not sf.allows(GuardState.STOP_TIER2, now=0)          # no file: nothing runs
    sf.write(evaluate(GuardPolicy(), AccountSnapshot(-200.0, 130.0, 0), 0), now=0)
    assert sf.allows(GuardState.STOP_TIER2, now=10)             # tier 1 scans still run
    assert not sf.allows(GuardState.OK, now=10)                 # tier 2 does not
    assert not sf.allows(GuardState.STOP_TIER2, now=10_000)     # stale state: nothing runs


def test_budget_report(monkeypatch):
    monkeypatch.setenv("RH_CREDIT_EXPIRES", "2026-12-04")
    send, _ = fake_api({
        "/account": account(-200.0, 4.0),
        "/plans": [{"plans": [{"id": "vc2-2c-4gb", "monthly_cost": 20.16}], "meta": {"links": {"next": ""}}}],
        "/instances": [{"instances": [{"id": "a", "label": "control", "plan": "vc2-2c-4gb"}], "meta": {"links": {"next": ""}}}],
        "/blocks": [{"blocks": [], "meta": {"links": {"next": ""}}}],
    })
    out = io.StringIO()
    code = cmd_budget(VultrClient("sekrit-key", transport=send), GuardPolicy(), out=out)
    text = out.getvalue()
    assert code == 0
    assert "$  196.00" in text and "OK" in text and "control" in text and "2026-12-04" in text


def test_load_env_does_not_override(tmp_path, monkeypatch):
    p = tmp_path / ".env"
    p.write_text("# comment\nA=1\nB='two'\n", encoding="utf-8")
    monkeypatch.setenv("A", "keep")
    monkeypatch.delenv("B", raising=False)
    load_env(p)
    import os
    assert os.environ["A"] == "keep" and os.environ["B"] == "two"
