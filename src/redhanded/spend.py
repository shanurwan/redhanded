"""Spend guard for a fixed Vultr credit grant.

Vultr has no spend alert, so RedHanded reads the account balance itself
and decides what may run. It fails closed: if the balance cannot be read
for too long, everything pauses, because unknown spend is not safe spend.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Iterator

API_BASE = "https://api.vultr.com/v2"
HOURS_PER_MONTH = 672   # Vultr bills hourly up to a monthly cap of 672 hours


class GuardState(IntEnum):
    OK = 0
    STOP_TIER2 = 1      # no throwaway VMs, no public feed
    PAUSE_ALL = 2       # no scans at all


class VultrError(RuntimeError):
    pass


# (method, url, headers, body) -> (status, body bytes)
Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]


def _urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class VultrClient:
    def __init__(self, api_key: str, base: str = API_BASE, transport: Transport | None = None):
        if not api_key:
            raise VultrError("VULTR_API_KEY is empty")
        self._key = api_key
        self._base = base.rstrip("/")
        self._send = transport or _urllib_transport

    def get(self, path: str, params: dict[str, str] | None = None) -> dict:
        url = self._base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        status, body = self._send("GET", url, {"Authorization": f"Bearer {self._key}"}, None)
        if status != 200:
            # Never echo the request headers: they carry the key.
            raise VultrError(f"GET {path} returned {status}: {body[:200].decode('utf-8', 'replace')}")
        return json.loads(body)

    def paged(self, path: str, key: str, per_page: int = 100) -> Iterator[dict]:
        cursor = ""
        while True:
            params = {"per_page": str(per_page)}
            if cursor:
                params["cursor"] = cursor
            page = self.get(path, params)
            yield from page.get(key, [])
            cursor = page.get("meta", {}).get("links", {}).get("next", "")
            if not cursor:
                return


@dataclass(frozen=True)
class AccountSnapshot:
    balance: float           # negative means credit left on the account
    pending_charges: float   # usage this month not yet invoiced
    taken_at: float

    @property
    def remaining_credit(self) -> float:
        return -self.balance - self.pending_charges

    @classmethod
    def read(cls, client: VultrClient, now: float | None = None) -> "AccountSnapshot":
        acct = client.get("/account")["account"]
        return cls(float(acct["balance"]), float(acct["pending_charges"]), time.time() if now is None else now)


@dataclass(frozen=True)
class GuardPolicy:
    grant: float = 200.0
    stop_tier2_at: float = 120.0
    pause_all_at: float = 160.0
    max_staleness_s: float = 1800.0

    def __post_init__(self) -> None:
        if not 0 < self.stop_tier2_at < self.pause_all_at <= self.grant:
            raise ValueError("need 0 < stop_tier2_at < pause_all_at <= grant")


@dataclass(frozen=True)
class GuardDecision:
    state: GuardState
    spent: float | None
    reason: str


def evaluate(policy: GuardPolicy, snap: AccountSnapshot | None, now: float) -> GuardDecision:
    if snap is None:
        return GuardDecision(GuardState.PAUSE_ALL, None, "balance never read")
    age = now - snap.taken_at
    if age > policy.max_staleness_s:
        return GuardDecision(GuardState.PAUSE_ALL, None, f"balance is {age / 60:.0f} min old")
    spent = round(policy.grant - snap.remaining_credit, 2)
    if spent >= policy.pause_all_at:
        return GuardDecision(GuardState.PAUSE_ALL, spent, f"spent ${spent:.2f} >= ${policy.pause_all_at:.0f}")
    if spent >= policy.stop_tier2_at:
        return GuardDecision(GuardState.STOP_TIER2, spent, f"spent ${spent:.2f} >= ${policy.stop_tier2_at:.0f}")
    return GuardDecision(GuardState.OK, spent, f"spent ${spent:.2f} of ${policy.grant:.0f}")


@dataclass(frozen=True)
class RunningCost:
    kind: str
    label: str
    plan: str
    hourly: float


def running_costs(client: VultrClient) -> list[RunningCost]:
    """Everything billing by the hour right now, priced from the plan list."""
    monthly = {p["id"]: float(p["monthly_cost"]) for p in client.paged("/plans", "plans")}
    out = [
        RunningCost("instance", i.get("label") or i["id"], i["plan"], monthly.get(i["plan"], 0.0) / HOURS_PER_MONTH)
        for i in client.paged("/instances", "instances")
    ]
    for b in client.paged("/blocks", "blocks"):
        out.append(RunningCost("block", b.get("label") or b["id"], f"{b.get('size_gb', '?')} GB",
                               float(b.get("cost", 0.0)) / HOURS_PER_MONTH))
    return out


class StateFile:
    """The guard's last decision on disk. Workers read it before taking a job."""

    def __init__(self, path: str):
        self.path = path

    def write(self, decision: GuardDecision, now: float) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"state": decision.state.name, "spent": decision.spent,
                       "reason": decision.reason, "at": now}, f)
        os.replace(tmp, self.path)

    def allows(self, need: GuardState, now: float, max_age_s: float = 1800.0) -> bool:
        """True if work that requires the guard to be at most `need` may run."""
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            state = GuardState[d["state"]]
            at = float(d["at"])
        except (OSError, ValueError, KeyError):
            return False
        return now - at <= max_age_s and state <= need
