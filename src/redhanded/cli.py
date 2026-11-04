"""Command line: `redhanded budget` and `redhanded guard`."""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
import time
from pathlib import Path

from .spend import (AccountSnapshot, GuardPolicy, GuardState, StateFile, VultrClient,
                    VultrError, evaluate, running_costs)


def load_env(path: Path) -> None:
    """Read KEY=VALUE lines into os.environ without overriding what is already set."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def policy_from_env() -> GuardPolicy:
    return GuardPolicy(
        grant=float(os.environ.get("RH_CREDIT_GRANT", "200")),
        stop_tier2_at=float(os.environ.get("RH_STOP_TIER2_AT", "120")),
        pause_all_at=float(os.environ.get("RH_PAUSE_ALL_AT", "160")),
    )


def _days_left(expires: str, today: dt.date) -> int | None:
    try:
        return (dt.date.fromisoformat(expires) - today).days
    except ValueError:
        return None


def cmd_budget(client: VultrClient, policy: GuardPolicy, out=sys.stdout) -> int:
    now = time.time()
    snap = AccountSnapshot.read(client, now)
    decision = evaluate(policy, snap, now)
    costs = running_costs(client)
    burn = sum(c.hourly for c in costs)

    print(f"credit left    ${snap.remaining_credit:8.2f}   (balance {snap.balance:.2f}, pending {snap.pending_charges:.2f})", file=out)
    print(f"spent of grant ${decision.spent:8.2f} / ${policy.grant:.0f}", file=out)
    print(f"guard          {decision.state.name}  ({decision.reason}; tier 2 stops at ${policy.stop_tier2_at:.0f}, "
          f"all scans pause at ${policy.pause_all_at:.0f})", file=out)
    print(f"burn rate      ${burn:.3f}/h  (~${burn * 24:.2f}/day)", file=out)
    if burn > 0:
        hours = max(policy.pause_all_at - decision.spent, 0) / burn
        print(f"pause in       ~{hours:.0f} h at this rate", file=out)
    expires = os.environ.get("RH_CREDIT_EXPIRES", "")
    if expires:
        left = _days_left(expires, dt.date.today())
        if left is not None:
            print(f"credit expires {expires} ({left} days): run `terraform destroy` before then", file=out)
    if costs:
        print("billing now:", file=out)
        for c in sorted(costs, key=lambda c: -c.hourly):
            print(f"  {c.kind:8} {c.label:32} {c.plan:24} ${c.hourly:.4f}/h", file=out)
    else:
        print("billing now:   nothing", file=out)
    return 0 if decision.state == GuardState.OK else 1


def cmd_guard(client: VultrClient, policy: GuardPolicy, state: StateFile, interval: float, once: bool) -> int:
    last: AccountSnapshot | None = None
    while True:
        now = time.time()
        try:
            last = AccountSnapshot.read(client, now)
        except (VultrError, OSError, ValueError, KeyError) as e:
            print(f"guard: balance read failed: {e}", file=sys.stderr)
        decision = evaluate(policy, last, now)
        state.write(decision, now)
        print(f"guard: {decision.state.name} ({decision.reason})", flush=True)
        if once:
            return 0 if decision.state == GuardState.OK else 1
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redhanded")
    parser.add_argument("--env", default=".env", help="env file to read (default .env)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("budget", help="show credit left, burn rate and everything billing")
    g = sub.add_parser("guard", help="read the balance on a loop and write the guard state")
    g.add_argument("--state", default=os.environ.get("RH_GUARD_STATE", "guard-state.json"))
    g.add_argument("--interval", type=float, default=600.0)
    g.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)

    load_env(Path(args.env))
    try:
        client = VultrClient(os.environ.get("VULTR_API_KEY", ""))
        policy = policy_from_env()
        if args.cmd == "budget":
            return cmd_budget(client, policy)
        return cmd_guard(client, policy, StateFile(args.state), args.interval, args.once)
    except VultrError as e:
        print(f"redhanded: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
