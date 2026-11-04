"""Eval gate: every Zoo sample must get the verdict it is owed, and benign
packages must not block a merge.

Verdicts are deterministic, so the gate is exact: one sample below its
expected verdict fails the run. Rates are still reported with Wilson 95%
bounds, because a recall of 10/10 on ten samples is not 100%.
"""
from __future__ import annotations

import json
import math
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from .verdict import Verdict


@dataclass(frozen=True)
class Case:
    id: str
    kind: str                     # "zoo" (should be caught) or "benign"
    target: str                   # folder for zoo samples, name@version for benign
    min_verdict: Verdict = Verdict.CLEAN
    max_verdict: Verdict = Verdict.CRITICAL
    deadline_s: float = 120.0
    why: str = ""


@dataclass
class Result:
    id: str
    kind: str
    verdict: str
    ok: bool
    seconds: float
    scan_id: str = ""
    reasons: list[str] = field(default_factory=list)
    error: str = ""


# (case) -> (verdict label, reasons, seconds, scan_id)
Scanner = Callable[[Case], tuple[str, list[str], float, str]]


def load_zoo(root: Path) -> list[Case]:
    cases = []
    for expect in sorted(root.glob("*/expect.json")):
        e = json.loads(expect.read_text(encoding="utf-8"))
        cases.append(Case(
            id=f"zoo/{expect.parent.name}", kind="zoo" if "min_verdict" in e else "benign",
            target=str(expect.parent),
            min_verdict=Verdict[e.get("min_verdict", "CLEAN")],
            max_verdict=Verdict[e.get("max_verdict", "CRITICAL")],
            deadline_s=float(e.get("deadline_s", 120)), why=e.get("why", ""),
        ))
    return cases


def load_benign(path: Path, max_verdict: Verdict = Verdict.REVIEW) -> list[Case]:
    cases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        spec = line.split("#", 1)[0].strip()
        if spec:
            cases.append(Case(id=spec, kind="benign", target=spec, max_verdict=max_verdict))
    return cases


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round(max(0.0, (c - m) / d), 4), round(min(1.0, (c + m) / d), 4))


def run(cases: list[Case], scanner: Scanner, progress: Callable[[Result], None] | None = None) -> list[Result]:
    results = []
    for case in cases:
        try:
            label, reasons, seconds, scan_id = scanner(case)
            v = Verdict[label]
            res = Result(case.id, case.kind, label, case.min_verdict <= v <= case.max_verdict,
                         seconds, scan_id, reasons)
        except Exception as e:      # a scan that cannot run is a failed case, never a skipped one
            res = Result(case.id, case.kind, "ERROR", False, 0.0, error=f"{type(e).__name__}: {e}")
        results.append(res)
        if progress:
            progress(res)
    return results


def _p95(xs: list[float]) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, math.ceil(0.95 * len(xs)) - 1)]


def summarize(results: list[Result]) -> dict:
    zoo = [r for r in results if r.kind == "zoo"]
    benign = [r for r in results if r.kind == "benign"]
    caught = sum(r.ok for r in zoo)
    blocking = sum(r.verdict in ("HIGH", "CRITICAL") for r in benign)
    review = sum(r.verdict == "REVIEW" for r in benign)
    return {
        "malicious": {"total": len(zoo), "caught": caught, "recall": round(caught / len(zoo), 4) if zoo else None,
                      "recall_wilson95": wilson(caught, len(zoo))},
        "benign": {"total": len(benign), "blocking_false_alarms": blocking, "review": review,
                   "blocking_rate_wilson95": wilson(blocking, len(benign)),
                   "review_rate": round(review / len(benign), 4) if benign else None},
        "errors": sum(r.verdict == "ERROR" for r in results),
        "seconds_p95": _p95([r.seconds for r in results if r.verdict != "ERROR"]),
    }


def gate(results: list[Result], summary: dict, thresholds: dict) -> list[str]:
    """Reasons the gate fails. Empty means pass."""
    failures = [f"{r.id}: got {r.verdict}" + (f" ({r.error})" if r.error else "")
                for r in results if not r.ok]
    b = summary["benign"]
    if b["total"] and b["review_rate"] > thresholds.get("max_review_rate", 1.0):
        failures.append(f"benign review rate {b['review_rate']:.0%} > {thresholds['max_review_rate']:.0%}")
    if summary["seconds_p95"] > thresholds.get("max_seconds_p95", math.inf):
        failures.append(f"p95 time {summary['seconds_p95']:.0f}s > {thresholds['max_seconds_p95']}s")
    return failures


def write_report(path: Path, results: list[Result], summary: dict, failures: list[str], meta: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **meta,
        "passed": not failures, "failures": failures, "summary": summary,
        "results": [asdict(r) for r in results],
    }, indent=1))
