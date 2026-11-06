"""Deterministic verdict rules. Evidence decides; the model only explains.

The same evidence always gives the same verdict. A model opinion can raise
a verdict to REVIEW but can never lower one, so text hidden in a package
cannot talk its way to CLEAN.
"""
from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from enum import IntEnum


# Bump whenever a rule changes: cached verdicts are keyed by it, so an old
# verdict is never served under new rules.
RULES_VERSION = "2026-11-06.2"


class Verdict(IntEnum):
    CLEAN = 0
    REVIEW = 1
    HIGH = 2
    CRITICAL = 3


# Hosts a benign install script may contact for public downloads.
BENIGN_HOSTS = frozenset({
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "github.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "nodejs.org",
})
NET_TOOLS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "powershell", "pwsh"})
INLINE_FLAGS = {"node": {"-e", "--eval", "-p"}, "python": {"-c"}, "python3": {"-c"}, "perl": {"-e"}, "ruby": {"-e"}}
PERSISTENCE_SUFFIXES = (
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
    "/.github/workflows", "/.git/hooks", "/crontab", "/.config/autostart",
)
# Files that only tell you something about the box you run in. A runtime reading its
# own /proc/<pid>/cgroup to size its heap is normal (node does), so only PID 1 counts.
# The image's runtime and npm toolchain. Build tooling run from here is trusted
# (trace.TOOLCHAIN_PREFIX), so writing here is tampering.
TOOLCHAIN_PREFIXES = ("/usr/local/lib/node_modules/", "/usr/local/bin/", "/usr/local/include/node/")
CONTAINER_CHECKS = frozenset({
    "/.dockerenv", "/run/.containerenv", "/proc/1/cgroup", "/proc/1/sched",
    "/proc/1/mountinfo", "/proc/1/environ", "/proc/vz", "/proc/xen",
})


@dataclass
class Evidence:
    """Facts collected outside the sandbox for one scan."""
    exfil_matches: list[str] = field(default_factory=list)      # honeytoken names found in outbound traffic
    machine_leaks: list[str] = field(default_factory=list)      # hosts sent this scan's unique machine name
    token_uses: list[str] = field(default_factory=list)         # stolen token used against fake npm/GitHub APIs
    bait_reads: list[str] = field(default_factory=list)         # bait file paths opened
    connects: list[str] = field(default_factory=list)           # destination hosts or IPs contacted
    execs: list[tuple[list[str], bool]] = field(default_factory=list)  # (argv, part of a declared lifecycle command)
    writes: list[str] = field(default_factory=list)             # paths written outside the package
    stats: list[str] = field(default_factory=list)              # paths stat-ed or opened that look like environment checks
    incomplete: list[str] = field(default_factory=list)         # reasons the scan could not finish
    deadline_killed: bool = False
    probe_flags: list[str] = field(default_factory=list)        # e.g. "obfuscated-eval" from probes


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reasons: tuple[str, ...]
    container_aware: bool        # escalate to tier 2 if no payload was seen

    @property
    def label(self) -> str:
        return self.verdict.name


# Services that exist to receive callbacks and collect what they are sent.
COLLECTORS = ("oastify.com", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me", "interact.sh",
              "burpcollaborator.net", "webhook.site", "pipedream.net", "requestbin.net", "requestcatcher.com", "canarytokens.com",
              "dnslog.cn", "ceye.io", "beeceptor.com", "ngrok.io", "ngrok-free.app", "pinggy.link", "pinggy-free.link", "trycloudflare.com")


def _collector(host: str) -> str | None:
    host = host.lower().rstrip(".")
    return next((c for c in COLLECTORS if host == c or host.endswith("." + c)), None)


def _domain(host: str) -> str:
    """The name an attacker controls: data smuggled in the left-hand labels changes from run to run."""
    parts = host.lower().rstrip(".").split(".")
    return host if host.startswith("port ") or host.replace(".", "").isdigit() or len(parts) < 2 else ".".join(parts[-2:])


def _suspicious_exec(argv: list[str], by_runner: bool) -> str | None:
    if not argv:
        return None
    exe = posixpath.basename(argv[0])
    if exe in NET_TOOLS:
        return f"spawned {exe}"
    if by_runner:
        return None   # the command the package declares in package.json, visible to any reviewer
    flags = INLINE_FLAGS.get(exe)
    if flags and any(a in flags for a in argv[1:]):
        return f"ran inline code with {exe}"
    # A plain nested `sh -c` is not flagged: packages such as esbuild fall back to
    # `sh -c "npm install <platform binary>"`. What the shell then does is still judged.
    return None


def decide(ev: Evidence) -> Decision:
    reasons: list[str] = []
    level = Verdict.CLEAN

    def hit(v: Verdict, why: str) -> None:
        nonlocal level
        level = max(level, v)
        reasons.append(f"{v.name}: {why}")

    for name in sorted(set(ev.exfil_matches)):
        hit(Verdict.CRITICAL, f"honeytoken {name} left the sandbox")
    for svc in sorted(set(ev.token_uses)):
        hit(Verdict.CRITICAL, f"stolen token used against fake {svc}")

    if ev.machine_leaks:
        hit(Verdict.HIGH, "sent this machine's name to an outside host")
    for name in sorted({c for c in map(_collector, ev.connects) if c}):
        hit(Verdict.HIGH, f"contacted a data-collection service ({name})")

    risky_connects = sorted({c for c in ev.connects if c not in BENIGN_HOSTS})
    if ev.bait_reads and (ev.connects or ev.exfil_matches):
        hit(Verdict.HIGH, f"read bait ({', '.join(sorted(set(ev.bait_reads)))}) and attempted network access")
    for argv, by_runner in ev.execs:
        why = _suspicious_exec(argv, by_runner)
        if why:
            hit(Verdict.HIGH, why)
    for path in sorted(set(ev.writes)):
        if any(path.endswith(s) or s + "/" in path for s in PERSISTENCE_SUFFIXES):
            hit(Verdict.HIGH, f"wrote persistence path {path}")
        elif path.startswith(TOOLCHAIN_PREFIXES):
            hit(Verdict.HIGH, f"modified the runtime toolchain at {path}")

    if risky_connects and not ev.bait_reads:
        hit(Verdict.REVIEW, f"network attempts to {', '.join(risky_connects)}")
    checks = sorted(set(ev.stats) & CONTAINER_CHECKS)
    if checks:
        hit(Verdict.REVIEW, f"checked whether it runs in a container ({', '.join(checks)})")
    for flag in sorted(set(ev.probe_flags)):
        hit(Verdict.REVIEW, f"probe flagged {flag}")
    for why in ev.incomplete:
        hit(Verdict.REVIEW, f"scan incomplete: {why}")
    if ev.deadline_killed:
        hit(Verdict.REVIEW, "killed at deadline")

    return Decision(level, tuple(reasons), container_aware=bool(checks) and level <= Verdict.REVIEW)


def combine_microvm(first: Decision, sandbox: Evidence, second: Decision, microvm: Evidence) -> Decision:
    """The same bytes, run again on a machine with its own kernel. Only ever raises.

    Anything a package does only in the microVM, it hid from the sandbox.
    """
    level = max(first.verdict, second.verdict)
    reasons = list(first.reasons) + [f"{r} (in the microVM)" for r in second.reasons]
    seen = {_domain(c) for c in sandbox.connects}
    hidden = sorted({_domain(c) for c in microvm.connects if c not in BENIGN_HOSTS} - seen)
    hidden += sorted(f"read {p}" for p in set(microvm.bait_reads) - set(sandbox.bait_reads))
    if hidden:
        level = max(level, Verdict.HIGH)
        reasons.append(f"HIGH: hid this from the sandbox: {', '.join(hidden)}")
    return Decision(level, tuple(reasons), first.container_aware)


def flag_agent_text(decision: Decision) -> Decision:
    """The package's text addresses AI agents. Raises to REVIEW at most, and never quotes it."""
    return Decision(max(decision.verdict, Verdict.REVIEW),
                    decision.reasons + ("REVIEW: package text gives instructions to AI agents",),
                    decision.container_aware)


def apply_model_opinion(decision: Decision, model_label: str | None) -> Decision:
    """Let the model raise CLEAN to REVIEW. Anything else it says is ignored."""
    if decision.verdict == Verdict.CLEAN and model_label and model_label.upper() in {"REVIEW", "HIGH", "CRITICAL"}:
        return Decision(Verdict.REVIEW, decision.reasons + ("REVIEW: raised by model explanation",), decision.container_aware)
    return decision
