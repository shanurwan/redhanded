"""Turn a gVisor `--strace` log into facts about what the code did.

gVisor's Sentry logs every syscall the sandboxed code makes, on the host,
outside anything the package can reach, so the package cannot hide a call
or rewrite the log. We read exit lines (`X`), which carry the arguments and
the result together. Line format checked against runsc release-20261012.0.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

# I1104 14:14:56.540322  1 strace.go:610] [   1:   1] sh X openat(AT_FDCWD /tmp/rt, 0x7efa /etc/ld.so.cache, O_RDONLY|O_CLOEXEC, 0o0) = 3 (0x3) (30µs)
# A failed call ends "= -1 errno=2 (no such file or directory) (5µs)". The task name can
# contain spaces: npm retitles itself "npm rebuild lef" (15 characters).
_LINE = re.compile(
    r"\]\s*\[\s*(?P<pid>\d+):\s*(?P<tid>\d+)\]\s+(?P<comm>.{1,16}?)\s+X\s+"
    r"(?P<call>\w+)\((?P<args>.*)\) = (?P<ret>-?\d+)(?P<rest>.*)$"
)
_PATH_ARG = re.compile(r"0x[0-9a-f]+ ([^,\s\[\]{}()]+)")
_DIRFD = re.compile(r"^(?:AT_FDCWD|0x[0-9a-f]+) (/[^,\s]*),")
_ARGV = re.compile(r"0x[0-9a-f]+ \[(.*?)\]")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_SOCKADDR = re.compile(r"\{Family: (AF_INET6?), Addr: \[?([0-9a-fA-F:.]+)\]?, Port: (\d+)")

_OPEN_CALLS = {"open", "openat", "openat2", "creat"}
_STAT_CALLS = {"stat", "lstat", "newfstatat", "fstatat", "statx", "access", "faccessat", "faccessat2",
               "readlink", "readlinkat"}
_RENAME_CALLS = {"rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat"}
_FORK_CALLS = {"clone", "clone3", "fork", "vfork"}
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
# npm runs each lifecycle script as `sh -c <script>`, spawned by the node process running npm's CLI.
_NPM_CLI = ("/npm", "/npm-cli.js")
# npm's own install in the image (bundled node-gyp, run-script). Processes started
# from here, and their children, are build tooling. A package that writes here is
# caught separately (verdict.TOOLCHAIN_PREFIXES).
TOOLCHAIN_PREFIX = "/usr/local/lib/node_modules/npm/"


@dataclass(frozen=True)
class Event:
    pid: int
    comm: str
    call: str
    args: str
    ret: int
    failed: bool


@dataclass
class TraceFacts:
    opened: list[str] = field(default_factory=list)       # paths opened successfully, read-only
    writes: list[str] = field(default_factory=list)       # paths created, written or renamed onto
    probes: list[str] = field(default_factory=list)       # paths stat-ed, accessed or opened, any result
    connects: list[tuple[str, int]] = field(default_factory=list)   # attempted, whatever the result
    execs: list[tuple[list[str], bool]] = field(default_factory=list)  # (argv, part of a declared lifecycle command)
    lines: int = 0
    unparsed: int = 0


def parse_line(line: str) -> Event | None:
    m = _LINE.search(line)
    if not m:
        return None
    return Event(int(m["pid"]), m["comm"], m["call"], m["args"], int(m["ret"]), "errno=" in m["rest"])


def _target_path(args: str) -> str | None:
    """The last path argument, made absolute against the directory fd when relative."""
    paths = _PATH_ARG.findall(args)
    if not paths:
        return None
    path = paths[-1]
    if not path.startswith("/"):
        base = _DIRFD.match(args)
        if not base:
            return None
        path = posixpath.join(base.group(1), path)
    return posixpath.normpath(path)


def _argv(args: str) -> list[str]:
    m = _ARGV.search(args)
    if not m:
        return []
    return [re.sub(r"\\(.)", r"\1", a) for a in _QUOTED.findall(m.group(1))]


def parse(lines) -> TraceFacts:
    facts = TraceFacts()
    parent: dict[int, int] = {}
    npm_pids: set[int] = set()
    lifecycle_pids: set[int] = set()     # the `sh -c` npm started, and its direct children
    toolchain_pids: set[int] = set()     # npm's bundled tooling and everything it starts

    for line in lines:
        if "strace.go" not in line or " X " not in line:
            continue
        facts.lines += 1
        ev = parse_line(line)
        if ev is None:
            facts.unparsed += 1
            continue
        call = ev.call

        if call in _FORK_CALLS:
            if not ev.failed and ev.ret > 0:
                parent[ev.ret] = ev.pid
                if ev.pid in toolchain_pids:
                    toolchain_pids.add(ev.ret)
        elif call in ("execve", "execveat"):
            argv = _argv(ev.args)
            if not ev.failed and argv:
                exe = posixpath.basename(argv[0])
                runner_shell = exe == "sh" and argv[1:2] == ["-c"] and parent.get(ev.pid) in npm_pids
                # busybox `sh -c "node -e ..."` execs node in place, so the declared command
                # can appear in the shell's own pid as well as in its children.
                declared = runner_shell or ev.pid in lifecycle_pids or parent.get(ev.pid) in lifecycle_pids
                if runner_shell:
                    lifecycle_pids.add(ev.pid)
                if any(a.startswith(TOOLCHAIN_PREFIX) for a in argv[:2]):
                    toolchain_pids.add(ev.pid)
                declared = declared or ev.pid in toolchain_pids
                if (argv, declared) not in facts.execs:
                    facts.execs.append((argv, declared))
                npm_pids.discard(ev.pid)
                if exe == "node" and len(argv) > 1 and argv[1].endswith(_NPM_CLI):
                    npm_pids.add(ev.pid)
        elif call in _OPEN_CALLS:
            path = _target_path(ev.args)
            if path:
                facts.probes.append(path)
                writing = call == "creat" or any(f in ev.args for f in _WRITE_FLAGS)
                if not ev.failed:
                    (facts.writes if writing else facts.opened).append(path)
        elif call in _STAT_CALLS:
            path = _target_path(ev.args)
            if path:
                facts.probes.append(path)
        elif call in _RENAME_CALLS:
            path = _target_path(ev.args)
            if path and not ev.failed:
                facts.writes.append(path)
        elif call == "connect":
            m = _SOCKADDR.search(ev.args)
            if m:
                facts.connects.append((m.group(2), int(m.group(3))))
    return facts
