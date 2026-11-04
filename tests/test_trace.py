from pathlib import Path

from redhanded.trace import parse, parse_line

# Recorded with runsc release-20261012.0:
#   runsc --rootless --network=none --strace do env -i ... sh -c \
#     'cat input.txt; ls /nonexistent; /bin/sh -c "echo hi > out.txt"; mv out.txt moved.txt; python3 -c <connect 10.66.0.5:443>'
FIXTURE = Path(__file__).parent / "fixtures" / "gvisor-strace-sample.log"
WORK = "/tmp/rt/work"


def facts():
    with FIXTURE.open(encoding="utf-8") as f:
        return parse(f)


def test_every_line_parses():
    f = facts()
    assert f.lines > 300 and f.unparsed == 0


def test_relative_open_resolved_against_cwd():
    assert f"{WORK}/input.txt" in facts().opened


def test_failed_lookups_are_probes_not_reads():
    f = facts()
    assert "/nonexistent" in f.probes
    assert "/nonexistent" not in f.opened


def test_redirect_and_rename_are_writes():
    f = facts()
    assert f"{WORK}/out.txt" in f.writes
    assert f"{WORK}/moved.txt" in f.writes
    assert f"{WORK}/input.txt" not in f.writes


def test_execs_keep_full_argv_with_quotes():
    argvs = [argv for argv, _ in facts().execs]
    assert ["cat", "input.txt"] in argvs
    assert ["/bin/sh", "-c", "echo hi > out.txt"] in argvs
    py = next(a for a in argvs if a[0] == "python3")
    assert '("10.66.0.5", 443)' in py[2]


def test_shell_under_a_shell_is_not_the_lifecycle_runner():
    # The nested `sh -c` here was spawned by sh, not by node or npm.
    assert all(not by_runner for _, by_runner in facts().execs)


def test_inet_connect_recorded_even_when_refused_and_unix_sockets_ignored():
    assert facts().connects == [("10.66.0.5", 443)]


def _x(pid, comm, call, args, ret="0 (0x0) (3µs)"):
    return f"I1104 14:15:09.215381       1 strace.go:607] [{pid:>4}:{pid:>4}] {comm} X {call}({args}) = {ret}"


def test_lifecycle_runner_detected_from_parent_comm():
    lines = [
        _x(1, "node", "clone", "CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|0x11, 0x0, 0x0, 0x7ed1, 0x0", "9 (0x9) (5µs)"),
        _x(9, "node", "execve", '0x55 /bin/sh, 0x56 ["sh", "-c", "node build.js"], 0x57 []'),
        _x(9, "sh", "clone", "CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|0x11, 0x0, 0x0, 0x7ed1, 0x0", "10 (0xa) (5µs)"),
        _x(10, "sh", "execve", '0x55 /usr/bin/node, 0x56 ["node", "build.js"], 0x57 []'),
    ]
    f = parse(lines)
    assert f.execs == [(["sh", "-c", "node build.js"], True), (["node", "build.js"], False)]


def test_failed_exec_not_counted():
    line = _x(3, "sh", "execve", '0x55 /usr/bin/nope, 0x56 ["nope"], 0x57 []',
              "-1 errno=2 (no such file or directory) (4µs)")
    assert parse([line]).execs == []


def test_entry_lines_and_other_logs_ignored():
    assert parse_line("I1104 14:14:56.540322 1 strace.go:575] [   1:   1] sh E openat(AT_FDCWD /, 0x7e /x, O_RDONLY, 0o0)") is None
    assert parse(["I1104 14:14:56.540322 1 boot.go:10] booting"]).lines == 0
