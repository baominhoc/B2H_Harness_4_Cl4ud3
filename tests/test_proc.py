"""The process registry and the sanctioned body reader.

The safety property is the whole point, so it is pinned from both sides: a
registered process that still matches IS stopped, and one whose cmdline, start
time or boot id disagrees is NOT -- and the second half is tested by asserting
the process is still alive afterwards, not merely that a verdict string said
"refused".

Real processes are used for the kill paths, because a mocked `os.kill` proves
nothing about escalation. They are all children this file spawned (a short
`sleep` loop in a throwaway interpreter), they are reaped by the `spawn`
fixture whatever the test does, and the conftest `no_claude` guard is the
backstop. Nothing here spawns `claude`, touches the real engagements tree or
opens a socket.

The one test that aims cleanup at a pid it must never signal -- init -- replaces
`os.kill` with a recorder that fails on contact, so "no signal was sent" is an
assertion rather than a hope.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from bbh import paths, proc, secrets
from bbh.proc import ProcError
from bbh.store import Store, sha256_bytes

# A child that outlives the test unless it is signalled. `-I` so nothing in the
# working directory is importable by it.
SLEEPER = [sys.executable, "-I", "-c", "import time\nwhile True: time.sleep(0.05)"]


def _deaf_sleeper(ready: Path) -> list[str]:
    """A child that ignores SIGTERM and says when the handler is installed."""
    script = (
        "import signal, sys, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"open({str(ready)!r}, 'w').write('x')\n"
        "while True: time.sleep(0.05)\n"
    )
    return [sys.executable, "-I", "-c", script]


@pytest.fixture
def spawn():
    """Spawn children for a test and make sure none of them outlive it.

    Each one is waited past execve before it is handed back: `Popen` returns
    between fork and exec, where /proc still shows an empty argv, and that
    window is the subject of its own test rather than a flake in every other.
    """
    children: list[subprocess.Popen] = []

    def start(argv: list[str] | None = None) -> subprocess.Popen:
        child = subprocess.Popen(
            argv or SLEEPER, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        children.append(child)
        limit = time.monotonic() + 5.0
        while time.monotonic() < limit:
            ident = proc.read_identity(child.pid)
            if ident is not None and ident.argv:
                return child
            time.sleep(0.01)
        raise AssertionError(f"pid {child.pid} never exec'd")

    yield start
    for child in children:
        if child.poll() is None:
            child.kill()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - a child we cannot reap
            pass


def _wait_for(path: Path, timeout: float = 5.0) -> None:
    limit = time.monotonic() + timeout
    while time.monotonic() < limit:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"the child never wrote {path}")


def _rows() -> dict[str, dict]:
    return json.loads(proc.registry_path().read_text(encoding="utf-8"))["procs"]


def _rewrite(pid: int, **fields) -> None:
    """Tamper with one stored row, the way a recycled pid looks from the registry."""
    path = proc.registry_path()
    state = json.loads(path.read_text(encoding="utf-8"))
    state["procs"][str(pid)].update(fields)
    path.write_text(json.dumps(state), encoding="utf-8")


# ---------------------------------------------------------------------------
# reading /proc
# ---------------------------------------------------------------------------


def test_read_identity_matches_the_live_process(spawn):
    child = spawn()
    ident = proc.read_identity(child.pid)
    assert ident is not None
    assert ident.pid == child.pid
    assert ident.argv == tuple(SLEEPER)
    assert ident.start_ticks > 0
    assert ident.uid == os.getuid()
    assert ident.cmdline_sha256 == sha256_bytes(
        Path(f"/proc/{child.pid}/cmdline").read_bytes()
    )


def test_read_identity_is_none_for_a_dead_pid(spawn):
    child = spawn()
    pid = child.pid
    child.kill()
    child.wait(timeout=5)
    # The parent has reaped it, so the pid is free rather than a zombie.
    assert proc.read_identity(pid) is None


def test_stat_fields_survive_a_comm_with_spaces_and_parens():
    # /proc/<pid>/stat field 2 is unquoted, so splitting the whole line on
    # whitespace misaligns every later field. Fields 3 and 22 must still come out.
    middle = " ".join(str(n) for n in range(4, 22))  # fields 4..21
    fabricated = f"4242 (my )weird prog) Z {middle} 999 trailing"
    assert proc._stat_fields(fabricated) == ("Z", 999)


def test_stat_fields_refuse_a_truncated_stat_line():
    with pytest.raises(ValueError):
        proc._stat_fields("1 (sh) S 1 2 3")


def test_identity_of_this_process_round_trips():
    ident = proc.read_identity(os.getpid())
    assert ident is not None
    assert ident.boot_id == proc.boot_id()


# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------


def test_register_records_what_the_process_is(engagement, spawn):
    child = spawn()
    entry = proc.register(child.pid, kind="proxy", port=8080, note="mitm stand-in")

    assert entry.pid == child.pid
    assert entry.kind == "proxy"
    assert entry.engagement == engagement
    assert entry.port == 8080
    assert entry.start_ticks > 0
    assert entry.boot_id == proc.boot_id()
    assert entry.registered_by == os.getpid()
    assert str(child.pid) in _rows()
    assert proc.registry_path().parent == paths.STATE_DIR


def test_register_is_global_not_per_engagement(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy", engagement="other-program")
    # The dangerous leftover is a proxy from an engagement that is no longer
    # active, so it has to be visible without selecting that engagement first.
    assert [e.engagement for e in proc.registered()] == ["other-program"]
    assert proc.registered(engagement=engagement) == []


def test_register_refuses_an_unknown_kind_and_names_the_valid_ones(engagement, spawn):
    child = spawn()
    with pytest.raises(ProcError) as exc:
        proc.register(child.pid, kind="daemon")
    assert "daemon" in str(exc.value)
    assert "proxy" in str(exc.value)
    assert "bb proc register" in str(exc.value)
    assert not proc.registry_path().exists()


def test_register_collects_every_problem_in_one_refusal(engagement):
    with pytest.raises(ProcError) as exc:
        proc.register(1, kind="daemon", port=99999)
    message = str(exc.value)
    assert "init" in message
    assert "daemon" in message
    assert "99999" in message


def test_register_refuses_itself_and_its_parent(engagement):
    for pid in (os.getpid(), os.getppid()):
        with pytest.raises(ProcError) as exc:
            proc.register(pid, kind="other")
        assert "kill the harness" in str(exc.value)


def test_register_refuses_a_pid_that_already_exited(engagement, spawn):
    child = spawn()
    pid = child.pid
    child.kill()
    child.wait(timeout=5)
    with pytest.raises(ProcError) as exc:
        proc.register(pid, kind="scan")
    assert "already gone" in str(exc.value)


def test_register_refuses_when_the_argv_is_not_the_one_spawned(engagement, spawn, monkeypatch):
    monkeypatch.setattr(proc, "EXEC_SETTLE_S", 0.05)
    child = spawn()
    with pytest.raises(ProcError) as exc:
        proc.register(child.pid, kind="proxy", expect=["mitmdump", "--listen-port", "8080"])
    message = str(exc.value)
    assert "never stop" in message
    assert "mitmdump --listen-port 8080" in message
    assert not proc.registry_path().exists()


# -- shebang scripts: the kernel shows the interpreter, Popen was given the script
#
# `bb proxy start` hit this on every single run. `mitmdump` is a console script
# with a `#!` line, so /proc/<pid>/cmdline reads
#   /…/mitmproxy/bin/python /…/bin/mitmdump -s … --listen-port 8080
# while the harness passed Popen
#   /…/bin/mitmdump -s … --listen-port 8080
# Exact equality refused it, which fails safe — but the consequence was that the
# proxy, the one process the registry exists to be able to stop, was never in
# it, so an interrupted hunt left it listening with a stale scope.


def test_a_shebang_script_registers_despite_the_interpreter_prefix():
    wanted = ["/usr/local/bin/mitmdump", "-s", "addon.py", "--listen-port", "8080"]
    running = ["/opt/venv/bin/python", *wanted]
    assert proc._is_spawned_argv(running, wanted)


def test_an_exact_argv_still_matches():
    argv = ["/usr/local/bin/mitmdump", "--listen-port", "8080"]
    assert proc._is_spawned_argv(argv, argv)


@pytest.mark.parametrize(
    "running,why",
    [
        (
            ["/opt/venv/bin/python", "-u", "/usr/local/bin/mitmdump", "--listen-port", "8080"],
            "two extra words: a wrapper of a wrapper is not something the harness can vouch for",
        ),
        (
            ["/opt/venv/bin/python", "/usr/local/bin/OTHER", "--listen-port", "8080"],
            "index 1 is not the program the harness asked for",
        ),
        (
            ["/usr/local/bin/mitmdump", "--listen-port", "9999"],
            "a real argument differs, which is the whole point of comparing",
        ),
        (
            ["/opt/venv/bin/python", "/usr/local/bin/mitmdump", "--listen-port"],
            "truncated: a prefix is not a suffix match",
        ),
        (["/usr/bin/sleep", "600"], "an unrelated process, i.e. a recycled pid"),
    ],
)
def test_the_relaxation_is_exactly_one_word_and_no_more(running, why):
    wanted = ["/usr/local/bin/mitmdump", "--listen-port", "8080"]
    assert not proc._is_spawned_argv(running, wanted), why


def test_an_empty_wanted_argv_never_matches_by_prefix():
    """Otherwise any single-word command would satisfy a caller that passed [].

    `expect=None` means "do not check"; `expect=[]` means "check against
    nothing", and those must not collapse into the same thing.
    """
    assert not proc._is_spawned_argv(["/usr/bin/sleep"], [])


def test_register_accepts_the_interpreter_prefixed_form_end_to_end(engagement, spawn, monkeypatch):
    """And records what /proc shows, so cleanup's later comparison matches."""
    monkeypatch.setattr(proc, "EXEC_SETTLE_S", 0.05)
    child = spawn()
    running = proc.read_identity(child.pid)
    assert running is not None and len(running.argv) >= 2
    # Pretend the harness spawned it the way a console script is spawned: argv
    # without the interpreter the kernel actually recorded.
    as_popen_saw_it = list(running.argv[1:])

    entry = proc.register(child.pid, kind="proxy", expect=as_popen_saw_it)
    assert entry.pid == child.pid
    assert entry.cmdline_sha256 == running.cmdline_sha256, (
        "the recorded identity must be the one /proc reports, or cleanup can never match it"
    )
    assert not proc.identity_problems(entry, running)


def test_register_refuses_a_pid_that_has_not_exec_ed_yet(engagement, spawn, monkeypatch):
    # The fork/exec window: `Popen` returns before execve, where /proc reports an
    # empty argv. Recording sha256(b"") there would pin an identity that stops
    # being true a millisecond later, and cleanup would refuse it for ever.
    monkeypatch.setattr(proc, "EXEC_SETTLE_S", 0.05)
    child = spawn()
    real = proc.read_identity(child.pid)
    assert real is not None
    blank = type(real)(
        pid=real.pid,
        cmdline_sha256=sha256_bytes(b""),
        start_ticks=real.start_ticks,
        boot_id=real.boot_id,
        uid=real.uid,
        argv=(),
        raw_cmdline=b"",
    )
    monkeypatch.setattr(proc, "read_identity", lambda pid: blank)

    with pytest.raises(ProcError) as exc:
        proc.register(child.pid, kind="proxy")
    message = str(exc.value)
    assert "empty /proc" in message
    assert "can never match again" in message
    assert not proc.registry_path().exists()


def test_register_accepts_the_argv_it_was_told_to_expect(engagement, spawn):
    child = spawn()
    entry = proc.register(child.pid, kind="scan", expect=SLEEPER)
    assert entry.pid == child.pid


def test_register_redacts_a_credential_on_the_command_line(engagement, spawn):
    secrets.put("attacker-session", "s3cr3t-session-value-0123456789")
    child = spawn(
        [sys.executable, "-I", "-c", "import time\nwhile True: time.sleep(0.05)",
         "--header", "Cookie: s3cr3t-session-value-0123456789"]
    )
    entry = proc.register(child.pid, kind="browser")
    assert "s3cr3t-session-value" not in entry.cmdline
    assert "secret://attacker-session" in entry.cmdline
    assert "s3cr3t-session-value" not in proc.registry_path().read_text(encoding="utf-8")
    # Identity still matches, because it is hashed from the raw bytes.
    assert proc.identity_problems(entry, proc.read_identity(child.pid)) == []


def test_register_escapes_a_newline_in_the_argv(engagement, spawn):
    child = spawn([sys.executable, "-I", "-c", "import time\nwhile True: time.sleep(0.05)"])
    entry = proc.register(child.pid, kind="other")
    assert "\n" not in entry.cmdline
    assert "\\n" in entry.cmdline


def test_registering_a_recycled_pid_replaces_the_row(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy", note="first")
    proc.register(child.pid, kind="scan", note="second")
    rows = _rows()
    assert list(rows) == [str(child.pid)]
    assert rows[str(child.pid)]["note"] == "second"


# ---------------------------------------------------------------------------
# cleanup: the refusals
# ---------------------------------------------------------------------------


def test_cleanup_refuses_a_changed_cmdline_and_leaves_the_process_alone(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="scan")
    _rewrite(child.pid, cmdline_sha256="0" * 64)

    report = proc.cleanup()

    (outcome,) = report.outcomes
    assert outcome.action == "refused"
    assert "cmdline" in outcome.detail
    assert "recycled" in outcome.detail
    assert outcome.signals == ()
    assert child.poll() is None, "a refused pid must not be signalled"
    assert not report.ok
    assert str(child.pid) in _rows(), "a refused row stays so the operator can see it"


def test_cleanup_refuses_a_changed_start_time(engagement, spawn):
    child = spawn()
    entry = proc.register(child.pid, kind="scan")
    _rewrite(child.pid, start_ticks=entry.start_ticks + 1)

    (outcome,) = proc.cleanup().outcomes

    assert outcome.action == "refused"
    assert "start time" in outcome.detail
    assert "field 22" in outcome.detail
    assert child.poll() is None


def test_cleanup_refuses_a_different_boot(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="scan")
    _rewrite(child.pid, boot_id="00000000-0000-0000-0000-000000000000")

    (outcome,) = proc.cleanup().outcomes

    assert outcome.action == "refused"
    assert "boot" in outcome.detail
    assert child.poll() is None


def test_cleanup_refuses_when_the_boot_id_was_never_recorded(engagement, spawn):
    # Fail closed: ticks since boot only identify a process within one boot, so
    # an absent boot id is a question with no answer, not a pass.
    child = spawn()
    proc.register(child.pid, kind="scan")
    _rewrite(child.pid, boot_id=None)

    (outcome,) = proc.cleanup().outcomes

    assert outcome.action == "refused"
    assert "boot id" in outcome.detail
    assert child.poll() is None


def test_cleanup_names_every_field_that_disagrees(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="scan")
    _rewrite(child.pid, cmdline_sha256="0" * 64, start_ticks=1)

    (outcome,) = proc.cleanup().outcomes

    assert "cmdline" in outcome.detail
    assert "start time" in outcome.detail


def test_cleanup_never_signals_init(engagement, monkeypatch):
    # The registry is hand-written: `register` refuses pid 1, which is the first
    # line of defence. This test is the second -- what cleanup does with a row
    # that got there anyway.
    proc.registry_path().parent.mkdir(parents=True, exist_ok=True)
    proc.registry_path().write_text(
        json.dumps(
            {
                "schema": 1,
                "procs": {
                    "1": {
                        "pid": 1,
                        "kind": "proxy",
                        "engagement": "acme",
                        "cmdline_sha256": "0" * 64,
                        "cmdline": "mitmdump --listen-port 8080",
                        "start_ticks": 7,
                        "boot_id": proc.boot_id(),
                        "uid": 0,
                        "port": 8080,
                        "note": None,
                        "registered_at": "2026-10-30T00:00:00Z",
                        "registered_by": 999999,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    def forbidden(pid, sig):
        if sig != 0:
            raise AssertionError(f"cleanup signalled pid {pid} with {sig}")
        return None

    monkeypatch.setattr(os, "kill", forbidden)
    (outcome,) = proc.cleanup().outcomes
    assert outcome.action == "refused"
    assert outcome.signals == ()


def test_cleanup_refuses_a_pid_whose_identity_cannot_be_read(engagement, spawn, monkeypatch):
    child = spawn()
    proc.register(child.pid, kind="proxy")

    def unreadable(pid):
        raise ProcError("pid is alive but /proc is not readable")

    monkeypatch.setattr(proc, "read_identity", unreadable)
    (outcome,) = proc.cleanup().outcomes

    assert outcome.action == "refused"
    assert outcome.signals == ()
    assert child.poll() is None


def test_cleanup_reports_a_denied_signal_with_a_sudo_remedy(engagement, spawn, monkeypatch):
    # The sandboxed phase launch is root-owned, so a refusal from the kernel is
    # expected rather than exceptional; what matters is that it says so.
    child = spawn()
    proc.register(child.pid, kind="proxy")

    real_kill = os.kill
    deny = {"on": True}

    def denied(pid, sig):
        if sig != 0 and deny["on"]:
            raise PermissionError(1, "Operation not permitted")
        return real_kill(pid, sig)

    monkeypatch.setattr(os, "kill", denied)
    try:
        (outcome,) = proc.cleanup().outcomes
    finally:
        deny["on"] = False  # the fixture still has to be able to reap the child

    assert outcome.action == "denied"
    assert outcome.signals == ()
    assert any("sudo kill" in r for r in outcome.remedy)
    assert child.poll() is None


# ---------------------------------------------------------------------------
# cleanup: the kills
# ---------------------------------------------------------------------------


def test_cleanup_stops_a_matching_process_and_drops_the_row(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy", port=8080)

    report = proc.cleanup()

    (outcome,) = report.outcomes
    assert outcome.action == "terminated"
    assert outcome.signals == ("SIGTERM",)
    assert child.wait(timeout=5) is not None
    assert report.ok
    assert _rows() == {}
    assert report.remaining == 0


def test_cleanup_escalates_to_sigkill_when_sigterm_is_ignored(engagement, spawn, tmp_path):
    ready = tmp_path / "deaf-ready"
    child = spawn(_deaf_sleeper(ready))
    _wait_for(ready)
    proc.register(child.pid, kind="scan")

    report = proc.cleanup(grace_s=0.5)

    (outcome,) = report.outcomes
    assert outcome.action == "killed"
    assert outcome.signals == ("SIGTERM", "SIGKILL")
    assert child.wait(timeout=5) == -signal.SIGKILL
    assert report.ok


def test_cleanup_reports_an_already_dead_process_as_gone(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="browser")
    child.kill()
    child.wait(timeout=5)

    (outcome,) = proc.cleanup().outcomes

    assert outcome.action == "gone"
    assert outcome.signals == ()
    assert _rows() == {}


def test_cleanup_withholds_sigkill_when_the_pid_was_reused_in_the_grace_window(
    engagement, spawn, monkeypatch
):
    # Our target dies, the kernel hands its number to something else, and the
    # escalation would land on a stranger. The registered process is still
    # reported as stopped, because it was.
    child = spawn()
    entry = proc.register(child.pid, kind="scan")
    real = proc.read_identity
    before = real(entry.pid)
    stranger = type(before)(
        pid=entry.pid,
        cmdline_sha256="f" * 64,
        start_ticks=before.start_ticks + 500,
        boot_id=before.boot_id,
        uid=before.uid,
        argv=("sshd:", "someone@pts/3"),
        raw_cmdline=b"sshd: someone@pts/3\x00",
    )
    # The first read is the one cleanup makes to prove the pid before signalling
    # it; every read after that is inside the grace window.
    calls = {"n": 0}

    def recycling(pid):
        if pid != entry.pid:
            return real(pid)
        calls["n"] += 1
        return before if calls["n"] == 1 else stranger

    sent: list[int] = []
    real_kill = os.kill

    def record(pid, sig):
        if sig != 0:
            sent.append(sig)
        return real_kill(pid, sig)

    monkeypatch.setattr(proc, "read_identity", recycling)
    monkeypatch.setattr(os, "kill", record)

    (outcome,) = proc.cleanup(grace_s=0.3).outcomes

    assert sent == [signal.SIGTERM], "SIGKILL must not be aimed at a reused pid"
    assert outcome.action == "terminated"
    assert "reused" in outcome.detail


def test_cleanup_continues_past_a_refusal(engagement, spawn):
    bad = spawn()
    good = spawn()
    proc.register(bad.pid, kind="scan", note="mismatched")
    proc.register(good.pid, kind="proxy", note="ours")
    _rewrite(bad.pid, cmdline_sha256="0" * 64)

    report = proc.cleanup()

    actions = {o.pid: o.action for o in report.outcomes}
    assert actions[bad.pid] == "refused"
    assert actions[good.pid] == "terminated"
    assert bad.poll() is None
    assert good.wait(timeout=5) is not None
    assert not report.ok
    assert list(_rows()) == [str(bad.pid)]


def test_cleanup_dry_run_signals_nothing(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")

    report = proc.cleanup(dry_run=True)

    (outcome,) = report.outcomes
    assert outcome.action == "dry-run"
    assert outcome.signals == ()
    assert child.poll() is None
    assert report.ok, "a dry run has left nothing running that was running before it"
    assert str(child.pid) in _rows()


def test_cleanup_report_text_names_the_stale_proxy_risk(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy", port=8080)
    _rewrite(child.pid, start_ticks=1)

    text = proc.cleanup().text()

    assert "STILL RUNNING" in text
    assert "scope it was started with" in text
    assert "bb proxy status" in text
    assert str(child.pid) in text


# ---------------------------------------------------------------------------
# cleanup: filters and the registry file
# ---------------------------------------------------------------------------


def test_cleanup_with_nothing_registered_is_a_clean_no_op(engagement):
    report = proc.cleanup()
    assert report.outcomes == ()
    assert report.ok
    assert "nothing registered" in report.text()


def test_cleanup_refuses_a_filter_that_matches_nothing(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")

    with pytest.raises(ProcError) as exc:
        proc.cleanup(engagement="typo-program")
    assert "matches none of the registered" in str(exc.value)
    assert "bb proc list" in str(exc.value)
    assert child.poll() is None


def test_cleanup_refuses_an_unregistered_pid(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")

    with pytest.raises(ProcError) as exc:
        proc.cleanup(pids=[child.pid + 10000])
    assert "not registered" in str(exc.value)


def test_cleanup_refuses_an_unknown_kind(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")
    with pytest.raises(ProcError) as exc:
        proc.cleanup(kind="daemon")
    assert "reads back as 'nothing to clean up'" in str(exc.value)


def test_cleanup_filters_by_kind_and_engagement(engagement, spawn):
    keep = spawn()
    drop = spawn()
    proc.register(keep.pid, kind="browser")
    proc.register(drop.pid, kind="proxy")

    report = proc.cleanup(kind="proxy", engagement=engagement)

    assert [o.pid for o in report.outcomes] == [drop.pid]
    assert keep.poll() is None
    assert list(_rows()) == [str(keep.pid)]


def test_a_corrupt_registry_is_a_refusal_not_a_fresh_start(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")
    proc.registry_path().write_text("{not json", encoding="utf-8")

    with pytest.raises(ProcError) as exc:
        proc.cleanup()
    message = str(exc.value)
    assert "cannot be read" in message
    assert "a pid killed wrong" in message
    assert ".broken" in message
    assert child.poll() is None


def test_a_row_missing_a_field_is_a_refusal(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")
    path = proc.registry_path()
    state = json.loads(path.read_text(encoding="utf-8"))
    del state["procs"][str(child.pid)]["start_ticks"]
    path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ProcError):
        proc.cleanup()
    assert child.poll() is None


def test_registry_is_0600(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")
    assert proc.registry_path().stat().st_mode & 0o777 == 0o600


def test_registered_lists_newest_first(engagement, spawn):
    first, second = spawn(), spawn()
    proc.register(first.pid, kind="proxy")
    proc.register(second.pid, kind="browser")
    # utcnow() has one-second resolution, so the stamps are set explicitly
    # rather than relying on two registrations landing in different seconds.
    _rewrite(first.pid, registered_at="2026-10-30T00:00:00Z")
    _rewrite(second.pid, registered_at="2026-10-30T00:00:05Z")
    assert [e.pid for e in proc.registered()] == [second.pid, first.pid]


# ---------------------------------------------------------------------------
# forget
# ---------------------------------------------------------------------------


def test_forget_drops_a_row_without_signalling(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")

    (dropped,) = proc.forget([child.pid], reason="recycled pid, not ours")

    assert dropped.pid == child.pid
    assert _rows() == {}
    assert child.poll() is None


def test_forget_needs_a_reason(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")
    with pytest.raises(ProcError) as exc:
        proc.forget([child.pid], reason="  ")
    assert "may still be running" in str(exc.value)
    assert str(child.pid) in _rows()


def test_forget_refuses_an_unregistered_pid(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")
    with pytest.raises(ProcError) as exc:
        proc.forget([child.pid, child.pid + 10000], reason="tidying up")
    assert "not in the registry" in str(exc.value)
    assert str(child.pid) in _rows(), "nothing is dropped while any pid is rejected"


def test_cleanup_and_forget_are_audited(engagement, spawn):
    child = spawn()
    proc.register(child.pid, kind="proxy")
    proc.forget([child.pid], reason="left for the operator")
    events = [
        json.loads(line)["event"]
        for line in paths.AUDIT_LOG.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert "proc_register" in events
    assert "proc_forget" in events


# ---------------------------------------------------------------------------
# the body reader
# ---------------------------------------------------------------------------

BIG = b"id=1&role=user\n" * 200 + b"flag=INTERESTING-TOKEN\n" + b"tail=1\n" * 200


def _bodies(engagement: str) -> Path:
    path = paths.engagement_dir(engagement) / "raw" / "bodies"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _record(store: Store, engagement: str, body: bytes, **kw) -> int:
    """A request row with its response body spilled to raw/bodies/, as http does."""
    digest = sha256_bytes(body)
    dest = _bodies(engagement) / f"{digest}.bin"
    dest.write_bytes(body)
    fields = {
        "source": "client",
        "actor": "attacker",
        "method": "GET",
        "url": "https://www.acme.example/api/docs/2",
        "host": "www.acme.example",
        "path": "/api/docs/2",
        "status": 200,
        "phase": "05-validate",
        "resp_body_path": str(dest),
        "resp_body_sha256": digest,
        "resp_len": len(body),
    }
    fields.update(kw)
    return store.add_request(**fields)


def test_show_body_greps_a_spilled_body(engagement, store):
    rid = _record(store, engagement, BIG)

    view = proc.show_body(store, rid, pattern="INTERESTING-[A-Z]+")

    assert len(view.matches) == 1
    assert "INTERESTING-TOKEN" in view.matches[0].text
    assert view.matches[0].line_no == 201
    assert view.complete
    assert view.length == len(BIG)
    assert view.sha256 == sha256_bytes(BIG)
    assert "1 match(es)" in view.text()


def test_show_body_without_a_pattern_previews_instead_of_cat(engagement, store):
    rid = _record(store, engagement, BIG)

    view = proc.show_body(store, rid)

    assert view.matches == ()
    assert view.preview is not None
    assert len(view.preview) < len(BIG)
    assert view.preview_truncated
    assert "--grep PATTERN" in view.text()


def test_show_body_refuses_a_body_whose_hash_changed(engagement, store):
    rid = _record(store, engagement, BIG)
    path = Path(store.conn.execute(
        "SELECT resp_body_path FROM requests WHERE id = ?", (rid,)
    ).fetchone()[0])
    path.write_bytes(BIG + b"tampered")

    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid, pattern="INTERESTING")
    message = str(exc.value)
    assert "hashes to" in message
    assert "not the body that was observed" in message
    assert "bb req GET https://www.acme.example/api/docs/2 --actor attacker" in message


def test_show_body_refuses_when_the_row_and_the_filename_disagree(engagement, store):
    rid = _record(store, engagement, BIG)
    store.conn.execute(
        "UPDATE requests SET resp_body_sha256 = ? WHERE id = ?", ("a" * 64, rid)
    )
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid)
    assert "One of the two is wrong" in str(exc.value)


def test_show_body_refuses_a_body_with_no_recorded_hash(engagement, store):
    body = b"x" * 5000
    dest = _bodies(engagement) / "not-content-addressed.bin"
    dest.write_bytes(body)
    rid = store.add_request(
        source="client", actor="anon", method="GET", url="https://www.acme.example/x",
        host="www.acme.example", resp_body_path=str(dest),
    )
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid)
    assert "nothing to verify it against" in str(exc.value)


def test_show_body_refuses_a_path_outside_the_raw_tree(engagement, store, tmp_path):
    outside = tmp_path / "id_rsa"
    outside.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + b"k" * 4000)
    rid = store.add_request(
        source="client", actor="anon", method="GET", url="https://www.acme.example/x",
        host="www.acme.example", resp_body_path=str(outside),
        resp_body_sha256=sha256_bytes(outside.read_bytes()),
    )
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid, pattern="PRIVATE")
    assert "outside" in str(exc.value)
    assert "print any file on this machine" in str(exc.value)


def test_show_body_refuses_a_symlink_out_of_the_raw_tree(engagement, store, tmp_path):
    secret_file = tmp_path / "outside.txt"
    secret_file.write_bytes(b"y" * 3000)
    digest = sha256_bytes(secret_file.read_bytes())
    link = _bodies(engagement) / f"{digest}.bin"
    link.symlink_to(secret_file)
    rid = store.add_request(
        source="client", actor="anon", method="GET", url="https://www.acme.example/x",
        host="www.acme.example", resp_body_path=str(link), resp_body_sha256=digest,
    )
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid)
    assert "outside" in str(exc.value)


def test_show_body_finds_a_moved_tree_by_content_address(engagement, store):
    # Recorded paths are absolute and the harness is one movable directory, so
    # the sha256 is the location of last resort.
    rid = _record(store, engagement, BIG)
    store.conn.execute(
        "UPDATE requests SET resp_body_path = ? WHERE id = ?",
        (f"/somewhere/else/raw/bodies/{sha256_bytes(BIG)}.bin", rid),
    )
    view = proc.show_body(store, rid, pattern="INTERESTING")
    assert len(view.matches) == 1
    assert view.path == _bodies(engagement) / f"{sha256_bytes(BIG)}.bin"


def test_show_body_refuses_a_missing_file(engagement, store):
    rid = _record(store, engagement, BIG)
    (_bodies(engagement) / f"{sha256_bytes(BIG)}.bin").unlink()
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid)
    assert "has lost its evidence" in str(exc.value)


def test_show_body_reads_a_small_inline_body(engagement, store):
    rid = store.add_request(
        source="client", actor="attacker", method="POST",
        url="https://www.acme.example/login", host="www.acme.example",
        resp_body_sha256=sha256_bytes(b'{"error":"invalid_grant"}'),
        note=json.dumps({"resp_body": {"text": '{"error":"invalid_grant"}'}}),
    )
    view = proc.show_body(store, rid, pattern="invalid_grant")
    assert len(view.matches) == 1
    assert view.path is None
    assert view.source == "request row"


def test_show_body_refuses_an_inline_body_that_no_longer_hashes(engagement, store):
    rid = store.add_request(
        source="client", actor="attacker", method="POST",
        url="https://www.acme.example/login", host="www.acme.example",
        resp_body_sha256="b" * 64,
        note=json.dumps({"resp_body": {"text": "something else entirely"}}),
    )
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid)
    assert "inline" in str(exc.value)


def test_show_body_handles_a_binary_body(engagement, store):
    body = bytes(range(256)) * 40 + b"NEEDLE" + bytes(range(256)) * 40
    rid = _record(store, engagement, body)

    view = proc.show_body(store, rid, pattern="NEEDLE")

    assert len(view.matches) == 1
    text = view.matches[0].text
    assert "NEEDLE" in text
    assert "\n" not in text
    assert "\\x00" in text


def test_show_body_redacts_a_secret_before_printing(engagement, store):
    secrets.put("victim-session", "sv-9f2c1a7b4e6d8c0f3a5b")
    body = b"set-cookie: session=sv-9f2c1a7b4e6d8c0f3a5b; Path=/\n" * 3
    rid = _record(store, engagement, body)

    view = proc.show_body(store, rid, pattern="session=")

    rendered = view.text()
    assert "sv-9f2c1a7b4e6d8c0f3a5b" not in rendered
    assert "secret://victim-session" in rendered
    assert view.redacted == ("victim-session",)
    assert "redacted before printing" in rendered


def test_show_body_redacts_a_secret_in_the_preview(engagement, store):
    secrets.put("victim-session", "sv-9f2c1a7b4e6d8c0f3a5b")
    rid = _record(store, engagement, b"token=sv-9f2c1a7b4e6d8c0f3a5b\n" * 50)

    view = proc.show_body(store, rid)

    assert "sv-9f2c1a7b4e6d8c0f3a5b" not in view.text()
    assert view.redacted == ("victim-session",)


def test_show_body_bounds_the_number_of_matches(engagement, store):
    rid = _record(store, engagement, b"needle\n" * 500)

    view = proc.show_body(store, rid, pattern="needle", max_matches=5)

    assert len(view.matches) == 5
    assert view.truncated_matches
    assert "bounded at 5" in view.text()


def test_a_match_window_is_trimmed_to_its_line_when_it_has_one(engagement, store):
    body = b"a=1\n" * 100 + b"role=admin\n" + b"b=2\n" * 100
    rid = _record(store, engagement, body)

    (match,) = proc.show_body(store, rid, pattern="role=").matches

    assert match.text == "role=admin", "a text body should read like grep, not a hexdump"
    assert match.line_no == 101


def test_show_body_bounds_each_match_window(engagement, store):
    rid = _record(store, engagement, b"A" * 5000 + b"needle" + b"B" * 5000)

    view = proc.show_body(store, rid, pattern="needle", window=40)

    text = view.matches[0].text
    assert len(text) < 120
    assert text.startswith("…")
    assert text.endswith("…")


def test_an_incomplete_scan_is_not_a_clean_negative(engagement, store, monkeypatch):
    rid = _record(store, engagement, b"x" * (proc.SCAN_WINDOW * 4))
    ticks = iter([0.0, 0.0, 99.0, 99.0, 99.0, 99.0])
    monkeypatch.setattr(proc.time, "monotonic", lambda: next(ticks, 99.0))

    view = proc.show_body(store, rid, pattern="nothing-here")

    assert view.matches == ()
    assert not view.complete
    assert "scan budget ran out" in (view.incomplete_reason or "")
    assert "NOT a clean negative" in view.text()


def test_a_match_spanning_a_scan_window_is_still_found(engagement, store):
    # The overlap carried between windows is what makes this true; without it a
    # body would quietly hide anything sitting on a 64 KiB boundary.
    filler = b"." * (proc.SCAN_WINDOW - 3)
    rid = _record(store, engagement, filler + b"needle" + b"." * 100)

    view = proc.show_body(store, rid, pattern="needle")

    assert len(view.matches) == 1
    assert view.matches[0].offset == len(filler)


def test_overlapping_windows_do_not_report_a_match_twice(engagement, store):
    body = b"." * (proc.SCAN_WINDOW - 100) + b"needle" + b"." * (proc.SCAN_WINDOW * 2)
    rid = _record(store, engagement, body)
    view = proc.show_body(store, rid, pattern="needle")
    assert len(view.matches) == 1


def test_show_body_refuses_an_unknown_side(engagement, store):
    rid = _record(store, engagement, BIG)
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid, side="payload")
    assert "payload" in str(exc.value)
    assert "request, response" in str(exc.value)


def test_show_body_accepts_the_short_side_spellings(engagement, store):
    rid = _record(store, engagement, BIG)
    assert proc.show_body(store, rid, side="resp").side == "response"


def test_show_body_refuses_to_search_a_side_with_no_body(engagement, store):
    rid = _record(store, engagement, BIG)
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid, side="request", pattern="anything")
    message = str(exc.value)
    assert "nothing to search" in message
    assert "--side response" in message


def test_show_body_shows_an_absent_side_without_a_pattern(engagement, store):
    rid = _record(store, engagement, BIG)
    view = proc.show_body(store, rid, side="request")
    assert view.length == 0
    assert view.matches == ()


def test_show_body_refuses_an_unknown_request_id(engagement, store):
    _record(store, engagement, BIG)
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, 9999, pattern="x")
    message = str(exc.value)
    assert "no request 9999" in message
    assert "fabrication flag" in message


def test_show_body_refuses_a_non_numeric_request_id(engagement, store):
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, "latest")
    assert "not a request id" in str(exc.value)


def test_show_body_refuses_an_empty_pattern(engagement, store):
    rid = _record(store, engagement, BIG)
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid, pattern="")
    assert "false negative" in str(exc.value)


def test_show_body_refuses_a_broken_pattern_and_offers_the_escaped_form(engagement, store):
    rid = _record(store, engagement, BIG)
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid, pattern="user[0-9")
    message = str(exc.value)
    assert "not a usable regular expression" in message
    assert "user\\[0" in message


def test_show_body_refuses_an_over_long_pattern(engagement, store):
    rid = _record(store, engagement, BIG)
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid, pattern="a" * (proc.MAX_PATTERN_CHARS + 1))
    assert "a pattern that long is a program" in str(exc.value)


def test_show_body_refuses_a_zero_bound(engagement, store):
    rid = _record(store, engagement, BIG)
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid, pattern="x", max_matches=0, budget_s=0)
    message = str(exc.value)
    assert "--max-matches" in message
    assert "--budget" in message


def test_show_body_matches_case_insensitively_on_request(engagement, store):
    rid = _record(store, engagement, b"X-Powered-By: PHP/5.4\n")
    assert proc.show_body(store, rid, pattern="php").matches == ()
    assert len(proc.show_body(store, rid, pattern="php", ignore_case=True).matches) == 1


def test_show_body_refuses_a_store_outside_the_engagements_tree(tmp_path, engagement):
    stray = Store(tmp_path / "stray.sqlite3")
    try:
        with pytest.raises(ProcError) as exc:
            proc.show_body(stray, 1)
        assert "cannot tell which engagement" in str(exc.value)
    finally:
        stray.close()


def test_show_body_searches_the_request_side_too(engagement, store):
    body = b"padding=1\n" * 300 + b"password=hunter2&next=/admin\n"
    digest = sha256_bytes(body)
    dest = _bodies(engagement) / f"{digest}.bin"
    dest.write_bytes(body)
    rid = store.add_request(
        source="client", actor="attacker", method="POST",
        url="https://www.acme.example/login", host="www.acme.example",
        req_body_path=str(dest), req_body_sha256=digest,
    )
    view = proc.show_body(store, rid, side="request", pattern="next=/admin")
    assert len(view.matches) == 1
    assert view.side == "request"


def test_every_problem_with_one_read_is_reported_together(engagement, store):
    rid = _record(store, engagement, BIG)
    with pytest.raises(ProcError) as exc:
        proc.show_body(store, rid, side="payload", pattern="user[0-9", max_matches=0)
    message = str(exc.value)
    assert "payload" in message
    assert "regular expression" in message
    assert "--max-matches" in message


def test_register_refuses_without_a_boot_id(engagement, spawn, monkeypatch):
    child = spawn()
    monkeypatch.setattr(proc, "boot_id", lambda: None)
    with pytest.raises(ProcError) as exc:
        proc.register(child.pid, kind="proxy")
    assert "post-reboot namesake" in str(exc.value)
    assert not proc.registry_path().exists()


def test_a_zombie_is_reported_as_gone_not_as_a_recycled_pid(engagement, spawn):
    # Its /proc/<pid>/cmdline is empty, so the strict identity check sees a
    # mismatch; the kernel cannot reuse the number while the zombie holds it, so
    # calling that "recycled" would be a false alarm every time a parent has not
    # yet called wait(). `poll()` is avoided deliberately: it reaps.
    child = spawn()
    proc.register(child.pid, kind="scan")
    os.kill(child.pid, signal.SIGKILL)
    limit = time.monotonic() + 5.0
    while time.monotonic() < limit:
        ident = proc.read_identity(child.pid)
        if ident is not None and ident.state == "Z":
            break
        time.sleep(0.02)
    else:  # pragma: no cover - the child was reaped by someone else
        pytest.skip("could not observe the child as a zombie")

    (outcome,) = proc.cleanup().outcomes

    assert outcome.action == "gone"
    assert "waiting to be reaped" in outcome.detail
    assert outcome.signals == ()
    assert _rows() == {}


def test_an_empty_cmdline_on_a_live_pid_is_still_refused(engagement, spawn):
    # The zombie relaxation must not become "an empty cmdline is fine": a live
    # process whose argv no longer matches is exactly the recycled-pid case.
    child = spawn()
    entry = proc.register(child.pid, kind="scan")
    real = proc.read_identity(child.pid)
    blanked = type(real)(
        pid=real.pid,
        cmdline_sha256=sha256_bytes(b""),
        start_ticks=entry.start_ticks,
        boot_id=entry.boot_id,
        uid=real.uid,
        argv=(),
        raw_cmdline=b"",
        state="S",
    )
    import pytest as _pytest

    with _pytest.MonkeyPatch.context() as mp:
        mp.setattr(proc, "read_identity", lambda pid: blanked)
        (outcome,) = proc.cleanup().outcomes

    assert outcome.action == "refused"
    assert outcome.signals == ()
    assert child.poll() is None


def test_an_absent_side_says_so_rather_than_printing_an_empty_hash(engagement, store):
    rid = _record(store, engagement, BIG)
    text = proc.show_body(store, rid, side="request").text()
    assert "no request body was recorded" in text
    assert "sha256:" not in text
