"""Custody of what a hunt leaves behind: the processes it spawned, the bytes it captured.

Two jobs that look unrelated and are the same job. An unattended hunt spawns
things that outlive it -- `mitmdump`, a headless browser, a long scan -- and it
captures response bodies too large to keep in the store, which land in
`raw/bodies/<sha256>.bin`. When a hunt is interrupted, the next person or agent
to touch either reaches for a raw OS tool: `kill` for the pid, `cat` and `grep`
for the file. Both reflexes are wrong here for the same reason: neither tool
checks that the thing it is about to act on is the thing that was recorded.

**A pid is not an identity.** Pids are recycled, and the window is not
theoretical on a machine running a hunt: the harness forks subprocesses
constantly, and `/proc/sys/kernel/pid_max` is 4194304 only on paper -- the
allocator wraps. A registry that remembers the number and kills it will
eventually kill an editor, a database, or the operator's shell. So `register`
writes down what the process *was* -- the exact bytes of `/proc/<pid>/cmdline`,
the start time in clock ticks since boot (field 22 of `/proc/<pid>/stat`), and
the boot id, because a tick count only means something within one boot -- and
`cleanup` signals a pid only while all of that still agrees. On any
disagreement it refuses *that pid*, names the field that disagreed, and moves
on: a mismatch is not an error that aborts the sweep, it is a process that must
not be touched.

**A file is not evidence.** A body under `raw/bodies/` is named after its own
sha256, so a file whose contents no longer hash to its name is not the body
that was captured, and nothing that cites it is a reproduction of anything.
`show_body` re-hashes before it reads, refuses on a mismatch, keeps the read
inside the engagement's `raw/` tree, bounds its own output, and passes
everything it is about to print through `bbh.secrets.redact` -- because the
likeliest place for a session cookie to resurface is the response that set it.

Why one module: both halves replace a reflex with a check, both must fail
closed (an identity that cannot be computed is a refusal, never an assumed
match; a scan that ran out of budget says so rather than reporting "no
matches"), and both need the same escaping of bytes nobody chose to write --
an argv can contain a newline just as a body can.

The registry lives at `.state/procs.json`, the harness-global state directory
rather than an engagement's, because the dangerous leftover is a proxy from a
*previous* engagement still listening and still enforcing the scope it started
with. A registry an operator has to pick the right engagement to read would
miss exactly that case. Each row carries its engagement so the filter is still
available.

It is written under an exclusive `fcntl` lock held across read-and-write, the
same way `bbh.http` writes `.state/rate.json`, and deliberately *not* with the
tmp-file-plus-`os.replace` that `bbh.secrets` uses: `flock` is held on an
inode, so replacing the file would hand a second writer a lock on a different
inode and lose the mutual exclusion that is the point. Corruption is never
reset: a registry that will not parse is a registry nothing can be verified
against, and starting over would silently forget a live proxy.
"""

from __future__ import annotations

import base64
import fcntl
import io
import json
import os
import re
import signal
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

from . import paths, secrets
from .store import Store, sha256_bytes, sha256_file, utcnow

__all__ = [
    "ProcError",
    "PROC_KINDS",
    "ACTIONS",
    "DEFAULT_GRACE_S",
    "Identity",
    "ProcEntry",
    "ProcOutcome",
    "CleanupReport",
    "registry_path",
    "read_identity",
    "pid_alive",
    "identity_problems",
    "exited_as_zombie",
    "register",
    "registered",
    "forget",
    "cleanup",
    "BODY_SIDES",
    "BodyMatch",
    "BodyView",
    "show_body",
]


class ProcError(RuntimeError):
    """A refusal whose message carries the remedy. Printed bare, never as a traceback."""


SCHEMA_VERSION = 1

# What the harness spawns. Constrained so `bb cleanup --kind proxy` is a
# question with an answer, and so a typo in `--kind` is a refusal rather than a
# filter that matches nothing and reads back as "there is nothing to clean up".
PROC_KINDS = ("proxy", "browser", "scan", "tunnel", "other")

# Every per-pid result. There is no "unknown": a pid whose fate cannot be
# determined is `refused` or `survived`, both of which say it is still running.
ACTIONS = ("gone", "terminated", "killed", "refused", "denied", "survived", "dry-run")
# The ones that mean "this is no longer running", and so may leave the registry.
RESOLVED_ACTIONS = ("gone", "terminated", "killed")

DEFAULT_GRACE_S = 5.0
POLL_S = 0.05

# `subprocess.Popen` returns between fork and exec, where /proc still shows the
# *parent's* argv. Registering then would pin the wrong identity for good, so
# `register(expect=...)` waits this long for the exec to land.
EXEC_SETTLE_S = 2.0
EXEC_POLL_S = 0.025

CMDLINE_DISPLAY = 200
EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
PROCFS = Path("/proc")
BOOT_ID_FILE = PROCFS / "sys" / "kernel" / "random" / "boot_id"

# Bodies. The reader is usually an agent with a finite context window, so the
# bound is structural: a fixed number of match windows, each a fixed size.
BODY_SIDES = ("request", "response")
_SIDE_ALIASES = {"request": "request", "req": "request", "response": "response", "resp": "response"}
_SIDE_PREFIX = {"request": "req", "response": "resp"}
MAX_MATCHES = 40
MATCH_WINDOW = 192
PREVIEW_BYTES = 2048
SCAN_BUDGET_S = 5.0
# Each regex call sees at most one window, so backtracking is bounded by the
# window and not by the file. The overlap is what a match may span and still be
# found whole; a pattern that matches more than 8 KiB is not a search.
SCAN_WINDOW = 1 << 16
SCAN_OVERLAP = 1 << 13
MAX_PATTERN_CHARS = 512

_BODY_FILENAME = re.compile(r"\A(?P<sha>[0-9a-f]{64})\.bin\Z")


# -- refusals -----------------------------------------------------------------
#
# Collected and raised together: one round trip, not five. The shape matches
# store.advance() -- what is wrong, then the command that fixes it.


def _refuse(headline: str, problems: Sequence[tuple[str, str]]) -> ProcError:
    detail = "\n".join(f"  - {what}\n    fix: {how}" for what, how in problems)
    return ProcError(f"{headline}\n{detail}")


def _escape_text(text: str) -> str:
    """One printable line. Argv and response bytes are not text anyone chose."""
    out: list[str] = []
    for ch in text:
        if ch == " " or ch.isprintable():
            out.append(ch)
            continue
        point = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif point < 0x100:
            out.append(f"\\x{point:02x}")
        elif point < 0x10000:
            out.append(f"\\u{point:04x}")
        else:
            out.append(f"\\U{point:08x}")
    return "".join(out)


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + f"…[+{len(text) - limit} chars]"


def _display_bytes(raw: bytes, engagement: str | None, limit: int) -> str:
    """Bytes as one redacted, escaped, clipped line.

    Decode first and redact before escaping: `bbh.secrets` matches the value's
    raw, base64, percent-encoded and JSON-escaped forms, and the reference it
    substitutes is plain ASCII that escaping leaves alone.
    """
    text = raw.decode("utf-8", "backslashreplace")
    if engagement:
        text = secrets.redact(text, engagement)
    return _clip(_escape_text(text), limit)


# -- /proc --------------------------------------------------------------------


@dataclass(frozen=True)
class Identity:
    """What a live pid is right now, recomputed from /proc on every read."""

    pid: int
    cmdline_sha256: str
    start_ticks: int
    boot_id: str | None
    uid: int | None
    argv: tuple[str, ...]
    raw_cmdline: bytes
    state: str = ""

    def display(self, engagement: str | None = None) -> str:
        return _display_bytes(
            self.raw_cmdline.replace(b"\x00", b" ").strip(), engagement, CMDLINE_DISPLAY
        )


def _procfs_problem() -> tuple[str, str] | None:
    """Why this machine cannot identify a process, or None."""
    if (PROCFS / "self" / "stat").is_file():
        return None
    return (
        f"this system has no readable procfs at {PROCFS}, and a pid on its own is not an "
        f"identity -- pids are recycled, so without /proc there is no way to tell the "
        f"process the harness spawned from whatever now holds its number",
        "stop the process by hand: ps -o pid,lstart,args -ax | grep mitmdump",
    )


def boot_id() -> str | None:
    """This boot's id, or None when the kernel does not publish one.

    Start time is counted in ticks since boot, so the same (pid, start_ticks)
    pair can name a different process after a reboot. Without a boot id that
    cannot be ruled out, which is why `cleanup` refuses rather than guesses.
    """
    try:
        text = BOOT_ID_FILE.read_text(encoding="ascii").strip()
    except OSError:
        return None
    return text or None


def pid_alive(pid: int) -> bool:
    """Whether signal 0 reaches the pid. PermissionError means alive, not absent."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True  # fail closed: unknown errno is not proof of absence
    return True


def _stat_fields(raw: str) -> tuple[str, int]:
    """(state, start ticks) -- fields 3 and 22 of /proc/<pid>/stat.

    Split after the LAST ')': field 2 is the executable name, unquoted and free
    to contain spaces and parentheses, so splitting the whole line on
    whitespace misaligns every field after it.
    """
    cut = raw.rfind(")")
    if cut < 0:
        raise ValueError("no ')' terminating the comm field")
    fields = raw[cut + 1 :].split()
    if len(fields) < 20:
        raise ValueError(f"only {len(fields)} fields after comm, need 20 to reach starttime")
    # fields[0] is field 3 (state), so field 22 is index 19.
    return fields[0], int(fields[19])


def _uid(pid: int) -> int | None:
    """The real uid from /proc/<pid>/status, or None when it cannot be read.

    Recorded, not enforced: the sandboxed phase launch is
    `sudo -n -- ip netns exec ... setpriv --reuid=<you>`, so the process most
    in need of cleanup is root-owned. What the uid buys is a remedy that names
    `sudo kill` instead of reporting a mysterious refusal.
    """
    try:
        for line in (PROCFS / str(pid) / "status").read_text(encoding="utf-8").splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def read_identity(pid: int) -> Identity | None:
    """What the pid is now, or None when there is no such process.

    Raises `ProcError` when the pid is alive but its identity cannot be
    computed -- an unreadable /proc (hidepid), a stat line that will not parse.
    That is the fail-closed case: `cleanup` must be able to tell "it is gone"
    from "I cannot prove what it is", because only the first one is safe.
    """
    entry = PROCFS / str(pid)
    try:
        raw_cmdline = (entry / "cmdline").read_bytes()
        raw_stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        if pid_alive(pid):
            raise ProcError(
                f"pid {pid} is alive but {entry} does not exist, so its identity cannot be "
                f"computed and the harness will not signal it -- on a /proc mounted with "
                f"hidepid, a pid the harness cannot inspect is indistinguishable from a "
                f"recycled one.\n"
                f"  ps -o pid,lstart,args -p {pid}\n"
                f"  kill -TERM {pid}    # only after you have confirmed what it is"
            ) from None
        return None
    except OSError as exc:
        raise ProcError(
            f"cannot read {entry} ({exc.strerror or exc}), so the process at pid {pid} "
            f"cannot be identified and will not be signalled.\n"
            f"  ps -o pid,lstart,args -p {pid}"
        ) from exc

    try:
        state, ticks = _stat_fields(raw_stat)
    except ValueError as exc:
        raise ProcError(
            f"cannot read the start time of pid {pid} from {entry / 'stat'} ({exc}); without "
            f"it a recycled pid cannot be told from the registered one, so this pid will not "
            f"be signalled.\n"
            f"  ps -o pid,lstart,args -p {pid}"
        ) from exc

    argv = tuple(
        part.decode("utf-8", "surrogateescape") for part in raw_cmdline.split(b"\x00") if part
    )
    return Identity(
        pid=pid,
        cmdline_sha256=sha256_bytes(raw_cmdline),
        start_ticks=ticks,
        boot_id=boot_id(),
        uid=_uid(pid),
        argv=argv,
        raw_cmdline=raw_cmdline,
        state=state,
    )


# -- the registry -------------------------------------------------------------


@dataclass(frozen=True)
class ProcEntry:
    """One registered process, as it was at the moment it was registered."""

    pid: int
    kind: str
    engagement: str | None
    cmdline_sha256: str
    cmdline: str
    start_ticks: int
    boot_id: str | None
    uid: int | None
    port: int | None
    note: str | None
    registered_at: str
    registered_by: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "kind": self.kind,
            "engagement": self.engagement,
            "cmdline_sha256": self.cmdline_sha256,
            "cmdline": self.cmdline,
            "start_ticks": self.start_ticks,
            "boot_id": self.boot_id,
            "uid": self.uid,
            "port": self.port,
            "note": self.note,
            "registered_at": self.registered_at,
            "registered_by": self.registered_by,
        }

    def label(self) -> str:
        bits = [self.kind]
        if self.engagement:
            bits.append(self.engagement)
        if self.port:
            bits.append(f"port {self.port}")
        return " ".join(bits)


def registry_path() -> Path:
    return paths.STATE_DIR / "procs.json"


def _entry_from_row(row: Any, path: Path) -> ProcEntry:
    """One stored row, or a refusal. A row that will not parse is not a default."""
    if not isinstance(row, Mapping):
        raise _unreadable_registry(path, f"a row is {type(row).__name__}, not an object")
    try:
        pid = int(row["pid"])
        ticks = int(row["start_ticks"])
        digest = str(row["cmdline_sha256"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _unreadable_registry(
            path, f"a row is missing pid, start_ticks or cmdline_sha256 ({exc})"
        ) from exc
    kind = str(row.get("kind") or "other")
    if kind not in PROC_KINDS:
        raise _unreadable_registry(
            path, f"a row has kind {kind!r}, which is not one of {', '.join(PROC_KINDS)}"
        )
    port = row.get("port")
    uid = row.get("uid")
    return ProcEntry(
        pid=pid,
        kind=kind,
        engagement=(str(row["engagement"]) if row.get("engagement") else None),
        cmdline_sha256=digest,
        cmdline=str(row.get("cmdline") or ""),
        start_ticks=ticks,
        boot_id=(str(row["boot_id"]) if row.get("boot_id") else None),
        uid=(int(uid) if isinstance(uid, int) else None),
        port=(int(port) if isinstance(port, int) else None),
        note=(str(row["note"]) if row.get("note") else None),
        registered_at=str(row.get("registered_at") or ""),
        registered_by=int(row.get("registered_by") or 0),
    )


def _unreadable_registry(path: Path, why: str) -> ProcError:
    return ProcError(
        f"the process registry {path} cannot be read: {why}. Nothing will be signalled "
        f"from a registry whose rows cannot be verified, because a row read wrong is a "
        f"pid killed wrong.\n"
        f"  cat {path}                                 # see what is in there\n"
        f"  ps -o pid,lstart,args -ax | grep -E 'mitmdump|chrom'   # find them by hand\n"
        f"  mv {path} {path}.broken                    # discard the registry; this kills "
        f"nothing, and the harness then has no record of what it spawned"
    )


@contextmanager
def _locked_registry() -> Iterator[dict[str, Any]]:
    """Read-modify-write the registry under an exclusive flock.

    Rewritten in place rather than replaced: the lock lives on the inode, so
    `os.replace` would leave a second writer holding a lock on a file nobody
    reads any more. Same approach as `bbh.http._locked_json`, and never
    `reset_on_corrupt` -- see the module docstring.
    """
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        raw = b""
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            raw += chunk
        try:
            state = json.loads(raw) if raw.strip() else {"schema": SCHEMA_VERSION, "procs": {}}
        except ValueError as exc:
            raise _unreadable_registry(path, f"it is not JSON ({exc})") from exc
        if not isinstance(state, dict) or not isinstance(state.get("procs", {}), dict):
            raise _unreadable_registry(path, "it has no 'procs' object")
        state.setdefault("schema", SCHEMA_VERSION)
        state.setdefault("procs", {})
        yield state
        payload = json.dumps(state, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, payload)
        os.ftruncate(fd, len(payload))
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_registry() -> list[ProcEntry]:
    path = registry_path()
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise _unreadable_registry(path, str(exc.strerror or exc)) from exc
    if not raw.strip():
        return []
    try:
        state = json.loads(raw)
    except ValueError as exc:
        raise _unreadable_registry(path, f"it is not JSON ({exc})") from exc
    rows = state.get("procs") if isinstance(state, Mapping) else None
    if not isinstance(rows, Mapping):
        raise _unreadable_registry(path, "it has no 'procs' object")
    return [_entry_from_row(row, path) for _, row in sorted(rows.items())]


def registered(*, engagement: str | None = None, kind: str | None = None) -> list[ProcEntry]:
    """Registered processes, newest first. What `bb proc list` prints."""
    entries = _read_registry()
    if engagement:
        entries = [e for e in entries if e.engagement == engagement]
    if kind:
        entries = [e for e in entries if e.kind == kind]
    return sorted(entries, key=lambda e: (e.registered_at, e.pid), reverse=True)


def register(
    pid: int,
    *,
    kind: str,
    engagement: str | None = None,
    port: int | None = None,
    note: str | None = None,
    expect: Sequence[str] | None = None,
) -> ProcEntry:
    """Record what the process at `pid` is, so `cleanup` can prove it later.

    `expect` is the argv the caller just spawned. When given, registration waits
    up to EXEC_SETTLE_S for /proc to show that argv and refuses if it never
    does, because between fork and exec /proc still reports the parent's
    command line and recording that would pin an identity that can never match.
    A pid with no argv at all is refused either way; see `_settled_identity`.

    The returned entry carries the command line as recorded, redacted and on one
    line. A caller that took the pid from an operator should print it: the
    identity check defends against a pid being recycled, not against the wrong
    pid being named here, and the cmdline is how a human notices the difference.
    """
    problems: list[tuple[str, str]] = []
    bad = _procfs_problem()
    if bad:
        problems.append(bad)
    elif boot_id() is None:
        # Refused here rather than at cleanup: a row whose boot cannot be
        # established is a row cleanup will always refuse, and the operator can
        # still do something about it while the process is in front of them.
        problems.append(
            (
                f"this kernel does not publish {BOOT_ID_FILE}, so a start time in ticks "
                f"since boot cannot be pinned to this boot and `bb cleanup` would refuse the "
                f"pid rather than risk killing a post-reboot namesake",
                "stop it by hand when you are done: ps -o pid,lstart,args -ax",
            )
        )

    if isinstance(pid, bool) or not isinstance(pid, int):
        problems.append(
            (
                f"pid {pid!r} is {type(pid).__name__}, not an int",
                "bb proc register <pid> --kind proxy",
            )
        )
    elif pid <= 1:
        problems.append(
            (
                f"pid {pid} is not a process the harness may ever signal (0 means 'every "
                f"process in my group' and 1 is init)",
                "bb proc register <pid> --kind proxy",
            )
        )
    elif pid in (os.getpid(), os.getppid()):
        who = "this process" if pid == os.getpid() else "the shell that started it"
        problems.append(
            (
                f"pid {pid} is {who}; registering it would make `bb cleanup` kill the harness "
                f"or your own shell",
                "register the process you spawned, not the one spawning it",
            )
        )

    if kind not in PROC_KINDS:
        problems.append(
            (
                f"kind {kind!r} is not one of {', '.join(PROC_KINDS)}",
                f"bb proc register {pid} --kind {PROC_KINDS[0]}",
            )
        )
    if port is not None and (
        isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
    ):
        problems.append(
            (
                f"port {port!r} is not a tcp port number",
                f"bb proc register {pid} --kind {kind} --port 8080",
            )
        )
    if problems:
        raise _refuse(f"refusing to register pid {pid!r}:", problems)

    name = (engagement or "").strip() or paths.active_engagement()
    ident = _settled_identity(pid, expect, name)

    entry = ProcEntry(
        pid=pid,
        kind=kind,
        engagement=name,
        cmdline_sha256=ident.cmdline_sha256,
        cmdline=ident.display(name),
        start_ticks=ident.start_ticks,
        boot_id=ident.boot_id,
        uid=ident.uid,
        port=port,
        note=(str(note).strip() or None) if note else None,
        registered_at=utcnow(),
        registered_by=os.getpid(),
    )
    with _locked_registry() as state:
        # Keyed on the pid: a number the kernel has handed out again belongs to
        # whatever registered last, and keeping both rows would mean cleanup
        # refusing one of them for ever.
        state["procs"][str(pid)] = entry.as_dict()
    _audit(
        "proc_register",
        {
            "pid": pid,
            "kind": kind,
            "engagement": name,
            "port": port,
            "start_ticks": ident.start_ticks,
            "cmdline_sha256": ident.cmdline_sha256,
        },
    )
    return entry


def _is_spawned_argv(running: Sequence[str], wanted: Sequence[str]) -> bool:
    """Is `running` the argv the harness passed to Popen, as the kernel sees it?

    Exact equality is the normal case and the one to prefer. It is wrong for one
    common shape, and `bb proxy start` hits it every time: `mitmdump` is a
    console script with a `#!` line, so the kernel execs the interpreter and
    `/proc/<pid>/cmdline` reads

        /…/mitmproxy/bin/python /…/bin/mitmdump -s … --listen-port 8080

    while the harness passed

        /…/bin/mitmdump -s … --listen-port 8080

    Every Python and Node CLI the harness might spawn looks like this, so an
    exact match refuses to register all of them. Refusing fails safe -- nothing
    is recorded under an identity `cleanup` could never match again -- but the
    net effect was that the proxy, the one process the registry exists to be
    able to stop, was never in it.

    The relaxation is one element and no more: the running argv must be exactly
    the wanted argv with a single extra leading word, and the word at index 1
    must be the program the harness actually asked for. Everything after it is
    compared byte for byte, and for the proxy that includes the addon path, the
    confdir and the port. A recycled pid cannot satisfy that by coincidence, and
    the start-time check in `identity_problems` is the other half of the guard
    either way. A deeper nesting -- a wrapper of a wrapper -- is still refused,
    because at that point the harness no longer knows what it is holding.
    """
    if tuple(running) == tuple(wanted):
        return True
    return (
        len(running) == len(wanted) + 1
        and bool(wanted)
        and tuple(running[1:]) == tuple(wanted)
        and running[1] == wanted[0]
    )


def _settled_identity(pid: int, expect: Sequence[str] | None, engagement: str | None) -> Identity:
    """The identity to record, once the process has an argv to be identified by.

    An empty `/proc/<pid>/cmdline` is refused however long it persists, with or
    without `expect`: it means the process has not reached execve yet, or it is
    a zombie, or it is a kernel thread. Recording `sha256(b"")` as the identity
    of the first of those pins something that stops being true a millisecond
    later, and `cleanup` would then refuse the process for the rest of its life.
    """
    wanted = tuple(str(a) for a in expect) if expect is not None else None
    deadline = time.monotonic() + EXEC_SETTLE_S
    last: Identity | None = None
    while True:
        ident = read_identity(pid)
        if ident is None:
            raise ProcError(
                f"pid {pid} is already gone, so there is nothing to register. A process that "
                f"exited immediately usually failed to start.\n"
                f"  bb proxy start          # check the log it names\n"
                f"  bb proc list"
            )
        if ident.argv and (wanted is None or _is_spawned_argv(ident.argv, wanted)):
            return ident
        last = ident
        if time.monotonic() >= deadline:
            break
        time.sleep(EXEC_POLL_S)

    if last is not None and not last.argv:
        raise ProcError(
            f"pid {pid} has an empty /proc/{pid}/cmdline after {EXEC_SETTLE_S:g}s, so there is "
            f"nothing to identify it by later: it has not reached execve, or it is a zombie, "
            f"or it is a kernel thread. Registering it would record an identity `bb cleanup` "
            f"can never match again.\n"
            f"  ps -o pid,stat,args -p {pid}\n"
            f"  bb proc register {pid} --kind other   # once it is running its own command"
        )
    shown = _display_bytes(
        " ".join(wanted or ()).encode("utf-8", "surrogateescape"), engagement, CMDLINE_DISPLAY
    )
    raise ProcError(
        f"pid {pid} is not running the command the harness spawned, so registering it would "
        f"record an identity `bb cleanup` can never match -- and a process it can never match "
        f"is a process it will never stop.\n"
        f"  expected: {shown}\n"
        f"  running:  {last.display(engagement) if last else '(nothing)'}\n"
        f"  ps -o pid,lstart,args -p {pid}"
    )


def forget(pids: Iterable[int], *, reason: str) -> list[ProcEntry]:
    """Drop rows without signalling anything. The reason is recorded, not optional.

    A row is normally dropped by `cleanup` once the process is gone. Dropping
    one by hand is how an operator clears a pid the harness refuses to touch,
    which means it may still be running -- so the audit log gets the reason and
    whether it was alive at the time.
    """
    wanted = _int_pids(pids, "bb proc forget")
    why = str(reason or "").strip()
    problems: list[tuple[str, str]] = []
    if not why:
        problems.append(
            (
                "no reason given, and a row dropped for a process that may still be running "
                "is the harness forgetting something it started",
                f"bb proc forget {next(iter(wanted), 0)} --reason 'recycled pid, not ours'",
            )
        )
    known = {e.pid: e for e in _read_registry()}
    unknown = sorted(p for p in wanted if p not in known)
    if unknown:
        listed = ", ".join(str(p) for p in sorted(known)) or "none"
        problems.append(
            (
                f"pid(s) {', '.join(str(p) for p in unknown)} are not in the registry "
                f"(registered: {listed}), so this would silently do nothing",
                "bb proc list",
            )
        )
    if problems:
        raise _refuse("refusing to forget:", problems)

    dropped = [known[p] for p in sorted(wanted)]
    with _locked_registry() as state:
        for entry in dropped:
            state["procs"].pop(str(entry.pid), None)
    for entry in dropped:
        _audit(
            "proc_forget",
            {
                "pid": entry.pid,
                "kind": entry.kind,
                "engagement": entry.engagement,
                "reason": why,
                "still_alive": pid_alive(entry.pid),
            },
        )
    return dropped


def _int_pids(pids: Iterable[int], command: str) -> set[int]:
    out: set[int] = set()
    bad: list[Any] = []
    for value in pids or ():
        if isinstance(value, bool) or not isinstance(value, int):
            bad.append(value)
        else:
            out.add(value)
    if bad:
        raise _refuse(
            f"refusing to run {command}:",
            [
                (
                    f"{', '.join(repr(b) for b in bad)} is not a pid",
                    f"{command} <pid>",
                )
            ],
        )
    return out


# -- cleanup ------------------------------------------------------------------


def identity_problems(entry: ProcEntry, ident: Identity) -> list[str]:
    """Every recorded field that disagrees with the live process. [] means it is ours.

    Pure, and public, because this is the whole safety property: `bb proc list`
    shows it without signalling anything, and a test can pin each field on its
    own.
    """
    problems: list[str] = []
    if ident.cmdline_sha256 != entry.cmdline_sha256:
        problems.append(
            f"cmdline: /proc/{entry.pid}/cmdline now hashes to "
            f"{ident.cmdline_sha256[:16]}, not the {entry.cmdline_sha256[:16]} that was "
            f"registered (now: {ident.display(entry.engagement)})"
        )
    if ident.start_ticks != entry.start_ticks:
        problems.append(
            f"start time: field 22 of /proc/{entry.pid}/stat is {ident.start_ticks} ticks "
            f"since boot, not the {entry.start_ticks} that was registered, so this is a "
            f"different process that was given the same pid"
        )
    if entry.boot_id is None or ident.boot_id is None:
        problems.append(
            "boot id: it was not recorded on one side, and a start time in ticks since boot "
            "only identifies a process within one boot"
        )
    elif entry.boot_id != ident.boot_id:
        problems.append(
            f"boot id: this machine booted {ident.boot_id} and the pid was registered under "
            f"{entry.boot_id}, so the registered process did not survive to now"
        )
    return problems


def exited_as_zombie(entry: ProcEntry, ident: Identity) -> bool:
    """Whether this pid is the registered process, already dead and unreaped.

    A zombie is why `identity_problems` cannot be the only question asked. Its
    `/proc/<pid>/cmdline` is empty by definition, so the strict check reports a
    cmdline mismatch and the honest-sounding conclusion -- "the pid was reused"
    -- would be false: the kernel cannot hand the number out again while the
    zombie holds it, which is exactly what makes the start time enough proof
    here. Treating it as a mismatch instead would tell an operator their pid was
    recycled every time a parent had not yet called wait().

    The relaxation is safe in the direction that matters: the outcome is "gone",
    which signals nothing. Nothing in here can make cleanup kill more.
    """
    return (
        ident.state == "Z"
        and not ident.raw_cmdline
        and ident.start_ticks == entry.start_ticks
        and entry.boot_id is not None
        and ident.boot_id == entry.boot_id
    )


@dataclass(frozen=True)
class ProcOutcome:
    """What cleanup did about one pid, and why."""

    pid: int
    kind: str
    engagement: str | None
    action: str
    detail: str
    label: str = ""
    signals: tuple[str, ...] = ()
    waited_s: float = 0.0
    remedy: tuple[str, ...] = ()
    cmdline: str = ""

    @property
    def resolved(self) -> bool:
        return self.action in RESOLVED_ACTIONS

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "kind": self.kind,
            "engagement": self.engagement,
            "action": self.action,
            "detail": self.detail,
            "label": self.label,
            "signals": list(self.signals),
            "waited_s": round(self.waited_s, 3),
            "remedy": list(self.remedy),
            "cmdline": self.cmdline,
        }


@dataclass(frozen=True)
class CleanupReport:
    """Every pid cleanup looked at. `ok` is false while anything is still running."""

    outcomes: tuple[ProcOutcome, ...]
    considered: int
    remaining: int
    dry_run: bool = False

    @property
    def left_running(self) -> tuple[ProcOutcome, ...]:
        return tuple(o for o in self.outcomes if not o.resolved and o.action != "dry-run")

    @property
    def ok(self) -> bool:
        return not self.left_running

    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for outcome in self.outcomes:
            tally[outcome.action] = tally.get(outcome.action, 0) + 1
        return tally

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "dry_run": self.dry_run,
            "considered": self.considered,
            "remaining": self.remaining,
            "counts": self.counts(),
            "outcomes": [o.as_dict() for o in self.outcomes],
        }

    def text(self) -> str:
        if not self.outcomes:
            return (
                "bb cleanup: nothing registered, so there is nothing the harness knows it "
                "started.\nA process it never registered is not in here; find those with:\n"
                "  ps -o pid,lstart,args -ax | grep -E 'mitmdump|chrom|nuclei'"
            )
        tally = self.counts()
        summary = ", ".join(f"{n} {word}" for word, n in sorted(tally.items()))
        lines = [
            f"bb cleanup{' --dry-run' if self.dry_run else ''}: "
            f"{self.considered} registered, {summary}"
        ]
        for outcome in self.outcomes:
            lines.append(f"\n  {outcome.pid}  {outcome.label}")
            if outcome.cmdline:
                lines.append(f"    {outcome.cmdline}")
            marker = outcome.action.upper() if not outcome.resolved else outcome.action
            lines.append(f"    {marker}: {outcome.detail}")
            if outcome.signals:
                lines.append(f"    sent {', '.join(outcome.signals)} after {outcome.waited_s:.1f}s")
            for remedy in outcome.remedy:
                lines.append(f"      {remedy}")
        left = self.left_running
        if left:
            lines.append("")
            lines.append(
                f"{len(left)} process(es) are STILL RUNNING. Nothing was signalled for the "
                f"refused ones: the harness could not prove they are the processes it started, "
                f"and a recycled pid belongs to something the operator cares about."
            )
            if any(o.kind == "proxy" for o in left):
                lines.append(
                    "One of them is a proxy, which is the worst case here: it may still be "
                    "listening and still enforcing the scope it was started with rather than "
                    "the scope armed now."
                )
                lines.append("  bb proxy status")
                lines.append("  bb scope show")
        lines.append("")
        lines.append(f"{self.remaining} row(s) left in {registry_path()}")
        return "\n".join(lines)


def cleanup(
    *,
    engagement: str | None = None,
    kind: str | None = None,
    pids: Iterable[int] | None = None,
    dry_run: bool = False,
    grace_s: float = DEFAULT_GRACE_S,
) -> CleanupReport:
    """Stop every registered process whose identity still matches. Refuse the rest.

    With no filter this covers every process the harness registered, in any
    engagement, because the leftover that matters most is a proxy from an
    engagement that is no longer active.
    """
    problems: list[tuple[str, str]] = []
    bad = _procfs_problem()
    if bad:
        problems.append(bad)
    if kind is not None and kind not in PROC_KINDS:
        problems.append(
            (
                f"kind {kind!r} is not one of {', '.join(PROC_KINDS)}, and a filter that "
                f"matches nothing reads back as 'nothing to clean up'",
                "bb cleanup --kind proxy",
            )
        )
    try:
        grace = float(grace_s)
    except (TypeError, ValueError):
        grace = -1.0
    if grace < 0:
        problems.append(
            (
                f"grace {grace_s!r} is not a number of seconds to wait between SIGTERM and "
                f"SIGKILL",
                "bb cleanup --grace 5",
            )
        )
    if problems:
        raise _refuse("refusing to run cleanup:", problems)

    everything = _read_registry()
    wanted = _int_pids(pids, "bb cleanup") if pids is not None else None
    selected = [
        e
        for e in everything
        if (engagement is None or e.engagement == engagement)
        and (kind is None or e.kind == kind)
        and (wanted is None or e.pid in wanted)
    ]

    # A filter that matches nothing while the registry holds rows is a typo, and
    # a typo that reports "all clear" is the worst answer available. An EMPTY
    # registry is not a typo: it is the second run of the same command.
    if wanted is not None:
        missing = sorted(wanted - {e.pid for e in selected})
        if missing:
            raise _refuse(
                "refusing to run cleanup:",
                [
                    (
                        f"pid(s) {', '.join(str(p) for p in missing)} are not registered under "
                        f"this filter, so cleanup would silently skip them",
                        "bb proc list",
                    )
                ],
            )
    if everything and not selected:
        listed = ", ".join(
            sorted({f"{e.pid}/{e.kind}/{e.engagement or '-'}" for e in everything})
        )
        raise _refuse(
            "refusing to run cleanup: the filter matches none of the registered processes, so "
            "a clean report from it would mean nothing.",
            [(f"registered: {listed}", "bb proc list")],
        )

    # Newest first: a browser or a scan registered later is likely to depend on
    # the proxy registered earlier, and stopping the dependency last keeps its
    # log readable while the rest shut down.
    selected.sort(key=lambda e: (e.registered_at, e.pid), reverse=True)

    outcomes: list[ProcOutcome] = []
    for entry in selected:
        outcomes.append(_resolve(entry, grace_s=grace, dry_run=dry_run))

    # The signalling above sleeps, so the lock is taken again here rather than
    # held across it. Compare-and-swap on the recorded identity: a pid that was
    # re-registered meanwhile is a different process and its row stays.
    dropped = [o.pid for o in outcomes if o.resolved]
    by_pid = {e.pid: e for e in selected}
    remaining = len(everything)
    if dropped and not dry_run:
        with _locked_registry() as state:
            for pid in dropped:
                row = state["procs"].get(str(pid))
                entry = by_pid[pid]
                if isinstance(row, Mapping) and (
                    row.get("cmdline_sha256") != entry.cmdline_sha256
                    or row.get("registered_at") != entry.registered_at
                ):
                    continue
                state["procs"].pop(str(pid), None)
            remaining = len(state["procs"])

    report = CleanupReport(
        outcomes=tuple(outcomes),
        considered=len(selected),
        remaining=remaining,
        dry_run=dry_run,
    )
    _audit(
        "proc_cleanup",
        {
            "engagement": engagement,
            "kind": kind,
            "dry_run": dry_run,
            "counts": report.counts(),
            "left_running": [
                {"pid": o.pid, "kind": o.kind, "action": o.action, "detail": o.detail}
                for o in report.left_running
            ],
        },
    )
    return report


def _outcome(entry: ProcEntry, action: str, detail: str, **kw: Any) -> ProcOutcome:
    return ProcOutcome(
        pid=entry.pid,
        kind=entry.kind,
        engagement=entry.engagement,
        action=action,
        detail=detail,
        label=entry.label(),
        cmdline=entry.cmdline,
        **kw,
    )


def _resolve(entry: ProcEntry, *, grace_s: float, dry_run: bool) -> ProcOutcome:
    """One registered pid: prove it, then stop it. A mismatch never aborts the sweep."""
    try:
        ident = read_identity(entry.pid)
    except ProcError as exc:
        return _outcome(
            entry,
            "refused",
            str(exc).splitlines()[0],
            remedy=(f"ps -o pid,lstart,args -p {entry.pid}",),
        )
    if ident is None:
        return _outcome(entry, "gone", "no such process; the registry row is dropped")
    if exited_as_zombie(entry, ident):
        return _outcome(
            entry,
            "gone",
            "already exited and waiting to be reaped by its parent, so it holds no port and "
            "needs no signal; the registry row is dropped",
        )

    problems = identity_problems(entry, ident)
    if problems:
        return _outcome(
            entry,
            "refused",
            "; ".join(problems)
            + " -- pids are recycled, so this is not the process the harness started",
            remedy=(
                f"ps -o pid,lstart,args -p {entry.pid}",
                f"bb proc forget {entry.pid} --reason 'recycled pid, not ours'",
            ),
        )
    if dry_run:
        return _outcome(
            entry,
            "dry-run",
            "identity matches; this is the process the harness started and it would be "
            "stopped without --dry-run",
        )
    return _stop(entry, grace_s=grace_s)


def _stop(entry: ProcEntry, *, grace_s: float) -> ProcOutcome:
    """SIGTERM, wait, SIGKILL, wait. Identity is re-proved before every escalation."""
    sent: list[str] = []
    started = time.monotonic()
    for sig, name, done in (
        (signal.SIGTERM, "SIGTERM", "terminated"),
        (signal.SIGKILL, "SIGKILL", "killed"),
    ):
        try:
            os.kill(entry.pid, sig)
        except ProcessLookupError:
            return _outcome(
                entry,
                "gone" if not sent else "terminated",
                "exited before the signal landed",
                signals=tuple(sent),
                waited_s=time.monotonic() - started,
            )
        except PermissionError:
            owner = f"uid {entry.uid}" if entry.uid is not None else "another user"
            return _outcome(
                entry,
                "denied",
                f"the kernel refused {name}: the process belongs to {owner} and the harness "
                f"will not escalate its own privileges to stop it",
                signals=tuple(sent),
                waited_s=time.monotonic() - started,
                remedy=(f"sudo kill -TERM {entry.pid}",),
            )
        except OSError as exc:
            return _outcome(
                entry,
                "survived",
                f"{name} failed: {exc.strerror or exc}",
                signals=tuple(sent),
                waited_s=time.monotonic() - started,
                remedy=(f"ps -o pid,lstart,args -p {entry.pid}", f"kill -9 {entry.pid}"),
            )
        sent.append(name)
        verdict = _wait_for_exit(entry, deadline=time.monotonic() + grace_s)
        waited = time.monotonic() - started
        if verdict == "gone":
            return _outcome(
                entry,
                done,
                f"exited after {name}",
                signals=tuple(sent),
                waited_s=waited,
            )
        if verdict == "recycled":
            # Our process died and the kernel handed its number to something
            # else inside the grace period. Escalating now would SIGKILL a
            # stranger, which is the exact failure this module exists to prevent.
            return _outcome(
                entry,
                done,
                f"exited after {name}; the pid has already been reused by another process, "
                f"which was NOT signalled",
                signals=tuple(sent),
                waited_s=waited,
            )
        if verdict == "unproven":
            return _outcome(
                entry,
                "survived",
                f"still running {grace_s:.1f}s after {name}, and its identity can no longer "
                f"be read, so SIGKILL was withheld rather than aimed at a pid the harness "
                f"cannot verify",
                signals=tuple(sent),
                waited_s=waited,
                remedy=(f"ps -o pid,lstart,args -p {entry.pid}",),
            )

    return _outcome(
        entry,
        "survived",
        f"still running {grace_s:.1f}s after SIGKILL; an unkillable process is in an "
        f"uninterruptible wait or a zombie whose parent has not reaped it",
        signals=tuple(sent),
        waited_s=time.monotonic() - started,
        remedy=(
            f"ps -o pid,stat,wchan,args -p {entry.pid}",
            f"bb proc forget {entry.pid} --reason '<why it is left behind>'",
        ),
    )


def _wait_for_exit(entry: ProcEntry, *, deadline: float) -> str:
    """One of gone | recycled | alive | unproven, polled until the deadline."""
    while True:
        try:
            ident = read_identity(entry.pid)
        except ProcError:
            return "unproven"
        if ident is None or exited_as_zombie(entry, ident):
            return "gone"
        if identity_problems(entry, ident):
            return "recycled"
        if time.monotonic() >= deadline:
            return "alive"
        time.sleep(POLL_S)


# -- the sanctioned body reader ----------------------------------------------


@dataclass(frozen=True)
class BodyMatch:
    """One hit, as a redacted printable window around it."""

    line_no: int
    offset: int
    text: str

    def as_dict(self) -> dict[str, Any]:
        return {"line": self.line_no, "offset": self.offset, "text": self.text}


@dataclass(frozen=True)
class BodyView:
    """One side of one recorded request, verified and bounded.

    `complete` is the field that matters: a scan stopped by its own budget has
    not shown that the pattern is absent, and an empty `matches` from an
    incomplete scan is not a negative result.
    """

    request_id: int
    side: str
    engagement: str
    method: str
    url: str
    status: int | None
    actor: str | None
    phase: str | None
    ts: str | None
    sha256: str
    length: int
    source: str
    path: Path | None
    pattern: str | None
    matches: tuple[BodyMatch, ...] = ()
    scanned_bytes: int = 0
    complete: bool = True
    incomplete_reason: str | None = None
    truncated_matches: bool = False
    match_bound: int = MAX_MATCHES
    preview: str | None = None
    preview_length: int = 0
    preview_truncated: bool = False
    redacted: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "side": self.side,
            "engagement": self.engagement,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "actor": self.actor,
            "phase": self.phase,
            "ts": self.ts,
            "sha256": self.sha256,
            "length": self.length,
            "source": self.source,
            "path": str(self.path) if self.path else None,
            "pattern": self.pattern,
            "matches": [m.as_dict() for m in self.matches],
            "match_count": len(self.matches),
            "scanned_bytes": self.scanned_bytes,
            "complete": self.complete,
            "incomplete_reason": self.incomplete_reason,
            "truncated_matches": self.truncated_matches,
            "match_bound": self.match_bound,
            "preview": self.preview,
            "preview_length": self.preview_length,
            "preview_truncated": self.preview_truncated,
            "redacted": list(self.redacted),
        }

    def text(self) -> str:
        head = [f"request {self.request_id}  {self.method} {self.url}"]
        if self.sha256:
            head.append(
                f"  {self.side} body: {self.length} bytes  sha256:{self.sha256[:16]}  "
                f"(verified against the {self.source})"
            )
        else:
            head.append(f"  no {self.side} body was recorded for this request")
        bits = [
            f"status {self.status}" if self.status is not None else "",
            f"actor {self.actor}" if self.actor else "",
            f"phase {self.phase}" if self.phase else "",
            self.ts or "",
        ]
        head.append("  " + "  ".join(b for b in bits if b))
        if self.path:
            head.append(f"  {self.path}")
        if self.redacted:
            head.append(
                f"  redacted before printing: {', '.join(self.redacted)} "
                f"(the value is in sensitive/secrets.json, not here)"
            )

        body: list[str] = []
        if self.pattern is None:
            body.append("")
            body.append(f"  first {self.preview_length} bytes, escaped:")
            body.append(self.preview or "  (empty)")
            if self.preview_truncated:
                body.append(
                    f"  ... {self.length} bytes in total; search the rest rather than "
                    f"printing it:"
                )
                body.append(f"    bb req show {self.request_id} --side {self.side} --grep PATTERN")
        else:
            body.append("")
            body.append(
                f"  {len(self.matches)} match(es) for {self.pattern!r} in {self.scanned_bytes} "
                f"of {self.length} bytes"
            )
            for match in self.matches:
                body.append(f"  {match.line_no}:{match.offset}: {match.text}")
            if not self.matches:
                body.append("  (no match)")
            if self.truncated_matches:
                body.append(
                    f"  ... more matches were not printed (bounded at {self.match_bound}); "
                    f"narrow the pattern"
                )
            if not self.complete:
                body.append(
                    f"  INCOMPLETE: {self.incomplete_reason}. This is NOT a clean negative -- "
                    f"the pattern may be in the part that was not scanned."
                )
        tail = [
            "",
            f"  cite it:  bb evidence add <finding> request --request-id {self.request_id}",
        ]
        return "\n".join(head + body + tail)


def _engagement_for(store: Store, given: str | None) -> str:
    """Which engagement this store belongs to, recomputed from its own path.

    Not taken on trust: redaction and the containment check below both depend
    on naming the right engagement, so the name is accepted only when
    `paths.db_path(name)` is literally the file this store has open.
    """
    name = (given or "").strip() or store.path.parent.name
    if name and os.path.realpath(paths.db_path(name)) == os.path.realpath(store.path):
        return name
    raise ProcError(
        f"cannot tell which engagement {store.path} belongs to (guessed {name!r}, whose "
        f"database would be {paths.db_path(name) if name else '(none)'}). Without it the "
        f"reader cannot bound the read to that engagement's raw/ tree or scan the output "
        f"for its recorded secrets, so it will not print anything.\n"
        f"  bb list\n"
        f"  bb use <engagement>"
    )


def show_body(
    store: Store,
    request_id: int | str,
    *,
    side: str = "response",
    pattern: str | None = None,
    ignore_case: bool = False,
    engagement: str | None = None,
    max_matches: int = MAX_MATCHES,
    window: int = MATCH_WINDOW,
    preview_bytes: int = PREVIEW_BYTES,
    budget_s: float = SCAN_BUDGET_S,
) -> BodyView:
    """Read one recorded body: verified, bounded, redacted. The library side of
    `bb req show <id> [--grep PATTERN]`.

    `pattern` is a regular expression applied to the raw bytes, so it works on a
    body that is not text. Without one, a bounded escaped preview is returned
    instead -- which is the half of this that replaces `cat`.
    """
    name = _engagement_for(store, engagement)
    rid = _request_id(request_id)
    which = _SIDE_ALIASES.get(str(side).strip().lower(), "")
    problems: list[tuple[str, str]] = []
    if not which:
        problems.append(
            (
                f"side {side!r} is not one of {', '.join(BODY_SIDES)}",
                f"bb req show {rid} --side response",
            )
        )
    pattern_problems, rx = _pattern_check(pattern, ignore_case=ignore_case, rid=rid)
    problems += pattern_problems
    problems += _bound_problems(
        rid, max_matches=max_matches, window=window, preview_bytes=preview_bytes,
        budget_s=budget_s,
    )
    if problems:
        raise _refuse(f"refusing to read request {rid}:", problems)

    row = store.conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if row is None:
        total = store.request_count()
        raise ProcError(
            f"no request {rid} in {store.path} ({total} recorded), so there is no body to "
            f"read; a citation of a request that does not exist is a fabrication flag at "
            f"gate time.\n"
            f"  bb status                                   # how many are recorded\n"
            f"  bb evidence list <finding>                  # the request ids a finding cites"
        )

    prefix = _SIDE_PREFIX[which]
    data, path, expected, source = _locate_body(row, rid, which, prefix, name)
    scan = {
        "engagement": name,
        "max_matches": max_matches,
        "window": window,
        "preview_bytes": preview_bytes,
        "budget_s": budget_s,
    }

    if path is None:
        if not data and expected in (None, EMPTY_SHA):
            return _empty_view(row, rid, which, name, pattern)
        actual = sha256_bytes(data)
        if expected is None:
            raise ProcError(
                f"request {rid} carries a {len(data)}-byte {which} body inline but recorded no "
                f"sha256 for it, so there is nothing to verify it against -- an unverifiable "
                f"body is not evidence.\n"
                f"  bb doctor"
            )
        if actual != expected:
            raise _body_mismatch(rid, which, None, expected, actual, row)
        length = len(data)
        view_kw = _scan_stream(io.BytesIO(data), rx, total=length, **scan)
    else:
        actual, length = sha256_file(path)
        if actual != expected:
            raise _body_mismatch(rid, which, path, expected, actual, row)
        with open(path, "rb") as fh:
            view_kw = _scan_stream(fh, rx, total=length, **scan)

    view = BodyView(
        request_id=rid,
        side=which,
        engagement=name,
        method=str(row["method"]),
        url=str(row["url"]),
        status=row["status"],
        actor=row["actor"],
        phase=row["phase"],
        ts=row["ts"],
        sha256=actual,
        length=length,
        source=source,
        path=path,
        pattern=pattern,
        **view_kw,
    )
    _assert_redacted(view, name)
    return view


def _bound_problems(
    rid: int, *, max_matches: int, window: int, preview_bytes: int, budget_s: float
) -> list[tuple[str, str]]:
    """The reader's own limits. A zero bound would report an empty result as a clean one."""
    problems: list[tuple[str, str]] = []
    for label, value, floor in (
        ("--max-matches", max_matches, 1),
        ("--window", window, 1),
        ("--preview-bytes", preview_bytes, 1),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < floor:
            problems.append(
                (
                    f"{label} is {value!r}; below {floor} the reader would print nothing and "
                    f"an empty result would read as a clean one",
                    f"bb req show {rid} {label} {floor * 16}",
                )
            )
    try:
        seconds = float(budget_s)
    except (TypeError, ValueError):
        seconds = -1.0
    if seconds <= 0:
        problems.append(
            (
                f"--budget {budget_s!r} leaves no time to scan, so every result would be "
                f"reported as incomplete",
                f"bb req show {rid} --budget 5",
            )
        )
    return problems


def _request_id(value: int | str) -> int:
    try:
        rid = int(str(value).strip())
    except (TypeError, ValueError):
        raise ProcError(
            f"{value!r} is not a request id. Ids are the integers `bb req` prints as "
            f"'request id: N' and `bb evidence list` shows against each cited request.\n"
            f"  bb evidence list <finding>"
        ) from None
    if rid <= 0:
        raise ProcError(f"request id {rid} is not a row id; ids start at 1.\n  bb status")
    return rid


def _pattern_check(
    pattern: str | None, *, ignore_case: bool, rid: int
) -> tuple[list[tuple[str, str]], re.Pattern[bytes] | None]:
    """The pattern as a bytes regex, with whatever is wrong with it.

    Bytes, not text: a captured body is not required to be valid UTF-8, and
    decoding it to search it would either fail or quietly replace the bytes a
    pattern is looking for.
    """
    if pattern is None:
        return [], None
    if not pattern:
        return [
            (
                "the pattern is empty, and 'no matches' from an empty pattern would be a "
                "false negative the harness handed over itself",
                f"bb req show {rid} --grep 'PATTERN'",
            )
        ], None
    if len(pattern) > MAX_PATTERN_CHARS:
        return [
            (
                f"the pattern is {len(pattern)} characters, over the {MAX_PATTERN_CHARS} "
                f"bound; a pattern that long is a program, and this reader scans bodies "
                f"that may be megabytes",
                f"bb req show {rid} --grep '<shorter pattern>'",
            )
        ], None
    flags = re.IGNORECASE if ignore_case else 0
    try:
        return [], re.compile(pattern.encode("utf-8", "surrogateescape"), flags)
    except re.error as exc:
        return [
            (
                f"{pattern!r} is not a usable regular expression ({exc})",
                f"bb req show {rid} --grep '{re.escape(pattern)[:60]}'   "
                f"# the same text, escaped",
            )
        ], None


def _locate_body(
    row: Any, rid: int, which: str, prefix: str, engagement: str
) -> tuple[bytes, Path | None, str | None, str]:
    """(inline bytes, file, expected sha256, what the hash was taken from).

    A body is either inline in the request note or a file under `raw/bodies/`.
    The expected hash comes from the request row, and for a file also from its
    own content-addressed name; when both are present they must agree.
    """
    recorded = row[f"{prefix}_body_sha256"]
    expected = str(recorded) if recorded else None
    raw_path = row[f"{prefix}_body_path"]

    if not raw_path:
        return _inline_body(row, prefix, rid, which) or b"", None, expected, "request row"

    path = _checked_path(Path(str(raw_path)), expected, rid, which, engagement)
    named = _BODY_FILENAME.match(path.name)
    from_name = named.group("sha") if named else None
    if expected and from_name and expected != from_name:
        raise ProcError(
            f"request {rid} records the {which} body as sha256 {expected} but points at "
            f"{path}, whose name says {from_name}. One of the two is wrong, so neither can "
            f"be read as evidence.\n"
            f"  sha256sum {path}\n"
            f"  bb doctor"
        )
    if expected is None and from_name is None:
        raise ProcError(
            f"request {rid} has a {which} body at {path} but no recorded sha256, and the "
            f"filename does not carry one either, so there is nothing to verify it against "
            f"-- an unverifiable body is not evidence.\n"
            f"  sha256sum {path}\n"
            f"  bb doctor"
        )
    both = expected is not None and from_name is not None
    source = "request row and the content-addressed filename" if both else (
        "request row" if expected else "content-addressed filename"
    )
    return b"", path, expected or from_name, source


def _inline_body(row: Any, prefix: str, rid: int, which: str) -> bytes | None:
    """The small body the client stored in the request note, or None."""
    raw_note = row["note"]
    if not raw_note:
        return None
    try:
        note = json.loads(str(raw_note))
    except ValueError as exc:
        raise ProcError(
            f"the note on request {rid} is not JSON ({exc}), so a body stored inline in it "
            f"cannot be read back.\n"
            f"  bb doctor"
        ) from exc
    held = note.get(f"{prefix}_body") if isinstance(note, Mapping) else None
    if not isinstance(held, Mapping):
        return None
    if isinstance(held.get("text"), str):
        return held["text"].encode("utf-8", "surrogateescape")
    if isinstance(held.get("base64"), str):
        try:
            return base64.b64decode(held["base64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ProcError(
                f"the inline {which} body of request {rid} is not valid base64 ({exc}), so it "
                f"cannot be read back or verified.\n  bb doctor"
            ) from exc
    return None


def _checked_path(path: Path, expected: str | None, rid: int, which: str, engagement: str) -> Path:
    """The body file, proved to be inside this engagement's raw/ tree.

    `*_body_path` is a stored field, and this reader turns it into a file read:
    if a row ever carried `~/.ssh/id_rsa`, following it would make `bb req show`
    an arbitrary-file reader with redaction on top. Symlinks are resolved before
    the check, so a link inside raw/ cannot point out of it. The content-addressed
    fallback exists because the harness is one movable directory and these paths
    are absolute: after a move, the recorded path is stale but the sha256 still
    names the file.
    """
    raw_root = paths.engagement_dir(engagement) / "raw"
    root = Path(os.path.realpath(raw_root))
    resolved = Path(os.path.realpath(path))
    if not resolved.is_file() and expected:
        candidate = Path(os.path.realpath(raw_root / "bodies" / f"{expected}.bin"))
        if candidate.is_file():
            resolved = candidate
    if not resolved.is_file():
        raise ProcError(
            f"the {which} body of request {rid} is recorded at {path}, which does not exist. "
            f"Captured bodies are content addressed under {raw_root / 'bodies'}, so a missing "
            f"one means the tree was moved or pruned -- and a finding citing it has lost its "
            f"evidence.\n"
            f"  ls {raw_root / 'bodies'}\n"
            f"  bb doctor"
        )
    if root != resolved and root not in resolved.parents:
        raise ProcError(
            f"refusing to read {resolved}: it is outside {root}, and this reader only reads "
            f"bodies the harness captured -- following a stored path anywhere else would make "
            f"`bb req show` a way to print any file on this machine.\n"
            f"  bb doctor"
        )
    return resolved


def _body_mismatch(
    rid: int, which: str, path: Path | None, expected: str | None, actual: str | None, row: Any
) -> ProcError:
    where = str(path) if path else "the copy stored inline in the request note"
    actor = row["actor"] or "<actor>"
    remedies = [f"  sha256sum {path}"] if path else []
    remedies += [
        "  bb doctor                     # check the rest of the tree",
        f"  bb req {row['method']} {row['url']} --actor {actor}   # capture it again",
    ]
    return ProcError(
        f"refusing to read the {which} body of request {rid}: {where} hashes to {actual} but "
        f"the request row recorded {expected}. The bytes have changed since they were "
        f"captured, so this is not the body that was observed and nothing citing it "
        f"reproduces anything.\n" + "\n".join(remedies)
    )


def _empty_view(row: Any, rid: int, which: str, engagement: str, pattern: str | None) -> BodyView:
    """A side that carries no body at all.

    With a pattern this is a refusal, not an answer: scanning nothing and
    reporting no matches is a false negative, and the usual cause is the wrong
    `--side` (a GET has no request body).
    """
    if pattern is not None:
        other = "response" if which == "request" else "request"
        raise ProcError(
            f"request {rid} ({row['method']} {row['url']}) recorded no {which} body (0 bytes), "
            f"so there is nothing to search; reporting 'no matches' from an empty body would "
            f"be a false negative.\n"
            f"  bb req show {rid} --side {other} --grep '{pattern}'\n"
            f"  bb req show {rid} --side {other}"
        )
    return BodyView(
        request_id=rid,
        side=which,
        engagement=engagement,
        method=str(row["method"]),
        url=str(row["url"]),
        status=row["status"],
        actor=row["actor"],
        phase=row["phase"],
        ts=row["ts"],
        sha256="",
        length=0,
        source="request row",
        path=None,
        pattern=None,
        preview=None,
    )


def _scan_stream(
    fh: Any,
    rx: re.Pattern[bytes] | None,
    *,
    total: int,
    engagement: str,
    max_matches: int,
    window: int,
    preview_bytes: int,
    budget_s: float,
) -> dict[str, Any]:
    """Run the pattern over the stream in bounded, overlapping windows.

    Window-oriented rather than line-oriented on purpose: a captured body may be
    one multi-megabyte line of binary, and handing that to one regex call is how
    a pathological pattern stops the hunt. Each call sees at most SCAN_WINDOW
    bytes, and the SCAN_OVERLAP carried between them is how long a single match
    may be and still be found whole.
    """
    if rx is None:
        raw = fh.read(max(0, preview_bytes))
        decoded = raw.decode("utf-8", "backslashreplace")
        return {
            "preview": _preview_text(raw, engagement),
            "preview_length": len(raw),
            "preview_truncated": total > len(raw),
            "scanned_bytes": 0,
            "redacted": tuple(secrets.scan_text(decoded, engagement)),
        }

    deadline = time.monotonic() + max(0.0, float(budget_s))
    matches: list[BodyMatch] = []
    seen: set[int] = set()
    found_labels: set[str] = set()
    buf = b""
    base = 0
    newlines_before = 0
    scanned = 0
    complete = True
    reason: str | None = None
    truncated_matches = False

    while True:
        chunk = fh.read(SCAN_WINDOW)
        if chunk:
            buf += chunk
            scanned = base + len(buf)
        for match in rx.finditer(buf):
            absolute = base + match.start()
            if absolute in seen:
                continue
            seen.add(absolute)
            if len(matches) >= max_matches:
                truncated_matches = True
                break
            text, labels = _match_window(buf, base, total, match, window, engagement)
            found_labels.update(labels)
            matches.append(
                BodyMatch(
                    line_no=1 + newlines_before + buf.count(b"\n", 0, match.start()),
                    offset=absolute,
                    text=text,
                )
            )
        if truncated_matches or not chunk:
            break
        if time.monotonic() > deadline:
            complete = False
            reason = (
                f"the {budget_s:g}s scan budget ran out after {scanned} of {total} bytes"
            )
            break
        keep = min(len(buf), SCAN_OVERLAP)
        dropped = len(buf) - keep
        newlines_before += buf.count(b"\n", 0, dropped)
        base += dropped
        buf = buf[dropped:]

    return {
        "matches": tuple(matches),
        "scanned_bytes": min(scanned, total),
        "complete": complete,
        "incomplete_reason": reason,
        "truncated_matches": truncated_matches,
        "match_bound": max_matches,
        "redacted": tuple(sorted(found_labels)),
    }


def _match_window(
    buf: bytes,
    base: int,
    total: int,
    match: re.Match[bytes],
    window: int,
    engagement: str,
) -> tuple[str, list[str]]:
    """One match as a redacted printable window, trimmed to its line where it has one.

    The window is the hard bound, because a captured body may have no newlines
    at all; trimming to the enclosing line inside that bound is what makes the
    output read like `grep` on the text bodies that do.
    """
    half = max(0, window) // 2
    left = max(0, match.start() - half)
    right = min(len(buf), match.end() + half)
    line_start = buf.rfind(b"\n", left, match.start())
    if line_start != -1:
        left = line_start + 1
    line_end = buf.find(b"\n", match.end(), right)
    if line_end != -1:
        right = line_end

    decoded = buf[left:right].decode("utf-8", "backslashreplace")
    labels = secrets.scan_text(decoded, engagement)
    text = _escape_text(secrets.redact(decoded, engagement))
    if base + left > 0 and buf[left - 1 : left] != b"\n":
        text = "…" + text
    if base + right < total and buf[right : right + 1] != b"\n":
        text = text + "…"
    return text, labels


def _preview_text(raw: bytes, engagement: str) -> str:
    """The head of a body, redacted and escaped line by line, indented for printing."""
    decoded = secrets.redact(raw.decode("utf-8", "backslashreplace"), engagement)
    return "\n".join(f"  {_escape_text(line)}" for line in decoded.splitlines() or [""])


def _assert_redacted(view: BodyView, engagement: str) -> None:
    """Nothing here trusts itself: re-scan the rendered output before it is printed.

    Unreachable unless redaction regressed, and a bug that leaks a credential
    into a transcript is worth a loud refusal rather than a quiet print.
    """
    rendered = "\n".join(
        [view.preview or ""] + [m.text for m in view.matches]
    )
    leaked = secrets.scan_text(rendered, engagement)
    if leaked:
        raise ProcError(
            f"refusing to print the {view.side} body of request {view.request_id}: the value "
            f"of secret(s) {', '.join(leaked)} survived redaction, which is a bug in "
            f"bbh/secrets.py or bbh/proc.py rather than something you can work around.\n"
            f"  .venv/bin/python -m pytest tests/test_proc.py -x\n"
            f"  bb secret list"
        )


# -- audit --------------------------------------------------------------------


def _audit(event: str, record: Mapping[str, Any]) -> None:
    """Append one chained record to the shared audit log. Never raises.

    Same shape and the same deferred import as `bbh.engagement._audit`: the log
    is a log, so a failure to write it is reported by `bb doctor --verify-chain`
    and not by an exception in the middle of a cleanup. Nothing on the refusal
    path is wrapped like this -- a mismatch is still a mismatch whether or not
    it was logged.
    """
    body = {"ts": utcnow(), **dict(record)}
    try:
        paths.STATE_DIR.mkdir(parents=True, exist_ok=True)
        from .cli import audit_record

        if audit_record(event, body):
            return
    except Exception:
        pass
    try:
        with paths.AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"event": event, **body}, default=str) + "\n")
    except Exception:
        pass
