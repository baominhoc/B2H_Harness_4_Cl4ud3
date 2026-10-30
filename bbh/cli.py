"""Command line front end: one door into the harness for agent and human alike.

Every subcommand is a thin wrapper over a library call. The CLI's own work is
threefold: decide which engagement a command means, turn library objects into
output a person can read at a glance, and turn every failure into a sentence
plus the exact command that fixes it. An autonomous agent reads these messages
mid-hunt and acts on them, so a leaked traceback is a bug, not a detail.

The heavy modules (runner, http, report, triage, engagement) are imported
inside their handlers rather than at the top. `bb doctor` has to be able to
report that one of them is broken, which it cannot do if importing it is what
kills the process.
"""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import getpass
import hashlib
import importlib
import inspect
import io
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import uuid
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, Iterator, Mapping, Sequence, TextIO
from urllib.parse import urlsplit

from . import __version__, guard, paths
from .scope import Scope, ScopeError, compile_rule
from .store import (
    ANGLE_OUTCOME_ALIASES,
    ANGLE_SOURCES,
    CONFIDENCE_LEVELS,
    DELIVERY_MODES,
    EVIDENCE_ROLES,
    LADDER,
    PREREQUISITE_VERDICTS,
    SEVERITIES,
    STATES,
    Store,
)
from .store import ANGLE_OUTCOMES as STORE_ANGLE_OUTCOMES

__all__ = ["main"]

# Vocabulary the store's schema documents; constraining the CLI keeps the
# report and triage layers from meeting a kind they have no rendering for.
EVIDENCE_KINDS = ("request", "screenshot", "har", "terminal", "file", "note")

# Angle outcomes, taken from the store rather than restated here: the CLI had a
# second, v1-only copy of this list, so every v2 word the store understands --
# the ones that carry a `control` or a `next_test` -- was unreachable through
# `bb angle add` and argparse rejected it before the store ever saw it. The v1
# words stay accepted because the phase prompts still teach them and the store
# maps them to their v2 equivalent; the help text leads with v2.
ANGLE_OUTCOMES = STORE_ANGLE_OUTCOMES + tuple(
    word for word in ANGLE_OUTCOME_ALIASES if word not in STORE_ANGLE_OUTCOMES
)
REPORTABLE_STATES = ("gated", "ready")

# Which rung `bb gate` is asked to guard. The gates that belong to a rung are
# triage.gates_for_state(...), which is the authority and has the error message;
# this list only keeps argparse from accepting a word nothing guards. Sliced off
# the store's ladder rather than written out, so a new rung is reachable without
# anyone remembering to edit the CLI. `LADDER[0]` is `candidate`: an unchecked
# claim, which is why triage guards no transition into it.
DEFAULT_GATE_TARGET = "gated"
GATE_TARGETS: tuple[str, ...] = LADDER[1:]

# Everything `bb gate` does besides running the gates. Hand-dispatched from its
# positional words rather than being argparse subcommands, because `bb gate
# <finding>` and `bb gate --all` are named all over the gate rationales and the
# prompts, and a subparser group would make the finding reference an invalid
# choice. An unrecognised first word is refused by name, never read as a
# finding.
GATE_SUBCOMMANDS: tuple[str, ...] = ("waive", "waivers", "waive-request")

HOOK_TIMEOUT = 10
PROBE_OUT_OF_SCOPE = "curl -sS https://doctor-probe.invalid/"

MIN_PYTHON = (3, 12)

# Output bounding. The reader is usually an agent with a finite context window,
# so a subcommand that can print an unbounded amount of text slices head+tail
# and says exactly what it dropped. A truncation that does not state its own
# size is where a wrong conclusion starts.
MAX_OUT_LINES = 200
MAX_OUT_BYTES = 16 * 1024
HEAD_LINES = 140
TAIL_LINES = MAX_OUT_LINES - HEAD_LINES
MAX_LINE_BYTES = 2048

# Models pass these literally where they mean "no value", and a filter of
# "none" that matches nothing reads back as "there is nothing there" -- a false
# negative the harness itself handed over. Treated as if the flag were absent.
OMITTED_LITERALS = ("", "null", "none", "nil", "undefined")

# Added to the `choices` of the constrained filters so a sentinel is normalised
# rather than killed by argparse with a usage dump. `metavar` keeps --help clean.
OMITTED_CHOICES = tuple(sorted(set(OMITTED_LITERALS)))

# Flows captured through the proxy outside a hunt phase still get a phase, so
# that a NULL phase means "lost", never "manual".
DEFAULT_PROXY_PHASE = "manual-proxy"

# What the first line of the audit chain links back to.
AUDIT_GENESIS = "0" * 64

# The only two `run_hunt` statuses that mean the plan ran. Everything else --
# `budget`, `deadline`, `expired`, `disk`, `error`, or a status a later runner
# adds -- is a hunt that stopped short, and an exit code of 0 is how a cron
# line or a wrapper script learns the night went fine when it did not. Listed
# as the successes rather than the failures so an unrecognised status exits
# non-zero instead of passing on a name nobody checked.
HUNT_OK_STATUSES = ("complete", "dry-run")

# `bb go` defaults. Every one of them spends money or sends traffic at somebody
# else's systems, so the plan prints all of them before anything starts instead
# of leaving them to be discovered in the summary afterwards. The figures are
# the ones the harness already chose elsewhere rather than new opinions: a
# second default for the same thing is a second thing to keep in step.
GO_MODEL = "claude-opus-5"  # `bb hunt --model`
# Pinned by full name rather than the `opus` alias: the alias follows whatever
# Opus ships latest, so the same command would quietly run a different model
# than the one named in the plan an operator read, and a `--resume` weeks later
# would finish a hunt on a model its earlier phases never saw.
GO_EFFORT = "high"  # `bb hunt --effort`, handed straight to `claude --effort`
# The levels `claude --effort` accepts, in its own order. Constrained in the
# parser so a typo is a refusal here instead of a phase that spawns, burns its
# startup and dies on the subprocess's own usage message.
EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
GO_HOURS = 12.0  # engagement.DEFAULT_ARM_HOURS, the documented overnight window

# The dollar cap `bb hunt` and `bb phase` apply when nobody says otherwise, and
# the figure suggested to anyone who wants one back. `bb go` has no default cap
# at all: it is the "point it at a target and leave" path, a dollar figure is
# one more thing to stop and decide, and the run is still bounded -- every
# phase carries `--max-turns` and the whole hunt carries `--hours`. `bb hunt`
# keeps the cap because it is the explicit-control path, and an upgrade must
# not silently remove a ceiling somebody is relying on; `--no-budget` is how it
# is given up there, deliberately and by name.
HUNT_BUDGET_USD = 25.0

# How much longer than the hunt the attestation is armed for. `run_hunt` refuses
# to start when the attestation expires before the hunt's deadline, and arming
# for exactly the hunt length lands the two stamps within a second of each
# other -- whichever rounds first decides whether the hunt runs at all. An hour
# is short enough to still be an attestation and long enough that no amount of
# compiling, hardening and arming in between can eat it.
GO_ARM_MARGIN_HOURS = 1.0

# What `bb go` writes into the lock as the attestation. `bb arm`'s sentence
# means a person opened a program's policy page and read it; nobody did that
# here, and a record claiming more than happened is worse than a thin one,
# because the record is what an operator may later have to stand behind.
GO_STATEMENT = (
    "Authorization asserted by the operator running `bb go {targets}` on this machine. "
    "No program policy page was named or read by that command."
)
GO_STATEMENT_WITH_POLICY = (
    "Authorization asserted by the operator running `bb go {targets}` on this machine, "
    "relying on the policy at {policy_url}, which that command did not read."
)

# Target list length past which the statement names the first target and counts
# the rest. The lock's own in_scope is the authoritative list; the statement
# only has to say what was invoked.
GO_STATEMENT_TARGETS_MAX = 120


class CliError(RuntimeError):
    """A failure whose message is a remedy. Printed bare, never as a traceback."""


# -- small formatting helpers -------------------------------------------------


def out(text: str = "") -> None:
    print(text)


def _flush_streams() -> None:
    """Push stdout and stderr out now, so what was printed is ordered as written.

    Only worth calling where the ORDER is the point. Python line-buffers stdout
    to a terminal and block-buffers it to a file or a pipe, so two streams that
    interleave correctly on screen come out of a redirect in flush order
    instead. A closed or broken stream is not a reason to stop: the caller is
    mid-command and the flush is a courtesy to the reader, not a step.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            pass


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    cells = [[("" if c is None else str(c)) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in cells:
        for i, cell in enumerate(row[: len(widths)]):
            widths[i] = max(widths[i], len(cell))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for row in cells:
        lines.append(
            "  ".join(c.ljust(widths[i]) for i, c in enumerate(row[: len(widths)])).rstrip()
        )
    return "\n".join(lines)


def _fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    seconds = int(max(0.0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    if seconds < 86400:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d{(seconds % 86400) // 3600:02d}h"


def _elapsed(start: float) -> str:
    total = int(time.monotonic() - start)
    if total >= 3600:
        return f"{total // 3600}:{(total % 3600) // 60:02d}:{total % 60:02d}"
    return f"{total // 60:3d}:{total % 60:02d}"


def _fmt_bytes(n: Any) -> str:
    try:
        size = float(n)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GB"


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def _shorten(text: Any, width: int = 90) -> str:
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= width else flat[: width - 1] + "…"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _rel(path: Any, root: Path) -> str:
    """Engagement-relative path when it is inside the engagement, else as given."""
    if not path:
        return "-"
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return str(path)


def _with_remedy(message: str, remedy: str) -> str:
    """Append a remedy unless the message already carries one of its own."""
    return message if "bb " in message else f"{message}\n  {remedy}"


def _describe(obj: Any) -> dict[str, Any]:
    """Best-effort mapping view of a result object this module did not define."""
    if isinstance(obj, Mapping):
        return dict(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    data = getattr(obj, "__dict__", None)
    if isinstance(data, dict):
        return {k: v for k, v in data.items() if not k.startswith("_")}
    return {"result": obj}


def _print_mapping(data: Mapping[str, Any], indent: int = 0) -> None:
    """Render a mapping whose exact shape belongs to another module."""
    pad = " " * indent
    width = max((len(str(k)) for k in data), default=0) + 1
    for key, value in data.items():
        label = f"{key}:".ljust(width)
        if isinstance(value, Mapping):
            out(f"{pad}{key}:")
            _print_mapping(value, indent + 2)
        elif isinstance(value, (list, tuple)):
            flat = [v for v in value if not isinstance(v, (Mapping, list, tuple))]
            joined = ", ".join(str(v) for v in flat)
            if not value:
                out(f"{pad}{label} -")
            elif len(flat) == len(value) and len(joined) <= 70:
                out(f"{pad}{label} {joined}")
            elif len(flat) == len(value):
                out(f"{pad}{key}:")
                for item in value:
                    out(f"{pad}  {item}")
            else:
                out(f"{pad}{key}:")
                for item in value:
                    if isinstance(item, Mapping):
                        _print_mapping(item, indent + 4)
                    else:
                        out(f"{pad}  - {item}")
        elif isinstance(value, str) and "\n" in value:
            out(f"{pad}{key}:")
            for line in value.splitlines():
                out(f"{pad}  {line}")
        else:
            out(f"{pad}{label} {value}")


def _dump(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str, sort_keys=False))


def _rows(rows: Iterable[Any]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


# -- omitted-value literals ---------------------------------------------------


def _is_omitted(value: str) -> bool:
    return value.strip().lower() in OMITTED_LITERALS


def vocabulary(module: str, name: str) -> Any:
    """An argparse `type` that checks a word against the module that owns it.

    `choices=` needs the list when the parser is built, which would mean
    importing that module on every `bb` invocation -- and the whole reason the
    heavy modules are imported inside their handlers is that `bb doctor` has to
    be able to report one of them as broken, which it cannot do if importing it
    is what kills the process. So the check happens when the value is parsed,
    against the one definition, instead of being a second copy here that drifts.

    A module that will not import refuses the word rather than passing it
    through: a vocabulary that cannot be checked has not been checked.
    """

    def check(value: str) -> str:
        word = str(value).strip().lower()
        try:
            words = tuple(getattr(importlib.import_module(f"bbh.{module}"), name))
        except (ImportError, AttributeError) as exc:
            raise argparse.ArgumentTypeError(
                f"cannot check {value!r} against bbh.{module}.{name} ({exc}), so it is "
                f"refused rather than accepted unchecked. Run: bb doctor"
            ) from exc
        if word not in words:
            raise argparse.ArgumentTypeError(f"{value!r} is not one of {', '.join(words)}")
        return word

    check.__name__ = f"{module}.{name}"
    return check


def _folded(value: str) -> str:
    """argparse `type` for the constrained filters.

    Applied before `choices`, so `--state GATED` lands and the Python-ish
    `--state None` reaches normalize_optional instead of dying in argparse.
    """
    return value.strip().lower()


def optional_dests(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> frozenset[str]:
    """Dests of every value THIS invocation may leave out.

    Derived from the parser rather than listed by hand, so an argument added
    later is covered without anyone remembering to. Required arguments, flags
    and anything with a real default are left alone: substituting None there
    would change behaviour rather than restore it.

    Scoped to the subcommand that actually parsed, which is what `args` is for.
    A dest is a name, not a place: `state` is both `bb finding list --state`, a
    filter that may be omitted, and `bb finding advance REF STATE`, which must
    be supplied; `target` is both `bb new --target` and `bb go TARGET`. Reading
    every subcommand's actions into one set of names made each name as
    permissive as its loosest use, so required values were blanked too -- `bb
    go nil www.example.com` hunted one target having been given two, and `bb
    scope check none` asked the compiler about nothing and crashed on the
    answer. Descending only the branch that parsed means each command is judged
    by its own arguments. The walk reads the chosen subcommand out of the
    namespace rather than naming the dests it holds them in, so a subcommand
    group added later is followed without being listed here.
    """
    found: set[str] = set()
    required: set[str] = set()
    current: argparse.ArgumentParser | None = parser
    while current is not None:
        descend: argparse.ArgumentParser | None = None
        for action in current._actions:
            if isinstance(action, argparse._SubParsersAction):
                chosen = getattr(args, action.dest, None)
                if chosen:
                    descend = action.choices.get(str(chosen))
                continue
            if action.dest in ("help", "version"):
                continue
            # Collected, not just skipped: `-e/--engagement` is optional on the
            # root parser, so a subcommand with a required argument of the same
            # name would otherwise be blanked by the root's permission.
            if action.required:
                required.add(action.dest)
                continue
            # REMAINDER is passed through verbatim (`bb req -d none` is a body).
            if action.nargs == argparse.REMAINDER:
                continue
            if action.default is not None and action.default is not argparse.SUPPRESS:
                continue
            if not isinstance(action, (argparse._StoreAction, argparse._AppendAction)):
                continue
            found.add(action.dest)
        current = descend
    return frozenset(found - required)


def json_mode(args: argparse.Namespace) -> bool:
    """Whether the handler will print JSON, including from behind a REMAINDER.

    `bb req` takes its arguments as REMAINDER, so a `--json` written after the
    subcommand never reaches the namespace and `main()` would bound a JSON
    document as text -- printing a sliced document that does not parse. Only
    `bb req show` is looked into: `bb req GET ... -d '--json'` is a body, not a
    flag, and reading it as one would change nothing except how an oversized
    document is sliced.
    """
    if bool(getattr(args, "json", False)):
        return True
    rest = getattr(args, "args", None)
    if not isinstance(rest, list) or not rest:
        return False
    return str(rest[0]).strip().lower() == REQ_SHOW and "--json" in rest


def normalize_optional(args: argparse.Namespace, dests: Iterable[str]) -> list[str]:
    """Blank out sentinel literals. Returns one note per argument it changed."""
    notes: list[str] = []
    for dest in sorted(dests):
        if not hasattr(args, dest):
            continue
        value = getattr(args, dest)
        if isinstance(value, str) and _is_omitted(value):
            setattr(args, dest, None)
            notes.append(
                f"{dest} was given as {value!r}; the literals "
                f"{', '.join(repr(v) for v in OMITTED_LITERALS)} are read as 'not given', so "
                f"that filter was NOT applied. Pass a real value or leave it out."
            )
        elif isinstance(value, list):
            kept = [v for v in value if not (isinstance(v, str) and _is_omitted(v))]
            if len(kept) != len(value):
                setattr(args, dest, kept or None)
                notes.append(
                    f"{dest}: {len(value) - len(kept)} value(s) were one of "
                    f"{', '.join(repr(v) for v in OMITTED_LITERALS)} and were read as "
                    f"'not given'."
                )
    return notes


# -- output bounding ----------------------------------------------------------


@dataclass
class Spill:
    """What a bounded command did not print, and where the rest of it went."""

    label: str
    lines: int
    bytes: int
    shown_lines: int
    dropped_lines: int
    dropped_bytes: int
    path: Path | None


def _clip_line(line: str) -> str:
    """One line, clipped so a single huge line cannot eat the whole budget."""
    raw = line.encode("utf-8", "replace")
    if len(raw) <= MAX_LINE_BYTES:
        return line
    return raw[:MAX_LINE_BYTES].decode("utf-8", "ignore") + " …[line clipped]"


def _spill_dir() -> Path:
    """raw/out/ in the active engagement, else a global fallback."""
    name = paths.active_engagement()
    root: Path
    if name and paths.engagement_dir(name).is_dir():
        try:
            root = _mod("secrets").harden_raw(name) / "out"
        except Exception:
            root = paths.engagement_dir(name) / "raw" / "out"
    else:
        root = paths.STATE_DIR / "out"
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    return root


def _write_spill(text: str) -> Path | None:
    """The full text on disk, verbatim, so `grep -n` line numbers are real."""
    try:
        path = _spill_dir() / f"{uuid.uuid4().hex}.txt"
        path.write_text(text, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return path
    except OSError:
        return None


def _spill_notice(spill: Spill, head_lines: int) -> list[str]:
    first_dropped = head_lines + 1
    lines = [
        "",
        f"···  {spill.dropped_lines:,} of {spill.lines:,} lines and {spill.dropped_bytes:,} "
        f"of {spill.bytes:,} bytes are NOT shown here ({spill.label} is bounded at "
        f"{MAX_OUT_LINES} lines / {MAX_OUT_BYTES // 1024} KiB)",
    ]
    if spill.path:
        lines += [
            f"···  the complete output is at {spill.path}",
            f"···    search it:  grep -n 'PATTERN' {spill.path}",
            f"···    read on:    sed -n '{first_dropped},{first_dropped + MAX_OUT_LINES - 1}p' "
            f"{spill.path}",
        ]
    else:
        lines.append(
            "···  the rest could NOT be written to a file, so it is gone; check the "
            "engagement tree with: bb status"
        )
    lines.append("")
    return lines


def bound_output(text: str, label: str) -> tuple[str, Spill | None]:
    """Head+tail slice of `text`, or `text` unchanged when it already fits."""
    total_bytes = len(text.encode("utf-8", "replace"))
    lines = text.splitlines()
    if len(lines) <= MAX_OUT_LINES and total_bytes <= MAX_OUT_BYTES:
        return text, None

    if len(lines) > MAX_OUT_LINES:
        head = [_clip_line(line) for line in lines[:HEAD_LINES]]
        tail = [_clip_line(line) for line in lines[-TAIL_LINES:]]
    else:
        head, tail = [_clip_line(line) for line in lines], []
    while len("\n".join(head + tail).encode("utf-8", "replace")) > MAX_OUT_BYTES:
        if tail and len(tail) >= len(head):
            tail.pop(0)
        elif head:
            head.pop()
        else:
            break

    kept = head + tail
    shown_bytes = len("\n".join(kept).encode("utf-8", "replace"))
    spill = Spill(
        label=label,
        lines=len(lines),
        bytes=total_bytes,
        shown_lines=len(kept),
        dropped_lines=len(lines) - len(kept),
        dropped_bytes=total_bytes - shown_bytes,
        path=_write_spill(text),
    )
    return "\n".join(head + _spill_notice(spill, len(head)) + tail), spill


def emit_bounded(text: str, label: str, *, json_mode: bool = False) -> Spill | None:
    """Print `text` within the bound, spilling the rest to a file."""
    shown, spill = bound_output(text, label)
    if spill is None:
        sys.stdout.write(text)
        return None
    if json_mode:
        # A sliced JSON document is not JSON. The envelope is valid, bounded,
        # and says where the document is.
        _dump(
            {
                "bounded": True,
                "command": spill.label,
                "lines": spill.lines,
                "bytes": spill.bytes,
                "dropped_lines": spill.dropped_lines,
                "dropped_bytes": spill.dropped_bytes,
                "spill": str(spill.path) if spill.path else None,
                "grep": f"grep -n 'PATTERN' {spill.path}" if spill.path else None,
                "note": (
                    f"the output exceeded {MAX_OUT_LINES} lines / {MAX_OUT_BYTES // 1024} KiB, "
                    "so the complete document is in the spill file rather than inline"
                ),
            }
        )
        return spill
    print(shown)
    return spill


@contextmanager
def bounded_output(label: str, *, json_mode: bool = False) -> Iterator[None]:
    """Capture a subcommand's stdout and emit it within the bound.

    stdout is swapped rather than every print site being rewritten, because
    `bb req` prints from bbh.http and the bound has to cover that too. The
    capture is emitted even when the handler raises: the output so far is
    context for the error that follows it on stderr.
    """
    buffer = io.StringIO()
    original = sys.stdout
    sys.stdout = buffer
    try:
        yield
    finally:
        sys.stdout = original
        captured = buffer.getvalue()
        if captured:
            emit_bounded(captured, label, json_mode=json_mode)


# -- lazy module access -------------------------------------------------------


def _mod(name: str) -> ModuleType:
    """Import a sibling module, turning a broken one into a readable error."""
    try:
        return importlib.import_module(f"bbh.{name}")
    except ImportError as exc:
        venv = paths.REPO / ".venv" / "bin" / "python"
        raise CliError(
            f"cannot load bbh.{name}: {exc}\n"
            f"If the module is missing, this build is incomplete: expected "
            f"{paths.REPO / 'bbh' / (name + '.py')}\n"
            f"If a third-party package is missing, install it into the harness venv:\n"
            f"  {venv} -m pip install requests pyyaml mitmproxy"
        ) from exc


# -- engagement resolution ----------------------------------------------------


def resolve_engagement(name: str | None, *, must_exist: bool = True) -> str:
    """Explicit argument, else the active engagement, else a remedy."""
    chosen = (name or "").strip() or (paths.active_engagement() or "")
    if not chosen:
        raise CliError(
            "no engagement given and none is active.\n"
            "  bb list                                  # engagements on this machine\n"
            "  bb use <engagement>                      # make one active\n"
            "  bb new <engagement> --program-url <url>  # create one"
        )
    if must_exist and not paths.scope_path(chosen).exists():
        known = paths.list_engagements()
        hint = ", ".join(known) if known else "none exist yet"
        raise CliError(
            f"engagement {chosen!r} has no scope.yaml at {paths.scope_path(chosen)}\n"
            f"known engagements: {hint}\n"
            f"  bb new {chosen} --program-url <url>"
        )
    # Downstream modules resolve the engagement themselves; pin them to the one
    # this invocation chose so -e and the positional name reach the subprocesses.
    os.environ["BBH_ENGAGEMENT"] = chosen
    return chosen


def _load_scope(name: str) -> Scope:
    lock = paths.lock_path(name)
    if not lock.exists():
        raise CliError(
            f"engagement {name!r} has no compiled scope at {lock}\n  bb scope compile {name}"
        )
    try:
        return Scope.from_lock_file(lock)
    except (ScopeError, OSError, ValueError) as exc:
        raise CliError(
            _with_remedy(f"scope lock for {name!r} is unusable: {exc}", f"bb scope compile {name}")
        ) from exc


def _open_store(name: str) -> Store:
    try:
        return Store(paths.db_path(name))
    except Exception as exc:
        db = paths.db_path(name)
        raise CliError(
            f"cannot open the store for {name!r} at {db}: {exc}\n"
            f"If the database is damaged, move it aside and let the harness rebuild it "
            f"(this discards recorded requests and findings):\n"
            f"  mv {db} {db}.broken"
        ) from exc


@dataclass
class ArmedState:
    """Whether an engagement may be touched right now, and for how much longer."""

    engagement: str
    compiled: bool
    armed: bool
    detail: str
    expires_at: str | None = None
    seconds_left: float | None = None

    @property
    def label(self) -> str:
        if not self.compiled:
            return "no scope"
        return "armed" if self.armed else "not armed"


def armed_state(name: str) -> ArmedState:
    lock = paths.lock_path(name)
    if not lock.exists():
        return ArmedState(name, False, False, f"scope not compiled; run: bb scope compile {name}")
    try:
        scope = Scope.from_lock_file(lock)
    except (ScopeError, OSError, ValueError) as exc:
        return ArmedState(
            name, False, False,
            _with_remedy(f"unusable lock: {exc}", f"run: bb scope compile {name}"),
        )
    problem = scope.authorization_error()
    if problem:
        return ArmedState(name, True, False, problem)
    expires = scope.authorization.get("expires_at")
    stamp = _parse_ts(expires)
    left = (stamp - datetime.now(timezone.utc)).total_seconds() if stamp else None
    detail = f"expires {expires}" + (f" (in {_fmt_duration(left)})" if left is not None else "")
    return ArmedState(name, True, True, detail, expires_at=expires, seconds_left=left)


# -- new / list / use / status ------------------------------------------------


def cmd_new(args: argparse.Namespace) -> int:
    engagement = _mod("engagement")
    name = args.name.strip()
    if paths.scope_path(name).exists():
        raise CliError(
            f"engagement {name!r} already exists at {paths.engagement_dir(name)}\n"
            f"  bb status {name}"
        )
    root = engagement.create(
        name,
        program_url=args.program_url,
        platform=args.platform,
        targets=tuple(args.target or ()),
    )
    # raw/ fills with captured bodies and phase transcripts; restrict it now,
    # while it is still empty, rather than after the first capture.
    _mod("secrets").harden_raw(name)
    if args.use:
        engagement.use(name)
    if args.json:
        _dump(
            {
                "engagement": name,
                "root": str(paths.engagement_dir(name)),
                "created": str(root),
                "scope": str(paths.scope_path(name)),
                "active": bool(args.use),
            }
        )
        return 0
    out(f"created engagement {name!r} at {paths.engagement_dir(name)}")
    if args.use:
        out("  it is now the active engagement")
    out("")
    out("next:")
    out(f"  $EDITOR {paths.scope_path(name)}   # list the in-scope assets")
    out(f"  bb scope compile {name}")
    out(f"  bb arm {name} --as '{os.environ.get('USER', 'you')}'")
    if not args.use:
        out(f"  bb use {name}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    active = paths.active_engagement()
    names = paths.list_engagements()
    states = [armed_state(n) for n in names]
    if args.json:
        _dump(
            {
                "active": active,
                "engagements": [
                    {**dataclasses.asdict(s), "active": s.engagement == active} for s in states
                ],
            }
        )
        return 0
    if not names:
        out(f"no engagements under {paths.ENGAGEMENTS}")
        out("  bb new <name> --program-url <url>")
        return 0
    rows = []
    for state in states:
        rows.append(
            [
                "*" if state.engagement == active else "",
                state.engagement,
                state.label,
                _shorten(state.detail, 70),
            ]
        )
    out(_table(("", "engagement", "state", "detail"), rows))
    if not active:
        out("")
        out("no active engagement; select one:  bb use <engagement>")
    return 0


def cmd_use(args: argparse.Namespace) -> int:
    engagement = _mod("engagement")
    name = resolve_engagement(args.name)
    engagement.use(name)
    state = armed_state(name)
    if args.json:
        _dump({"active": name, **dataclasses.asdict(state)})
        return 0
    out(f"active engagement: {name}  ({state.label}: {state.detail})")
    if not state.armed:
        out(f"  bb arm {name} --as '{os.environ.get('USER', 'you')}'")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    engagement = _mod("engagement")
    name = resolve_engagement(args.name or args.engagement)
    try:
        data = engagement.status(name)
    except (RuntimeError, OSError, ValueError) as exc:
        raise CliError(f"cannot read status for {name!r}: {exc}") from exc
    # Coverage is a line here because "what has nothing tested it" is the
    # question a status screen should answer and the angle ledger cannot. A
    # coverage computation that fails lands in `problems` rather than killing
    # the command: the rest of the status is still true, and an unsayable
    # coverage answer is itself worth printing.
    if isinstance(data, dict):
        try:
            with _open_store(name) as store:
                # The verdict is written to stand alone, so it labels itself;
                # under a field already called `coverage` that reads twice.
                data["coverage"] = (
                    _mod("coverage").verdict(store, engagement=name).removeprefix("coverage: ")
                )
        except (CliError, RuntimeError, sqlite3.Error, OSError) as exc:
            data.setdefault("problems", []).append(f"coverage could not be computed: {exc}")
        # `engagement.status` reports the store's own totals, which is the half
        # of the spend record that lives in the directory the agent is handed.
        # The budgets are enforced against the higher of the store and the
        # harness's ledger, so the operator's screen has to show that number
        # too -- otherwise `bb status` says $4 while `bb hunt` refuses at $25.
        # A gap between them is a stated problem, never silently absorbed.
        try:
            runner = _mod("runner")
            with _open_store(name) as store:
                spend = runner.spend_to_date(name, store)
            data["cost_usd"] = round(spend.cost_usd, 4)
            data["requests_counted"] = spend.requests
            data["request_budget"] = runner.request_budget(name)
            data.setdefault("problems", []).extend(spend.understated())
        except (CliError, RuntimeError, ScopeError, sqlite3.Error, OSError) as exc:
            data.setdefault("problems", []).append(
                f"spend to date could not be computed, so the figures above are the "
                f"store's own and may understate it: {exc}"
            )
    if args.json:
        _dump(data)
        return 0
    if isinstance(data, Mapping):
        _print_mapping(data)
    else:
        out(str(data))
    return 0


# -- scope --------------------------------------------------------------------


def cmd_scope_compile(args: argparse.Namespace) -> int:
    engagement = _mod("engagement")
    name = resolve_engagement(args.name or args.engagement)
    try:
        lock = engagement.compile_scope(name)
    except ScopeError as exc:
        raise CliError(
            f"scope.yaml for {name!r} is not valid: {exc}\n"
            f"  $EDITOR {paths.scope_path(name)}\n"
            f"  bb scope compile {name}"
        ) from exc
    except (OSError, ValueError) as exc:
        raise CliError(f"cannot compile scope for {name!r}: {exc}") from exc
    if args.json:
        _dump(lock)
        return 0
    out(f"compiled {paths.scope_path(name)} -> {paths.lock_path(name)}")
    out("")
    out(Scope(lock).summary())
    for line in program_constraint_caveats(lock):
        out(line)
    state = armed_state(name)
    out(f"authorization: {state.detail}")
    return 0


def program_constraint_caveats(lock: Mapping[str, Any]) -> list[str]:
    """What `program_constraints` does not yet reach, said where it is set.

    `bbh.http.effective_rules` is the only layer that applies them. The proxy
    addon and the guard read `scope.rules` directly -- the addon is stdlib-only
    and cannot import the clamp, and nothing has moved the arithmetic somewhere
    all three can reach it. An operator who copies a program's 0.5 rps into
    scope.yaml and watches the compiler echo it back will otherwise believe
    browser traffic is held to it. Printed here rather than warned about once
    in the README, because this is the moment the belief forms.
    """
    constraints = lock.get("program_constraints") or {}
    if not isinstance(constraints, Mapping) or not constraints:
        return []
    return [
        "",
        "note: program_constraints are applied by the sanctioned client (bb req, "
        "bbh.http.Session) and by nothing else in this build.",
        "      Traffic through `bb proxy` and the scanner rate check in the PreToolUse "
        "guard read rules.* unclamped, so set rules.* to the program's own",
        "      figures as well if you drive either of them.",
    ]


def cmd_scope_show(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.name or args.engagement)
    scope = _load_scope(name)
    if args.json:
        _dump(scope.lock)
        return 0
    out(scope.summary())
    out(f"authorization: {armed_state(name).detail}")
    return 0


def cmd_scope_check(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    scope = _load_scope(name)
    decisions = scope.decide_many(args.target)
    if args.json:
        _dump(
            [
                {"target": d.target, "allowed": d.allowed, "reason": d.reason, "rule": d.rule}
                for d in decisions
            ]
        )
    else:
        for decision in decisions:
            out(f"{'ALLOW' if decision.allowed else 'DENY '}  {decision.target}  {decision.reason}")
    return 0 if all(d.allowed for d in decisions) else 1


# -- arm / disarm -------------------------------------------------------------


def cmd_arm(args: argparse.Namespace) -> int:
    engagement = _mod("engagement")
    name = resolve_engagement(args.name or args.engagement)
    try:
        record = engagement.arm(
            name,
            attested_by=args.attested_by,
            hours=args.hours,
            policy_url=args.policy_url,
        )
    except (RuntimeError, ValueError, OSError) as exc:
        raise CliError(f"cannot arm {name!r}: {exc}") from exc
    state = armed_state(name)
    if args.json:
        _dump({"engagement": name, "attestation": record, **dataclasses.asdict(state)})
        return 0
    out(f"armed {name} as {args.attested_by!r}")
    out(f"  {state.detail}")
    out("")
    out("Recorded attestation:")
    out("  I confirm I am authorized to test the assets in this scope under")
    out(f"  {scope_program_url(name) or '<program_url>'}")
    out("")
    out(f"Every enforcement layer now reads this expiry. Stop early with: bb disarm {name}")
    return 0


def scope_program_url(name: str) -> str | None:
    try:
        return Scope.from_lock_file(paths.lock_path(name)).lock.get("program_url")
    except Exception:
        return None


def cmd_disarm(args: argparse.Namespace) -> int:
    engagement = _mod("engagement")
    name = resolve_engagement(args.name or args.engagement)
    engagement.disarm(name)
    if args.json:
        _dump({"engagement": name, "armed": False})
        return 0
    out(f"disarmed {name}")
    out("Every target is denied until you re-arm:")
    out(f"  bb arm {name} --as '{os.environ.get('USER', 'you')}'")
    return 0


# -- hunt ---------------------------------------------------------------------


def _number(event: Mapping[str, Any], keys: Sequence[str]) -> float | None:
    for key in keys:
        value = event.get(key)
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue
    return None


def _brief(event: Mapping[str, Any], width: int = 110) -> str:
    bits = [
        f"{k}={v}"
        for k, v in event.items()
        if k not in ("type", "event", "kind") and not isinstance(v, (Mapping, list, tuple))
    ]
    return _shorten(" ".join(bits), width)


@dataclass
class HuntPrinter:
    """Turns runner events into one readable line each, live.

    The runner owns the event vocabulary, so every lookup here is defensive: an
    unrecognised event must print as a plain line, not raise inside a hunt that
    has already spent money. On a terminal the running counters redraw in place;
    piped to a file they are emitted on a slow heartbeat instead.
    """

    json_mode: bool = False
    stream: TextIO = sys.stdout
    start: float = field(default_factory=time.monotonic)
    phase: str | None = None
    phase_start: float = field(default_factory=time.monotonic)
    tools: int = 0
    cost: float = 0.0
    findings: int = 0
    last_tool: str = ""

    def __post_init__(self) -> None:
        try:
            self.tty = bool(self.stream.isatty())
        except Exception:
            self.tty = False
        self._live = False
        self._last_beat = 0.0

    # -- output primitives ---------------------------------------------------

    def line(self, text: str) -> None:
        if self._live:
            self.stream.write("\r\x1b[K")
            self._live = False
        self.stream.write(f"[{_elapsed(self.start)}] {text}\n")
        self.stream.flush()

    def beat(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_beat < (2.0 if self.tty else 15.0):
            return
        self._last_beat = now
        body = (
            f"{self.phase or 'hunt'}  tools {self.tools}  "
            f"cost ${self.cost:.2f}  findings {self.findings}"
            + (f"  {self.last_tool}" if self.last_tool else "")
        )
        if self.tty:
            self.stream.write(f"\r\x1b[K        {body}")
            self.stream.flush()
            self._live = True
        else:
            self.line(f"  ..  {body}")

    def close(self) -> None:
        if self._live:
            self.stream.write("\r\x1b[K")
            self.stream.flush()
            self._live = False

    # -- the callback --------------------------------------------------------

    def __call__(self, event: Any) -> None:
        if not isinstance(event, Mapping):
            event = {"event": str(event)}
        if self.json_mode:
            self.stream.write(json.dumps(dict(event), default=str) + "\n")
            self.stream.flush()
            return

        kind = str(event.get("event") or event.get("type") or event.get("kind") or "event")
        key = kind.replace("-", "_").lower()
        phase = str(event.get("phase") or event.get("phase_key") or event.get("key") or "") or None

        # A total the emitter states outright always wins; a phase's own cost is
        # accumulated at phase_end instead, so the running figure stays a total.
        total = _number(event, ("total_cost_usd", "spent_usd"))
        if total is not None:
            self.cost = total
        found = _number(event, ("findings", "num_findings", "finding_count"))
        if found is not None:
            self.findings = int(found)

        if "phase" in key and ("start" in key or "begin" in key):
            self.phase = phase or self.phase
            self.phase_start = time.monotonic()
            self.tools = 0
            self.last_tool = ""
            budget = _number(event, ("budget_usd", "max_budget_usd"))
            attempt, of = event.get("attempt"), event.get("of")
            bits = [str(event.get("title") or "")]
            if attempt and of and int(of) > 1:
                bits.append(f"attempt {attempt}/{of}")
            if budget is not None:
                bits.append(f"budget ${budget:.2f}")
            elif "budget_usd" in event:
                # Emitted and null: the hunt has no dollar cap, and a line that
                # just omitted the figure would read as one the harness lost.
                # A key that is absent entirely still prints nothing.
                bits.append("budget uncapped")
            if event.get("max_turns"):
                bits.append(f"max {event['max_turns']} turns")
            self.line(f"START {self.phase or '?':<12} " + "  ".join(b for b in bits if b))
            return

        if "phase" in key and any(w in key for w in ("end", "done", "finish")):
            status = str(event.get("status") or ("error" if event.get("is_error") else "ok"))
            spent = _number(event, ("cost_usd",))
            if spent is not None:
                self.cost += spent
            turns = _number(event, ("turns", "num_turns"))
            bits = [f"${spent:.2f}" if spent is not None else f"${self.cost:.2f}",
                    _fmt_duration(time.monotonic() - self.phase_start)]
            if turns is not None:
                bits.insert(0, f"{int(turns)} turns")
            if event.get("denials"):
                bits.append(f"{event['denials']} guard denials")
            produced = event.get("produced")
            if isinstance(produced, Mapping) and produced:
                bits.append(", ".join(f"{k} {v}" for k, v in produced.items()))
            mark = {"ok": "OK   ", "skipped": "SKIP ", "timeout": "TIME "}.get(status, "FAIL ")
            self.line(f"{mark} {phase or self.phase or '?':<12} {status}  " + "  ".join(bits))
            for problem in _as_list(event.get("errors") or event.get("problems")):
                self.line(f"         - {_shorten(problem, 100)}")
            self.phase = None
            return

        if "tool_error" in key:
            self.beat()
            return

        if "tool" in key:
            self.tools += 1
            self.last_tool = _shorten(f"{event.get('tool') or ''} {event.get('detail') or ''}", 48)
            self.beat()
            return

        if "skip" in key:
            why = event.get("why") or event.get("reason") or "skipped"
            self.line(f"SKIP  {phase or '?':<12} {why}")
            return

        if "retry" in key:
            self.line(f"RETRY {phase or '?':<12} attempt {event.get('next_attempt', '?')}")
            for problem in _as_list(event.get("errors"))[:4]:
                self.line(f"         - {_shorten(problem, 100)}")
            return

        if key.startswith("assistant"):
            text = _shorten(event.get("text"), 100)
            if text:
                self.line(f'  "   {text}')
            return

        if "finding" in key:
            if found is None:
                self.findings += 1
            label = f"{event.get('uid') or event.get('ref') or ''} {event.get('title') or ''}"
            self.line(f"  +   finding {_shorten(label, 90)}".rstrip())
            return

        if key in ("unsandboxed", "denials_high", "governor_inert", "phase_inputs_missing"):
            detail = (
                event.get("detail") or event.get("missing") or event.get("turns") or kind
            )
            self.line(f"WARN  {phase or '':<12} {kind}: "
                      f"{_shorten('; '.join(str(d) for d in _as_list(detail)), 90)}")
            return

        if key == "hunt_start":
            cap = _number(event, ("budget_usd",))
            self.line(f"----  {len(_as_list(event.get('phases')))} phases  "
                      f"budget {_budget_label(cap)}  "
                      f"model {event.get('model')}  already spent ${self.cost:.2f}")
            return

        if key in ("hunt_stop", "hunt_end"):
            label = event.get("status") or event.get("why") or ""
            detail = event.get("reason") or event.get("detail") or ""
            at = f" at {event['at_phase']}" if event.get("at_phase") else ""
            total_cost = _number(event, ("cost_usd",))
            if total_cost is not None:
                self.cost = total_cost
            self.line(f"----  {label}{at}  {_shorten(detail, 80)}  ${self.cost:.2f}")
            return

        if "error" in key or "fail" in key:
            detail = event.get("error") or event.get("message") or event.get("reason") or kind
            self.line(f"FAIL  {phase or self.phase or '':<12} {_shorten(detail, 100)}")
            return

        self.line(f"  .   {kind}  {_brief(event)}".rstrip())


def _fail_running_phases(name: str, error: str) -> list[str]:
    """Mark phases the store still believes are running as failed."""
    touched: list[str] = []
    try:
        with _open_store(name) as store:
            for row in store.phase_runs():
                if row["status"] == "running":
                    store.finish_phase(int(row["id"]), "failed", error=error)
                    touched.append(str(row["phase"]))
    except Exception:
        return touched
    return touched


def _hunt_interrupted(name: str, printer: HuntPrinter) -> int:
    """Shared ctrl-c landing: nothing stays 'running', and say how to continue."""
    printer.close()
    touched = _fail_running_phases(name, "interrupted by operator (ctrl-c)")
    print("", file=sys.stderr)
    print("interrupted.", file=sys.stderr)
    if touched:
        print(f"recorded as failed: {', '.join(touched)}", file=sys.stderr)
    print(f"everything finished so far is on disk; pick up where it stopped:\n"
          f"  bb hunt {name} --resume", file=sys.stderr)
    return 130


def _stats_line(name: str) -> str:
    try:
        with _open_store(name) as store:
            stats = store.stats()
    except Exception as exc:
        return f"(store unreadable: {exc})"
    by_state = ", ".join(f"{v} {k}" for k, v in sorted(stats.get("by_state", {}).items()))
    return (
        f"requests {stats.get('requests', 0)}  findings {stats.get('findings', 0)}"
        f"{' (' + by_state + ')' if by_state else ''}  "
        f"evidence {stats.get('evidence', 0)}  angles {stats.get('angles', 0)}  "
        f"cost ${float(stats.get('cost_usd', 0.0)):.2f}"
    )


def _budget_label(budget: float | None) -> str:
    """How a dollar cap prints, including when the operator asked for none.

    A word rather than `$0.00` or `None`: the line that says what a run may
    spend is the last place a reader should have to decide whether a blank is
    a choice or a bug.
    """
    return "uncapped" if budget is None else f"${budget:.2f}"


def _turn_budget(runner: ModuleType, phases: list[str] | None) -> str:
    """The governor left when there is no dollar cap: N turns over M phases.

    Stated rather than implied. An operator who is told only that the money is
    uncapped has been told what stopped being true, not what still is.
    """
    selected = [p for p in runner.PHASES if not phases or p.key in phases]
    turns = sum(int(p.max_turns) for p in selected)
    return f"{turns} turns across {len(selected)} phase{'' if len(selected) == 1 else 's'}"


def _two_commands(command: str, first: str, why_first: str, second: str, why_second: str) -> str:
    """Two remedies under one refusal, with their comments in a column."""
    left, right = f"{command} {first}", f"{command} {second}"
    width = max(len(left), len(right))
    return f"  {left.ljust(width)}   # {why_first}\n  {right.ljust(width)}   # {why_second}"


def _hunt_budget(args: argparse.Namespace, command: str) -> float | None:
    """The dollar cap this invocation runs under, or None for no cap.

    `--budget-usd` parses to None rather than to the default figure, so that
    "the operator typed a number" and "nobody said anything" stay
    distinguishable here. That is what lets a `--no-budget --budget-usd 40`
    pair be named as the contradiction it is, instead of silently resolved by
    a precedence rule nobody would remember.

    `--budget-usd 0` stays a refusal and is not read as "no cap". Zero is what
    an unset shell variable expands to (`--budget-usd ${CAP:-0}`), and reading
    the commonest way to lose a number as the most expensive possible request
    is the opposite of failing closed. Asking for no cap has its own flag.
    """
    given = getattr(args, "budget_usd", None)
    uncapped = bool(getattr(args, "no_budget", False))
    if uncapped and given is not None:
        raise CliError(
            f"--no-budget and --budget-usd {given:g} were both given and they ask for "
            f"opposite things, so neither was applied.\n"
            + _two_commands(
                command,
                "--no-budget", "record the spend, never stop on it",
                f"--budget-usd {given:g}", "stop at that figure",
            )
        )
    if uncapped:
        return None
    if given is None:
        return HUNT_BUDGET_USD
    if not given > 0:
        raise CliError(
            f"--budget-usd is {given:g}; a cap has to be a positive number of dollars, "
            f"and 0 is what an unset shell variable expands to rather than a way to ask "
            f"for no cap, so nothing was started.\n"
            + _two_commands(
                command,
                "--no-budget", "no cap; the spend is still recorded",
                f"--budget-usd {HUNT_BUDGET_USD:g}", "cap it there",
            )
        )
    return float(given)


def _hunt_config(args: argparse.Namespace, name: str, phases: list[str] | None) -> Any:
    runner = _mod("runner")
    if args.deadline and _parse_ts(args.deadline) is None:
        raise CliError(
            f"--deadline {args.deadline!r} is not ISO8601. Use e.g. "
            "--deadline 2026-10-30T23:00:00Z"
        )
    # `bb phase` and `bb hunt` share this builder and take the same flags, so a
    # refusal has to name the one the operator actually typed -- sending a
    # `bb phase` caller to `bb hunt` changes what the command does, not just
    # the flag it carries.
    if getattr(args, "key", None):
        command = f"bb phase {args.key} {name}"
    else:
        command = f"bb hunt {name}"
    return runner.HuntConfig(
        engagement=name,
        phases=phases,
        budget_usd=_hunt_budget(args, command),
        deadline=args.deadline,
        model=args.model,
        effort=args.effort,
        resume=args.resume,
        dry_run=args.dry_run,
        max_retries=args.max_retries,
        unsandboxed=args.unsandboxed,
        allow_unpriced=args.allow_unpriced,
        # So the containment refusal can name the flag this caller can actually
        # act on. Absent for every parser but `bb go`'s hand-built namespace.
        invoked_as=getattr(args, "invoked_as", "bb hunt"),
    )


def _phase_keys(runner: ModuleType) -> list[str]:
    return [p.key for p in runner.PHASES]


def _phase_events(runner: ModuleType, name: str, printer: HuntPrinter) -> Any:
    """The runner's event sink for a single phase, or None if it takes none.

    run_hunt wires progress up for us; run_phase expects the sink itself. The
    signature is checked rather than assumed, because the fallback for guessing
    wrong would be a second paid run of the same phase.
    """
    try:
        if "events" not in inspect.signature(runner.run_phase).parameters:
            return None
        sink = getattr(runner, "_Events", None)
        if sink is None:
            return None
        log = paths.engagement_dir(name) / "raw" / "hunt-events.jsonl"
        return sink(log, printer, name)
    except Exception:
        return None


def cmd_hunt(args: argparse.Namespace) -> int:
    runner = _mod("runner")
    name = resolve_engagement(args.name or args.engagement)

    phases: list[str] | None = None
    if args.phases:
        phases = [p.strip() for p in str(args.phases).replace(" ", ",").split(",") if p.strip()]
        known = _phase_keys(runner)
        unknown = [p for p in phases if p not in known]
        if unknown:
            raise CliError(
                f"unknown phase(s): {', '.join(unknown)}\n"
                f"valid phases: {', '.join(known)}\n"
                f"  bb hunt {name} --phases {known[0]}"
            )

    cfg = _hunt_config(args, name, phases)
    printer = HuntPrinter(json_mode=args.json)

    if not args.json:
        state = armed_state(name)
        out(f"hunt {name}  budget {_budget_label(cfg.budget_usd)}  "
            f"model {args.model}  effort {args.effort}")
        out(f"  scope: {state.label} - {state.detail}")
        out(f"  phases: {', '.join(phases or _phase_keys(runner))}")
        if cfg.budget_usd is None:
            out(f"  budget: no dollar cap; the spend is recorded and reported, never "
                f"enforced.\n"
                f"          {_turn_budget(runner, phases)} and the deadline are what "
                f"stop this hunt.")
        if args.deadline:
            out(f"  deadline: {args.deadline}")
        if args.resume:
            out("  resume: phases that already finished ok will be skipped")
        if args.dry_run:
            out("  dry run: no subprocess will be started")
        out("")

    try:
        result = runner.run_hunt(cfg, on_event=printer)
    except KeyboardInterrupt:
        return _hunt_interrupted(name, printer)
    except RuntimeError as exc:
        printer.close()
        raise CliError(_with_remedy(str(exc), f"bb hunt {name} --resume")) from exc
    finally:
        printer.close()

    # run_hunt catches the interrupt itself and still returns its summary, so the
    # resume instructions hang off the status rather than off the exception.
    if str(_describe(result).get("status", "")) == "interrupted":
        return _hunt_interrupted(name, printer)

    if args.json:
        _dump(_describe(result))
    else:
        out("")
        out("hunt finished")
        shown = _describe(result)
        if "budget_usd" in shown and shown["budget_usd"] is None:
            # A bare `None` among a column of dollar figures reads as a value
            # the harness failed to collect. `cost_usd` beside it is the real
            # number and it is still there; this field is the cap, and there
            # was not one.
            shown["budget_usd"] = "uncapped"
        _print_mapping(shown, indent=2)
        out("")
        out(f"  {_stats_line(name)}")
        out(f"  reports:  {paths.engagement_dir(name) / 'reports'}")
        out(f"  handoffs: {paths.engagement_dir(name) / 'handoff'}")

    data = _describe(result)
    status = str(data.get("status", ""))
    if data.get("ok") is False or status not in HUNT_OK_STATUSES:
        if not args.json and status not in ("failed", "error"):
            # `budget`, `deadline`, `expired` and `disk` each print their own
            # reason inside the summary above; what the reader needs here is
            # that the plan did not finish, and the one command that continues
            # it once the reason is dealt with.
            out("")
            out(f"the hunt stopped short ({status}); phases after it never ran.")
            out(f"  bb hunt {name} --resume")
        return 1
    return 0


def cmd_phase(args: argparse.Namespace) -> int:
    runner = _mod("runner")
    name = resolve_engagement(args.name or args.engagement)
    known = {p.key: p for p in runner.PHASES}
    phase = known.get(args.key)
    if phase is None:
        raise CliError(
            f"unknown phase {args.key!r}\nvalid phases: {', '.join(known)}\n"
            f"  bb phase {next(iter(known))} {name}"
        )
    cfg = _hunt_config(args, name, [args.key])
    printer = HuntPrinter(json_mode=args.json)
    start = time.monotonic()
    if not args.json:
        out(f"phase {phase.key}  {getattr(phase, 'title', '')}  "
            f"budget {_budget_label(cfg.budget_usd)}  model {args.model}  "
            f"effort {args.effort}")
        if cfg.budget_usd is None:
            out(f"  budget: no dollar cap; the spend is recorded and reported, never "
                f"enforced. {phase.max_turns} turns is what stops this phase.")
    with _open_store(name) as store:
        # run_hunt honours dry_run itself; run_phase does not, and a dry run that
        # quietly spawned a paid subprocess would be the worst kind of surprise.
        if args.dry_run:
            prompt = runner.build_prompt(cfg, phase, store)
            if args.json:
                _dump({"phase": phase.key, "chars": len(prompt), "prompt": prompt})
            else:
                out(prompt)
                out("")
                out(f"[dry run] {len(prompt)} character prompt; no subprocess was started")
            return 0

        events = _phase_events(runner, name, printer)
        try:
            result = runner.run_phase(cfg, phase, store, **({"events": events} if events else {}))
        except KeyboardInterrupt:
            printer.close()
            touched = _fail_running_phases(name, "interrupted by operator (ctrl-c)")
            print(f"\ninterrupted; recorded as failed: {', '.join(touched) or 'nothing'}",
                  file=sys.stderr)
            print(f"  bb phase {phase.key} {name}", file=sys.stderr)
            return 130
        finally:
            printer.close()
    data = _describe(result)
    status = str(data.get("status", "ok"))
    if args.json:
        _dump(data)
    else:
        out(f"{'OK   ' if status in ('ok', 'skipped') else 'FAIL '} {phase.key}  {status}  "
            f"{_fmt_duration(time.monotonic() - start)}")
        _print_mapping(data, indent=2)
    return 0 if status in ("ok", "skipped") else 1


# -- go: a target in, a hunt running ------------------------------------------
#
# `bb go` is a composition, not a layer: every step below calls the function the
# matching subcommand calls, so a change to arming or to the hunt loop reaches
# it without anyone remembering it exists. What it adds is the two decisions the
# five-command sequence left to the operator -- which engagement a target
# belongs to, and how long the attestation has to last for the hunt to survive
# it -- and nothing else. Scope enforcement, the signed lock, the expiry, the
# budgets, the rate limit and the gates are all downstream of here and untouched.
#
# Four names in `bbh.engagement` are used here from behind their underscore:
# _NAME_RE, _yaml_scalar, _write_text and _write_authorization. That is a seam,
# not a decision -- the engagement module owns scope.yaml and should own these
# too (see the note on `go_arm`) -- but reaching in beats a second copy of the
# name rule, the YAML quoting or the authorization writer living here and
# drifting from the one that decides what the lock says.

# Anything that cannot appear in an engagement name collapses to a single dash,
# so one asset maps onto one directory however it was spelled.
_GO_UNSAFE_NAME = re.compile(r"[^a-z0-9._-]+")

# The top-level `in_scope:` key, capturing whatever else sits on its line.
_GO_IN_SCOPE_KEY = re.compile(r"^in_scope[ \t]*:(.*)$")

_GO_ISO = "%Y-%m-%dT%H:%M:%SZ"


def go_engagement_name(target: str) -> str:
    """The engagement a target belongs to, derived from the target alone.

    Derived rather than asked for, because the alternative is that `bb go
    '*.example.com'` run a second time starts a second engagement beside the
    first with none of its findings, evidence or request log in it.
    `scope.compile_rule` canonicalizes before the slug is built, which is what
    makes `*.example.com` and `example.com` agree: the wildcard is stripped by
    the compiler, not here.
    """
    try:
        rule = compile_rule(target)
    except ScopeError as exc:
        raise CliError(
            f"cannot derive an engagement name from {target!r}: it is not a usable scope "
            f"rule ({exc})\n"
            f"  bb go '*.example.com'                  # domain, wildcard, CIDR or URL prefix\n"
            f"  bb go {target!r} --name <engagement>   # or name the engagement yourself"
        ) from exc
    value = str(rule.get("value") or "")
    if rule.get("type") == "url_prefix":
        # The path is not part of the identity: https://x/api/ and https://x/admin/
        # are two slices of one program, not two engagements with separate stores.
        value = urlsplit(value).hostname or value
    name = _GO_UNSAFE_NAME.sub("-", value.lower()).strip("._-")[:64].rstrip("._-")
    # The name becomes a directory and bbh.engagement owns that rule. Read it
    # from there rather than restating it here; a build where it has been
    # renamed refuses rather than writing a name nothing else will accept.
    name_re = getattr(_mod("engagement"), "_NAME_RE", None)
    if name_re is None or not name_re.fullmatch(name):
        raise CliError(
            f"the engagement name derived from {target!r} is {name!r}, which is not a "
            f"usable directory name, so there is nowhere to put the engagement.\n"
            f"  bb go {target!r} --name <engagement>   # lowercase letters, digits and . _ -"
        )
    return name


def _go_identity(raw: Any) -> tuple[Any, ...] | None:
    """What makes two in_scope entries the same asset, or None if it does not compile.

    The note is deliberately left out of it: a target the operator already
    listed with a note of their own is the same target, and re-adding it would
    bury that note under a bare duplicate.
    """
    try:
        rule = compile_rule(raw)
    except ScopeError:
        return None
    return (rule["type"], rule["value"], rule.get("include_apex"))


def _go_splice_in_scope(text: str, targets: Sequence[str]) -> str:
    """Add in_scope entries to scope.yaml as text, leaving every other byte alone.

    A PyYAML round trip would be shorter and would throw away every comment in
    the file together with the operator's own exclusions, rules and
    program_constraints formatting; `engagement._splice_authorization` refuses
    the round trip for exactly that reason. A flow sequence on the key's own
    line, or a second top-level `in_scope:`, is refused rather than guessed at:
    which one YAML keeps is not something to be wrong about in the file that
    decides what may be touched.
    """
    engagement = _mod("engagement")
    lines = text.splitlines(keepends=True)
    hits = [(i, m) for i, m in ((i, _GO_IN_SCOPE_KEY.match(l)) for i, l in enumerate(lines))
            if m is not None]
    if not hits:
        raise CliError(
            "scope.yaml has no top-level `in_scope:` key, so there is nowhere to add a "
            "target and nothing would be testable.\n"
            '  add a line reading `in_scope:` with the assets indented under it, then:\n'
            "  bb scope compile <engagement>"
        )
    if len(hits) > 1:
        raise CliError(
            f"scope.yaml has {len(hits)} top-level `in_scope:` keys (lines "
            f"{', '.join(str(i + 1) for i, _ in hits)}); only one of them decides what is "
            "in scope and this command will not guess which.\n"
            "  delete the duplicates, leaving one `in_scope:` list, then:\n"
            "  bb scope compile <engagement>"
        )
    index, match = hits[0]
    if (match.group(1) or "").split("#", 1)[0].strip():
        raise CliError(
            f"scope.yaml writes in_scope inline ({lines[index].strip()!r}); a target can "
            "only be added to a block list, and rewriting the line would lose whatever "
            "formatting is around it.\n"
            "  rewrite it as a block list, one `- asset` per indented line, then re-run"
        )
    entries = "".join(f"  - {engagement._yaml_scalar(t)}\n" for t in targets)
    lines.insert(index + 1, entries)
    return "".join(lines)


def _go_current_rules(name: str) -> list[Any]:
    """The in_scope rules the engagement already has, read through the compiler.

    Recompiled first rather than read from whatever lock is lying there: an
    engagement made by `bb new --target ...` and never compiled has no lock at
    all, and diffing against nothing writes a second copy of every target it
    already lists. Going through the compiler also means this never needs a
    second YAML parser beside the one that decides what the lock says.

    A scope that does not compile yet falls back to the lock, because `bb new
    <name>` with no targets is the ordinary way to get one and the targets
    about to be added are what fixes it. The compile after the splice is the
    authority either way, and it puts the file back if it refuses.
    """
    try:
        return list(_mod("engagement").compile_scope(name).get("in_scope") or [])
    except (RuntimeError, OSError, ValueError):
        pass
    try:
        return list(Scope.from_lock_file(paths.lock_path(name)).lock.get("in_scope") or [])
    except (RuntimeError, OSError, ValueError):
        return []


def go_add_targets(name: str, targets: Sequence[str]) -> list[str]:
    """Add the targets an existing scope.yaml does not list yet. Returns the new ones.

    Verified by recompiling rather than by re-parsing: the compiler is what
    decides which assets the lock authorizes, so asking it is the only check
    that proves the splice meant what it said. A compile that refuses, or a
    target that does not come back out of it, puts scope.yaml back exactly as it
    was -- a half-widened boundary is the one outcome worth protecting against.
    """
    engagement = _mod("engagement")
    scope_file = paths.scope_path(name)
    try:
        original = scope_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(
            f"cannot read {scope_file}: {exc.strerror or exc}, so the targets cannot be "
            f"added and nothing would be testable.\n"
            f"  bb status {name}"
        ) from exc

    known = {_go_identity(entry) for entry in _go_current_rules(name)}
    wanted: list[str] = []
    for target in targets:
        identity = _go_identity(target)
        if identity is not None and identity not in known:
            known.add(identity)
            wanted.append(target)
    if not wanted:
        return []

    engagement._write_text(scope_file, _go_splice_in_scope(original, wanted))
    try:
        lock = engagement.compile_scope(name)
    except (RuntimeError, OSError, ValueError) as exc:
        engagement._write_text(scope_file, original)
        raise CliError(
            f"adding {', '.join(wanted)} to {scope_file} would stop it compiling, so the "
            f"file was put back exactly as it was and nothing was armed: {exc}"
        ) from exc
    present = {_go_identity(rule) for rule in lock.get("in_scope") or []}
    missing = [t for t in wanted if _go_identity(t) not in present]
    if missing:
        engagement._write_text(scope_file, original)
        raise CliError(
            f"{', '.join(missing)} did not read back out of {scope_file} after being added, "
            f"so the compiled scope would not have authorized the target you asked for. The "
            f"file was put back exactly as it was.\n"
            f"  $EDITOR {scope_file}   # add the target by hand under in_scope:\n"
            f"  bb scope compile {name}"
        )
    return wanted


def go_arm(
    name: str,
    *,
    attested_by: str,
    targets: Sequence[str],
    expires_at: datetime,
    policy_url: str | None,
) -> dict[str, Any]:
    """Record the attestation `bb go` can honestly make, and recompile the lock.

    `engagement.arm` is unreachable from here for two halves of one reason: its
    statement says a human read the program's policy page, and it refuses an
    engagement that has no program_url for that sentence to name. Neither is
    true of an operator who typed one command. So the attestation is built from
    the engagement module's own `Attestation` and written by its own writer --
    which splices the block in and re-reads it to prove it parsed as meant --
    with a statement that says exactly what was done and no more.

    bbh/engagement.py should grow `arm(..., statement=...)` so this can call it
    instead of reaching past the underscore; until it does, the shape of the
    record and the writing of it still live in one place.
    """
    engagement = _mod("engagement")
    listed = " ".join(shlex.quote(t) for t in targets)
    if len(listed) > GO_STATEMENT_TARGETS_MAX:
        listed = f"{shlex.quote(targets[0])} and {len(targets) - 1} more targets"
    template = GO_STATEMENT_WITH_POLICY if policy_url else GO_STATEMENT
    attestation = engagement.Attestation(
        attested_by=attested_by,
        attested_at=datetime.now(timezone.utc).strftime(_GO_ISO),
        expires_at=expires_at.strftime(_GO_ISO),
        policy_url=policy_url or None,
        statement=template.format(targets=listed, policy_url=policy_url),
    )
    engagement._write_authorization(name, attestation.render(), attestation.as_dict())
    lock = engagement.compile_scope(name)

    problem = Scope(lock).authorization_error()
    if problem:
        raise CliError(
            f"arming {name!r} did not take effect: {problem}\n"
            f"  $EDITOR {paths.scope_path(name)}   # leave authorization as `{{}}`\n"
            f"  bb go <target> --name {name}"
        )
    # Same record `bb arm` writes, so one chain carries every attestation this
    # machine has made however it was made; `via` is what tells them apart.
    audit_record(
        "arm",
        {
            "action": "arm",
            "engagement": name,
            "attested_by": attested_by,
            "expires_at": attestation.expires_at,
            "policy_url": policy_url,
            "statement": attestation.statement,
            "via": "bb go",
        },
    )
    return attestation.as_dict()


def _go_operator() -> str:
    """Who is running this command, for the attestation's `attested_by`."""
    for source in (
        lambda: os.environ.get("USER"),
        lambda: os.environ.get("LOGNAME"),
        getpass.getuser,
    ):
        try:
            who = str(source() or "").strip()
        except Exception:  # getpass.getuser() raises when there is no account for the uid
            continue
        if who:
            return who
    return ""


def _go_plan_lines(plan: Mapping[str, Any]) -> list[str]:
    """The plan, printed before anything happens rather than explained after."""
    verb = "reuse" if plan["reused"] else "create"
    budget = plan["budget_usd"]
    lines = [
        f"bb go -> engagement {plan['engagement']!r} ({verb})  {plan['root']}",
        f"  targets      {', '.join(plan['targets'])}",
    ]
    if budget is None:
        # The money stopped being the governor, so the line under it says what
        # took over rather than leaving "uncapped" to read as unbounded.
        lines.append(
            "  budget       uncapped — the spend is recorded and reported, never enforced"
        )
        lines.append(f"  bounded by   {plan['turn_budget']}, and the deadline below")
    else:
        lines.append(f"  budget       ${float(budget):.2f}")
    lines += [
        f"  hunt for     {plan['hours']:g}h, deadline {plan['deadline']}",
        f"  attestation  {plan['attested_by']}, expires {plan['expires_at']}"
        + (f", policy {plan['policy_url']}" if plan["policy_url"] else ", no policy page"),
        f"  model        {plan['model']}  effort {plan['effort']}",
    ]
    if plan["phases"]:
        lines.append(f"  phases       {plan['phases']}")
    if plan["resumed"]:
        lines.append("  resume       phases that already finished ok are not re-run")
    lines.append(
        "  containment  egress sandbox ON"
        if plan["sandbox"]
        else "  containment  no egress sandbox; the scope guard is the only barrier "
        "(--sandbox turns it on)"
    )
    lines.append(f"  output       {plan['root']}  (nothing is ever submitted anywhere)")
    return lines


def cmd_go(args: argparse.Namespace) -> int:
    """One command from a target to a running hunt: new, compile, arm, hunt.

    An engagement that already exists is reused and never rebuilt. It holds the
    findings, the evidence and the request log of every earlier run, so the only
    thing a re-run writes into its scope.yaml is a target it does not already
    list, and the hunt picks up where the last one stopped instead of paying for
    the phases that finished.

    The exit code is the hunt's, so a cron line or a wrapper can read it. A
    setup step that fails raises before the hunt starts, carrying its own
    message.
    """
    engagement = _mod("engagement")
    problems: list[tuple[str, str]] = []

    given = [str(t) for t in (args.target or [])]
    targets = [t.strip() for t in given if t.strip()]
    if not targets:
        raise CliError(
            "bb go needs at least one target. Nothing is inferred: a host nobody typed is "
            "a host nobody is authorized to touch.\n"
            "  bb go '*.example.com'"
        )
    # A blank argument among real ones is an unset shell variable, not a target
    # the operator decided to leave out. Dropping it quietly would arm a scope
    # narrower than the one that was typed and hunt it anyway, under an
    # engagement named after whichever target happened to survive.
    blank = len(given) - len(targets)
    if blank:
        problems.append((
            f"{blank} of the {len(given)} targets given {'is' if blank == 1 else 'are'} "
            f"empty, so the hunt would have run against the other "
            f"{len(targets)} as if that is what was asked for",
            f"bb go {' '.join(shlex.quote(t) for t in targets)}   "
            f"# drop the empty argument, or supply the host it should have held",
        ))
    # The name is derived from the first target, so a first target that does not
    # compile has to stop the derivation as well as being reported.
    first_ok = True
    for position, target in enumerate(targets):
        # `none` and `nil` are what a model writes where it means "no value",
        # and both are syntactically valid single-label hosts, so the compiler
        # would accept either and hunt it. Refused rather than dropped: a
        # dropped target leaves the other targets running under an engagement
        # the operator did not ask for, which is the one outcome here that
        # spends money and sends traffic without being noticed.
        if _is_omitted(target):
            first_ok = first_ok and position != 0
            problems.append((
                f"target {target!r} is one of {', '.join(repr(v) for v in OMITTED_CHOICES)}, "
                f"which is what a caller writes where it means 'no value', so it is not read "
                f"as a host",
                f"bb go '*.example.com'\n"
                f"         bb go https://{target.strip().lower()}/   "
                f"# if a host really is named that, say so as a URL prefix",
            ))
            continue
        try:
            compile_rule(target)
        except ScopeError as exc:
            first_ok = first_ok and position != 0
            problems.append((
                f"target {target!r} is not a usable scope rule ({exc}), so it cannot be "
                f"written into the scope and would not be testable",
                "targets are domains, *.wildcards, CIDRs or https:// URL prefixes:\n"
                "         bb go '*.example.com' 198.51.100.0/24 https://www.example.com/api/",
            ))

    name = str(getattr(args, "name", None) or "").strip()
    name_re = getattr(engagement, "_NAME_RE", None)
    if name and (name_re is None or not name_re.fullmatch(name)):
        problems.append((
            f"--name {name!r} is not a usable engagement name, and the name becomes a "
            f"directory under {paths.ENGAGEMENTS}",
            "bb go '*.example.com' --name example-com   # lowercase, digits and . _ -",
        ))
        name = ""
    elif not name and first_ok:
        try:
            name = go_engagement_name(targets[0])
        except CliError as exc:
            problems.append((str(exc).splitlines()[0], f"bb go {targets[0]!r} --name <name>"))

    selected = str(getattr(args, "engagement", None) or "").strip()
    if selected and name and selected != name:
        problems.append((
            f"-e {selected!r} names a different engagement from {name!r}, which is the one "
            f"this target belongs to; bb go derives its engagement from the target",
            f"bb go {targets[0]!r} --name {selected}",
        ))

    margin = GO_ARM_MARGIN_HOURS
    max_hours = float(engagement.MAX_ARM_HOURS) - margin
    try:
        hours = float(args.hours)
    except (TypeError, ValueError):
        hours = -1.0
    if not 0 < hours <= max_hours:
        problems.append((
            f"--hours is {args.hours!r}; it has to be more than 0 and at most {max_hours:g}, "
            f"because the attestation is armed for the hunt plus {margin:g}h of margin and "
            f"an attestation is capped at {engagement.MAX_ARM_HOURS}h",
            f"bb go <target> --hours {GO_HOURS:g}",
        ))
    # No cap unless one is asked for: `bb go` is the path that exists so a
    # target can be handed over and left, and a dollar figure is one more thing
    # to stop and decide. What a phase costs is still measured and recorded; it
    # is the turn caps and the deadline that stop the hunt. A number that was
    # typed and cannot be read is still a refusal -- an unparseable cap must
    # never arrive here as "none".
    budget: float | None = None
    if args.budget_usd is not None:
        try:
            budget = float(args.budget_usd)
        except (TypeError, ValueError):
            budget = -1.0
        if getattr(args, "no_budget", False):
            # `--no-budget` only says the default out loud here, so it exists
            # to be writable in a script and to catch this pair. Either
            # precedence rule silently discards something that was typed.
            problems.append((
                f"--no-budget and --budget-usd {budget:g} were both given and they ask "
                f"for opposite things, so neither was applied",
                f"bb go <target> --no-budget   # the default; record the spend, never stop\n"
                f"         bb go <target> --budget-usd {budget:g}   # stop at that figure",
            ))
            budget = None
        elif not budget > 0:
            problems.append((
                f"--budget-usd is {args.budget_usd!r}; a cap has to be a positive number "
                f"of dollars, and 0 is what an unset shell variable expands to rather "
                f"than a way to ask for no cap (which is already the default here)",
                f"bb go <target>   # no cap; the spend is still recorded\n"
                f"         bb go <target> --budget-usd {HUNT_BUDGET_USD:g}   # cap it there",
            ))

    if not str(args.model or "").strip():
        problems.append((
            f"--model is {args.model!r}; the hunt has no model to spend the budget on",
            f"bb go <target> --model {GO_MODEL}",
        ))
    # Checked here rather than left to `cmd_hunt`, which validates the same list
    # but only after this command has already created and armed an engagement:
    # a typo in --phases should not leave an armed engagement behind it.
    phases = [p.strip() for p in str(args.phases or "").replace(" ", ",").split(",") if p.strip()]
    if phases:
        known = _phase_keys(_mod("runner"))
        unknown = [p for p in phases if p not in known]
        if unknown:
            problems.append((
                f"unknown phase(s) {', '.join(unknown)}; the hunt would refuse after the "
                f"engagement had been created and armed",
                f"valid phases: {', '.join(known)}\n"
                f"         bb go <target> --phases {known[0]}",
            ))

    who = str(getattr(args, "attested_by", None) or "").strip() or _go_operator()
    if not who or any(ord(ch) < 32 for ch in who):
        problems.append((
            "there is no single-line name to record as having asserted this authorization, "
            "and the harness will not attest on its own behalf",
            "bb go <target> --as '<your name>'",
        ))
    policy = str(getattr(args, "program_url", None) or "").strip()
    if any(ord(ch) < 32 for ch in policy):
        problems.append((
            "--program-url must be a single line of plain text; it is written straight "
            "into scope.yaml and quoted back in the attestation",
            "bb go <target> --program-url https://hackerone.com/<program>",
        ))

    if problems:
        detail = "\n".join(f"  - {what}\n    fix: {how}" for what, how in problems)
        raise CliError(
            f"bb go cannot start:\n{detail}\n"
            f"Then retry: bb go {' '.join(shlex.quote(t) for t in targets)}"
        )

    reused = paths.scope_path(name).exists()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    deadline = now + timedelta(hours=hours)
    expires = deadline + timedelta(hours=margin)
    # An engagement the operator already gave a policy page keeps pointing at
    # it; `--program-url` is how a new one gets one. Neither is invented here.
    policy = policy or (scope_program_url(name) if reused else None) or None
    plan: dict[str, Any] = {
        "engagement": name,
        "root": str(paths.engagement_dir(name)),
        "reused": reused,
        "targets": targets,
        "budget_usd": None if budget is None else round(budget, 4),
        # What governs the run once the money does not. Carried in the plan
        # rather than worked out by the printer, so the `--json` caller reading
        # an uncapped plan can see the same bound the printed one states.
        "turn_budget": _turn_budget(_mod("runner"), phases or None),
        "hours": hours,
        "deadline": deadline.strftime(_GO_ISO),
        "arm_hours": round(hours + margin, 4),
        "expires_at": expires.strftime(_GO_ISO),
        "attested_by": who,
        "policy_url": policy,
        "model": args.model,
        "effort": args.effort,
        "phases": args.phases or None,
        "resumed": reused,
        "sandbox": bool(args.sandbox),
        "dry_run": bool(args.dry_run),
    }

    if args.dry_run:
        if args.json:
            _dump(plan)
        else:
            for line in _go_plan_lines(plan):
                out(line)
            out("")
            out("dry run: nothing was created, compiled, armed or started.")
        return 0

    # A --json caller gets one parseable document from the hunt, so the plan
    # goes to stderr rather than in front of it.
    for line in _go_plan_lines(plan):
        if args.json:
            print(line, file=sys.stderr)
        else:
            out(line)
    if not args.json:
        out("")
    # The plan is only "before anything happens" if it has actually left the
    # process. Redirected to a file -- which is how an unattended hunt is run --
    # stdout is block-buffered while stderr is not, so without this the first
    # thing in the log is whatever refusal came next and the plan surfaces
    # thousands of lines later, if at all. An operator reading a log to find out
    # which domain they armed should not have to scroll for it.
    _flush_streams()

    if not reused:
        engagement.create(
            name,
            program_url=args.program_url,
            platform=args.platform,
            targets=targets,
        )
    # raw/ fills with captured bodies and phase transcripts; `bb new` restricts
    # it while it is still empty and a reused engagement is re-checked cheaply.
    _mod("secrets").harden_raw(name)
    # Downstream modules and the phase subprocesses resolve the engagement from
    # the environment. Pin it to the one this command derived before anything
    # reads it, including engagement.use(), which refuses to disagree with it.
    os.environ["BBH_ENGAGEMENT"] = name
    engagement.use(name)

    added = go_add_targets(name, targets) if reused else []
    try:
        lock = engagement.compile_scope(name)
    except (RuntimeError, OSError, ValueError) as exc:
        raise CliError(
            f"scope.yaml for {name!r} does not compile, so nothing was armed: {exc}\n"
            f"  $EDITOR {paths.scope_path(name)}\n"
            f"  bb scope compile {name}"
        ) from exc

    if not args.json:
        note = f", added {', '.join(added)}" if added else ""
        out(
            f"{'reusing' if reused else 'created'} {name}: "
            f"{len(lock.get('in_scope') or [])} in-scope rule(s){note}"
        )
    go_arm(name, attested_by=who, targets=targets, expires_at=expires, policy_url=policy)
    if not args.json:
        out(f"armed as {who!r} until {plan['expires_at']}")
        out("")

    hunt_args = argparse.Namespace(
        name=name,
        engagement=name,
        phases=args.phases,
        # `budget` is already resolved, so `no_budget` carries the decision
        # rather than letting `_hunt_budget` read a None as "nobody said" and
        # reinstate the `bb hunt` default under a caller who dropped it.
        budget_usd=budget,
        no_budget=budget is None,
        deadline=plan["deadline"],
        model=args.model,
        effort=args.effort,
        max_retries=args.max_retries,
        resume=reused,
        dry_run=False,
        unsandboxed=not args.sandbox,
        allow_unpriced=args.allow_unpriced,
        json=args.json,
        invoked_as="bb go",
    )
    return cmd_hunt(hunt_args)


# -- req ----------------------------------------------------------------------


def cmd_req(args: argparse.Namespace) -> int:
    http = _mod("http")
    name = resolve_engagement(args.engagement)
    try:
        # Response bodies land under raw/; restrict it before the first one does.
        _mod("secrets").harden_raw(name)
    except (CliError, RuntimeError) as exc:
        print(f"bb req: {exc}", file=sys.stderr)
    argv = list(args.args or [])
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        raise CliError(
            "bb req needs a method and a URL:\n"
            "  bb req GET https://target/path\n"
            "  bb req POST https://target/api -H 'Content-Type: application/json' -d @body.json\n"
            "  bb req show <id> --grep PATTERN   # read a recorded body back"
        )
    # `show` is a reader, not a request, and it is dispatched here rather than
    # as a subparser because `bb req`'s first word is an HTTP method: a
    # subparser group would reject `GET` as an invalid choice. There is no HTTP
    # method named SHOW, so the word is unambiguous.
    if argv[0].strip().lower() == REQ_SHOW:
        return cmd_req_show(argv[1:], args)
    return int(http.cli_req(argv) or 0)


# -- findings -----------------------------------------------------------------


def _next_uid(store: Store) -> str:
    n = len(store.list_findings()) + 1
    while store.get_finding(f"F-{n:03d}") is not None:
        n += 1
    return f"F-{n:03d}"


def cmd_finding_add(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        uid = args.uid or _next_uid(store)
        if store.get_finding(uid) is not None:
            raise CliError(f"finding {uid!r} already exists in {name}\n  bb finding show {uid}")
        store.add_finding(
            uid,
            args.title,
            args.vuln_class,
            phase_found=args.phase,
            host=args.host,
            endpoint=args.endpoint,
            severity=args.severity,
            summary=args.summary,
            impact=args.impact,
            repro=args.repro,
            remediation=args.remediation,
            dedup_key=args.dedup_key,
        )
        row = store.get_finding(uid)
    if args.json:
        _dump(dict(row) if row else {"uid": uid})
        return 0
    out(f"added {uid}  {args.vuln_class}  {args.title}")
    out(f"  bb evidence add {uid} request --request-id <id>")
    out(f"  bb finding show {uid}")
    return 0


def _search_findings(store: Store, query: str, limit: int) -> list[Any]:
    """store.search_findings, with an FTS5 syntax error turned into a usable message.

    A model searching prose writes `can't read other users' invoices`, which
    FTS5 rejects on the apostrophe. Retrying it as a quoted phrase is what was
    meant; only a query that fails both ways is an error worth reporting.
    """
    try:
        return store.search_findings(query, limit)
    except sqlite3.OperationalError:
        pass
    phrase = '"' + query.replace('"', '""') + '"'
    try:
        return store.search_findings(phrase, limit)
    except sqlite3.OperationalError as exc:
        raise CliError(
            f"--search {query!r} is not a usable full-text query ({exc}). The syntax is "
            f"FTS5: bare words, AND / OR / NOT in capitals, \"a quoted phrase\", prefix*.\n"
            f"  bb finding list --search 'invoice OR billing'\n"
            f"  bb finding list                              # everything, unfiltered"
        ) from exc


def cmd_finding_list(args: argparse.Namespace) -> int:
    name = resolve_engagement(getattr(args, "name", None) or args.engagement)
    limit = max(1, int(getattr(args, "limit", 25) or 25))
    with _open_store(name) as store:
        if args.query:
            rows = _search_findings(store, args.query, limit)
            # Both filters at once: search decides the candidates, state narrows
            # them. Honouring only one of two given filters is a silent lie.
            if args.state:
                rows = [r for r in rows if r["state"] == args.state]
        else:
            rows = store.list_findings(args.state)
    if args.json:
        _dump(_rows(rows))
        return 0
    if not rows:
        applied = [f"--search {args.query!r}" if args.query else "",
                   f"--state {args.state}" if args.state else ""]
        shown = ", ".join(a for a in applied if a)
        out(f"no findings in {name}" + (f" matching {shown}" if shown else ""))
        if shown:
            out("  bb finding list        # everything recorded, unfiltered")
        return 0
    out(
        _table(
            ("uid", "state", "severity", "class", "host", "title"),
            [
                [r["uid"], r["state"], r["severity"] or "-", r["vuln_class"], r["host"] or "-",
                 _shorten(r["title"], 60)]
                for r in rows
            ],
        )
    )
    return 0


def cmd_finding_show(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        row = store.get_finding(args.ref)
        if row is None:
            raise CliError(f"no finding {args.ref!r} in {name}\n  bb finding list")
        evidence = store.evidence_for(args.ref)
        gates = store.gates_for(args.ref)
        problems = store.verify_evidence(args.ref)
    if args.json:
        _dump(
            {
                "finding": dict(row),
                "evidence": _rows(evidence),
                "gates": _rows(gates),
                "integrity": problems,
            }
        )
        return 0

    out(f"{row['uid']}  {row['vuln_class']}  state={row['state']}  "
        f"severity={row['severity'] or 'unset'}")
    # `blocked_reason` and `unblock_condition` are shown because a block that
    # does not say what clears it is a dead end: CONTRACT v2 item 6 requires the
    # condition, the store records it, and a refusal pointing an agent at this
    # command was pointing it at a screen that did not print it.
    for field_name in ("title", "host", "endpoint", "cvss_vector", "frozen_sha256",
                       "dedup_key", "phase_found", "ts_created", "ts_updated",
                       "reject_reason", "blocked_from", "blocked_reason",
                       "unblock_condition"):
        if row[field_name]:
            out(f"  {field_name + ':':<19} {row[field_name]}")
    for block in ("summary", "impact", "repro", "remediation"):
        if row[block]:
            out("")
            out(f"{block}:")
            for line in str(row[block]).splitlines():
                out(f"  {line}")

    out("")
    if evidence:
        root = paths.engagement_dir(name)
        out(f"evidence ({len(evidence)}):")
        for ev in evidence:
            digest = f"sha256:{ev['sha256'][:12]}" if ev["sha256"] else "-"
            where = (
                _rel(ev["path"], root)
                if ev["path"]
                else (f"request #{ev['request_id']}" if ev["request_id"] else "-")
            )
            out(f"  {ev['id']:<4} {ev['kind']:<11} {where}  {digest}  {_fmt_bytes(ev['bytes'])}")
            if ev["caption"]:
                out(f"       {_shorten(ev['caption'], 90)}")
    else:
        out("evidence: none. A finding without artifacts cannot pass the gates.")
        out(f"  bb evidence add {row['uid']} request --request-id <id>")

    if gates:
        out("")
        out("gates:")
        for g in gates:
            # `waived`, never `pass`, for a requirement someone stood down; the
            # column is six wide because that is how long the third word is.
            out(f"  {_gate_verdict(g):<6} {g['gate']:<32} {_shorten(g['rationale'], 60)}")
    if problems:
        out("")
        out("INTEGRITY PROBLEMS:")
        for problem in problems:
            out(f"  {problem}")
    return 0


def _severity_from_vector(vector: str) -> tuple[str, float]:
    """(label, base score) for a CVSS v3.1 vector, or a CliError naming the fault."""
    cvss = _mod("cvss")
    try:
        score = cvss.base_score(vector)
        return cvss.severity_label(score), score
    except ValueError as exc:  # CvssError
        raise CliError(
            f"--cvss {vector!r} is not a usable CVSS v3.1 vector: {exc}\n"
            f"  bb finding set <ref> --cvss '{cvss.EXAMPLE_VECTOR}'\n"
            "The eight base metrics are required; temporal and environmental metrics are "
            "ignored. Severity is computed from the vector, so it is not asserted by hand."
        ) from exc


def cmd_finding_set(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    derived: tuple[str, float] | None = None
    severity = args.severity
    vector = args.cvss_vector
    if vector:
        # Severity is derived, never asserted: gate_severity_derived recomputes
        # from the vector and fails on a mismatch, so storing a vector without
        # the label it implies would build a finding that cannot pass its own
        # gate. Free-text --severity is still accepted on its own, for the
        # info/low findings the contract allows it for.
        derived = _severity_from_vector(vector)
        if severity and severity != derived[0]:
            raise CliError(
                f"--severity {severity!r} contradicts --cvss {vector!r}, which scores "
                f"{derived[1]:.1f} ({derived[0]}). Severity is computed from the vector, so "
                "pass one or the other:\n"
                f"  bb finding set {args.ref} --cvss '{vector}'\n"
                f"  bb finding set {args.ref} --severity {derived[0]}"
            )
        severity = derived[0]
    fields = {
        k: v
        for k, v in {
            "title": args.title,
            "vuln_class": args.vuln_class,
            "host": args.host,
            "endpoint": args.endpoint,
            "severity": severity,
            "cvss_vector": vector,
            "summary": args.summary,
            "impact": args.impact,
            "repro": args.repro,
            "remediation": args.remediation,
            "dedup_key": args.dedup_key,
            "counterevidence": args.counterevidence,
            "confidence": args.confidence,
            "confidence_rationale": args.confidence_rationale,
            "severity_change_conditions": args.severity_change_conditions,
            "delivery": args.delivery,
        }.items()
        if v is not None
    }
    if not fields:
        raise CliError(
            "nothing to set. Pass at least one field, e.g.\n"
            f"  bb finding set {args.ref} --cvss 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' "
            f"--impact 'reads any tenant order'"
        )
    with _open_store(name) as store:
        store.update_finding(args.ref, **fields)
        row = store.get_finding(args.ref)
    if args.json:
        _dump(dict(row) if row else {})
        return 0
    out(f"updated {row['uid']}: {', '.join(sorted(fields))}")
    if derived:
        out(f"  severity {derived[0]} computed from the vector (base score {derived[1]:.1f})")
    return 0


def cmd_finding_advance(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        store.advance(
            args.ref, args.state, args.reason,
            unblock_condition=getattr(args, "unblock_condition", None),
        )
        row = store.get_finding(args.ref)
    if args.json:
        _dump(dict(row) if row else {})
        return 0
    out(f"{row['uid']} -> {row['state']}")
    if row["state"] == "blocked" and not row["unblock_condition"]:
        out(f"  no unblock condition is recorded, so nothing says what would resume it:\n"
            f"  bb finding advance {row['uid']} blocked --reason '<what stopped you>' "
            f"--unblock-condition '<what would clear it>'")
    elif row["unblock_condition"]:
        out(f"  clears when: {row['unblock_condition']}")
    return 0


def cmd_finding_freeze(args: argparse.Namespace) -> int:
    """Pin the claim 06-verify is briefed with, or check that it still holds.

    `gate_frozen_claim_intact` recomputes this, so the pin is not a record
    nobody reads: a claim edited after the independent pass agreed with it
    blocks instead of shipping.
    """
    runner = _mod("runner")
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        if getattr(args, "check", False):
            problems = runner.frozen_claim_problems(store, args.ref)
            if args.json:
                _dump({"ref": args.ref, "intact": not problems, "problems": problems})
            else:
                for problem in problems:
                    out(problem)
                if not problems:
                    out(f"{args.ref}: the claim still matches what was pinned")
            return 1 if problems else 0

        digest = runner.freeze_finding(store, args.ref)
        row = store.get_finding(args.ref)
    uid = str(row["uid"])
    path = runner.frozen_path(name, uid)
    if args.json:
        _dump({"uid": uid, "sha256": digest, "path": str(path),
               "fields": list(runner.FROZEN_CLAIM_FIELDS)})
        return 0
    out(f"pinned {uid}  sha256:{digest}")
    out(f"  {path}")
    out(f"  pinned fields: {', '.join(runner.FROZEN_CLAIM_FIELDS)}")
    out("  everything else -- severity, confidence, summary, impact -- is withheld from "
        "06-verify and is not covered by this digest")
    return 0


def cmd_finding_merge(args: argparse.Namespace) -> int:
    """Collapse one finding into another: one bug, one submission, one record."""
    triage = _mod("triage")
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        result = triage.merge_findings(store, args.ref, args.into, reason=args.reason)
    if args.json:
        _dump(dataclasses.asdict(result))
        return 0
    out(f"merged {result.duplicate_uid} into {result.canonical_uid} ({result.relation})")
    out(f"  {result.why}")
    out(f"  reason recorded: {result.reason}")
    for note in result.notes:
        out(f"  note: {note}")
    out(f"  bb finding show {result.canonical_uid}")
    return 0


def _dedupe_pair_lines(pair: Any) -> list[str]:
    lines = [f"  {pair.relation:<10} {pair.other_uid} ({pair.other_state})  {pair.why}"]
    if pair.verdict:
        lines.append(
            f"             adjudicated {pair.verdict} by {pair.source or 'unknown'}"
            f"{': ' + pair.reason if pair.reason else ''}"
        )
    else:
        lines.append("             nothing has adjudicated this pair yet")
    return lines


def cmd_finding_dedupe(args: argparse.Namespace) -> int:
    """Show, adjudicate or override the harness's own duplicate comparison.

    Exit 1 while a pair is unresolved or a duplicate stands, the same shape as
    `bb gate`: an unadjudicated pair is a measurement nobody took, and the gate
    blocks on it.
    """
    triage = _mod("triage")
    name = resolve_engagement(args.engagement)
    verdict = getattr(args, "verdict", None)
    override = getattr(args, "not_duplicate_because", None)
    against = getattr(args, "against", None)

    if verdict and override:
        raise CliError(
            "--verdict and --not-duplicate-because are two different acts: one records a "
            "judge's answer, the other an operator standing the comparison down by hand. "
            "Pick one:\n"
            f"  bb finding dedupe {args.ref} --against <uid> --verdict distinct "
            "--because '<why they are two bugs>'\n"
            f"  bb finding dedupe {args.ref} --not-duplicate-because '<why>'"
        )
    if verdict and not getattr(args, "because", None):
        raise CliError(
            f"--verdict {verdict} needs --because: a verdict with no reason cannot be "
            "disagreed with, and only a reasoned `distinct` lets both findings ship.\n"
            f"  bb finding dedupe {args.ref} --against <uid> --verdict {verdict} "
            "--because '<the mechanical difference>'"
        )
    if verdict and not against:
        raise CliError(
            "--verdict needs --against <uid>: a verdict is about one pair.\n"
            f"  bb finding dedupe {args.ref}        # which pairs are ambiguous"
        )

    with _open_store(name) as store:
        if getattr(args, "write_key", False):
            digest = triage.refresh_dedup_key(store, args.ref)
            if args.json:
                _dump({"ref": args.ref, "dedup_key": digest})
            else:
                out(digest)
            return 0
        if verdict:
            record = triage.record_dedupe_verdict(
                store, args.ref, against, verdict,
                reason=args.because, source=getattr(args, "source", None) or "judge",
            )
            if args.json:
                _dump(dataclasses.asdict(record))
            else:
                out(f"{record.uid} vs {record.other_uid}: {record.verdict} "
                    f"({record.source}) -- {record.reason}")
                if record.verdict == triage.CLEARING_VERDICT:
                    out("  both findings may now ship; nothing else clears this pair")
                else:
                    out(f"  bb finding merge {record.uid} --into {record.other_uid} "
                        f"--reason '<why they are one bug>'")
            return 0
        if override:
            records = triage.record_not_duplicate(
                store, args.ref, reason=override, against=against
            )
            if args.json:
                _dump([dataclasses.asdict(r) for r in records])
                return 0
            for record in records:
                out(f"{record.uid} vs {record.other_uid}: overridden by hand -- {record.reason}")
            out("  recorded as an override, not as a pass: the report's gate table shows it")
            return 0

        review = triage.review_duplicates(store, args.ref)

    if args.json:
        _dump(review.as_dict())
    else:
        out(f"{review.uid}  dedup key {review.key.short}")
        out(f"  {review.key.canonical}")
        if review.stored_disagrees:
            out(f"  the stored dedup_key {review.stored_key!r} disagrees and was ignored")
            out(f"  bb finding dedupe {review.uid} --write-key")
        if not review.pairs:
            out("  no other live finding is close enough to be ambiguous")
        for pair in review.pairs:
            for line in _dedupe_pair_lines(pair):
                out(line)
        for other, why in review.not_compared:
            out(f"  not compared against {other}: {why}")
        if review.unresolved:
            out("")
            out("Each unresolved pair is a measurement nobody took, so the gate blocks:")
            for pair in review.unresolved:
                out(f"  bb finding dedupe {review.uid} --against {pair.other_uid} "
                    f"--verdict <duplicate|distinct|undetermined> --because '<why>'")
        for pair in review.duplicates:
            out(f"  bb finding merge {review.uid} --into {pair.other_uid} "
                f"--reason '{pair.reason or '<why they are one bug>'}'")
    return 1 if (review.unresolved or review.duplicates) else 0


# -- evidence -----------------------------------------------------------------


def cmd_evidence_add(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    path = None
    if args.path:
        path = Path(args.path).expanduser()
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
    role = getattr(args, "role", None) or "context"
    with _open_store(name) as store:
        ev_id = store.add_evidence(
            args.finding,
            args.kind,
            path=str(path) if path else None,
            request_id=args.request_id,
            caption=args.caption,
            role=role,
        )
        rows = [r for r in store.evidence_for(args.finding) if r["id"] == ev_id]
    if args.json:
        _dump(dict(rows[0]) if rows else {"id": ev_id, "role": role})
        return 0
    row = rows[0] if rows else None
    digest = f"  sha256:{row['sha256'][:12]}" if row and row["sha256"] else ""
    out(f"evidence {ev_id} attached to {args.finding}: {args.kind} role={role}{digest}")
    if role == "context":
        out("  access-control, auth, differential and business-logic findings need a "
            "baseline and an attack row: --role baseline|attack")
    return 0


def cmd_evidence_list(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        if store.get_finding(args.finding) is None:
            raise CliError(f"no finding {args.finding!r} in {name}\n  bb finding list")
        rows = store.evidence_for(args.finding)
    if args.json:
        _dump(_rows(rows))
        return 0
    if not rows:
        out(f"no evidence on {args.finding}")
        return 0
    root = paths.engagement_dir(name)
    out(
        _table(
            ("id", "kind", "where", "sha256", "size", "caption"),
            [
                [
                    r["id"],
                    r["kind"],
                    _rel(r["path"], root)
                    if r["path"]
                    else (f"request #{r['request_id']}" if r["request_id"] else "-"),
                    (r["sha256"] or "-")[:16],
                    _fmt_bytes(r["bytes"]),
                    _shorten(r["caption"], 40),
                ]
                for r in rows
            ],
        )
    )
    return 0


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        if store.get_finding(args.finding) is None:
            raise CliError(f"no finding {args.finding!r} in {name}\n  bb finding list")
        problems = store.verify_evidence(args.finding)
        count = len(store.evidence_for(args.finding))
    if args.json:
        _dump({"finding": args.finding, "evidence": count, "problems": problems})
        return 0 if not problems else 1
    if problems:
        out(f"{args.finding}: {len(problems)} problem(s) across {count} artifact(s)")
        for problem in problems:
            out(f"  {problem}")
        out("Re-capture the artifact; the harness will not report evidence it cannot verify.")
        return 1
    out(f"{args.finding}: {count} artifact(s) intact")
    return 0


# -- prerequisites ------------------------------------------------------------
#
# The reachability ledger gate_prerequisites_reachable reads. Its remedies name
# these commands, and until they existed nothing could record a trace, so no
# finding could reach `verified` however good the proof was.


def cmd_prereq_add(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        if store.get_finding(args.finding) is None:
            raise CliError(f"no finding {args.finding!r} in {name}\n  bb finding list")
        store.add_prerequisite(
            args.finding,
            args.name,
            attacker_start=args.attacker_start,
            acquisition=args.acquisition,
            request_id=args.request_id,
            verdict=args.verdict,
            searched=args.searched,
        )
        rows = [r for r in store.prerequisites_for(args.finding) if r["name"] == args.name]
    row = rows[0] if rows else None
    if args.json:
        _dump(dict(row) if row else {"finding": args.finding, "name": args.name})
        return 0
    out(f"prerequisite on {args.finding}: {args.name} -> {args.verdict}")
    if args.verdict == "reachable" and not args.request_id:
        out("  reachable with no --request-id does not reach 'verified': the gate wants the "
            "request that acquired it from the attacker's own position")
    return 0


def cmd_prereq_list(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        if store.get_finding(args.finding) is None:
            raise CliError(f"no finding {args.finding!r} in {name}\n  bb finding list")
        rows = store.prerequisites_for(args.finding)
    if args.json:
        _dump(_rows(rows))
        return 0
    if not rows:
        out(f"no prerequisites recorded on {args.finding}")
        out(f"  bb prereq add {args.finding} '<what the attack needs>' "
            "--acquisition '<how an attacker gets it>'")
        return 0
    out(
        _table(
            ("name", "verdict", "request", "attacker_start", "acquisition"),
            [
                [r["name"], r["verdict"], r["request_id"] or "-",
                 _shorten(r["attacker_start"], 28), _shorten(r["acquisition"], 40)]
                for r in rows
            ],
        )
    )
    return 0


# -- angles, accounts, objects ------------------------------------------------


def cmd_angle_add(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        # record_angle refuses `ruled_out` with no control and `open_gap` with no
        # next test, and its StoreError already carries the retry line, so it is
        # passed through rather than second-guessed here.
        store.record_angle(
            args.surface,
            args.vuln_class,
            args.technique,
            args.outcome,
            phase=args.phase,
            note=args.note,
            source=args.source,
            control=args.control,
            next_test=args.next_test,
        )
        stored = [
            r
            for r in store.angles(args.surface)
            if r["vuln_class"] == args.vuln_class and r["technique"] == args.technique
        ]
    outcome = stored[0]["outcome"] if stored else args.outcome
    if args.json:
        _dump(
            {
                "surface": args.surface,
                "vuln_class": args.vuln_class,
                "technique": args.technique,
                "outcome": outcome,
                "given": args.outcome,
                "control": args.control,
                "next_test": args.next_test,
                "source": args.source,
            }
        )
        return 0
    out(f"angle recorded: {args.surface}  {args.vuln_class}/{args.technique} -> {outcome}")
    if outcome != args.outcome:
        out(f"  {args.outcome!r} is the v1 word for {outcome!r}; it was stored as {outcome!r}")
    return 0


def cmd_angle_list(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        rows = store.angles(args.surface)
    if args.json:
        _dump(_rows(rows))
        return 0
    if not rows:
        out(f"no angles recorded for {name}; every surface is still untested")
        return 0
    # control and next_test are the reason the v2 vocabulary exists: a later
    # phase has to be able to see which defence ruled a class out and which test
    # an open gap is still waiting for. Storing them and not showing them makes
    # the ledger unreadable at exactly the moment it is consulted.
    out(
        _table(
            ("surface", "class", "technique", "outcome", "phase", "control / next test", "note"),
            [
                [r["surface"], r["vuln_class"], r["technique"], r["outcome"], r["phase"] or "-",
                 _shorten(r["control"] or r["next_test"], 44) if (r["control"] or r["next_test"])
                 else "-",
                 _shorten(r["note"], 30)]
                for r in rows
            ],
        )
    )
    open_gaps = [r for r in rows if r["outcome"] == "open_gap"]
    if open_gaps and not args.json:
        out("")
        out(f"{len(open_gaps)} open gap(s): named but not settled, so they are still untested "
            "ground rather than clean surface.")
    return 0


def cmd_account_add(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        store.add_account(
            args.label, args.role, email=args.email, secret_ref=args.secret_ref, note=args.note
        )
    if args.json:
        _dump({"label": args.label, "role": args.role})
        return 0
    out(f"account {args.label} ({args.role})")
    if args.secret_ref:
        out(f"  secret_ref {args.secret_ref}  (keep the secret itself under "
            f"{paths.engagement_dir(name) / 'sensitive'})")
    return 0


def cmd_account_list(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        rows = store.accounts()
    if args.json:
        _dump(_rows(rows))
        return 0
    if not rows:
        out(f"no accounts recorded for {name}")
        out("  bb account add victim --role victim --email ...")
        return 0
    out(
        _table(
            ("label", "role", "email", "secret_ref", "note"),
            [[r["label"], r["role"] or "-", r["email"] or "-", r["secret_ref"] or "-",
              _shorten(r["note"], 40)] for r in rows],
        )
    )
    return 0


def cmd_object_add(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    label = (args.label or getattr(args, "label_flag", None) or "").strip()
    if not label:
        raise CliError(
            "an object needs a label to refer to it by.\n"
            "  bb object add victim-doc --kind document --identifier 8831 --owner victim"
        )
    args.label = label
    with _open_store(name) as store:
        if not any(a["label"] == args.owner for a in store.accounts()):
            raise CliError(
                f"owner {args.owner!r} is not a recorded account, so ownership cannot be "
                f"proven later.\n  bb account add {args.owner} --role victim"
            )
        store.add_object(
            args.label,
            args.kind,
            args.identifier,
            args.owner,
            created_by_request=args.created_by_request,
            expected_access=args.expected_access,
            note=args.note,
        )
    if args.json:
        _dump({"label": args.label, "kind": args.kind, "identifier": args.identifier,
               "owner_account": args.owner})
        return 0
    out(f"object {args.kind}:{args.identifier} ({args.label}) owned by {args.owner}")
    return 0


def cmd_object_list(args: argparse.Namespace) -> int:
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        rows = store.objects(args.owner)
    if args.json:
        _dump(_rows(rows))
        return 0
    if not rows:
        out(f"no objects recorded for {name}")
        out("  bb object add order-victim --kind order --identifier 1041 --owner victim")
        return 0
    out(
        _table(
            ("label", "kind", "identifier", "owner", "expected_access", "note"),
            [[r["label"], r["kind"] or "-", r["identifier"], r["owner_account"] or "-",
              r["expected_access"] or "-", _shorten(r["note"], 30)] for r in rows],
        )
    )
    return 0


# -- secrets ------------------------------------------------------------------


def _secret_value(args: argparse.Namespace) -> str:
    """The value to record: a file, stdin, or an unechoed prompt.

    stdin is the default on purpose. A credential in argv is in the shell
    history, in `ps` output and in the guard's own audit log, which is exactly
    the set of places this module exists to keep it out of.
    """
    if args.from_file:
        path = Path(args.from_file).expanduser()
        try:
            return path.read_text(encoding="utf-8").rstrip("\n")
        except OSError as exc:
            raise CliError(
                f"cannot read the value from {path}: {exc.strerror or exc}"
            ) from exc
    if args.value is not None:
        print(
            f"bb: --value put the credential in argv, so it is now in your shell history and "
            f"in the guard's audit log. Next time:\n"
            f"  printf '%s' '<value>' | bb secret put {args.label}",
            file=sys.stderr,
        )
        return args.value
    try:
        interactive = sys.stdin is None or sys.stdin.isatty()
    except (AttributeError, ValueError):
        interactive = False
    if interactive:
        try:
            return getpass.getpass(f"value for secret://{args.label} (not echoed): ")
        except (EOFError, KeyboardInterrupt):
            raise CliError("no value was given, so nothing was recorded") from None
    data = sys.stdin.read()
    if data.endswith("\n"):
        data = data[:-1]  # the newline `printf`/`echo` adds, not part of the value
    if not data:
        raise CliError(
            f"stdin was empty, so there is nothing to record for {args.label!r}.\n"
            f"  printf '%s' '<value>' | bb secret put {args.label}\n"
            f"  bb secret put {args.label} --from-file <path>"
        )
    return data


def cmd_secret_put(args: argparse.Namespace) -> int:
    secrets = _mod("secrets")
    name = resolve_engagement(args.engagement)
    value = _secret_value(args)
    try:
        reference = secrets.put(args.label, value, engagement=name, note=args.note)
    except RuntimeError as exc:  # SecretError already carries its remedy
        raise CliError(str(exc)) from exc
    audit_append("secret_put", {"engagement": name, "label": args.label, "chars": len(value)})
    store_file = secrets.secrets_file(name)
    if args.json:
        _dump({"engagement": name, "label": args.label, "ref": reference,
               "file": str(store_file)})
        return 0
    out(f"recorded {reference}")
    out(f"  file: {store_file}   (0600, in a 0700 sensitive/)")
    out("  use the reference wherever the credential belongs; it is resolved at send time:")
    out(f"    bb req GET https://<host>/api -H 'Authorization: Bearer {reference}'")
    out(f"    bb account add <label> --role attacker --secret-ref {reference}")
    out("  the value is scanned for in every report and transcript, and refused if it shows up")
    return 0


def cmd_secret_list(args: argparse.Namespace) -> int:
    secrets = _mod("secrets")
    name = resolve_engagement(args.engagement)
    rows = secrets.entries(name)
    if args.json:
        _dump(rows)
        return 0
    if not rows:
        out(f"no secrets recorded for {name}")
        out("  printf '%s' '<value>' | bb secret put <label>")
        return 0
    out(
        _table(
            ("label", "ref", "sha256", "chars", "recorded", "note"),
            [
                [r["label"], r["ref"], (r["sha256"] or "-")[:12], r["chars"] or "-",
                 r["ts"] or "-", _shorten(r["note"], 40)]
                for r in rows
            ],
        )
    )
    out("")
    out(f"values live only in {secrets.secrets_file(name)}; when the engagement is over:")
    out(f"  {secrets.shred_hint(name)}")
    return 0


# -- gate and report ----------------------------------------------------------


def _targets(store: Store, ref: str | None, all_flag: bool, states: Sequence[str],
             state_override: str | None) -> list[str]:
    if ref:
        if store.get_finding(ref) is None:
            raise CliError(f"no finding {ref!r} in this engagement\n  bb finding list")
        return [ref]
    if not all_flag:
        raise CliError("give a finding reference or --all")
    wanted = (
        list(STATES)
        if state_override == "any"
        else [state_override] if state_override else list(states)
    )
    return [r["uid"] for r in store.list_findings() if r["state"] in wanted]


def _gate_words(args: argparse.Namespace) -> tuple[str | None, list[str]]:
    """Split `bb gate`'s positional words into (subcommand, arguments).

    An unrecognised first word is refused rather than read as a finding
    reference: `bb gate wiave F-001 gate_x` must not silently look for a
    finding called `wiave`, and a typo that reports "no such finding" sends an
    agent looking in the wrong place.
    """
    words = [str(word) for word in (getattr(args, "words", None) or [])]
    if words and words[0] in GATE_SUBCOMMANDS:
        return words[0], words[1:]
    if len(words) > 1:
        raise CliError(
            f"bb gate does not understand {' '.join(words)!r}. It takes one finding "
            f"reference, or one of {', '.join(GATE_SUBCOMMANDS)}:\n"
            "  bb gate <finding>                       # run the gates for one finding\n"
            "  bb gate --all                           # every finding in state 'verified'\n"
            "  bb gate waive <finding> <gate> --reason '<why>' --as <who>\n"
            "  bb gate waive --revoke <finding> <gate> --as <who>\n"
            "  bb gate waivers                         # what is waived, and whether it stands\n"
            "  bb gate waive-request <finding> <gate> --reason '<why>'   # argue, grant nothing"
        )
    return None, words


def cmd_gate(args: argparse.Namespace) -> int:
    subcommand, words = _gate_words(args)
    if subcommand == "waive":
        return _cmd_gate_waive(args, words)
    if subcommand == "waivers":
        return _cmd_gate_waivers(args, words)
    if subcommand == "waive-request":
        return _cmd_gate_waive_request(args, words)

    triage = _mod("triage")
    name = resolve_engagement(args.engagement)
    scope = _load_scope(name)
    args.ref = words[0] if words else None
    target = getattr(args, "target", None) or DEFAULT_GATE_TARGET
    # The rung being guarded decides which gates run. `apply_gates` still
    # defaults to the published v1 seven for a v1 caller, so naming the set here
    # is what makes the v2 gates -- derived severity, prerequisite reachability,
    # evidence roles, repro reconciliation, independent verification -- run at
    # all. Without this `bb gate` passed a finding on the v1 bar and advanced it
    # to `gated`, which is the state `bb report` will emit from.
    try:
        gates = triage.gates_for_state(target)
    except RuntimeError as exc:  # TriageError names the guarded rungs
        raise CliError(str(exc)) from exc
    results: list[dict[str, Any]] = []
    with _open_store(name) as store:
        refs = _targets(store, args.ref, args.all, ("verified",), args.state)
        if not refs:
            msg = f"nothing to gate in {name} (default: findings in state 'verified')"
            if args.json:
                _dump({"gated": [], "note": msg})
            else:
                out(msg)
                out("  bb finding list")
            return 0
        if not args.json:
            out(f"gating to {target}: {len(gates)} gate(s)")
        for ref in refs:
            passed = bool(
                triage.apply_gates(store, scope, ref, gates, target_state=target)
            )
            # Only the gates this run evaluated. The ledger also holds rows from
            # earlier runs and from other target rungs, and printing those under
            # "gating to verified: 10 gate(s)" showed a stale FAIL beside ten
            # fresh verdicts -- a gate that did not run reading as one that did.
            # The whole ledger is still one command away: `bb finding show`.
            latest: dict[str, Any] = {}
            for row in store.gates_for(ref):
                if row["gate"] in gates:
                    latest[row["gate"]] = dict(row)
            row = store.get_finding(ref)
            results.append(
                {
                    "uid": row["uid"],
                    "passed": passed,
                    "state": row["state"],
                    "gates": list(latest.values()),
                }
            )
            if not args.json:
                out(f"{'PASS' if passed else 'FAIL'}  {row['uid']}  -> {row['state']}")
                for gate in latest.values():
                    out(f"      {_gate_verdict(gate):<6} {gate['gate']:<32} "
                        f"{_shorten(gate['rationale'], 60)}")

    failed = [r for r in results if not r["passed"]]
    if args.json:
        _dump({"results": results, "passed": len(results) - len(failed), "failed": len(failed)})
    else:
        out("")
        out(f"{len(results) - len(failed)} of {len(results)} passed every gate")
        # Read the state the store actually holds. This line used to say every
        # failure was rejected, which is false for every blocked disposition --
        # a measurement that could not be taken parks the finding instead, and
        # telling an agent its finding was binned when it was parked sends it to
        # re-file rather than to unblock.
        for result in failed:
            out(f"  {result['uid']} is now '{result['state']}'. This is a verdict, not a "
                f"tool error.")
            if result["state"] == "blocked":
                out(f"    it was parked, not binned; `bb finding show {result['uid']}` names "
                    f"what would clear it")
    return 1 if failed else 0


# -- waivers ------------------------------------------------------------------
#
# Standing a gate down is the operator's act, and the asymmetry is structural:
# `bb gate waive-request` is what an agent runs and it grants nothing, while
# `bb gate waive` writes a signed file under `.state/`. Two further brakes:
#
#   * it refuses while a phase is running, because that is exactly the window in
#     which an agent and not the operator is at the keyboard. The check is the
#     store's own phase_runs table, so an unattended agent cannot pass it
#     without first marking its own phase finished, which ends its own run and
#     is recorded;
#   * a waived gate displays and ships as `waived`, never as `pass`.
#
# Honest bound, the same one the armkey carries: the agent runs as this uid, so
# it can read the signing key. This buys tamper-evidence and an audit trail
# against a confused or injection-steered agent, not containment.


def _gate_verdict(row: Any) -> str:
    """The word to display for one gates row: pass, waived or fail."""
    return _mod("waiver").gate_verdict(row)


def _waiver_args(words: Sequence[str], command: str) -> tuple[str, str]:
    """The (finding, gate) pair a waiver subcommand needs, or a remedy."""
    if len(words) != 2:
        raise CliError(
            f"{command} takes a finding and the gate it stands down, so the waiver is scoped "
            f"to one claim and one requirement:\n"
            f"  {command} <finding> <gate> ...\n"
            f"  bb gate <finding>        # which gate is refusing, and why"
        )
    return words[0], words[1]


def _require_no_phase_running(name: str, command: str) -> None:
    """Refuse an operator-only act while a phase is live.

    An agent inside a phase can run any `bb` command, so a waiver that a running
    phase could grant would be a waiver the gate's own subject can grant itself.
    This is the mechanical half of the asymmetry; the prompts' half is advisory
    and does not count.
    """
    running = _running_phase(name)
    if running:
        raise CliError(
            f"refusing to grant a waiver while phase {running} is running in {name}: a "
            f"running phase is an agent at the keyboard, and a gate's subject may not stand "
            f"its own gate down. Let the phase finish, or stop it, then:\n"
            f"  bb status {name}      # what the store believes is running\n"
            f"  {command}\n"
            f"From inside a phase the command that exists is `bb gate waive-request "
            f"<finding> <gate> --reason '<why>'`, which records the argument and grants "
            f"nothing."
        )


def _cmd_gate_waive(args: argparse.Namespace, words: Sequence[str]) -> int:
    waiver = _mod("waiver")
    name = resolve_engagement(args.engagement)
    # None means the flag was absent. A list -- empty or carrying the pair --
    # means a revocation was asked for; see the parser for why it takes values.
    revoked = getattr(args, "revoke", None)
    revoke = revoked is not None
    command = "bb gate waive" + (" --revoke" if revoke else "")
    ref, gate = _waiver_args(list(words) + list(revoked or []), command)
    who = getattr(args, "who", None)
    if not who:
        raise CliError(
            f"{command} needs --as <who>: a stand-down is a person's decision and the report "
            f"names them.\n  {command} {ref} {gate} --as <you@example.com>"
            + ("" if revoke else " --reason '<why the artifact cannot exist>'")
        )
    with _open_store(name) as store:
        if revoke:
            removed, audited = waiver.revoke(store, name, ref, gate, revoked_by=who)
            if args.json:
                _dump({"revoked": dataclasses.asdict(removed) if removed else None,
                       "audited": audited})
                return 0
            if removed is None:
                out(f"no waiver of {gate} on {ref} was on record; nothing to revoke")
            else:
                out(f"revoked {removed.gate} on {removed.finding_uid} "
                    f"(granted by {removed.waived_by})")
                out(f"  bb gate {removed.finding_uid}      # the gate decides again")
            if not audited:
                print(
                    "bb: the revocation could NOT be written to the audit log; it still "
                    "happened, because removing a waiver can only make the gates stricter. "
                    "Check the log with: bb doctor --verify-chain",
                    file=sys.stderr,
                )
            return 0

        _require_no_phase_running(name, f"{command} {ref} {gate} --reason '<why>' --as {who}")
        granted = waiver.grant(
            store, name, ref, gate,
            reason=args.reason or "", waived_by=who,
            hours=getattr(args, "hours", None) or waiver.DEFAULT_HOURS,
        )
    if args.json:
        _dump(dataclasses.asdict(granted))
        return 0
    out(f"waived {granted.gate} on {granted.finding_uid} by {granted.waived_by} "
        f"until {granted.expires_at}")
    out(f"  reason on record: {granted.reason}")
    out(f"  {waiver.waiver_path(name, granted.finding_uid, granted.gate)}")
    out("A waived gate is not a passed gate. Nothing mechanical now checks what it would "
        "have checked, the report says so where a triager cannot miss it, and the waiver "
        "lapses if the finding changes.")
    out(f"  bb gate {granted.finding_uid}")
    return 0


def _cmd_gate_waivers(args: argparse.Namespace, words: Sequence[str]) -> int:
    waiver = _mod("waiver")
    name = resolve_engagement(args.engagement)
    if words:
        raise CliError("bb gate waivers takes no arguments; it lists this engagement's waivers")
    with _open_store(name) as store:
        rows = waiver.listing(store, name)
    if args.json:
        _dump([
            {
                "finding_uid": row.finding_uid,
                "gate": row.gate,
                "path": str(row.path),
                "honored": row.honored,
                "waiver": dataclasses.asdict(row.waiver) if row.waiver else None,
                "problems": row.problems,
                "notes": row.notes,
            }
            for row in rows
        ])
        return 0
    if not rows:
        out(f"no gate is waived in {name}")
        return 0
    out(_table(
        ("gate", "finding", "waived by", "expires", "standing"),
        [
            (
                row.gate,
                row.finding_uid,
                row.waiver.waived_by if row.waiver else "-",
                row.waiver.expires_at if row.waiver else "-",
                "LIVE" if row.honored else "NOT HONORED",
            )
            for row in rows
        ],
    ))
    for row in rows:
        for problem in row.problems:
            out(f"  {row.finding_uid} {row.gate}: {problem}")
        for note in row.notes:
            out(f"  note: {row.finding_uid} {row.gate}: {note}")
    return 0


def _cmd_gate_waive_request(args: argparse.Namespace, words: Sequence[str]) -> int:
    waiver = _mod("waiver")
    name = resolve_engagement(args.engagement)
    ref, gate = _waiver_args(words, "bb gate waive-request")
    asked_by = (
        getattr(args, "asked_by", None)
        or _running_phase(name)
        or "agent"
    )
    with _open_store(name) as store:
        row_id = waiver.request_waiver(
            store, ref, gate, reason=args.reason or "", asked_by=asked_by
        )
    if args.json:
        _dump({"recorded": row_id, "finding": ref, "gate": gate,
               "asked_by": asked_by, "granted": False})
        return 0
    out(f"recorded as gates row {row_id}: {asked_by} argues {gate} cannot be satisfied for "
        f"{ref}")
    out("This grants nothing. The gate still refuses, and the row's verdict is 'fail'.")
    out(f"  bb gate waive {ref} {gate} --reason '<why>' --as <who>   # the operator's command")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    report = _mod("report")
    name = resolve_engagement(args.engagement)
    scope = _load_scope(name)
    with _open_store(name) as store:
        if args.summary:
            text = report.render_summary(store, scope)
            if args.json:
                _dump({"summary": text})
            else:
                out(text)
            return 0

        refs = _targets(store, args.ref, args.all, REPORTABLE_STATES, args.state)
        if not refs:
            msg = (
                f"no findings in state {' or '.join(REPORTABLE_STATES)} in {name}; "
                "nothing to report"
            )
            if args.json:
                _dump({"reports": [], "note": msg})
            else:
                out(msg)
                out("  bb gate --all      # run the gates first")
                out("  bb finding list")
            return 0

        written: list[dict[str, str]] = []
        failures: list[str] = []
        for ref in refs:
            try:
                if args.stdout:
                    text = report.render(store, scope, ref)
                    if not args.json:
                        out(text)
                        out("")
                    written.append({"uid": str(ref), "markdown": text})
                else:
                    path = report.write_report(store, scope, ref)
                    written.append({"uid": str(ref), "path": str(path)})
                    if not args.json:
                        out(f"wrote {path}")
            except (RuntimeError, ValueError, OSError) as exc:
                failures.append(f"{ref}: {exc}")
                if not args.json:
                    print(f"bb report: {ref}: {exc}", file=sys.stderr)

    if args.json:
        _dump({"reports": written, "failures": failures})
    elif failures:
        out("")
        out(f"{len(failures)} finding(s) could not be reported; see the errors above.")
    return 1 if failures else 0


# -- coverage -----------------------------------------------------------------


def cmd_coverage(args: argparse.Namespace) -> int:
    """The coverage table, or one class's remaining surfaces.

    Exit 0 when the arithmetic computed. Not being clean is the normal state of
    a hunt in progress, so it is not an error unless `--require-clean` asks for
    one; that flag is for a caller that wants "is there anything left" as an
    exit status rather than as prose.
    """
    coverage = _mod("coverage")
    name = resolve_engagement(args.engagement)
    wanted = getattr(args, "vuln_class", None)
    with _open_store(name) as store:
        if wanted:
            row = coverage.class_report(store, wanted, engagement=name)
            if args.json:
                _dump(dataclasses.asdict(row))
                return 0
            out(f"{row.vuln_class}  {row.status}  eligible={row.eligible} "
                f"tested={row.tested} remaining={row.remaining}")
            out(f"  narrowed by: {', '.join(row.requires) or '-'}  ({row.why})")
            if row.reason:
                out(f"  recorded reason: {row.reason}")
            if not row.in_vocabulary:
                out("  not in the class vocabulary; it is here because the ledger names it")
            for surface in row.remaining_surfaces:
                out(f"  untested  {surface.label}")
            for claim in row.unsupported:
                out(f"  UNSUPPORTED  {claim}")
            if row.status == coverage.STATUS_UNROUTED:
                out("")
                out("No surface in the inventory is eligible for this class and no reason is "
                    "recorded, so it reads as never routed rather than as clean:")
                out(f"  bb coverage reason {row.vuln_class} '<the mechanical fact>'")
            return 0

        if getattr(args, "refresh", False):
            rebuilt = coverage.refresh(store, name)
            if not args.json:
                out(f"inventory rebuilt: {rebuilt.surfaces} surface(s) "
                    f"({rebuilt.observed} observed, {rebuilt.declared_only} declared only) "
                    f"from {rebuilt.requests_folded} request(s)")
        rep = coverage.report(store, engagement=name)

    if args.json:
        _dump(dataclasses.asdict(rep))
    else:
        out(_table(coverage.TABLE_HEADERS, rep.table()))
        out("")
        out(rep.verdict)
        for blocker in rep.blockers:
            out("")
            out(f"GAP IN THE INVENTORY ITSELF: {blocker}")
        for claim in rep.unsupported:
            out(f"UNSUPPORTED CLAIM: {claim}")
        for note in rep.notes:
            out(f"note: {note}")
    if getattr(args, "require_clean", False) and not rep.clean:
        raise CliError(
            "coverage is not a clean sweep, and --require-clean was asked for.\n"
            "  bb coverage                      # the table above, in full\n"
            "  bb coverage --class <class>      # every surface still untested for one class\n"
            "A class with no eligible surface and no recorded reason was never routed, which "
            "is not the same as clean."
        )
    return 0


def cmd_coverage_reason(args: argparse.Namespace) -> int:
    """Record why a class has no eligible surface, so it stops reading as untested."""
    coverage = _mod("coverage")
    name = resolve_engagement(args.engagement)
    with _open_store(name) as store:
        cls = coverage.record_reason(
            store, args.vuln_class, args.reason, phase=getattr(args, "phase", None)
        )
    if args.json:
        _dump({"vuln_class": cls, "reason": args.reason, "phase": getattr(args, "phase", None)})
        return 0
    out(f"recorded: {cls} has no eligible surface because {args.reason}")
    out("  bb coverage        # the class now reads 'explained' rather than 'unrouted'")
    return 0


# -- handoff ------------------------------------------------------------------


def cmd_handoff_write(args: argparse.Namespace) -> int:
    """Validate a phase's handoff and print the coverage gaps alongside it.

    The two answers are deliberately separate. `problems` decide the exit code,
    because a handoff missing a key fails the phase. `coverage_gaps` never do: a
    phase that ran out of budget still produced its work, and the gaps exist so
    the next phase can dispatch against them rather than read silence as
    coverage.
    """
    runner = _mod("runner")
    coverage = _mod("coverage")
    name = resolve_engagement(args.engagement)
    try:
        phase = runner.phase_by_key(args.phase)
    except RuntimeError as exc:  # RunnerError names the known keys
        raise CliError(str(exc)) from exc
    path = runner.handoff_path_for(name, phase)
    problems = runner.validate_handoff(phase, path)
    with _open_store(name) as store:
        gaps = coverage.handoff_gaps(store, phase.key)

    if args.json:
        _dump({"ok": not problems, "phase": phase.key, "path": str(path),
               "problems": problems, "coverage_gaps": gaps})
    else:
        out(f"{'ok' if not problems else 'NOT VALID'}  {phase.key}  {path}")
        for problem in problems:
            out(f"  PROBLEM  {problem}")
        for gap in gaps:
            out(f"  gap      {gap}")
        if problems:
            out("")
            out("The handoff is the phase's deliverable; a missing key re-runs the phase.")
    return 1 if problems else 0


# -- proxy --------------------------------------------------------------------


def _proxy_state_dir(name: str) -> Path:
    state = paths.engagement_dir(name) / ".state"
    state.mkdir(parents=True, exist_ok=True)
    return state


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _running_phase(name: str) -> str | None:
    """The phase the store believes is running, so proxy rows join up with it."""
    try:
        with _open_store(name) as store:
            for row in reversed(store.phase_runs()):
                if row["status"] == "running":
                    return str(row["phase"])
    except Exception:
        return None
    return None


def proxy_command(
    name: str,
    *,
    mitmdump: str,
    addon: Path,
    confdir: Path,
    phase: str,
    listen_host: str,
    port: int,
) -> list[str]:
    """The exact mitmdump invocation `bb proxy start` runs.

    Two options are not optional. `confdir` gives the engagement its own CA, so
    the certificate a target sees is not the one the operator's other mitmproxy
    use installed, and tearing the engagement down takes the CA with it.
    `bbh_phase` is always set, because a capture with a NULL phase cannot be
    told apart from one the harness lost track of.
    """
    return [
        mitmdump,
        "-s", str(addon),
        "--set", f"bbh_engagement={name}",
        "--set", f"bbh_phase={phase}",
        "--set", f"confdir={confdir}",
        "--listen-host", listen_host,
        "--listen-port", str(port),
    ]


def _read_pid(pid_file: Path, expect: str = "mitmdump") -> int | None:
    """The live pid in a pid file, or None. A recycled pid must not be killed."""
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if not _pid_alive(pid):
        return None
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", "replace")
    except OSError:
        return pid  # no procfs to cross-check against; trust the file
    return pid if expect in cmdline else None


def cmd_proxy_start(args: argparse.Namespace) -> int:
    engagement = _mod("engagement")
    name = resolve_engagement(getattr(args, "name", None) or args.engagement)
    try:
        engagement.require_armed(name)
    except RuntimeError as exc:
        raise CliError(str(exc)) from exc

    addon = paths.REPO / "bbh" / "proxy_addon.py"
    if not addon.exists():
        raise CliError(f"the mitmproxy addon is missing: {addon}\nThis build is incomplete.")
    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        raise CliError(
            "mitmdump is not on PATH.\n"
            f"  {paths.REPO / '.venv' / 'bin' / 'python'} -m pip install mitmproxy"
        )

    state = _proxy_state_dir(name)
    pid_file = state / "proxy.pid"
    running = _read_pid(pid_file)
    if running:
        raise CliError(f"proxy for {name} is already running (pid {running})\n  bb proxy stop")

    try:
        raw_dir = _mod("secrets").harden_raw(name)
    except (CliError, RuntimeError) as exc:
        raise CliError(str(exc)) from exc
    log_path = raw_dir / "proxy.log"
    confdir = state / "mitmproxy"
    confdir.mkdir(parents=True, exist_ok=True)
    phase = args.phase or _running_phase(name) or DEFAULT_PROXY_PHASE
    cmd = proxy_command(
        name,
        mitmdump=mitmdump,
        addon=addon,
        confdir=confdir,
        phase=phase,
        listen_host=args.listen_host,
        port=args.port,
    )
    with log_path.open("ab") as log:
        log.write(f"\n--- {datetime.now(timezone.utc).isoformat()} {' '.join(cmd)}\n".encode())
        log.flush()
        try:
            proc = subprocess.Popen(
                cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                cwd=str(paths.engagement_dir(name)), start_new_session=True,
            )
        except OSError as exc:
            raise CliError(f"cannot start mitmdump: {exc}") from exc

    time.sleep(0.8)
    if proc.poll() is not None:
        tail = "\n".join(_tail_lines(log_path, 15))
        raise CliError(
            f"mitmdump exited immediately (code {proc.returncode}). Last log lines:\n{tail}\n"
            f"full log: {log_path}"
        )
    pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")
    # Register it, so `bb cleanup` can prove this pid is still the process the
    # harness started before it signals anything. `expect=cmd` makes the settle
    # wait an assertion about the argv rather than a hope that execve landed.
    # A registry that will not write is not a reason to leave the proxy
    # unrecorded, so the failure is reported and the proxy keeps running.
    registered: dict[str, Any] | None = None
    try:
        registered = _mod("proc").register(
            proc.pid, kind="proxy", engagement=name, port=args.port,
            expect=cmd, note=f"mitmdump for {name}",
        ).as_dict()
    except (CliError, RuntimeError, OSError) as exc:
        print(
            f"bb proxy start: the proxy is running as pid {proc.pid} but could not be "
            f"registered: {exc}\n"
            f"    `bb cleanup` will not know about it; stop it with `bb proxy stop`.",
            file=sys.stderr,
        )

    endpoint = f"http://{args.listen_host}:{args.port}"
    ca_cert = confdir / "mitmproxy-ca-cert.pem"
    if args.json:
        _dump({"pid": proc.pid, "endpoint": endpoint, "log": str(log_path),
               "engagement": name, "phase": phase, "confdir": str(confdir),
               "ca_cert": str(ca_cert), "registered": registered})
        return 0
    out(f"proxy up for {name} on {endpoint} (pid {proc.pid})")
    out(f"  log:   {log_path}")
    out(f"  phase: {phase}  (recorded on every captured request)")
    out("  out-of-scope flows are killed by the addon, not merely logged")
    out("")
    out("  export HTTPS_PROXY=" + endpoint + " HTTP_PROXY=" + endpoint)
    out(f"  CA cert: {ca_cert}")
    out(f"    this engagement's own CA, not ~/.mitmproxy; it appears once the proxy has "
        f"served a flow")
    out("  bb proxy stop")
    return 0


def cmd_proxy_stop(args: argparse.Namespace) -> int:
    """Stop the engagement's proxy, through the registry when there is a row.

    The registry is preferred because it is the only path that can prove the
    pid is still the process the harness started: the pid file plus a substring
    of the cmdline cannot, and this command sends SIGKILL. A proxy started
    before it was registered falls back to the pid file, and that path now
    refuses to signal a pid whose identity it cannot read at all.
    """
    proc = _mod("proc")
    name = resolve_engagement(getattr(args, "name", None) or args.engagement)
    pid_file = _proxy_state_dir(name) / "proxy.pid"

    if proc.registered(engagement=name, kind="proxy"):
        try:
            report = proc.cleanup(engagement=name, kind="proxy")
        except RuntimeError as exc:
            raise CliError(str(exc)) from exc
        if report.ok:
            pid_file.unlink(missing_ok=True)
        if args.json:
            _dump({"stopped": report.ok, **report.as_dict()})
        else:
            out(report.text())
        return 2 if report.left_running else 0

    pid = _read_pid(pid_file)
    if pid is None:
        pid_file.unlink(missing_ok=True)
        if args.json:
            _dump({"stopped": False, "note": "no proxy running"})
        else:
            out(f"no proxy running for {name}")
        return 0
    identity = proc.read_identity(pid)
    if identity is None or "mitmdump" not in identity.raw_cmdline.decode("utf-8", "replace"):
        raise CliError(
            f"refusing to signal pid {pid}: {pid_file} names it, but this harness cannot "
            f"read an argv for it that is still mitmdump's, so it may be a different "
            f"process that was given the same number. Check it and stop it by hand:\n"
            f"  ps -o pid,lstart,args -p {pid}\n"
            f"  kill -TERM {pid}\n"
            f"Then clear the stale file: rm {pid_file}"
        )
    os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        if not _pid_alive(pid):
            break
        time.sleep(0.1)
    else:
        os.kill(pid, signal.SIGKILL)
    pid_file.unlink(missing_ok=True)
    if args.json:
        _dump({"stopped": True, "pid": pid})
        return 0
    out(f"stopped proxy for {name} (pid {pid})")
    return 0


# -- process registry ---------------------------------------------------------


def cmd_proc_register(args: argparse.Namespace) -> int:
    """Record a pid the harness is responsible for, with proof of its identity."""
    proc = _mod("proc")
    name = resolve_engagement(args.engagement, must_exist=False) if args.engagement else None
    entry = proc.register(
        args.pid, kind=args.kind, engagement=name or paths.active_engagement(),
        port=getattr(args, "port", None), note=getattr(args, "note", None),
    )
    if args.json:
        _dump(entry.as_dict())
        return 0
    # The cmdline is printed, not summarised: the recorded identity defends
    # against a recycled pid, not against the wrong pid being typed here, and
    # the only reader who can catch that is the one looking at this line.
    out(f"registered pid {entry.pid} ({entry.label()}): {entry.cmdline}")
    out("  bb cleanup")
    return 0


def cmd_proc_list(args: argparse.Namespace) -> int:
    proc = _mod("proc")
    rows = proc.registered(
        engagement=getattr(args, "engagement", None), kind=getattr(args, "kind", None)
    )
    if args.json:
        _dump([row.as_dict() for row in rows])
        return 0
    if not rows:
        out(f"nothing registered in {proc.registry_path()}")
        out("  bb proc register <pid> --kind proxy")
        return 0
    out(_table(
        ("pid", "kind", "engagement", "port", "registered", "cmdline"),
        [
            (row.pid, row.kind, row.engagement or "-", row.port or "-",
             row.registered_at, _shorten(row.cmdline, 60))
            for row in rows
        ],
    ))
    return 0


def cmd_proc_forget(args: argparse.Namespace) -> int:
    """Drop rows without signalling anything; for a process someone else stopped."""
    proc = _mod("proc")
    dropped = proc.forget(args.pid, reason=args.reason or "")
    if args.json:
        _dump([row.as_dict() for row in dropped])
        return 0
    for row in dropped:
        out(f"forgot pid {row.pid} ({row.label()}); nothing was signalled")
    return 0


def cmd_cleanup(args: argparse.Namespace) -> int:
    """Stop every registered process whose identity still matches. Refuse the rest.

    Exit 2, not 1, when something is still running: a refusal to signal is the
    registry working, and it must not read like the command itself failed.
    """
    proc = _mod("proc")
    try:
        report = proc.cleanup(
            engagement=getattr(args, "engagement", None),
            kind=getattr(args, "kind", None),
            pids=getattr(args, "pid", None),
            dry_run=bool(getattr(args, "dry_run", False)),
            grace_s=(
                args.grace if getattr(args, "grace", None) is not None
                else proc.DEFAULT_GRACE_S
            ),
        )
    except RuntimeError as exc:  # ProcError: the command itself is refused
        raise CliError(str(exc)) from exc
    if args.json:
        _dump(report.as_dict())
    else:
        out(report.text())
    return 2 if report.left_running else 0


# -- reading a recorded body --------------------------------------------------

REQ_SHOW = "show"


def _req_show_parser() -> argparse.ArgumentParser:
    """`bb req show`'s own parser.

    `bb req` takes its arguments as REMAINDER, because its first word is an HTTP
    method and a subparser group would make `GET` an invalid choice. So `show`
    is dispatched by hand and parses the rest here. Keeping it a real parser is
    what makes `--help` work and what lets `optional_dests` normalise
    `--grep none`.
    """
    parser = argparse.ArgumentParser(
        prog="bb req show",
        description="Print one recorded request or response body, verified against its hash.",
    )
    parser.add_argument("request_id", metavar="ID",
                        help="a request id, as `bb req` and `bb evidence list` print it")
    parser.add_argument("--side", default="response", metavar="SIDE",
                        help="request or response (default: response; req/resp are accepted)")
    parser.add_argument("--grep", default=None, metavar="PATTERN",
                        help="regular expression; prints a window around each match")
    parser.add_argument("-i", "--ignore-case", action="store_true")
    parser.add_argument("--max-matches", type=int, default=None, metavar="N")
    parser.add_argument("--window", type=int, default=None, metavar="BYTES")
    parser.add_argument("--preview-bytes", type=int, default=None, metavar="BYTES")
    parser.add_argument("--budget", type=float, default=None, metavar="SECONDS",
                        help="how long the scan may run before it reports itself incomplete")
    parser.add_argument("-e", "--engagement", default=None)
    parser.add_argument("--json", action="store_true")
    return parser


def cmd_req_show(argv: Sequence[str], outer: argparse.Namespace) -> int:
    """Exit 0 shown, 1 a clean no-match, 3 an incomplete scan, 2 refused.

    The three failure codes are distinct because they mean different things to a
    caller. Exit 1 is grep's clean negative -- the pattern is not in the body.
    Exit 3 is a scan the budget stopped, where an empty match list is not a
    negative result and must not be read as one. Exit 2 is the command refusing.
    """
    proc = _mod("proc")
    parser = _req_show_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit as exc:  # --help, or a usage error already printed
        return int(exc.code or 0)
    for note in normalize_optional(args, optional_dests(parser, args)):
        print(f"bb req show: {note}", file=sys.stderr)
    name = resolve_engagement(args.engagement or getattr(outer, "engagement", None))
    defaults = {
        "max_matches": proc.MAX_MATCHES,
        "window": proc.MATCH_WINDOW,
        "preview_bytes": proc.PREVIEW_BYTES,
        "budget": proc.SCAN_BUDGET_S,
    }
    chosen = {
        key: (getattr(args, key) if getattr(args, key) is not None else fallback)
        for key, fallback in defaults.items()
    }
    try:
        with _open_store(name) as store:
            view = proc.show_body(
                store, args.request_id,
                side=args.side, pattern=args.grep, ignore_case=args.ignore_case,
                engagement=name, max_matches=chosen["max_matches"],
                window=chosen["window"], preview_bytes=chosen["preview_bytes"],
                budget_s=chosen["budget"],
            )
    except RuntimeError as exc:  # ProcError, StoreError: refused, not a negative
        print(f"bb req show: {exc}", file=sys.stderr)
        return 2
    if args.json:
        _dump(view.as_dict())
    else:
        out(view.text())
    if not view.complete:
        return 3
    if args.grep and not view.matches:
        return 1
    return 0


def cmd_proxy_status(args: argparse.Namespace) -> int:
    name = resolve_engagement(getattr(args, "name", None) or args.engagement)
    pid = _read_pid(_proxy_state_dir(name) / "proxy.pid")
    if args.json:
        _dump({"engagement": name, "running": pid is not None, "pid": pid})
        return 0
    if pid is None:
        out(f"proxy for {name}: not running\n  bb proxy start {name}")
        return 0
    out(f"proxy for {name}: running (pid {pid})")
    return 0


# -- sandbox ------------------------------------------------------------------
#
# The runner refuses an unattended hunt without egress containment and names
# these commands in its remedy, so they exist here even though bbh/sandbox.py is
# optional. A remedy that points at a command the CLI does not have is worse
# than no remedy at all.


def _sandbox_module(name: str) -> ModuleType:
    try:
        return importlib.import_module("bbh.sandbox")
    except ImportError as exc:
        raise CliError(
            f"bbh/sandbox.py is not installed, so a hunt has no egress containment: the "
            f"scope guard is static, and a raw socket or an interpreter it cannot parse "
            f"would not be stopped ({exc}).\n"
            f"To hunt anyway, accepting that the guard is the only barrier:\n"
            f"  bb hunt {name} --unsandboxed"
        ) from exc


def _sandbox_call(name: str, function: str, *args: Any) -> Any:
    mod = _sandbox_module(name)
    fn = getattr(mod, function, None)
    if not callable(fn):
        available = ", ".join(sorted(a for a in dir(mod) if not a.startswith("_"))) or "nothing"
        raise CliError(
            f"bbh/sandbox.py does not expose {function}(engagement); it exposes: {available}"
        )
    return fn(name, *args)


def _sandbox_problems(name: str) -> list[str]:
    runner = _mod("runner")
    contained, problems = runner.sandbox_state(name)
    return [] if contained else [str(p) for p in problems]


def cmd_sandbox_up(args: argparse.Namespace) -> int:
    name = resolve_engagement(getattr(args, "name", None) or args.engagement)
    _sandbox_call(name, "up")
    problems = _sandbox_problems(name)
    if args.json:
        _dump({"engagement": name, "contained": not problems, "problems": problems})
        return 1 if problems else 0
    if problems:
        out(f"sandbox for {name} came up but is not containing traffic:")
        for problem in problems:
            out(f"  - {problem}")
        return 1
    out(f"sandbox up for {name}; egress is confined to the compiled scope")
    return 0


def cmd_sandbox_down(args: argparse.Namespace) -> int:
    name = resolve_engagement(getattr(args, "name", None) or args.engagement)
    _sandbox_call(name, "down")
    if args.json:
        _dump({"engagement": name, "contained": False})
        return 0
    out(f"sandbox down for {name}")
    return 0


def cmd_sandbox_verify(args: argparse.Namespace) -> int:
    name = resolve_engagement(getattr(args, "name", None) or args.engagement)
    problems = _sandbox_problems(name)
    if args.json:
        _dump({"engagement": name, "contained": not problems, "problems": problems})
        return 1 if problems else 0
    if problems:
        out(f"NOT contained ({name}):")
        for problem in problems:
            out(f"  - {problem}")
        out(f"  bb sandbox up {name}")
        out(f"  bb hunt {name} --unsandboxed   # accept the guard as the only barrier")
        return 1
    out(f"contained: {name} egress is confined")
    return 0


# -- audit --------------------------------------------------------------------
#
# The audit log is append-only evidence: what the guard denied, what the proxy
# killed, when an engagement was armed. Appends made through audit_append() are
# hash chained -- {"prev", "ts", "event", "data"}, where prev is the sha256 of
# the previous line exactly as it was written -- so editing, deleting or
# inserting a line breaks the link the line after it records, and
# `bb doctor --verify-chain` finds the break.
#
# Honest bound: tamper-EVIDENT, not tamper-proof. Same uid means a determined
# process can rewrite the file and recompute the whole chain, and truncating the
# tail destroys the only record of what the tail said. What it catches is the
# realistic case: a confused or injection-steered agent editing a line it does
# not like.
#
# It lives here because the CLI owns both readers (`bb audit`, `bb doctor`).
# Every writer chains. bbh.guard, bbh.http, bbh.runner, bbh.engagement and
# bbh.proxy_addon go through audit_record(), which keeps the flat record shape
# those five already had and that `bb audit` renders -- see its docstring for
# why that is the same guarantee and not a weaker one. `bb secret put` uses
# audit_append(), whose payload has no settled shape to preserve. A line with no
# `prev` is counted as unchained and reported rather than treated as tampering:
# that is an older log, or a writer added later that forgot to chain.


def _audit_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _audit_tail(fh: Any) -> tuple[bytes, bool]:
    """(final line, does the file end with a newline) for an open binary file.

    Read backwards from the end: an append must not cost a pass over a log that
    grows for the whole engagement.
    """
    fh.seek(0, os.SEEK_END)
    end = fh.tell()
    if end == 0:
        return b"", True
    fh.seek(end - 1)
    ends_clean = fh.read(1) == b"\n"
    limit = end - 1 if ends_clean else end  # ignore the terminator, not a blank line
    if limit == 0:
        return b"", ends_clean
    pos, data = limit, b""
    while pos > 0:
        step = min(4096, pos)
        pos -= step
        fh.seek(pos)
        data = fh.read(min(step, limit - pos)) + data
        cut = data.rfind(b"\n")
        if cut != -1:
            return data[cut + 1 :], ends_clean
    return data, ends_clean


def _append_chained(build: Any, *, log: Path | None = None) -> bool:
    """Append one line built from the hash of the line before it. True when it landed.

    Auditing never breaks its caller: a failure is reported by the return value
    and by `bb doctor`, not by an exception in the middle of a hunt. The lock is
    held across read-and-write so two harness processes cannot chain onto the
    same line and fork the log.
    """
    path = log or paths.AUDIT_LOG
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a+b") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                size = os.fstat(fh.fileno()).st_size
                last, ends_clean = _audit_tail(fh)
                prev = AUDIT_GENESIS if size == 0 else hashlib.sha256(last).hexdigest()
                if size and not ends_clean:
                    fh.write(b"\n")  # a writer died mid-line; do not glue onto it
                fh.write(json.dumps(build(prev), default=str).encode("utf-8") + b"\n")
                fh.flush()
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return True
    except Exception:
        return False


def audit_append(event: str, data: Mapping[str, Any] | None = None,
                 *, log: Path | None = None) -> bool:
    """Append one chained record as {prev, ts, event, data}."""
    return _append_chained(
        lambda prev: {
            "prev": prev,
            "ts": _audit_ts(),
            "event": str(event),
            "data": dict(data or {}),
        },
        log=log,
    )


def audit_record(event: str, record: Mapping[str, Any], *, log: Path | None = None) -> bool:
    """Chain a writer's own flat record instead of nesting it under `data`.

    The guard, the client, the runner and the lifecycle commands each write a
    record with a settled shape that `bb audit` and several callers read by its
    top-level keys. Nesting those under `data` to chain them would have been a
    change to the log's published shape for no gain, because the chain does not
    care what a line says -- `prev` is the sha256 of the previous line exactly
    as it was written, whatever shape that line had. So the chain field is added
    to the record the writer already had, and every line in the log becomes
    tamper-evident without any reader being rewritten.
    """
    body = {k: v for k, v in dict(record).items() if k != "prev"}
    body.setdefault("ts", _audit_ts())
    body["event"] = str(event)
    return _append_chained(lambda prev: {"prev": prev, **body}, log=log)


@dataclass
class ChainReport:
    """The verdict on the audit log's hash chain."""

    path: Path
    lines: int = 0
    chained: int = 0
    unchained: int = 0
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def verify_audit_chain(log: Path | None = None) -> ChainReport:
    """Walk the audit log and report every break in its chain."""
    path = log or paths.AUDIT_LOG
    report = ChainReport(path=path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return report
    except OSError as exc:
        report.problems.append(f"cannot read {path}: {exc.strerror or exc}")
        return report

    chunks = raw.split(b"\n")
    if chunks and chunks[-1] == b"":
        chunks.pop()  # the final terminator is not a line
    expected = AUDIT_GENESIS
    for number, line in enumerate(chunks, 1):
        report.lines += 1
        digest = hashlib.sha256(line).hexdigest()
        try:
            record = json.loads(line)
        except ValueError:
            report.problems.append(
                f"line {number} is not JSON, so nothing can be said about what it recorded. "
                f"A crash mid-write can truncate the last line; anywhere else this is an edit."
            )
            expected = digest
            continue
        if isinstance(record, dict) and isinstance(record.get("prev"), str) and "event" in record:
            report.chained += 1
            found = str(record["prev"])
            if found != expected:
                anchor = (
                    "the log should start from the genesis hash"
                    if number == 1
                    else f"line {number - 1} hashes to sha256:{expected[:12]}"
                )
                report.problems.append(
                    f"line {number} ({record.get('event') or 'event'} at "
                    f"{record.get('ts') or 'an unrecorded time'}) breaks the chain: it records "
                    f"prev sha256:{found[:12]} but {anchor}. A line at or before "
                    f"{number - 1 if number > 1 else 1} was edited, inserted or removed after "
                    f"it was written."
                )
        else:
            report.unchained += 1
        expected = digest
    return report


def _audit_view(record: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten a chained record for display; a flat legacy record passes through."""
    payload = record.get("data")
    if "prev" in record and isinstance(payload, Mapping):
        view = dict(payload)
        view.setdefault("ts", record.get("ts"))
        view.setdefault("action", record.get("event"))
        return view
    # A record chained in place by audit_record: the writer's own keys, plus the
    # two the chain added. `prev` is machinery, not a decision, so it is not
    # rendered; `event` names the decision when the writer had no `action`.
    view = {k: v for k, v in record.items() if k != "prev"}
    if "prev" in record and view.get("event") and not view.get("action"):
        view["action"] = view.pop("event")
    return view


def _tail_lines(path: Path, count: int) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return [line.rstrip("\n") for line in deque(fh, maxlen=count)]
    except OSError:
        return []


def cmd_audit(args: argparse.Namespace) -> int:
    log = paths.AUDIT_LOG
    if not log.exists():
        if args.json:
            _dump([])
        else:
            out(f"no guard decisions recorded yet ({log})")
            out("  bb doctor   # confirm the PreToolUse hook is installed")
        return 0
    records: list[dict[str, Any]] = []
    for line in _tail_lines(log, max(args.tail * 4, args.tail)):
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        # Three shapes reach this log: a chained {prev, ts, event, data} record,
        # a guard decision (an "allowed" key) and a lifecycle event written by
        # the engagement module (an "action" key). The chained one is unwrapped
        # so the other two render exactly as before.
        view = _audit_view(record)
        if args.denied and view.get("allowed") is not False:
            continue
        records.append(view)
    records = records[-args.tail :]
    if args.json:
        _dump(records)
        return 0
    if not records:
        out("no matching audit records")
        return 0
    for record in records:
        stamp = record.get("ts", "?")
        engagement = str(record.get("engagement") or "-")
        if "allowed" in record:
            verdict = "ok  " if record.get("allowed") else "DENY"
            out(f"{stamp}  {verdict}  {str(record.get('tool') or '-'):<10} {engagement:<12} "
                f"{_shorten(record.get('command'), 70)}")
            for reason in _as_list(record.get("reasons"))[:3]:
                for line in str(reason).splitlines()[:2]:
                    if line.strip():
                        out(f"        {_shorten(line, 100)}")
        else:
            action = str(record.get("action") or record.get("event") or "event")
            detail = " ".join(
                f"{k}={v}"
                for k, v in record.items()
                if k not in ("ts", "action", "event", "engagement")
                and v not in (None, "", [], {})
            )
            out(f"{stamp}  {action:<6} {engagement:<12} {_shorten(detail, 80)}")
    return 0


# -- hook wiring --------------------------------------------------------------


def guard_shim() -> Path:
    return paths.REPO / "bin" / "bb-guard"


def settings_file(scope_flag: str) -> Path:
    if scope_flag == "project":
        return Path.cwd() / ".claude" / "settings.json"
    return Path.home() / ".claude" / "settings.json"


def _same_command(command: Any, target: Path) -> bool:
    """True when a settings hook command invokes the given script."""
    if not isinstance(command, str) or not command.strip():
        return False
    try:
        first = shlex.split(command)[0]
    except ValueError:
        first = command.split()[0]
    try:
        return Path(first).expanduser().resolve() == target.resolve()
    except OSError:
        return False


def _matcher_covers_bash(matcher: Any) -> bool:
    if matcher in (None, "", "*"):
        return True
    return "Bash" in str(matcher)


def _hook_entry(target: Path) -> dict[str, Any]:
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": str(target), "timeout": HOOK_TIMEOUT}],
    }


def _read_settings(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc}") from exc
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise CliError(
            f"{path} is not valid JSON ({exc}). Fix it by hand, then re-run: bb install-hook"
        ) from exc
    if not isinstance(data, dict):
        raise CliError(f"{path} must contain a JSON object at the top level; it has a "
                       f"{type(data).__name__}")
    return data


def find_installed_hook(path: Path) -> tuple[bool, bool, str | None]:
    """Return (present, covers_bash, command) for this repo's guard in a settings file."""
    try:
        data = _read_settings(path)
    except CliError:
        return False, False, None
    target = guard_shim()
    entries = ((data.get("hooks") or {}).get("PreToolUse") or [])
    if not isinstance(entries, list):
        return False, False, None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for hook in entry.get("hooks") or []:
            if isinstance(hook, dict) and _same_command(hook.get("command"), target):
                return True, _matcher_covers_bash(entry.get("matcher")), hook.get("command")
    return False, False, None


def cmd_install_hook(args: argparse.Namespace) -> int:
    target = guard_shim()
    if not target.exists():
        raise CliError(f"the guard shim is missing: {target}\nThis build is incomplete.")
    if not os.access(target, os.X_OK):
        raise CliError(f"the guard shim is not executable.\n  chmod +x {target}")

    path = settings_file("project" if args.project else "global")
    data = _read_settings(path)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise CliError(f'{path}: "hooks" must be an object; fix it by hand and re-run')
    entries = hooks.setdefault("PreToolUse", [])
    if not isinstance(entries, list):
        raise CliError(f'{path}: "hooks.PreToolUse" must be a list; fix it by hand and re-run')

    present, covers_bash, _ = find_installed_hook(path)
    if present and covers_bash:
        if args.json:
            _dump({"settings": str(path), "changed": False, "installed": True})
        else:
            out(f"already installed in {path}")
            out("  bb doctor   # confirm the guard actually denies")
        return 0

    # Merge into an existing Bash entry when there is one, so a user's other
    # PreToolUse hooks keep running.
    merged = False
    for entry in entries:
        if isinstance(entry, dict) and str(entry.get("matcher", "")) == "Bash":
            entry.setdefault("hooks", [])
            if isinstance(entry["hooks"], list):
                entry["hooks"].append(
                    {"type": "command", "command": str(target), "timeout": HOOK_TIMEOUT}
                )
                merged = True
                break
    if not merged:
        entries.append(_hook_entry(target))

    path.parent.mkdir(parents=True, exist_ok=True)
    backup: Path | None = None
    if path.exists():
        backup = path.with_name(path.name + ".bak")
        shutil.copy2(path, backup)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)

    if args.json:
        _dump({"settings": str(path), "changed": True, "backup": str(backup) if backup else None,
               "command": str(target)})
        return 0
    out(f"installed the PreToolUse scope guard in {path}")
    if backup:
        out(f"  previous settings saved to {backup}")
    out(f"  command: {target}")
    out("  every Bash tool call is now checked against the armed engagement's scope")
    out("  bb doctor   # confirm it denies an out-of-scope command")
    return 0


# -- doctor -------------------------------------------------------------------


@dataclass
class Check:
    """One doctor line: what was tested, how it went, and how to fix it."""

    name: str
    level: str  # pass | warn | fail
    detail: str
    remedy: str | None = None


def _probe_urls(scope: Scope, limit: int = 5) -> list[str]:
    """URLs that the scope should allow, one per in-scope rule."""
    urls: list[str] = []
    for rule in scope.in_scope[:limit]:
        kind, value = rule.get("type"), str(rule.get("value", ""))
        if kind == "domain":
            urls.append(f"https://{value}/")
        elif kind == "wildcard":
            urls.append(f"https://{value}/" if rule.get("include_apex", True)
                        else f"https://www.{value}/")
        elif kind == "url_prefix":
            urls.append(value)
        elif kind == "cidr":
            try:
                net = ipaddress.ip_network(value)
                host = next(iter(net.hosts()), net.network_address)
                urls.append(f"https://{host}/")
            except (ValueError, StopIteration):
                continue
    return urls


def _check_enforcement(name: str | None) -> list[Check]:
    """The check that matters: prove the guard denies, and does not blanket-deny."""
    try:
        denied = guard.check_command(PROBE_OUT_OF_SCOPE, paths.REPO)
    except Exception as exc:
        return [
            Check(
                "enforcement",
                "fail",
                f"the scope guard crashed on a probe command: {type(exc).__name__}: {exc}",
                "this is a harness bug; the guard must never raise",
            )
        ]
    if denied.allowed:
        return [
            Check(
                "enforcement",
                "fail",
                f"the guard ALLOWED {PROBE_OUT_OF_SCOPE!r}. Out-of-scope commands are not "
                "being blocked.",
                "bb install-hook && bb use <engagement> && bb arm <engagement> --as '<you>'",
            )
        ]
    checks = [
        Check("enforcement", "pass",
              f"guard denies an out-of-scope target: {_shorten(denied.reasons[0], 80)}")
    ]

    if not name:
        return checks
    try:
        scope = _load_scope(name)
    except CliError:
        return checks
    probes = _probe_urls(scope)
    if not probes:
        return checks
    allowed_any = None
    for url in probes:
        result = guard.check_command(f"curl -sS {shlex.quote(url)}", paths.REPO)
        if result.allowed:
            checks.append(Check("enforcement (allow path)", "pass",
                                f"guard allows the in-scope target {url}"))
            allowed_any = url
            break
    if allowed_any is None:
        armed = armed_state(name).armed
        last = guard.check_command(f"curl -sS {shlex.quote(probes[0])}", paths.REPO)
        reason = _shorten(last.reasons[0] if last.reasons else "no reason given", 90)
        checks.append(
            Check(
                "enforcement (allow path)",
                "fail" if armed else "warn",
                f"the guard denies every in-scope target too ({reason})",
                f"bb arm {name} --as '<you>'" if not armed
                else f"bb scope show {name}   # an out_of_scope rule or a private range is "
                     "shadowing the whole scope",
            )
        )
    return checks


def _check_hook() -> list[Check]:
    target = guard_shim()
    checks: list[Check] = []
    if not target.exists():
        checks.append(Check("shims", "fail", f"{target} is missing", "this build is incomplete"))
    elif not os.access(target, os.X_OK):
        checks.append(Check("shims", "fail", f"{target} is not executable", f"chmod +x {target}"))
    else:
        checks.append(
            Check("shims", "pass", f"{paths.REPO / 'bin'}/bb and bb-guard are executable")
        )

    path = settings_file("global")
    present, covers_bash, command = find_installed_hook(path)
    if not present:
        # A warning, not a failure. `run_phase` spawns every phase with
        # `--settings <runtime>/settings.json`, a file outside the directory
        # the agent can write, and that file registers this same guard -- so a
        # hunt is guarded whether or not the global config mentions it. What
        # the global hook adds is cover for commands the OPERATOR types, and it
        # is not free: with no engagement selected it denies `curl`, `wget` and
        # `ssh` in every other project on this machine, while `git clone`,
        # `npm install` and `pip install` still reach the network because they
        # are not tools the guard parses. Calling that "not ready to hunt" was
        # wrong, and it pushed operators into a trade they had not been told
        # the price of.
        checks.append(
            Check("hook", "warn",
                  f"no PreToolUse hook pointing at {target} in {path}; hunts carry their own "
                  f"guard, so this only covers commands you type yourself",
                  "bb install-hook   # note: denies curl/wget/ssh everywhere when no "
                  "engagement is active")
        )
    elif not covers_bash:
        checks.append(
            Check("hook", "fail",
                  f"the guard is registered in {path} but its matcher does not cover Bash",
                  f'set "matcher": "Bash" on that entry in {path}')
        )
    else:
        checks.append(Check("hook", "pass", f"PreToolUse -> {command} ({path})"))
    return checks


def _chain_checks() -> list[Check]:
    """The audit log's hash chain, as doctor lines."""
    report = verify_audit_chain()
    if report.problems:
        return [
            Check(
                "audit chain",
                "fail",
                f"{len(report.problems)} break(s) in {report.path}: "
                f"{_shorten(report.problems[0], 120)}",
                f"keep the evidence (cp {report.path} {report.path}.tampered) and find what "
                f"edited it: bb doctor --verify-chain",
            )
        ]
    if not report.lines:
        return [Check("audit chain", "pass", f"empty log, nothing recorded yet ({report.path})")]
    detail = f"{report.chained} chained line(s) intact"
    if report.unchained:
        return [
            Check(
                "audit chain",
                "warn",
                f"{detail}, {report.unchained} line(s) carry no chain field",
                "every writer in this build chains, so unchained lines are either from an "
                "older log or from a writer added since; they are recorded but not "
                "tamper-evident on their own. Keep the log and check what wrote them: "
                "bb audit --tail 50",
            )
        ]
    return [Check("audit chain", "pass", f"{detail} ({report.path})")]


def _doctor_checks() -> list[Check]:
    checks: list[Check] = []

    version = ".".join(str(v) for v in sys.version_info[:3])
    if sys.version_info >= MIN_PYTHON:
        checks.append(Check("python", "pass", f"{version} at {sys.executable}"))
    else:
        checks.append(
            Check("python", "fail", f"{version} is older than "
                  f"{'.'.join(str(v) for v in MIN_PYTHON)}",
                  f"run the harness through {paths.REPO / 'bin' / 'bb'}")
        )

    venv_python = paths.REPO / ".venv" / "bin" / "python"
    if venv_python.exists():
        same = Path(sys.executable).resolve() == venv_python.resolve()
        checks.append(
            Check("venv", "pass" if same else "warn",
                  f"{venv_python}" + ("" if same else " exists but this process is not using it"),
                  None if same else f"run commands as {paths.REPO / 'bin' / 'bb'}")
        )
    else:
        checks.append(
            Check("venv", "fail", f"no virtualenv at {venv_python}",
                  f"python3 -m venv {paths.REPO / '.venv'} && "
                  f"{venv_python} -m pip install requests pyyaml mitmproxy")
        )

    for label, module, package in (("requests", "requests", "requests"),
                                   ("pyyaml", "yaml", "pyyaml")):
        try:
            importlib.import_module(module)
            checks.append(Check(label, "pass", "importable"))
        except ImportError as exc:
            checks.append(
                Check(label, "fail", f"not importable ({exc})",
                      f"{venv_python} -m pip install {package}")
            )

    claude = shutil.which("claude")
    checks.append(
        Check("claude", "pass", claude) if claude
        else Check("claude", "fail", "the claude binary is not on PATH; bb hunt cannot run a phase",
                   "install Claude Code, then re-run bb doctor")
    )
    mitmdump = shutil.which("mitmdump")
    checks.append(
        Check("mitmdump", "pass", mitmdump) if mitmdump
        else Check("mitmdump", "warn", "not on PATH; bb proxy is unavailable "
                   "(the sanctioned HTTP client still works)",
                   f"{venv_python} -m pip install mitmproxy")
    )

    checks.extend(_check_hook())

    name = paths.active_engagement()
    if not name:
        # Two different situations, and only one of them is a problem. With no
        # engagements at all, nothing is wrong: this is a fresh install, and
        # `bb go` creates and selects one in the same breath, so reporting
        # "not ready to hunt" sends a new operator looking for a fault that
        # does not exist. With engagements on disk and none selected, every
        # target really is denied until one is picked, which is worth a
        # failure.
        existing = paths.list_engagements()
        if existing:
            checks.append(
                Check("engagement", "fail",
                      f"{len(existing)} engagement(s) on disk and none selected, so every "
                      f"target is denied",
                      f"bb use {existing[0]}")
            )
        else:
            checks.append(
                Check("engagement", "warn",
                      "no engagements yet; one command creates, arms and hunts one",
                      "bb go '*.yourtarget.com'")
            )
    elif not paths.scope_path(name).exists():
        checks.append(
            Check("engagement", "fail", f"active engagement {name!r} has no "
                  f"{paths.scope_path(name)}", f"bb new {name} --program-url <url>")
        )
    else:
        checks.append(Check("engagement", "pass", f"{name} ({paths.engagement_dir(name)})"))

    if name:
        try:
            scope = _load_scope(name)
            checks.append(
                Check("scope", "pass",
                      f"{len(scope.in_scope)} in-scope rule(s), {len(scope.out_of_scope)} "
                      f"exclusion(s), {scope.rules['max_rps']} rps, "
                      f"{scope.rules['max_requests']} request cap")
            )
        except CliError as exc:
            checks.append(Check("scope", "fail", _shorten(str(exc).splitlines()[0], 100),
                                f"bb scope compile {name}"))
        # Nothing can be recorded without the store, and the proxy fails closed
        # on it, so the cause goes in the line rather than a wrapped message.
        db = paths.db_path(name)
        try:
            with Store(db) as store:
                stats = store.stats()
            checks.append(
                Check("store", "pass",
                      f"{stats['requests']} request(s), {stats['findings']} finding(s), "
                      f"{stats['evidence']} artifact(s), ${stats['cost_usd']:.2f} spent")
            )
        except Exception as exc:
            checks.append(
                Check("store", "fail",
                      f"{type(exc).__name__}: {_shorten(exc, 90)}  ({db})",
                      f"if the file is damaged: mv {db} {db}.broken  -  otherwise report "
                      f"the error above, nothing can be recorded until it opens")
            )

        state = armed_state(name)
        if state.armed:
            level = "warn" if (state.seconds_left or 0) < 1800 else "pass"
            checks.append(
                Check("armed", level, state.detail,
                      f"bb arm {name} --as '<you>'" if level == "warn" else None)
            )
        else:
            checks.append(Check("armed", "fail", state.detail,
                                f"bb arm {name} --as '{os.environ.get('USER', 'you')}'"))
    else:
        for item in ("scope", "store", "armed"):
            checks.append(Check(item, "warn", "no active engagement to check",
                                "bb use <engagement>"))

    checks.extend(_check_enforcement(name))
    checks.extend(_chain_checks())
    return checks


def cmd_verify_chain(args: argparse.Namespace) -> int:
    """`bb doctor --verify-chain`: just the audit log, in detail."""
    report = verify_audit_chain()
    if args.json:
        _dump(
            {
                "ok": report.ok,
                "path": str(report.path),
                "lines": report.lines,
                "chained": report.chained,
                "unchained": report.unchained,
                "problems": report.problems,
            }
        )
        return 1 if report.problems else 0

    out(f"audit log: {report.path}")
    if not report.lines:
        out("  empty: nothing has been recorded yet, so there is no chain to verify")
        out("  bb doctor      # confirm the PreToolUse hook is installed")
        return 0
    out(f"  {report.lines} line(s): {report.chained} chained, {report.unchained} unchained")
    for problem in report.problems:
        out(f"  BROKEN  {problem}")
    if report.problems:
        out("")
        out("The log is evidence, so the harness will not rewrite it to make the chain fit.")
        out(f"  cp {report.path} {report.path}.tampered   # keep it for review")
        out("  bb audit --tail 50                        # read around the break")
        return 1
    if report.unchained:
        out("")
        out("Unchained lines carry no `prev` of their own: an older log, or a writer added "
            "since this build. They are recorded but not tamper-evident on their own; the "
            "chain across the lines around them still holds, because `prev` hashes the "
            "previous line whatever shape it had.")
    out("")
    out("chain intact: no line was edited, inserted or removed after it was written")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    if getattr(args, "verify_chain", False):
        return cmd_verify_chain(args)
    checks = _doctor_checks()
    failed = [c for c in checks if c.level == "fail"]
    warned = [c for c in checks if c.level == "warn"]
    if args.json:
        _dump({"ok": not failed, "checks": [dataclasses.asdict(c) for c in checks]})
        return 1 if failed else 0
    width = max(len(c.name) for c in checks)
    for check in checks:
        mark = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}[check.level]
        out(f"{mark}  {check.name.ljust(width)}  {check.detail}")
        if check.remedy:
            out(f"      {' ' * width}  fix: {check.remedy}")
    out("")
    out(f"{len(checks) - len(failed) - len(warned)} pass, {len(warned)} warn, {len(failed)} fail")
    if failed:
        out("The harness is not ready to hunt. Fix the failures above, then re-run: bb doctor")
    return 1 if failed else 0


# -- parser -------------------------------------------------------------------


def _need_subcommand(parser: argparse.ArgumentParser) -> int:
    parser.print_help(sys.stderr)
    return 2


def _common() -> argparse.ArgumentParser:
    """Flags every subcommand accepts; SUPPRESS so the global value survives."""
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("-e", "--engagement", metavar="NAME", default=argparse.SUPPRESS,
                        help="engagement to act on (default: the active one)")
    shared.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="machine-readable output")
    return shared


def build_parser() -> argparse.ArgumentParser:
    shared = _common()
    parser = argparse.ArgumentParser(
        prog="bb",
        description="Bug bounty harness: scoped, evidence-backed, autonomous hunting.",
        epilog="Start with: bb doctor",
    )
    parser.add_argument("-e", "--engagement", metavar="NAME", default=None,
                        help="engagement to act on (default: the active one)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--version", action="version", version=f"bb {__version__}")
    parser.set_defaults(func=lambda a: _need_subcommand(parser))
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # -- one command ---------------------------------------------------------
    # Listed first because it is the one an operator starts from; everything
    # under it is the same sequence taken a step at a time.
    p = sub.add_parser(
        "go", parents=[shared],
        help="target in, hunt running: new + compile + arm + hunt, in one command",
        description="bb go '*.example.com' --budget-usd 40 --hours 8",
    )
    p.add_argument("target", nargs="+", metavar="TARGET",
                   help="domain, *.wildcard, CIDR or https:// URL prefix (quote the *)")
    p.add_argument("--name", metavar="NAME",
                   help="engagement to use (default: derived from the first target)")
    p.add_argument("--budget-usd", type=float, default=None, metavar="N",
                   help="hard spend ceiling for the hunt (default: none; the spend is "
                        "recorded, and the per-phase turn caps and --hours are what stop it)")
    p.add_argument("--no-budget", action="store_true",
                   help="the default, said out loud: no spend ceiling")
    p.add_argument("--hours", type=float, default=GO_HOURS, metavar="N",
                   help=f"how long the hunt may run (default {GO_HOURS:g}); the "
                        f"attestation is armed for this plus {GO_ARM_MARGIN_HOURS:g}h")
    p.add_argument("--model", default=GO_MODEL, help=f"default {GO_MODEL}")
    p.add_argument("--effort", default=GO_EFFORT, choices=EFFORT_LEVELS,
                   help=f"reasoning effort for every phase (default {GO_EFFORT})")
    p.add_argument("--as", dest="attested_by", metavar="WHO",
                   help="who is asserting that this testing is authorized (default: you)")
    p.add_argument("--program-url", help="the program policy page this relies on")
    p.add_argument("--platform", help="hackerone, bugcrowd, intigriti, self, ...")
    p.add_argument("--phases", metavar="A,B", help="only these phase keys, comma separated")
    p.add_argument("--max-retries", type=int, default=1, help="retries per failed phase")
    p.add_argument("--sandbox", action="store_true",
                   help="require egress containment, exactly as bare `bb hunt` does")
    p.add_argument("--allow-unpriced", action="store_true",
                   help="continue when the subprocess reports no cost")
    p.add_argument("--dry-run", action="store_true",
                   help="print the plan and the derived name; create, compile and start "
                        "nothing")
    p.set_defaults(func=cmd_go)

    # -- lifecycle ----------------------------------------------------------
    p = sub.add_parser("new", parents=[shared], help="create an engagement")
    p.add_argument("name")
    p.add_argument("--program-url", help="the program page that authorizes this testing")
    p.add_argument("--platform", help="hackerone, bugcrowd, intigriti, self, ...")
    p.add_argument("--target", action="append", metavar="T", help="seed in-scope target (repeat)")
    p.add_argument("--use", action="store_true", help="also make it the active engagement")
    p.set_defaults(func=cmd_new)

    p = sub.add_parser("list", parents=[shared], help="list engagements")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("use", parents=[shared], help="select the active engagement")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_use)

    p = sub.add_parser("status", parents=[shared], help="scope, armed state and store stats")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_status)

    # -- scope --------------------------------------------------------------
    scope_p = sub.add_parser("scope", parents=[shared], help="compile, show and test the scope")
    scope_p.set_defaults(func=lambda a: _need_subcommand(scope_p))
    scope_sub = scope_p.add_subparsers(dest="scope_command", metavar="<subcommand>")

    p = scope_sub.add_parser("compile", parents=[shared], help="scope.yaml -> scope.lock.json")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_scope_compile)

    p = scope_sub.add_parser("show", parents=[shared], help="print the compiled scope")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_scope_show)

    p = scope_sub.add_parser("check", parents=[shared],
                             help="decide targets against the scope (exit 1 if any is denied)")
    p.add_argument("target", nargs="+")
    p.set_defaults(func=cmd_scope_check)

    # -- authorization ------------------------------------------------------
    p = sub.add_parser("arm", parents=[shared], help="attest authorization and set an expiry")
    p.add_argument("name", nargs="?")
    p.add_argument("--as", dest="attested_by", required=True, metavar="WHO",
                   help="who is attesting that this testing is authorized")
    p.add_argument("--hours", type=int, default=12, help="how long the attestation lasts")
    p.add_argument("--policy-url", help="link to the program policy being relied on")
    p.set_defaults(func=cmd_arm)

    p = sub.add_parser("disarm", parents=[shared], help="revoke the attestation immediately")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_disarm)

    # -- hunting ------------------------------------------------------------
    p = sub.add_parser("hunt", parents=[shared], help="run the autonomous hunt loop")
    p.add_argument("name", nargs="?")
    p.add_argument("--phases", metavar="A,B", help="only these phase keys, comma separated")
    p.add_argument("--budget-usd", type=float, default=None, metavar="N",
                   help=f"hard spend ceiling for the hunt (default {HUNT_BUDGET_USD:g})")
    p.add_argument("--no-budget", action="store_true",
                   help="run with no spend ceiling; the cost is still recorded and "
                        "reported, and the per-phase turn caps and --deadline stop the hunt")
    p.add_argument("--deadline", metavar="ISO8601", help="hard stop, e.g. 2026-10-30T23:00:00Z")
    p.add_argument("--model", default=GO_MODEL)
    p.add_argument("--effort", default=GO_EFFORT, choices=EFFORT_LEVELS)
    p.add_argument("--max-retries", type=int, default=1, help="retries per failed phase")
    p.add_argument("--resume", action="store_true", help="skip phases that already finished ok")
    p.add_argument("--dry-run", action="store_true", help="plan the hunt without running it")
    p.add_argument("--unsandboxed", action="store_true",
                   help="run without egress containment; the scope guard becomes the only barrier")
    p.add_argument("--allow-unpriced", action="store_true",
                   help="continue when the subprocess reports no cost")
    p.set_defaults(func=cmd_hunt)

    p = sub.add_parser("phase", parents=[shared], help="run one phase")
    p.add_argument("key")
    p.add_argument("name", nargs="?")
    p.add_argument("--budget-usd", type=float, default=None, metavar="N",
                   help=f"hard spend ceiling for the phase (default {HUNT_BUDGET_USD:g})")
    p.add_argument("--no-budget", action="store_true",
                   help="run with no spend ceiling; the cost is still recorded")
    p.add_argument("--deadline", metavar="ISO8601")
    p.add_argument("--model", default=GO_MODEL)
    p.add_argument("--effort", default=GO_EFFORT, choices=EFFORT_LEVELS)
    p.add_argument("--max-retries", type=int, default=1)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--unsandboxed", action="store_true")
    p.add_argument("--allow-unpriced", action="store_true")
    p.set_defaults(func=cmd_phase)

    p = sub.add_parser(
        "req", parents=[shared],
        help="one scoped, recorded request",
        description="bb req GET https://target/path -H 'K: V' -d @body --actor attacker",
    )
    p.add_argument("args", nargs=argparse.REMAINDER, metavar="METHOD URL [options]")
    p.set_defaults(func=cmd_req, bounded="bb req")

    # -- findings -----------------------------------------------------------
    finding_p = sub.add_parser("finding", parents=[shared], help="findings")
    finding_p.set_defaults(func=lambda a: _need_subcommand(finding_p))
    finding_sub = finding_p.add_subparsers(dest="finding_command", metavar="<subcommand>")

    p = finding_sub.add_parser("add", parents=[shared], help="record a candidate finding")
    p.add_argument("--uid", help="stable reference (default: F-001, F-002, ...)")
    p.add_argument("--title", required=True)
    p.add_argument("--class", dest="vuln_class", required=True, metavar="CLASS",
                   help="idor, bac, auth-bypass, xss, ssrf, ...")
    p.add_argument("--host")
    p.add_argument("--endpoint")
    # The sentinel literals are accepted as choices and normalised away in
    # main(); argparse would otherwise answer `--severity none` with a usage
    # dump, which tells an agent nothing about what to pass instead.
    p.add_argument("--severity", choices=(*SEVERITIES, *OMITTED_CHOICES), metavar="SEVERITY",
                   type=_folded, help="info, low, medium, high or critical")
    p.add_argument("--summary")
    p.add_argument("--impact")
    p.add_argument("--repro", help="numbered steps naming a concrete URL")
    p.add_argument("--remediation")
    p.add_argument("--dedup-key")
    p.add_argument("--phase", dest="phase", help="phase key that found it")
    p.set_defaults(func=cmd_finding_add)

    p = finding_sub.add_parser("list", parents=[shared], help="list and search findings")
    p.add_argument("name", nargs="?", help="engagement to list (default: the active one)")
    p.add_argument("--state", choices=(*STATES, *OMITTED_CHOICES), metavar="STATE",
                   type=_folded, help=f"only this state ({', '.join(STATES)})")
    p.add_argument("--search", "--query", "-q", dest="query", metavar="FTS",
                   help="full-text search over title, summary, impact and repro")
    p.add_argument("--limit", type=int, default=25, metavar="N",
                   help="most relevant N search hits (default 25)")
    p.set_defaults(func=cmd_finding_list, bounded="bb finding list")

    p = finding_sub.add_parser("show", parents=[shared],
                               help="one finding with its evidence and gates")
    p.add_argument("ref", help="uid or numeric id")
    p.set_defaults(func=cmd_finding_show, bounded="bb finding show")

    p = finding_sub.add_parser("set", parents=[shared], help="edit fields of a finding")
    p.add_argument("ref")
    p.add_argument("--title")
    p.add_argument("--class", dest="vuln_class", metavar="CLASS")
    p.add_argument("--host")
    p.add_argument("--endpoint")
    p.add_argument("--severity", choices=(*SEVERITIES, *OMITTED_CHOICES), metavar="SEVERITY",
                   type=_folded,
                   help="info or low only once a --cvss vector is what decides the rest")
    # `--cvss` is the spelling the contract and triage.py's remedies use; it was
    # only reachable before as an argparse abbreviation of --cvss-vector, which
    # would have broken the moment another --cvss* flag was added.
    p.add_argument("--cvss", "--cvss-vector", dest="cvss_vector", metavar="VECTOR",
                   help="CVSS v3.1 base vector; severity is computed from it")
    p.add_argument("--summary")
    p.add_argument("--impact")
    p.add_argument("--repro")
    p.add_argument("--remediation")
    p.add_argument("--dedup-key")
    # advance(..., 'validated') refuses while these are empty, so they have to be
    # settable from the CLI or the ladder has a rung nothing can climb.
    p.add_argument("--counterevidence",
                   help="what you tested that could have shown this is not a bug")
    p.add_argument("--confidence", choices=CONFIDENCE_LEVELS, type=_folded)
    p.add_argument("--confidence-rationale")
    p.add_argument("--severity-change-conditions",
                   help="what would make this more or less severe than it is rated")
    p.add_argument("--delivery",
                   choices=DELIVERY_MODES,
                   help="harness_only is the honest answer when the repro needs harness state")
    p.set_defaults(func=cmd_finding_set)

    p = finding_sub.add_parser("advance", parents=[shared], help="move a finding to a new state")
    p.add_argument("ref")
    p.add_argument("state", choices=STATES)
    p.add_argument("--reason")
    # CONTRACT v2 item 6: a block names the condition that clears it. The store
    # has taken this since `blocked` landed and nothing could pass it, so the
    # condition could only be stated inside --reason, where no later run reads it.
    p.add_argument("--unblock-condition", dest="unblock_condition", metavar="TEXT",
                   help="with `blocked`: what would let this resume")
    p.set_defaults(func=cmd_finding_advance)

    p = finding_sub.add_parser(
        "freeze", parents=[shared],
        help="pin the claim 06-verify re-proves, so a later edit cannot ship unverified",
        description="bb finding freeze F-001        # before the independent pass runs",
    )
    p.add_argument("ref")
    p.add_argument("--check", action="store_true",
                   help="do not pin; report whether the claim still matches its pin")
    p.set_defaults(func=cmd_finding_freeze)

    p = finding_sub.add_parser(
        "merge", parents=[shared], help="collapse a duplicate into the finding it duplicates",
        description="bb finding merge F-004 --into F-001 --reason '<one root cause>'",
    )
    p.add_argument("ref", metavar="DUPLICATE")
    p.add_argument("--into", required=True, metavar="CANONICAL",
                   help="the finding that survives and gets reported")
    p.add_argument("--reason", required=True,
                   help="what makes them one bug; it is recorded on both findings")
    p.set_defaults(func=cmd_finding_merge)

    p = finding_sub.add_parser(
        "dedupe", parents=[shared],
        help="the harness's duplicate comparison, and how to settle an ambiguous pair",
    )
    p.add_argument("ref")
    p.add_argument("--against", metavar="UID", help="the other finding in the pair")
    # Both vocabularies belong to triage and are checked against it at parse
    # time; the words in the help text are pinned to that list by a test, so a
    # third verdict added there cannot leave this reading as if there were two.
    p.add_argument("--verdict", type=vocabulary("triage", "DEDUPE_VERDICTS"), metavar="VERDICT",
                   help="duplicate, distinct or undetermined")
    p.add_argument("--because", metavar="TEXT", help="required with --verdict")
    p.add_argument("--not-duplicate-because", dest="not_duplicate_because", metavar="TEXT",
                   help="operator override: these are not duplicates, and here is why")
    p.add_argument("--source", type=vocabulary("triage", "DEDUPE_SOURCES"), default="judge",
                   metavar="WHO", help="judge or operator (default: judge)")
    p.add_argument("--write-key", action="store_true",
                   help="store the computed key in findings.dedup_key and print it")
    p.set_defaults(func=cmd_finding_dedupe, bounded="bb finding dedupe")

    # -- evidence -----------------------------------------------------------
    ev_p = sub.add_parser("evidence", parents=[shared], help="artifacts backing a finding")
    ev_p.set_defaults(func=lambda a: _need_subcommand(ev_p))
    ev_sub = ev_p.add_subparsers(dest="evidence_command", metavar="<subcommand>")

    p = ev_sub.add_parser("add", parents=[shared], help="attach a real artifact")
    p.add_argument("finding")
    p.add_argument("kind", choices=EVIDENCE_KINDS)
    p.add_argument("path", nargs="?", help="file on disk; hashed at capture time")
    p.add_argument("--request-id", type=int, help="id from the store, as printed by bb req")
    # gate_evidence_roles reads this and its remedy names the flag, so without
    # it an access-control finding could not be made to satisfy its own gate.
    p.add_argument("--role", choices=EVIDENCE_ROLES, default="context",
                   help="baseline = the control working, attack = the control bypassed, "
                        "verification = the effect seen from the owner's side, "
                        "context = everything else (default)")
    p.add_argument("--caption")
    p.set_defaults(func=cmd_evidence_add)

    p = ev_sub.add_parser("list", parents=[shared], help="evidence attached to a finding")
    p.add_argument("finding")
    p.set_defaults(func=cmd_evidence_list, bounded="bb evidence list")

    p = ev_sub.add_parser("verify", parents=[shared],
                          help="re-hash every artifact (exit 1 if any changed or vanished)")
    p.add_argument("finding")
    p.set_defaults(func=cmd_evidence_verify)

    # -- prerequisites ------------------------------------------------------
    prereq_p = sub.add_parser(
        "prereq", parents=[shared],
        help="what the attack needs, and whether an attacker can get it",
    )
    prereq_p.set_defaults(func=lambda a: _need_subcommand(prereq_p))
    prereq_sub = prereq_p.add_subparsers(dest="prereq_command", metavar="<subcommand>")

    p = prereq_sub.add_parser(
        "add", parents=[shared], help="record one prerequisite and its reachability",
        description="Owning both test accounts proves the authorization check is broken and "
                    "is zero evidence an attacker can obtain the identifier. Nothing reaches "
                    "'verified' until every prerequisite is reachable and cites the request "
                    "that acquired it as the attacker.",
    )
    p.add_argument("finding")
    p.add_argument("name", help="e.g. 'victim document id'")
    p.add_argument("--attacker-start", dest="attacker_start",
                   help="what the attacker is assumed to hold before this step")
    p.add_argument("--acquisition", help="how an attacker obtains it")
    p.add_argument("--request-id", dest="request_id", type=int,
                   help="the recorded request that acquired it, made as the attacker")
    p.add_argument("--verdict", choices=PREREQUISITE_VERDICTS, default="not_reachable",
                   help="default not_reachable: a prerequisite nobody traced is not reachable")
    p.add_argument("--searched", help="where you looked for a leak, so a later phase need not")
    p.set_defaults(func=cmd_prereq_add)

    p = prereq_sub.add_parser("list", parents=[shared], help="the ledger for one finding")
    p.add_argument("finding")
    p.set_defaults(func=cmd_prereq_list, bounded="bb prereq list")

    # -- angles -------------------------------------------------------------
    angle_p = sub.add_parser("angle", parents=[shared], help="the ledger of what has been tried")
    angle_p.set_defaults(func=lambda a: _need_subcommand(angle_p))
    angle_sub = angle_p.add_subparsers(dest="angle_command", metavar="<subcommand>")

    p = angle_sub.add_parser(
        "add", parents=[shared], help="record an angle, including the ones that found nothing",
        description="Outcomes: " + ", ".join(STORE_ANGLE_OUTCOMES)
                    + ". ruled_out needs --control, open_gap needs --next-test. The v1 words ("
                    + ", ".join(w for w in ANGLE_OUTCOME_ALIASES if w not in STORE_ANGLE_OUTCOMES)
                    + ") are still accepted and stored as their v2 equivalent.",
    )
    p.add_argument("surface", help="host, or host+path")
    p.add_argument("vuln_class", metavar="class")
    p.add_argument("technique")
    p.add_argument("outcome", choices=ANGLE_OUTCOMES, metavar="OUTCOME",
                   help=", ".join(STORE_ANGLE_OUTCOMES))
    p.add_argument("--control", metavar="WHAT",
                   help="required for ruled_out: the defence you observed holding")
    p.add_argument("--next-test", dest="next_test", metavar="WHAT",
                   help="required for open_gap: the concrete request to try next")
    p.add_argument("--source", choices=ANGLE_SOURCES, default="agent",
                   help="agent = work you did; machine = derived from the request log")
    p.add_argument("--phase")
    p.add_argument("--note")
    p.set_defaults(func=cmd_angle_add)

    p = angle_sub.add_parser("list", parents=[shared], help="angles tried so far")
    p.add_argument("--surface")
    p.set_defaults(func=cmd_angle_list, bounded="bb angle list")

    # -- accounts -----------------------------------------------------------
    acct_p = sub.add_parser("account", parents=[shared], help="test accounts")
    acct_p.set_defaults(func=lambda a: _need_subcommand(acct_p))
    acct_sub = acct_p.add_subparsers(dest="account_command", metavar="<subcommand>")

    p = acct_sub.add_parser("add", parents=[shared], help="record a test account")
    p.add_argument("label")
    p.add_argument("--role", required=True, help="attacker, victim, admin, anon, or an app role")
    p.add_argument("--email")
    p.add_argument("--secret-ref",
                   help="path under sensitive/, or an env var name - never the secret")
    p.add_argument("--note")
    p.set_defaults(func=cmd_account_add)

    p = acct_sub.add_parser("list", parents=[shared], help="recorded accounts")
    p.set_defaults(func=cmd_account_list, bounded="bb account list")

    # -- secrets ------------------------------------------------------------
    secret_p = sub.add_parser("secret", parents=[shared],
                              help="credential labels; values stay in sensitive/")
    secret_p.set_defaults(func=lambda a: _need_subcommand(secret_p))
    secret_sub = secret_p.add_subparsers(dest="secret_command", metavar="<subcommand>")

    p = secret_sub.add_parser(
        "put", parents=[shared],
        help="record a credential and get a secret:// reference for it",
        description="The value is read from stdin, so it stays out of argv, `ps` and the "
                    "audit log:  printf '%s' '<value>' | bb secret put attacker-session",
    )
    p.add_argument("label", help="what to call it, e.g. attacker-session")
    p.add_argument("--from-file", metavar="PATH", help="read the value from a file instead")
    p.add_argument("--value", help="the value inline; it lands in your shell history")
    p.add_argument("--note")
    p.set_defaults(func=cmd_secret_put)

    p = secret_sub.add_parser("list", parents=[shared],
                              help="recorded labels and hashes, never values")
    p.set_defaults(func=cmd_secret_list)

    # -- objects ------------------------------------------------------------
    obj_p = sub.add_parser("object", parents=[shared],
                           help="objects whose owner is known, for access-control proof")
    obj_p.set_defaults(func=lambda a: _need_subcommand(obj_p))
    obj_sub = obj_p.add_subparsers(dest="object_command", metavar="<subcommand>")

    p = obj_sub.add_parser("add", parents=[shared], help="record an object and its owner")
    # The label is positional, but triage.py's remedies and the phase prompts spell
    # it --label/--owner-account; both spellings are accepted so a remedy an agent
    # is told to run is never a dead end.
    p.add_argument("label", nargs="?")
    p.add_argument("--label", dest="label_flag", help=argparse.SUPPRESS)
    p.add_argument("--kind", required=True, help="order, document, user, ...")
    p.add_argument("--identifier", required=True)
    p.add_argument("--owner", "--owner-account", required=True, metavar="ACCOUNT",
                   help="account label that owns it")
    p.add_argument("--expected-access")
    p.add_argument("--created-by-request", type=int)
    p.add_argument("--note")
    p.set_defaults(func=cmd_object_add)

    p = obj_sub.add_parser("list", parents=[shared], help="recorded objects")
    p.add_argument("--owner")
    p.set_defaults(func=cmd_object_list, bounded="bb object list")

    # -- gate / report ------------------------------------------------------
    p = sub.add_parser(
        "gate", parents=[shared],
        help="run the deterministic gates (exit 1 if any finding fails)",
        description="bb gate <finding> | --all | waive <f> <g> | waivers | waive-request <f> <g>",
    )
    # One positional list, dispatched in cmd_gate. `bb gate <finding>` and
    # `bb gate --all` are named in gate rationales, in the prompts and in the
    # README, so this parser cannot become a subparser group: argparse would
    # then reject every finding reference as an invalid choice.
    p.add_argument("words", nargs="*",
                   metavar="<finding> | waive <finding> <gate> | waivers | "
                           "waive-request <finding> <gate>")
    p.add_argument("--all", action="store_true", help="every finding in state 'verified'")
    p.add_argument("--state", help="with --all: gate this state instead, or 'any'")
    p.add_argument("--target", default=DEFAULT_GATE_TARGET, metavar="STATE",
                   choices=GATE_TARGETS,
                   help="the rung being guarded; it decides which gates run "
                        f"(default: {DEFAULT_GATE_TARGET}, which runs all of them)")
    p.add_argument("--reason", metavar="TEXT",
                   help="with waive / waive-request: why the requirement cannot be met")
    p.add_argument("--as", dest="who", metavar="WHO",
                   help="with waive: who is standing the gate down; it is named in the report")
    p.add_argument("--hours", type=float, metavar="N",
                   help="with waive: how long it lasts, clamped to the engagement's own expiry")
    # `nargs="*"` so both spellings parse: `bb gate waive --revoke <f> <g> --as
    # <who>`, which is what bbh.waiver's own refusal text writes, and `bb gate
    # waive <f> <g> --revoke --as <who>`, which is how every other command here
    # puts its flags after its positionals. With `action="store_true"` the first
    # form dies on "unrecognized arguments": argparse cannot hand a `nargs="*"`
    # positional two words that arrive after an option.
    p.add_argument("--revoke", nargs="*", default=None, metavar="FINDING GATE",
                   help="with waive: remove a granted waiver instead of granting one")
    p.add_argument("--asked-by", dest="asked_by", metavar="WHO",
                   help="with waive-request: who is asking (default: the running phase)")
    p.set_defaults(func=cmd_gate, bounded="bb gate")

    p = sub.add_parser("report", parents=[shared], help="render reports for gated findings")
    p.add_argument("ref", nargs="?")
    p.add_argument("--all", action="store_true", help="every finding in state gated or ready")
    p.add_argument("--state", help="with --all: report this state instead, or 'any'")
    p.add_argument("--stdout", action="store_true", help="print markdown instead of writing files")
    p.add_argument("--summary", action="store_true", help="one summary across all findings")
    p.set_defaults(func=cmd_report)

    # -- coverage / handoff -------------------------------------------------
    cov_p = sub.add_parser(
        "coverage", parents=[shared],
        help="what has nothing tested it, derived from the request log",
        description="bb coverage | bb coverage --class idor | "
                    "bb coverage reason race '<why nothing is eligible>'",
        epilog="Takes the engagement through -e/--engagement, like every other command.",
    )
    cov_p.add_argument("--class", dest="vuln_class", metavar="CLASS",
                       help="one class: every surface still untested for it")
    cov_p.add_argument("--require-clean", action="store_true",
                       help="exit 1 unless every class is closed or explained")
    cov_p.add_argument("--refresh", action="store_true",
                       help="rebuild the surface inventory first and say what it found")
    cov_p.set_defaults(func=cmd_coverage, bounded="bb coverage")
    cov_sub = cov_p.add_subparsers(dest="coverage_command", metavar="<subcommand>")

    p = cov_sub.add_parser(
        "reason", parents=[shared],
        help="record why a class has no eligible surface",
        description="An empty eligible set reads as 'never routed', not as 'clean'.",
    )
    p.add_argument("vuln_class", metavar="CLASS")
    p.add_argument("reason", metavar="TEXT")
    p.add_argument("--phase", metavar="KEY", help="the phase recording it")
    p.set_defaults(func=cmd_coverage_reason)

    handoff_p = sub.add_parser("handoff", parents=[shared],
                               help="the mechanical check on a phase's deliverable")
    handoff_p.set_defaults(func=lambda a: _need_subcommand(handoff_p))
    handoff_sub = handoff_p.add_subparsers(dest="handoff_command", metavar="<subcommand>")

    p = handoff_sub.add_parser(
        "write", parents=[shared],
        help="validate a phase's handoff and print the coverage gaps with it",
        description="Exit 1 on a handoff problem. Coverage gaps never fail it: work was "
                    "still done, and the gaps are what the next phase dispatches against.",
    )
    p.add_argument("phase", metavar="PHASE", help="the phase key, e.g. 02-sweep")
    p.set_defaults(func=cmd_handoff_write, bounded="bb handoff write")

    # -- proxy / audit / setup ----------------------------------------------
    proxy_p = sub.add_parser("proxy", parents=[shared], help="scope-enforcing intercept proxy")
    proxy_p.set_defaults(func=lambda a: _need_subcommand(proxy_p))
    proxy_sub = proxy_p.add_subparsers(dest="proxy_command", metavar="<subcommand>")

    # Positionally as well as through -e, for the same reason `sandbox` takes
    # it: bbh/sandbox.py prints `bb proxy start <engagement> --listen-host ...`
    # as the next command to run, four times, and a remedy the parser rejects
    # costs an unattended agent a turn and teaches it the harness is unreliable.
    p = proxy_sub.add_parser("start", parents=[shared], help="start mitmdump with the addon")
    p.add_argument("name", nargs="?")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--listen-host", default="127.0.0.1")
    p.add_argument("--phase", metavar="KEY",
                   help=f"phase recorded on captured requests (default: the phase the store "
                        f"has running, else {DEFAULT_PROXY_PHASE})")
    p.set_defaults(func=cmd_proxy_start)

    p = proxy_sub.add_parser("stop", parents=[shared], help="stop the proxy")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_proxy_stop)

    p = proxy_sub.add_parser("status", parents=[shared], help="is the proxy running")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_proxy_status)

    # -- process registry ---------------------------------------------------
    proc_p = sub.add_parser("proc", parents=[shared],
                            help="processes the harness started and can prove it started")
    proc_p.set_defaults(func=lambda a: _need_subcommand(proc_p))
    proc_sub = proc_p.add_subparsers(dest="proc_command", metavar="<subcommand>")

    p = proc_sub.add_parser(
        "register", parents=[shared], help="record a pid with proof of its identity",
        description="bb proc register 4821 --kind proxy --port 8080",
    )
    p.add_argument("pid", type=int)
    p.add_argument("--kind", required=True, type=vocabulary("proc", "PROC_KINDS"),
                   metavar="KIND", help="proxy, browser, scan, tunnel or other")
    p.add_argument("--port", type=int)
    p.add_argument("--note")
    p.set_defaults(func=cmd_proc_register)

    p = proc_sub.add_parser("list", parents=[shared], help="what is registered")
    p.add_argument("--kind", type=vocabulary("proc", "PROC_KINDS"), metavar="KIND")
    p.set_defaults(func=cmd_proc_list, bounded="bb proc list")

    p = proc_sub.add_parser(
        "forget", parents=[shared],
        help="drop rows without signalling anything",
        description="For a process someone else already stopped. It kills nothing.",
    )
    p.add_argument("pid", type=int, nargs="+")
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_proc_forget)

    p = sub.add_parser(
        "cleanup", parents=[shared],
        help="stop registered processes whose identity still matches (exit 2 if any survive)",
        description="With no filter: every process the harness registered, in any engagement.",
    )
    p.add_argument("--kind", type=vocabulary("proc", "PROC_KINDS"), metavar="KIND")
    p.add_argument("--pid", type=int, action="append", metavar="N",
                   help="only these pids; repeat the flag")
    p.add_argument("--dry-run", action="store_true", help="say what would be signalled")
    p.add_argument("--grace", type=float, metavar="SECONDS",
                   help="how long to wait between SIGTERM and SIGKILL")
    p.set_defaults(func=cmd_cleanup, bounded="bb cleanup")

    sandbox_p = sub.add_parser("sandbox", parents=[shared],
                               help="egress containment for unattended hunts")
    sandbox_p.set_defaults(func=lambda a: _need_subcommand(sandbox_p))
    sandbox_sub = sandbox_p.add_subparsers(dest="sandbox_command", metavar="<subcommand>")

    # Each takes the engagement positionally as well as through -e, because
    # runner.py's own refusal text tells the operator to run
    # `bb sandbox up <engagement> && bb sandbox verify <engagement>`.
    p = sandbox_sub.add_parser("up", parents=[shared], help="bring up the engagement's namespace")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_sandbox_up)

    p = sandbox_sub.add_parser("down", parents=[shared], help="tear it down")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_sandbox_down)

    p = sandbox_sub.add_parser("verify", parents=[shared],
                               help="is egress contained (exit 1 if not)")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_sandbox_verify)

    p = sandbox_sub.add_parser("status", parents=[shared], help="alias for verify")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_sandbox_verify)

    p = sub.add_parser("audit", parents=[shared], help="recent guard decisions")
    p.add_argument("--tail", type=int, default=20, metavar="N")
    p.add_argument("--denied", action="store_true", help="only denials")
    p.set_defaults(func=cmd_audit, bounded="bb audit")

    p = sub.add_parser("doctor", parents=[shared],
                       help="check dependencies, hook installation and live enforcement")
    p.add_argument("--verify-chain", action="store_true",
                   help="verify the audit log's hash chain and report any break")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("install-hook", parents=[shared],
                       help="merge the PreToolUse guard into settings.json")
    p.add_argument("--global", dest="global_scope", action="store_true", default=True,
                   help="write ~/.claude/settings.json (default)")
    p.add_argument("--project", action="store_true",
                   help="write ./.claude/settings.json instead")
    p.set_defaults(func=cmd_install_hook)

    return parser


# -- entrypoint ---------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    # On stderr, not stdout: a --json caller still gets a parseable document,
    # and an agent still gets told why its filter did nothing.
    for note in normalize_optional(args, optional_dests(parser, args)):
        print(f"bb: {note}", file=sys.stderr)
    if getattr(args, "engagement", None):
        os.environ["BBH_ENGAGEMENT"] = str(args.engagement)
    label = getattr(args, "bounded", None)
    try:
        if not label:
            return int(args.func(args) or 0)
        with bounded_output(label, json_mode=json_mode(args)):
            return int(args.func(args) or 0)
    except BrokenPipeError:
        return 0
    except (CliError, RuntimeError, ScopeError, OSError) as exc:
        # StoreError, RunnerError and the engagement module's refusals are all
        # RuntimeErrors whose text is already written for the reader.
        print(f"bb: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        if os.environ.get("BBH_DEBUG"):
            raise
        print(
            f"bb: unexpected {type(exc).__name__}: {exc}\n"
            f"    re-run with BBH_DEBUG=1 for the traceback, then report it",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
