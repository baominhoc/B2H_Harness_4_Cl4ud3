"""Engagement lifecycle: create, compile, arm, disarm, select, report status.

An engagement is a directory and two files that matter: scope.yaml, which a
human writes and reads, and the signed lock compiled from it, which every
enforcement layer reads and nobody edits by hand. This module is the only
writer of either, so the invariant "the lock is exactly what the author
approved" holds in one place instead of being re-checked everywhere. The lock
is signed on the way out and lives outside the engagement directory, so the
agent working inside that directory cannot widen its own scope.

Arming is a separate, expiring act on purpose. Compiling a scope says "these
are the assets"; arming says "I attest that I am authorized to test them, now".
The attestation carries an expiry, so an engagement nobody remembers to close
goes cold by itself: the guard, the HTTP client and the proxy all refuse the
moment expires_at passes, and the only way back is to attest again.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from string import Template
from typing import Any, Iterable

from . import paths
from .scope import Scope, ScopeError, compile_rule, compile_scope_file, sign_lock
from .store import Store

ATTESTATION = "I confirm I am authorized to test the assets in this scope under {program_url}."

DEFAULT_ARM_HOURS = 12
MAX_ARM_HOURS = 168  # one week: longer than any run that is still "now"

_ISO = "%Y-%m-%dT%H:%M:%SZ"

# Same name rule scope.compile_scope enforces, applied earlier so a bad name
# cannot reach engagement_dir() and escape the engagements directory.
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")

# A value may only be written as a plain YAML scalar when it starts with a
# letter and holds no indicator character. Anything starting with a digit is
# quoted, because YAML 1.1 reads 2026-10-30T12:00:00Z back as a datetime and
# 198.51.100.0 as something other than the string that was written.
_PLAIN_SAFE = re.compile(r"^[A-Za-z][A-Za-z0-9._/:@+-]*$")

# ... and these words come back as booleans or null.
_YAML_WORDS = frozenset({"y", "n", "yes", "no", "true", "false", "on", "off", "null", "none"})

_AUTH_KEY_RE = re.compile(r"^authorization\s*:")


class EngagementError(RuntimeError):
    """A lifecycle problem, worded as what is wrong plus the command that fixes it."""


# -- scope.yaml template ----------------------------------------------------


def _yaml_scalar(value: str | None) -> str:
    """Render one value for scope.yaml. None becomes an empty (null) field."""
    if value is None:
        return ""
    text = str(value)
    plain = (
        _PLAIN_SAFE.match(text)
        and not text.endswith(":")
        and text.lower() not in _YAML_WORDS
    )
    return text if plain else "'" + text.replace("'", "''") + "'"


_TEMPLATE = Template(
    """\
# scope.yaml -- the authorization boundary for this engagement.
#
#   out_of_scope ALWAYS wins, and anything not listed in in_scope is DENIED.
#   There is no implicit scope: an asset you forget to list here cannot be
#   reached by the guard, the HTTP client or the proxy. That is deliberate.
#
# Nothing reads this file at run time: every enforcement layer reads the signed
# lock compiled from it. Compile after each edit, try a target against the
# result, and attest that you are authorized before anything will run.
#
#     bb scope compile $engagement
#     bb scope check https://www.example.com/login
#     bb arm $engagement --as "your name"

engagement: $engagement

# The platform and the policy page you are testing under. program_url is
# required before `bb arm` will attest anything: the attestation names it.
platform:$platform
program_url:$program_url

# -- in_scope ---------------------------------------------------------------
#
# Four rule types. A bare string infers its type; a mapping states the type and
# can carry a note, which is quoted back in deny messages.
#
#   domain      www.example.com            exactly this host, nothing else
#   wildcard    "*.example.com"            any subdomain, and the apex as well
#   cidr        198.51.100.0/24            any address inside the network
#   url_prefix  https://example.com/api/   only URLs starting with the prefix
#
# Quote anything that starts with * -- YAML reads a bare * as an alias.
in_scope:$in_scope

# -- out_of_scope -----------------------------------------------------------
#
# Checked first, and it always wins, even over a more specific in_scope rule.
# Copy the program's exclusions here verbatim. This is where "everything under
# *.example.com except the host a third party runs" gets said.
out_of_scope:
  # - "*.cdn.example.com"
  # - value: blog.example.com
  #   note: hosted WordPress, excluded by the policy page
  # - value: https://www.example.com/admin/
  #   type: url_prefix
  #   note: staff only

# -- rules ------------------------------------------------------------------
#
# Traffic limits and opt-ins, shown with the harness defaults. Lower max_rps to
# whatever the program asks for: the guard refuses scanner commands that carry
# no matching rate flag, and the HTTP client sleeps to hold the rate.
rules:
  max_rps: 2.0                 # requests per second, per host
  max_requests: 20000          # ceiling for the whole engagement
  allowed_methods: [GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE]
  allow_tools: []              # opt in by name, e.g. [gobuster, sqlmap]
  allow_private_ranges: false  # true only for infrastructure you host yourself
  oob_hosts: []                # your own callback hosts for blind bugs, e.g.
                               # ["*.oast.fun"] -- reachable, but never a target
  redact_headers: []           # extra headers never stored in cleartext;
                               # Authorization, Cookie, Set-Cookie and X-API-Key
                               # are always redacted

# -- program_constraints ----------------------------------------------------
#
# The program's OWN limits, copied from its policy page. They can only CLAMP
# the rules above -- a lower rate, a smaller ceiling, fewer methods, more
# mandatory headers, more redaction -- and never loosen anything. A key this
# build cannot enforce stops the compile rather than being ignored: dropping a
# program's own limit is what makes `bb arm`'s attestation a false statement.
#
# Keys: max_rps, max_requests, max_nonowned_objects, allowed_methods,
#       required_headers, forbidden_tests, redact_headers
#
# program_constraints:
#   max_rps: 0.5
#   required_headers:
#     X-Bug-Bounty: <your handle>
#   forbidden_tests: [delete, account_takeover]

# -- authorization ----------------------------------------------------------
#
# Written by `bb arm`, not by hand. It records who attested, when, and when the
# attestation lapses; every layer refuses once expires_at passes, so a
# forgotten engagement goes cold on its own.
#
#     bb arm $engagement --as "your name" --hours 12
#     bb disarm $engagement
authorization: {}
"""
)

_IN_SCOPE_EXAMPLES = """
  # Rule types by example -- uncomment one, or add your own:
  # - www.example.com
  # - "*.example.com"
  # - 198.51.100.0/24
  # - https://www.example.com/api/
  # - value: "*.example.net"
  #   type: wildcard
  #   include_apex: false
  #   note: acquisition -- subdomains only, the apex is a parked page
"""


def _render_scope(
    engagement: str,
    program_url: str | None,
    platform: str | None,
    targets: Iterable[str],
) -> str:
    def field(value: str | None) -> str:
        rendered = _yaml_scalar(value)
        return " " + rendered if rendered else ""

    entries = "".join(f"\n  - {_yaml_scalar(t)}" for t in targets)
    return _TEMPLATE.substitute(
        engagement=engagement,
        platform=field(platform),
        program_url=field(program_url),
        in_scope=entries + _IN_SCOPE_EXAMPLES.rstrip("\n"),
    )


# The published starter is the same render with placeholder values, so it is
# real YAML that compiles up to -- and only up to -- the empty in_scope list.
TEMPLATE_SCOPE: str = _render_scope(
    "example-program", "https://hackerone.com/example-program", "hackerone", ()
)


# -- small helpers ----------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _stamp(moment: datetime) -> str:
    return moment.strftime(_ISO)


def _yaml_module():
    """PyYAML, or a remedy. Imported lazily so a missing dep is not a traceback."""
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - environment problem
        raise EngagementError(
            "PyYAML is not installed, so scope.yaml cannot be read or written.\n"
            f"  {sys.executable} -m pip install pyyaml"
        ) from exc
    return yaml


def _valid_name(name: str | None) -> str:
    candidate = (name or "").strip()
    if not _NAME_RE.fullmatch(candidate):
        raise EngagementError(
            f"{candidate!r} is not a usable engagement name: lowercase letters, digits "
            "and . _ - only, 64 characters at most.\n"
            "  bb list                 # engagements on this machine\n"
            "  bb use <engagement>     # select an existing one"
        )
    return candidate


def _resolve(name: str | None) -> str:
    """The engagement a command acts on: the argument, else the selected one."""
    chosen = (name or paths.active_engagement() or "").strip()
    if not chosen:
        raise EngagementError(
            "no engagement is selected, so there is nothing to act on.\n"
            "  bb list                                          # what exists\n"
            "  bb use <engagement>                              # select one\n"
            "  bb new <engagement> --program-url <policy-url>   # or start one"
        )
    return _valid_name(chosen)


def _require_single_line(field: str, value: str, remedy: str) -> None:
    if any(ord(ch) < 32 for ch in value):
        raise EngagementError(
            f"{field} must be a single line of plain text; it is written straight into "
            f"scope.yaml.\n{remedy}"
        )


def _write_text(path: Path, text: str) -> None:
    """Replace a file in one step, so a crash never leaves a half-written scope."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _audit(action: str, engagement: str, **extra: Any) -> None:
    """Append a lifecycle event to the shared audit log, chained. Never raises.

    `arm` and `disarm` are the two entries a dispute would turn on, so they are
    hash chained like every other line; the import is deferred and a flat append
    is the fallback, because a lifecycle command must not fail over its own log.
    """
    try:
        paths.STATE_DIR.mkdir(parents=True, exist_ok=True)
        record = {"ts": _stamp(_utcnow()), "action": action, "engagement": engagement, **extra}
    except Exception:
        return  # auditing must never break a lifecycle command
    try:
        from .cli import audit_record

        if audit_record(action, record):
            return
    except Exception:
        pass
    try:
        with paths.AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass  # auditing must never break a lifecycle command


def _format_span(seconds: float) -> str:
    total = int(seconds)
    if total <= 0:
        return "expired"
    hours, rest = divmod(total, 3600)
    minutes = rest // 60
    if hours >= 24:
        days, hours = divmod(hours, 24)
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _parse_stamp(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _source_digest(scope_file: Path) -> str:
    # Hashed exactly the way scope.compile_scope_file hashes it, so the two are
    # comparable: decoded text, re-encoded, not the raw bytes on disk.
    return hashlib.sha256(
        scope_file.read_text(encoding="utf-8").encode("utf-8")
    ).hexdigest()


def _lock_is_stale(scope_file: Path, lock: dict[str, Any]) -> bool:
    """True when scope.yaml has been edited since the lock was compiled."""
    recorded = lock.get("source_sha256")
    if not recorded:
        return False  # compiled from a document with no source text; nothing to compare
    try:
        return _source_digest(scope_file) != recorded
    except OSError:
        return True


# -- authorization block ----------------------------------------------------


@dataclass(frozen=True)
class Attestation:
    """What `bb arm` records: who said it, when, until when, and under what policy."""

    attested_by: str
    attested_at: str
    expires_at: str
    policy_url: str | None
    statement: str

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    def render(self) -> str:
        """The YAML block, keys in declaration order, one line each."""
        lines = ["authorization:"]
        for field in dataclasses.fields(self):
            rendered = _yaml_scalar(getattr(self, field.name))
            lines.append(f"  {field.name}:" + (f" {rendered}" if rendered else ""))
        return "\n".join(lines) + "\n"


def _splice_authorization(text: str, block: str) -> str:
    """Swap the top-level authorization mapping, leaving the rest of the file alone.

    A YAML round-trip would be shorter but would throw away every comment in
    the file, and this file is mostly comments on purpose.
    """
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    index = 0
    spliced = False
    while index < len(lines):
        if not spliced and _AUTH_KEY_RE.match(lines[index]):
            end = index  # last line belonging to the block
            probe = index + 1
            while probe < len(lines):
                if not lines[probe].strip():
                    probe += 1  # a blank line may sit inside the mapping
                    continue
                if lines[probe][:1] not in " \t":
                    break
                end = probe
                probe += 1
            out.append(block)
            index = end + 1
            spliced = True
            continue
        out.append(lines[index])
        index += 1
    if not spliced:
        if out and not out[-1].endswith("\n"):
            out.append("\n")
        out.append("\n" + block)
    return "".join(out)


def _write_authorization(engagement: str, block: str, expected: Any) -> None:
    """Splice a block into scope.yaml, then re-read it to prove it parsed as meant."""
    yaml = _yaml_module()
    scope_file = paths.scope_path(engagement)
    try:
        original = scope_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise EngagementError(
            f"cannot read {scope_file}: {exc.strerror or exc}\n"
            f"  bb new {engagement} --program-url <policy-url>"
        ) from exc

    updated = _splice_authorization(original, block)
    reason: str | None = None
    try:
        doc = yaml.safe_load(updated)
    except yaml.YAMLError as exc:
        reason = f"the result does not parse: {exc}"
    else:
        if not isinstance(doc, dict) or doc.get("authorization") != expected:
            reason = "the authorization block did not read back as it was written"
    if reason is not None:
        raise EngagementError(
            f"refusing to write {scope_file}: editing its authorization block would not "
            f"produce the intended document ({reason}). Nothing was changed.\n"
            "Repair the authorization block by hand, leaving it as `authorization: {}`, "
            f"then re-run:\n  bb arm {engagement} --as \"<your name>\""
        )
    _write_text(scope_file, updated)


# -- lifecycle --------------------------------------------------------------


def create(
    name: str,
    *,
    program_url: str | None = None,
    platform: str | None = None,
    targets: Iterable[str] = (),
) -> Path:
    """Create the engagement tree and write a starter scope.yaml. Returns that file."""
    engagement = _valid_name(name)
    scope_file = paths.scope_path(engagement)
    if scope_file.exists():
        raise EngagementError(
            f"engagement {engagement!r} already exists ({scope_file}); refusing to "
            "overwrite it.\n"
            f"  bb status {engagement}     # what is already in it\n"
            f"  bb use {engagement}        # select it\n"
            "Choose another name if you meant a new engagement."
        )

    listed = [str(t).strip() for t in targets if str(t).strip()]
    for target in listed:
        try:
            compile_rule(target)
        except ScopeError as exc:
            raise EngagementError(
                f"target {target!r} is not a usable scope rule: {exc}\n"
                "Targets are domains, *.wildcards, CIDRs or https:// URL prefixes:\n"
                f"  bb new {engagement} --target '*.example.com' --target 198.51.100.0/24"
            ) from exc

    for field, value in (("--program-url", program_url), ("--platform", platform)):
        if value:
            _require_single_line(
                field,
                str(value),
                f"  bb new {engagement} --program-url https://hackerone.com/<program>",
            )

    paths.ensure_engagement_tree(engagement)
    _write_text(scope_file, _render_scope(engagement, program_url, platform, listed))
    _audit("create", engagement, program_url=program_url, targets=listed)
    return scope_file


def compile_scope(name: str | None = None) -> dict[str, Any]:
    """Compile scope.yaml into the signed scope lock and return that lock."""
    engagement = _resolve(name)
    scope_file = paths.scope_path(engagement)
    if not scope_file.is_file():
        raise EngagementError(
            f"engagement {engagement!r} has no scope.yaml at {scope_file}.\n"
            f"  bb new {engagement} --program-url <policy-url> --target <asset>"
        )

    yaml = _yaml_module()
    try:
        lock = compile_scope_file(scope_file)
    except ScopeError as exc:
        raise EngagementError(
            f"{scope_file} does not compile: {exc}\n"
            f"Fix the file, then re-run:\n  bb scope compile {engagement}"
        ) from exc
    except yaml.YAMLError as exc:
        raise EngagementError(
            f"{scope_file} is not valid YAML: {exc}\n"
            f"Fix the syntax, then re-run:\n  bb scope compile {engagement}"
        ) from exc
    except OSError as exc:
        raise EngagementError(
            f"cannot read {scope_file}: {exc.strerror or exc}\n"
            f"  bb new {engagement} --program-url <policy-url>"
        ) from exc

    if lock.get("engagement") != engagement:
        raise EngagementError(
            f"{scope_file} declares engagement {lock.get('engagement')!r} but sits in the "
            f"{engagement!r} directory; one of them is wrong and the lock would authorize "
            "the wrong target set.\n"
            f"Set `engagement: {engagement}` in {scope_file}, then re-run:\n"
            f"  bb scope compile {engagement}"
        )

    # Signed on the way out: every reader loads the lock through
    # Scope.from_lock_file, which refuses an unsigned or edited one.
    try:
        signed = sign_lock(lock)
    except OSError as exc:
        raise EngagementError(
            f"cannot sign the compiled scope ({exc.strerror or exc}); without a signature "
            "every enforcement layer will refuse it.\n"
            f"Make {paths.STATE_DIR} writable, then re-run:\n"
            f"  bb scope compile {engagement}"
        ) from exc

    lock_file = paths.lock_path(engagement)
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    _write_text(lock_file, json.dumps(signed, indent=2) + "\n")
    return signed


def arm(
    name: str | None = None,
    *,
    attested_by: str,
    hours: int = DEFAULT_ARM_HOURS,
    policy_url: str | None = None,
) -> dict[str, Any]:
    """Record an expiring authorization attestation and recompile the lock."""
    engagement = _resolve(name)
    scope_file = paths.scope_path(engagement)
    yaml = _yaml_module()

    if not scope_file.is_file():
        raise EngagementError(
            f"engagement {engagement!r} has no scope.yaml at {scope_file}.\n"
            f"  bb new {engagement} --program-url <policy-url> --target <asset>\n"
            f"  bb arm {engagement} --as \"<your name>\""
        )
    try:
        doc = yaml.safe_load(scope_file.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise EngagementError(
            f"cannot read {scope_file}: {exc}\n"
            f"Fix the file, then re-run:\n  bb arm {engagement} --as \"<your name>\""
        ) from exc
    if not isinstance(doc, dict):
        raise EngagementError(
            f"{scope_file} is not a YAML mapping, so it has no program_url to attest to.\n"
            f"  bb scope compile {engagement}"
        )

    program = str(doc.get("program_url") or "").strip()
    if not program:
        raise EngagementError(
            f"engagement {engagement!r} has no program_url, so there is nothing to attest "
            "to; the attestation has to name the policy that authorizes the test.\n"
            f"Add the policy page URL to {scope_file}:\n"
            "  program_url: https://hackerone.com/<program>\n"
            f"then: bb arm {engagement} --as \"<your name>\""
        )
    arm_cmd = f'  bb arm {engagement} --as "<your name>"'
    _require_single_line(
        "program_url", program, f"  Fix program_url in {scope_file}, then:\n{arm_cmd}"
    )

    who = str(attested_by or "").strip()
    if not who:
        raise EngagementError(
            "arming needs the name of the person attesting authorization; the harness "
            "will not attest on its own behalf.\n"
            f"{arm_cmd}"
        )
    _require_single_line("--as", who, arm_cmd)

    # The attestation points at the policy it was made under; unless a separate
    # policy page is given, that is the program page itself.
    policy = str(policy_url).strip() if policy_url else program
    _require_single_line("--policy-url", policy, arm_cmd)

    try:
        span = float(hours)
    except (TypeError, ValueError):
        span = -1.0
    if not 0 < span <= MAX_ARM_HOURS:
        raise EngagementError(
            f"--hours must be more than 0 and at most {MAX_ARM_HOURS} (got {hours!r}); an "
            "attestation that outlives the session it was made for is not an attestation.\n"
            f"  bb arm {engagement} --as \"{who}\" --hours {DEFAULT_ARM_HOURS}"
        )

    now = _utcnow()
    attestation = Attestation(
        attested_by=who,
        attested_at=_stamp(now),
        expires_at=_stamp(now + timedelta(hours=span)),
        policy_url=policy,
        statement=ATTESTATION.format(program_url=program),
    )

    _write_authorization(engagement, attestation.render(), attestation.as_dict())
    lock = compile_scope(engagement)

    problem = Scope(lock).authorization_error()
    if problem:
        raise EngagementError(
            f"arming did not take effect: {problem}\n"
            f"Check the authorization block in {scope_file}, then re-run:\n"
            f"  bb arm {engagement} --as \"{who}\" --hours {int(span) or 1}"
        )

    _audit(
        "arm",
        engagement,
        attested_by=who,
        expires_at=attestation.expires_at,
        policy_url=policy,
    )
    return attestation.as_dict()


def disarm(name: str | None = None) -> None:
    """Drop the attestation and recompile, so every layer denies again."""
    engagement = _resolve(name)
    scope_file = paths.scope_path(engagement)
    if not scope_file.is_file():
        raise EngagementError(
            f"engagement {engagement!r} has no scope.yaml at {scope_file}; there is "
            "nothing armed.\n"
            f"  bb list"
        )

    _write_authorization(engagement, "authorization: {}\n", {})
    lock = compile_scope(engagement)

    if Scope(lock).authorization_error() is None:
        raise EngagementError(
            f"disarm did not take effect: {paths.lock_path(engagement)} still carries a "
            "live attestation.\n"
            f"Remove the authorization block from {scope_file} by hand, then re-run:\n"
            f"  bb scope compile {engagement}"
        )
    _audit("disarm", engagement)


def use(name: str) -> None:
    """Select the engagement that later commands act on by default."""
    engagement = _valid_name(name)
    scope_file = paths.scope_path(engagement)
    if not scope_file.is_file():
        known = paths.list_engagements()
        listing = "known: " + ", ".join(known) if known else "there are none yet"
        raise EngagementError(
            f"engagement {engagement!r} does not exist ({listing}).\n"
            "  bb list\n"
            f"  bb new {engagement} --program-url <policy-url> --target <asset>"
        )

    override = (os.environ.get("BBH_ENGAGEMENT") or "").strip()
    if override and override != engagement:
        raise EngagementError(
            f"BBH_ENGAGEMENT={override!r} is set in this environment and overrides the "
            f"selection, so choosing {engagement!r} would have no effect.\n"
            "  unset BBH_ENGAGEMENT\n"
            f"  bb use {engagement}"
        )

    paths.set_active(engagement)
    _audit("use", engagement)


def require_armed(name: str | None = None) -> Scope:
    """Return the armed scope, or raise with the exact sequence that arms it."""
    engagement = _resolve(name)
    scope_file = paths.scope_path(engagement)
    lock_file = paths.lock_path(engagement)
    arm_cmd = f'  bb arm {engagement} --as "<your name>" --hours {DEFAULT_ARM_HOURS}'

    if not scope_file.is_file():
        raise EngagementError(
            f"engagement {engagement!r} does not exist, so no target is authorized.\n"
            f"  bb new {engagement} --program-url <policy-url> --target <asset>\n"
            f"  bb use {engagement}\n" + arm_cmd
        )
    if not lock_file.is_file():
        raise EngagementError(
            f"engagement {engagement!r} has no compiled scope, so no target is authorized.\n"
            f"  bb scope compile {engagement}\n" + arm_cmd
        )
    try:
        scope = Scope.from_lock_file(lock_file)
    except (ScopeError, OSError, json.JSONDecodeError) as exc:
        raise EngagementError(
            f"engagement {engagement!r} has an unusable scope lock ({exc}).\n"
            f"  bb scope compile {engagement}\n" + arm_cmd
        ) from exc

    if _lock_is_stale(scope_file, scope.lock):
        raise EngagementError(
            f"{scope_file} has changed since it was compiled, so {lock_file} is no longer "
            "what you approved.\n"
            f"  bb scope compile {engagement}\n" + arm_cmd
        )

    problem = scope.authorization_error()
    if problem:
        raise EngagementError(
            f"engagement {engagement!r} is not armed: {problem}\n"
            f"  bb use {engagement}\n" + arm_cmd
        )
    return scope


# -- status -----------------------------------------------------------------


def _phase_progress(store: Store) -> list[dict[str, Any]]:
    """The latest run of each phase, in the order the phases were first started."""
    latest: dict[str, dict[str, Any]] = {}
    for row in store.phase_runs():
        previous = latest.get(row["phase"])
        latest[row["phase"]] = {
            "phase": row["phase"],
            "status": row["status"],
            "attempts": (previous["attempts"] + 1) if previous else 1,
            "ts_start": row["ts_start"],
            "ts_end": row["ts_end"],
            "turns": row["turns"],
            "cost_usd": row["cost_usd"],
            "session_id": row["session_id"],
            "error": row["error"],
        }
    return list(latest.values())


def status(name: str | None = None) -> dict[str, Any]:
    """Everything `bb status` prints: scope, attestation, counts, phase progress."""
    engagement = _resolve(name)
    scope_file = paths.scope_path(engagement)
    lock_file = paths.lock_path(engagement)
    if not scope_file.is_file():
        raise EngagementError(
            f"engagement {engagement!r} does not exist.\n"
            "  bb list\n"
            f"  bb new {engagement} --program-url <policy-url> --target <asset>"
        )

    problems: list[str] = []
    scope: Scope | None = None
    if not lock_file.is_file():
        problems.append(f"scope is not compiled; run: bb scope compile {engagement}")
    else:
        try:
            scope = Scope.from_lock_file(lock_file)
        except (ScopeError, OSError, json.JSONDecodeError) as exc:
            problems.append(
                f"scope lock is unusable ({exc}); run: bb scope compile {engagement}"
            )

    armed = False
    expires_at: str | None = None
    time_left: str | None = None
    seconds_left: int | None = None
    if scope is not None:
        if _lock_is_stale(scope_file, scope.lock):
            problems.append(
                f"scope.yaml has changed since it was compiled; run: "
                f"bb scope compile {engagement}"
            )
        problem = scope.authorization_error()
        if problem:
            problems.append(problem)
        armed = problem is None
        expires_at = scope.authorization.get("expires_at")
        expiry = _parse_stamp(expires_at)
        if expiry is not None:
            seconds_left = int((expiry - _utcnow()).total_seconds())
            time_left = _format_span(seconds_left)

    stats: dict[str, Any] = {}
    requests = 0
    phases: list[dict[str, Any]] = []
    try:
        with Store(paths.db_path(engagement)) as store:
            stats = store.stats()
            requests = store.request_count()
            phases = _phase_progress(store)
    except (sqlite3.Error, OSError) as exc:
        problems.append(
            f"store {paths.db_path(engagement)} is unreadable ({exc}); move it aside to "
            "start a fresh one"
        )

    return {
        "engagement": engagement,
        "root": str(paths.engagement_dir(engagement)),
        "scope_file": str(scope_file),
        "lock_file": str(lock_file),
        "active": paths.active_engagement() == engagement,
        "platform": scope.lock.get("platform") if scope else None,
        "program_url": scope.lock.get("program_url") if scope else None,
        "armed": armed,
        "attested_by": scope.authorization.get("attested_by") if scope else None,
        "attested_at": scope.authorization.get("attested_at") if scope else None,
        "expires_at": expires_at,
        "time_left": time_left,
        "seconds_left": seconds_left,
        "scope_summary": scope.summary().splitlines() if scope else [],
        "stats": stats,
        "requests": requests,
        "phases": phases,
        "problems": problems,
    }
