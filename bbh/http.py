"""The sanctioned HTTP client: the only way the harness is allowed to make requests.

Agent scripts may not drive `requests` (or any other network library) directly --
the PreToolUse guard denies that -- because a request only counts as evidence if
it was scope-checked before it left, rate-limited on the way out, and recorded
with its response on the way back. This module is that chokepoint.

Every request runs the same ordered gauntlet: resolve the engagement and reload
its lock, decide the target, check the method, check the request budget, take a
rate-limit token, perform exactly one hop, persist the exchange. Redirects are
followed by hand so that each hop runs the gauntlet again: a 302 pointing out of
scope is recorded and the 3xx handed back to the caller, never followed.

The lock is re-read per request (one stat, then a load only if it moved) so that
`bb disarm`, an expiring attestation or a recompiled scope takes effect mid-hunt
instead of at the next process start.

Redaction has one rule: anything *persisted* -- the store, a saved transcript --
has its credential headers replaced by a stable hash, so the same credential is
still correlatable across requests without being recoverable from the artifacts
that end up in a report. What the operator sees on their own terminal is not
redacted; they already hold those credentials, and they need the Set-Cookie to
drive the next request.

`requests` is imported on demand so that the stdlib-only consumers -- the
mitmproxy addon shares this module's rate-limit file and redaction rules -- can
import it under an interpreter that has no `requests`.

Three more controls sit in the same gauntlet, for the failures that end an
engagement rather than a request. A host that answers 429 or 423, sends any
Retry-After, or shows a lockout / captcha / step-up signature trips a per-host
circuit breaker: the phase stops asking, nothing sleeps the cooldown out, and
the breaker holds for *every* actor, because the counter belongs to the target
and retrying it as a second account is evasion rather than testing. A ceiling
across the whole engagement bounds how many other accounts' records a hunt can
reach at all. And a destructive method against someone else's object is refused
-- DELETE outright, PUT and PATCH unless the call records how it will put the
record back.

`actor` is mandatory from here on. A request recorded against no identity is
evidence of nothing: every ownership control in this module, and every
access-control gate downstream, is relative to who asked.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import json
import os
import re
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Iterator, NoReturn
from urllib.parse import unquote, urljoin, urlsplit

from . import paths, secrets
from .scope import PROGRAM_CONSTRAINT_KEYS as SCOPE_PROGRAM_CONSTRAINT_KEYS
from .scope import Scope, ScopeError, host_from_url
from .store import Store, sha256_bytes, utcnow
from .untrusted import fence, new_nonce, scrub

if TYPE_CHECKING:  # only for annotations; see _requests()
    import requests

# Redirect hops followed in one call before the client gives up.
MAX_REDIRECTS = 10

# Bodies at or below this go inline in the stored note; larger ones to a file.
BODY_INLINE_MAX = 2048

# A single request never sleeps longer than this for the rate limiter, however
# deep the queue is; it also bounds the damage from a wall-clock jump.
MAX_THROTTLE_SLEEP = 60.0

# Characters of the response shown by `bb req`.
BODY_PREVIEW = 2048

# The same, for the other two target-controlled parts of a printed response.
HEADERS_PREVIEW = 4096
HEADER_VALUE_PREVIEW = 512
URL_PREVIEW = 512

# C0, DEL, C1 and the Unicode line separators: everything that can start a new
# line or move a cursor in printed output. Matched one character at a time.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")

# Never persisted in cleartext. rules.redact_headers extends this list.
REDACTED_HEADERS = ("authorization", "cookie", "set-cookie", "x-api-key")

REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# The explicitly unauthenticated identity. Always a valid actor; never silent.
ANON_ACTOR = "anon"

# Statuses that are themselves the target saying stop.
AVAILABILITY_TRIP_STATUSES = (423, 429)

# Statuses on which a lockout / captcha / step-up string in the response is a
# block, rather than a page that merely mentions one. A 200 login page full of
# reCAPTCHA markup is not a block, and tripping on it would stall every hunt on
# its first request.
AVAILABILITY_SIGNAL_STATUSES = (401, 403, 406, 418, 428, 451, 503, 511)

# Response headers worth pattern-matching, as an allowlist: "rate limit" also
# matches the x-ratelimit-* headers a healthy API sends on every response.
AVAILABILITY_SIGNAL_HEADERS = (
    "www-authenticate", "warning", "x-amzn-waf-action", "x-blocked-by",
    "x-captcha-required", "x-mfa-required", "x-request-blocked",
)

# Bytes of a response body scanned for a block signature.
BODY_SIGNAL_SCAN = 8192

# rules.max_nonowned_objects: how many *other* accounts' records one engagement
# may reach, in total. Three proves a class is real and not a one-off; past that
# a proof turns into a dataset, and the blast radius stops being the harness's
# to justify.
DEFAULT_MAX_NONOWNED_OBJECTS = 3

# A restore plan shorter than this is a promise, not a plan.
REVERSIBLE_MIN_CHARS = 40

# program_constraints keys this build knows how to clamp with, re-exported from
# the compiler so the two layers refuse the same set. An unknown key is refused
# rather than ignored: silently dropping a program's own limit is how the
# attestation becomes a false statement. The compiler stops it reaching a lock;
# this module stops one that got there another way -- hand edited, or built in
# memory by a caller that never ran the compiler.
PROGRAM_CONSTRAINT_KEYS = SCOPE_PROGRAM_CONSTRAINT_KEYS

_CONTENT_HEADERS = ("content-length", "content-type", "content-encoding", "transfer-encoding")
_CREDENTIAL_HEADERS = ("authorization", "cookie")
_SAVE_AS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# What an agent writes when it means "I did not set this".
_OMITTED_WORDS = frozenset({"", "null", "none", "nil", "undefined"})

_STUB_REVERSIBLE = re.compile(
    r"^(yes|yep|y|true|ok|sure|fine|n/?a|none|nothing|reversible|revertible|idempotent|safe)\b",
    re.IGNORECASE,
)

# Ordered: the first match names the signal, so the more serious and more
# specific wording comes first.
_AVAILABILITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (kind, re.compile(pattern, re.IGNORECASE))
    for kind, pattern in (
        ("lockout", r"too many (?:failed )?(?:login |sign-?in |authentication )?attempts"),
        ("lockout", r"account (?:is |has been |was )?(?:temporarily )?(?:locked|suspended|disabled)"),
        ("lockout", r"(?:temporarily|permanently) (?:locked|blocked|banned|suspended)"),
        ("lockout", r"(?:you|your ip|your account)[^.\n]{0,24}been (?:blocked|banned)"),
        ("lockout", r"\blocked out\b"),
        ("lockout", r"unusual (?:activity|traffic)"),
        ("captcha", r"\b(?:re|h)?captcha\b"),
        ("captcha", r"\bturnstile\b"),
        ("captcha", r"(?:are you|verify (?:that )?you(?:'re| are)?) (?:a )?human"),
        ("captcha", r"not a robot"),
        ("challenge", r"\bchallenge\b"),
        ("challenge", r"cdn-cgi|cf-chl"),
        ("challenge", r"attention required|checking your browser"),
        ("challenge", r"blocked by (?:our )?(?:security|waf|firewall)"),
        ("challenge", r"incapsula incident"),
        ("step-up", r"step[\s_-]?up (?:authentication|verification|required)"),
        ("step-up", r"(?:additional|further|second[- ]factor) (?:authentication|verification)"),
        ("step-up", r"\bmfa[_\s-]?(?:required|challenge)\b"),
        ("step-up", r"two[\s_-]?factor (?:authentication )?(?:is )?required"),
        ("step-up", r"re-?authenticat(?:e|ion) (?:is )?required"),
        ("step-up", r"insufficient[_ ]authentication"),
        ("rate-limit", r"rate[\s_-]?limit"),
        ("rate-limit", r"too many requests"),
        ("rate-limit", r"slow down"),
        ("rate-limit", r"quota exceeded"),
        ("rate-limit", r"throttl(?:ed|ing)"),
    )
)

_NO_ENGAGEMENT = (
    "no engagement is selected, so no target is authorized.\n"
    "  bb list                 # engagements on this machine\n"
    "  bb use <engagement>     # select one\n"
    "  bb arm <engagement>     # attest authorization (expires)"
)


class BudgetExceeded(RuntimeError):
    """The engagement has spent its request budget."""


class OutOfScope(PermissionError):
    """The target, method or engagement state forbids this request."""


class TransportError(RuntimeError):
    """The request left the harness but no response came back."""


class AvailabilityTripped(RuntimeError):
    """The target asked the harness to back off; the per-host breaker is open.

    Not a `BudgetExceeded`: a budget is the operator's choice, this is the
    target's. It carries the facts a caller needs to record the block instead of
    laundering it into a false negative.
    """

    def __init__(
        self,
        message: str,
        *,
        host: str | None = None,
        phase: str | None = None,
        signal: "AvailabilitySignal | None" = None,
        request_ids: Iterable[int] = (),
    ):
        super().__init__(message)
        self.host = host
        self.phase = phase
        self.signal = signal
        self.request_ids = list(request_ids)
        self.request_id = self.request_ids[-1] if self.request_ids else None


class BlastRadiusExceeded(OutOfScope):
    """The engagement has reached its ceiling of other accounts' objects.

    Both this and `DestructiveRefused` subclass `OutOfScope` so that every
    existing `except OutOfScope` path -- `bb req`, agent scripts written against
    v1 -- refuses correctly without being taught the new names first. Catch the
    subclass when the difference matters.
    """


class DestructiveRefused(OutOfScope):
    """A destructive method aimed at an object another account owns."""


def _deny(reason: str) -> str:
    return (
        f"{reason}\n"
        "This is the mechanical scope check, not a permission prompt. Fix the target or the "
        "engagement scope; do not route around it."
    )


def _refused(reason: str) -> str:
    return (
        f"{reason}\n"
        "This is a mechanical harness control, not a permission prompt. Satisfy it or stop "
        "here; do not route around it."
    )


def _back_off(reason: str) -> str:
    return (
        f"{reason}\n"
        "This is a mechanical availability brake. It does not clear by waiting, by retrying, "
        "or by acting as another identity."
    )


def _given(value: Any) -> str | None:
    """A caller-supplied string, or None when it is one of the ways of saying unset.

    `--actor null` is an agent telling the harness it has no identity for this
    request, not an account called "null"; treating it as a label would record
    traffic against a phantom.
    """
    text = ("" if value is None else str(value)).strip()
    return None if text.lower() in _OMITTED_WORDS else text


@dataclass(frozen=True)
class Refusal:
    """Why a request is not being sent, and the exception that says so."""

    reason: str
    exc: type[Exception] = OutOfScope


_requests_cache: Any = None


def _requests() -> Any:
    """Import `requests` on demand, with the exact install command if it is missing."""
    global _requests_cache
    if _requests_cache is None:
        try:
            import requests
        except ImportError:
            raise RuntimeError(
                "the sanctioned HTTP client needs the 'requests' package, which is not "
                f"installed for {sys.executable}.\n"
                f"  {sys.executable} -m pip install requests"
            ) from None
        _requests_cache = requests
    return _requests_cache


# -- redaction ---------------------------------------------------------------


def redact_value(value: str) -> str:
    """A credential stand-in: correlatable across requests, not recoverable."""
    return f"<redacted sha256:{sha256_bytes(value.encode('utf-8', 'replace'))[:8]}>"


def flatten_headers(headers: Any) -> dict[str, str]:
    """Headers as a plain dict, repeats joined. Accepts a mapping or pairs, so
    the proxy addon can hand over mitmproxy's multi-valued header object."""
    items = headers.items() if hasattr(headers, "items") else (headers or ())
    out: dict[str, str] = {}
    for name, value in items:
        key = str(name)
        text = "" if value is None else (value if isinstance(value, str) else str(value))
        out[key] = f"{out[key]}, {text}" if key in out else text
    return out


def redact_headers(headers: Any, extra: Iterable[str] = ()) -> dict[str, str]:
    """Flatten headers, hashing every credential-bearing value. Use this on
    everything that gets persisted; never on what the operator sees live."""
    drop = set(REDACTED_HEADERS)
    drop.update(str(h).strip().lower() for h in (extra or ()) if str(h).strip())
    return {
        key: redact_value(value) if key.strip().lower() in drop else value
        for key, value in flatten_headers(headers).items()
    }


# -- bodies ------------------------------------------------------------------


@dataclass(frozen=True)
class StoredBody:
    """Where one body ended up. The sha256 is recorded either way."""

    length: int
    sha256: str | None = None
    path: str | None = None
    inline: dict[str, str] | None = None


def persist_body(bodies_dir: Path, data: bytes | None) -> StoredBody:
    """Inline a small body, write a large one to raw/bodies/<sha256>.bin."""
    if data is None:
        return StoredBody(0)
    digest = sha256_bytes(data)
    if not data:  # an empty body is still a fact; its hash records it
        return StoredBody(0, digest)
    if len(data) <= BODY_INLINE_MAX:
        try:
            inline = {"text": data.decode("utf-8")}
        except UnicodeDecodeError:
            inline = {"base64": base64.b64encode(data).decode("ascii")}
        return StoredBody(len(data), digest, None, inline)
    bodies_dir.mkdir(parents=True, exist_ok=True)
    dest = bodies_dir / f"{digest}.bin"
    if not dest.exists():  # content addressed: an identical body is already there
        tmp = dest.with_name(f".{digest}.{os.getpid()}.tmp")
        tmp.write_bytes(data)
        os.replace(tmp, dest)
    return StoredBody(len(data), digest, str(dest), None)


def decoded_body(data: bytes | None) -> str | None:
    """A body as text, or None when only a digest of it is printable."""
    if not data:
        return ""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if "\x00" in text else text


def _as_text(data: bytes | None) -> str:
    if not data:
        return ""
    text = decoded_body(data)
    if text is None:
        return f"<binary body, {len(data)} bytes, sha256:{sha256_bytes(data)}>"
    return text


def escape_controls(text: str, *, keep_newlines: bool = False) -> str:
    """Control characters as `\\xNN`, so target bytes cannot drive a terminal.

    A response body is the most target-controlled string in the harness, and it
    is printed into a tool result an agent reads. Newlines are kept inside a
    fenced body because that is what makes it readable as the evidence it is;
    everywhere else -- a URL, a header, a reason phrase, all of which the
    harness prints on a line of its own -- every control character goes.
    """
    keep = "\n" if keep_newlines else ""
    return "".join(
        ch if (ch in keep or not _CONTROL_RE.match(ch)) else f"\\x{ord(ch):02x}"
        for ch in text
    )


def _clip(text: str, cap: int) -> str:
    if len(text) <= cap:
        return text
    return f"{text[:cap]} ... [{len(text) - cap} more characters]"


def _inline(value: Any, nonce: str, cap: int) -> str:
    """Target-chosen text, fit to print on a line in the harness's own voice."""
    return _clip(escape_controls(scrub(str(value), nonce)), cap)


def _prepared_body(prepared: Any) -> bytes | None:
    body = getattr(prepared, "body", None)
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8", "replace")
    return None  # a streaming generator; not re-readable, so not recorded


# -- shared state files ------------------------------------------------------


@contextmanager
def _locked_json(path: Path, *, reset_on_corrupt: bool) -> Iterator[dict[str, Any]]:
    """Read-modify-write a small JSON state file under an exclusive flock.

    Shared by the rate bucket and the circuit breaker, because both are
    cross-process state that the client, the proxy and a restarted phase all
    mutate. They differ on corruption, which is `reset_on_corrupt`: losing a
    token bucket costs a second of burst, while losing the breaker loses the
    knowledge that a host told us to stop, so only one of them may start over.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        state = _parse_state(_read_all(fd), reset_on_corrupt=reset_on_corrupt)
        yield state
        payload = json.dumps(state).encode("utf-8")
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, payload)
        os.ftruncate(fd, len(payload))
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_json(path: Path) -> dict[str, Any] | None:
    """Shared-locked read. None if there is no file; ValueError if it will not parse.

    A read does not create the file, so checking the breaker on every request
    does not leave breaker.json behind for an engagement that never tripped one.
    """
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        raw = _read_all(fd)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    return _parse_state(raw, reset_on_corrupt=False)


def _read_all(fd: int) -> bytes:
    raw = b""
    while True:
        chunk = os.read(fd, 1 << 16)
        if not chunk:
            return raw
        raw += chunk


def _parse_state(raw: bytes, *, reset_on_corrupt: bool) -> dict[str, Any]:
    try:
        state = json.loads(raw) if raw.strip() else {}
        if not isinstance(state, dict):
            raise ValueError("state file is not a JSON object")
    except ValueError:
        if not reset_on_corrupt:
            raise
        state = {}
    return state


# -- rate limiting -----------------------------------------------------------


class RateLimiter:
    """Per-host token bucket shared by every process working one engagement.

    The state lives in a small JSON file under the engagement's .state/ and is
    mutated under an exclusive flock, so the client and the mitmproxy addon --
    and a client that restarted mid-run -- queue behind each other instead of
    each getting a fresh allowance. Wall-clock time, not monotonic, because the
    file outlives the process that wrote it.
    """

    def __init__(self, path: str | Path, rps: float, max_sleep: float = MAX_THROTTLE_SLEEP):
        self.path = Path(path)
        self.rps = max(0.01, float(rps))
        self.capacity = max(1.0, self.rps)  # one second of burst, at least one token
        self.max_sleep = float(max_sleep)

    def reserve(self, host: str, now: float | None = None) -> float:
        """Claim the next slot for `host`; returns the seconds the caller owes."""
        moment = time.time() if now is None else now
        floor = 1.0 - self.rps * self.max_sleep
        with self._locked() as state:
            state["rps"] = self.rps
            hosts: dict[str, Any] = state["hosts"]
            entry = hosts.get(host) or {}
            try:
                tokens = float(entry.get("tokens", self.capacity))
                updated = float(entry.get("updated", moment))
            except (TypeError, ValueError):
                tokens, updated = self.capacity, moment
            # A negative elapsed means another caller reserved a slot in the
            # future; it must push this one further back, so it is not clamped.
            tokens = min(self.capacity, tokens + (moment - updated) * self.rps)
            tokens = max(tokens, floor)  # bounds the queue, and a clock jump
            if tokens >= 1.0:
                tokens -= 1.0
                wait = 0.0
                updated = moment
            else:
                wait = (1.0 - tokens) / self.rps
                tokens = 0.0
                updated = moment + wait
            # Unrounded: at epoch magnitude a float has ~240ns of resolution, so
            # rounding the timestamp makes a full bucket look a hair short.
            hosts[host] = {"tokens": tokens, "updated": updated}
            self._prune(hosts, moment)
        return wait

    def acquire(self, host: str) -> float:
        """Reserve a slot and sleep until it arrives. Returns the seconds slept."""
        wait = self.reserve(host)
        if wait > 0:
            time.sleep(wait)
        return wait

    def _prune(self, hosts: dict[str, Any], moment: float) -> None:
        if len(hosts) <= 512:
            return
        for name in [
            n
            for n, e in hosts.items()
            if isinstance(e, dict) and float(e.get("updated", 0.0)) < moment - 3600.0
        ]:
            hosts.pop(name, None)

    @contextmanager
    def _locked(self) -> Iterator[dict[str, Any]]:
        # reset_on_corrupt: a truncated bucket costs one second of burst, not the hunt.
        with _locked_json(self.path, reset_on_corrupt=True) as state:
            if not isinstance(state.get("hosts"), dict):
                state["hosts"] = {}
            yield state


# -- availability: the circuit breaker ---------------------------------------


@dataclass(frozen=True)
class AvailabilitySignal:
    """A host telling the harness to stop, and how we know."""

    kind: str  # rate-limit | retry-after | lockout | captcha | challenge | step-up
    detail: str
    status: int | None = None
    retry_after: str | None = None

    def describe(self) -> str:
        bits = [f"HTTP {self.status}" if self.status else "no status"]
        if self.retry_after:
            bits.append(f"Retry-After: {self.retry_after}")
        if self.detail and self.detail != f"status {self.status}":
            bits.append(self.detail)
        return f"{self.kind} ({', '.join(bits)})"

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "status": self.status,
            "retry_after": self.retry_after,
        }


def availability_signal(response: Any) -> AvailabilitySignal | None:
    """The back-off signal in this response, or None.

    Three triggers: a 429 or 423, *any* Retry-After, and a lockout / captcha /
    step-up signature. The signature is only read on a status that is itself a
    refusal, because the word "recaptcha" in a 200 login page is a widget and the
    same word in a 403 is a wall -- and a breaker that trips on the widget stops
    the hunt on its first request.

    The matched text is recorded, never the surrounding bytes: the evidence is
    the signal, and the body it came from may carry a session.
    """
    raw_status = getattr(response, "status_code", None)
    status = int(raw_status) if isinstance(raw_status, int) else None
    lowered = {
        str(k).strip().lower(): str(v)
        for k, v in flatten_headers(getattr(response, "headers", None) or {}).items()
    }
    retry_after = _given(lowered.get("retry-after"))

    if status in AVAILABILITY_TRIP_STATUSES:
        kind = "rate-limit" if status == 429 else "lockout"
        return AvailabilitySignal(kind, f"status {status}", status, retry_after)
    if retry_after:
        return AvailabilitySignal(
            "retry-after", f"Retry-After: {retry_after}", status, retry_after
        )
    mitigated = _given(lowered.get("cf-mitigated"))
    if mitigated:
        # Only ever sent for a challenge, so it needs no status gate.
        return AvailabilitySignal("challenge", f"cf-mitigated: {mitigated}", status, retry_after)
    if status not in AVAILABILITY_SIGNAL_STATUSES:
        return None

    haystacks = [
        (f"header {name}", f"{name}: {lowered[name]}")
        for name in AVAILABILITY_SIGNAL_HEADERS
        if name in lowered
    ]
    body = getattr(response, "content", None)
    if isinstance(body, bytes) and body:
        haystacks.append(("body", body[:BODY_SIGNAL_SCAN].decode("utf-8", "replace")))
    for kind, pattern in _AVAILABILITY_PATTERNS:
        for where, text in haystacks:
            found = pattern.search(text)
            if found:
                return AvailabilitySignal(
                    kind, f"{where} matched {found.group(0)!r}", status, retry_after
                )
    return None


class CircuitBreaker:
    """Per-host "stop asking", shared by every process working one engagement.

    Next to rate.json and for the same reason: the client, the proxy and a phase
    that restarted have to agree about it. A trip records the phase it happened
    in, so a later phase gets exactly one fresh attempt -- the harness never
    waits a cooldown out, because a cooldown is the target saying stop and
    outlasting it is the thing program rules forbid.

    The actor is recorded but is deliberately *not* part of the key. A tripped
    host is refused to every identity: the counter belongs to the target, not to
    the account, so retrying as a second account is evasion, and evasion is what
    gets a researcher banned and a program closed.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def hosts(self) -> dict[str, dict[str, Any]]:
        """Every tripped host. Raises ValueError when the state will not parse."""
        state = _read_json(self.path)
        if not state:
            return {}
        hosts = state.get("hosts")
        if hosts is None:
            return {}
        if not isinstance(hosts, dict):
            raise ValueError("breaker state has no 'hosts' object")
        return {str(k): v for k, v in hosts.items() if isinstance(v, dict)}

    def open_for(self, host: str, phase: str | None) -> dict[str, Any] | None:
        """The trip that refuses this (host, phase), or None.

        Fail closed on an unknown phase: a trip with no phase recorded, or a
        caller that cannot say which phase it is in, cannot prove it is a later
        one, so the breaker holds.
        """
        entry = self.hosts().get(host)
        if entry is None:
            return None
        tripped_in = _given(entry.get("phase"))
        if tripped_in and phase and str(phase) != tripped_in:
            return None
        return entry

    def trip(
        self,
        host: str,
        *,
        phase: str | None,
        actor: str | None,
        signal: AvailabilitySignal,
        request_id: int | None = None,
        url: str | None = None,
        method: str | None = None,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ts": utcnow(),
            "phase": phase,
            "actor": actor,
            "kind": signal.kind,
            "signal": signal.describe(),
            "status": signal.status,
            "retry_after": signal.retry_after,
            "request_id": request_id,
            "method": method,
            "url": url,
        }
        # reset_on_corrupt, unlike every read: recording the trip has to succeed,
        # and a file holding this one trip beats a file holding junk. Nothing
        # reaches here over a corrupt file anyway -- the pre-send check refuses
        # first, which is where the strict read lives.
        with _locked_json(self.path, reset_on_corrupt=True) as state:
            hosts = state.get("hosts")
            if not isinstance(hosts, dict):
                hosts = {}
            prior = hosts.get(host)
            prior = prior if isinstance(prior, dict) else {}
            try:
                entry["trips"] = int(prior.get("trips", 0)) + 1
            except (TypeError, ValueError):
                entry["trips"] = 1
            hosts[host] = entry
            state["hosts"] = hosts
        return entry

    def clear(self, host: str | None = None) -> None:
        """Reopen a host, or all of them. Deliberately operator-side: no code
        path inside a phase calls this, because a phase clearing its own brake is
        the same as not having one."""
        with _locked_json(self.path, reset_on_corrupt=True) as state:
            hosts = state.get("hosts")
            if not isinstance(hosts, dict) or host is None:
                state["hosts"] = {}
            else:
                hosts.pop(host, None)
                state["hosts"] = hosts


# -- program constraints -----------------------------------------------------


def _program_constraints(scope: Scope) -> list[tuple[str, dict[str, Any]]]:
    """Program-mandated limits, from the lock or from `rules`.

    Both places are read so this module keeps working whichever one the scope
    compiler puts them in; applying both is safe because every clamp below only
    tightens.
    """
    found: list[tuple[str, dict[str, Any]]] = []
    for where, holder in (
        ("program_constraints", scope.lock),
        ("rules.program_constraints", scope.rules),
    ):
        raw = (holder or {}).get("program_constraints")
        if not raw:
            continue
        if not isinstance(raw, dict):
            raise OutOfScope(
                _refused(
                    f"{where} is a {type(raw).__name__}; it must be a mapping of the program's "
                    f"own limits, e.g. {{max_rps: 0.5, required_headers: {{X-Bug-Bounty: me}}}}."
                    f"\nFix it in {paths.scope_path(scope.engagement)} then run: "
                    f"bb scope compile {scope.engagement}"
                )
            )
        found.append((where, raw))
    return found


def effective_rules(scope: Scope) -> dict[str, Any]:
    """`scope.rules` with `program_constraints` applied. Constraints only clamp.

    The prompt packs this harness was studied against hand the model a licence to
    ignore program-mandated rate limits. Copying that would make the
    authorization attestation a false statement, so the program's own limits live
    here instead and can only ever tighten what scope.yaml allows: a lower rps, a
    smaller budget, fewer methods, more mandatory headers, more redaction.

    Anything this function cannot make sense of raises, including a constraint
    key it does not implement. A limit the harness cannot apply is a program rule
    it is about to break.
    """
    rules = dict(scope.rules)
    rules["max_rps"] = _as_number(rules.get("max_rps", 2.0), "rules.max_rps", scope)
    rules["max_requests"] = _as_count(rules.get("max_requests", 20000), "rules.max_requests", scope)
    rules["max_nonowned_objects"] = _as_count(
        rules.get("max_nonowned_objects", DEFAULT_MAX_NONOWNED_OBJECTS),
        "rules.max_nonowned_objects",
        scope,
    )
    rules["allowed_methods"] = [
        str(m).strip().upper() for m in (rules.get("allowed_methods") or ()) if str(m).strip()
    ]
    rules["required_headers"] = _as_header_map(
        rules.get("required_headers"), "rules.required_headers", scope
    )
    rules["forbidden_tests"] = _as_test_names(
        rules.get("forbidden_tests"), "rules.forbidden_tests", scope
    )
    rules["redact_headers"] = sorted(
        {str(h).strip().lower() for h in (rules.get("redact_headers") or ()) if str(h).strip()}
    )

    for where, constraint in _program_constraints(scope):
        unknown = sorted(set(constraint) - set(PROGRAM_CONSTRAINT_KEYS))
        if unknown:
            raise OutOfScope(
                _refused(
                    f"{where} names {unknown}, which this build cannot enforce; it clamps "
                    f"{list(PROGRAM_CONSTRAINT_KEYS)}. A program constraint the harness cannot "
                    "apply is a program rule it would break, so no request is sent until the "
                    "key is one of those.\n"
                    f"Fix it in {paths.scope_path(scope.engagement)} then run: "
                    f"bb scope compile {scope.engagement}"
                )
            )
        if "max_rps" in constraint:
            rules["max_rps"] = min(
                rules["max_rps"], _as_number(constraint["max_rps"], f"{where}.max_rps", scope)
            )
        if "max_requests" in constraint:
            rules["max_requests"] = min(
                rules["max_requests"],
                _as_count(constraint["max_requests"], f"{where}.max_requests", scope),
            )
        if "max_nonowned_objects" in constraint:
            rules["max_nonowned_objects"] = min(
                rules["max_nonowned_objects"],
                _as_count(
                    constraint["max_nonowned_objects"], f"{where}.max_nonowned_objects", scope
                ),
            )
        if "allowed_methods" in constraint:
            permitted = {
                str(m).strip().upper() for m in (constraint["allowed_methods"] or ())
            }
            rules["allowed_methods"] = [m for m in rules["allowed_methods"] if m in permitted]
        if "required_headers" in constraint:
            # The program's value wins: one more obligation is a tightening.
            rules["required_headers"] = {
                **rules["required_headers"],
                **_as_header_map(
                    constraint["required_headers"], f"{where}.required_headers", scope
                ),
            }
        if "forbidden_tests" in constraint:
            rules["forbidden_tests"] = sorted(
                set(rules["forbidden_tests"])
                | set(
                    _as_test_names(
                        constraint["forbidden_tests"], f"{where}.forbidden_tests", scope
                    )
                )
            )
        if "redact_headers" in constraint:
            rules["redact_headers"] = sorted(
                set(rules["redact_headers"])
                | {str(h).strip().lower() for h in (constraint["redact_headers"] or ()) if str(h).strip()}
            )

    forbidden = set(rules["forbidden_tests"])
    rules["allowed_methods"] = [m for m in rules["allowed_methods"] if _test_name(m) not in forbidden]
    return rules


def _test_name(value: Any) -> str:
    """One spelling for a test name, so `Account Takeover` and `account_takeover` match."""
    return re.sub(r"[\s_]+", "-", str(value or "").strip().lower())


def _rules_problem(where: str, value: Any, expected: str, scope: Scope) -> str:
    return (
        f"{where} is {value!r}, which is not {expected}. Every request is refused while a "
        "limit the harness has to enforce is unreadable.\n"
        f"Fix it in {paths.scope_path(scope.engagement)} then run: "
        f"bb scope compile {scope.engagement}"
    )


def _as_number(value: Any, where: str, scope: Scope) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise OutOfScope(_refused(_rules_problem(where, value, "a number", scope))) from None
    if number <= 0 or number != number:  # NaN compares unequal to itself
        raise OutOfScope(_refused(_rules_problem(where, value, "greater than zero", scope)))
    return number


def _as_count(value: Any, where: str, scope: Scope) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise OutOfScope(_refused(_rules_problem(where, value, "a whole number", scope))) from None
    if number < 0:
        raise OutOfScope(_refused(_rules_problem(where, value, "zero or more", scope)))
    return number


def _as_test_names(value: Any, where: str, scope: Scope) -> list[str]:
    if not value:
        return []
    if isinstance(value, str) or not isinstance(value, (list, tuple, set, frozenset)):
        raise OutOfScope(
            _refused(_rules_problem(where, value, "a list of test names", scope))
        )
    return sorted({name for name in (_test_name(v) for v in value) if name})


def _as_header_map(value: Any, where: str, scope: Scope) -> dict[str, str]:
    """`{name: value}` from a mapping or from `Name: value` strings."""
    if not value:
        return {}
    pairs: list[tuple[str, str]] = []
    if isinstance(value, dict):
        pairs = [(str(k), "" if v is None else str(v)) for k, v in value.items()]
    elif isinstance(value, (list, tuple)):
        for entry in value:
            if isinstance(entry, dict) and len(entry) == 1:
                [(name, raw)] = entry.items()
                pairs.append((str(name), "" if raw is None else str(raw)))
                continue
            text = str(entry)
            if ":" not in text:
                raise OutOfScope(
                    _refused(
                        f"{where} entry {entry!r} is not 'Name: value'. Write the headers the "
                        "program mandates as a mapping:\n"
                        "  rules:\n    required_headers:\n      X-Bug-Bounty: <your handle>\n"
                        f"in {paths.scope_path(scope.engagement)} then run: "
                        f"bb scope compile {scope.engagement}"
                    )
                )
            name, _, raw = text.partition(":")
            pairs.append((name, raw))
    else:
        raise OutOfScope(
            _refused(_rules_problem(where, value, "a mapping of header names to values", scope))
        )

    headers: dict[str, str] = {}
    for name, raw in pairs:
        key = name.strip()
        text = raw.strip()
        bad = not key or not key.isascii() or any(c in key for c in " \t\r\n:")
        if bad or any(c in text for c in "\r\n"):
            raise OutOfScope(
                _refused(
                    f"{where} has an unusable header {name!r}: a name cannot be empty or carry "
                    "spaces, colons or non-ASCII, and neither name nor value may carry a "
                    "newline -- that would be header injection by the harness itself.\n"
                    f"Fix it in {paths.scope_path(scope.engagement)} then run: "
                    f"bb scope compile {scope.engagement}"
                )
            )
        headers[key] = text
    return headers


# -- blast radius ------------------------------------------------------------


@dataclass(frozen=True)
class ObjectRef:
    """One row of the `objects` table, as this module needs it."""

    kind: str
    identifier: str
    owner: str | None
    label: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind, self.identifier)

    def describe(self) -> str:
        name = f" '{self.label}'" if self.label else ""
        return f"{self.kind or 'object'} {self.identifier}{name} (owner: {self.owner or 'none'})"

    @classmethod
    def from_row(cls, row: Any) -> "ObjectRef":
        return cls(
            kind=str(_field(row, "kind") or ""),
            identifier=str(_field(row, "identifier") or ""),
            owner=_given(_field(row, "owner_account")),
            label=_given(_field(row, "label")),
        )


def _field(row: Any, name: str) -> Any:
    try:
        return row[name]
    except (KeyError, IndexError, TypeError):
        return None


@lru_cache(maxsize=1024)
def _identifier_pattern(identifier: str) -> re.Pattern[str]:
    """Delimited match: `2` is in /docs/2 and ?id=2, not in /docs/1234 or /v2/docs."""
    return re.compile(
        r"(?<![0-9A-Za-z_-])" + re.escape(identifier) + r"(?![0-9A-Za-z_-])", re.IGNORECASE
    )


def objects_in_url(url: str, objects: Iterable[Any]) -> list[ObjectRef]:
    """Registered objects whose identifier appears in this URL's path or query.

    The URL is the whole check, percent-decoded as well as raw. An identifier
    that travels only in a request body is not caught here: a body carries the
    credentials being tested, and searching it would refuse a login POST for
    containing the victim's own email address. Put the identifier the request
    acts on in the path or the query, which is where an API puts it anyway.
    """
    path, query = _split(url or "")
    target = path + (f"?{query}" if query else "")
    haystacks = {target, unquote(target)}
    found: list[ObjectRef] = []
    for raw in objects:
        ref = raw if isinstance(raw, ObjectRef) else ObjectRef.from_row(raw)
        if not ref.identifier:
            continue
        pattern = _identifier_pattern(ref.identifier)
        if any(pattern.search(text) for text in haystacks):
            found.append(ref)
    return found


def reversible_problem(marker: Any) -> str | None:
    """Why this restore plan is a gesture rather than a plan, or None if it is one."""
    text = (_given(marker) or "").strip()
    if not text:
        return "no reversible= marker was passed"
    stub = _STUB_REVERSIBLE.match(text)
    if stub:
        return f"the marker starts with {stub.group(0)!r}, which records no restore step"
    if len(text) < REVERSIBLE_MIN_CHARS:
        return (
            f"the marker is {len(text)} characters; the bar is {REVERSIBLE_MIN_CHARS}, because "
            "anything shorter names neither the original value nor the request that puts it back"
        )
    return None


# -- redirects ---------------------------------------------------------------


@dataclass(frozen=True)
class RedirectHop:
    """One Location hop and what the client decided to do about it."""

    status: int
    from_url: str
    to_url: str
    to_host: str
    method: str
    followed: bool
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "to": self.to_url,
            "to_host": self.to_host,
            "method": self.method,
            "followed": self.followed,
            "reason": self.reason,
        }


def redirect_method(method: str, status: int) -> str:
    """How a redirect rewrites the method, matching browser and `requests` behaviour."""
    if status == 303 and method not in ("GET", "HEAD"):
        return "GET"
    if status in (301, 302) and method == "POST":
        return "GET"
    return method


def _next_kwargs(kw: dict[str, Any], *, drop_body: bool, cross_host: bool) -> dict[str, Any]:
    """Carry request kwargs across a hop, dropping what must not travel."""
    out = dict(kw)
    out.pop("params", None)  # the Location URL already carries its own query
    raw = out.get("headers")
    headers = dict(raw.items()) if hasattr(raw, "items") else {}
    if drop_body:
        for key in ("data", "json", "files"):
            out.pop(key, None)
        for name in [n for n in headers if n.lower() in _CONTENT_HEADERS]:
            headers.pop(name)
    if cross_host:
        # A credential minted for one host is not handed to another, even when
        # both are in scope; that is how a redirect turns into a token leak.
        out.pop("auth", None)
        out.pop("cookies", None)
        for name in [n for n in headers if n.lower() in _CREDENTIAL_HEADERS]:
            headers.pop(name)
    if raw is not None:
        out["headers"] = headers
    return out


def _with_required(kw: dict[str, Any], required: dict[str, str]) -> dict[str, Any]:
    """Merge the program-mandated headers in. The mandate wins over the caller:
    a header the program requires exists so the target can identify this
    traffic, and a caller that overrides it has removed the identification."""
    if not required:
        return kw
    out = dict(kw)
    taken = {name.lower() for name in required}
    headers = {
        name: value
        for name, value in flatten_headers(out.get("headers") or {}).items()
        if name.lower() not in taken
    }
    headers.update(required)
    out["headers"] = headers
    return out


# -- transcripts -------------------------------------------------------------


def transcript(response: "requests.Response", *, redact_extra: Iterable[str] = ()) -> str:
    """A redacted request/response transcript, fit to attach as evidence."""
    prepared = response.request
    parts = _split(prepared.url or "")
    target = parts[0] or "/"
    if parts[1]:
        target += "?" + parts[1]
    req_headers = redact_headers(prepared.headers or {}, redact_extra)
    resp_headers = redact_headers(response.headers or {}, redact_extra)

    lines = [f"# bbh transcript {utcnow()}", f"# {prepared.method} {prepared.url}", ""]
    lines.append(f"{prepared.method} {target} HTTP/1.1")
    if not any(k.lower() == "host" for k in req_headers):
        host = host_from_url(prepared.url or "")
        if host:
            lines.append(f"Host: {host}")
    lines.extend(f"{k}: {v}" for k, v in req_headers.items())
    lines.append("")
    lines.append(_as_text(_prepared_body(prepared)))
    lines.append("")
    lines.append(f"HTTP/1.1 {response.status_code} {response.reason or ''}".rstrip())
    lines.extend(f"{k}: {v}" for k, v in resp_headers.items())
    lines.append("")
    lines.append(_as_text(response.content))
    return "\n".join(lines) + "\n"


def _split(url: str) -> tuple[str, str]:
    """(path, query) for the store row, tolerant of a URL that will not parse."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", ""
    return parts.path or "", parts.query or ""


def _scheme(url: str) -> str:
    try:
        return (urlsplit(url).scheme or "").lower()
    except ValueError:
        return ""


def _join(base: str, location: str) -> str | None:
    try:
        return urljoin(base, location)
    except ValueError:
        return None


# -- audit -------------------------------------------------------------------


def _audit(engagement: str | None, allowed: bool, summary: str, reasons: list[str]) -> None:
    """Mirror the guard's audit line so `bb audit` shows client denials too.

    Hash chained through cli.audit_record, so a refusal recorded here cannot be
    edited out of the log without the next line's `prev` disagreeing. The import
    is deferred to keep this module usable from the stdlib-only consumers, and a
    plain append is the fallback: an unchained record of a denial still beats no
    record of it.
    """
    try:
        paths.STATE_DIR.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": utcnow(),
            "engagement": engagement,
            "session": None,
            "tool": "bbh.http",
            "allowed": allowed,
            "command": summary[:2000],
            "checked": [],
            "reasons": reasons,
        }
    except Exception:
        return  # auditing must never break a request
    try:
        from .cli import audit_record

        if audit_record("client_allowed" if allowed else "client_denial", record):
            return
    except Exception:
        pass
    try:
        with paths.AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass  # auditing must never break a request


# -- the client --------------------------------------------------------------


class Session:
    """A scope-checked, rate-limited, fully recorded HTTP session."""

    def __init__(
        self,
        engagement: str | None = None,
        *,
        actor: str | None = None,
        phase: str | None = None,
        store: Store | None = None,
        timeout: float = 20.0,
        verify: bool | str = True,
        proxy: str | None = None,
    ):
        self._engagement_arg = (engagement or "").strip() or None
        self._engagement: str | None = None
        # Mandatory, but refused at request time rather than here: a Session is
        # also how a caller asks whether something is in scope at all, and the
        # answer to that should be the scope's, not a TypeError's.
        self.actor = _given(actor)
        self.phase = phase
        self.timeout = float(timeout)
        self.verify = verify
        self.proxy = proxy
        self._store = store
        self._owns_store = store is None
        self._scope: Scope | None = None
        self._scope_stamp: tuple[int, int] | None = None
        self._limiter: RateLimiter | None = None
        self._breaker_obj: CircuitBreaker | None = None
        self._rules: dict[str, Any] | None = None
        self._client_obj: Any = None
        # The non-owned-object ledger is derived from the request log, scanned
        # incrementally; see _nonowned_touched.
        self._objects_sig: tuple[tuple[str, str, str], ...] | None = None
        self._touched: dict[tuple[str, str], ObjectRef] = {}
        self._scanned_to = 0
        self._actor_noted = False

    # -- bindings ------------------------------------------------------------

    @property
    def engagement(self) -> str:
        """Resolved on first use, then pinned: the store and scope must agree."""
        if self._engagement is None:
            name = self._engagement_arg or paths.active_engagement()
            if not name:
                raise OutOfScope(_deny(_NO_ENGAGEMENT))
            self._engagement = name
        return self._engagement

    @property
    def root(self) -> Path:
        return paths.engagement_dir(self.engagement)

    @property
    def store(self) -> Store:
        if self._store is None:
            self._store = Store(paths.db_path(self.engagement))
        return self._store

    @property
    def redact_extra(self) -> tuple[str, ...]:
        try:
            extra = self._effective_rules(self._scope_now()).get("redact_headers") or ()
        except (OutOfScope, BudgetExceeded):
            return ()
        return tuple(str(h) for h in extra)

    def close(self) -> None:
        if self._client_obj is not None:
            try:
                self._client_obj.close()
            except Exception:
                pass
            self._client_obj = None
        if self._owns_store and self._store is not None:
            self._store.close()
            self._store = None

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- checks --------------------------------------------------------------

    def _scope_now(self) -> Scope:
        """Step 1: reload the lock if it moved, so a disarm lands immediately."""
        name = self.engagement
        lock = paths.lock_path(name)
        try:
            stat = lock.stat()
        except OSError:
            self._scope, self._scope_stamp = None, None
            raise OutOfScope(
                _deny(
                    f"engagement {name!r} has no compiled scope, so no target is authorized.\n"
                    f"  bb scope compile {name}"
                )
            ) from None
        stamp = (stat.st_mtime_ns, stat.st_size)
        if self._scope is None or stamp != self._scope_stamp:
            try:
                scope = Scope.from_lock_file(lock)
            except (ScopeError, OSError, ValueError) as exc:
                self._scope, self._scope_stamp = None, None
                detail = str(exc)
                # A signature or schema failure already carries its own remedy.
                remedy = "" if "bb " in detail else f"\n  bb scope compile {name}"
                raise OutOfScope(
                    _deny(f"engagement {name!r} has an unusable scope lock: {detail}{remedy}")
                ) from None
            self._scope, self._scope_stamp = scope, stamp
            self._limiter = None  # max_rps may have changed with the lock
            self._rules = None  # and so may every other limit
        problem = self._scope.authorization_error()
        if problem:
            raise OutOfScope(_deny(problem))
        return self._scope

    def _effective_rules(self, scope: Scope) -> dict[str, Any]:
        """`scope.rules` clamped by `program_constraints`, cached per lock version."""
        if self._rules is None:
            self._rules = effective_rules(scope)
        return self._rules

    def _target_check(self, scope: Scope, method: str, url: str) -> tuple[str | None, str | None]:
        """Steps 2 and 3. Returns (normalized host, problem); a problem denies."""
        decision = scope.decide(url)
        if not decision.allowed:
            return decision.target or None, decision.reason
        if _scheme(url) not in ("http", "https"):
            return decision.target, (
                f"{url!r} is not an http(s) URL; the sanctioned client only speaks HTTP. "
                "Pass an absolute http:// or https:// URL."
            )
        rules = self._effective_rules(scope)
        permitted = rules["allowed_methods"]
        if method not in permitted:
            allowed = ", ".join(permitted) or "(none)"
            clamped = ""
            if method in {str(m).strip().upper() for m in (scope.rules.get("allowed_methods") or ())}:
                named_by = (
                    "forbidden_tests names it"
                    if _test_name(method) in set(rules.get("forbidden_tests") or ())
                    else "a program_constraints entry removed it"
                )
                clamped = (
                    f"\nscope.yaml allows it; {named_by}, and a program constraint can only "
                    "clamp. Editing rules.allowed_methods will not bring it back."
                )
            return decision.target, (
                f"method {method} is not allowed for engagement {scope.engagement!r} "
                f"(allowed: {allowed}).{clamped}\n"
                f"If the program's rules permit it, add it in scope.yaml:\n"
                f"  rules:\n    allowed_methods: [{method}]\n"
                f"then run: bb scope compile {scope.engagement}"
            )
        return decision.target, None

    def _budget_problem(self, scope: Scope, rules: dict[str, Any] | None = None) -> str | None:
        """Step 4."""
        rules = self._effective_rules(scope) if rules is None else rules
        limit = int(rules.get("max_requests", 20000))
        made = self.store.request_count()
        if made >= limit:
            return (
                f"request budget exhausted for engagement {scope.engagement!r}: "
                f"{made} requests recorded, limit is {limit}.\n"
                f"Raise rules.max_requests in {paths.scope_path(scope.engagement)} then run: "
                f"bb scope compile {scope.engagement}"
            )
        return None

    def _rate_limiter(self, scope: Scope) -> RateLimiter:
        """Step 5.

        The bucket lives wherever `paths` says, which is outside the engagement
        root: `run_phase` hands that root to the agent with `--add-dir`, so a
        token bucket kept inside it is a rate limit the rate-limited process can
        refill. The path is asked for rather than built here so that the client,
        the proxy addon and anything else sharing the bucket cannot drift apart
        and quietly double the engagement's real request rate.
        """
        if self._limiter is None:
            self._limiter = RateLimiter(
                paths.rate_path(scope.engagement),
                float(self._effective_rules(scope).get("max_rps", 2.0)),
            )
        return self._limiter

    def _breaker(self) -> CircuitBreaker:
        """Out of the engagement root for the same reason as the bucket above,
        and more sharply: a breaker a phase can delete is a phase that can
        reopen a host the target closed."""
        if self._breaker_obj is None:
            self._breaker_obj = CircuitBreaker(paths.breaker_path(self.engagement))
        return self._breaker_obj

    # -- v2 controls ---------------------------------------------------------

    def _refuse(self, scope: Scope, summary: str, refusal: Refusal) -> NoReturn:
        """Audit a refusal and raise it. Every control below lands here."""
        _audit(scope.engagement, False, summary, [refusal.reason])
        tail = _back_off if refusal.exc is AvailabilityTripped else _refused
        raise refusal.exc(tail(refusal.reason))

    def _actor_refusal(self, scope: Scope) -> Refusal | None:
        """The acting identity has to exist before a request can mean anything."""
        if self.actor is None:
            return Refusal(
                "this request names no actor, so nothing can attribute it to an identity. An "
                "access-control result only means something relative to who asked, and traffic "
                "recorded against no account is evidence of nothing.\n"
                "  bb req <METHOD> <URL> --actor anon       # deliberately unauthenticated\n"
                "  bb req <METHOD> <URL> --actor <label>    # an account from `bb account list`\n"
                f"  Session({scope.engagement!r}, actor='anon')   # from a script"
            )
        if self.actor == ANON_ACTOR:
            return None
        labels = {str(row["label"]) for row in self.store.accounts()}
        if self.actor in labels:
            return None
        if not labels:
            # Documented bound: before 01-access registers anything there is no
            # roster to check against, and no object has an owner either, so the
            # ownership controls below have nothing to protect. The unverified
            # label is audited once per session rather than refused, so recon can
            # run; the moment one account exists, every actor is checked.
            if not self._actor_noted:
                self._actor_noted = True
                _audit(
                    scope.engagement,
                    True,
                    f"actor {self.actor}",
                    [
                        f"actor {self.actor!r} is unverified: engagement "
                        f"{scope.engagement!r} has no accounts yet, so there is no roster to "
                        f"check it against. Register it: bb account add {self.actor} --role "
                        "attacker"
                    ],
                )
            return None
        return Refusal(
            f"actor {self.actor!r} is not an account of engagement {scope.engagement!r} "
            f"(registered: {', '.join(sorted(labels))}; {ANON_ACTOR!r} is always valid). A "
            "request attributed to an account that does not exist cannot show who may touch "
            "what, and a typo would invent a second identity that proves a finding it never "
            "tested.\n"
            f"  bb account add {self.actor} --role attacker   # if it is a real test account\n"
            f"  ... --actor {ANON_ACTOR}                             # if it is unauthenticated"
        )

    def _availability_refusal(self, scope: Scope, host: str) -> Refusal | None:
        """Refuse a host whose breaker is open -- whoever is asking."""
        if not host:
            return None
        breaker = self._breaker()
        try:
            entry = breaker.open_for(host, self.phase)
        except (ValueError, OSError) as exc:
            return Refusal(
                f"the circuit-breaker state of engagement {scope.engagement!r} cannot be read "
                f"({exc}), so the harness cannot tell which hosts have asked it to stop. Every "
                "request is refused until that is resolved: a brake that cannot verify has to "
                "hold.\n"
                f"The operator -- not this agent -- inspects {breaker.path} and removes it to "
                "reopen every host.",
                AvailabilityTripped,
            )
        if entry is None:
            return None
        return Refusal(self._breaker_reason(host, entry, breaker.path), AvailabilityTripped)

    def _breaker_reason(self, host: str, entry: dict[str, Any], path: Path) -> str:
        phase = _given(entry.get("phase")) or "(no phase)"
        lines = [
            f"{host} asked this engagement to back off at {entry.get('ts')} "
            f"({entry.get('signal')}), and the per-host circuit breaker is open for phase "
            f"{phase}. No further request to {host} leaves the harness.",
            "The cooldown is not waited out: a cooldown is the target saying stop, and "
            "outlasting it is what the program's rules forbid.",
        ]
        tripped_as = _given(entry.get("actor"))
        if tripped_as and tripped_as != self.actor:
            lines.append(
                f"It tripped as actor {tripped_as!r} and this request acts as {self.actor!r}. "
                "Rotating identity to get past a lockout or rate-limit counter is refused here "
                "in code, not discouraged in prose: the counter belongs to the target, not to "
                "the account, and evading it is what gets a researcher banned and a program "
                "closed."
            )
        rid = entry.get("request_id")
        cited = f"request id {rid} and " if rid else ""
        lines.append(
            f"The block is recorded as {cited}angle "
            f"{host} / availability / {entry.get('kind')} = blocked."
        )
        lines.append(
            "Pick one:\n"
            f"  bb angle list --surface {host}                 # what blocked, and when\n"
            "  bb finding advance <ref> blocked --reason '<the host stopped serving this>'\n"
            "  work a different host, or end the phase\n"
            f"Reopening it is the operator's call, not this agent's: {path}"
        )
        return "\n".join(lines)

    def _registered_objects(self) -> list[ObjectRef]:
        return [ObjectRef.from_row(row) for row in self.store.objects()]

    def _nonowned_touched(self, objects: list[ObjectRef]) -> dict[tuple[str, str], ObjectRef]:
        """Every registered object this engagement has reached as a non-owner.

        Derived from the request log rather than from a counter, so it spans
        phases, processes and the proxy, and so removing a state file cannot reset
        it. Scanned incrementally; a change to the objects table restarts the
        scan, because an object registered today still has to be matched against
        yesterday's requests.
        """
        signature = tuple(sorted((o.kind, o.identifier, o.owner or "") for o in objects))
        if signature != self._objects_sig:
            self._objects_sig, self._touched, self._scanned_to = signature, {}, 0
        rows = self.store.conn.execute(
            "SELECT id, actor, url FROM requests WHERE id > ? ORDER BY id", (self._scanned_to,)
        ).fetchall()
        for row in rows:
            self._scanned_to = max(self._scanned_to, int(row["id"]))
            # An unattributed row counts as a non-owner: it cannot prove it was
            # the owner asking.
            actor = _given(row["actor"]) or ANON_ACTOR
            for ref in objects_in_url(row["url"] or "", objects):
                if ref.owner and ref.owner != actor:
                    self._touched[ref.key] = ref
        return self._touched

    def _radius_refusal(
        self, scope: Scope, rules: dict[str, Any], method: str, url: str, reversible: Any
    ) -> Refusal | None:
        """Destructive methods, and the engagement-wide ceiling on other people's records."""
        objects = self._registered_objects()
        if not objects:
            return None
        others = [o for o in objects_in_url(url, objects) if o.owner and o.owner != self.actor]
        if not others:
            return None
        named = "; ".join(o.describe() for o in others)

        if method == "DELETE":
            return Refusal(
                f"DELETE {url} as actor {self.actor!r} targets {named}, which belongs to "
                "another account. A destructive method against someone else's record is "
                "refused outright: the researcher cannot put it back, and a program that "
                "loses a real user's data closes.\n"
                "Show the authorization break without destroying anything:\n"
                f"  bb req GET {url} --actor {self.actor}   # the read is the proof; the "
                "delete is the damage\n"
                "If the DELETE path itself has to be exercised, do it to an object you own:\n"
                f"  bb object add '<label>' --kind <kind> --identifier <id> --owner "
                f"{self.actor}",
                DestructiveRefused,
            )

        if method in ("PUT", "PATCH"):
            problem = reversible_problem(reversible)
            if problem:
                return Refusal(
                    f"{method} {url} as actor {self.actor!r} writes to {named}, which belongs "
                    f"to another account, and {problem}. A write to someone else's record is "
                    "allowed only when the call itself records how the record goes back.\n"
                    "  s.patch(url, json=..., reversible='restore title to \"Q3 plan\" with "
                    "PATCH /api/docs/9 as victim; original captured in request 41')\n"
                    f"  bb req {method} {url} --actor {self.actor} -d '...' --reversible '<the "
                    "same sentence>'\n"
                    "The marker is stored with the request, so the restore is auditable "
                    "instead of remembered.",
                    DestructiveRefused,
                )

        budget = int(rules["max_nonowned_objects"])
        touched = self._nonowned_touched(objects)
        would = dict(touched)
        would.update({o.key: o for o in others})
        if len(would) > budget:
            already = (
                "; ".join(o.describe() for o in list(touched.values())[:10]) or "none yet"
            )
            if len(touched) > 10:
                already += f"; and {len(touched) - 10} more"
            return Refusal(
                f"{method} {url} as actor {self.actor!r} would reach {named}. This engagement "
                f"has already reached {len(touched)} object(s) it does not own ({already}), and "
                f"rules.max_nonowned_objects is {budget} for the whole engagement, not per "
                "phase.\n"
                "The ceiling bounds how many real users' records one hunt can touch: one "
                "proof per class is a finding, a dataset is an incident.\n"
                "Cite what is already proven, or raise the ceiling deliberately:\n"
                "  rules:\n"
                f"    max_nonowned_objects: {budget + 1}\n"
                f"in {paths.scope_path(scope.engagement)} then run: "
                f"bb scope compile {scope.engagement}",
                BlastRadiusExceeded,
            )
        return None

    def _forbidden_refusal(
        self, scope: Scope, rules: dict[str, Any], method: str, label: Any
    ) -> Refusal | None:
        """program_constraints.forbidden_tests, matched on the method and the label."""
        forbidden = set(rules.get("forbidden_tests") or ())
        if not forbidden:
            return None
        for value, what in ((method, "the HTTP method"), (label, "the request label")):
            name = _test_name(value)
            if name and name in forbidden:
                return Refusal(
                    f"{what} {value!r} is one of the program's forbidden_tests "
                    f"({', '.join(sorted(forbidden))}), so the harness will not send it. A "
                    "program constraint only clamps what scope.yaml allows, and this one "
                    "removes this request.\n"
                    "If the program's rules changed, the operator edits program_constraints in "
                    f"{paths.scope_path(scope.engagement)} then runs: "
                    f"bb scope compile {scope.engagement}"
                )
        return None

    def _trip(
        self,
        scope: Scope,
        host: str,
        signal: AvailabilitySignal,
        ids: list[int],
        method: str,
        url: str,
    ) -> NoReturn:
        """Open the breaker, write the ledger row, refuse. Nothing here sleeps."""
        rid = ids[-1] if ids else None
        # The breaker first: if recording the angle fails, the host is closed
        # anyway. The refusal is the control; the ledger row is the record of it.
        self._breaker().trip(
            host,
            phase=self.phase,
            actor=self.actor,
            signal=signal,
            request_id=rid,
            url=url,
            method=method,
        )
        self.store.record_angle(
            host,
            "availability",
            signal.kind,
            "blocked",
            phase=self.phase,
            source="machine",
            note=json.dumps(
                {
                    "actor": self.actor,
                    "method": method,
                    "url": url,
                    "request_id": rid,
                    **signal.as_dict(),
                },
                ensure_ascii=False,
            ),
        )
        reason = "\n".join(
            [
                f"{host} returned {signal.describe()} for {method} {url} as actor "
                f"{self.actor!r}.",
                f"The per-host circuit breaker is now open for phase "
                f"{self.phase or '(no phase)'}: no further request to {host} leaves the "
                "harness, from any actor. Rotating identity to get past the counter is refused "
                "in code, because the counter belongs to the target and evading it is what "
                "gets a researcher banned and a program closed.",
                "The cooldown is not waited out.",
                f"Recorded as {f'request id {rid} and ' if rid else ''}angle "
                f"{host} / availability / {signal.kind} = blocked.",
                "Pick one:\n"
                f"  bb angle list --surface {host}                 # what blocked, and when\n"
                "  bb finding advance <ref> blocked --reason '<the host stopped serving this>'\n"
                "  work a different host, or end the phase",
            ]
        )
        _audit(scope.engagement, False, f"{method} {url}", [reason])
        raise AvailabilityTripped(
            _back_off(reason),
            host=host,
            phase=self.phase,
            signal=signal,
            request_ids=ids,
        )

    def _client(self) -> Any:
        if self._client_obj is None:
            http = _requests().Session()
            if self.proxy:
                http.proxies.update({"http": self.proxy, "https": self.proxy})
            self._client_obj = http
        return self._client_obj

    # -- requests ------------------------------------------------------------

    def request(self, method: str, url: str, **kw: Any) -> "requests.Response":
        """One checked request, plus any redirect hops that are themselves in scope."""
        method = (method or "").strip().upper()
        if not method:
            raise ValueError("request() needs an HTTP method, e.g. s.request('GET', url)")

        follow = bool(kw.pop("allow_redirects", True))
        kw.pop("stream", None)  # the body must be read in full to be recorded
        label = kw.pop("label", None)
        # How a write to someone else's object gets put back. Checked, recorded
        # with the request, and never sent to the target.
        reversible = kw.pop("reversible", None)
        timeout = kw.pop("timeout", None) or self.timeout
        verify = kw.pop("verify", self.verify)
        # `secret://<label>` is what an agent writes in a header or a body; the
        # value is substituted here, on the way out, and nowhere that is written
        # down. The URL is left alone on purpose -- it is recorded verbatim.
        kw = secrets.resolve_sendables(kw, self.engagement)

        scope = self._scope_now()
        summary = f"{method} {url}"
        try:
            rules = self._effective_rules(scope)
        except OutOfScope as exc:
            # A limit the harness cannot read is a refusal like any other, and
            # the operator finds out about it in `bb audit`.
            _audit(scope.engagement, False, summary, [str(exc)])
            raise
        host, problem = self._target_check(scope, method, url)
        if problem:
            _audit(scope.engagement, False, summary, [problem])
            raise OutOfScope(_deny(problem))
        # Availability first among the v2 controls: a host that has told this
        # engagement to stop is refused before anything else is weighed up.
        refusal = self._availability_refusal(scope, host or "")
        if refusal:
            self._refuse(scope, summary, refusal)
        budget = self._budget_problem(scope, rules)
        if budget:
            _audit(scope.engagement, False, summary, [budget])
            raise BudgetExceeded(budget)
        # Who is asking is settled before what it is allowed to touch: every
        # ownership comparison below is relative to the actor.
        for check in (
            lambda: self._actor_refusal(scope),
            lambda: self._forbidden_refusal(scope, rules, method, label),
            lambda: self._radius_refusal(scope, rules, method, url, reversible),
        ):
            refusal = check()
            if refusal:
                self._refuse(scope, summary, refusal)

        bodies = self.root / "raw" / "bodies"
        redact_extra = tuple(rules.get("redact_headers") or ())
        # Resolved like any other sendable: a program-mandated header may carry
        # `secret://<label>` when the program issues researchers a token.
        required = secrets.resolve_sendables(rules.get("required_headers") or {}, self.engagement)
        hops: list[RedirectHop] = []
        ids: list[int] = []
        stopped: str | None = None
        waited = 0.0
        network_ms = 0
        cur_method, cur_url, cur_host, cur_kw = method, url, host or "", dict(kw)
        response: Any = None

        while True:
            # Re-applied per hop: a program-mandated header is how the target
            # tells our traffic apart from an attack, so it travels on every
            # request the harness makes, including the ones a redirect causes.
            cur_kw = _with_required(cur_kw, required)
            waited += self._rate_limiter(scope).acquire(cur_host)
            started = time.perf_counter()
            try:
                response = self._client().request(
                    cur_method,
                    cur_url,
                    timeout=timeout,
                    verify=verify,
                    allow_redirects=False,
                    **cur_kw,
                )
            except Exception as exc:
                duration = int((time.perf_counter() - started) * 1000)
                rid = self._record(
                    method=cur_method,
                    url=cur_url,
                    host=cur_host,
                    duration_ms=duration,
                    response=None,
                    prepared=getattr(exc, "request", None),
                    redact_extra=redact_extra,
                    bodies=bodies,
                    label=label,
                    # A write that timed out may still have landed, so the
                    # restore plan is recorded on the failure path too.
                    reversible=reversible,
                    hop=None,
                    stopped=stopped,
                    error=f"{type(exc).__name__}: {exc}",
                )
                raise TransportError(
                    f"{cur_method} {cur_url} failed after {duration} ms: "
                    f"{type(exc).__name__}: {exc}\n"
                    f"The attempt is recorded as request id {rid}. Confirm the host resolves "
                    f"and is still in scope: bb scope check {cur_url}"
                ) from None

            duration = int((time.perf_counter() - started) * 1000)
            network_ms += duration

            signal = availability_signal(response)
            if signal is not None:
                # Recorded first, so the ledger row and the exception can cite
                # it; a host that is telling us to stop gets no redirect hop.
                ids.append(
                    self._record(
                        method=cur_method,
                        url=response.url or cur_url,
                        host=cur_host,
                        duration_ms=duration,
                        response=response,
                        prepared=response.request,
                        redact_extra=redact_extra,
                        bodies=bodies,
                        label=label,
                        reversible=reversible,
                        hop=None,
                        stopped=f"availability: {signal.describe()}",
                        error=None,
                    )
                )
                self._trip(scope, cur_host, signal, ids, cur_method, cur_url)

            hop, stop = self._next_hop(
                scope, response, cur_method, follow, len(hops), reversible
            )
            if stop:
                stopped = stop
                _audit(scope.engagement, False, f"{cur_method} {cur_url} -> redirect", [stop])
            ids.append(
                self._record(
                    method=cur_method,
                    url=response.url or cur_url,
                    host=cur_host,
                    duration_ms=duration,
                    response=response,
                    prepared=response.request,
                    redact_extra=redact_extra,
                    bodies=bodies,
                    label=label,
                    reversible=reversible,
                    hop=hop,
                    stopped=stop,
                    error=None,
                )
            )
            if hop is not None:
                hops.append(hop)
            if hop is None or not hop.followed:
                break
            cur_kw = _next_kwargs(
                cur_kw, drop_body=hop.method != cur_method, cross_host=hop.to_host != cur_host
            )
            cur_method, cur_url, cur_host = hop.method, hop.to_url, hop.to_host

        response.bbh_request_id = ids[-1]
        response.bbh_request_ids = ids
        response.bbh_redirects = hops
        response.bbh_stopped = stopped
        response.bbh_duration_ms = network_ms
        response.bbh_waited_ms = int(waited * 1000)
        response.bbh_engagement = scope.engagement
        return response

    def _next_hop(
        self,
        scope: Scope,
        response: Any,
        method: str,
        follow: bool,
        hops_done: int,
        reversible: Any = None,
    ) -> tuple[RedirectHop | None, str | None]:
        """Decide one redirect. Returns (hop, reason the chain stopped)."""
        location = (response.headers.get("location") or "").strip()
        if response.status_code not in REDIRECT_STATUSES or not location:
            return None, None

        from_url = response.url or ""
        to_url = _join(from_url, location)
        if not to_url:
            reason = f"redirect Location {location!r} is not a usable URL; not followed"
            return (
                RedirectHop(response.status_code, from_url, location, "", method, False, reason),
                reason,
            )

        next_method = redirect_method(method, response.status_code)
        to_host = host_from_url(to_url) or ""
        followed = False
        reason: str | None = None
        stop: str | None = None

        if not follow:
            reason = "allow_redirects=False; the 3xx is returned as-is"
        elif hops_done >= MAX_REDIRECTS:
            reason = stop = f"redirect chain exceeded {MAX_REDIRECTS} hops; stopped here"
        else:
            checked_host, problem = self._target_check(scope, next_method, to_url)
            to_host = checked_host or to_host
            # Every control the first hop passed is re-run on this one: a 307 to
            # a different path keeps the method, and a chain is a cheap way to
            # arrive somewhere the gauntlet would have refused.
            onward = problem or self._budget_problem(scope)
            if not onward:
                # The marker travels with the hop: a 307 onto the same object is
                # the write the caller already said how to undo.
                refusal = self._availability_refusal(scope, to_host) or self._radius_refusal(
                    scope, self._effective_rules(scope), next_method, to_url, reversible
                )
                onward = refusal.reason if refusal else None
            if onward:
                reason = stop = f"redirect not followed: {onward}"
            else:
                followed = True

        return (
            RedirectHop(
                response.status_code, from_url, to_url, to_host, next_method, followed, reason
            ),
            stop,
        )

    def _record(
        self,
        *,
        method: str,
        url: str,
        host: str,
        duration_ms: int,
        response: Any,
        prepared: Any,
        redact_extra: Iterable[str],
        bodies: Path,
        label: str | None,
        hop: RedirectHop | None,
        stopped: str | None,
        error: str | None,
        reversible: Any = None,
    ) -> int:
        """Step 7: persist the exchange and return its store row id."""
        req_body = persist_body(bodies, _prepared_body(prepared))
        resp_body = persist_body(bodies, response.content if response is not None else None)

        note: dict[str, Any] = {}
        if label:
            note["label"] = label
        # The restore plan is part of the record, not a parameter the caller
        # remembers: a report has to be able to show what was promised.
        marker = _given(reversible)
        if marker:
            note["reversible"] = marker
        if error:
            note["error"] = error
        if hop is not None:
            note["redirect"] = hop.as_dict()
        if stopped:
            note["stopped"] = stopped
        if req_body.inline is not None:
            note["req_body"] = req_body.inline
        if resp_body.inline is not None:
            note["resp_body"] = resp_body.inline

        path, query = _split(url)
        return self.store.add_request(
            phase=self.phase,
            source="client",
            actor=self.actor,
            method=method,
            url=url,
            host=host,
            path=path or "/",
            query=query or None,
            status=response.status_code if response is not None else None,
            req_headers=(
                redact_headers(prepared.headers or {}, redact_extra)
                if getattr(prepared, "headers", None) is not None
                else None
            ),
            req_body_path=req_body.path,
            req_body_sha256=req_body.sha256,
            # NULL, not {}: there was no response at all, which is not the same
            # as a response that carried no headers.
            resp_headers=(
                redact_headers(response.headers, redact_extra) if response is not None else None
            ),
            resp_body_path=resp_body.path,
            resp_body_sha256=resp_body.sha256,
            resp_len=resp_body.length if response is not None else None,
            duration_ms=duration_ms,
            note=json.dumps(note, ensure_ascii=False) if note else None,
        )

    # -- verbs ---------------------------------------------------------------

    def get(self, url: str, **kw: Any) -> "requests.Response":
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> "requests.Response":
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw: Any) -> "requests.Response":
        """PUT. Against an object another account owns, pass
        `reversible='<how this is put back>'`; see `_radius_refusal`."""
        return self.request("PUT", url, **kw)

    def patch(self, url: str, **kw: Any) -> "requests.Response":
        """PATCH. Same reversible marker rule as `put`."""
        return self.request("PATCH", url, **kw)

    def delete(self, url: str, **kw: Any) -> "requests.Response":
        """DELETE. Refused outright against an object another account owns."""
        return self.request("DELETE", url, **kw)

    def head(self, url: str, **kw: Any) -> "requests.Response":
        return self.request("HEAD", url, **kw)

    def options(self, url: str, **kw: Any) -> "requests.Response":
        return self.request("OPTIONS", url, **kw)


# -- bb req ------------------------------------------------------------------

_REQ_USAGE = (
    "usage: bb req <METHOD> <URL> --actor NAME [-H 'K: V'] [-d DATA|@FILE]\n"
    "               [--label NAME] [--reversible 'how this is put back']\n"
    "               [--save-as NAME] [--timeout SECONDS] [--no-follow] [--insecure]"
)


class _ArgError(RuntimeError):
    """A usage problem, reported with a remedy instead of an argparse exit."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:  # argparse would SystemExit(2); 2 means OutOfScope
        raise _ArgError(message)


def _req_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="bb req", description="Make one scope-checked, recorded HTTP request.")
    p.add_argument("method", nargs="?", default=None, help="HTTP method (default: GET)")
    p.add_argument("url", nargs="?", default=None, help="absolute http(s) URL")
    p.add_argument("-X", "--request", dest="method_flag", default=None, help="method, curl style")
    p.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'")
    p.add_argument(
        "-d", "--data", action="append", default=[], metavar="DATA",
        help="request body; @FILE reads a file, repeats are joined with &",
    )
    # No default: an unauthenticated request says `--actor anon` out loud, so
    # that nothing is recorded against an identity nobody chose.
    p.add_argument("--actor", default=None,
                   help="account label this request acts as; 'anon' for unauthenticated")
    p.add_argument("--phase", default=None, help="phase key to tag the request with")
    p.add_argument("--label", default=None,
                   help="what this request is testing; checked against forbidden_tests")
    p.add_argument("--reversible", default=None, metavar="HOW",
                   help="required for PUT/PATCH on another account's object: how it is restored")
    p.add_argument("-e", "--engagement", default=None, help="override the active engagement")
    p.add_argument("--save-as", dest="save_as", default=None, metavar="NAME",
                   help="also write a redacted transcript to evidence/<NAME>.http")
    p.add_argument("--timeout", type=float, default=20.0, metavar="SECONDS")
    p.add_argument("--no-follow", dest="follow", action="store_false", default=True,
                   help="return the 3xx instead of following it")
    p.add_argument("-k", "--insecure", action="store_true", help="do not verify TLS certificates")
    return p


def _read_data(items: list[str]) -> bytes | None:
    """curl semantics: @file reads a file, repeated -d values join with &."""
    chunks: list[bytes] = []
    for item in items:
        if item.startswith("@"):
            path = Path(item[1:]).expanduser()
            try:
                chunks.append(path.read_bytes())
            except OSError as exc:
                raise _ArgError(
                    f"cannot read -d {item!r}: {exc.strerror or exc}. "
                    "Pass a readable path, or give the body inline."
                ) from None
        else:
            chunks.append(item.encode("utf-8"))
    return b"&".join(chunks) if chunks else None


def _parse_headers(items: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in items:
        if ":" not in raw:
            raise _ArgError(
                f"header {raw!r} is not 'Name: value'. Quote it: -H 'X-Token: abc123'"
            )
        name, _, value = raw.partition(":")
        if not name.strip():
            raise _ArgError(f"header {raw!r} has no name. Quote it: -H 'X-Token: abc123'")
        headers[name.strip()] = value.strip()
    return headers


def _resolve_target(args: argparse.Namespace) -> tuple[str, str]:
    method, url = args.method, args.url
    if url is None and method and ("://" in method or method.startswith("//")):
        method, url = None, method  # `bb req https://host/path` means GET
    method = (args.method_flag or method or "GET").strip().upper()
    if not url:
        raise _ArgError("a URL is required")
    url = url.strip()
    if "://" not in url:
        # Not guessed: http and https are different attack surfaces, and a
        # silent upgrade turns a plaintext finding into a connection error.
        raise _ArgError(f"URL {url!r} has no scheme. Write it in full: https://{url.lstrip('/')}")
    return method, url


def _save_transcript(session: Session, response: Any, name: str) -> Path:
    dest = session.root / "evidence" / f"{name}.http"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(transcript(response, redact_extra=session.redact_extra), encoding="utf-8")
    return dest


def _print_result(session: Session, response: Any, save_as: str | None) -> None:
    """Print one exchange: harness facts in the open, target bytes in a fence.

    `HARNESS_RULES` teaches the agent that fenced content is data a target
    produced and never an instruction. The most target-controlled bytes in the
    system arrive here, through a tool result rather than through a prompt, so
    they are fenced here too -- otherwise the rule is true of prompts and false
    of the channel the agent actually reads responses on.

    The nonce is fresh per invocation and the fenced text is scrubbed, so a body
    captured before this process started cannot name the tag that would close
    it. Only what is PRINTED changes: `persist_body` has already written the
    body to raw/bodies/<sha256>.bin byte-exact, and that file is what evidence
    cites and re-hashes.
    """
    nonce = new_nonce()
    body = response.content or b""
    print(f"{response.request.method} {_inline(response.url, nonce, URL_PREVIEW)}")
    print(
        f"  {response.status_code} {_inline(response.reason or '', nonce, 64)}".rstrip()
        + f"  {response.bbh_duration_ms} ms  {len(body)} bytes"
    )
    if response.bbh_waited_ms:
        print(f"  throttled {response.bbh_waited_ms} ms to stay inside the engagement rate limit")
    for hop in response.bbh_redirects:
        # The verdict and its reason are the harness speaking; the Location it
        # is speaking about was chosen by the target.
        verdict = "followed" if hop.followed else f"NOT followed: {hop.reason}"
        print(f"  {hop.status} -> {_inline(hop.to_url, nonce, URL_PREVIEW)}  [{verdict}]")

    # Live output is not redacted: the operator already holds these credentials
    # and needs the Set-Cookie to drive the next request. Only what is written
    # to the store and to saved transcripts is hashed.
    header_lines = [
        f"{_inline(key, nonce, 128)}: {_inline(value, nonce, HEADER_VALUE_PREVIEW)}"
        for key, value in flatten_headers(response.headers).items()
    ]
    print("\nresponse headers:")
    print(fence("\n".join(header_lines), source="response headers", nonce=nonce,
                cap=HEADERS_PREVIEW))

    text = decoded_body(body)
    if not body:
        print("\nbody: (empty)")
    elif text is None:
        # Nothing to fence: there are no printable target bytes, only the digest
        # the harness computed over them.
        print(f"\nbody: binary, {len(body)} bytes, sha256:{sha256_bytes(body)}")
    else:
        print(f"\nbody ({len(body)} bytes, sha256:{sha256_bytes(body)[:16]}):")
        print(fence(escape_controls(text, keep_newlines=True), source="response body",
                    nonce=nonce, cap=BODY_PREVIEW))
    if body and len(body) > BODY_INLINE_MAX:
        print(f"  full body: {session.root / 'raw' / 'bodies' / (sha256_bytes(body) + '.bin')}")

    rid = response.bbh_request_id
    print(f"\nrequest id: {rid}")
    print(f"  cite it:  bb evidence add <finding> request --request-id {rid}")
    if save_as:
        dest = _save_transcript(session, response, save_as)
        print(f"  saved:    {dest}")
        print(f"  attach:   bb evidence add <finding> request {dest}")


def cli_req(argv: list[str] | None = None) -> int:
    """`bb req`: one request, printed for a human and recorded for a report."""
    parser = _req_parser()
    try:
        args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
        method, url = _resolve_target(args)
        headers = _parse_headers(args.header)
        data = _read_data(args.data)
        if args.save_as and not _SAVE_AS_RE.fullmatch(args.save_as):
            raise _ArgError(
                f"--save-as {args.save_as!r} must be a plain name (letters, digits, . _ -), "
                "not a path; it is written under the engagement's evidence/ directory"
            )
    except _ArgError as exc:
        print(f"bb req: {exc}", file=sys.stderr)
        print(_REQ_USAGE, file=sys.stderr)
        return 1
    except SystemExit as exc:  # --help
        return int(exc.code or 0)

    if data is not None and not any(k.lower() == "content-type" for k in headers):
        # curl's default. Stated out loud, because the wrong content type is a
        # common reason a real finding looks like a dud.
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        print("note: no -H 'Content-Type: ...' given, sending application/x-www-form-urlencoded")

    session = Session(
        args.engagement,
        actor=args.actor,
        phase=args.phase,
        timeout=args.timeout,
        verify=not args.insecure,
    )
    try:
        response = session.request(
            method,
            url,
            headers=headers or None,
            data=data,
            allow_redirects=args.follow,
            label=args.label,
            reversible=args.reversible,
        )
        _print_result(session, response, args.save_as)
        return 0
    except OutOfScope as exc:  # also BlastRadiusExceeded, DestructiveRefused
        print(f"bb req: {exc}", file=sys.stderr)
        return 2
    except BudgetExceeded as exc:
        print(f"bb req: {exc}", file=sys.stderr)
        return 3
    except AvailabilityTripped as exc:
        # Its own code: the target stopped serving us, which is not a budget the
        # operator chose and not something a retry fixes.
        print(f"bb req: {exc}", file=sys.stderr)
        return 4
    except (RuntimeError, OSError, ValueError) as exc:  # TransportError, StoreError, bad args
        print(f"bb req: {exc}", file=sys.stderr)
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(cli_req())
