"""Credential indirection, and the scanner that keeps values out of artifacts.

The harness authenticates to a target, and nearly everything else it does is
designed to be written down: request rows, stream-json transcripts, handoff
files, prompts, reports. Those two facts collide, and the collision is one-way:
a credential that reaches an artifact is already gone, because the artifact is
what gets attached to a submission or read back into the next phase's prompt.

So there is exactly one place a secret VALUE lives -- 0600
`engagements/<e>/sensitive/secrets.json`, inside a 0700 directory -- and two
mechanical directions around it:

  * **out.** An agent writes `secret://<label>` wherever a credential belongs:
    a header, a form field, an account note, a script. `bbh.http.Session`
    resolves refs at send time through `resolve_sendables`, so the value exists
    in the outbound request and nowhere else.
  * **in.** `scan_text` looks for the stored values -- raw, base64,
    percent-encoded and JSON-escaped -- in anything about to be written or
    printed. `bbh.report.render` refuses to emit a report that carries one, and
    `bbh.runner` must pass every stream-json line through `redact` before it
    lands in `raw/phases/`, because the model's own transcript of a request is
    the likeliest place for a session cookie to resurface.

Honest bound: the values are stored in cleartext, because the harness has to
send them, and encrypting them under a key the same uid can read would buy
tamper-evidence at best, never secrecy. What the indirection buys is that one
file is the only place to look, the only thing to shred when the engagement
ends, and the thing every other writer is scanned against.

A value shorter than MIN_SECRET_CHARS is refused at `put` time rather than
stored: scanning for a four-character string would flag ordinary prose, and a
control that cries wolf gets switched off. Use a longer test credential.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

from . import paths

SCHEME = "secret://"
SCHEMA_VERSION = 1

# Labels are filename-safe and shell-safe: they travel through argv, prompts and
# `--secret-ref` values, and a label that needs quoting is a label an agent will
# mangle.
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
REF_RE = re.compile(r"secret://([A-Za-z0-9][A-Za-z0-9._-]{0,63})")

# Below this, a value cannot be told apart from ordinary text, so the scanner
# would refuse every report. Refusing the value instead keeps the scan sound.
MIN_SECRET_CHARS = 6

__all__ = [
    "SecretError",
    "SCHEME",
    "MIN_SECRET_CHARS",
    "secrets_file",
    "ref",
    "put",
    "get",
    "labels",
    "entries",
    "resolve_text",
    "resolve_sendables",
    "scan_text",
    "redact",
    "leak_problem",
    "harden_raw",
    "shred_hint",
]


class SecretError(RuntimeError):
    """A secret could not be stored or resolved. The message carries the remedy."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engagement(name: str | None) -> str:
    chosen = (name or "").strip() or (paths.active_engagement() or "")
    if not chosen:
        raise SecretError(
            "no engagement given and none is active, so there is no sensitive/ directory "
            "to put a secret in.\n"
            "  bb list\n"
            "  bb use <engagement>"
        )
    return chosen


def secrets_file(engagement: str | None = None) -> Path:
    """The one file that holds values, for one engagement."""
    return paths.engagement_dir(_engagement(engagement)) / "sensitive" / "secrets.json"


def ref(label: str) -> str:
    """The reference an agent writes instead of the value."""
    return f"{SCHEME}{label}"


def _check_label(label: str) -> str:
    text = (label or "").strip()
    if not LABEL_RE.fullmatch(text):
        raise SecretError(
            f"{label!r} is not a usable secret label. Use letters, digits, dot, dash or "
            "underscore, up to 64 characters, e.g.\n"
            "  bb secret put attacker-session"
        )
    return text


# -- the file ----------------------------------------------------------------
#
# Loaded through a cache keyed on (mtime_ns, size): `redact` runs over every
# stream-json line a phase produces, so re-reading and re-deriving the match
# forms per line would be the most expensive thing in the loop.

_cache: dict[str, tuple[tuple[int, int], dict[str, dict[str, Any]]]] = {}


def _forms(value: str) -> tuple[str, ...]:
    """Every shape the value can take in a written artifact.

    A cookie arrives percent-encoded in a URL, base64 inside a Basic header, and
    backslash-escaped inside a stream-json line. Matching only the raw value
    would miss all three.
    """
    raw = value.encode("utf-8", "surrogateescape")
    forms = {
        value,
        base64.b64encode(raw).decode("ascii"),
        base64.b64encode(raw).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        quote(value, safe=""),
        json.dumps(value)[1:-1],
    }
    return tuple(sorted((f for f in forms if len(f) >= MIN_SECRET_CHARS), key=len, reverse=True))


def _load(engagement: str) -> dict[str, dict[str, Any]]:
    """Secrets for one engagement as {label: {"value", "forms", ...}}."""
    path = paths.engagement_dir(engagement) / "sensitive" / "secrets.json"
    try:
        info = path.stat()
    except OSError:
        _cache.pop(engagement, None)
        return {}
    stamp = (info.st_mtime_ns, info.st_size)
    cached = _cache.get(engagement)
    if cached is not None and cached[0] == stamp:
        return cached[1]

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        # Fail closed: a store we cannot read is a store we cannot scan against,
        # and every caller here is about to write something.
        raise SecretError(
            f"cannot read the secret store {path}: {exc}\n"
            "Nothing can be resolved or scanned until it parses. Inspect it, or move it "
            "aside and re-record the labels (this discards the values):\n"
            f"  mv {path} {path}.broken"
        ) from exc
    held = data.get("secrets") if isinstance(data, Mapping) else None
    out: dict[str, dict[str, Any]] = {}
    if isinstance(held, Mapping):
        for label, entry in held.items():
            if not isinstance(entry, Mapping):
                continue
            value = entry.get("value")
            if not isinstance(value, str) or not value:
                continue
            out[str(label)] = {**entry, "value": value, "forms": _forms(value)}
    _cache[engagement] = (stamp, out)
    return out


def _write(engagement: str, held: dict[str, dict[str, Any]]) -> Path:
    """Replace the store atomically, 0600, inside a 0700 sensitive/."""
    root = paths.engagement_dir(engagement) / "sensitive"
    try:
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o700)
    except OSError as exc:
        raise SecretError(
            f"cannot secure {root}: {exc.strerror or exc}. A secret is not written to a "
            f"directory the harness cannot restrict.\n  mkdir -p {root} && chmod 700 {root}"
        ) from exc

    path = root / "secrets.json"
    document = {
        "schema": SCHEMA_VERSION,
        "engagement": engagement,
        "note": "values in cleartext at 0600; bb scans every report and transcript for them",
        "secrets": {
            label: {k: v for k, v in entry.items() if k != "forms"}
            for label, entry in sorted(held.items())
        },
    }
    tmp = root / f".secrets.{os.getpid()}.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, (json.dumps(document, indent=2) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, path)
        path.chmod(0o600)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise SecretError(
            f"cannot write the secret store {path}: {exc.strerror or exc}\n"
            f"  bb status {engagement}"
        ) from exc
    _cache.pop(engagement, None)
    return path


# -- recording and resolving -------------------------------------------------


def put(label: str, value: str, *, engagement: str | None = None, note: str | None = None) -> str:
    """Record one value and return the reference that stands in for it."""
    name = _engagement(engagement)
    key = _check_label(label)
    if not isinstance(value, str) or not value.strip():
        raise SecretError(
            f"secret {key!r} has no value. The value is read from stdin so it never lands in "
            f"argv, the shell history or the audit log:\n"
            f"  printf '%s' '<value>' | bb secret put {key}"
        )
    if value.startswith(SCHEME):
        raise SecretError(
            f"{value!r} is a reference, not a value: storing it would make "
            f"{ref(key)} resolve to another reference. Pass the credential itself."
        )
    if len(value) < MIN_SECRET_CHARS:
        raise SecretError(
            f"the value for {key!r} is {len(value)} characters; a value shorter than "
            f"{MIN_SECRET_CHARS} cannot be told apart from ordinary text, so the leak scanner "
            f"would flag every report and transcript.\n"
            f"Use a longer test credential and record that instead:\n"
            f"  printf '%s' '<longer value>' | bb secret put {key}"
        )

    held = {k: dict(v) for k, v in _load(name).items()}
    held[key] = {
        "sha256": hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()[:16],
        "chars": len(value),
        "ts": _utcnow(),
        "note": note,
        "value": value,
    }
    _write(name, held)
    harden_raw(name)
    return ref(key)


def get(label: str, engagement: str | None = None) -> str:
    """The value behind a label. Raises rather than returning a placeholder."""
    name = _engagement(engagement)
    key = _check_label(label)
    entry = _load(name).get(key)
    if entry is None:
        known = ", ".join(sorted(_load(name))) or "none recorded"
        raise SecretError(
            f"no secret labelled {key!r} for engagement {name!r} (recorded: {known}).\n"
            f"Record it -- the value is read from stdin, so it stays out of argv and the "
            f"audit log:\n"
            f"  printf '%s' '<value>' | bb secret put {key}"
        )
    return str(entry["value"])


def labels(engagement: str | None = None) -> list[str]:
    return sorted(_load(_engagement(engagement)))


def entries(engagement: str | None = None) -> list[dict[str, Any]]:
    """Metadata for every label. Never the value: this is what `bb secret list` prints."""
    out = []
    for label, entry in sorted(_load(_engagement(engagement)).items()):
        out.append(
            {
                "label": label,
                "ref": ref(label),
                "sha256": entry.get("sha256"),
                "chars": entry.get("chars"),
                "ts": entry.get("ts"),
                "note": entry.get("note"),
            }
        )
    return out


def resolve_text(text: str, engagement: str | None = None) -> str:
    """Replace every `secret://<label>` in a string with its value."""
    if SCHEME not in text:
        return text
    name = _engagement(engagement)
    return REF_RE.sub(lambda m: get(m.group(1), name), text)


def resolve_sendables(payload: Any, engagement: str | None = None) -> Any:
    """Resolve refs anywhere inside request kwargs, on the way out.

    This is the single call `bbh.http.Session.request` makes, so headers, form
    fields, JSON bodies and query parameters all accept `secret://<label>`
    without any of them having to know about this module. Values that are not
    text -- file objects, generators, numbers -- are handed back untouched.

    The URL is deliberately NOT resolved by the caller: a URL is recorded
    verbatim in the request log, so a credential in one would be persisted in
    cleartext. Put it in a header or a body.
    """
    if isinstance(payload, str):
        return resolve_text(payload, engagement)
    if isinstance(payload, bytes):
        if SCHEME.encode("ascii") not in payload:
            return payload
        text = payload.decode("utf-8", "surrogateescape")
        return resolve_text(text, engagement).encode("utf-8", "surrogateescape")
    if isinstance(payload, Mapping):
        return {k: resolve_sendables(v, engagement) for k, v in payload.items()}
    if isinstance(payload, (list, tuple)):
        resolved = [resolve_sendables(item, engagement) for item in payload]
        return type(payload)(resolved) if isinstance(payload, tuple) else resolved
    return payload


# -- scanning ----------------------------------------------------------------


def scan_text(text: str, engagement: str | None = None) -> list[str]:
    """Labels whose stored VALUE appears in `text`, in any of its written forms.

    An empty list means no recorded value is in there. With no engagement and no
    secret store there is nothing to match, so the answer is also an empty list;
    a store that exists but cannot be parsed raises instead, because then the
    question has no answer and the caller is about to write the text out.
    """
    if not text:
        return []
    name = (engagement or "").strip() or (paths.active_engagement() or "")
    if not name:
        return []
    hits = [
        label
        for label, entry in _load(name).items()
        if any(form in text for form in entry["forms"])
    ]
    return sorted(hits)


def redact(text: str, engagement: str | None = None) -> str:
    """Swap stored values for their references, keeping the text otherwise intact.

    Used on anything that must still be written after a value turns up in it --
    a stream-json transcript, a saved body. The substitution is deliberately the
    reference and not a hash: a later reader can tell what was there, and the
    line stays valid JSON because a reference needs no escaping.
    """
    if not text:
        return text
    name = (engagement or "").strip() or (paths.active_engagement() or "")
    if not name:
        return text
    for label, entry in _load(name).items():
        for form in entry["forms"]:
            if form in text:
                text = text.replace(form, ref(label))
    return text


def leak_problem(text: str, *, where: str, engagement: str | None = None) -> str | None:
    """The refusal message for text that carries a secret value, or None.

    `bbh.report.render` calls this and raises on anything but None. The message
    names the labels rather than quoting the match, because the message itself
    gets printed and logged.
    """
    found = scan_text(text, engagement)
    if not found:
        return None
    name = (engagement or "").strip() or (paths.active_engagement() or "") or "<engagement>"
    listed = ", ".join(found)
    return (
        f"refusing to emit {where}: it contains the value of secret(s) {listed}, recorded in "
        f"{paths.engagement_dir(name) / 'sensitive' / 'secrets.json'}. A credential in a "
        f"submitted artifact is a disclosure of its own.\n"
        f"Replace the value with its reference in whatever field carries it, e.g.\n"
        f"  bb finding set <ref> --repro '... Authorization: Bearer {ref(found[0])} ...'\n"
        f"then re-run this command. If the value is coming from a captured response body "
        f"rather than from your own text, cite a request that does not return it:\n"
        f"  bb evidence list <ref>\n"
        f"If the match is spurious because the recorded value is also ordinary text, rotate "
        f"the test credential to something distinctive:\n"
        f"  printf '%s' '<new value>' | bb secret put {found[0]}"
    )


# -- the raw/ tree -----------------------------------------------------------


def harden_raw(engagement: str | None = None) -> Path:
    """Create `raw/` and restrict every directory in it to 0700. Returns raw/.

    `raw/` accumulates response bodies, phase transcripts and spilled command
    output: target data, and the one tree whose contents nobody chose to write
    by hand. Restricting the directories is enough to stop another local account
    reading the files inside, and it is cheap enough to call on every write path
    because a mode that already matches is left alone.
    """
    root = paths.engagement_dir(_engagement(engagement)) / "raw"
    try:
        root.mkdir(parents=True, exist_ok=True)
        if root.stat().st_mode & 0o777 != 0o700:
            root.chmod(0o700)
    except OSError as exc:
        raise SecretError(
            f"cannot secure {root}: {exc.strerror or exc}. Captured bodies and phase "
            f"transcripts would be readable by other accounts on this machine.\n"
            f"  mkdir -p {root} && chmod 700 {root}"
        ) from exc
    for dirpath, dirnames, _ in os.walk(root):
        for name in dirnames:
            child = Path(dirpath) / name
            try:
                if child.stat().st_mode & 0o777 != 0o700:
                    child.chmod(0o700)
            except OSError:
                continue  # a sub-tree we do not own is reported by `bb doctor`, not here
    return root


def shred_hint(engagement: str | None = None) -> str:
    """What to delete when the engagement ends; printed by `bb secret list`."""
    return f"rm -f {secrets_file(engagement)}"
