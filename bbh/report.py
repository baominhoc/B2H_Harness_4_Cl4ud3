"""Report rendering: the one artifact that leaves the machine.

Everything else in the harness talks to the agent. A report talks to a human
triager, who will reject it on the first claim that does not hold up. So
nothing here is taken on the finding's word: the reproduction steps are rebuilt
from the recorded requests, the evidence list is re-hashed while the report is
written, and the scope statement is resolved through the same compiled rules
the guard enforces. Prose the agent wrote is quoted, never promoted to proof.

The agent supplies prose for exactly three sections -- Summary, Impact,
Remediation -- and nothing else here comes from it. The finding table, the
numbered reproduction, the evidence manifest and the scope statement are
generated from the store on every render, so a write-up cannot describe a
request that was never made.

Two failure modes are kept deliberately apart:

  * the report would be *false or unusable* -- wrong state, a state no gate
    ever produced, evidence that no longer matches its hash, an asset no
    in-scope rule covers, a recorded credential value sitting in the text --
    and rendering raises rather than emitting a draft that reads like proof;
  * the report would be *true but thin* -- no severity, no cited request, a
    gate failure on record -- and the weakness is printed inside the report,
    where the triager and the agent both see it.

The second bullet is why a *recorded* gate failure is printed rather than
refused, and the first is why no record at all is not the same thing. A
finding reaches `gated` by passing gates, but `findings.state` is a column and
`bb finding advance <uid> gated` writes it by name -- so the state alone was
one command away from laundering a candidate with no evidence into a document
a human acts on. `ungated_requirements` recomputes from the `gates` rows, which
nothing but the triage module writes a `pass` into. Honest bound, the same one
the spend ledger carries: those rows live in the engagement's sqlite file,
which `run_phase` hands the agent with `--add-dir`, so this raises the cost of
the bypass from one published command to fabricating a row per gate. The
findings, evidence and angles in that file are the agent's own output and have
nowhere else to live.

Reports are reproducible from the store alone: given the sqlite database and
the raw/ + evidence/ trees, rendering the same finding twice yields the same
document apart from its generation timestamp.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

from . import paths, secrets, triage, waiver
from .scope import SCHEMA_VERSION, Decision, Scope
from .store import Store, sha256_bytes

# A report is only written for a finding that has cleared the gates.
REPORTABLE_STATES = ("gated", "ready")

# Mirrors the capture layer's redaction set. A report is the last place a live
# credential could escape, so the check is repeated at render time instead of
# assuming whatever wrote the row got it right.
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-session-token",
        "x-access-token",
        "x-csrf-token",
    }
)

REDACTION_MARKERS = ("<redacted", "[redacted", "REDACTED")

# Set by whatever client replays the request; noise in a reproduction block.
NOISE_HEADERS = frozenset(
    {
        "accept-encoding",
        "connection",
        "content-length",
        "dnt",
        "keep-alive",
        "priority",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "te",
        "upgrade-insecure-requests",
    }
)

# Keys the HTTP client may use to stash a small body in the request note.
REQ_BODY_KEYS = ("req_body", "request_body", "body")
RESP_BODY_KEYS = ("resp_body", "response_body")

MAX_BODY_CHARS = 1200
MAX_SUMMARY_ANGLES = 40
MAX_SUMMARY_HOSTS = 8

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Reading order for the summary: what a human wants to see first.
STATE_ORDER = ("ready", "gated", "verified", "validated", "candidate", "blocked",
               "duplicate", "rejected")

# Angle outcomes, as a reader wants them. The store speaks the v2 vocabulary and
# rewrites the v1 words when it migrates, but both are mapped here so a summary
# can never raise on a word it has not met.
ANGLE_LABELS = {
    "confirmed": "confirmed finding",
    "ruled_out": "ruled out",
    "open_gap": "open gap, not tested",
    "blocked": "blocked before it was tested",
    "not_applicable": "not applicable",
    "negative": "ruled out",
    "partial": "open gap, not tested",
    "finding": "confirmed finding",
}

# "Tried and produced no reportable finding" -- everything but a confirmation.
QUIET_OUTCOMES = ("ruled_out", "open_gap", "blocked", "not_applicable", "negative", "partial")

# Of those, the ones that settled nothing: an untested surface in disguise.
UNSETTLED_OUTCOMES = ("open_gap", "blocked", "partial")

# Inlined rather than taken from stdlib `http`: this package ships its own
# bbh/http.py, and a report should not depend on which one a given sys.path wins.
STATUS_PHRASES = {
    200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
    307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable",
    409: "Conflict", 410: "Gone", 413: "Content Too Large", 415: "Unsupported Media Type",
    422: "Unprocessable Content", 429: "Too Many Requests",
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_BACKTICKS = re.compile(r"`+")


class ReportError(RuntimeError):
    """Rendering refused. The message says why and how to fix it."""


def _refuse_leaked_secret(text: str, *, where: str, engagement: str) -> None:
    """Raise unless `text` is free of every recorded credential value.

    The last gate before an artifact leaves the machine. It runs on the finished
    document rather than on each field, because a credential can arrive through
    a replayed header or a body preview as easily as through the agent's prose.
    """
    try:
        problem = secrets.leak_problem(text, where=where, engagement=engagement)
    except secrets.SecretError as exc:
        raise ReportError(
            f"cannot check {where} against the engagement's recorded secrets, so it is not "
            f"written: {exc}"
        ) from exc
    if problem:
        raise ReportError(problem)


# ---- small formatting helpers ----


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cell(value: Any) -> str:
    """One markdown table cell: single line, pipes escaped, em dash for empty."""
    if value is None or value == "":
        return "—"
    return " ".join(str(value).split()).replace("|", "\\|")


def _table(header: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    out = [
        "| " + " | ".join(header) + " |",
        "|" + "|".join("---" for _ in header) + "|",
    ]
    out.extend("| " + " | ".join(_cell(c) for c in row) + " |" for row in rows)
    return out


def _fence(body: str, lang: str = "") -> list[str]:
    """Fence a block with enough backticks to survive backticks in the content."""
    longest = max((len(m) for m in _BACKTICKS.findall(body)), default=0)
    ticks = "`" * max(3, longest + 1)
    return [ticks + lang, body, ticks]


def _blockquote(text: str) -> list[str]:
    return [("> " + line).rstrip() for line in text.strip().splitlines()]


def _short(digest: str | None, size: int = 12) -> str:
    return digest[:size] if digest else "—"


def _count(value: Any) -> str:
    """Thousands-separated when it is a number, verbatim when the store held text."""
    if value is None:
        return "—"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:,}"
    return str(value)


def _relpath(raw: str | None, root: Path) -> str | None:
    """Engagement-relative path when possible: the report travels with the tree."""
    if not raw:
        return None
    p = Path(raw)
    try:
        return str(p.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return str(p)


def _safe_name(uid: str) -> str:
    name = _SAFE_NAME.sub("-", (uid or "").strip()).strip("-.")
    if not name:
        raise ReportError(
            f"finding uid {uid!r} has no characters usable in a filename, so the report "
            "has nowhere to go. Give findings a plain uid such as 'BBH-0003'."
        )
    return name


# ---- redaction ----


def _redact(name: str, value: str, extra: frozenset[str]) -> str:
    """Replace a credential with the same placeholder shape the client stores."""
    low = name.strip().lower()
    if low not in SENSITIVE_HEADERS and low not in extra:
        return value
    if any(marker in value for marker in REDACTION_MARKERS):
        return value  # already redacted when it was captured
    return f"<redacted sha256:{sha256_bytes(value.encode('utf-8', 'replace'))[:8]}>"


def _extra_sensitive(scope: Scope) -> frozenset[str]:
    raw = scope.rules.get("redact_headers") or []
    if isinstance(raw, str):
        raw = [raw]
    return frozenset(str(h).strip().lower() for h in raw if str(h).strip())


def _display_url(url: str) -> str:
    """Strip userinfo: a URL is also a place a password can hide."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.netloc or "@" not in parts.netloc:
        return url
    clean = parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1])
    return clean.geturl()


# ---- pulling requests back out of the store ----


def _fetch_requests(store: Store, ids: Iterable[int]) -> dict[int, sqlite3.Row]:
    """Request rows by id.

    Store exposes no by-id getter -- it is written for the capture side -- so
    this reads the table directly, read-only and parameterized. An id that no
    longer resolves is dropped here and named in the report, because a dangling
    citation is information, not a crash.
    """
    out: dict[int, sqlite3.Row] = {}
    for raw in ids:
        try:
            rid = int(raw)
        except (TypeError, ValueError):
            continue
        try:
            row = store.conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
        except sqlite3.Error:
            continue
        if row is not None:
            out[rid] = row
    return out


def _parse_headers(raw: Any) -> list[tuple[str, str]]:
    """Headers as stored: a JSON object, JSON pairs, or a raw header block."""
    if not raw:
        return []
    data: Any = raw
    if isinstance(data, (str, bytes)):
        try:
            data = json.loads(data)
        except (TypeError, ValueError):
            out: list[tuple[str, str]] = []
            for line in str(raw).splitlines():
                if ":" in line:
                    name, _, value = line.partition(":")
                    out.append((name.strip(), value.strip()))
            return out
    if isinstance(data, dict):
        return [(str(k), str(v)) for k, v in data.items()]
    if isinstance(data, list):
        pairs: list[tuple[str, str]] = []
        for item in data:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                pairs.append((str(item[0]), str(item[1])))
            elif isinstance(item, str) and ":" in item:
                name, _, value = item.partition(":")
                pairs.append((name.strip(), value.strip()))
        return pairs
    return []


def _notable_headers(raw: Any, extra: frozenset[str]) -> list[tuple[str, str]]:
    """Headers worth replaying, credentials shown as their placeholder."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for name, value in _parse_headers(raw):
        low = name.strip().lower()
        if not low or low == "host":  # Host is emitted from the URL itself
            continue
        secret = low in SENSITIVE_HEADERS or low in extra
        if low in NOISE_HEADERS and not secret:
            continue
        shown = (name.strip(), _redact(name, value, extra))
        if shown in seen:
            continue
        seen.add(shown)
        out.append(shown)
    out.sort(key=lambda kv: (0 if kv[0].lower() in SENSITIVE_HEADERS else 1, kv[0].lower()))
    return out


def _inline_body(note: Any, keys: Sequence[str]) -> str | None:
    """A small body the client stashed in the request note, if it is there."""
    if not note:
        return None
    try:
        data = json.loads(note)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, indent=2, sort_keys=True)
    return None


def _body_preview(
    path: str | None, digest: str | None, inline: str | None, root: Path
) -> tuple[str | None, str | None]:
    """Return (preview, note). The note explains whatever the preview omits."""
    if path:
        p = Path(path)
        shown = _relpath(path, root)
        if not p.is_file():
            return None, f"body file `{shown}` is missing (sha256 `{_short(digest)}`)"
        try:
            raw = p.read_bytes()
        except OSError as exc:
            return None, f"body file `{shown}` is unreadable: {exc.strerror or exc}"
        if b"\x00" in raw[:4096]:
            return None, (
                f"binary body, {len(raw):,} bytes, saved at `{shown}` "
                f"(sha256 `{_short(digest)}`)"
            )
        text = raw.decode("utf-8", "replace")
        if len(text) > MAX_BODY_CHARS:
            return text[:MAX_BODY_CHARS], (
                f"body truncated here; the full {len(raw):,} bytes are at `{shown}` "
                f"(sha256 `{_short(digest)}`)"
            )
        return text, f"body saved at `{shown}` (sha256 `{_short(digest)}`)"
    if inline:
        if len(inline) > MAX_BODY_CHARS:
            return inline[:MAX_BODY_CHARS], f"body truncated at {MAX_BODY_CHARS} characters"
        return inline, None
    return None, None


def _origin_form(url: str) -> tuple[str, str]:
    """(Host header value, origin-form request target) for a stored URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", url or "/"
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    host = (parts.netloc or "").rsplit("@", 1)[-1]
    return host, target


@dataclass(frozen=True)
class CitedRequest:
    """One recorded request, rendered for a triager to replay by hand."""

    request_id: int
    evidence_id: int | None = None
    caption: str | None = None
    ts: str | None = None
    actor: str | None = None
    phase: str | None = None
    method: str = ""
    url: str = ""
    host: str | None = None
    host_header: str = ""
    target: str = "/"
    status: int | None = None
    resp_len: int | None = None
    duration_ms: int | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str | None = None
    body_note: str | None = None
    resp_body_path: str | None = None
    resp_body_sha256: str | None = None
    missing: bool = False

    def observed(self) -> str:
        if self.status is None:
            bits = ["no response was recorded"]
        else:
            try:
                code = int(self.status)
            except (TypeError, ValueError):
                bits = [f"HTTP {self.status}"]
            else:
                bits = [f"HTTP {code} {STATUS_PHRASES.get(code, '')}".strip()]
        if self.resp_len is not None:
            bits.append(f"{_count(self.resp_len)} bytes")
        if self.duration_ms is not None:
            bits.append(f"{_count(self.duration_ms)} ms")
        return "`→ " + " · ".join(bits) + "`"

    def block(self, index: int) -> list[str]:
        label = f"**Step {index}**"
        if self.caption:
            label = f"**Step {index} — {self.caption}**"
        if self.missing:
            return [
                label,
                "",
                f"Request #{self.request_id} is cited as evidence but is no longer in the "
                "request log, so this step cannot be reproduced from the store. Re-run the "
                "proof and attach the new request id.",
            ]

        meta = [f"`{self.method} {self.url}`", f"request #{self.request_id}"]
        if self.ts:
            meta.append(self.ts)
        if self.actor:
            meta.append(f"actor `{self.actor}`")
        if self.phase:
            meta.append(f"phase `{self.phase}`")

        raw = [f"{self.method} {self.target} HTTP/1.1"]
        if self.host_header:
            raw.append(f"Host: {self.host_header}")
        raw.extend(f"{name}: {value}" for name, value in self.headers)
        if self.body is not None:
            raw.extend(["", self.body])

        lines = [label, "", " · ".join(meta), ""]
        lines.extend(_fence("\n".join(raw), "http"))
        lines.extend(["", self.observed()])
        if self.body_note:
            lines.append(f"Request {self.body_note}")
        if self.resp_body_path:
            lines.append(
                f"Response body saved at `{self.resp_body_path}` "
                f"(sha256 `{_short(self.resp_body_sha256)}`)"
            )
        return lines


def _cited_requests(
    store: Store, finding: sqlite3.Row, extra: frozenset[str], root: Path
) -> list[CitedRequest]:
    """The requests this finding cites, in the order they were attached."""
    cites = [ev for ev in store.evidence_for(finding["id"]) if ev["request_id"] is not None]
    rows = _fetch_requests(store, [ev["request_id"] for ev in cites])

    out: list[CitedRequest] = []
    for ev in cites:
        rid = int(ev["request_id"])
        row = rows.get(rid)
        if row is None:
            out.append(
                CitedRequest(request_id=rid, evidence_id=ev["id"], caption=ev["caption"], missing=True)
            )
            continue
        url = _display_url(row["url"] or "")
        host_header, target = _origin_form(url)
        body, body_note = _body_preview(
            row["req_body_path"],
            row["req_body_sha256"],
            _inline_body(row["note"], REQ_BODY_KEYS),
            root,
        )
        out.append(
            CitedRequest(
                request_id=rid,
                evidence_id=ev["id"],
                caption=ev["caption"],
                ts=row["ts"],
                actor=row["actor"],
                phase=row["phase"],
                method=(row["method"] or "GET").upper(),
                url=url,
                host=row["host"],
                host_header=host_header or (row["host"] or ""),
                target=target,
                status=row["status"],
                resp_len=row["resp_len"],
                duration_ms=row["duration_ms"],
                headers=_notable_headers(row["req_headers"], extra),
                body=body,
                body_note=body_note,
                resp_body_path=_relpath(row["resp_body_path"], root),
                resp_body_sha256=row["resp_body_sha256"],
            )
        )
    return out


# ---- scope resolution ----


def _asset_target(finding: sqlite3.Row, cited: Sequence[CitedRequest]) -> str:
    """The best URL or host to put to the scope rules.

    A full URL is preferred because url_prefix rules can only match one, and
    the cited requests carry the real scheme and port -- guessing those would
    make the scope statement a guess too.
    """
    endpoint = (finding["endpoint"] or "").strip()
    if "://" in endpoint:
        return endpoint
    for cite in cited:
        if cite.url:
            return cite.url
    host = (finding["host"] or "").strip()
    if host:
        return host
    raise ReportError(
        f"finding {finding['uid']} names no host, endpoint or cited request, so the harness "
        "cannot say which asset the report is about. Set one with:\n"
        f"  bb finding set {finding['uid']} --host <host> --endpoint <path>"
    )


def _decide_asset(scope: Scope, target: str) -> tuple[Decision, str | None]:
    """Decide the asset, returning (decision, attestation problem if any).

    Reports are written after testing stops, and an expired attestation must
    not erase which rule covered the asset. When that is the only objection,
    the same rules are re-run with the window set aside and the expiry is
    reported instead of hidden.
    """
    decision = scope.decide(target)
    attestation = scope.authorization_error()
    if decision.allowed or attestation is None:
        return decision, None
    relaxed = Scope(
        {
            "schema": SCHEMA_VERSION,
            "engagement": scope.engagement,
            "rules": scope.rules,
            "in_scope": scope.in_scope,
            "out_of_scope": scope.out_of_scope,
            "authorization": {
                "attested_by": "(attestation window closed)",
                "expires_at": "9999-12-31T23:59:59Z",
            },
        }
    )
    return relaxed.decide(target), attestation


# ---- report sections ----


def _severity_section(finding: sqlite3.Row) -> list[str]:
    severity = (finding["severity"] or "").strip().lower()
    out = ["## Severity", ""]
    if not severity:
        out.append(
            "**Not set.** A report without a severity will be triaged as informational. "
            f"Set it with: `bb finding set {finding['uid']} --severity <low|medium|high|critical>`"
        )
    elif severity == "info":
        out.append("**Informational** — this is below the bar most programs pay on.")
    else:
        out.append(f"**{severity.capitalize()}**")
    if finding["cvss_vector"]:
        out += ["", f"CVSS vector as recorded: `{finding['cvss_vector']}`"]
    return out


def _asset_section(finding: sqlite3.Row, cited: Sequence[CitedRequest], target: str) -> list[str]:
    out = ["## Affected asset", ""]
    rows: list[tuple[str, Any]] = [
        ("Host", f"`{finding['host']}`" if finding["host"] else None),
        ("Endpoint", f"`{finding['endpoint']}`" if finding["endpoint"] else None),
        ("Vulnerability class", f"`{finding['vuln_class']}`"),
    ]
    if cited:
        first = cited[0]
        if not first.missing:
            rows.append(("Observed at", f"`{first.url}` (request #{first.request_id})"))
    rows.append(("Scope target evaluated", f"`{target}`"))
    out.extend(_table(("field", "value"), rows))
    return out


def _prose_section(title: str, text: str | None, uid: str, field_name: str) -> list[str]:
    out = [f"## {title}", ""]
    body = (text or "").strip()
    if body:
        out.append(body)
    else:
        out.append(
            f"_Not recorded._ Add it with: `bb finding set {uid} --{field_name} \"...\"`"
        )
    return out


def _narrative_block(finding: sqlite3.Row, *, standalone: bool) -> list[str]:
    """The agent's own repro text, kept subordinate to the generated steps.

    It is context, not the reproduction: the numbered steps are built from the
    request log, so a narrative that names an endpoint the harness never
    requested shows up as a disagreement instead of becoming the report.
    """
    repro = (finding["repro"] or "").strip()
    if not repro:
        return []
    lead = (
        "This is the only account of the work, and nothing in the request log backs it:"
        if standalone
        else "Context from the write-up. The steps above are the reproduction; nothing here "
        "is load-bearing and a triager should not need it."
    )
    return ["### Narrative recorded during the hunt", "", lead, "", *_blockquote(repro)]


def _steps_section(finding: sqlite3.Row, cited: Sequence[CitedRequest]) -> list[str]:
    out = ["## Steps to reproduce", ""]
    if not cited:
        out += [
            "> **No request evidence is attached to this finding**, so the harness has no "
            "requests to generate steps from and a triager has nothing to replay. Attach the "
            "proving request with:",
            f"> `bb evidence add {finding['uid']} request --request-id <id>`",
            "",
        ]
        return out + _narrative_block(finding, standalone=True)

    out += [
        f"The {len(cited)} numbered step(s) below are generated from the engagement request "
        "log, not from the write-up: each block is the request exactly as it was sent, with "
        "credentials shown as the placeholder that was stored in their place. Substitute your "
        "own session values to replay.",
        "",
    ]
    for index, cite in enumerate(cited, 1):
        out += cite.block(index) + [""]
    return out + _narrative_block(finding, standalone=False)


def _evidence_section(store: Store, finding: sqlite3.Row, root: Path) -> list[str]:
    out = ["## Evidence", ""]
    rows = store.evidence_for(finding["id"])
    if not rows:
        out.append(
            "> **No evidence artifacts are attached.** Attach at least one with: "
            f"`bb evidence add {finding['uid']} <kind> <path>`"
        )
        return out

    table: list[tuple[Any, ...]] = []
    for ev in rows:
        artifact = _relpath(ev["path"], root)
        if artifact:
            artifact = f"`{artifact}`"
        elif ev["request_id"] is not None:
            artifact = f"request #{ev['request_id']}"
        table.append(
            (
                ev["id"],
                ev["kind"],
                artifact,
                f"`{_short(ev['sha256'], 16)}`" if ev["sha256"] else None,
                _count(ev["bytes"]),
                ev["caption"],
            )
        )
    out.extend(_table(("#", "kind", "artifact", "sha256 (short)", "bytes", "caption"), table))
    out += [
        "",
        "Every artifact above was re-hashed when this report was written and matched the "
        "hash recorded at capture time. Full hashes are in the provenance section.",
    ]
    return out


def _scope_section(
    scope: Scope,
    target: str,
    decision: Decision,
    attestation: str | None,
    cited: Sequence[CitedRequest],
) -> list[str]:
    lock = getattr(scope, "lock", {}) or {}
    out = ["## Scope statement", ""]

    rule = decision.rule or {}
    note = f" ({rule['note']})" if rule.get("note") else ""
    out.append(
        f"`{decision.target}` is in scope for engagement `{scope.engagement}`: it matches the "
        f"in-scope rule `{rule.get('type', 'unknown')} {rule.get('value', '?')}`{note}."
    )
    if lock.get("program_url"):
        out.append(f"Program: {lock['program_url']}")
    if lock.get("compiled_at"):
        out.append(
            f"Scope compiled at {lock['compiled_at']} from `scope.yaml` "
            f"(sha256 `{_short(lock.get('source_sha256'))}`)."
        )
    out.append(
        f"The scope carries {len(scope.in_scope)} in-scope rule(s) and "
        f"{len(scope.out_of_scope)} exclusion(s); none of the exclusions match this asset."
    )
    if attestation:
        out += [
            "",
            f"> Authorization note: {attestation} The asset is still covered by the rule "
            "above; the attestation window simply closed before the report was written. "
            "Re-arm before testing again.",
        ]

    hosts: dict[str, Decision] = {}
    for cite in cited:
        if cite.host and cite.host not in hosts:
            hosts[cite.host] = scope.decide(cite.host)
    if hosts:
        out += ["", "Hosts touched by the cited requests:", ""]
        out.extend(
            _table(
                ("host", "verdict", "reason"),
                [
                    (host, "in scope" if d.allowed else "OUT OF SCOPE", d.reason)
                    for host, d in sorted(hosts.items())
                ],
            )
        )
        if any(not d.allowed for d in hosts.values()):
            out += [
                "",
                "An out-of-scope host in the trace is expected for findings about redirects "
                "or third-party sinks, where the destination is the point. If that is not "
                "this finding, the citation is wrong and should be corrected before "
                "submission.",
            ]
    return out


def _dedup_key(store: Store, finding: sqlite3.Row) -> str | None:
    """The key the harness computes, not the one the model wrote.

    `findings.dedup_key` is a column a model fills in, so printing it put an
    assertion in the provenance table under a heading that reads as a
    measurement. `triage.dedup_parts` recomputes all four components from the
    class, the route the cited traffic hit, the parameters it carried and the
    account positions it was sent from. A key that will not compute is said so
    rather than filled in from the column.
    """
    from . import triage

    try:
        parts = triage.dedup_parts(store, finding)
    except RuntimeError as exc:  # TriageError: nothing cited, or no route to shape
        return f"not computable: {exc}".splitlines()[0]
    stored = str(finding["dedup_key"] or "").strip()
    line = f"`{parts.short}`  ({parts.canonical})"
    if stored and stored.casefold() != parts.digest:
        line += f"; the stored `dedup_key` is `{stored}` and disagrees"
    return line


def _provenance_section(
    store: Store,
    scope: Scope,
    finding: sqlite3.Row,
    cited: Sequence[CitedRequest],
    root: Path,
) -> list[str]:
    out = ["## Harness provenance", ""]
    cited_ids = ", ".join(f"#{c.request_id}" for c in cited) or "none"
    host_total = store.request_count(finding["host"]) if finding["host"] else None

    facts: list[tuple[str, Any]] = [
        ("Engagement", f"`{scope.engagement}`"),
        ("Finding uid", f"`{finding['uid']}`"),
        ("State", f"`{finding['state']}`"),
        ("Phase found", f"`{finding['phase_found']}`" if finding["phase_found"] else None),
        ("Created / updated", f"{finding['ts_created']} / {finding['ts_updated']}"),
        ("Requests cited", cited_ids),
        (
            "Requests recorded",
            f"{store.request_count():,} for the engagement"
            + (f", {host_total:,} against `{finding['host']}`" if host_total is not None else ""),
        ),
        ("Dedup key", _dedup_key(store, finding)),
        ("Report generated", _utcnow()),
    ]
    out.extend(_table(("field", "value"), facts))

    out += ["", "### Gate results", ""]
    gates = store.gates_for(finding["id"])
    if not gates:
        out.append(
            f"> **No gate results are recorded** although this finding is in state "
            f"`{finding['state']}`. It reached that state without the mechanical checks. "
            f"Run them with: `bb gate {finding['uid']}`"
        )
    else:
        # A waived gate was not checked by anything, so it must not read as a
        # pass in the one table a human triager actually looks at. The verdict
        # word comes from `waiver.gate_verdict`, which is pure and local to the
        # row: the ledger keeps saying the requirement was stood down even after
        # the waiver that stood it down has expired.
        out.extend(
            _table(
                ("gate", "verdict", "when", "rationale"),
                [
                    (
                        g["gate"],
                        {"pass": "pass", waiver.WAIVED: f"**{waiver.WAIVED}**"}.get(
                            waiver.gate_verdict(g), "**FAIL**"
                        ),
                        g["ts"],
                        g["rationale"],
                    )
                    for g in gates
                ],
            )
        )
        latest = {g["gate"]: g for g in gates}  # rows arrive oldest first
        failing = sorted(
            name for name, g in latest.items() if waiver.gate_verdict(g) == "fail"
        )
        if failing:
            out += [
                "",
                f"> **The most recent verdict is a failure for: {', '.join(failing)}.** "
                f"This finding should not be submitted while that stands. Re-run the gates "
                f"with: `bb gate {finding['uid']}`",
            ]

    out += ["", "### Evidence manifest (sha256)", ""]
    manifest = [
        f"{ev['sha256']}  {_relpath(ev['path'], root)}"
        for ev in store.evidence_for(finding["id"])
        if ev["sha256"] and ev["path"]
    ]
    if manifest:
        out.extend(_fence("\n".join(manifest)))
        out += [
            "",
            f"Verify from the engagement root with `sha256sum -c`, or re-run the checks with "
            f"`bb gate {finding['uid']}`.",
        ]
    else:
        out.append("_No file-backed evidence is attached; the citations above are request rows._")
    return out


# ---- public API ----


def ungated_requirements(store: Store, finding: Any) -> list[str]:
    """Gates that guard this finding's rung and have no standing pass on record.

    `findings.state` is a field, and `bb finding advance <uid> gated` writes it
    by name: one command took a candidate with no evidence, no severity and no
    gate row at all to `gated`, and a report was rendered from it. So the state
    is read only to decide WHICH gates were owed, and the answer comes from the
    `gates` rows -- which nothing but `triage.apply_gates` and
    `triage.record_dedupe` can write a `pass` into, both of them computing the
    verdict from the store at the moment they write it.

    Latest row per gate wins, through `waiver.gate_verdict`, so a stood-down
    requirement counts as answered (loudly, in its own section) and a gate that
    later failed does not stay satisfied by an older pass.
    """
    required = triage.gates_for_state(str(finding["state"]))
    standing: dict[str, str] = {}
    for row in store.gates_for(finding["id"]):  # oldest first
        standing[str(row["gate"] or "")] = waiver.gate_verdict(row)
    return [
        gate for gate in required if standing.get(gate) not in ("pass", waiver.WAIVED)
    ]


def render(store: Store, scope: Scope, finding_ref: str | int) -> str:
    """Render one finding as a submittable markdown report.

    Raises ReportError -- never a half-made draft -- when the finding has not
    cleared the gates, when a gate that guards its rung never recorded a pass,
    when its evidence no longer matches what was captured, or when no in-scope
    rule covers the asset.
    """
    finding = store.get_finding(finding_ref)
    if finding is None:
        raise ReportError(
            f"no finding {finding_ref!r} in engagement {scope.engagement!r}. "
            "List what is there with: bb finding list"
        )

    uid = finding["uid"]
    state = finding["state"]
    if state not in REPORTABLE_STATES:
        if state == "rejected":
            reason = finding["reject_reason"] or "no reason recorded"
            raise ReportError(
                f"finding {uid} was rejected ({reason}); rejected findings are not reported. "
                "If the rejection was wrong, capture the missing proof and raise a fresh "
                "finding with: bb finding add"
            )
        if state == "duplicate":
            raise ReportError(
                f"finding {uid} is marked duplicate; report the finding it duplicates instead. "
                "Check which one with: bb finding list"
            )
        raise ReportError(
            f"finding {uid} is in state {state!r}; a report is only written from "
            f"{' or '.join(REPORTABLE_STATES)}. Run the mechanical gates first:\n"
            f"  bb gate {uid}\n"
            "A finding that passes every gate becomes 'gated', and 'ready' after the "
            "duplicate check."
        )

    unmet = ungated_requirements(store, finding)
    if unmet:
        detail = "\n".join(f"  - {gate} has no pass or waiver on record" for gate in unmet)
        raise ReportError(
            f"refusing to write a report for {uid}: it is in state {state!r} but "
            f"{len(unmet)} of the {len(triage.gates_for_state(state))} gates that guard that "
            f"state never recorded a verdict, so the state says checked and the record does "
            f"not. A report is the one artifact a human acts on.\n{detail}\n"
            f"Run them: bb gate {uid}"
        )

    problems = store.verify_evidence(finding["id"])
    if problems:
        detail = "\n".join(f"  - {p}" for p in problems)
        raise ReportError(
            f"refusing to write a report for {uid}: its evidence no longer matches what was "
            f"captured, so the report would claim proof that is not on disk.\n{detail}\n"
            f"Re-capture the artifacts, then re-gate with: bb gate {uid}"
        )

    root = paths.engagement_dir(scope.engagement)
    extra = _extra_sensitive(scope)
    cited = _cited_requests(store, finding, extra, root)

    target = _asset_target(finding, cited)
    decision, attestation = _decide_asset(scope, target)
    if not decision.allowed:
        raise ReportError(
            f"refusing to write a report for {uid}: {decision.reason}. A report names an "
            "asset the program authorized, and this one matches no in-scope rule. Either the "
            "finding points at the wrong asset:\n"
            f"  bb finding set {uid} --host <host>\n"
            "or the scope is missing a rule the program does cover: edit scope.yaml, then\n"
            f"  bb scope compile {scope.engagement}"
        )

    lines: list[str] = [
        f"# {finding['title']}",
        "",
        f"<!-- bbh report · engagement {scope.engagement} · finding {uid} · "
        f"generated {_utcnow()} · regenerate with: bb report {uid} -->",
        "",
    ]
    lines += _severity_section(finding) + [""]
    lines += _asset_section(finding, cited, target) + [""]
    lines += _prose_section("Summary", finding["summary"], uid, "summary") + [""]
    lines += _prose_section("Impact", finding["impact"], uid, "impact") + [""]
    lines += _steps_section(finding, cited) + [""]
    lines += _evidence_section(store, finding, root) + [""]
    lines += _prose_section("Remediation", finding["remediation"], uid, "remediation") + [""]
    lines += _scope_section(scope, target, decision, attestation, cited) + [""]
    # Its own `##` section rather than a block inside the provenance table: it
    # emits a heading of its own, and nesting it between the gate table and the
    # evidence manifest would put the manifest under it. Immediately above
    # provenance so a stood-down requirement sits with the other harness facts
    # and still above the longest section in the document.
    waived = waiver.report_lines(store, finding, engagement=scope.engagement)
    if waived:
        lines += waived + [""]
    lines += _provenance_section(store, scope, finding, cited, root) + [""]

    text = "\n".join(lines).rstrip() + "\n"
    _refuse_leaked_secret(
        text, where=f"the report for {uid}", engagement=scope.engagement
    )
    return text


def write_report(store: Store, scope: Scope, finding_ref: str | int) -> Path:
    """Render and save to engagements/<e>/reports/<uid>.md."""
    finding = store.get_finding(finding_ref)
    if finding is None:
        raise ReportError(
            f"no finding {finding_ref!r} in engagement {scope.engagement!r}. "
            "List what is there with: bb finding list"
        )
    # Render before touching the filesystem: a refusal must leave no file behind
    # that could be mistaken for a report.
    text = render(store, scope, int(finding["id"]))
    path = paths.engagement_dir(scope.engagement) / "reports" / f"{_safe_name(finding['uid'])}.md"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise ReportError(
            f"cannot write {path}: {exc.strerror or exc}. Check the engagement tree with: "
            f"bb status {scope.engagement}"
        ) from exc
    return path


# ---- hunt summary ----


def _finding_sort_key(row: sqlite3.Row) -> tuple[int, int, int]:
    state = row["state"]
    rank = STATE_ORDER.index(state) if state in STATE_ORDER else len(STATE_ORDER)
    severity = -SEVERITY_RANK.get((row["severity"] or "").lower(), -1)
    return (rank, severity, int(row["id"]))


def _host_traffic(store: Store, limit: int = MAX_SUMMARY_HOSTS) -> list[tuple[str, int]]:
    try:
        rows = store.conn.execute(
            "SELECT host, COUNT(*) AS n FROM requests GROUP BY host ORDER BY n DESC LIMIT ?",
            (limit,),
        ).fetchall()
    except sqlite3.Error:
        return []
    return [(r["host"], int(r["n"])) for r in rows]


def _coverage_section(store: Store) -> list[str]:
    """What was tried and did not pay off -- the half of a hunt nothing else records."""
    out = ["## Tested, nothing found", ""]
    quiet = [a for a in store.angles() if a["outcome"] in QUIET_OUTCOMES]
    if not quiet:
        out.append(
            "_The angle ledger holds no settled negatives, so this hunt has no recorded "
            "coverage: there is no way to tell an untested surface from a clean one. "
            "Record attempts with: `bb angle add <surface> <class> <technique> ruled_out "
            "--control '<the defence you observed>'`_"
        )
        return out

    by_surface: dict[str, list[sqlite3.Row]] = {}
    for angle in quiet:
        by_surface.setdefault(angle["surface"], []).append(angle)

    out.append(
        f"{len(quiet)} angle(s) across {len(by_surface)} surface(s) were run and produced no "
        "reportable finding. This is the coverage evidence for the hunt."
    )
    if any(a["outcome"] in UNSETTLED_OUTCOMES for a in quiet):
        out.append(
            "Entries marked as an open gap or blocked are not clean results: nothing was "
            "ruled out there, and they are the first place to pick the hunt back up."
        )
    out.append("")
    shown = 0
    for surface, angles in by_surface.items():
        if shown >= MAX_SUMMARY_ANGLES:
            break
        out.append(f"**`{surface}`**")
        for angle in angles:
            if shown >= MAX_SUMMARY_ANGLES:
                break
            outcome = angle["outcome"]
            detail = angle["note"]
            # `ruled_out` carries the control that rules it out and `open_gap`
            # the test it did not get to; both are the point of the row.
            for column in ("control", "next_test"):
                try:
                    extra = angle[column]
                except (IndexError, KeyError):
                    extra = None
                if extra:
                    detail = f"{detail}; {extra}" if detail else extra
            note = f" — {detail}" if detail else ""
            out.append(
                f"- {angle['vuln_class']} · {angle['technique']} — "
                f"{ANGLE_LABELS.get(outcome, outcome)}{note}"
            )
            shown += 1
        out.append("")
    remaining = len(quiet) - shown
    if remaining > 0:
        out.append(f"…and {remaining} more. Full ledger: `bb angle list`")
    return out


def _uid_of(item: Any) -> str:
    """The uid of a finding given as a row, a mapping or a bare reference."""
    if isinstance(item, (str, int)):
        return str(item)
    try:
        return str(item["uid"])
    except (TypeError, KeyError, IndexError):
        return str(item)


def _reportable_disagreement(store: Store, claimed: Iterable[Any] | None) -> str | None:
    """Why the summary's finding list cannot be trusted, or None.

    The summary is the one document a human reads instead of the store, so the
    set it calls shippable is checked against the store twice: once per
    reportable state, and once against the full list it is about to table. A
    caller that supplies its own list -- a phase handing over what it believes
    it produced -- is checked against the same answer. A disagreement is a bug
    or a concurrent write, and either way the honest output is none.
    """
    per_state = {r["uid"] for state in REPORTABLE_STATES for r in store.list_findings(state)}
    from_all = {r["uid"] for r in store.list_findings() if r["state"] in REPORTABLE_STATES}
    problems: list[str] = []
    if per_state != from_all:
        problems.append(
            f"the store disagrees with itself: listing by state gives "
            f"{sorted(per_state) or 'none'} and the full finding list gives "
            f"{sorted(from_all) or 'none'}. Something wrote to the store while this summary "
            f"was being built."
        )
    if claimed is not None:
        asked = {_uid_of(item) for item in claimed}
        extra = sorted(asked - per_state)
        missing = sorted(per_state - asked)
        if extra or missing:
            problems.append(
                f"the finding list handed to render_summary does not match the store: "
                f"listed but not in state {' or '.join(REPORTABLE_STATES)}: "
                f"{', '.join(extra) or 'none'}; reportable but not listed: "
                f"{', '.join(missing) or 'none'}"
            )
    if not problems:
        return None
    detail = "\n".join(f"  - {p}" for p in problems)
    return (
        "refusing to write the hunt summary: its finding list does not agree with the store, "
        "and a summary that overstates what cleared the gates is the one document a human "
        f"would act on without re-checking.\n{detail}\n"
        "The store decides what is reportable. Re-read it and regenerate:\n"
        "  bb finding list --state gated\n"
        "  bb finding list --state ready\n"
        "  bb report --summary"
    )


def render_summary(store: Store, scope: Scope, findings: Iterable[Any] | None = None) -> str:
    """One page covering the whole hunt: state, findings, traffic, cost, coverage.

    `findings` is an optional list of what the caller believes is reportable,
    as rows or uids. It is not rendered -- the table below is built from the
    store either way -- it is compared, and a mismatch raises.
    """
    problem = _reportable_disagreement(store, findings)
    if problem:
        raise ReportError(problem)

    lock = getattr(scope, "lock", {}) or {}
    stats = store.stats()
    rows = store.list_findings()

    lines = [f"# Hunt summary — {scope.engagement}", "", f"Generated {_utcnow()}"]
    if lock.get("program_url"):
        lines.append(f"Program: {lock['program_url']}")

    rules = ", ".join(f"`{r['value']}`" for r in scope.in_scope[:6])
    if len(scope.in_scope) > 6:
        rules += f", +{len(scope.in_scope) - 6} more"
    lines.append(
        f"Scope: {len(scope.in_scope)} in-scope rule(s) — {rules} · "
        f"{len(scope.out_of_scope)} exclusion(s)"
    )
    attestation = scope.authorization_error()
    auth = getattr(scope, "authorization", {}) or {}
    if attestation:
        lines.append(f"Authorization: {attestation}")
    else:
        lines.append(
            f"Authorization: attested by {auth.get('attested_by', 'unknown')} "
            f"until {auth.get('expires_at', 'unknown')}"
        )

    lines += ["", "## Where it stands", ""]
    by_state = stats["by_state"]
    ordered = [s for s in STATE_ORDER if by_state.get(s)]
    ordered += sorted(s for s in by_state if s not in STATE_ORDER)
    lines.extend(
        _table(
            ("state", "findings"),
            [(s, by_state.get(s, 0)) for s in ordered] + [("**total**", stats["findings"])],
        )
    )
    lines += [
        "",
        f"{stats['requests']:,} requests · {stats['evidence']} evidence artifact(s) · "
        f"{stats['angles']} angle(s) tested · ${stats['cost_usd']:.2f} spent",
    ]

    lines += ["", "## Findings", ""]
    if not rows:
        lines.append("_No findings were recorded._")
    else:
        lines.extend(
            _table(
                ("uid", "state", "severity", "class", "asset", "title"),
                [
                    (
                        f["uid"],
                        f["state"],
                        f["severity"] or "unset",
                        f["vuln_class"],
                        f["endpoint"] or f["host"],
                        f["title"],
                    )
                    for f in sorted(rows, key=_finding_sort_key)
                ],
            )
        )
        shippable = [f for f in rows if f["state"] in REPORTABLE_STATES]
        lines.append("")
        if shippable:
            lines.append(
                f"{len(shippable)} finding(s) reached a reportable state "
                f"({' or '.join(REPORTABLE_STATES)}); write them out with: `bb report --all`"
            )
        else:
            lines.append("No finding cleared the gates, so there is nothing to submit.")

    lines += ["", "## Traffic", ""]
    traffic = _host_traffic(store)
    if traffic:
        lines.extend(_table(("host", "requests"), traffic))
        counted = sum(n for _, n in traffic)
        if stats["requests"] > counted:
            lines.append("")
            lines.append(f"…and {stats['requests'] - counted:,} more against other hosts.")
    else:
        lines.append("_No requests were recorded._")

    lines += ["", "## Phases", ""]
    runs = store.phase_runs()
    if runs:
        lines.extend(
            _table(
                ("phase", "attempt", "status", "turns", "cost", "finished"),
                [
                    (
                        r["phase"],
                        r["attempt"],
                        r["status"],
                        r["turns"],
                        f"${r['cost_usd']:.2f}" if r["cost_usd"] is not None else None,
                        r["ts_end"],
                    )
                    for r in runs
                ],
            )
        )
        lines += ["", f"Total cost: **${store.total_cost():.2f}**"]
    else:
        lines.append("_No phase has run yet._")

    lines += [""] + _coverage_section(store)
    text = "\n".join(lines).rstrip() + "\n"
    _refuse_leaked_secret(text, where="the hunt summary", engagement=scope.engagement)
    return text


def write_summary(store: Store, scope: Scope) -> Path:
    """Save the hunt summary next to the reports it indexes."""
    text = render_summary(store, scope)
    path = paths.engagement_dir(scope.engagement) / "reports" / "SUMMARY.md"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise ReportError(
            f"cannot write {path}: {exc.strerror or exc}. Check the engagement tree with: "
            f"bb status {scope.engagement}"
        ) from exc
    return path
