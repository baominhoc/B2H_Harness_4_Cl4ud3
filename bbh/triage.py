"""Deterministic gates a finding must survive before any model judges it.

Phase 07 asks a model to act as a hostile triager, but a model can be argued
round. These checks cannot be: each one is a small function over the store, and
a finding that fails any of them is rejected before the hostile-triager prompt
ever runs. That ordering is the whole point -- rhetoric cannot stand in for an
artifact on disk, a recorded request, or a registered object with an owner.

`gate_access_control_ownership` is the one that earns its keep. "I changed
id=1 to id=2 and got a 200" is the most common false positive in bug bounty,
and it is indistinguishable from a real IDOR unless someone wrote down, in
advance, which account owns the object behind id=2. So the gate refuses to take
the agent's word for it: an access-control finding must cite a recorded request
made as one registered account that reached an object the objects table says
belongs to a different one.

v2 adds the rule the rest of it rests on: a gate never reads a model-written
field where an artifact can be recomputed. Severity is derived from the CVSS
vector through `bbh.cvss` instead of read off the severity column, evidence is
re-hashed, every cited `request_id` is resolved against the requests table, and
the hosts and URLs in the repro are reconciled against traffic that actually
left the harness. No gate reads `findings.state`: state is what gates produce,
never what they consult, because a finding that can gate itself by sitting in
the right state is not gated at all.

Dedupe is the sharpest case of that rule. `findings.dedup_key` is a column a
model writes, so a model that wants two findings to survive writes two different
keys and a careless one writes a single key for two real bugs: either way the
stored value asserts nothing. `dedup_key()` recomputes it here from the class,
the route the cited traffic actually hit, the parameters that traffic carried
and the account positions it was sent from, and `gate_not_duplicate` ignores the
stored value except to report that it disagrees. Only genuinely ambiguous pairs
-- the same computed key, or a key that differs in exactly one component and
differs in it narrowly -- are referred to a judge, whose verdict is tri-state,
because a judge asked to rule on every pair of findings is a judge nobody reads.

There are several sets, because the gates guard different transitions.
`DEFAULT_GATES` is the seven the contract publishes -- the entry checks, and
still what `gates=None` runs. `VERIFY_GATES` guards `verified`: is the attack
reachable by an attacker at all, and was it reproduced from a position that did
not already know the answer. `SHIP_GATES` is everything, and is what has to hold
before a human reads a word of a report. `SHIP_GATES` contains `VERIFY_GATES`
deliberately: `apply_gates` can move a candidate straight to `gated`, so a check
that only ran at `verified` would be bypassable by skipping a rung.

That bypass is not only a question about gates. `store.advance` carries bars of
its own, keyed on the rung being entered -- `validated` refuses a claim nobody
argued against -- and a single jump to `gated` asked for none of them. Two
things close that, because they fail differently. `VALIDATED_BAR_GATES` carries
the `validated` bar upward as a gate, recomputed from the store on every run
through `store.counterevidence_problem`, so a field cleared after the rung was
climbed is caught and the refusal is a recorded verdict with a remedy rather
than an exception. `apply_gates` also walks the ladder one rung at a time, so
whatever `store.advance` asks at each rung is asked, including any bar added to
it after this module was written.

One gate writes, by design. `gate_access_control_ownership` records the
prerequisite row its own proof implies, because proving the authorization check
is missing says nothing about whether an attacker could ever obtain the
identifier, and the prerequisite ledger is where that second question lives.

Rationales are written for an agent mid-hunt: what failed, and the command that
fixes it. Nothing here calls a model, and nothing here reaches the network.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, unquote, urlsplit

from . import cvss, waiver
from .scope import Scope, host_from_url, normalize_host
from .store import (
    LADDER,
    SEVERITIES,
    TERMINAL_STATES,
    Store,
    counterevidence_problem,
)

# Verbatim rationale for the access-control gate's central failure. Named so
# the report and the tests can refer to the same string.
NO_OBJECT_RATIONALE = (
    "no registered object: changing an identifier you own is not broken access control. "
    "Register the victim's object with `bb object add` and cite the request that proves "
    "the attacker account reached it."
)

NO_REQUEST_RATIONALE = (
    "no request evidence is cited, so nothing shows one account reaching another account's "
    "object. Send the proof request as the attacker (`bb req <METHOD> <URL> --actor "
    "<attacker>`) and cite the id it prints: `bb evidence add {uid} request "
    "--request-id <id>`"
)

# The headline for the repro reconciliation gate. A repro naming traffic the
# harness never sent is not a sloppy write-up: it is the one mechanical signal
# that the steps were composed rather than observed, so it is worded to be
# unmistakable in a log an operator skims.
FABRICATION_FLAG = (
    "FABRICATION FLAG: these reproduction steps name traffic this harness never sent, "
    "so they were written from memory or invented rather than read off the request log"
)

# vuln_class values that demand ownership proof. Matched against the class with
# separators normalized, so "Broken Access Control" and "broken_access_control"
# both land here. Matching is on whole tokens in sequence, so "bac" does not
# match "callback-ssrf" and "auth" does not match "author".
ACCESS_CONTROL_CLASSES = (
    "idor",
    "bac",
    "broken-access-control",
    "access-control",
    "auth-bypass",
    "privilege-escalation",
)

# Classes whose proof is a comparison rather than a single response: the control
# working, then the control bypassed. One response proves nothing about either.
AUTH_CLASSES = (
    "auth", "authn", "authz", "authentication", "authorization", "login", "logout",
    "session", "session-fixation", "sso", "oauth", "saml", "jwt", "mfa", "2fa",
    "password-reset", "account-takeover", "ato", "csrf",
)
DIFFERENTIAL_CLASSES = (
    "differential", "blind", "timing", "oracle", "race", "race-condition",
    "cache-poisoning", "cache-deception",
)
BUSINESS_LOGIC_CLASSES = (
    "business-logic", "logic", "workflow", "price", "pricing", "payment",
    "coupon", "discount", "quota",
)

EVIDENCE_ROLE_CLASSES = (
    ACCESS_CONTROL_CLASSES + AUTH_CLASSES + DIFFERENTIAL_CLASSES + BUSINESS_LOGIC_CLASSES
)

# Severities a human may still assert in free text. Nothing at or below `low` is
# worth the argument; above it, the rating has to come out of the metrics.
FREE_TEXT_SEVERITIES = ("info", "low")

# Methods whose success changes the target's state, so the claim owes a third
# artifact: the effect, observed from the side of whoever owns the data.
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Standing a gate down lives in `bbh.waiver` and nowhere else. It used to be a
# recorded gate row whose detail carried the literal `not-applicable: <reason>`,
# which `store.record_gate` can write -- and the sanctioned-import guard lets an
# agent call the store directly, so the gate being refused could grant its own
# waiver. A waiver is now a signed file under `.state/`, outside the directory a
# phase can write, and it is read by `_waived_or` below.

# ---- dedupe vocabulary -----------------------------------------------------

# The four components of a dedup key, in the order they are hashed.
DEDUP_KEY_FIELDS: tuple[str, ...] = ("vuln_class", "path_shape", "param", "auth_state")

# What a judge may answer about an ambiguous pair. `undetermined` exists so a
# judge that cannot decide has somewhere to go that is not `distinct`: only
# `distinct` lets both findings ship, so resolving a failure to it is how two
# reports of one bug both get submitted and the researcher looks careless.
DEDUPE_VERDICTS: tuple[str, ...] = ("duplicate", "distinct", "undetermined")
CLEARING_VERDICT = "distinct"
DEDUPE_SOURCES: tuple[str, ...] = ("judge", "operator")

# Adjudications are stored as gate rows, because `gates` is the only ledger the
# store exposes that a report already prints. Three names, not one, so a human
# reading the provenance table can tell a judge's verdict from a human override
# from a merge that already happened.
DEDUPE_VERDICT_GATE = "dedupe_verdict"
DEDUPE_OVERRIDE_GATE = "dedupe_override"
DEDUPE_MERGE_GATE = "dedupe_merge"
DEDUPE_GATES: tuple[str, ...] = (
    DEDUPE_VERDICT_GATE,
    DEDUPE_OVERRIDE_GATE,
    DEDUPE_MERGE_GATE,
)

# A reason short enough to be a shrug cannot be argued with, and these reasons
# are the only thing standing between an ambiguous pair and two submissions.
# Its own literal rather than an alias of the waiver bar it used to share: a
# waiver reason is read by a triager in a submitted report and answers to
# `bbh.waiver.MIN_REASON_CHARS`, while this one is read by the next phase.
DEDUPE_MIN_REASON_CHARS = 20
_STUB_REASON_RE = re.compile(
    r"^(?:dup(?:licate)?s?|same|distinct|different|not\s*a?\s*dup\w*|n/?a|none|no|yes)[.!]*$",
    re.I,
)

# A path segment collapses to this when it looks like an identifier rather than
# a route. Deliberately narrow -- all digits, a uuid, a long hex string or a
# ULID -- so `/api/v2/docs` keeps its `v2` instead of becoming `/api/{id}/docs`.
ID_PLACEHOLDER = "{id}"
_DIGIT_SEG_RE = re.compile(r"^\d+$")
_UUID_SEG_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_HEX_SEG_RE = re.compile(r"^[0-9a-f]{12,}$", re.I)
_ULID_SEG_RE = re.compile(r"^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{26}$")  # canonical ULID is upper case

# `anon` is a claim about the attack -- the surface answered with no credential
# at all -- and the unrecorded spellings are the absence of a claim. They are
# kept apart on purpose: an unrecorded actor must not be able to pass itself off
# as the stronger finding.
ANON_ACTORS = frozenset({"anon", "anonymous"})
_UNRECORDED_ACTORS = frozenset({"", "null", "none", "nil", "undefined"})

_STEP_RE = re.compile(r"^[ \t]*(?:step[ \t]*)?(\d{1,3})[ \t]*[.):\]-][ \t]*\S", re.I | re.M)
_URL_RE = re.compile(r"https?://[^\s<>\"'`\])]+", re.I)
_ASCII_ALNUM = re.compile(r"[A-Za-z0-9]")

# A dotted name written in prose, for the repro reconciliation gate. Deliberately
# conservative: it has to end in letters, so "/v1/2.3" and "id=2" do not look
# like hosts, and a filename-shaped tail is dropped below.
_BARE_HOST_RE = re.compile(
    r"(?<![/@\w.-])(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])", re.I
)
_NOT_HOST_TAILS = frozenset(
    "php html htm js mjs jsx ts json xml txt md png jpg jpeg gif svg webp css scss "
    "py sh rb go rs java yaml yml toml csv tsv log zip gz tar pdf bak old aspx asp "
    "jsp do cgi exe dll so ini conf cfg env lock sql har pcap".split()
)


class TriageError(RuntimeError):
    """The gates could not be run at all. Not a verdict on a finding."""


@dataclass(frozen=True)
class GateResult:
    name: str
    verdict: str  # pass | fail
    rationale: str
    detail: dict[str, Any] | None = None
    # Where a failure sends the finding. None means the bin; "blocked" means the
    # siding. A blocked gate has still not passed -- the distinction is only
    # whether the verdict is permanent, and `rejected` is permanent, so a gate
    # that could not finish its work must never claim one.
    disposition: str | None = None
    unblock: str | None = None  # what would clear a blocked disposition

    @property
    def passed(self) -> bool:
        return self.verdict == "pass"

    @property
    def blocked(self) -> bool:
        return self.disposition == "blocked"

    def __bool__(self) -> bool:
        return self.passed


def _pass(name: str, rationale: str, detail: dict[str, Any] | None = None) -> GateResult:
    return GateResult(name, "pass", rationale, detail)


def _fail(name: str, rationale: str, detail: dict[str, Any] | None = None) -> GateResult:
    return GateResult(name, "fail", rationale, detail)


def _blocked(
    name: str, rationale: str, unblock: str, detail: dict[str, Any] | None = None
) -> GateResult:
    """A failure that parks the finding instead of killing it.

    Used where the record is incomplete for a reason that names a missing
    resource, rather than complete and damning.
    """
    return GateResult(name, "fail", rationale, detail, disposition="blocked", unblock=unblock)


# ---- reading a finding -----------------------------------------------------


def _field(finding: Any, name: str) -> Any:
    """Read one column off a sqlite3.Row, a dict, or a Finding dataclass."""
    try:
        return finding[name]
    except (KeyError, IndexError, TypeError):
        return getattr(finding, name, None)


def _ref(finding: Any) -> str | int:
    ident = _field(finding, "id")
    if ident is not None:
        return int(ident)
    uid = _field(finding, "uid")
    if not uid:
        raise TriageError(
            "gates take a finding row, not a bare value; load it with store.get_finding(ref)"
        )
    return str(uid)


def _uid(finding: Any) -> str:
    return str(_field(finding, "uid") or _field(finding, "id") or "<finding>")


def _request_row(store: Store, request_id: Any) -> sqlite3.Row | None:
    """Store exposes no get-by-id, so triage reads the requests table itself."""
    if request_id is None or request_id == "":
        return None
    try:
        rid = int(request_id)
    except (TypeError, ValueError):
        return None
    return store.conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()


def _row_get(row: Any, column: str, default: Any = None) -> Any:
    """Read a column that a database older than the migration may not have."""
    try:
        value = row[column]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


def _evidence_citations(
    store: Store, finding: Any
) -> tuple[list[tuple[sqlite3.Row, sqlite3.Row]], list[sqlite3.Row]]:
    """Evidence rows paired with the request they cite: (resolved, dangling).

    In attachment order, because several gates care about what was already on
    the record when a row was added.
    """
    resolved: list[tuple[sqlite3.Row, sqlite3.Row]] = []
    dangling: list[sqlite3.Row] = []
    for ev in store.evidence_for(_ref(finding)):
        if ev["request_id"] is None:
            continue
        req = _request_row(store, ev["request_id"])
        if req is None:
            dangling.append(ev)
        else:
            resolved.append((ev, req))
    return resolved, dangling


def _linked_requests(store: Store, finding: Any) -> dict[int, sqlite3.Row]:
    """Every recorded request this finding cites, from evidence and prerequisites.

    Keyed by id: a request cited twice is one piece of traffic.
    """
    linked: dict[int, sqlite3.Row] = {}
    for _ev, req in _evidence_citations(store, finding)[0]:
        linked[int(req["id"])] = req
    for row in store.prerequisites_for(_ref(finding)):
        req = _request_row(store, row["request_id"])
        if req is not None:
            linked[int(req["id"])] = req
    return linked


def _cross_account_traffic(store: Store, finding: Any) -> list[str]:
    """Cited requests that reached a registered object belonging to someone else.

    What the traffic says, independent of what the finding calls itself. A
    vuln_class is model-written, so relabelling an IDOR as something else would
    otherwise be a way around the gates that police access control; this is the
    recomputed version of the same question. `gate_access_control_ownership`
    does the detailed reading -- this only answers whether it has to.
    """
    known = {str(a["label"]).strip().casefold() for a in store.accounts()}
    objects = store.objects()
    crossing: list[str] = []
    for _ev, request in _evidence_citations(store, finding)[0]:
        actor = str(request["actor"] or "").strip()
        if actor.casefold() not in known:
            continue
        for obj in objects:
            owner = str(obj["owner_account"] or "").strip()
            if not owner or owner.casefold() == actor.casefold():
                continue
            if _touches(str(obj["identifier"] or ""), request):
                crossing.append(
                    f"request {request['id']} as {actor} reached "
                    f"{obj['kind'] or 'object'}:{obj['identifier']}, owned by {owner}"
                )
    return crossing


def _attacker_labels(store: Store) -> set[str]:
    """Accounts declared as the attacker's position, case-folded."""
    return {
        str(a["label"]).strip().casefold()
        for a in store.accounts()
        if str(a["role"] or "").strip().casefold() == "attacker"
    }


def _when(request: sqlite3.Row) -> tuple[str, int]:
    """Order requests in time. Timestamps are per-second, so the id breaks ties."""
    return (str(request["ts"] or ""), int(request["id"]))


def _evidence_is_checkable(evidence: sqlite3.Row, request: sqlite3.Row | None) -> bool:
    """True when the row points at something that exists and can be re-read."""
    path = evidence["path"]
    if path and Path(str(path)).is_file():
        return True
    return request is not None


def _shape(host: Any, path: Any) -> tuple[str, str]:
    """(host, path) normalized for comparison between prose and the request log."""
    normalized = normalize_host(str(host or "")) or str(host or "").strip().lower()
    text = str(path or "") or "/"
    if len(text) > 1:
        text = text.rstrip("/") or "/"
    return normalized, text


def _request_shape(request: sqlite3.Row) -> tuple[str, str]:
    """Recomputed from the recorded URL, not from the host/path columns alone."""
    parts = urlsplit(str(request["url"] or ""))
    return _shape(parts.hostname or request["host"], parts.path or request["path"])


def _url_shape(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return (parts.hostname or "", parts.path or "/")


def _oob_hosts(scope: Scope | None) -> tuple[str, ...]:
    """Researcher-owned callback hosts: infrastructure, not assets under test."""
    if scope is None:
        return ()
    return tuple(str(h).strip().lower() for h in scope.rules.get("oob_hosts", []) if h)


def _is_oob_host(host: str, oob: Iterable[str]) -> bool:
    candidate = str(host or "").strip().lower()
    if not candidate:
        return False
    for pattern in oob:
        bare = pattern[2:] if pattern.startswith("*.") else pattern
        if candidate == bare or candidate.endswith("." + bare):
            return True
    return False


def _urls_and_hosts(text: str) -> tuple[list[str], list[str]]:
    """Every URL and bare hostname a repro mentions, in the order written."""
    body = str(text or "").replace("\r\n", "\n").replace("\\n", "\n")
    urls: list[str] = []
    for match in _URL_RE.finditer(body):
        url = _clean_url(match.group(0))
        if host_from_url(url):
            urls.append(url)
    # Scan what is left for bare names, so a host inside a URL is not counted
    # twice and a URL's path cannot be mistaken for a hostname.
    remainder = _URL_RE.sub(" ", body)
    hosts: list[str] = []
    for match in _BARE_HOST_RE.finditer(remainder):
        candidate = match.group(0).strip(".").lower()
        if candidate.rsplit(".", 1)[-1] in _NOT_HOST_TAILS:
            continue  # "login.php" is a file, not a host
        host = normalize_host(candidate)
        if host and host not in hosts:
            hosts.append(host)
    return urls, hosts


def _waived_or(
    store: Store,
    finding: Any,
    scope: Scope | None,
    failure: GateResult,
    outstanding: Iterable[str] = (),
) -> GateResult:
    """`failure`, unless an operator's signed waiver stands this gate down.

    The waiver is a signed file under `.state/` read by `bbh.waiver`, never a
    row in `gates`: a row is something an agent can write through the sanctioned
    store API, so the literal `not-applicable:` note this replaced could be
    granted by the agent the gate was refusing. The pass this returns carries
    the waiver's own stamp in its detail, so the ledger and the report keep
    saying the requirement was stood down rather than met.

    A waiver that was granted and no longer stands -- expired, revoked, or over
    a finding that has since changed -- is named in the refusal instead of being
    ignored, because an operator who thinks a gate is waived should not have to
    read the code to find out it is not.

    Every refusal that comes back from here parks the finding rather than
    binning it, and that is what makes the waiver reachable at all. A waiver is
    granted against a live finding, the gate it would stand down cannot be known
    until the gates have run, and `bb gate` is the command the gate phase starts
    with -- so a `rejected` on this path would close the door on the way in,
    every time, and the whole mechanism would be dead on arrival. The reading is
    also the honest one: these two gates fail when an artifact is missing, which
    is a measurement nobody took, never a demonstration that the bug is not
    there.
    """
    status = waiver.check(
        store, finding, failure.name, engagement=getattr(scope, "engagement", None)
    )
    if status.honored and status.waiver is not None:
        reasons = " ".join(outstanding) or failure.rationale
        return _pass(
            failure.name,
            f"stood down by {status.waiver.waived_by} until {status.waiver.expires_at}: "
            f"{status.waiver.reason}. Outstanding without it: {reasons}",
            (failure.detail or {}) | waiver.stamp_for(status.waiver),
        )
    parked = _parks_for_waiver(failure, _uid(finding))
    if not (status.found and status.problems):
        # No waiver was granted, or the question could not be answered at all.
        # Either way the gate refuses, which is the strict direction; only a
        # waiver that exists and does not stand is worth adding to the refusal.
        return parked
    return GateResult(
        parked.name,
        parked.verdict,
        f"{parked.rationale} A waiver of this gate exists and does NOT stand: "
        + " ".join(status.problems),
        (parked.detail or {}) | {"waiver_problems": list(status.problems)},
        disposition=parked.disposition,
        unblock=parked.unblock,
    )


def _parks_for_waiver(failure: GateResult, uid: str) -> GateResult:
    """A waivable gate's refusal, as a park rather than a rejection.

    Computed from `waiver.WAIVABLE` rather than written into each gate, so the
    rule is "a gate an operator may stand down never bins its own subject" and
    not a convention the next gate's author has to remember. A gate that already
    said how it parks keeps its own wording.
    """
    if failure.passed or failure.name not in waiver.WAIVABLE or failure.blocked:
        return failure
    return GateResult(
        failure.name,
        failure.verdict,
        failure.rationale,
        failure.detail,
        disposition="blocked",
        unblock=(
            f"the evidence named above; or, if it cannot exist for this bug -- "
            f"{waiver.WAIVABLE[failure.name]} -- an operator's stand-down, argued for with "
            f"`bb gate waive-request {uid} {failure.name} --reason '<why>'` and granted only "
            f"by `bb gate waive {uid} {failure.name} --reason '<why>' --as <who>`"
        ),
    )


def _waiver_remedy(uid: str, gate: str) -> str:
    """How an agent argues a requirement is impossible without granting itself one."""
    return (
        f"If the artifact genuinely cannot exist for this bug, argue it on the record rather "
        f"than inventing it: `bb gate waive-request {uid} {gate} --reason '<why it cannot "
        f"exist>'` records the argument and grants nothing. Only an operator's "
        f"`bb gate waive {uid} {gate} --reason '<why>' --as <who>` stands a gate down, and a "
        f"waived gate ships as waived, not as passed."
    )


# ---- gates -----------------------------------------------------------------


def gate_evidence_exists(store: Store, finding: Any) -> GateResult:
    """At least one artifact, still on disk, still hashing to what was captured.

    A claim with nothing behind it is rejected; an artifact that was hashed
    clean at capture time and does not hash so now is parked instead. The
    second is the harness failing to read its own record -- a moved tree, a
    deleted file -- which says nothing about the bug, and `rejected` is
    permanent.
    """
    name = "gate_evidence_exists"
    uid = _uid(finding)
    ref = _ref(finding)

    rows = store.evidence_for(ref)
    if not rows:
        return _fail(
            name,
            f"no evidence is attached, so there is nothing to check. Capture the artifact "
            f"and record it: `bb evidence add {uid} <request|screenshot|har|terminal|file> <path>`",
        )

    # A citation is an artifact too, so it is resolved rather than believed: a
    # row whose claim is a request id missing from the requests table is a note
    # with a number on it. Checked before the note branch below, so the message
    # names the real problem rather than calling a citation free text.
    resolved, dangling = _evidence_citations(store, finding)
    if dangling:
        broken = "; ".join(
            f"evidence {ev['id']} cites request {ev['request_id']!r}" for ev in dangling
        )
        return _fail(
            name,
            f"{broken}, which is not in the requests table, so the artifact behind it cannot "
            f"be read. Re-send the request (`bb req <METHOD> <URL> --actor <account>`) and cite "
            f"the id it prints: `bb evidence add {uid} request --request-id <id>`",
            {"dangling_evidence_ids": [int(ev["id"]) for ev in dangling]},
        )

    resolving = {int(ev["id"]) for ev, _req in resolved}
    checkable = [r for r in rows if r["path"] or int(r["id"]) in resolving]
    if not checkable:
        return _fail(
            name,
            f"only free-text notes are attached, and a note is not proof. Attach the real "
            f"artifact: `bb evidence add {uid} <request|screenshot|har|terminal|file> <path>`",
            {"evidence_ids": [r["id"] for r in rows]},
        )

    problems = store.verify_evidence(ref)
    if problems:
        # Parked, not binned. An artifact that hashed clean at capture time and
        # does not now is the harness failing to read its own record -- a moved
        # tree, a deleted file, a rebuilt database -- and that says nothing
        # about the bug. `rejected` is permanent, so the one disposition that
        # must not be reached by a file going missing is this one.
        return _blocked(
            name,
            "evidence no longer matches what was captured: "
            + "; ".join(problems)
            + f". Re-capture it and attach it again: `bb evidence add {uid} <kind> <path>`",
            f"every artifact on {uid} present and hashing as captured: "
            f"`bb evidence verify {uid}`, then `bb evidence add {uid} <kind> <path>` for each "
            f"one that moved",
            {"problems": problems},
        )

    return _pass(
        name,
        f"{len(rows)} evidence row(s); every artifact is present and hashes as captured",
        {"evidence_ids": [r["id"] for r in rows]},
    )


def gate_has_request_proof(store: Store, finding: Any) -> GateResult:
    """Evidence of kind "request" pointing at a row that is actually in the store."""
    name = "gate_has_request_proof"
    uid = _uid(finding)

    cited = [ev for ev in store.evidence_for(_ref(finding)) if (ev["kind"] or "").lower() == "request"]
    if not cited:
        return _fail(
            name,
            f"no recorded request backs this finding, so nothing shows the traffic happened. "
            f"Send the proof request through the sanctioned client (`bb req <METHOD> <URL> "
            f"--actor <account>`) and cite the id it prints: `bb evidence add {uid} request "
            f"--request-id <id>`",
        )

    resolved: list[int] = []
    dangling: list[str] = []
    for ev in cited:
        req = _request_row(store, ev["request_id"])
        if req is None:
            dangling.append(f"evidence {ev['id']} -> request {ev['request_id']!r}")
        else:
            resolved.append(int(req["id"]))

    if not resolved:
        return _fail(
            name,
            "the cited request evidence does not resolve to a recorded request ("
            + "; ".join(dangling)
            + f"). Re-send it with `bb req <METHOD> <URL> --actor <account>` and cite the new "
            f"id: `bb evidence add {uid} request --request-id <id>`",
            {"dangling": dangling},
        )

    return _pass(
        name,
        f"backed by recorded request(s) {', '.join(str(r) for r in resolved)}",
        {"request_ids": resolved, "dangling": dangling},
    )


def gate_in_scope(
    scope: Scope | None, finding: Any, store: Store | None = None
) -> GateResult:
    """The asset named by the finding must be one the program authorized.

    `store` is optional only because the contract publishes a two-argument call;
    the registry always passes it, and with it the hosts of the requests this
    finding cites are checked too. A host typed into a finding is a claim, the
    traffic is the artifact, and a proof made against an asset the program did
    not authorize is not a reportable proof whatever the finding says its host is.
    """
    name = "gate_in_scope"
    uid = _uid(finding)
    host = str(_field(finding, "host") or "").strip()

    if not host:
        return _fail(
            name,
            f"the finding names no host, so scope cannot be checked. Set it: "
            f"`bb finding set {uid} --host <host>`",
        )
    if scope is None:
        return _fail(
            name,
            f"no compiled scope was loaded, so {host} cannot be shown to be in scope. "
            f"Run: `bb scope compile <engagement>`",
        )

    auth_problem = scope.authorization_error()
    if auth_problem:
        return _fail(name, f"the engagement is not usable right now: {auth_problem}")

    decision = scope.decide(host)
    if not decision.allowed:
        return _fail(
            name,
            f"{decision.reason}. A finding outside the program's scope cannot be reported; "
            f"fix the host with `bb finding set {uid} --host <host>` if it is wrong.",
            {"host": host, "rule": decision.rule},
        )

    detail: dict[str, Any] = {"host": host, "rule": decision.rule}
    if store is None:
        return _pass(name, decision.reason, detail)

    offenders: list[str] = []
    checked: list[int] = []
    for request in sorted(_linked_requests(store, finding).values(), key=lambda r: int(r["id"])):
        checked.append(int(request["id"]))
        cited_host = normalize_host(request["host"]) or str(request["host"] or "")
        cited = scope.decide(cited_host)
        if not cited.allowed:
            offenders.append(
                f"request {request['id']} ({request['method']} {request['url']}): {cited.reason}"
            )
    if offenders:
        detail["out_of_scope_requests"] = offenders
        return _fail(
            name,
            f"{host} is in scope, but this finding's own proof is traffic the program did not "
            f"authorize: " + "; ".join(offenders) + ". A finding cannot be reported on evidence "
            f"gathered outside scope; cite requests against in-scope assets only, and drop the "
            f"rest with `bb finding advance {uid} rejected`.",
            detail,
        )
    detail["requests_checked"] = checked
    suffix = f"; all {len(checked)} cited request(s) are in scope too" if checked else ""
    return _pass(name, decision.reason + suffix, detail)


def gate_severity_floor(store: Store, finding: Any, floor: str = "low") -> GateResult:
    """Severity must be set, real, and at or above the floor. "info" never ships."""
    name = "gate_severity_floor"
    if floor not in SEVERITIES:
        raise TriageError(f"severity floor must be one of {', '.join(SEVERITIES)}, got {floor!r}")

    uid = _uid(finding)
    severity = str(_field(finding, "severity") or "").strip().lower()
    shippable = "|".join(s for s in SEVERITIES if s != "info")

    # Where a vector exists the severity is recomputable, so the floor is applied
    # to what the metrics say rather than to what was typed. An unreadable vector
    # fails here rather than falling back to the column: falling back is exactly
    # how a free-text "critical" would slip past a gate that looks derived.
    vector = str(_field(finding, "cvss_vector") or "").strip()
    derived_from: str | None = None
    if vector:
        try:
            severity = cvss.severity_label(cvss.base_score(vector))
            derived_from = vector
        except cvss.CvssError as exc:
            return _fail(
                name,
                f"the recorded CVSS vector cannot be scored, so there is no severity here the "
                f"harness can check: {exc}. Fix the vector: "
                f"`bb finding set {uid} --cvss '{cvss.EXAMPLE_VECTOR}'`",
                {"cvss_vector": vector},
            )

    if not severity:
        return _fail(
            name,
            f"severity is not set. Rate it: `bb finding set {uid} --severity <{shippable}>`",
        )
    if severity not in SEVERITIES:
        return _fail(
            name,
            f"severity {severity!r} is not one of {', '.join(SEVERITIES)}. Fix it: "
            f"`bb finding set {uid} --severity <{shippable}>`",
        )
    if severity == "info":
        return _fail(
            name,
            f"informational findings are never shipped. Either demonstrate real impact and "
            f"re-rate it (`bb finding set {uid} --severity <{shippable}>`) or drop it "
            f"(`bb finding advance {uid} rejected`).",
        )
    if SEVERITIES.index(severity) < SEVERITIES.index(floor):
        return _fail(
            name,
            f"severity {severity} is below this engagement's floor of {floor}. Either show "
            f"impact that justifies a higher rating and re-rate it with `bb finding set {uid} "
            f"--severity <{shippable}>`, or drop it with `bb finding advance {uid} rejected`.",
            {"severity": severity, "floor": floor},
        )
    return _pass(
        name,
        f"severity {severity} meets the floor of {floor}"
        + (f" (derived from {derived_from})" if derived_from else ""),
        {"severity": severity, "cvss_vector": derived_from},
    )


def gate_severity_derived(store: Store, finding: Any) -> GateResult:
    """Severity must be what the CVSS vector scores, not what someone typed.

    A severity is the one field a report is read through, and it is the cheapest
    thing in the whole record to inflate: nothing about "critical" costs an agent
    anything. A vector costs eight decisions that a triager can disagree with one
    at a time, and the score follows from them mechanically. So above `low`, the
    rating has to come from metrics, and the harness recomputes it rather than
    believing the column.
    """
    name = "gate_severity_derived"
    uid = _uid(finding)
    vector = str(_field(finding, "cvss_vector") or "").strip()
    severity = str(_field(finding, "severity") or "").strip().lower()

    if not vector:
        if severity in FREE_TEXT_SEVERITIES:
            return _pass(
                name,
                f"severity {severity} is at or below {FREE_TEXT_SEVERITIES[-1]}, where a "
                f"free-text rating is accepted without a vector",
                {"severity": severity},
            )
        asserted = f"severity {severity!r} is asserted" if severity else "severity is not set"
        return _fail(
            name,
            f"{asserted} and no CVSS vector is recorded. Free text is accepted only for "
            f"{' and '.join(FREE_TEXT_SEVERITIES)}; anything a human would act on has to be "
            f"derived from the metrics, so that the rating can be argued with one metric at a "
            f"time: `bb finding set {uid} --cvss '{cvss.EXAMPLE_VECTOR}'` (then the severity "
            f"follows from the vector; do not set both by hand).",
            {"severity": severity or None},
        )

    try:
        score = cvss.base_score(vector)
    except cvss.CvssError as exc:
        return _fail(
            name,
            f"the recorded CVSS vector {vector!r} cannot be scored: {exc}. Fix it: "
            f"`bb finding set {uid} --cvss '{cvss.EXAMPLE_VECTOR}'`",
            {"cvss_vector": vector},
        )

    derived = cvss.severity_label(score)
    detail = {"cvss_vector": vector, "base_score": score, "derived_severity": derived}
    if not severity:
        return _fail(
            name,
            f"{vector} scores {score} ({derived}) but no severity is recorded, so nothing the "
            f"report prints would match the vector. Record what the metrics say: "
            f"`bb finding set {uid} --severity {derived}`",
            detail,
        )
    if severity != derived:
        return _fail(
            name,
            f"severity {severity} does not match the metrics: {vector} scores {score}, which is "
            f"{derived}. One of the two is wrong -- either re-rate it "
            f"(`bb finding set {uid} --severity {derived}`) or fix the metrics that are overstated "
            f"(`bb finding set {uid} --cvss '<vector>'`). Do not change the vector to reach a "
            f"rating; a severity above what the metrics support is the most common over-claim in "
            f"a bounty report and the first thing a triager checks.",
            detail | {"recorded_severity": severity},
        )
    return _pass(name, f"severity {severity} is what {vector} scores ({score})", detail)


def gate_counterevidence_recorded(store: Store, finding: Any) -> GateResult:
    """Somebody argued against this claim, rated it, and said what would move it.

    This is the bar `store.advance` applies when a finding enters `validated`,
    carried upward. Nothing above that rung re-asked it, and `apply_gates` can
    enter `gated` -- the state a report renders from -- straight from
    `candidate`, so until this gate existed the three fields were optional for
    every finding that skipped the rung, which is every finding `bb gate` moved.

    The bar itself is `store.counterevidence_problem`, imported rather than
    restated, so the gate and the state machine cannot disagree about what a
    stub looks like. The rest is recomputed the same way on every run: a field
    cleared after the rung was climbed fails here, where a stored `validated`
    state would have reported the bar as met forever.

    Read out of the store rather than off the row the caller handed in. These
    are the three fields a model writes about its own work, and a gate that
    judged the mapping it was passed would be judging whatever the caller
    composed; the store is the only copy a later run and a report read.
    """
    name = "gate_counterevidence_recorded"
    uid = _uid(finding)
    row = store.get_finding(_ref(finding))
    if row is None:
        # Fail closed: the question "was this argued against" has no answer here,
        # and no answer is not a pass. Parked rather than binned -- a finding the
        # store cannot produce is the harness's problem, not a false claim.
        return _blocked(
            name,
            f"{uid} is not a finding in this engagement's store, so the argument against it "
            f"cannot be read and this gate cannot answer. A gate that cannot compute its "
            f"answer refuses.",
            f"a finding row for {uid} in the engagement being gated: `bb finding list`",
        )

    problems: list[str] = []
    fixes: list[str] = []

    stub = counterevidence_problem(row["counterevidence"])
    if stub:
        problems.append(
            f"{stub}, so nothing on the record says what would make this not a bug -- which is "
            f"the first thing a triager tries"
        )
        fixes.append(
            f"bb finding set {uid} --counterevidence '<the strongest case that this is not a "
            f"bug, and what you checked against it: alternative explanations, an "
            f"intended-behaviour reading, the same request without the payload>'"
        )

    if not str(row["severity_change_conditions"] or "").strip():
        problems.append(
            "severity_change_conditions is empty, so the rating reads as a certainty nobody "
            "has and a triager cannot tell what would move it"
        )
        fixes.append(
            f"bb finding set {uid} --severity-change-conditions '<what would raise this "
            f"severity, and what would lower it>'"
        )

    confidence = row["confidence"]
    if confidence != "high" and not str(row["confidence_rationale"] or "").strip():
        # Unset is not high: a finding nobody rated still owes the reason.
        said = f"confidence is {confidence!r}" if confidence else "confidence is not set"
        problems.append(
            f"{said} and confidence_rationale is empty, so the doubt that rating admits to is "
            f"nowhere a reader can see it"
        )
        fixes.append(
            f"bb finding set {uid} --confidence-rationale '<what you are unsure of and why>'   "
            f"# or --confidence high, if nothing is"
        )

    detail = {
        "problems": problems,
        "confidence": str(confidence or ""),
        "counterevidence_chars": len(str(row["counterevidence"] or "").strip()),
    }
    if not problems:
        return _pass(
            name,
            f"{uid} carries its own counterevidence, a confidence rating and what would change "
            f"its severity",
            detail,
        )

    # Parked, not binned. Every one of these is a sentence nobody has written
    # yet, which says nothing about whether the bug is real; `rejected` is
    # permanent and would kill a true finding over a missing field.
    return _blocked(
        name,
        f"{uid} would ship without the case against it: "
        + "; ".join(problems)
        + ". A claim nobody argued against is a claim nobody checked, and `gated` is a state "
        + "`bb report` renders from. Fix all of it:\n  "
        + "\n  ".join(fixes),
        "; ".join(fixes),
        detail,
    )


def gate_repro_present(store: Store, finding: Any) -> GateResult:
    """Numbered steps a stranger can follow, naming a real URL."""
    name = "gate_repro_present"
    uid = _uid(finding)
    repro = str(_field(finding, "repro") or "").strip()
    if not repro:
        return _fail(
            name,
            f"no reproduction steps are recorded. Write them: `bb finding set {uid} --repro "
            f"'1. <request>\\n2. <request>\\n3. <observed result>'`",
        )

    # Steps written through the CLI sometimes arrive with escaped newlines.
    text = repro.replace("\r\n", "\n").replace("\\n", "\n")
    steps = {m.group(1) for m in _STEP_RE.finditer(text)}
    urls = [u for u in (_clean_url(m.group(0)) for m in _URL_RE.finditer(text)) if host_from_url(u)]

    problems: list[str] = []
    if len(steps) < 2:
        problems.append(
            f"found {len(steps)} numbered step(s); a triager needs at least 2, written as "
            f"'1. ...' then '2. ...'"
        )
    if not urls:
        problems.append(
            "no concrete http(s) URL appears in the steps; write the exact URL that was "
            "requested, not a placeholder"
        )
    if problems:
        return _fail(
            name,
            "; ".join(problems) + f". Rewrite them: `bb finding set {uid} --repro '1. ...'`",
            {"steps": sorted(steps), "urls": urls},
        )

    return _pass(
        name,
        f"{len(steps)} numbered steps naming {len(urls)} URL(s)",
        {"steps": sorted(steps), "urls": urls[:5]},
    )


def gate_repro_cites_real_requests(
    store: Store, finding: Any, scope: Scope | None = None
) -> GateResult:
    """Every URL and host in the repro must appear in traffic linked to this finding.

    This is the anti-hallucination control. Steps that read well are free; steps
    that reconcile against the request log are not, because every line of them had
    to happen. An endpoint in the repro that the harness never requested means the
    steps were composed rather than observed, and a composed repro is the one
    defect that wastes a triager's whole afternoon before it is caught.

    `scope` is optional and only used to excuse researcher-owned callback hosts
    (`rules.oob_hosts`), which are infrastructure a blind finding has to name and
    which the harness, by construction, never requests.
    """
    name = "gate_repro_cites_real_requests"
    uid = _uid(finding)
    repro = str(_field(finding, "repro") or "").strip()

    if not repro:
        return _fail(
            name,
            f"there are no reproduction steps to reconcile against the request log, so nothing "
            f"here can be checked against what the harness actually sent. Write them from the "
            f"traffic: `bb finding set {uid} --repro '1. <request>\\n2. <request>\\n3. <result>'`",
        )

    urls, hosts = _urls_and_hosts(repro)
    if not urls and not hosts:
        # Nothing to reconcile is not the same as nothing wrong: a repro that
        # names no traffic cannot be checked against any, so it fails closed.
        return _fail(
            name,
            f"the steps name no URL or host at all, so there is nothing to reconcile against the "
            f"request log. Write the exact URL each step requested, copied from the traffic: "
            f"`bb finding set {uid} --repro '1. GET https://<host>/<path> as <actor> ...'`",
            {"repro_urls": [], "repro_hosts": []},
        )

    linked = _linked_requests(store, finding)
    recorded_shapes = {_request_shape(r) for r in linked.values()}
    recorded_hosts = {shape[0] for shape in recorded_shapes}

    if not linked:
        return _fail(
            name,
            f"{FABRICATION_FLAG}: no recorded request is linked to this finding at all, so every "
            f"URL in the steps is unverifiable. Re-run each step through the sanctioned client "
            f"(`bb req <METHOD> <URL> --actor <account>`) and cite the ids it prints "
            f"(`bb evidence add {uid} request --request-id <id> --role attack`).",
            {"repro_urls": urls[:10], "repro_hosts": hosts[:10], "linked_requests": []},
        )

    oob = _oob_hosts(scope)
    unmatched_hosts = [
        host for host in hosts if host not in recorded_hosts and not _is_oob_host(host, oob)
    ]
    unmatched_urls = [
        url
        for url in urls
        if _shape(*_url_shape(url)) not in recorded_shapes
        and not _is_oob_host(host_from_url(url) or "", oob)
        # A URL on a host already named below is the same fabrication twice.
        and (host_from_url(url) or "") not in unmatched_hosts
    ]

    detail = {
        "repro_urls": urls[:10],
        "repro_hosts": hosts[:10],
        "linked_requests": sorted(linked),
        "unmatched_urls": unmatched_urls,
        "unmatched_hosts": unmatched_hosts,
    }
    if unmatched_urls or unmatched_hosts:
        named = ", ".join(unmatched_urls + unmatched_hosts)
        return _fail(
            name,
            f"{FABRICATION_FLAG}: the steps name {named}, which appears in no request linked to "
            f"this finding (linked requests: {', '.join(str(i) for i in sorted(linked))}). Either "
            f"the step never happened, or it happened outside the harness and there is no record "
            f"of it -- both make the report unverifiable. Re-run exactly these steps "
            f"(`bb req <METHOD> <URL> --actor <account>`), cite each one "
            f"(`bb evidence add {uid} request --request-id <id> --role attack`), and rewrite the "
            f"steps from what the log says. If a host is researcher-owned callback "
            f"infrastructure, list it under `rules.oob_hosts` in scope.yaml and recompile: "
            f"`bb scope compile <engagement>`.",
            detail,
        )

    return _pass(
        name,
        f"every URL ({len(urls)}) and host ({len(hosts)}) in the steps appears in traffic linked "
        f"to this finding",
        detail,
    )


def gate_access_control_ownership(store: Store, finding: Any) -> GateResult:
    """Proof that one account reached another account's registered object.

    Everything else about an access-control report is narration. This is the
    only part that can be checked mechanically, so it is the only part trusted.
    """
    name = "gate_access_control_ownership"
    uid = _uid(finding)
    vuln_class = str(_field(finding, "vuln_class") or "")

    # The class is a label and the traffic is the artifact: a finding whose own
    # evidence reaches another account's object is policed here whatever it is
    # called, so that relabelling is not a way round this gate.
    crossing = _cross_account_traffic(store, finding)
    if not is_access_control_class(vuln_class) and not crossing:
        return _pass(
            name,
            f"vuln_class {vuln_class!r} is not an access-control class; no ownership proof "
            f"is required",
        )

    registered = store.objects()
    if not registered:
        return _fail(name, NO_OBJECT_RATIONALE, {"registered_objects": 0})

    cited = [
        ev
        for ev in store.evidence_for(_ref(finding))
        if (ev["kind"] or "").lower() == "request" and ev["request_id"] is not None
    ]
    if not cited:
        return _fail(
            name,
            NO_REQUEST_RATIONALE.format(uid=uid),
            {"registered_objects": len(registered)},
        )

    known = {str(a["label"]).strip().casefold() for a in store.accounts()}
    inspected: list[int] = []
    problems: list[str] = []
    own: list[str] = []
    unowned: list[str] = []

    for ev in cited:
        req = _request_row(store, ev["request_id"])
        if req is None:
            problems.append(
                f"evidence {ev['id']} cites request {ev['request_id']!r}, which is not in the "
                f"requests table."
            )
            continue
        inspected.append(int(req["id"]))

        actor = str(req["actor"] or "").strip()
        # A is only an account if it was declared as one; otherwise the harness
        # cannot tell the attacker's traffic from the victim's own session.
        if actor.casefold() not in known:
            problems.append(
                f"request {req['id']} is recorded against actor "
                f"{(actor or '(none)')!r}, which is not a registered account, so the harness "
                f"cannot say who made it. Register it (`bb account add <label> --role attacker`) "
                f"and re-send the request with `bb req <METHOD> <URL> --actor <label>`."
            )
            continue

        for obj in registered:
            if not _touches(str(obj["identifier"] or ""), req):
                continue
            label = f"{obj['kind'] or 'object'}:{obj['identifier']} ({obj['label']})"
            owner = str(obj["owner_account"] or "").strip()
            if not owner:
                unowned.append(label)
                continue
            if owner.casefold() == actor.casefold():
                own.append(f"{label} is owned by {actor}")
                continue
            # The proof is also a question: how would an attacker have got this
            # identifier? Produce the ledger row that asks it.
            produced = _record_identifier_prerequisite(store, finding, obj)
            return _pass(
                name,
                f"request {req['id']} ({req['method']} {req['url']}) was made as {actor!r} and "
                f"reached {label}, which the objects table records as owned by {owner!r}",
                {
                    "request_id": int(req["id"]),
                    "actor": actor,
                    "object": obj["identifier"],
                    "owner": owner,
                    "requests_inspected": inspected,
                    **produced,
                },
            )

    detail = {
        "requests_inspected": inspected,
        "registered_objects": len(registered),
        "own_objects": own,
        "unowned_objects": unowned,
        "problems": problems,
    }
    if own:
        return _fail(
            name,
            f"every object the cited requests reached belongs to the acting account "
            f"({'; '.join(own)}): changing an identifier you own is not broken access control. "
            f"Cite a request made as one account that reaches an object registered to another: "
            f"`bb req <METHOD> <URL> --actor <attacker>` then `bb evidence add {uid} request "
            f"--request-id <id>`",
            detail,
        )
    if problems:
        return _fail(name, " ".join(problems), detail)
    if unowned:
        return _fail(
            name,
            f"the cited request reached {', '.join(unowned)}, but no owner is recorded for it, "
            f"so the harness cannot tell whose data it is. Re-register the object with its "
            f"owner: `bb object add --label <label> --kind <kind> --identifier <id> "
            f"--owner-account <account>`",
            detail,
        )
    return _fail(name, NO_OBJECT_RATIONALE, detail)


def _record_identifier_prerequisite(
    store: Store, finding: Any, obj: sqlite3.Row
) -> dict[str, Any]:
    """Record that the attack needs the victim's identifier, unless it already is.

    The ownership gate proves the authorization check is missing. That is a
    different claim from "an attacker could do this": the harness handed the
    identifier to the attacker out of the objects table. So the proof produces a
    row in the reachability ledger, defaulting to `not_reachable`, because nobody
    has traced it yet and until someone does, the verdict that keeps the finding
    out of a report is the honest one.

    A row that already mentions this identifier is left exactly as it stands: a
    producer must never overwrite a verdict somebody traced.
    """
    identifier = str(obj["identifier"] or "").strip()
    if not identifier:
        return {}
    kind = str(obj["kind"] or "").strip() or "object"
    label = f"{kind} identifier {identifier}"

    for row in store.prerequisites_for(_ref(finding)):
        mentions = str(row["name"] or "").strip().casefold() == label.casefold() or any(
            _mentions(identifier, row[column])
            for column in ("name", "acquisition", "attacker_start", "searched")
        )
        if mentions:
            return {
                "prerequisite": str(row["name"]),
                "prerequisite_verdict": str(row["verdict"]),
                "prerequisite_produced": False,
            }

    store.add_prerequisite(
        _ref(finding),
        label,
        acquisition=(
            "untraced: the harness handed this identifier to the attacker out of the objects "
            "table. Owning both test accounts proves the authorization check is missing and is "
            "zero evidence an attacker could obtain the identifier."
        ),
        verdict="not_reachable",
    )
    return {
        "prerequisite": label,
        "prerequisite_verdict": "not_reachable",
        "prerequisite_produced": True,
    }


def gate_prerequisites_reachable(store: Store, finding: Any) -> GateResult:
    """Nothing is verified until every prerequisite is reachable by an attacker.

    This is the gate that separates "the authorization check is missing" from
    "someone could exploit this". The harness gives its own attacker account the
    victim's identifier, so the authorization break is trivial to demonstrate and
    says nothing about delivery: a UUIDv4 with no attacker-reachable leak kills
    the finding however clean the break is. Each prerequisite therefore has to be
    traced from a position an attacker actually starts in, and the trace has to
    cite a request that is in the log and was made as a registered attacker.

    Dispositions, in order of precedence: a `not_reachable` row, or a `reachable`
    row whose trace does not hold up, is a determined negative and rejects the
    finding. A `blocked` row is an unfinished measurement, not a negative, and
    parks the finding instead -- a tooling failure recorded as a negative poisons
    every later run through the angle ledger. No row at all parks too, by the
    same rule: nobody having traced the prerequisite is strictly less measured
    than a row that says the trace was blocked, and binning the finding would
    bin the one this gate's own `bb prereq add` remedy is addressed to.
    """
    name = "gate_prerequisites_reachable"
    uid = _uid(finding)
    vuln_class = str(_field(finding, "vuln_class") or "")
    rows = store.prerequisites_for(_ref(finding))

    if not rows:
        # Recomputed, not read: a finding whose evidence crosses accounts owes
        # the same question whatever its vuln_class says.
        crossing = _cross_account_traffic(store, finding)
        if is_access_control_class(vuln_class) or crossing:
            because = (
                f"a {vuln_class} claim always has at least one: the victim's identifier"
                if is_access_control_class(vuln_class)
                else f"this finding's own evidence crosses accounts ({crossing[0]}), so it "
                f"needs one whatever its class says"
            )
            # Parked, by this gate's own rule: a `blocked` row below is an
            # unfinished measurement rather than a negative, and no row at all
            # is strictly less measured than that. Rejecting here would also
            # bin the finding the remedy in this very sentence is addressed to.
            return _blocked(
                name,
                f"no prerequisite is recorded, and {because}. "
                f"Owning both test accounts proves the authorization "
                f"check is missing and is zero evidence an attacker could obtain the identifier, "
                f"so trace it and record what you find: `bb prereq add {uid} '<what the attack "
                f"needs>' --attacker-start '<where an attacker begins>' --acquisition '<how they "
                f"get it from there>' --verdict reachable --request-id <id>`. If you looked and "
                f"it is not reachable, record that instead (`--verdict not_reachable --searched "
                f"'<where you looked>'`); an untraced prerequisite is not a finding.",
                f"a prerequisite row with a traced verdict: `bb prereq add {uid} '<what the "
                f"attack needs>' --verdict <reachable|not_reachable> --request-id <id>`",
                {"vuln_class": vuln_class, "prerequisites": 0},
            )
        return _pass(
            name,
            f"no prerequisite is recorded and {vuln_class!r} is not a class that needs one; "
            f"record any identifier, token or state the attack needs with `bb prereq add {uid}`",
            {"vuln_class": vuln_class, "prerequisites": 0},
        )

    attackers = _attacker_labels(store)
    determined: list[str] = []
    parked: list[str] = []
    proven: list[str] = []

    for row in rows:
        label = str(row["name"])
        verdict = str(row["verdict"] or "").strip()

        if verdict == "blocked":
            why = str(row["acquisition"] or row["searched"] or "no reason recorded")
            parked.append(f"{label!r} ({why})")
            continue
        if verdict != "reachable":
            searched = str(row["searched"] or "").strip()
            looked = f" Searched: {searched}." if searched else (
                " Nothing is recorded about where anyone looked, which is not the same as "
                "having looked."
            )
            determined.append(
                f"prerequisite {label!r} is {verdict or 'unrecorded'}, so the attack needs "
                f"something an attacker cannot get.{looked}"
            )
            continue

        request = _request_row(store, row["request_id"])
        if request is None:
            determined.append(
                f"prerequisite {label!r} is recorded reachable but cites "
                f"{row['request_id']!r}, which is not a request in the log, so the claim rests "
                f"on nothing. Acquire it for real and cite the id: "
                f"`bb prereq add {uid} '{label}' --verdict reachable --request-id <id>`"
            )
            continue

        actor = str(request["actor"] or "").strip()
        if actor.casefold() in attackers:
            proven.append(f"{label!r} via request {request['id']} as {actor}")
            continue
        if not attackers:
            determined.append(
                f"prerequisite {label!r} cites request {request['id']}, but no account in this "
                f"engagement is registered with --role attacker, so the harness cannot tell "
                f"whose position acquired it. Register the attacker's starting point -- an "
                f"unauthenticated visitor is still an attacker -- and re-acquire it from there: "
                f"`bb account add <label> --role attacker` then "
                f"`bb req <METHOD> <URL> --actor <label>`"
            )
            continue
        determined.append(
            f"prerequisite {label!r} cites request {request['id']}, which was made as "
            f"{(actor or '(none)')!r}: not one of this engagement's attacker accounts "
            f"({', '.join(sorted(attackers))}). Acquiring the identifier as its owner, or as the "
            f"harness, proves only that the harness knows it. Re-acquire it as the attacker and "
            f"cite that request: `bb req <METHOD> <URL> --actor <attacker>` then "
            f"`bb prereq add {uid} '{label}' --verdict reachable --request-id <id>`"
        )

    detail = {
        "prerequisites": len(rows),
        "proven": proven,
        "determined": determined,
        "blocked": parked,
    }

    if determined:
        return _fail(
            name,
            " ".join(determined)
            + f" A finding whose prerequisites an attacker cannot reach is not reportable "
            f"however clean the authorization break is; if that is the answer, record it: "
            f"`bb finding advance {uid} rejected`",
            detail,
        )
    if parked:
        names = ", ".join(parked)
        return _blocked(
            name,
            f"prerequisite {names} is blocked, so whether an attacker could reach it is "
            f"unmeasured rather than answered. The finding is parked, not rejected: a block is "
            f"not a negative result, and a tooling failure recorded as a negative poisons every "
            f"later run through the angle ledger.",
            f"a reachable or not_reachable verdict for {names}, with the request that settles it: "
            f"`bb prereq add {uid} '<name>' --verdict reachable --request-id <id>`",
            detail,
        )
    return _pass(
        name,
        f"every prerequisite ({len(rows)}) was acquired from the attacker's own position: "
        + "; ".join(proven),
        detail,
    )


def gate_evidence_roles(
    store: Store, finding: Any, scope: Scope | None = None
) -> GateResult:
    """A differential claim needs both sides of the difference on the record.

    "It returned the victim's document" is one response. On its own it is equally
    consistent with the endpoint being public, with a shared cache, with the test
    accounts being the same account, and with the bug. What distinguishes them is
    the pair: the control working (`baseline`), then the control bypassed
    (`attack`). A claim that changed something also owes the effect seen from the
    owner's side (`verification`), because the attacker's own 200 is the response
    the server chose to send, not proof that anything persisted.

    The only way out is an operator's signed waiver (`bb gate waive`), which
    ships in the report as a waived gate rather than a passed one. A public,
    unauthenticated or single-party bug has no owner side and no working control
    to photograph, so the comparison this gate wants cannot exist for it; that
    is a decision someone made, not a gap nobody noticed.
    """
    name = "gate_evidence_roles"
    uid = _uid(finding)
    vuln_class = str(_field(finding, "vuln_class") or "")
    trigger = _class_hits(vuln_class, EVIDENCE_ROLE_CLASSES)
    if not trigger and _cross_account_traffic(store, finding):
        trigger = "access-control (by its own traffic, whatever the class says)"

    if not trigger:
        return _pass(
            name,
            f"vuln_class {vuln_class!r} is not a class whose proof is a comparison, so no "
            f"baseline/attack pair is required",
            {"vuln_class": vuln_class},
        )

    resolved, _dangling = _evidence_citations(store, finding)
    requests_by_evidence = {int(ev["id"]): req for ev, req in resolved}
    by_role: dict[str, list[sqlite3.Row]] = {}
    for ev in store.evidence_for(_ref(finding)):
        request = requests_by_evidence.get(int(ev["id"]))
        if not _evidence_is_checkable(ev, request):
            continue  # a row pointing at nothing readable is not evidence of a role
        by_role.setdefault(str(_row_get(ev, "role", "context")), []).append(ev)

    problems: list[str] = []
    for role, what in (
        ("baseline", "nothing shows the control working before it was bypassed"),
        ("attack", "nothing shows the control being bypassed"),
    ):
        if not by_role.get(role):
            problems.append(
                f"no readable evidence row with --role {role}, so {what}. Capture it and record "
                f"the role at capture time: `bb evidence add {uid} request --request-id <id> "
                f"--role {role}`"
            )

    baseline_ids = {
        int(requests_by_evidence[int(ev["id"])]["id"])
        for ev in by_role.get("baseline", [])
        if int(ev["id"]) in requests_by_evidence
    }
    attack_ids = {
        int(requests_by_evidence[int(ev["id"])]["id"])
        for ev in by_role.get("attack", [])
        if int(ev["id"]) in requests_by_evidence
    }
    if baseline_ids and baseline_ids == attack_ids:
        problems.append(
            f"the baseline and the attack cite the same request(s) "
            f"({', '.join(str(i) for i in sorted(attack_ids))}): one request cannot be both "
            f"sides of a comparison. Send the control case separately and cite it as the "
            f"baseline"
        )

    mutating = sorted(
        {
            (str(req["method"]).upper(), int(req["id"]))
            for _ev, req in resolved
            if str(req["method"] or "").upper() in STATE_CHANGING_METHODS
        }
    )
    if mutating and not by_role.get("verification"):
        shown = ", ".join(f"{method} as request {rid}" for method, rid in mutating)
        problems.append(
            f"this claim changes state ({shown}) but no evidence row has --role verification, so "
            f"the only witness to the effect is the response the server chose to send the "
            f"attacker. Observe it from the owner's side and record that: "
            f"`bb evidence add {uid} <request|screenshot> --role verification ...`"
        )
    elif mutating and attack_ids:
        attack_actors = {
            str(requests_by_evidence[int(ev["id"])]["actor"] or "").strip().casefold()
            for ev in by_role.get("attack", [])
            if int(ev["id"]) in requests_by_evidence
        }
        checks = [
            requests_by_evidence[int(ev["id"])]
            for ev in by_role["verification"]
            if int(ev["id"]) in requests_by_evidence
        ]
        if checks and all(
            str(r["actor"] or "").strip().casefold() in attack_actors for r in checks
        ):
            problems.append(
                f"every verification request ({', '.join(str(r['id']) for r in checks)}) was made "
                f"as the attacking account itself, which is the same side of the test as the "
                f"attack. Re-read the object as its owner: `bb req GET <url> --actor <owner>` "
                f"then `bb evidence add {uid} request --request-id <id> --role verification`"
            )

    detail = {
        "vuln_class": vuln_class,
        "matched": trigger,
        "roles": {role: [int(ev["id"]) for ev in rows] for role, rows in sorted(by_role.items())},
        "problems": problems,
    }

    if not problems:
        return _pass(
            name,
            f"a {trigger} claim with "
            + ", ".join(f"{len(rows)} {role}" for role, rows in sorted(by_role.items()))
            + " evidence row(s)",
            detail,
        )

    return _waived_or(
        store,
        finding,
        scope,
        _fail(name, " ".join(problems) + " " + _waiver_remedy(uid, name), detail),
        problems,
    )


def gate_independent_verification(
    store: Store, finding: Any, scope: Scope | None = None
) -> GateResult:
    """The verification has to be traffic that did not already know the answer.

    Agreement only means something when the second look could have disagreed, so
    the harness asks for an `attack` evidence row citing a request that is not
    one of the requests already on the record, and that happened after them.
    Re-citing a request that was already there is a replay: the same response
    read twice, agreeing with itself.

    There is no state-transition log to read the `validated` citation set out of,
    so the set is reconstructed as everything this finding already cited when the
    row was attached -- a superset of the validated-era citations, which can only
    make the gate stricter, never laxer.
    """
    name = "gate_independent_verification"
    uid = _uid(finding)

    resolved, dangling = _evidence_citations(store, finding)
    prereq_cited = {
        int(req["id"])
        for req in (
            _request_row(store, row["request_id"])
            for row in store.prerequisites_for(_ref(finding))
        )
        if req is not None
    }
    attacks = [(ev, req) for ev, req in resolved if str(_row_get(ev, "role", "")) == "attack"]

    retry = (
        f"Re-run the attack from a clean position -- a session and account registered in this "
        f"phase, not the one that found it -- and cite the new request: "
        f"`bb req <METHOD> <URL> --actor <attacker>` then "
        f"`bb evidence add {uid} request --request-id <new id> --role attack`"
    )

    if not attacks:
        missing = (
            "no readable evidence row is recorded with --role attack, so there is no second "
            "reproduction to be independent of the first."
        )
        return _waived_or(
            store,
            finding,
            scope,
            _fail(
                name,
                f"{missing} {retry} {_waiver_remedy(uid, name)}",
                {"dangling_evidence": [int(ev["id"]) for ev in dangling]},
            ),
            [missing],
        )

    problems: list[str] = []
    for ev, req in attacks:
        earlier = [(e, r) for e, r in resolved if int(e["id"]) < int(ev["id"])]
        earlier_ids = {int(r["id"]) for _e, r in earlier} | prereq_cited
        if int(req["id"]) in earlier_ids:
            problems.append(
                f"evidence {ev['id']} cites request {req['id']}, which this finding already "
                f"cited: replaying a request that is already on the record is the same response "
                f"read twice, not a second reproduction."
            )
            continue
        if not [e for e, _r in earlier if str(_row_get(e, "role", "")) == "attack"]:
            # The first attack row is the reproduction itself. Independence needs
            # a second one; a baseline cited before it proves nothing about that.
            problems.append(
                f"evidence {ev['id']} (request {req['id']}) is the only attack reproduction on "
                f"this finding, so there is nothing for it to be independent of."
            )
            continue
        not_later = [r for _e, r in earlier if _when(r) >= _when(req)]
        if not_later:
            problems.append(
                f"request {req['id']} ({req['ts']}) is not later than every request already "
                f"cited ({', '.join(str(r['id']) + ' at ' + str(r['ts']) for r in not_later)}), "
                f"so it is traffic from the original pass, not a re-test of it."
            )
            continue
        return _pass(
            name,
            f"evidence {ev['id']} cites request {req['id']} ({req['method']} {req['url']} at "
            f"{req['ts']}), disjoint from the {len(earlier_ids)} request(s) cited earlier and "
            f"later than all of them",
            {
                "verification_evidence_id": int(ev["id"]),
                "verification_request_id": int(req["id"]),
                "earlier_request_ids": sorted(earlier_ids),
            },
        )

    return _waived_or(
        store,
        finding,
        scope,
        _fail(
            name,
            " ".join(problems) + f" {retry} {_waiver_remedy(uid, name)}",
            {
                "attack_request_ids": sorted({int(r["id"]) for _e, r in attacks}),
                "earlier_request_ids": sorted(
                    {int(r["id"]) for _e, r in resolved} | prereq_cited
                ),
                "problems": problems,
            },
        ),
        problems,
    )


def gate_frozen_claim_intact(store: Store, finding: Any) -> GateResult:
    """The claim that was verified has to be the claim that ships.

    `gate_independent_verification` asks whether the second reproduction could
    have disagreed with the first. What it cannot see is an edit made after the
    agreement: rewrite `repro`, the endpoint or the class once the verifying pass
    has agreed, and the agreement is about text nobody checked. `bb finding
    freeze` pins the bytes the verifier is briefed with, and this gate is what
    reads the pin -- without it, the pin is a record no gate consults, which is
    not a check.

    Every failure here parks rather than rejects. An unpinned claim is a
    measurement nobody took, and a moved claim is a verification that has to be
    run again; both are things a later run fixes, and `rejected` is permanent.
    """
    name = "gate_frozen_claim_intact"
    # Imported here rather than at module scope: `runner` is the orchestrator
    # that calls these gates, so a top-level import would read as the dependency
    # pointing the wrong way and would pull the subprocess machinery into every
    # importer of the gate registry. There is no cycle either way -- runner
    # imports the store, the scope and untrusted, and never triage.
    from . import runner

    uid = _uid(finding)
    unblock = (
        f"the claim is pinned and the independent pass has run against it as it now stands: "
        f"bb finding freeze {uid}, then bb phase {runner.VERIFY_PHASE_KEY} <engagement>"
    )
    try:
        problems = runner.frozen_claim_problems(store, _ref(finding))
    except (RuntimeError, OSError) as exc:
        # Not log-and-continue: an unanswerable question becomes the strictest
        # non-permanent verdict and names what went wrong. A store outside the
        # engagement tree has nowhere to pin a claim, which is the harness's
        # problem and not grounds for binning a finding.
        return _blocked(
            name,
            f"whether {uid} still matches its pinned claim could not be computed: {exc}",
            unblock,
            {"error": str(exc)},
        )
    if not problems:
        return _pass(
            name,
            f"{uid} still hashes to the claim pinned before the independent pass "
            f"({', '.join(runner.FROZEN_CLAIM_FIELDS)})",
            {"frozen_fields": list(runner.FROZEN_CLAIM_FIELDS),
             "frozen_sha256": str(_field(finding, "frozen_sha256") or "")},
        )
    return _blocked(name, " ".join(problems), unblock, {"problems": problems})


def gate_not_duplicate(store: Store, finding: Any) -> GateResult:
    """No other live finding is the same bug, by a key the harness computed.

    The stored `findings.dedup_key` is read only to report that it disagrees.
    See `dedup_parts` for what replaces it and why the model-written column
    could never have answered this question.

    Every failure here is `blocked`, never `rejected`. "This may be a duplicate"
    is not a determined negative about the bug: it is either a merge waiting to
    happen -- and the terminal state for a duplicate is `duplicate`, which
    `merge_findings` sets, not `rejected` -- or an ambiguous pair nobody has
    adjudicated. `rejected` is permanent and would be the wrong word for both.
    """
    name = "gate_not_duplicate"
    uid = _uid(finding)
    try:
        review = review_duplicates(store, finding)
    except DedupUnavailable as exc:
        return _blocked(
            name,
            f"the harness cannot compute a dedup key for {uid}, so it cannot tell whether this "
            f"is a second report of a bug already on the record: " + " ".join(exc.problems),
            "; ".join(exc.problems),
            {"problems": list(exc.problems)},
        )

    detail = review.as_dict()
    problems: list[str] = []
    unblocks: list[str] = []
    for pair in review.duplicates:
        problems.append(
            f"{pair.other_uid} ({pair.other_state}) was adjudicated a duplicate of this "
            f"finding by {pair.source or 'a judge'} -- {pair.reason or 'no reason recorded'} -- "
            f"and nothing has been merged, so both are still live and both would be submitted. "
            f"Collapse them: `bb finding merge {uid} --into {pair.other_uid} "
            f"--reason '<the shared root cause>'` (or the other way round, if this one is the "
            f"better write-up)."
        )
        unblocks.append(f"bb finding merge {uid} --into {pair.other_uid} --reason '<cause>'")
    for pair in review.unresolved:
        held = (
            f"holds the same computed dedup key {pair.key.short}"
            if pair.relation == "same_key"
            else f"is a near miss for dedup key {pair.key.short}"
        )
        said = (
            f"a judge has already looked and returned undetermined "
            f"({pair.reason or 'no reason recorded'}), so the question is still open"
            if pair.verdict == "undetermined"
            else "and no verdict is recorded"
        )
        problems.append(
            f"{pair.other_uid} ({pair.other_state}) {held} -- {pair.why} -- {said}. Submitting "
            f"both would send one bug twice. Decide it: `bb finding dedupe {uid} --against "
            f"{pair.other_uid} --verdict duplicate|distinct --because '<what makes them the "
            f"same bug, or two>'`, then `bb finding merge {uid} --into {pair.other_uid} "
            f"--reason '<the shared root cause>'` if they are the same. If you have compared "
            f"them yourself and they are two bugs, record that as yours: `bb finding dedupe "
            f"{uid} --against {pair.other_uid} --not-duplicate-because '<why they are two>'`."
        )
        unblocks.append(
            f"bb finding dedupe {uid} --against {pair.other_uid} --verdict <v> --because '<r>'"
        )

    if problems:
        return _blocked(name, " ".join(problems), "; ".join(unblocks), detail)

    rationale = (
        f"dedup key {review.key.short} ({review.key.canonical}), computed from "
        f"{len(review.key.request_ids)} cited request(s), is held by no other live finding"
    )
    if review.cleared:
        rationale += (
            "; " + ", ".join(
                f"{p.other_uid} was adjudicated {p.verdict} by {p.source or 'a judge'} "
                f"({p.reason})"
                for p in review.cleared
            )
        )
    if review.stored_disagrees:
        rationale += (
            f"; the stored dedup_key {review.stored_key!r} is not what the harness computes and "
            f"was ignored -- refresh it with `bb finding dedupe {uid} --write-key`"
        )
    if review.not_compared:
        rationale += (
            "; not compared against "
            + ", ".join(f"{other} (no computable key)" for other, _why in review.not_compared)
            + ", each of which fails this gate itself until its own key can be computed"
        )
    return _pass(name, rationale, detail)


# ---- dedupe ----------------------------------------------------------------


def normalize_path_shape(path: Any) -> str:
    """Collapse identifier-shaped segments, so two hits on one route match.

    MUST stay in step with the normaliser `bbh/coverage.py` (v2 item 10) uses
    for its `surfaces` rows. A dedup key and a coverage surface that disagree
    about what counts as one route would make "tested" and "duplicate" answer
    questions about different things, and the gap would be invisible: both would
    look right in isolation. coverage.py does not exist yet, so this is the only
    copy; when it lands it should import this function rather than write a
    second one, and a test should pin the two together.

    Case-folded, like the host. Two findings whose routes differ only in case
    would otherwise differ in more than one segment and be read as two bugs,
    which makes the shift key an evasion; folding them together costs only a
    referral in the rare case where a target really routes case-sensitively.
    """
    text = unquote(str(path or "").strip())
    for cut in ("?", "#"):
        if cut in text:
            text = text.split(cut, 1)[0]
    # Classified before folding, because a canonical ULID is upper case and a
    # case-insensitive match for one would swallow any 26-letter word.
    segments = [
        ID_PLACEHOLDER if _is_identifier_segment(raw) else raw.casefold()
        for raw in text.split("/")
        if raw
    ]
    return "/" + "/".join(segments)


def _is_identifier_segment(segment: str) -> bool:
    return bool(
        _DIGIT_SEG_RE.match(segment)
        or _UUID_SEG_RE.match(segment)
        or _HEX_SEG_RE.match(segment)
        or _ULID_SEG_RE.match(segment)
    )


def surface_shape(host: Any, path: Any) -> str:
    """`host` plus the normalized path: the unit a dedup key treats as one route."""
    normalized_host, _path = _shape(host, path)  # same host normalization as the other gates
    return f"{normalized_host}{normalize_path_shape(path)}"


def _request_surface(request: sqlite3.Row) -> str:
    """Recomputed from the recorded URL, so the host/path columns cannot drift."""
    parts = urlsplit(str(request["url"] or ""))
    return surface_shape(parts.hostname or request["host"], parts.path or request["path"])


class DedupUnavailable(TriageError):
    """The record does not support computing this finding's dedup key.

    Carries every problem it found, not the first: a finding missing both an
    endpoint and a citation should learn both in one round trip.
    """

    def __init__(self, uid: str, problems: Iterable[str]) -> None:
        self.uid = uid
        self.problems: tuple[str, ...] = tuple(problems)
        super().__init__(f"cannot compute a dedup key for {uid}: " + " ".join(self.problems))


def _escape_component(value: Any) -> str:
    """Make the four components unambiguous under a `|` join.

    Without this, a class `a|b` with a route `c` would hash the same as a class
    `a` with a route `b|c`.
    """
    return str(value).replace("%", "%25").replace("|", "%7C")


@dataclass(frozen=True)
class DedupKey:
    """The four components of a dedup key, plus where they were read from."""

    vuln_class: str
    path_shape: str
    param: str
    auth_state: str
    # Provenance, excluded from comparison: two findings hold the same key when
    # the four components match, whether or not they cite the same rows.
    request_ids: tuple[int, ...] = field(default=(), compare=False)
    auth_sources: tuple[tuple[int, str], ...] = field(default=(), compare=False)

    @property
    def canonical(self) -> str:
        return "|".join(_escape_component(getattr(self, name)) for name in DEDUP_KEY_FIELDS)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical.encode("utf-8")).hexdigest()

    @property
    def short(self) -> str:
        return self.digest[:12]

    def as_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "canonical": self.canonical,
            **{name: getattr(self, name) for name in DEDUP_KEY_FIELDS},
            "request_ids": list(self.request_ids),
            "positions": [
                {"request_id": rid, "position": position} for rid, position in self.auth_sources
            ],
        }


def _account_roles(store: Store) -> dict[str, str]:
    """Registered label -> role, both case-folded and separator-normalized.

    The key uses the role, not the label, so one bug proven by two different
    attacker accounts -- the one that found it and the fresh one 06-verify
    registers to re-test it independently -- lands on one key instead of two.
    """
    return {
        str(account["label"]).strip().casefold(): "-".join(
            _class_tokens(str(account["role"] or ""))
        )
        for account in store.accounts()
    }


def _actor_position(request: sqlite3.Row, roles: dict[str, str]) -> str:
    """The position a recorded request was sent from, for the auth_state component.

    An actor with no registered account falls back to `account:<label>` rather
    than being refused. A browser capture is recorded as `browser` and a label
    is all the proxy knows, so refusing would make proxy-captured evidence
    unusable; and an unknown position is not a way round the gate, because a key
    that differs only in auth_state is a near miss and goes to a judge anyway.
    """
    actor = str(request["actor"] or "").strip()
    folded = actor.casefold()
    if folded in _UNRECORDED_ACTORS:
        return "unknown"
    if folded in ANON_ACTORS:
        return "anon"
    return roles.get(folded) or f"account:{folded}"


def _param_component(requests: Iterable[sqlite3.Row]) -> str:
    """The query parameter names the cited traffic carried, as one token.

    Names, never values: the value is the identifier that moved, and two
    attempts at one bug differ in the value. Request bodies are not read -- they
    live on disk behind a hash and are not uniformly parseable -- so a
    body-parameter bug on a route that also takes query parameters lands on the
    same key as the query one and is referred to a judge, which is the safe
    direction for an approximation to be wrong in.
    """
    names: set[str] = set()
    for request in requests:
        query = str(_row_get(request, "query", "") or "")
        if not query:
            query = urlsplit(str(request["url"] or "")).query
        for name, _value in parse_qsl(query.lstrip("?"), keep_blank_values=True):
            cleaned = name.strip().casefold()
            if cleaned:
                names.add(cleaned)
    return ",".join(sorted(names)) or "-"


def _declared_surface(finding: Any) -> str:
    """The route the finding says it is about, normalized; "" when it names none."""
    endpoint = str(_field(finding, "endpoint") or "").strip()
    host = str(_field(finding, "host") or "").strip()
    if endpoint.lower().startswith(("http://", "https://")):
        parts = urlsplit(endpoint)
        return surface_shape(parts.hostname or host, parts.path or "/")
    if not endpoint or not host:
        return ""
    return surface_shape(host, endpoint)


def dedup_parts(store: Store, finding: Any) -> DedupKey:
    """Recompute the four key components. Raises `DedupUnavailable` if it cannot.

    `vuln_class` is the one component with no mechanical source -- nothing in a
    request log says what to call a bug -- so it is taken as written, with its
    separators normalized. The other three come off the traffic:

    * `path_shape` is the route the cited requests hit, with identifier-shaped
      segments collapsed. The finding's own `endpoint` only chooses between
      routes the traffic shows; an endpoint no cited request hit is refused,
      because a key built from a route the harness never requested would make
      two reports of one bug look like two bugs on the operator's say-so.
    * `param` is the query parameter names that traffic carried.
    * `auth_state` is the set of positions those requests were sent from, which
      is the privilege boundary the bug crosses. It is a set over every cited
      request on the route rather than whichever row is labelled `role=attack`,
      because the role column is model-written: deriving the key from it would
      let relabelling two evidence rows buy a second submission.
    """
    uid = _uid(finding)
    problems: list[str] = []

    vuln_class = "-".join(_class_tokens(_field(finding, "vuln_class")))
    if not vuln_class:
        problems.append(
            f"vuln_class is empty, and the class is one quarter of the key: "
            f"`bb finding set {uid} --class <e.g. idor>`."
        )

    linked = _linked_requests(store, finding)
    shapes = {rid: _request_surface(request) for rid, request in linked.items()}
    declared = _declared_surface(finding)
    chosen: str | None = None
    if not linked:
        problems.append(
            f"no cited request resolves to a row in the requests table, so the route, the "
            f"parameters and the position it was attacked from cannot be read off the traffic: "
            f"`bb evidence add {uid} request --request-id <id> --role attack`."
        )
    elif declared and declared in set(shapes.values()):
        chosen = declared
    elif declared:
        seen = ", ".join(sorted(set(shapes.values())))
        problems.append(
            f"the recorded endpoint normalizes to {declared!r}, which none of the cited "
            f"requests hit ({seen}), so which route this finding is about is unresolved: "
            f"`bb finding set {uid} --endpoint <the path the cited request used>`."
        )
    else:
        candidates = sorted(set(shapes.values()))
        if len(candidates) == 1:
            chosen = candidates[0]
        else:
            problems.append(
                f"the finding names no route -- that needs both a host and an endpoint -- and "
                f"the cited requests hit {len(candidates)} of them ({', '.join(candidates)}), "
                f"so which one this finding is about would be a guess: `bb finding set {uid} "
                f"--host <host> --endpoint <path>`."
            )
    if problems:
        raise DedupUnavailable(uid, problems)

    on_route = sorted(
        (linked[rid] for rid, shape in shapes.items() if shape == chosen),
        key=lambda row: int(row["id"]),
    )
    roles = _account_roles(store)
    positions = tuple((int(row["id"]), _actor_position(row, roles)) for row in on_route)
    return DedupKey(
        vuln_class=vuln_class,
        path_shape=str(chosen),
        param=_param_component(on_route),
        auth_state="+".join(sorted({position for _rid, position in positions})),
        request_ids=tuple(int(row["id"]) for row in on_route),
        auth_sources=positions,
    )


def dedup_key(store: Store, finding: Any) -> str:
    """sha256(class|path_shape|param|auth_state), recomputed from the record.

    Takes the store as well as the finding because three of the four components
    are read off the requests the finding cites; a key computed from the finding
    row alone would be a key the model chose.
    """
    return dedup_parts(store, finding).digest


def refresh_dedup_key(store: Store, finding_ref: str | int) -> str:
    """Write the computed key into `findings.dedup_key` and return it.

    No gate reads that column any more. Refreshing it turns it into a cache of
    the harness's own answer, so the `--dedup-key` queries the phase prompts
    teach keep working and a human comparing the two sees one number.
    """
    row = store.get_finding(finding_ref)
    if row is None:
        raise TriageError(f"no such finding: {finding_ref!r}. List them: `bb finding list`")
    digest = dedup_key(store, row)
    if str(row["dedup_key"] or "") != digest:
        store.update_finding(row["id"], dedup_key=digest)
    return digest


# ---- how near is near ------------------------------------------------------


def _near_class(mine: str, theirs: str) -> tuple[bool, str]:
    """Two class labels are near when they could be two names for one bug."""
    if _class_hits(mine, (theirs,)) or _class_hits(theirs, (mine,)):
        return True, f"{mine!r} and {theirs!r} are one label inside the other"
    for family in (
        ACCESS_CONTROL_CLASSES,
        AUTH_CLASSES,
        DIFFERENTIAL_CLASSES,
        BUSINESS_LOGIC_CLASSES,
    ):
        if _class_hits(mine, family) and _class_hits(theirs, family):
            return True, f"{mine!r} and {theirs!r} name the same class family"
    return False, f"{mine!r} and {theirs!r} are unrelated classes"


def _segments_within_one(left: list[str], right: list[str]) -> bool:
    """True when one segment list becomes the other by a single edit."""
    if len(left) == len(right):
        return sum(1 for a, b in zip(left, right) if a != b) == 1
    if abs(len(left) - len(right)) != 1:
        return False
    longer, shorter = (left, right) if len(left) > len(right) else (right, left)
    return any(
        longer[:drop] + longer[drop + 1 :] == shorter for drop in range(len(longer))
    )


def _near_path(mine: str, theirs: str) -> tuple[bool, str]:
    """Routes are near when they differ by one segment: one handler, mounted twice."""
    my_host, _, my_path = mine.partition("/")
    their_host, _, their_path = theirs.partition("/")
    if my_host != their_host:
        return False, f"different hosts ({my_host} and {their_host})"
    if _segments_within_one(my_path.split("/"), their_path.split("/")):
        return True, (
            f"/{my_path} and /{their_path} differ by one path segment, which is what one "
            f"handler reached two ways looks like"
        )
    return False, f"/{my_path} and /{their_path} differ by more than one path segment"


def _near_param(mine: str, theirs: str) -> tuple[bool, str]:
    """Parameter sets are near when they overlap, or when one side is empty.

    The empty side is the fragile case: it means the cited traffic carried no
    query parameter at all, which also happens when a finding simply cites one
    request fewer. That must not be the difference that buys a submission.
    """
    my_set = {name for name in mine.split(",") if name and name != "-"}
    their_set = {name for name in theirs.split(",") if name and name != "-"}
    if not my_set or not their_set:
        return True, "one side's cited traffic carried no query parameter to compare"
    shared = my_set & their_set
    if shared:
        return True, f"both carry {', '.join(sorted(shared))}"
    return False, f"no parameter is shared ({mine} against {theirs})"


def _near_auth(mine: str, theirs: str) -> tuple[bool, str]:
    """Always near.

    The positions come from which requests happen to be cited, so one finding
    that cites a baseline its twin left out gets a different auth_state for the
    same bug. Letting that difference alone stand for "distinct" is exactly how
    one bug ships twice, so it goes to a judge instead.
    """
    return True, f"the same class, route and parameter from {mine} and from {theirs}"


_NEAR_CHECKS: dict[str, Callable[[str, str], tuple[bool, str]]] = {
    "vuln_class": _near_class,
    "path_shape": _near_path,
    "param": _near_param,
    "auth_state": _near_auth,
}


def compare_keys(left: DedupKey, right: DedupKey) -> tuple[str, str]:
    """(relation, why) for two computed keys: same_key | near_miss | distinct.

    A pair is ambiguous when the keys match, or when they differ in exactly one
    component and that one difference is itself small. Two or more differences
    are two different bugs: a judge asked about every pair of findings is a
    judge whose verdicts nobody reads, and the near-miss rules below are chosen
    so that the places where the computation is fragile -- a relabelled class, a
    route reached two ways, a missing parameter, a position that depends on
    which requests were cited -- are the places that still get referred.
    """
    differing = [name for name in DEDUP_KEY_FIELDS if getattr(left, name) != getattr(right, name)]
    if not differing:
        return "same_key", (
            f"the same computed key: class {left.vuln_class}, route {left.path_shape}, "
            f"parameter {left.param}, position {left.auth_state}"
        )
    if len(differing) > 1:
        return "distinct", f"the keys differ in {', '.join(differing)}: more than one component"
    name = differing[0]
    near, why = _NEAR_CHECKS[name](getattr(left, name), getattr(right, name))
    return ("near_miss" if near else "distinct"), f"{name} differs -- {why}"


# ---- reviewing one finding against the rest --------------------------------


@dataclass(frozen=True)
class DedupePair:
    """One ambiguous pair, with whatever has been recorded about it."""

    uid: str
    other_uid: str
    other_state: str
    relation: str  # same_key | near_miss
    why: str
    key: DedupKey
    other_key: DedupKey
    verdict: str | None = None  # duplicate | distinct | undetermined
    reason: str = ""
    source: str = ""  # judge | operator
    recorded_by: str = ""  # the gate row the verdict was read from

    @property
    def cleared(self) -> bool:
        return self.verdict == CLEARING_VERDICT

    def as_dict(self) -> dict[str, Any]:
        return {
            "other_uid": self.other_uid,
            "other_state": self.other_state,
            "relation": self.relation,
            "why": self.why,
            "other_key": self.other_key.digest,
            "verdict": self.verdict,
            "reason": self.reason,
            "source": self.source,
            "recorded_by": self.recorded_by,
        }


@dataclass(frozen=True)
class DedupeReview:
    """What the harness computes about one finding's uniqueness, right now."""

    uid: str
    key: DedupKey
    stored_key: str
    pairs: tuple[DedupePair, ...]
    not_compared: tuple[tuple[str, str], ...]  # (uid, why) for keys that would not compute

    @property
    def stored_disagrees(self) -> bool:
        return bool(self.stored_key) and self.stored_key.casefold() != self.key.digest

    @property
    def duplicates(self) -> tuple[DedupePair, ...]:
        return tuple(pair for pair in self.pairs if pair.verdict == "duplicate")

    @property
    def unresolved(self) -> tuple[DedupePair, ...]:
        """Pairs nothing has decided: no verdict, or a judge that could not decide."""
        return tuple(
            pair for pair in self.pairs if pair.verdict in (None, "undetermined")
        )

    @property
    def cleared(self) -> tuple[DedupePair, ...]:
        return tuple(pair for pair in self.pairs if pair.cleared)

    def as_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "computed_key": self.key.as_dict(),
            "stored_dedup_key": self.stored_key or None,
            "stored_key_disagrees": self.stored_disagrees,
            "pairs": [pair.as_dict() for pair in self.pairs],
            "not_compared": [{"uid": uid, "why": why} for uid, why in self.not_compared],
        }


def _dedupe_payload(detail: Any) -> dict[str, Any] | None:
    """The `dedupe` block of a gate row's detail, or None when there is not one.

    A row whose detail is not the JSON this module writes clears nothing. The
    catch is narrow by type and does not continue past a problem: an unreadable
    row is treated as no adjudication at all, which leaves the pair unresolved
    and the gate failing.
    """
    if not isinstance(detail, str) or "dedupe" not in detail:
        return None
    try:
        parsed = json.loads(detail)
    except ValueError:
        return None
    block = parsed.get("dedupe") if isinstance(parsed, dict) else None
    return block if isinstance(block, dict) else None


def _recorded_verdicts(store: Store, finding: Any) -> dict[tuple[str, str, str], dict[str, str]]:
    """Adjudications recorded on this finding, keyed by (other uid, both keys).

    Both keys are pinned into the row, and a row only counts while both findings
    still hash to the same thing. An adjudication is a statement about two
    findings as they stood: edit either one -- add a citation, change the class,
    point it at another route -- and the statement lapses instead of carrying a
    stale `distinct` forward into a comparison nobody made.
    """
    uid = _uid(finding)
    out: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in store.gates_for(_ref(finding)):
        gate = str(row["gate"] or "")
        if gate not in DEDUPE_GATES:
            continue
        payload = _dedupe_payload(row["detail"])
        if payload is None:
            continue
        verdict = str(payload.get("verdict") or "")
        other_uid = str(payload.get("other_uid") or "")
        self_key = str(payload.get("self_key") or "")
        other_key = str(payload.get("other_key") or "")
        if verdict not in DEDUPE_VERDICTS or not (other_uid and self_key and other_key):
            continue
        if str(payload.get("self_uid") or "") != uid:
            continue  # a row written about the other side of the pair
        # Rows arrive oldest first, so a later adjudication of the same pair
        # supersedes an earlier one.
        out[(other_uid, self_key, other_key)] = {
            "verdict": verdict,
            "reason": str(payload.get("reason") or ""),
            "source": str(payload.get("source") or ""),
            "recorded_by": gate,
        }
    return out


def _standing_dedupe_failures(store: Store, finding: Any, other_uid: str) -> set[str]:
    """Dedupe gate names whose last word on this pair was a failure.

    `report.render` warns on the latest row per gate name, so a pair resolved
    under one name -- an operator override, a merge -- would leave the report
    saying the finding should not be submitted because of a judge's older
    `undetermined`. A false alarm in a tool whose job is to stop over-claiming
    teaches a reader to skim the warnings, so a resolving decision is also
    written under the name of the decision it replaces.
    """
    latest: dict[str, str] = {}
    uid = _uid(finding)
    for row in store.gates_for(_ref(finding)):
        gate = str(row["gate"] or "")
        if gate not in DEDUPE_GATES:
            continue
        payload = _dedupe_payload(row["detail"])
        if payload is None or str(payload.get("other_uid") or "") != other_uid:
            continue
        if str(payload.get("self_uid") or "") != uid:
            continue
        latest[gate] = str(row["verdict"] or "")
    return {gate for gate, verdict in latest.items() if verdict != "pass"}


def _as_row(store: Store, finding: Any, *, what: str = "finding") -> Any:
    if isinstance(finding, (str, int)):
        row = store.get_finding(finding)
        if row is None:
            raise TriageError(
                f"no such {what}: {finding!r}. List them: `bb finding list`"
            )
        return row
    return finding


def review_duplicates(store: Store, finding: Any) -> DedupeReview:
    """Compare one finding against every other live finding by computed key.

    A finding whose own key will not compute is not compared and is listed in
    `not_compared` instead. That is not a hole: a finding the harness cannot key
    fails `gate_not_duplicate` itself, so it cannot reach a report, and whichever
    of an ambiguous pair is gated second is the one that gets stopped. Blocking
    the complete finding on the incomplete one would park good work behind a
    candidate nobody is going to finish.
    """
    finding = _as_row(store, finding)
    key = dedup_parts(store, finding)
    uid = _uid(finding)
    mine = _field(finding, "id")
    verdicts = _recorded_verdicts(store, finding)
    pairs: list[DedupePair] = []
    skipped: list[tuple[str, str]] = []
    for row in store.list_findings():
        if row["id"] == mine or row["state"] in TERMINAL_STATES:
            continue
        try:
            other = dedup_parts(store, row)
        except DedupUnavailable as exc:
            skipped.append((str(row["uid"]), " ".join(exc.problems)))
            continue
        relation, why = compare_keys(key, other)
        if relation == "distinct":
            continue
        recorded = verdicts.get((str(row["uid"]), key.digest, other.digest), {})
        pairs.append(
            DedupePair(
                uid=uid,
                other_uid=str(row["uid"]),
                other_state=str(row["state"]),
                relation=relation,
                why=why,
                key=key,
                other_key=other,
                verdict=recorded.get("verdict"),
                reason=recorded.get("reason", ""),
                source=recorded.get("source", ""),
                recorded_by=recorded.get("recorded_by", ""),
            )
        )
    return DedupeReview(
        uid=uid,
        key=key,
        stored_key=str(_field(finding, "dedup_key") or "").strip(),
        pairs=tuple(pairs),
        not_compared=tuple(skipped),
    )


# ---- recording a verdict ---------------------------------------------------


@dataclass(frozen=True)
class DedupeRecord:
    """One adjudication, as it was written to both findings' gate ledgers."""

    uid: str
    other_uid: str
    verdict: str
    reason: str
    source: str
    gate: str
    relation: str
    key: str
    other_key: str
    rows: tuple[int, int]


def _reason_problem(reason: Any, *, what: str) -> str | None:
    text = str(reason or "").strip()
    if len(text) < DEDUPE_MIN_REASON_CHARS or _STUB_REASON_RE.match(text):
        return (
            f"{what} needs a reason at least {DEDUPE_MIN_REASON_CHARS} characters long that "
            f"someone can disagree with, and {text!r} is not one"
        )
    return None


def record_dedupe_verdict(
    store: Store,
    finding_ref: str | int,
    other_ref: str | int,
    verdict: str,
    *,
    reason: str,
    source: str = "judge",
) -> DedupeRecord:
    """Record a tri-state verdict about one ambiguous pair, on both findings.

    Refuses a pair the harness does not compute as ambiguous. A verdict is a
    judgement about a collision; accepting one for a pair that does not collide
    would let `distinct` be filed in advance against a key a finding does not
    have yet, and then quietly apply once it did.

    The row is written on both findings so each one's own ledger -- which is
    what the report prints -- carries the decision. The verdict and both keys go
    in the detail; only `distinct` is stored with a passing verdict, because it
    is the only answer that lets a finding through.
    """
    problems: list[str] = []
    if verdict not in DEDUPE_VERDICTS:
        problems.append(
            f"verdict must be one of {', '.join(DEDUPE_VERDICTS)}, not {verdict!r}; a judge "
            f"that cannot decide answers 'undetermined', never 'distinct'"
        )
    if source not in DEDUPE_SOURCES:
        problems.append(f"source must be one of {', '.join(DEDUPE_SOURCES)}, not {source!r}")
    if verdict in ("duplicate", CLEARING_VERDICT):
        problem = _reason_problem(reason, what=f"a {verdict!r} verdict")
        if problem:
            problems.append(problem)
    mine = _as_row(store, finding_ref)
    other = _as_row(store, other_ref)
    if _field(mine, "id") == _field(other, "id"):
        problems.append(f"{_uid(mine)} cannot be adjudicated against itself")
    if problems:
        raise TriageError(
            "refusing to record a dedupe verdict: "
            + " ".join(problems)
            + f"\n  bb finding dedupe {_uid(mine)} --against {_uid(other)} "
            f"--verdict {'|'.join(DEDUPE_VERDICTS)} --because '<what makes them one bug, or two>'"
        )

    key = dedup_parts(store, mine)
    other_key = dedup_parts(store, other)
    relation, why = compare_keys(key, other_key)
    if relation == "distinct":
        raise TriageError(
            f"refusing to record a verdict about {_uid(mine)} and {_uid(other)}: the harness "
            f"computes no collision and no near miss between them ({why}), so there is nothing "
            f"to adjudicate and a recorded verdict would apply to a pair nobody compared. If "
            f"they really are one bug despite that, say so in the merge:\n"
            f"  bb finding merge {_uid(mine)} --into {_uid(other)} --reason '<the shared cause>'"
        )

    text = str(reason or "").strip()
    # An operator clearing a pair by hand is the one row a human reading the
    # report must not mistake for a judge's verdict.
    gate = (
        DEDUPE_OVERRIDE_GATE
        if source == "operator" and verdict == CLEARING_VERDICT
        else DEDUPE_VERDICT_GATE
    )
    row_verdict = "pass" if verdict == CLEARING_VERDICT else "fail"
    rows: list[int] = []
    for me, them, my_key, their_key in (
        (mine, other, key, other_key),
        (other, mine, other_key, key),
    ):
        payload = {
            "verdict": verdict,
            "self_uid": _uid(me),
            "other_uid": _uid(them),
            "self_key": my_key.digest,
            "other_key": their_key.digest,
            "relation": relation,
            "why": why,
            "reason": text,
            "source": source,
        }
        stale = (
            _standing_dedupe_failures(store, me, _uid(them)) - {gate}
            if row_verdict == "pass"
            else set()
        )
        rows.append(
            store.record_gate(
                _field(me, "id"),
                gate,
                row_verdict,
                f"{verdict}: {_uid(me)} against {_uid(them)} ({relation}, {why}) -- "
                f"{source}: {text or 'no reason recorded'}",
                {"dedupe": payload},
            )
        )
        for name in sorted(stale):
            store.record_gate(
                _field(me, "id"),
                name,
                "pass",
                f"superseded by the {gate} row: {verdict} against {_uid(them)} -- "
                f"{source}: {text or 'no reason recorded'}",
                {"dedupe": {**payload, "superseded": gate}},
            )
    return DedupeRecord(
        uid=_uid(mine),
        other_uid=_uid(other),
        verdict=verdict,
        reason=text,
        source=source,
        gate=gate,
        relation=relation,
        key=key.digest,
        other_key=other_key.digest,
        rows=(rows[0], rows[1]),
    )


def _judge_verdict(judge: Callable[[DedupePair], Any], pair: DedupePair) -> tuple[str, str]:
    """Read a judge's answer, resolving anything unusable to `undetermined`.

    A judge is arbitrary caller code -- in practice a model behind a prompt --
    so every way it can fail to answer is mapped to the strictest verdict:
    raising, returning something that is not a verdict, returning a verdict this
    module does not know, or answering `duplicate`/`distinct` with no reason
    anyone could argue with. None of them resolves to `distinct`.
    """
    try:
        answer = judge(pair)
    except Exception as exc:  # noqa: BLE001 -- see the docstring: this is not log-and-continue
        # The pair stays unresolved and the gate keeps failing; nothing is
        # swallowed. Exceptions that are not about the judge's own answer --
        # KeyboardInterrupt, SystemExit -- are not Exceptions and still abort.
        return "undetermined", f"the judge raised {type(exc).__name__}: {exc}"

    verdict: Any = ""
    reason: Any = ""
    if isinstance(answer, str):
        verdict = answer
    elif isinstance(answer, dict):
        verdict, reason = answer.get("verdict", ""), answer.get("reason", "")
    elif isinstance(answer, (tuple, list)) and len(answer) == 2:
        verdict, reason = answer
    else:
        return "undetermined", f"the judge returned {answer!r}, which is not a verdict"

    decided = str(verdict or "").strip().casefold()
    if decided not in DEDUPE_VERDICTS:
        return "undetermined", (
            f"the judge answered {str(verdict)!r}, which is not one of "
            f"{', '.join(DEDUPE_VERDICTS)}"
        )
    if decided != "undetermined":
        problem = _reason_problem(reason, what=f"a {decided!r} verdict")
        if problem:
            return "undetermined", f"the judge answered {decided!r} but {problem}"
    return decided, str(reason or "").strip()


def adjudicate_duplicates(
    store: Store,
    finding_ref: str | int,
    judge: Callable[[DedupePair], Any],
    *,
    source: str = "judge",
) -> list[DedupeRecord]:
    """Hand every unresolved ambiguous pair to `judge` and record what it says.

    Only ambiguous pairs are referred: a judge asked whether two unrelated
    findings are the same bug learns nothing and teaches the reader to skim.

    `_judge_verdict` is where the tri-state is enforced -- a judge that cannot
    decide is `undetermined`, never `distinct` -- because a rule about what
    happens when the judge fails cannot live in the judge's own prompt.
    """
    review = review_duplicates(store, finding_ref)
    records: list[DedupeRecord] = []
    for pair in review.unresolved:
        verdict, reason = _judge_verdict(judge, pair)
        records.append(
            record_dedupe_verdict(
                store, review.uid, pair.other_uid, verdict, reason=reason, source=source
            )
        )
    return records


def record_not_duplicate(
    store: Store,
    finding_ref: str | int,
    *,
    reason: str,
    against: str | int | None = None,
) -> list[DedupeRecord]:
    """`--not-duplicate-because`: an operator clears ambiguous pairs, on the record.

    Written as a `dedupe_override` gate row on both findings with the reason in
    the rationale, so a human reading the report sees a gate that was overridden
    by hand rather than a gate that passed.

    With no `against` it covers every pair the gate currently reports and no
    others. The pairs come from the harness's own comparison, so an override
    cannot be filed against a collision that does not exist yet, and each row
    pins the two keys it was written for, so it lapses if either finding changes.
    """
    review = review_duplicates(store, finding_ref)
    targets = [pair for pair in review.pairs if not pair.cleared]
    if against is not None:
        other = _as_row(store, against)
        wanted = _uid(other)
        targets = [pair for pair in targets if pair.other_uid == wanted]
        if not targets:
            raise TriageError(
                f"refusing to override: the harness computes no unresolved collision or near "
                f"miss between {review.uid} and {wanted}, so there is nothing to override and "
                f"the row would record a decision about a comparison nobody made. See what it "
                f"does compute:\n  bb finding dedupe {review.uid}"
            )
    if not targets:
        raise TriageError(
            f"refusing to override: {review.uid} has no unresolved duplicate question -- its "
            f"computed key {review.key.short} collides with nothing live -- so an override "
            f"would be a waiver for a gate that passes. Check with:\n"
            f"  bb finding dedupe {review.uid}"
        )
    return [
        record_dedupe_verdict(
            store,
            review.uid,
            pair.other_uid,
            CLEARING_VERDICT,
            reason=reason,
            source="operator",
        )
        for pair in targets
    ]


# ---- merging ---------------------------------------------------------------


@dataclass(frozen=True)
class MergeResult:
    """What `merge_findings` did, for the CLI to print and for a test to read."""

    duplicate_uid: str
    canonical_uid: str
    relation: str  # same_key | near_miss | distinct | unknown
    why: str
    duplicate_key: str
    canonical_key: str
    reason: str
    rows: tuple[int, int]
    key_written: bool
    notes: tuple[str, ...]


def merge_findings(
    store: Store, dup_ref: str | int, into_ref: str | int, *, reason: str
) -> MergeResult:
    """Collapse `dup_ref` into `into_ref`: one bug, one submission, one record.

    The duplicate moves to `duplicate` -- the terminal state that says which
    kind of dead it is -- and both findings get a `dedupe_merge` row naming the
    other and carrying the reason, so the survivor's report shows what was
    folded into it. The harness's own comparison of the two keys goes in the row
    whether or not it agrees: a merge the harness computes as `distinct` is
    allowed, because two endpoints with one root cause are one report and the
    harness cannot see a shared root cause, but it is recorded as resting on the
    operator's reason alone rather than on a collision.

    Each store call is its own transaction, so the order matters: the shared key
    and the ledger rows are written before the state moves, and a failure part
    way through leaves the duplicate live with the record of why it was going to
    be merged.
    """
    problems: list[str] = []
    dup = _as_row(store, dup_ref)
    canonical = _as_row(store, into_ref)
    dup_uid, canonical_uid = _uid(dup), _uid(canonical)

    if _field(dup, "id") == _field(canonical, "id"):
        problems.append(f"{dup_uid} cannot be merged into itself")
    problem = _reason_problem(reason, what="a merge")
    if problem:
        problems.append(problem)
    if str(_field(canonical, "state")) in TERMINAL_STATES:
        problems.append(
            f"the survivor {canonical_uid} is {_field(canonical, 'state')}, which is terminal, "
            f"so merging into it would bury both findings; pick a live survivor "
            f"(`bb finding list`)"
        )
    if str(_field(dup, "state")) == "duplicate":
        problems.append(
            f"{dup_uid} is already marked duplicate; merging it again would record a second "
            f"reason for the same decision (`bb finding show {dup_uid}`)"
        )
    if problems:
        raise TriageError(
            f"refusing to merge {dup_uid} into {canonical_uid}: "
            + " ".join(problems)
            + f"\n  bb finding merge {dup_uid} --into {canonical_uid} "
            f"--reason '<the root cause both reports share>'"
        )

    notes: list[str] = []
    # `advance` overwrites reject_reason and nothing else records the old one,
    # so a finding that was rejected before being merged would lose why. Carry
    # it into the new reason instead of dropping it.
    prior = str(_field(dup, "reject_reason") or "").strip()
    if prior:
        notes.append(
            f"{dup_uid} already carried the reason {prior!r}, which is kept inside the merge "
            f"reason because advancing a finding overwrites it"
        )
    keys: dict[str, DedupKey | None] = {}
    for label, row in (("duplicate", dup), ("canonical", canonical)):
        try:
            keys[label] = dedup_parts(store, row)
        except DedupUnavailable as exc:
            keys[label] = None
            notes.append(f"no computable key for {_uid(row)}: {' '.join(exc.problems)}")
    dup_key, canonical_key = keys["duplicate"], keys["canonical"]
    if dup_key is not None and canonical_key is not None:
        relation, why = compare_keys(dup_key, canonical_key)
        if relation == "distinct":
            notes.append(
                "the harness computes these as two different bugs, so this merge rests on the "
                "reason given and not on a collision"
            )
    else:
        relation, why = "unknown", "at least one key could not be computed from the record"

    text = str(reason).strip()
    key_written = False
    if canonical_key is not None:
        # Both rows end up holding the harness's computed key for the survivor,
        # so the `WHERE dedup_key = ...` queries the dedupe prompt teaches find
        # the pair. It is a harness-computed value in a column no gate reads.
        for row in (dup, canonical):
            if str(_field(row, "dedup_key") or "") != canonical_key.digest:
                store.update_finding(_field(row, "id"), dedup_key=canonical_key.digest)
        key_written = True

    payload = {
        "verdict": "duplicate",
        "relation": relation,
        "why": why,
        "reason": text,
        "source": "operator",
        "merged": {"duplicate": dup_uid, "canonical": canonical_uid},
        "notes": notes,
    }
    dup_row_id = store.record_gate(
        _field(dup, "id"),
        DEDUPE_MERGE_GATE,
        "fail",
        f"merged into {canonical_uid} as a duplicate ({relation}, {why}) -- {text}",
        {
            "dedupe": {
                **payload,
                "self_uid": dup_uid,
                "other_uid": canonical_uid,
                "self_key": dup_key.digest if dup_key else "",
                "other_key": canonical_key.digest if canonical_key else "",
            }
        },
    )
    survivor_payload = {
        **payload,
        "self_uid": canonical_uid,
        "other_uid": dup_uid,
        "self_key": canonical_key.digest if canonical_key else "",
        "other_key": dup_key.digest if dup_key else "",
    }
    stale = _standing_dedupe_failures(store, canonical, dup_uid) - {DEDUPE_MERGE_GATE}
    canonical_row_id = store.record_gate(
        _field(canonical, "id"),
        DEDUPE_MERGE_GATE,
        "pass",
        f"{dup_uid} was merged into this finding as a duplicate ({relation}, {why}) -- {text}",
        {"dedupe": survivor_payload},
    )
    for name in sorted(stale):
        # The survivor's question is settled; see _standing_dedupe_failures.
        store.record_gate(
            _field(canonical, "id"),
            name,
            "pass",
            f"superseded by the {DEDUPE_MERGE_GATE} row: {dup_uid} was merged into this "
            f"finding -- {text}",
            {"dedupe": {**survivor_payload, "superseded": DEDUPE_MERGE_GATE}},
        )
    moved = f"duplicate of {canonical_uid}: {text}"
    store.advance(
        _field(dup, "id"),
        "duplicate",
        f"{moved} (earlier reason, kept: {prior})" if prior else moved,
    )
    return MergeResult(
        duplicate_uid=dup_uid,
        canonical_uid=canonical_uid,
        relation=relation,
        why=why,
        duplicate_key=dup_key.digest if dup_key else "",
        canonical_key=canonical_key.digest if canonical_key else "",
        reason=text,
        rows=(dup_row_id, canonical_row_id),
        key_written=key_written,
        notes=tuple(notes),
    )


# ---- class and identifier matching -----------------------------------------


def _class_tokens(value: str) -> tuple[str, ...]:
    """Split a class name on anything that is not a letter or a digit."""
    norm = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return tuple(token for token in norm.split("-") if token)


def _class_hits(vuln_class: str, triggers: Iterable[str]) -> str | None:
    """The first trigger whose tokens appear in sequence in the class, or None.

    Whole tokens, never substrings: "bac" must not match "callback-ssrf" and
    "auth" must not match "author", while "access-control" still has to match
    "improper-access-control".
    """
    tokens = _class_tokens(vuln_class)
    if not tokens:
        return None
    for trigger in triggers:
        want = _class_tokens(trigger)
        if not want or len(want) > len(tokens):
            continue
        for start in range(len(tokens) - len(want) + 1):
            if tokens[start : start + len(want)] == want:
                return trigger
    return None


def is_access_control_class(vuln_class: str) -> bool:
    """True when this class is one the ownership gate must police."""
    return _class_hits(vuln_class, ACCESS_CONTROL_CLASSES) is not None


@lru_cache(maxsize=512)
def _identifier_pattern(identifier: str) -> re.Pattern[str]:
    """Match an identifier only as a whole token, so "1" does not match "/v1/"."""
    left = r"(?<![A-Za-z0-9])" if _ASCII_ALNUM.match(identifier[:1] or " ") else ""
    right = r"(?![A-Za-z0-9])" if _ASCII_ALNUM.match(identifier[-1:] or " ") else ""
    return re.compile(left + re.escape(identifier) + right, re.I)


def _touches(identifier: str, request: sqlite3.Row) -> bool:
    ident = identifier.strip()
    if not ident:
        return False
    pattern = _identifier_pattern(ident)
    for column in ("url", "path", "query"):
        raw = request[column] or ""
        if not raw:
            continue
        if pattern.search(raw) or pattern.search(unquote(raw)):
            return True
    return False


def _mentions(identifier: str, text: Any) -> bool:
    """True when the text names this identifier as a whole token."""
    body = str(text or "")
    ident = str(identifier or "").strip()
    if not ident or not body:
        return False
    return bool(_identifier_pattern(ident).search(body))


def _clean_url(raw: str) -> str:
    return raw.rstrip(".,;:!?")


# ---- running the gates -----------------------------------------------------

GateCall = Callable[[Store, "Scope | None", Any], GateResult]

# The published gates do not share one signature (gate_in_scope reads the scope,
# the rest read the store), so the registry adapts them to a single call shape.
GATES: dict[str, GateCall] = {
    "gate_evidence_exists": lambda store, scope, f: gate_evidence_exists(store, f),
    "gate_has_request_proof": lambda store, scope, f: gate_has_request_proof(store, f),
    "gate_in_scope": lambda store, scope, f: gate_in_scope(scope, f, store),
    "gate_severity_floor": lambda store, scope, f: gate_severity_floor(store, f),
    "gate_repro_present": lambda store, scope, f: gate_repro_present(store, f),
    "gate_access_control_ownership": lambda store, scope, f: gate_access_control_ownership(store, f),
    "gate_not_duplicate": lambda store, scope, f: gate_not_duplicate(store, f),
    # v2: the checks that decide whether a human ever sees this.
    "gate_severity_derived": lambda store, scope, f: gate_severity_derived(store, f),
    "gate_counterevidence_recorded": (
        lambda store, scope, f: gate_counterevidence_recorded(store, f)
    ),
    # The scope reaches these two because a waiver is scoped to one engagement,
    # and the engagement the gate is running under beats bbh.waiver's fallback
    # to whichever engagement happens to be active.
    "gate_evidence_roles": lambda store, scope, f: gate_evidence_roles(store, f, scope),
    "gate_repro_cites_real_requests": (
        lambda store, scope, f: gate_repro_cites_real_requests(store, f, scope)
    ),
    "gate_prerequisites_reachable": lambda store, scope, f: gate_prerequisites_reachable(store, f),
    "gate_independent_verification": (
        lambda store, scope, f: gate_independent_verification(store, f, scope)
    ),
    "gate_frozen_claim_intact": lambda store, scope, f: gate_frozen_claim_intact(store, f),
}

# The seven the contract publishes, and what `gates=None` still runs, so a v1
# caller keeps v1 behaviour. Written out instead of derived from GATES: adding a
# gate to the registry must not silently change what an existing caller checks.
DEFAULT_GATES: tuple[str, ...] = (
    "gate_evidence_exists",
    "gate_has_request_proof",
    "gate_in_scope",
    "gate_severity_floor",
    "gate_repro_present",
    "gate_access_control_ownership",
    "gate_not_duplicate",
)

# What has to hold before `verified`: is this reachable by an attacker at all,
# and did a second look that could have disagreed agree. Ownership comes first
# because it produces the prerequisite row the next gate reads, and the frozen
# claim comes last because it is the question "was that agreement about this
# text" -- which only means anything once the agreement itself is established.
VERIFY_GATES: tuple[str, ...] = (
    "gate_access_control_ownership",
    "gate_prerequisites_reachable",
    "gate_independent_verification",
    "gate_frozen_claim_intact",
)

# The bar `store.advance` applies at `validated`, written as a gate so that the
# rungs above `validated` apply it too. The state machine asks once, on the way
# in; nothing asks again, and `apply_gates` can enter `gated` from `candidate`
# without passing through the rung at all. It is deliberately NOT in the set
# that guards `validated` itself: there the state machine is the authority and a
# gate would only say the same thing twice in one breath.
VALIDATED_BAR_GATES: tuple[str, ...] = ("gate_counterevidence_recorded",)

# Everything. This is the set that has to hold before a human reads a word of a
# report, and it contains VERIFY_GATES and VALIDATED_BAR_GATES on purpose:
# `apply_gates` can take a candidate straight to `gated`, so a check that only
# ran at a lower rung would be bypassed by skipping it.
SHIP_GATES: tuple[str, ...] = DEFAULT_GATES + tuple(
    gate
    for gate in (
        "gate_severity_derived",
        "gate_evidence_roles",
        "gate_repro_cites_real_requests",
        *VALIDATED_BAR_GATES,
        *VERIFY_GATES,
    )
    if gate not in DEFAULT_GATES
)

# Which gates guard which rung. Each set contains the ones below it, because a
# finding that skipped a rung must not escape the checks that rung carried --
# and above `validated`, that includes the bar the state machine applies rather
# than the gates.
GATES_FOR_STATE: dict[str, tuple[str, ...]] = {
    "validated": DEFAULT_GATES,
    "verified": tuple(dict.fromkeys(DEFAULT_GATES + VALIDATED_BAR_GATES + VERIFY_GATES)),
    "gated": SHIP_GATES,
    "ready": SHIP_GATES,
}


def gates_for_state(state: str) -> tuple[str, ...]:
    """The gates that guard a transition into `state`.

    Callers moving a finding up the ladder pass this to `apply_gates` together
    with `target_state`, rather than relying on the default, which stays the
    published seven.
    """
    try:
        return GATES_FOR_STATE[state]
    except KeyError:
        raise TriageError(
            f"triage guards no transition into {state!r}; the guarded rungs are "
            f"{', '.join(GATES_FOR_STATE)}. A candidate is an unchecked claim and the terminal "
            f"states are not reached by passing gates, so there is nothing to run for them."
        ) from None


def _resolve(gates: Iterable[str | GateCall] | None) -> list[tuple[str, GateCall]]:
    if gates is None:
        return [(name, GATES[name]) for name in DEFAULT_GATES]
    chosen: list[tuple[str, GateCall]] = []
    for item in gates:
        if isinstance(item, str):
            key = item if item.startswith("gate_") else "gate_" + item
            if key not in GATES:
                raise TriageError(
                    f"unknown gate {item!r}; known gates: {', '.join(DEFAULT_GATES)}"
                )
            chosen.append((key, GATES[key]))
            continue
        if not callable(item):
            raise TriageError(f"gates must be names or callables, got {type(item).__name__}")
        # A published gate passed by reference keeps its registry adapter, so
        # its own argument order still applies.
        label = getattr(item, "__name__", "")
        chosen.append((label, GATES[label]) if label in GATES else (label or "gate_custom", item))
    if not chosen:
        # An empty selection would let apply_gates pass a finding on zero checks.
        raise TriageError(
            f"no gates were selected, so nothing would be checked; pass gates=None for all of "
            f"them ({', '.join(DEFAULT_GATES)})"
        )
    return chosen


def run_gates(
    store: Store,
    scope: Scope | None,
    finding: Any,
    gates: Iterable[str | GateCall] | None = None,
) -> list[GateResult]:
    """Evaluate the gates against one finding, recording no verdict.

    The one write any gate performs is `gate_access_control_ownership` adding the
    prerequisite row its proof implies; see `_record_identifier_prerequisite` for
    why that belongs to the proof rather than to the caller. No verdict, state or
    gate row is touched here -- that is `apply_gates`.
    """
    if isinstance(finding, (str, int)):
        row = store.get_finding(finding)
        if row is None:
            raise TriageError(f"no such finding: {finding!r}. List them: `bb finding list`")
        finding = row
    return [call(store, scope, finding) for _name, call in _resolve(gates)]


def _state_rank(state: str) -> int:
    try:
        return LADDER.index(state)
    except ValueError:
        return len(LADDER)  # terminal or off-ladder: never advanced forward out of it


def apply_gates(
    store: Store,
    scope: Scope | None,
    finding_ref: str | int,
    gates: Iterable[str | GateCall] | None = None,
    *,
    target_state: str = "gated",
) -> bool:
    """Run every gate, record each verdict, and move the finding.

    True means every gate passed. `target_state` is the rung being guarded. To
    guard it with the checks that belong to it rather than with the published
    seven, pass `gates=gates_for_state(target_state)`.

    The move is a climb, one rung at a time, never a jump to `target_state`:
    `store.advance` carries requirements of its own and they are keyed on the
    rung being entered, so a finding that went straight from `candidate` to
    `gated` was asked for none of the ones `validated` and `verified` carry.
    Walking is what makes the store ask; the gates for `target_state` already
    contain every gate below it, so the rungs being walked are rungs the finding
    earned.

    The finding's current state is read only to decide where it may move to, and
    never to decide a verdict: state is what gates produce. A failure that could
    not finish its measurement parks the finding in `blocked` instead of
    rejecting it, because `rejected` is permanent and an unfinished measurement
    has not earned a permanent verdict.

    An unusable engagement raises instead of rejecting: rejection is permanent,
    and a stale attestation is the harness's problem, not the finding's. So
    does a rung whose own bar refuses -- see `_climb`.
    """
    if target_state not in LADDER:
        raise TriageError(
            f"target_state must be a rung on the ladder ({', '.join(LADDER)}), got "
            f"{target_state!r}; `rejected`, `duplicate` and `blocked` are not reached by "
            f"passing gates"
        )
    finding = store.get_finding(finding_ref)
    if finding is None:
        raise TriageError(f"no such finding: {finding_ref!r}. List them: `bb finding list`")
    if scope is None:
        raise TriageError(
            "gating needs a compiled scope and this call got none; refusing to judge a finding "
            "without one. Run: `bb scope compile <engagement>`"
        )
    auth_problem = scope.authorization_error()
    if auth_problem:
        raise TriageError(
            f"refusing to gate findings while the engagement is unusable: {auth_problem}"
        )

    results = run_gates(store, scope, finding, gates)
    for result in results:
        detail = result.detail
        if result.disposition:
            # The ledger should say why a finding was parked rather than binned,
            # since the two verdicts read identically as "fail" otherwise.
            detail = {
                **(detail or {}),
                "disposition": result.disposition,
                "unblock": result.unblock,
            }
        store.record_gate(finding["id"], result.name, result.verdict, result.rationale, detail)

    failures = [r for r in results if not r.passed]
    if failures:
        reason = "\n".join(f"[{r.name}] {r.rationale}" for r in failures)
        if all(r.blocked for r in failures):
            # Nothing here is a determined negative: every failure is a
            # measurement that could not be taken. Park it with what would clear
            # it, so a later run resumes the finding instead of re-deciding it.
            if finding["state"] not in TERMINAL_STATES:
                unblock = "; ".join(r.unblock for r in failures if r.unblock) or None
                store.advance(
                    finding["id"], "blocked", reason, unblock_condition=unblock
                )
            return False
        if finding["state"] != "rejected":
            store.advance(finding["id"], "rejected", reason)
        return False

    # A parked finding resumes from the rung it was parked at, which is the one
    # the store remembers; its `blocked` state is a siding, not a rung.
    standing = finding["state"]
    if standing == "blocked":
        standing = str(_row_get(finding, "blocked_from", "") or LADDER[0])
    if _state_rank(standing) < _state_rank(target_state):
        _climb(store, finding, standing, target_state)
    return True


def _climb(store: Store, finding: Any, standing: str, target_state: str) -> None:
    """Walk the ladder from `standing` up to `target_state`, a rung at a time.

    Each rung is its own `store.advance`, so each rung's own bar is applied.
    Jumping to `target_state` asked for the bar of that rung and no other, which
    is how a finding nobody had argued against reached `gated` -- the state
    `bb report` renders from -- without ever being asked for the counterevidence
    `validated` carries.

    A rung that refuses raises, and the finding is left on the last rung it
    earned. The refusal is not caught here because `store.advance` is the
    register this harness matches: it already names what is wrong and the exact
    command that fixes it, and turning that into a silent state change would
    replace a message an agent acts on with one it has to go looking for. In the
    normal path it cannot fire -- `VALIDATED_BAR_GATES` recomputes the same bar
    as a gate, which returns a verdict long before the climb starts -- so
    reaching it means the caller chose a gate set that does not guard the rungs
    it is climbing through.
    """
    ref = int(finding["id"])
    for rung in LADDER[_state_rank(standing) + 1 : _state_rank(target_state) + 1]:
        store.advance(ref, rung)
