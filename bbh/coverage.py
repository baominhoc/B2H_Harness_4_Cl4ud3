"""Coverage derived from runtime facts: what was never tried, not what was claimed.

The angle ledger records what an agent says it tried. Nothing before this module
computed what was never tried at all, and that difference is the harness's worst
failure mode. A class that was never routed -- the tool crashed, the phase ran
out of budget, the agent forgot -- reads downstream exactly like a class that was
tested and found clean. Every later run then reads the same ledger, sees no open
angle, and treats the ground as covered, so one tooling failure becomes a
permanent false negative.

Coverage here is therefore arithmetic over the request log, not over an agent's
account of its own work:

    remaining(cls) = eligible(cls) - tested(cls)

`eligible` comes from the `surfaces` table: a materialised view over `requests`
plus the recon handoff, one row per (host, path_shape, method), rebuilt wholesale
on every refresh so the cache cannot drift from the facts. `tested` needs a
settled angle row *and* recorded traffic on that surface, because a `ruled_out`
on ground the request log never touched is a claim rather than a result -- and it
is reported as one instead of being quietly counted.

Four decisions shape the rest, each of them the fail-closed direction:

- **The recon handoff may only add surfaces.** It is model-written, so a declared
  endpoint nobody ever requested makes coverage look worse, which is the honest
  reading. Nothing a model writes can mark ground covered, and a declared host
  outside the armed scope is dropped rather than listed as work.
- **Normalisation under-collapses.** An identifier the shaper does not recognise
  leaves one extra row, which is noise. A route wrongly merged into another shape
  vanishes from the inventory and reads as covered, which is a false negative.
- **An angle row's method credit can only narrow.** An angle names a route and no
  method, so it is credited to every eligible method variant of that route unless
  its technique slug names a method, in which case only that method is credited.
  Model-written text narrows credit and can never widen it.
- **An empty `eligible` set is not a clean sweep.** It means the class was never
  routed to anything, which is the exact confusion this module exists to end, so
  closing one takes a recorded reason in `coverage_reasons`.

The eligibility table is a routing hint, not a kill list: a class absent from it
is eligible on every surface, and nothing in it can mark a class impossible. The
narrowest thing it can say is "eligible nowhere here", which requires an
explanation rather than granting one.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence
from urllib.parse import parse_qsl, unquote, urlsplit

from . import paths
from .scope import Scope, ScopeError, host_from_url, normalize_host
from .store import Store, utcnow

# The class vocabulary the phase prompts teach. Held here so the coverage table
# has a fixed set of rows: a class missing from the report is indistinguishable
# from a class with nothing left to do, which is the bug this module exists for.
CLASSES: tuple[str, ...] = (
    "idor", "bac", "auth-bypass", "authn", "session", "csrf", "xss", "sqli",
    "nosqli", "cmdi", "ssti", "xxe", "ssrf", "path-traversal", "file-upload",
    "open-redirect", "business-logic", "race", "info-disclosure", "misconfig",
    "subdomain-takeover", "crypto", "rce",
)

# Angle outcomes that close ground. `blocked` never reached the surface and
# `open_gap` names the test it did not get to, so neither settles anything.
# Taken from the store rather than restated, so the two cannot drift: a word
# that stops settling ground there has to stop counting here in the same commit.
SETTLED_OUTCOMES: tuple[str, ...] = tuple(Store.SETTLED_OUTCOMES)

# The recon phase whose handoff declares surfaces nobody has requested yet. The
# path is built here rather than imported from runner.handoff_path_for, because
# runner imports this module to append gaps to the next phase's prompt.
RECON_PHASE = "00-recon"

ID = "{id}"
DATE = "{date}"

# Methods that only read. Everything else -- including an unparseable one -- is
# treated as state-changing, so an unknown method widens eligibility rather than
# quietly excusing a surface from the classes that need a write.
READ_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

UNKNOWN_METHOD = "?"

# Request header names that mean a credential was sent. http.redact_headers
# hashes their values before storing them but keeps the names, so presence is
# recoverable from the recorded request while the secret is not. Deliberately
# not read from bbh.http: that module imports the `requests` package, and
# coverage has to work under the proxy's interpreter too.
CREDENTIAL_HEADERS: frozenset[str] = frozenset({"cookie", "authorization", "x-api-key"})

# Query parameter names that carry an object identifier, for surfaces whose ids
# live in the query rather than the path. Small and explicit: a broad suffix
# match would read "valid", "paid" and "void" as identifiers. `key` and `ref`
# are in because an object-store route addresses its object that way, and a
# name here only ever adds surfaces to look at.
ID_QUERY_KEYS: frozenset[str] = frozenset(
    {"id", "uid", "uuid", "guid", "userid", "docid", "objectid", "key", "ref"}
)

# Bounds. The handoff is untrusted content, and the gap lines go into a prompt.
MAX_DECLARED_SURFACES = 2000
MAX_SHAPE_CHARS = 300
MAX_PATH_SEGMENTS = 24
MAX_QUERY_KEYS = 20
MAX_GAP_LINES = 14
MAX_GAP_LINE_CHARS = 520
GAP_EXAMPLES = 3
TABLE_NOTE_CHARS = 88

# A reason shorter than this is a gesture. The bar is lower than the one for
# counterevidence because the honest reason is often one clause -- "no mapped
# surface accepts a file upload" -- but "n/a" still has to fail.
REASON_MIN_CHARS = 40

_STUB_REASON = re.compile(
    r"^(none|n/?a|nothing|no reason|not applicable|unknown|tbd|todo)\b", re.IGNORECASE
)

# Meta keys recording what the inventory was derived from, so a stale read is
# detectable rather than silently wrong.
DERIVED_AT_KEY = "coverage_derived_at"
DERIVED_THROUGH_KEY = "coverage_max_request_id"


class CoverageError(RuntimeError):
    """A coverage question that cannot be answered. The message names the fix."""


# ---- path shaping ----------------------------------------------------------
#
# Every decision below is a decision about what counts as the same surface, and
# each one is pinned by a test. Shaping is per segment and the order matters:
# the first rule that matches wins.

_DIGITS = re.compile(r"^[0-9]+$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# 12+ hex digits is an object id (ObjectId 24, sha1 40, sha256 64). Shorter runs
# are words -- "cafe", "decade", "added" -- and collapsing those would merge
# real routes.
_LONG_HEX = re.compile(r"^[0-9a-fA-F]{12,}$")
# A date, a month, or an ISO timestamp.
_DATE_LIKE = re.compile(
    r"^[0-9]{4}-[0-9]{2}(-[0-9]{2}([T _][0-9]{2}[:-][0-9]{2}([:-][0-9]{2})?Z?)?)?$"
)
# An id an agent or a spec already templated: {id}, :id, <id>, *.
_TEMPLATED = re.compile(r"^(\{[^/{}]*\}|:[A-Za-z_][A-Za-z0-9_-]*|<[^/<>]*>|\*+)$")
_TOKEN_CHARS = re.compile(r"^[A-Za-z0-9_-]+$")
_EXTENSION = re.compile(r"^[A-Za-z0-9]{1,8}$")

# Words inside a templated segment that mean a date rather than an object.
_DATE_WORDS: frozenset[str] = frozenset({"date", "day", "month", "year", "timestamp", "ts"})

# An opaque token -- a session id, a JWT segment, a ULID, a signed blob -- is at
# least this long before it is collapsed. Long enough that a route name does not
# reach it by accident.
TOKEN_MIN_CHARS = 20

# ...and carries at least this many digits. A route segment rarely carries two;
# a generated token almost always does. With the "not all lowercase" test below
# this keeps `this-is-a-very-long-route-name` and `getUserProfileV2Data` intact.
TOKEN_MIN_DIGITS = 2


def _is_opaque_token(segment: str) -> bool:
    if len(segment) < TOKEN_MIN_CHARS or not _TOKEN_CHARS.match(segment):
        return False
    if sum(c.isdigit() for c in segment) < TOKEN_MIN_DIGITS:
        return False
    # An all-lowercase segment is a slug until proven otherwise; leaving it
    # alone costs one row, merging it loses a route.
    return not segment.islower()


def _shape_segment(segment: str) -> str:
    """One path segment as a shape. Returns the segment unchanged when it is a name.

    Classification runs on the percent-decoded segment, because `%32` and `2`
    reach the same handler, but a segment that is not an identifier is returned
    as it was written: decoding the whole path would let a `%2F` restructure it
    and merge two genuinely different routes into one shape.
    """
    if not segment:
        return segment
    decoded = unquote(segment)
    if _TEMPLATED.match(decoded):
        inner = decoded.strip("{}<>:*").lower()
        return DATE if inner in _DATE_WORDS else ID
    if _DIGITS.match(decoded):
        return ID
    if _UUID.match(decoded):
        return ID
    if _DATE_LIKE.match(decoded):
        # A distinct placeholder, because a date is a range to query and not an
        # object to enumerate: `/reports/{date}` is the same document for every
        # tenant, so it must not make a surface look IDOR-eligible.
        return DATE
    if _LONG_HEX.match(decoded):
        return ID
    if _is_opaque_token(decoded):
        return ID
    if "." in decoded:
        stem, _, ext = decoded.rpartition(".")
        if stem and _EXTENSION.match(ext):
            shaped = _shape_segment(stem)
            # The extension stays: it selects the handler, and therefore which
            # classes can live there at all. `/files/{id}.pdf` is not
            # `/files/{id}.json`.
            if shaped in (ID, DATE):
                return f"{shaped}.{ext}"
    return segment


def path_shape(raw: str | None) -> str:
    """Normalise a URL path to the surface it belongs to.

    Numeric, uuid, long-hex and opaque-token segments become `{id}`; date-shaped
    segments become `{date}`; a file extension is kept. The result always starts
    with `/`, duplicate slashes collapse and a trailing slash is dropped, because
    a trailing slash is a routing detail rather than a different surface.
    """
    text = str(raw or "").strip()
    if "?" in text:
        text = text.split("?", 1)[0]
    if "#" in text:
        text = text.split("#", 1)[0]
    segments = [s for s in text.split("/") if s]
    truncated = len(segments) > MAX_PATH_SEGMENTS
    if truncated:
        segments = segments[:MAX_PATH_SEGMENTS]
    shaped = [_shape_segment(s) for s in segments]
    # A deeper or longer path keeps a marker rather than being folded into its
    # own prefix, so two different deep paths cannot become one row.
    out = "/" + "/".join(shaped)
    if truncated:
        out += "/..."
    if len(out) > MAX_SHAPE_CHARS:
        out = out[:MAX_SHAPE_CHARS] + "..."
    return out


def normalize_method(raw: str | None) -> str:
    """Uppercase the method. An empty one becomes `?` rather than a guess."""
    method = str(raw or "").strip().upper()
    return method if method else UNKNOWN_METHOD


def is_state_changing(method: str) -> bool:
    return normalize_method(method) not in READ_METHODS


def query_keys(raw: str | None) -> tuple[str, ...]:
    """Parameter names from a query string. Names only: a value can be a secret."""
    text = str(raw or "").strip().lstrip("?")
    if not text:
        return ()
    try:
        pairs = parse_qsl(text, keep_blank_values=True)
    except (ValueError, UnicodeDecodeError):
        # Crude split rather than nothing: returning () would say the surface
        # has no parameter, and a surface with no parameter is not eligible for
        # the classes that need one, so a parse failure would quietly excuse it.
        pairs = [(chunk.partition("=")[0], "") for chunk in text.split("&")]
    names = sorted({str(k).strip().lower() for k, _v in pairs if str(k).strip()})
    return tuple(names[:MAX_QUERY_KEYS])


def split_surface(raw: str | None) -> tuple[str, str] | None:
    """`host/path` (as the angle ledger spells it) -> (host, path_shape), or None.

    Accepts a bare host, a `host/path`, and a full URL, so an angle row written
    by any phase lands on the same surface the request log produced.
    """
    text = str(raw or "").strip()
    if not text:
        return None
    if "://" in text:
        parts = urlsplit(text)
        host = normalize_host(parts.hostname or "")
        return (host, path_shape(parts.path)) if host else None
    head, slash, tail = text.partition("/")
    host = normalize_host(head)
    if not host:
        return None
    # A bare host is the host's root surface and nothing more: "I tested the
    # host" is not a claim about forty routes under it.
    return host, path_shape(tail if slash else "")


# ---- the surface inventory -------------------------------------------------


@dataclass(frozen=True)
class Surface:
    """One row of the inventory: a shape the harness either touched or mapped."""

    host: str
    path_shape: str
    method: str
    observations: int = 0
    declared: bool = False
    authed: int = 0
    anon: int = 0
    query_keys: tuple[str, ...] = ()
    first_seen: str | None = None
    last_seen: str | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return self.host, self.path_shape, self.method

    @property
    def route(self) -> tuple[str, str]:
        return self.host, self.path_shape

    @property
    def observed(self) -> bool:
        """True when a recorded request actually landed here."""
        return self.observations > 0

    @property
    def angle_surface(self) -> str:
        """The surface string `bb angle add` takes for this row."""
        return f"{self.host}{self.path_shape}"

    @property
    def label(self) -> str:
        return f"{self.method} {self.angle_surface}"


@dataclass(frozen=True)
class Refresh:
    """What one rebuild of the inventory found, and what it could not see."""

    surfaces: int
    observed: int
    declared_only: int
    requests_folded: int
    # Reasons the inventory may be missing ground. Each line names what is
    # wrong, why it matters and the command that fixes it; they are blockers,
    # so coverage is never reported clean while one stands.
    problems: tuple[str, ...] = ()
    # Correct outcomes worth stating: declared endpoints dropped as out of
    # scope, for instance. Never a blocker.
    notes: tuple[str, ...] = ()


def engagement_of(store: Store) -> str | None:
    """The engagement a store belongs to, by its position in the tree, or None."""
    try:
        db = Path(store.path).resolve()
        root = paths.ENGAGEMENTS.resolve()
    except OSError:
        return None
    parent = db.parent
    if parent.parent != root:
        return None
    name = parent.name
    return name if db.name == paths.db_path(name).name else None


def _recon_handoff_path(engagement: str) -> Path:
    return paths.engagement_dir(engagement) / "handoff" / f"{RECON_PHASE}.json"


def _credentialled(raw_headers: Any) -> bool:
    """Did this recorded request carry a credential header?

    Read from the stored headers rather than from `requests.actor`, because the
    actor label is chosen by the agent while the headers are what was sent. A
    credential in a query parameter or a bespoke header is not detected, which
    is why `seen-authenticated-and-not` is a routing hint and not a proof.
    """
    if not raw_headers:
        return False
    try:
        headers = json.loads(raw_headers) if isinstance(raw_headers, str) else raw_headers
    except (json.JSONDecodeError, ValueError):
        return False
    if isinstance(headers, dict):
        names: Iterable[Any] = headers.keys()
    elif isinstance(headers, list):
        names = [pair[0] for pair in headers if isinstance(pair, (list, tuple)) and pair]
    else:
        return False
    return any(str(name).strip().lower() in CREDENTIAL_HEADERS for name in names)


@dataclass
class _Row:
    """Accumulator for one surface while the request log is folded."""

    host: str
    path_shape: str
    method: str
    observations: int = 0
    declared: bool = False
    authed: int = 0
    anon: int = 0
    keys: set[str] = field(default_factory=set)
    first_seen: str | None = None
    last_seen: str | None = None

    def saw(self, ts: str | None, *, authed: bool, keys: Iterable[str]) -> None:
        self.observations += 1
        if authed:
            self.authed += 1
        else:
            self.anon += 1
        self.keys.update(keys)
        if ts:
            if self.first_seen is None or ts < self.first_seen:
                self.first_seen = ts
            if self.last_seen is None or ts > self.last_seen:
                self.last_seen = ts

    def frozen(self) -> Surface:
        return Surface(
            host=self.host,
            path_shape=self.path_shape,
            method=self.method,
            observations=self.observations,
            declared=self.declared,
            authed=self.authed,
            anon=self.anon,
            query_keys=tuple(sorted(self.keys)[:MAX_QUERY_KEYS]),
            first_seen=self.first_seen,
            last_seen=self.last_seen,
        )


def _fold_requests(store: Store, rows: dict[tuple[str, str, str], _Row]) -> tuple[int, int]:
    """Fold every recorded request into `rows`. Returns (folded, max request id)."""
    folded = 0
    high = 0
    cursor = store.conn.execute(
        "SELECT id, ts, method, url, host, path, query, req_headers FROM requests ORDER BY id"
    )
    for row in cursor:
        high = max(high, int(row["id"] or 0))
        host = normalize_host(row["host"]) or host_from_url(row["url"] or "")
        if not host:
            # A row with no recoverable host cannot be placed on a surface. It
            # is still counted, so the gap line can say the inventory is short.
            continue
        path = row["path"]
        if not path and row["url"]:
            try:
                path = urlsplit(str(row["url"])).path
            except ValueError:
                path = None
        key = (host, path_shape(path), normalize_method(row["method"]))
        entry = rows.get(key)
        if entry is None:
            entry = rows[key] = _Row(*key)
        entry.saw(
            row["ts"],
            authed=_credentialled(row["req_headers"]),
            keys=query_keys(row["query"]),
        )
        folded += 1
    return folded, high


def _declared_endpoints(data: Any) -> list[tuple[str, str]]:
    """(url, method) pairs the recon handoff declares. Untrusted; shape only."""
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str]] = []
    for key in ("endpoints", "auth_surfaces"):
        for item in data.get(key) or ():
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip()
            if url:
                out.append((url, normalize_method(item.get("method") or "GET")))
    for item in data.get("hosts") or ():
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "").strip()
        if host:
            scheme = str(item.get("scheme") or "https").strip() or "https"
            out.append((f"{scheme}://{host}/", "GET"))
    return out


def _fold_declared(
    engagement: str | None,
    rows: dict[tuple[str, str, str], _Row],
) -> tuple[list[str], list[str]]:
    """Add the recon handoff's declared surfaces. Returns (problems, notes)."""
    if engagement is None:
        return (
            [
                "the surface inventory could not be matched to an engagement, so the recon "
                "handoff was not read and a route recon mapped but nobody requested is "
                "invisible here. Run coverage against a named engagement:\n"
                "  bb coverage --engagement <name>"
            ],
            [],
        )

    handoff = _recon_handoff_path(engagement)
    try:
        data = json.loads(handoff.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return (
            [
                f"{handoff} does not exist, so the inventory is only what has already been "
                "requested and a route recon mapped but never touched does not appear as "
                f"remaining work. Write it as {RECON_PHASE}'s last action, or re-run it:\n"
                f"  bb phase {RECON_PHASE} {engagement}"
            ],
            [],
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return (
            [
                f"{handoff} could not be read ({exc}), so declared surfaces are missing from "
                "the inventory and this coverage table understates what is left. Fix the "
                f"file, then:\n  bb coverage --engagement {engagement}"
            ],
            [],
        )

    try:
        scope: Scope | None = Scope.from_lock_file(paths.lock_path(engagement))
    except (ScopeError, OSError, json.JSONDecodeError, ValueError) as exc:
        return (
            [
                f"the scope lock for {engagement} is unusable ({exc}), so the handoff's "
                "declared endpoints could not be scope-checked and none were counted; "
                "listing an unscoped host as remaining work is how a hunt leaves its "
                "authorization. Rebuild it:\n"
                f"  bb scope compile {engagement} && bb arm {engagement} --as <you>"
            ],
            [],
        )

    problems: list[str] = []
    notes: list[str] = []
    declared = _declared_endpoints(data)
    if len(declared) > MAX_DECLARED_SURFACES:
        problems.append(
            f"{handoff} declares {len(declared)} endpoints; only the first "
            f"{MAX_DECLARED_SURFACES} were folded into the inventory, so this table is "
            "short of the rest. Split the engagement or trim the handoff:\n"
            f"  bb coverage --engagement {engagement}"
        )
        declared = declared[:MAX_DECLARED_SURFACES]

    out_of_scope = 0
    unparsed = 0
    added = 0
    for url, method in declared:
        host = host_from_url(url)
        if not host:
            unparsed += 1
            continue
        # A url_prefix scope rule matches on the path too, so the whole URL is
        # what gets decided, not just the host it resolved to.
        candidate = url if "://" in url else f"https://{url.lstrip('/')}"
        try:
            parts = urlsplit(candidate)
        except ValueError:
            unparsed += 1
            continue
        if not scope.decide(candidate):
            out_of_scope += 1
            continue
        key = (host, path_shape(parts.path), method)
        entry = rows.get(key)
        if entry is None:
            entry = rows[key] = _Row(*key)
        entry.declared = True
        entry.keys.update(query_keys(parts.query))
        added += 1

    if out_of_scope:
        notes.append(
            f"{out_of_scope} endpoint(s) the recon handoff declares are outside the armed "
            "scope and are not listed as surfaces"
        )
    if unparsed:
        notes.append(
            f"{unparsed} endpoint(s) in the recon handoff carry no usable URL and were skipped"
        )
    if added == 0 and declared:
        notes.append(
            f"none of the {len(declared)} endpoint(s) in {handoff.name} added a surface"
        )
    return problems, notes


def refresh(store: Store, engagement: str | None = None) -> Refresh:
    """Rebuild the `surfaces` table from the request log and the recon handoff.

    The table is deleted and rewritten in one transaction rather than amended.
    It is a cache of a derivation, and rewriting it wholesale is the only way it
    cannot drift from what it was derived from: a row that no longer derives from
    anything would otherwise sit there as a surface nobody can account for.
    """
    name = engagement or engagement_of(store)
    rows: dict[tuple[str, str, str], _Row] = {}
    folded, high = _fold_requests(store, rows)
    problems, notes = _fold_declared(name, rows)

    stamp = utcnow()
    surfaces = [entry.frozen() for entry in rows.values()]
    with store.tx() as conn:
        conn.execute("DELETE FROM surfaces")
        conn.executemany(
            "INSERT INTO surfaces(host, path_shape, method, observations, declared, "
            "authed, anon, query_keys, first_seen, last_seen, derived_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    s.host, s.path_shape, s.method, s.observations, int(s.declared),
                    s.authed, s.anon, ",".join(s.query_keys) or None,
                    s.first_seen, s.last_seen, stamp,
                )
                for s in surfaces
            ],
        )
        # Written with this connection inside this transaction: set_meta opens
        # its own, and sqlite has no nested transactions, so the stamp has to
        # land here or the table and its watermark could disagree.
        for key, value in ((DERIVED_AT_KEY, stamp), (DERIVED_THROUGH_KEY, str(high))):
            conn.execute(
                "INSERT INTO meta(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    observed = sum(1 for s in surfaces if s.observed)
    return Refresh(
        surfaces=len(surfaces),
        observed=observed,
        declared_only=len(surfaces) - observed,
        requests_folded=folded,
        problems=tuple(problems),
        notes=tuple(notes),
    )


def stale_reason(store: Store) -> str | None:
    """Why the stored inventory cannot be trusted right now, or None."""
    if store.get_meta(DERIVED_AT_KEY) is None:
        return (
            "the surface inventory has never been derived for this engagement, so there is "
            "nothing to subtract tested ground from"
        )
    try:
        through = int(str(store.get_meta(DERIVED_THROUGH_KEY)))
    except (TypeError, ValueError):
        return (
            "the surface inventory does not record which requests it was derived through, "
            "so it cannot be told apart from an empty one"
        )
    row = store.conn.execute("SELECT COALESCE(MAX(id), 0) AS high FROM requests").fetchone()
    high = int(row["high"])
    if high > through:
        return (
            f"{high - through} request(s) have been recorded since the surface inventory was "
            f"derived (through request {through}), so surfaces the hunt has already touched "
            "are missing from it"
        )
    return None


def load_surfaces(store: Store) -> tuple[Surface, ...]:
    """The stored inventory. Refuses a stale or never-derived one."""
    reason = stale_reason(store)
    if reason is not None:
        raise CoverageError(f"{reason}. Derive it:\n  bb coverage")
    rows = store.conn.execute(
        "SELECT host, path_shape, method, observations, declared, authed, anon, "
        "query_keys, first_seen, last_seen FROM surfaces ORDER BY host, path_shape, method"
    )
    return tuple(
        Surface(
            host=row["host"],
            path_shape=row["path_shape"],
            method=row["method"],
            observations=int(row["observations"]),
            declared=bool(row["declared"]),
            authed=int(row["authed"]),
            anon=int(row["anon"]),
            query_keys=tuple(k for k in str(row["query_keys"] or "").split(",") if k),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )
        for row in rows
    )


# ---- eligibility: one table a reader can audit -----------------------------


@dataclass(frozen=True)
class Predicate:
    """One mechanical fact about a surface, with the sentence that justifies it."""

    name: str
    why: str
    holds: Callable[[Surface], bool]


def _has_identifier(surface: Surface) -> bool:
    if ID in surface.path_shape:
        return True
    return any(
        key in ID_QUERY_KEYS or key.endswith(("_id", "-id")) for key in surface.query_keys
    )


HAS_IDENTIFIER = Predicate(
    "identifier-in-request",
    "an identifier in the path or query is the thing you swap for someone else's",
    _has_identifier,
)

BOTH_AUTH_STATES = Predicate(
    "seen-authenticated-and-not",
    "a bypass needs the surface recorded both with a credential and without, or there is "
    "no before and after to compare",
    lambda surface: surface.authed > 0 and surface.anon > 0,
)

STATE_CHANGING = Predicate(
    "state-changing-method",
    "the class turns on a request that changes something, so a read-only method is the "
    "wrong place to look first",
    lambda surface: is_state_changing(surface.method),
)

HAS_QUERY = Predicate(
    "parameter-in-query",
    "the payload needs a parameter to travel in",
    lambda surface: bool(surface.query_keys),
)


@dataclass(frozen=True)
class Eligibility:
    """Where one class could live. All predicates must hold."""

    requires: tuple[Predicate, ...]

    @property
    def why(self) -> str:
        return "; ".join(p.why for p in self.requires)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(p.name for p in self.requires)

    def holds(self, surface: Surface) -> bool:
        return all(p.holds(surface) for p in self.requires)


# The routing hint. A class absent from this table is eligible on every surface,
# which is why the table can only ever narrow where to look first and can never
# say a class is impossible: the narrowest thing it produces is an empty set,
# and an empty set demands a recorded reason rather than granting a clean sweep.
# Predicates are referenced as objects, so a typo here is an import-time error
# rather than a silently unsatisfiable rule.
ELIGIBILITY: dict[str, Eligibility] = {
    "idor": Eligibility((HAS_IDENTIFIER,)),
    "auth-bypass": Eligibility((BOTH_AUTH_STATES,)),
    "csrf": Eligibility((STATE_CHANGING,)),
    "race": Eligibility((STATE_CHANGING,)),
    "file-upload": Eligibility((STATE_CHANGING,)),
    "open-redirect": Eligibility((HAS_QUERY,)),
}


def normalize_class(raw: str | None) -> str:
    """Lowercase a class name and reduce separators to `-`."""
    return re.sub(r"[^a-z0-9]+", "-", str(raw or "").lower()).strip("-")


def eligibility_for(vuln_class: str) -> Eligibility | None:
    """The narrowing rule for a class, or None when it is eligible everywhere."""
    return ELIGIBILITY.get(normalize_class(vuln_class))


# ---- the angle ledger, read as evidence of what was tried ------------------

# HTTP methods an angle's technique slug may name. A technique that names one
# narrows the credit to that method; one that names none is credited to every
# eligible method variant of its route. Narrowing only, so a model-written slug
# can never widen what counts as tested.
_METHOD_TOKENS: frozenset[str] = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}
)


def _technique_methods(technique: str | None) -> frozenset[str]:
    tokens = {t.upper() for t in re.split(r"[^A-Za-z0-9]+", str(technique or "")) if t}
    return frozenset(tokens & _METHOD_TOKENS)


@dataclass(frozen=True)
class SettledAngle:
    """A settled angle row, resolved to the route and methods it can credit."""

    host: str
    path_shape: str
    vuln_class: str
    technique: str
    outcome: str
    methods: frozenset[str]

    @property
    def route(self) -> tuple[str, str]:
        return self.host, self.path_shape

    def credits(self, surface: Surface) -> bool:
        if surface.route != self.route:
            return False
        return not self.methods or surface.method in self.methods


def settled_angles(store: Store) -> tuple[tuple[SettledAngle, ...], tuple[str, ...]]:
    """Settled angle rows, and the surface strings that would not resolve.

    A row whose surface cannot be parsed credits nothing: it is reported instead,
    because silently dropping it would turn an unreadable ledger entry into
    covered ground.
    """
    resolved: list[SettledAngle] = []
    unresolved: list[str] = []
    for row in store.angles():
        if row["outcome"] not in SETTLED_OUTCOMES:
            continue
        where = split_surface(row["surface"])
        if where is None:
            unresolved.append(str(row["surface"]))
            continue
        host, shape = where
        resolved.append(
            SettledAngle(
                host=host,
                path_shape=shape,
                vuln_class=normalize_class(row["vuln_class"]),
                technique=str(row["technique"] or ""),
                outcome=row["outcome"],
                methods=_technique_methods(row["technique"]),
            )
        )
    return tuple(resolved), tuple(unresolved)


def ledger_classes(store: Store) -> frozenset[str]:
    """Every class this engagement has already named, from angles and findings.

    A class in the ledger is a class some phase routed, whatever the vocabulary
    says, so the coverage table has to have a row for it.
    """
    seen = {normalize_class(row["vuln_class"]) for row in store.angles()}
    seen.update(
        normalize_class(row["vuln_class"]) for row in store.list_findings()
    )
    return frozenset(c for c in seen if c)


# ---- recorded reasons ------------------------------------------------------


def reason_problem(text: str | None) -> str | None:
    """Why this reason does not explain anything, or None when it does."""
    body = str(text or "").strip()
    if not body:
        return "the reason is empty"
    if _STUB_REASON.match(body):
        return f"the reason begins with a non-answer ({body.split()[0]!r})"
    if len(body) < REASON_MIN_CHARS:
        return (
            f"the reason is {len(body)} characters; the bar is {REASON_MIN_CHARS}, because "
            "anything shorter names no mechanical fact a later phase can re-check"
        )
    return None


def record_reason(
    store: Store, vuln_class: str, reason: str, *, phase: str | None = None
) -> str:
    """Record why a class has no eligible surface. Returns the normalised class.

    This is the only way to close a class the inventory cannot route, so it
    refuses an unknown class name and a reason that argues nothing: both would
    leave a class reading as clean when nothing was tested.
    """
    cls = normalize_class(vuln_class)
    # Both problems in one round trip: a caller with a misspelled class and a
    # stub reason should not have to be told twice.
    problems: list[str] = []
    if not cls:
        problems.append(
            "no class is named, so nothing says which ground the reason accounts for"
        )
    elif cls not in set(CLASSES) | ledger_classes(store):
        problems.append(
            f"{cls!r} is not a known vulnerability class and does not appear in the angle "
            "ledger or the findings, so a reason for it accounts for ground no phase is "
            f"looking at. The vocabulary is: {', '.join(CLASSES)}"
        )
    problem = reason_problem(reason)
    if problem:
        problems.append(problem)
    if problems:
        detail = "\n".join(f"  - {text}" for text in problems)
        raise CoverageError(
            f"cannot record a coverage reason:\n{detail}\n"
            "An unexplained empty eligible set reads as 'the class was never routed', which "
            "is exactly what a later run must not mistake for 'the class was clean'. Retry "
            "with:\n"
            f"  bb coverage reason {cls or '<class>'} '<the mechanical fact: e.g. no mapped "
            "surface accepts a file upload, and recon found no upload form>'"
        )
    with store.tx() as conn:
        conn.execute(
            "INSERT INTO coverage_reasons(ts, vuln_class, reason, phase) VALUES (?,?,?,?) "
            "ON CONFLICT(vuln_class) DO UPDATE SET ts = excluded.ts, "
            "reason = excluded.reason, phase = COALESCE(excluded.phase, phase)",
            (utcnow(), cls, str(reason).strip(), phase),
        )
    return cls


def reasons(store: Store) -> dict[str, str]:
    """Recorded reasons, by normalised class."""
    return {
        normalize_class(row["vuln_class"]): row["reason"]
        for row in store.conn.execute(
            "SELECT vuln_class, reason FROM coverage_reasons ORDER BY vuln_class"
        )
    }


# ---- the coverage arithmetic -----------------------------------------------

# What a class's row in the table says. `explained` is the only way a class with
# no eligible surface counts as accounted for, and `unrouted` is the state this
# whole module exists to make visible.
STATUS_CLOSED = "closed"
STATUS_PARTIAL = "partial"
STATUS_UNTESTED = "untested"
STATUS_EXPLAINED = "explained"
STATUS_UNROUTED = "unrouted"

ACCOUNTED_FOR = (STATUS_CLOSED, STATUS_EXPLAINED)


@dataclass(frozen=True)
class Coverage:
    """A snapshot of the inventory and the ledger, for one pass of arithmetic."""

    surfaces: tuple[Surface, ...]
    angles: tuple[SettledAngle, ...]
    unresolved_angles: tuple[str, ...]
    reasons: dict[str, str]
    named: frozenset[str] = frozenset()

    def classes_in_play(self) -> tuple[str, ...]:
        return CLASSES + tuple(sorted(self.named - set(CLASSES)))

    def eligible(self, vuln_class: str) -> tuple[Surface, ...]:
        rule = eligibility_for(vuln_class)
        if rule is None:
            return self.surfaces
        return tuple(s for s in self.surfaces if rule.holds(s))

    def tested(self, vuln_class: str) -> tuple[Surface, ...]:
        cls = normalize_class(vuln_class)
        claims = [a for a in self.angles if a.vuln_class == cls]
        if not claims:
            return ()
        return tuple(
            surface
            for surface in self.eligible(cls)
            # Observed traffic is the corroboration: a settled angle on a
            # surface the request log never touched is a claim, not a result,
            # and `unsupported` reports it rather than counting it.
            if surface.observed and any(claim.credits(surface) for claim in claims)
        )

    def remaining(self, vuln_class: str) -> tuple[Surface, ...]:
        tested = {s.key for s in self.tested(vuln_class)}
        return tuple(s for s in self.eligible(vuln_class) if s.key not in tested)

    def unsupported(self, vuln_class: str | None = None) -> tuple[str, ...]:
        """Settled angles whose ground the request log has no traffic for."""
        observed = {s.route for s in self.surfaces if s.observed}
        wanted = normalize_class(vuln_class) if vuln_class else None
        out: list[str] = []
        for angle in self.angles:
            if wanted is not None and angle.vuln_class != wanted:
                continue
            if angle.route in observed:
                continue
            # The shape is a shape, so the remedy says to put a real value back
            # in rather than printing a URL that cannot be requested as written.
            swap = (
                "   # substitute a real value for the placeholder"
                if ID in angle.path_shape or DATE in angle.path_shape
                else ""
            )
            out.append(
                f"{angle.vuln_class}/{angle.technique} on "
                f"{angle.host}{angle.path_shape} is recorded as {angle.outcome}, but the "
                "request log holds no request to that surface, so nothing corroborates the "
                "result and it does not count as tested. Send the request and record the "
                "angle again:\n"
                f"  bb req GET 'https://{angle.host}{angle.path_shape}' --actor <label>{swap}"
            )
        return tuple(out)


def snapshot(store: Store) -> Coverage:
    """Load the inventory, the settled ledger and the recorded reasons."""
    angles, unresolved = settled_angles(store)
    return Coverage(
        surfaces=load_surfaces(store),
        angles=angles,
        unresolved_angles=unresolved,
        reasons=reasons(store),
        named=ledger_classes(store),
    )


def eligible(store: Store, vuln_class: str) -> tuple[Surface, ...]:
    """Surfaces where this class could live. Never empty for a lack of a rule."""
    return snapshot(store).eligible(vuln_class)


def tested(store: Store, vuln_class: str) -> tuple[Surface, ...]:
    """Eligible surfaces with a settled angle and recorded traffic to match."""
    return snapshot(store).tested(vuln_class)


def remaining(store: Store, vuln_class: str) -> tuple[Surface, ...]:
    """eligible - tested: the ground nothing has decided."""
    return snapshot(store).remaining(vuln_class)


# ---- the report ------------------------------------------------------------


@dataclass(frozen=True)
class ClassCoverage:
    """One row of the coverage table."""

    vuln_class: str
    status: str
    eligible: int
    tested: int
    requires: tuple[str, ...]
    why: str
    reason: str | None
    remaining_surfaces: tuple[Surface, ...]
    unsupported: tuple[str, ...]
    in_vocabulary: bool

    @property
    def remaining(self) -> int:
        return len(self.remaining_surfaces)

    @property
    def accounted_for(self) -> bool:
        return self.status in ACCOUNTED_FOR

    @property
    def examples(self) -> tuple[str, ...]:
        return tuple(s.label for s in self.remaining_surfaces[:GAP_EXAMPLES])


def class_coverage(cov: Coverage, vuln_class: str) -> ClassCoverage:
    """The arithmetic for one class against a loaded snapshot."""
    cls = normalize_class(vuln_class)
    rule = eligibility_for(cls)
    eligible_rows = cov.eligible(cls)
    tested_rows = cov.tested(cls)
    left = cov.remaining(cls)
    reason = cov.reasons.get(cls)

    if not eligible_rows:
        status = STATUS_EXPLAINED if reason else STATUS_UNROUTED
    elif left:
        status = STATUS_UNTESTED if not tested_rows else STATUS_PARTIAL
    else:
        status = STATUS_CLOSED

    return ClassCoverage(
        vuln_class=cls,
        status=status,
        eligible=len(eligible_rows),
        tested=len(tested_rows),
        requires=rule.names if rule else (),
        why=rule.why if rule else "eligible on every surface",
        reason=reason,
        remaining_surfaces=left,
        unsupported=cov.unsupported(cls),
        in_vocabulary=cls in CLASSES,
    )


TABLE_HEADERS: tuple[str, ...] = (
    "class", "eligible", "tested", "remaining", "status", "narrowed by", "note",
)


@dataclass(frozen=True)
class CoverageReport:
    """The coverage table, the gap lines, and the one-line verdict."""

    engagement: str | None
    phase: str | None
    surfaces: int
    observed: int
    declared_only: int
    hosts: int
    classes: tuple[ClassCoverage, ...]
    blockers: tuple[str, ...]
    notes: tuple[str, ...]
    unsupported: tuple[str, ...]
    gaps: tuple[str, ...]

    @property
    def closed(self) -> tuple[ClassCoverage, ...]:
        return tuple(c for c in self.classes if c.status == STATUS_CLOSED)

    @property
    def unrouted(self) -> tuple[ClassCoverage, ...]:
        return tuple(c for c in self.classes if c.status == STATUS_UNROUTED)

    @property
    def remaining_surfaces(self) -> int:
        """Distinct surfaces with at least one class left to test on them."""
        return len({s.key for c in self.classes for s in c.remaining_surfaces})

    @property
    def clean(self) -> bool:
        """Whether this hunt may be described as having swept its ground.

        False while anything is unaccounted for, including an inventory that
        could not be built completely: a class with no eligible surface and no
        recorded reason was never routed, and "never routed" is the one thing a
        clean sweep must never be allowed to mean.
        """
        if self.blockers or self.unsupported:
            return False
        return all(c.accounted_for for c in self.classes)

    @property
    def verdict(self) -> str:
        """The one line `bb status` shows."""
        accounted = sum(1 for c in self.classes if c.accounted_for)
        total = len(self.classes)
        if self.clean:
            return (
                f"coverage: {accounted}/{total} classes closed or explained across "
                f"{self.surfaces} surface(s); nothing is left untested (bb coverage)"
            )
        parts = [f"coverage: {accounted}/{total} classes closed or explained"]
        if self.remaining_surfaces:
            parts.append(f"{self.remaining_surfaces} of {self.surfaces} surface(s) untested")
        if self.unrouted:
            parts.append(f"{len(self.unrouted)} class(es) unrouted with no recorded reason")
        if self.unsupported:
            parts.append(f"{len(self.unsupported)} unsupported angle claim(s)")
        if self.blockers:
            parts.append(f"{len(self.blockers)} gap(s) in the inventory itself")
        return ", ".join(parts) + " -- not a clean sweep (bb coverage)"

    def table(self) -> list[tuple[str, ...]]:
        """Rows for the coverage table the 09-report phase renders."""
        rows: list[tuple[str, ...]] = []
        for row in self.classes:
            if row.status == STATUS_EXPLAINED:
                note = f"reason: {row.reason or ''}"
            elif row.status == STATUS_UNROUTED:
                note = "no eligible surface and no recorded reason: never routed"
            elif row.remaining_surfaces:
                note = ", ".join(row.examples)
            else:
                note = ""
            if not row.in_vocabulary:
                note = (note + "; " if note else "") + "not in the class vocabulary"
            rows.append(
                (
                    row.vuln_class,
                    str(row.eligible),
                    str(row.tested),
                    str(row.remaining),
                    row.status,
                    ",".join(row.requires) or "-",
                    # A sample, not the list: `bb coverage --class <cls>` prints
                    # every remaining surface, so the table stays readable.
                    _clip(note, TABLE_NOTE_CHARS),
                )
            )
        return rows


def _clip(text: str, limit: int) -> str:
    body = " ".join(str(text or "").split())
    return body if len(body) <= limit else body[: limit - 1].rstrip() + "…"


def _gap_lines(
    cov: Coverage,
    classes: Sequence[ClassCoverage],
    blockers: Sequence[str],
    phase: str | None,
) -> tuple[str, ...]:
    """The human-readable gap lines, worst first, bounded for a prompt.

    The order is what a prompt can afford to lose from the bottom: the ledger
    being wrong, then ground that needs an explanation, then the specific work
    the inventory can point at, then the broad classes that are eligible
    everywhere and say the same thing twenty times over.
    """
    lines: list[str] = list(blockers)

    for surface in cov.unresolved_angles:
        lines.append(
            f"the angle ledger holds a row for surface {surface!r}, which does not parse as "
            "a host or host/path, so it credits no coverage at all. Re-record it as "
            "host/path with ids templated:\n"
            "  bb angle add <host>/<path> <class> <technique> <outcome>"
        )

    lines.extend(cov.unsupported())

    unrouted = [c for c in classes if c.status == STATUS_UNROUTED]
    if unrouted and not cov.surfaces:
        # One empty inventory, not one line per class: every class is unrouted
        # for the same single reason, and that reason is the gap.
        lines.append(
            f"the surface inventory is empty, so all {len(unrouted)} class(es) are unrouted "
            "and this engagement has no recorded coverage of anything. Map and request "
            "something before any negative here means anything:\n"
            "  bb req GET https://<in-scope host>/ --actor anon"
        )
    else:
        for row in unrouted:
            lines.append(
                f"{row.vuln_class}: no surface in the inventory is eligible ({row.why}) and "
                "no reason is recorded, so this class reads as never routed rather than "
                "clean. Record why, or widen the surface map:\n"
                f"  bb coverage reason {row.vuln_class} '<the mechanical fact that rules it "
                "out here>'"
            )

    open_rows = [c for c in classes if c.status in (STATUS_UNTESTED, STATUS_PARTIAL)]
    # A class the eligibility table narrows is one the inventory can point at a
    # specific surface for; a class eligible everywhere cannot be, so naming
    # each of those separately is the same sentence repeated per class.
    named = [c for c in open_rows if c.status == STATUS_PARTIAL or c.requires]
    broad = [c for c in open_rows if c not in named]
    for row in sorted(named, key=lambda c: (c.status != STATUS_PARTIAL, -c.remaining)):
        lines.append(_untested_line(row))
    if broad:
        surfaces = len({s.key for c in broad for s in c.remaining_surfaces})
        examples = broad[0].examples[0] if broad[0].examples else ""
        lines.append(
            f"{len(broad)} class(es) have no settled angle anywhere and no narrowing rule, "
            f"so {surfaces} surface(s) read as covered while nothing was tried on them: "
            f"{', '.join(c.vuln_class for c in broad)} (e.g. {examples}). Walk them and "
            "record each cell:\n"
            f"  bb angle add {broad[0].remaining_surfaces[0].angle_surface} "
            f"{broad[0].vuln_class} <technique> ruled_out "
            "--control '<the defence you observed>'"
        )

    if phase and lines:
        lines.insert(
            0,
            f"coverage after {phase}: {len(lines)} gap(s) below are ground nothing has "
            "decided yet. They are not failures of this phase; they are what the next one "
            "must not read as covered.",
        )

    bounded = [_clip_line(line) for line in lines[:MAX_GAP_LINES]]
    dropped = len(lines) - len(bounded)
    if dropped > 0:
        bounded.append(f"...and {dropped} more coverage gap(s). Full table: bb coverage")
    return tuple(bounded)


def _untested_line(row: ClassCoverage) -> str:
    more = f" and {row.remaining - GAP_EXAMPLES} more" if row.remaining > GAP_EXAMPLES else ""
    if row.status == STATUS_PARTIAL:
        head = (
            f"{row.vuln_class}: {row.remaining} of {row.eligible} eligible surface(s) are "
            "still unsettled, so they read as covered while nothing was tried on them"
        )
    else:
        head = (
            f"{row.vuln_class}: none of the {row.eligible} eligible surface(s) has a settled "
            "angle, so the class reads as clean while it was never tested at all"
        )
    return (
        f"{head} ({'; '.join(row.examples)}{more}). Settle or park each:\n"
        f"  bb angle add {row.remaining_surfaces[0].angle_surface} {row.vuln_class} "
        "<technique> ruled_out --control '<the defence you observed>'"
    )


def _clip_line(line: str) -> str:
    """Clip a gap line without losing the command on its last line."""
    if len(line) <= MAX_GAP_LINE_CHARS:
        return line
    head, sep, tail = line.rpartition("\n")
    if sep and len(tail) < MAX_GAP_LINE_CHARS:
        return _clip(head, MAX_GAP_LINE_CHARS - len(tail) - 1) + "\n" + tail
    return _clip(line, MAX_GAP_LINE_CHARS)


def report(
    store: Store,
    *,
    engagement: str | None = None,
    phase: str | None = None,
    rebuild: bool = True,
) -> CoverageReport:
    """The coverage table, the gap lines and the verdict.

    Rebuilds the inventory first by default, because a coverage answer computed
    from a stale one is wrong in the dangerous direction: a surface the hunt has
    touched but the inventory has not seen is missing from `remaining`, and
    missing from `remaining` reads as covered.
    """
    blockers: list[str] = []
    notes: list[str] = []
    if rebuild:
        rebuilt = refresh(store, engagement)
        blockers.extend(rebuilt.problems)
        notes.extend(rebuilt.notes)

    cov = snapshot(store)
    classes = tuple(class_coverage(cov, cls) for cls in cov.classes_in_play())
    gaps = _gap_lines(cov, classes, blockers, phase)
    return CoverageReport(
        engagement=engagement or engagement_of(store),
        phase=phase,
        surfaces=len(cov.surfaces),
        observed=sum(1 for s in cov.surfaces if s.observed),
        declared_only=sum(1 for s in cov.surfaces if not s.observed),
        hosts=len({s.host for s in cov.surfaces}),
        classes=classes,
        blockers=tuple(blockers),
        notes=tuple(notes),
        unsupported=cov.unsupported(),
        gaps=gaps,
    )


def verdict(store: Store, *, engagement: str | None = None) -> str:
    """The one-line coverage verdict, for `bb status`.

    Rebuilds like `report` does. A status line computed from a stale inventory
    would be the one place a hunt could read as further along than it is.
    """
    return report(store, engagement=engagement).verdict


def class_report(
    store: Store,
    vuln_class: str,
    *,
    engagement: str | None = None,
    rebuild: bool = True,
) -> ClassCoverage:
    """What is left for one class. Refuses a class name nothing is looking at."""
    cls = normalize_class(vuln_class)
    if not cls:
        raise CoverageError(
            "name the class to report on, so the answer is about something:\n"
            f"  bb coverage --class <{'|'.join(CLASSES[:4])}|...>"
        )
    if rebuild:
        refresh(store, engagement)
    cov = snapshot(store)
    if cls not in cov.classes_in_play():
        raise CoverageError(
            f"{cls!r} is not a known vulnerability class and does not appear in the angle "
            "ledger. Reporting 'nothing left' for a misspelled class is how a class ends up "
            "looking covered, so check the spelling:\n"
            f"  {', '.join(CLASSES)}\n"
            f"  bb coverage --class <class>"
        )
    return class_coverage(cov, cls)


def handoff_gaps(
    store: Store, phase: str, *, engagement: str | None = None
) -> list[str]:
    """Coverage gap lines for `bb handoff write <phase>` and the next prompt.

    Same shape as `runner.validate_handoff`: human-readable lines, empty when
    there is nothing to say. These are not handoff problems and must not fail a
    phase -- a phase that ran out of budget still produced its work, and the
    point of the lines is that the *next* phase learns what was never tried
    rather than reading silence as coverage.

    The lines name hosts and path shapes derived from the request log, which is
    target-derived text, so a caller putting them in a prompt scrubs them
    (`untrusted.scrub`) the way the runner already scrubs validation problems.
    """
    key = str(phase or "").strip()
    if not key:
        raise CoverageError(
            "name the phase the gaps are being computed after, so the next prompt can say "
            "where they came from:\n  bb handoff write <phase>"
        )
    return list(report(store, engagement=engagement, phase=key).gaps)
