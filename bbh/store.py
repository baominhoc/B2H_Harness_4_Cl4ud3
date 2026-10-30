"""SQLite store: requests, evidence, findings, gates, angle ledger, run state.

Stdlib-only so the mitmproxy addon can write to it under a different
interpreter. WAL mode because the proxy, the HTTP client and the phase runner
all write concurrently.

The schema encodes the harness's central rule: a finding cannot reach a report
without evidence rows pointing at real artifacts on disk. Nothing here lets a
caller mark something proven by assertion alone.

The shape is versioned. `SCHEMA` is the v1 base and is frozen; every later
change is an entry in `MIGRATIONS`, applied in order, in a transaction, keyed on
`meta['schema_version']`. A brand-new database is created at the base shape and
then migrated like any other, so the upgrade path runs on every open instead of
only on the one old engagement nobody thought to test. Without that gate a
`CREATE TABLE IF NOT EXISTS` silently leaves an engagement created yesterday on
the old shape, and every control added since passes vacuously.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

SCHEMA_VERSION = 3

# The version `SCHEMA` itself creates. Everything after it is a migration.
BASE_VERSION = 1

# Lifecycle of a finding. Order matters: advance() refuses to skip backwards.
STATES = (
    "candidate",   # an agent thinks it saw something
    "validated",   # reproduced once, with evidence attached
    "verified",    # reproduced independently, from a clean position
    "gated",       # survived the hostile-triager gate
    "ready",       # survived dedup; a human may submit it
    "rejected",    # killed by a gate or by the agent
    "duplicate",   # same bug as another finding in this engagement
    "blocked",     # parked: a missing resource stops the work, not the bug
)

TERMINAL_STATES = {"rejected", "duplicate"}

# `blocked` is a siding, not a rung: an agent that cannot proceed parks the
# finding there with the reason, and a later run resumes it from the rung it
# left. Treating it as a rung would make the block either unreachable (from
# `ready`) or an escape hatch out of forward-only ordering.
OFF_LADDER_STATES = {"blocked"}

# The ordered rungs. Forward-only applies here and nowhere else; other modules
# should read this rather than re-deriving an order from STATES.
LADDER = tuple(s for s in STATES if s not in TERMINAL_STATES and s not in OFF_LADDER_STATES)

SEVERITIES = ("info", "low", "medium", "high", "critical")

CONFIDENCE_LEVELS = ("high", "medium", "low")

# How the bug would land outside the harness. `harness_only` and `blocked` are
# honest answers that keep a finding out of a report.
DELIVERY_MODES = ("production_realistic", "harness_only", "blocked")

# What a piece of evidence is for. A differential claim needs both sides.
EVIDENCE_ROLES = ("baseline", "attack", "verification", "context")

PREREQUISITE_VERDICTS = ("reachable", "not_reachable", "blocked")

ANGLE_OUTCOMES = ("confirmed", "ruled_out", "open_gap", "blocked", "not_applicable")

# v1 words, still accepted on input so v1 prompts and `bb angle add` keep
# working; always stored as the v2 word above.
ANGLE_OUTCOME_ALIASES = {
    "negative": "ruled_out",
    "finding": "confirmed",
    "partial": "open_gap",
    "blocked": "blocked",
}

ANGLE_SOURCES = ("agent", "machine")

# Counterevidence shorter than this is a gesture, not an argument.
COUNTEREVIDENCE_MIN_CHARS = 80

_STUB_COUNTEREVIDENCE = re.compile(
    r"^(none|n/?a|nothing|no counterevidence|not applicable)\b", re.IGNORECASE
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Frozen at v1. Columns and tables added later live in MIGRATIONS below, so
-- that the only code path which can produce the current shape is the one an
-- existing engagement also takes. Do not edit the statements here.

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS requests (
    id              INTEGER PRIMARY KEY,
    ts              TEXT NOT NULL,
    phase           TEXT,
    source          TEXT NOT NULL,          -- client | proxy | import
    actor           TEXT,                   -- account label, or 'anon'
    method          TEXT NOT NULL,
    url             TEXT NOT NULL,
    host            TEXT NOT NULL,
    path            TEXT,
    query           TEXT,
    status          INTEGER,
    req_headers     TEXT,
    req_body_path   TEXT,
    req_body_sha256 TEXT,
    resp_headers    TEXT,
    resp_body_path  TEXT,
    resp_body_sha256 TEXT,
    resp_len        INTEGER,
    duration_ms     INTEGER,
    note            TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_host ON requests(host);
CREATE INDEX IF NOT EXISTS idx_requests_ts   ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_actor ON requests(actor);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY,
    uid           TEXT UNIQUE NOT NULL,
    ts_created    TEXT NOT NULL,
    ts_updated    TEXT NOT NULL,
    phase_found   TEXT,
    title         TEXT NOT NULL,
    vuln_class    TEXT NOT NULL,
    host          TEXT,
    endpoint      TEXT,
    severity      TEXT,
    cvss_vector   TEXT,
    state         TEXT NOT NULL DEFAULT 'candidate',
    summary       TEXT,
    impact        TEXT,
    repro         TEXT,
    remediation   TEXT,
    reject_reason TEXT,
    dedup_key     TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);
CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(dedup_key);

CREATE TABLE IF NOT EXISTS evidence (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    request_id INTEGER REFERENCES requests(id),
    kind       TEXT NOT NULL,     -- request | screenshot | har | terminal | file | note
    path       TEXT,
    sha256     TEXT,
    bytes      INTEGER,
    caption    TEXT
);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);

CREATE TABLE IF NOT EXISTS gates (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    gate       TEXT NOT NULL,
    verdict    TEXT NOT NULL,     -- pass | fail
    rationale  TEXT,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_gates_finding ON gates(finding_id);

-- What has already been tried, so later phases do not redo work and so a
-- "not found" is distinguishable from "never tested".
CREATE TABLE IF NOT EXISTS angles (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    phase      TEXT,
    surface    TEXT NOT NULL,     -- host, or host+path
    vuln_class TEXT NOT NULL,
    technique  TEXT NOT NULL,
    outcome    TEXT NOT NULL,     -- negative | blocked | finding | partial
    note       TEXT,
    UNIQUE(surface, vuln_class, technique)
);

CREATE TABLE IF NOT EXISTS accounts (
    id         INTEGER PRIMARY KEY,
    label      TEXT UNIQUE NOT NULL,
    role       TEXT,              -- attacker | victim | admin | anon
    email      TEXT,
    secret_ref TEXT,              -- path under sensitive/, or env var name
    note       TEXT
);

-- Objects an account owns, so access-control tests can state who *should*
-- be able to touch what. Changing a random id is not a finding; touching an
-- object recorded here as another account's is.
CREATE TABLE IF NOT EXISTS objects (
    id              INTEGER PRIMARY KEY,
    label           TEXT NOT NULL,
    kind            TEXT,
    identifier      TEXT NOT NULL,
    owner_account   TEXT REFERENCES accounts(label),
    created_by_request INTEGER REFERENCES requests(id),
    expected_access TEXT,
    note            TEXT,
    UNIQUE(kind, identifier)
);

CREATE TABLE IF NOT EXISTS phase_runs (
    id         INTEGER PRIMARY KEY,
    phase      TEXT NOT NULL,
    attempt    INTEGER NOT NULL DEFAULT 1,
    ts_start   TEXT NOT NULL,
    ts_end     TEXT,
    status     TEXT NOT NULL,     -- running | ok | failed | timeout | budget | skipped
    exit_code  INTEGER,
    turns      INTEGER,
    cost_usd   REAL,
    session_id TEXT,
    error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_phase_runs_phase ON phase_runs(phase);

CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
    title, summary, impact, repro, vuln_class, endpoint,
    content='findings', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
    INSERT INTO findings_fts(rowid, title, summary, impact, repro, vuln_class, endpoint)
    VALUES (new.id, new.title, new.summary, new.impact, new.repro, new.vuln_class, new.endpoint);
END;
CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, title, summary, impact, repro, vuln_class, endpoint)
    VALUES ('delete', old.id, old.title, old.summary, old.impact, old.repro, old.vuln_class, old.endpoint);
END;
CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, title, summary, impact, repro, vuln_class, endpoint)
    VALUES ('delete', old.id, old.title, old.summary, old.impact, old.repro, old.vuln_class, old.endpoint);
    INSERT INTO findings_fts(rowid, title, summary, impact, repro, vuln_class, endpoint)
    VALUES (new.id, new.title, new.summary, new.impact, new.repro, new.vuln_class, new.endpoint);
END;
"""


class StoreError(RuntimeError):
    pass


# -- migrations ---------------------------------------------------------------


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    """ADD COLUMN, skipped when it is already there, so a migration can re-run."""
    if column not in _column_names(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _migrate_v2(conn: sqlite3.Connection) -> None:
    """v2: blocked state, the reachability ledger, evidence roles, angle vocabulary.

    Every statement is conditional, because a migration that crashed halfway
    through must be safe to replay.
    """
    for column, decl in (
        # Why the work stopped, and what would clear it. A block that names
        # neither is indistinguishable from a false negative.
        ("blocked_reason", "TEXT"),
        ("unblock_condition", "TEXT"),
        # The rung the finding was parked from, so forward-only survives a block.
        ("blocked_from", "TEXT"),
        # What would make this finding wrong, and what was checked against it.
        ("counterevidence", "TEXT"),
        ("confidence", "TEXT"),
        ("confidence_rationale", "TEXT"),
        ("severity_change_conditions", "TEXT"),
        # Whether the bug lands outside the harness.
        ("delivery", "TEXT"),
        # sha256 of the report the independent verification pass was built from.
        ("frozen_sha256", "TEXT"),
    ):
        _add_column(conn, "findings", column, decl)

    _add_column(conn, "evidence", "role", "TEXT NOT NULL DEFAULT 'context'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_role ON evidence(role)")

    _add_column(conn, "angles", "source", "TEXT NOT NULL DEFAULT 'agent'")
    _add_column(conn, "angles", "control", "TEXT")
    _add_column(conn, "angles", "next_test", "TEXT")
    for old, new in ANGLE_OUTCOME_ALIASES.items():
        if old != new:
            conn.execute("UPDATE angles SET outcome = ? WHERE outcome = ?", (new, old))

    # Owning both test accounts proves the authz check is missing and says
    # nothing about whether an attacker can obtain the identifier. Each
    # prerequisite records where an attacker starts, how the thing is acquired
    # from there, the request that proves it, and where we looked -- so that
    # "not found" stays distinguishable from "never looked".
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS prerequisites (
            id             INTEGER PRIMARY KEY,
            ts             TEXT NOT NULL,
            finding_id     INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            name           TEXT NOT NULL,
            attacker_start TEXT,
            acquisition    TEXT,
            request_id     INTEGER REFERENCES requests(id),
            verdict        TEXT NOT NULL,
            searched       TEXT,
            UNIQUE(finding_id, name)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_prerequisites_finding ON prerequisites(finding_id)"
    )


def _migrate_v3(conn: sqlite3.Connection) -> None:
    """v3: the derived surface inventory, and why an empty one is not a clean sweep.

    `surfaces` is a materialised view over `requests` plus the recon handoff, one
    row per (host, path_shape, method). `bbh.coverage` rebuilds it wholesale
    rather than amending it, which is the only way a cache of a derivation cannot
    drift from what it was derived from. Every column is a count or a shape
    computed from recorded requests, so `remaining = eligible - tested` is
    arithmetic over the request log rather than over an agent's account of its
    own work.

    `coverage_reasons` exists because an empty eligible set reads as "this class
    was never routed", not "this class was clean". Closing one takes a stated
    reason, and a stated reason has to be a row a later phase can read back
    rather than a sentence in a handoff nobody re-reads.

    Both statements are conditional: a migration that crashed halfway through
    must be safe to replay.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS surfaces (
            id           INTEGER PRIMARY KEY,
            host         TEXT NOT NULL,
            path_shape   TEXT NOT NULL,   -- ids collapsed to {id}, dates to {date}
            method       TEXT NOT NULL,
            observations INTEGER NOT NULL DEFAULT 0,  -- requests collapsing here
            declared     INTEGER NOT NULL DEFAULT 0,  -- the recon handoff listed it
            authed       INTEGER NOT NULL DEFAULT 0,  -- those sent with a credential
            anon         INTEGER NOT NULL DEFAULT 0,  -- those sent without one
            query_keys   TEXT,            -- parameter NAMES only, never values
            first_seen   TEXT,
            last_seen    TEXT,
            derived_at   TEXT NOT NULL,
            UNIQUE(host, path_shape, method)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_surfaces_host ON surfaces(host)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS coverage_reasons (
            id         INTEGER PRIMARY KEY,
            ts         TEXT NOT NULL,
            vuln_class TEXT NOT NULL,
            reason     TEXT NOT NULL,
            phase      TEXT,
            UNIQUE(vuln_class)
        )
        """
    )


# (version, what it does, how). Ordered, forward-only, applied once each.
MIGRATIONS: tuple[tuple[int, str, Callable[[sqlite3.Connection], None]], ...] = (
    (2, "blocked state, prerequisites, evidence roles, angle vocabulary", _migrate_v2),
    (3, "derived surface inventory and recorded coverage reasons", _migrate_v3),
)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: str | Path) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def counterevidence_problem(text: str | None) -> str | None:
    """Why this counterevidence is a stub, or None when it argues something.

    Shared with the gates so a finding cannot pass one bar and fail the other.
    """
    body = (text or "").strip()
    if not body:
        return "counterevidence is empty"
    if _STUB_COUNTEREVIDENCE.match(body):
        return f"counterevidence begins with a non-answer ({body.split()[0]!r})"
    if len(body) < COUNTEREVIDENCE_MIN_CHARS:
        return (
            f"counterevidence is {len(body)} characters; the bar is "
            f"{COUNTEREVIDENCE_MIN_CHARS}, because anything shorter names no alternative "
            "explanation"
        )
    return None


def _check_enum(
    value: Any, allowed: Iterable[str], field: str, remedy: str, *, optional: bool = True
) -> None:
    """Membership check. `optional` is for the fields where None means "unset"."""
    if value is None and optional:
        return
    if value not in tuple(allowed):
        raise StoreError(
            f"{field} must be one of {tuple(allowed)}, got {value!r}. {remedy}"
        )


@dataclass
class Finding:
    id: int
    uid: str
    title: str
    vuln_class: str
    state: str
    severity: str | None
    host: str | None
    endpoint: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Finding":
        return cls(
            id=row["id"],
            uid=row["uid"],
            title=row["title"],
            vuln_class=row["vuln_class"],
            state=row["state"],
            severity=row["severity"],
            host=row["host"],
            endpoint=row["endpoint"],
        )


class Store:
    """Per-engagement database. Safe for concurrent writers."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=30.0, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=30000")
        self._init_schema()

    def _init_schema(self) -> None:
        # executescript() implicitly commits any open transaction, so it must not
        # run inside tx(): the trailing COMMIT would have nothing to commit and
        # sqlite3 would raise "cannot commit - no transaction is active".
        self.conn.executescript(SCHEMA)
        with self.tx():
            # A new database is stamped at the base version, not at the current
            # one, so it goes through the same migrations as an old engagement.
            self.conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(BASE_VERSION),),
            )
        self._migrate()

    def schema_version(self) -> int:
        raw = self.get_meta("schema_version")
        try:
            return int(str(raw))
        except (TypeError, ValueError):
            # Unreadable means unknown, and unknown means "needs every
            # migration": replaying them is safe, skipping them is not.
            return BASE_VERSION

    def _migrate(self) -> None:
        current = self.schema_version()
        if current > SCHEMA_VERSION:
            raise StoreError(
                f"{self.path} is at schema version {current} but this build of bbh only "
                f"understands {SCHEMA_VERSION}. Refusing to write a newer database with an "
                "older harness. Update the harness:\n"
                "  git -C ~/claude-harness pull && ~/claude-harness/bin/bb doctor"
            )
        for version, description, apply in MIGRATIONS:
            if version <= current:
                continue
            with self.tx() as conn:
                # Re-read under the write lock: another writer may have applied
                # this migration between the check above and the BEGIN.
                if self.schema_version() >= version:
                    continue
                try:
                    apply(conn)
                except sqlite3.Error as exc:
                    raise StoreError(
                        f"migration to schema v{version} ({description}) failed on "
                        f"{self.path}: {exc}. The database is unchanged. Save a copy and "
                        f"report it:\n  cp {self.path} {self.path}.v{current}.bak"
                    ) from exc
                conn.execute(
                    "UPDATE meta SET value = ? WHERE key = 'schema_version'", (str(version),)
                )

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Immediate transaction, retrying briefly when another writer holds it."""
        for attempt in range(6):
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError:
                if attempt == 5:
                    raise
                time.sleep(0.2 * (attempt + 1))
        try:
            yield self.conn
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    # -- meta / run state -------------------------------------------------

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self.tx():
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    # -- requests ---------------------------------------------------------

    def add_request(self, **kw: Any) -> int:
        fields = (
            "phase", "source", "actor", "method", "url", "host", "path", "query",
            "status", "req_headers", "req_body_path", "req_body_sha256",
            "resp_headers", "resp_body_path", "resp_body_sha256", "resp_len",
            "duration_ms", "note",
        )
        for required in ("source", "method", "url", "host"):
            if not kw.get(required):
                raise StoreError(f"add_request needs {required}")
        for key in ("req_headers", "resp_headers"):
            if isinstance(kw.get(key), (dict, list)):
                kw[key] = json.dumps(kw[key])
        cols = ", ".join(("ts",) + fields)
        marks = ", ".join(["?"] * (len(fields) + 1))
        values = [utcnow()] + [kw.get(f) for f in fields]
        with self.tx():
            cur = self.conn.execute(f"INSERT INTO requests({cols}) VALUES ({marks})", values)
            return int(cur.lastrowid)

    def request_count(self, host: str | None = None) -> int:
        if host:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM requests WHERE host = ?", (host,)
            ).fetchone()
        else:
            row = self.conn.execute("SELECT COUNT(*) AS n FROM requests").fetchone()
        return int(row["n"])

    def search_requests(
        self, pattern: str, limit: int = 50, host: str | None = None
    ) -> list[sqlite3.Row]:
        sql = "SELECT * FROM requests WHERE url LIKE ?"
        args: list[Any] = [f"%{pattern}%"]
        if host:
            sql += " AND host = ?"
            args.append(host)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return list(self.conn.execute(sql, args))

    # -- findings ---------------------------------------------------------

    def add_finding(
        self,
        uid: str,
        title: str,
        vuln_class: str,
        *,
        phase_found: str | None = None,
        host: str | None = None,
        endpoint: str | None = None,
        severity: str | None = None,
        summary: str | None = None,
        impact: str | None = None,
        repro: str | None = None,
        remediation: str | None = None,
        dedup_key: str | None = None,
    ) -> int:
        if severity and severity not in SEVERITIES:
            raise StoreError(f"severity must be one of {SEVERITIES}, got {severity!r}")
        now = utcnow()
        with self.tx():
            cur = self.conn.execute(
                "INSERT INTO findings(uid, ts_created, ts_updated, phase_found, title, "
                "vuln_class, host, endpoint, severity, state, summary, impact, repro, "
                "remediation, dedup_key) "
                "VALUES (?,?,?,?,?,?,?,?,?,'candidate',?,?,?,?,?)",
                (uid, now, now, phase_found, title, vuln_class, host, endpoint, severity,
                 summary, impact, repro, remediation, dedup_key),
            )
            return int(cur.lastrowid)

    def get_finding(self, ref: str | int) -> sqlite3.Row | None:
        if isinstance(ref, int) or str(ref).isdigit():
            return self.conn.execute(
                "SELECT * FROM findings WHERE id = ?", (int(ref),)
            ).fetchone()
        return self.conn.execute("SELECT * FROM findings WHERE uid = ?", (ref,)).fetchone()

    def list_findings(self, state: str | None = None) -> list[sqlite3.Row]:
        if state:
            return list(
                self.conn.execute(
                    "SELECT * FROM findings WHERE state = ? ORDER BY id", (state,)
                )
            )
        return list(self.conn.execute("SELECT * FROM findings ORDER BY id"))

    def update_finding(self, ref: str | int, **fields: Any) -> None:
        row = self.get_finding(ref)
        if row is None:
            raise StoreError(f"no such finding: {ref!r}")
        allowed = {
            "title", "vuln_class", "host", "endpoint", "severity", "cvss_vector",
            "summary", "impact", "repro", "remediation", "dedup_key", "reject_reason",
            "counterevidence", "confidence", "confidence_rationale",
            "severity_change_conditions", "delivery", "frozen_sha256",
            "blocked_reason", "unblock_condition",
        }
        bad = set(fields) - allowed
        if bad:
            raise StoreError(f"cannot set {sorted(bad)} via update_finding")
        # None clears a field. A severity that was asserted and then found not to
        # be derivable has to be removable, or the only way out is a new finding.
        if fields.get("severity") is not None and fields["severity"] not in SEVERITIES:
            raise StoreError(f"severity must be one of {SEVERITIES}")
        _check_enum(
            fields.get("confidence"), CONFIDENCE_LEVELS, "confidence",
            f"Set it with: `bb finding set {row['uid']} --confidence medium`",
        )
        _check_enum(
            fields.get("delivery"), DELIVERY_MODES, "delivery",
            "`harness_only` is the honest answer when the repro needs harness state that "
            "an attacker has no way to create.",
        )
        digest = fields.get("frozen_sha256")
        if digest is not None and not _SHA256_RE.match(str(digest)):
            raise StoreError(
                f"frozen_sha256 must be a 64-character sha256 hex digest, got {digest!r}. "
                f"Freeze the report instead of writing the field by hand:\n"
                f"  bb finding freeze {row['uid']}"
            )
        if not fields:
            return
        sets = ", ".join(f"{k} = ?" for k in fields)
        with self.tx():
            self.conn.execute(
                f"UPDATE findings SET {sets}, ts_updated = ? WHERE id = ?",
                [*fields.values(), utcnow(), row["id"]],
            )

    def _validated_problems(self, row: sqlite3.Row) -> list[tuple[str, str]]:
        """(what is wrong, how to fix it) for everything blocking `validated`."""
        uid = row["uid"]
        problems: list[tuple[str, str]] = []

        problem = counterevidence_problem(row["counterevidence"])
        if problem:
            problems.append((
                problem,
                f"bb finding set {uid} --counterevidence "
                "'<the strongest case that this is not a bug, and what you checked against "
                "it: alternative explanations, an intended-behaviour reading, the same "
                "request without the payload>'",
            ))

        if not str(row["severity_change_conditions"] or "").strip():
            problems.append((
                "severity_change_conditions is empty",
                f"bb finding set {uid} --severity-change-conditions "
                "'<what would raise this severity, and what would lower it>'",
            ))

        confidence = row["confidence"]
        if confidence != "high" and not str(row["confidence_rationale"] or "").strip():
            # Unset is not high: a finding nobody rated still owes the reason.
            said = f"confidence is {confidence!r}" if confidence else "confidence is not set"
            problems.append((
                f"{said}, and confidence_rationale is empty",
                f"bb finding set {uid} --confidence-rationale '<what you are unsure of and "
                "why>'   # or --confidence high, if nothing is",
            ))
        return problems

    def advance(
        self,
        ref: str | int,
        state: str,
        reason: str | None = None,
        *,
        unblock_condition: str | None = None,
    ) -> None:
        """Move a finding to a new state. Forward-only except into terminal states.

        `blocked` is off the ladder: reachable from any live state, leaveable by a
        later run, and it remembers the rung it was parked from so resuming it
        cannot quietly rewind a finding's history.
        """
        if state not in STATES:
            raise StoreError(f"state must be one of {STATES}, got {state!r}")
        row = self.get_finding(ref)
        if row is None:
            raise StoreError(f"no such finding: {ref!r}")
        current = row["state"]
        if current in TERMINAL_STATES and state not in TERMINAL_STATES:
            raise StoreError(f"finding {row['uid']} is {current}; it cannot be revived")

        if state == "blocked":
            if not str(reason or "").strip():
                raise StoreError(
                    f"blocking {row['uid']} needs a reason naming the resource you are "
                    "missing; an unexplained block is indistinguishable from a false "
                    "negative, and a false negative poisons every later run through the "
                    "angle ledger. Retry with:\n"
                    f"  bb finding advance {row['uid']} blocked --reason '<what is missing, "
                    "e.g. no second account on this tenant>'"
                )
        elif state not in TERMINAL_STATES:
            # Compare against the rung the finding actually sits on. While it is
            # parked in `blocked` that is blocked_from; a row with neither (hand
            # edited) is treated as the first rung rather than refused, because
            # the rungs above it carry their own requirements.
            rung = current if current in LADDER else (row["blocked_from"] or LADDER[0])
            if rung in LADDER and LADDER.index(state) < LADDER.index(rung):
                raise StoreError(
                    f"refusing to move {row['uid']} backwards from {current} to {state}"
                )

        if state == "validated":
            problems = self._validated_problems(row)
            if problems:
                detail = "\n".join(f"  - {what}\n    fix: {how}" for what, how in problems)
                raise StoreError(
                    f"{row['uid']} cannot reach 'validated' yet:\n{detail}\n"
                    f"Then retry: bb finding advance {row['uid']} validated"
                )

        with self.tx():
            if state == "blocked":
                self.conn.execute(
                    "UPDATE findings SET state = 'blocked', ts_updated = ?, "
                    "blocked_reason = ?, "
                    "unblock_condition = COALESCE(?, unblock_condition), "
                    "blocked_from = COALESCE(blocked_from, ?) WHERE id = ?",
                    (
                        utcnow(),
                        reason,
                        unblock_condition,
                        current if current in LADDER else None,
                        row["id"],
                    ),
                )
            else:
                self.conn.execute(
                    "UPDATE findings SET state = ?, ts_updated = ?, "
                    "reject_reason = COALESCE(?, reject_reason), "
                    "blocked_from = NULL WHERE id = ?",
                    (state, utcnow(), reason, row["id"]),
                )

    def search_findings(self, query: str, limit: int = 25) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT f.* FROM findings_fts JOIN findings f ON f.id = findings_fts.rowid "
                "WHERE findings_fts MATCH ? ORDER BY rank LIMIT ?",
                (query, limit),
            )
        )

    # -- evidence ---------------------------------------------------------

    def add_evidence(
        self,
        finding_ref: str | int | None,
        kind: str,
        *,
        path: str | Path | None = None,
        request_id: int | None = None,
        caption: str | None = None,
        role: str = "context",
    ) -> int:
        """Attach evidence. A path argument must point at a file that exists.

        `role` is what the artifact proves. An access-control claim with no
        `baseline` row has not shown the control working in the first place, so
        the gates need the distinction recorded at capture time.
        """
        _check_enum(
            role, EVIDENCE_ROLES, "evidence role",
            "baseline = the control working, attack = the control bypassed, "
            "verification = the effect seen from the owner's side, context = everything else.",
            optional=False,
        )
        finding_id = None
        if finding_ref is not None:
            row = self.get_finding(finding_ref)
            if row is None:
                raise StoreError(f"no such finding: {finding_ref!r}")
            finding_id = row["id"]

        digest = None
        size = None
        stored = None
        if path is not None:
            p = Path(path)
            if not p.is_file():
                raise StoreError(
                    f"evidence path {p} does not exist. Evidence must be a real artifact; "
                    "the harness will not record a claim as proof."
                )
            digest, size = sha256_file(p)
            stored = str(p)

        if path is None and request_id is None and kind != "note":
            raise StoreError(f"{kind} evidence needs either a path or a request_id")

        with self.tx():
            cur = self.conn.execute(
                "INSERT INTO evidence(ts, finding_id, request_id, kind, path, sha256, "
                "bytes, caption, role) VALUES (?,?,?,?,?,?,?,?,?)",
                (utcnow(), finding_id, request_id, kind, stored, digest, size, caption, role),
            )
            return int(cur.lastrowid)

    def evidence_for(
        self, finding_ref: str | int, role: str | None = None
    ) -> list[sqlite3.Row]:
        _check_enum(role, EVIDENCE_ROLES, "evidence role", "Omit it to get every role.")
        row = self.get_finding(finding_ref)
        if row is None:
            return []
        if role is not None:
            return list(
                self.conn.execute(
                    "SELECT * FROM evidence WHERE finding_id = ? AND role = ? ORDER BY id",
                    (row["id"], role),
                )
            )
        return list(
            self.conn.execute(
                "SELECT * FROM evidence WHERE finding_id = ? ORDER BY id", (row["id"],)
            )
        )

    # -- prerequisite reachability ledger ---------------------------------

    def add_prerequisite(
        self,
        finding_ref: str | int,
        name: str,
        *,
        attacker_start: str | None = None,
        acquisition: str | None = None,
        request_id: int | None = None,
        verdict: str = "not_reachable",
        searched: str | None = None,
    ) -> int:
        """Record one thing the attack needs, and whether an attacker can get it.

        Default verdict is `not_reachable`: a prerequisite nobody has traced is
        not reachable, and a UUIDv4 with no attacker-reachable leak kills a
        finding however clean the authorization break is.
        """
        row = self.get_finding(finding_ref)
        if row is None:
            raise StoreError(f"no such finding: {finding_ref!r}")
        label = str(name or "").strip()
        if not label:
            raise StoreError(
                "a prerequisite needs a name, e.g. 'victim document id'. Retry with:\n"
                f"  bb prereq add {row['uid']} '<name>' --acquisition '<how an attacker "
                "gets it>'"
            )
        _check_enum(
            verdict, PREREQUISITE_VERDICTS, "prerequisite verdict",
            f"Use `reachable` only with the request id that acquired it from the "
            f"attacker's own position: `bb prereq add {row['uid']} '{label}' "
            "--verdict reachable --request-id <id>`",
            optional=False,
        )
        with self.tx():
            self.conn.execute(
                "INSERT INTO prerequisites(ts, finding_id, name, attacker_start, "
                "acquisition, request_id, verdict, searched) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(finding_id, name) DO UPDATE SET "
                "ts = excluded.ts, verdict = excluded.verdict, "
                "attacker_start = COALESCE(excluded.attacker_start, attacker_start), "
                "acquisition = COALESCE(excluded.acquisition, acquisition), "
                "request_id = COALESCE(excluded.request_id, request_id), "
                "searched = COALESCE(excluded.searched, searched)",
                (utcnow(), row["id"], label, attacker_start, acquisition, request_id,
                 verdict, searched),
            )
        # lastrowid is only meaningful when the upsert inserted, so read the id
        # back instead of guessing which branch ran.
        return int(
            self.conn.execute(
                "SELECT id FROM prerequisites WHERE finding_id = ? AND name = ?",
                (row["id"], label),
            ).fetchone()["id"]
        )

    def prerequisites_for(self, finding_ref: str | int) -> list[sqlite3.Row]:
        row = self.get_finding(finding_ref)
        if row is None:
            return []
        return list(
            self.conn.execute(
                "SELECT * FROM prerequisites WHERE finding_id = ? ORDER BY id", (row["id"],)
            )
        )

    def verify_evidence(self, finding_ref: str | int) -> list[str]:
        """Re-hash every artifact. Returns a list of problems; empty means intact."""
        problems: list[str] = []
        for ev in self.evidence_for(finding_ref):
            if not ev["path"]:
                continue
            p = Path(ev["path"])
            if not p.is_file():
                problems.append(f"evidence {ev['id']} missing: {p}")
                continue
            digest, _ = sha256_file(p)
            if digest != ev["sha256"]:
                problems.append(f"evidence {ev['id']} changed on disk since capture: {p}")
        return problems

    # -- gates ------------------------------------------------------------

    def record_gate(
        self,
        finding_ref: str | int,
        gate: str,
        verdict: str,
        rationale: str | None = None,
        detail: Any = None,
    ) -> int:
        if verdict not in ("pass", "fail"):
            raise StoreError("gate verdict must be 'pass' or 'fail'")
        row = self.get_finding(finding_ref)
        if row is None:
            raise StoreError(f"no such finding: {finding_ref!r}")
        if detail is not None and not isinstance(detail, str):
            detail = json.dumps(detail)
        with self.tx():
            cur = self.conn.execute(
                "INSERT INTO gates(ts, finding_id, gate, verdict, rationale, detail) "
                "VALUES (?,?,?,?,?,?)",
                (utcnow(), row["id"], gate, verdict, rationale, detail),
            )
            return int(cur.lastrowid)

    def gates_for(self, finding_ref: str | int) -> list[sqlite3.Row]:
        row = self.get_finding(finding_ref)
        if row is None:
            return []
        return list(
            self.conn.execute(
                "SELECT * FROM gates WHERE finding_id = ? ORDER BY id", (row["id"],)
            )
        )

    # -- angle ledger -----------------------------------------------------

    def record_angle(
        self,
        surface: str,
        vuln_class: str,
        technique: str,
        outcome: str,
        *,
        phase: str | None = None,
        note: str | None = None,
        source: str = "agent",
        control: str | None = None,
        next_test: str | None = None,
    ) -> None:
        """Record what was tried. "I moved on" is not an outcome.

        v1 words (negative, finding, partial) are accepted and stored as their v2
        equivalent, so v1 prompts and `bb angle add` keep working; the `control`
        and `next_test` requirements apply to callers using the v2 vocabulary,
        which is what opting into it means. Drop the aliases once the prompts and
        the CLI only speak v2.
        """
        canonical = (
            outcome if outcome in ANGLE_OUTCOMES else ANGLE_OUTCOME_ALIASES.get(outcome)
        )
        if canonical is None:
            raise StoreError(
                f"outcome must be one of {ANGLE_OUTCOMES} (v1 words "
                f"{tuple(k for k in ANGLE_OUTCOME_ALIASES if k not in ANGLE_OUTCOMES)} are "
                f"still accepted), got {outcome!r}"
            )
        _check_enum(
            source, ANGLE_SOURCES, "angle source",
            "`machine` is for rows derived from the request log, `agent` for rows an agent "
            "wrote about work it did.",
            optional=False,
        )
        if outcome in ANGLE_OUTCOMES:
            if canonical == "ruled_out" and not str(control or "").strip():
                raise StoreError(
                    f"ruling out {vuln_class}/{technique} on {surface} needs the control "
                    "that rules it out -- the defence you actually observed, not the "
                    "absence of a result. Retry with:\n"
                    f"  bb angle add {surface} {vuln_class} {technique} ruled_out "
                    "--control '<e.g. server-side ownership check returns 403 for every id>'\n"
                    "If nothing stopped you and you simply stopped, the outcome is open_gap."
                )
            if canonical == "open_gap" and not str(next_test or "").strip():
                raise StoreError(
                    f"leaving {vuln_class}/{technique} on {surface} as an open gap needs the "
                    "next test, so a later phase can pick it up instead of re-deciding it is "
                    "untested. Retry with:\n"
                    f"  bb angle add {surface} {vuln_class} {technique} open_gap "
                    "--next-test '<the concrete request to try next>'"
                )
        with self.tx():
            self.conn.execute(
                "INSERT INTO angles(ts, phase, surface, vuln_class, technique, outcome, "
                "note, source, control, next_test) VALUES (?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(surface, vuln_class, technique) DO UPDATE SET "
                "ts = excluded.ts, outcome = excluded.outcome, note = excluded.note, "
                "phase = excluded.phase, source = excluded.source, "
                # Keep what an earlier, better-documented record knew.
                "control = COALESCE(excluded.control, control), "
                "next_test = COALESCE(excluded.next_test, next_test)",
                (utcnow(), phase, surface, vuln_class, technique, canonical, note,
                 source, control, next_test),
            )

    def angles(self, surface: str | None = None) -> list[sqlite3.Row]:
        if surface:
            return list(
                self.conn.execute(
                    "SELECT * FROM angles WHERE surface = ? ORDER BY vuln_class, technique",
                    (surface,),
                )
            )
        return list(self.conn.execute("SELECT * FROM angles ORDER BY surface, vuln_class"))

    # Ground an angle row actually covers. `blocked` never reached the surface and
    # `open_gap` names the test it did not get to, so neither closes anything: a
    # later phase has to be able to tell both apart from a decided result.
    SETTLED_OUTCOMES = ("confirmed", "ruled_out", "not_applicable")

    def angle_tested(self, surface: str, vuln_class: str, technique: str) -> bool:
        row = self.conn.execute(
            "SELECT outcome FROM angles WHERE surface=? AND vuln_class=? AND technique=?",
            (surface, vuln_class, technique),
        ).fetchone()
        return row is not None and row["outcome"] in self.SETTLED_OUTCOMES

    # -- accounts and objects ---------------------------------------------

    def add_account(
        self, label: str, role: str, email: str | None = None,
        secret_ref: str | None = None, note: str | None = None,
    ) -> int:
        with self.tx():
            cur = self.conn.execute(
                "INSERT INTO accounts(label, role, email, secret_ref, note) VALUES (?,?,?,?,?) "
                "ON CONFLICT(label) DO UPDATE SET role=excluded.role, email=excluded.email, "
                "secret_ref=excluded.secret_ref, note=excluded.note",
                (label, role, email, secret_ref, note),
            )
            return int(cur.lastrowid)

    def accounts(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM accounts ORDER BY role, label"))

    def add_object(
        self, label: str, kind: str, identifier: str, owner_account: str,
        *, created_by_request: int | None = None, expected_access: str | None = None,
        note: str | None = None,
    ) -> int:
        with self.tx():
            cur = self.conn.execute(
                "INSERT INTO objects(label, kind, identifier, owner_account, "
                "created_by_request, expected_access, note) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(kind, identifier) DO UPDATE SET owner_account=excluded.owner_account, "
                "expected_access=excluded.expected_access, note=excluded.note",
                (label, kind, identifier, owner_account, created_by_request,
                 expected_access, note),
            )
            return int(cur.lastrowid)

    def objects(self, owner: str | None = None) -> list[sqlite3.Row]:
        if owner:
            return list(
                self.conn.execute(
                    "SELECT * FROM objects WHERE owner_account = ? ORDER BY kind, label",
                    (owner,),
                )
            )
        return list(self.conn.execute("SELECT * FROM objects ORDER BY kind, label"))

    def owner_of(self, kind: str, identifier: str) -> str | None:
        row = self.conn.execute(
            "SELECT owner_account FROM objects WHERE kind = ? AND identifier = ?",
            (kind, identifier),
        ).fetchone()
        return row["owner_account"] if row else None

    # -- phase runs -------------------------------------------------------

    def start_phase(self, phase: str, session_id: str | None = None) -> int:
        prior = self.conn.execute(
            "SELECT COALESCE(MAX(attempt), 0) AS n FROM phase_runs WHERE phase = ?", (phase,)
        ).fetchone()["n"]
        with self.tx():
            cur = self.conn.execute(
                "INSERT INTO phase_runs(phase, attempt, ts_start, status, session_id) "
                "VALUES (?,?,?,'running',?)",
                (phase, int(prior) + 1, utcnow(), session_id),
            )
            return int(cur.lastrowid)

    def finish_phase(
        self, run_id: int, status: str, *, exit_code: int | None = None,
        turns: int | None = None, cost_usd: float | None = None,
        session_id: str | None = None, error: str | None = None,
    ) -> None:
        with self.tx():
            self.conn.execute(
                "UPDATE phase_runs SET ts_end=?, status=?, exit_code=?, turns=?, "
                "cost_usd=?, session_id=COALESCE(?, session_id), error=? WHERE id=?",
                (utcnow(), status, exit_code, turns, cost_usd, session_id, error, run_id),
            )

    def phase_status(self, phase: str) -> str | None:
        row = self.conn.execute(
            "SELECT status FROM phase_runs WHERE phase = ? ORDER BY id DESC LIMIT 1", (phase,)
        ).fetchone()
        return row["status"] if row else None

    def phase_runs(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM phase_runs ORDER BY id"))

    def total_cost(self) -> float:
        row = self.conn.execute(
            "SELECT COALESCE(SUM(cost_usd), 0.0) AS c FROM phase_runs"
        ).fetchone()
        return float(row["c"])

    # -- summary ----------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        by_state = {
            r["state"]: r["n"]
            for r in self.conn.execute(
                "SELECT state, COUNT(*) AS n FROM findings GROUP BY state"
            )
        }
        return {
            "requests": self.request_count(),
            "findings": sum(by_state.values()),
            "by_state": by_state,
            "angles": self.conn.execute("SELECT COUNT(*) AS n FROM angles").fetchone()["n"],
            "evidence": self.conn.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()["n"],
            "cost_usd": round(self.total_cost(), 4),
        }
