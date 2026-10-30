"""The v2 store: versioned migrations and the controls they carry.

v1 created its tables with CREATE TABLE IF NOT EXISTS and no version gate, so an
engagement created before a control was added kept the old shape and every new
gate passed vacuously. The migration tests here are the ones that matter most:
they build a genuine v1-shaped database and assert it comes out the far side
usable, and they assert a migrated database and a fresh one are the same shape,
so nobody can add a column to the base DDL instead of to a migration.

The rest pin the controls added on top: a block that must name what is missing,
a `validated` transition that refuses a finding nobody argued against, evidence
that says what it proves, and an angle ledger where "I moved on" is not a state.
"""

from __future__ import annotations

import sqlite3

import pytest

from bbh.store import (
    ANGLE_OUTCOMES,
    BASE_VERSION,
    CONFIDENCE_LEVELS,
    COUNTEREVIDENCE_MIN_CHARS,
    DELIVERY_MODES,
    EVIDENCE_ROLES,
    LADDER,
    MIGRATIONS,
    OFF_LADDER_STATES,
    PREREQUISITE_VERDICTS,
    SCHEMA_VERSION,
    STATES,
    TERMINAL_STATES,
    Store,
    StoreError,
    counterevidence_problem,
)

# Long enough to clear the stub bar, and an actual argument against the finding.
GOOD_COUNTEREVIDENCE = (
    "Repeated the request from a second attacker account and with no session at all: "
    "the first saw the victim record, the second got a 401, so neither a shared cache "
    "nor an open endpoint explains it."
)

GOOD_CONDITIONS = "critical if the ids are enumerable; low if it needs the victim's session"


def validatable(store: Store, uid: str = "F-001") -> None:
    """Give a finding the minimum a `validated` transition requires."""
    store.update_finding(
        uid,
        counterevidence=GOOD_COUNTEREVIDENCE,
        severity_change_conditions=GOOD_CONDITIONS,
        confidence="high",
    )


# ---------------------------------------------------------------------------
# migrations
# ---------------------------------------------------------------------------

# The v1 shape, frozen here on purpose. bbh.store.SCHEMA will keep drifting;
# this is what the databases created before the migration list look like.
V1_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS requests (
    id              INTEGER PRIMARY KEY,
    ts              TEXT NOT NULL,
    phase           TEXT,
    source          TEXT NOT NULL,
    actor           TEXT,
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
    kind       TEXT NOT NULL,
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
    verdict    TEXT NOT NULL,
    rationale  TEXT,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_gates_finding ON gates(finding_id);

CREATE TABLE IF NOT EXISTS angles (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    phase      TEXT,
    surface    TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    technique  TEXT NOT NULL,
    outcome    TEXT NOT NULL,
    note       TEXT,
    UNIQUE(surface, vuln_class, technique)
);

CREATE TABLE IF NOT EXISTS accounts (
    id         INTEGER PRIMARY KEY,
    label      TEXT UNIQUE NOT NULL,
    role       TEXT,
    email      TEXT,
    secret_ref TEXT,
    note       TEXT
);

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
    status     TEXT NOT NULL,
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


def write_v1_database(path, *, version: str | None = "1") -> None:
    """A database exactly as a pre-migration harness left it, with real rows."""
    conn = sqlite3.connect(str(path))
    conn.executescript(V1_SCHEMA)
    if version is not None:
        conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', ?)", (version,))
    conn.execute(
        "INSERT INTO requests(ts, source, method, url, host, path, status) "
        "VALUES ('2026-10-01T00:00:00Z', 'client', 'GET', 'https://a/api/docs/2', 'a', "
        "'/api/docs/2', 200)"
    )
    conn.execute(
        "INSERT INTO findings(uid, ts_created, ts_updated, title, vuln_class, host, "
        "severity, state, summary) VALUES ('F-001', '2026-10-01T00:00:00Z', "
        "'2026-10-01T00:00:00Z', 'Old finding', 'idor', 'a', 'high', 'verified', "
        "'cross tenant read')"
    )
    conn.execute(
        "INSERT INTO evidence(ts, finding_id, request_id, kind, caption) "
        "VALUES ('2026-10-01T00:00:00Z', 1, 1, 'request', 'the v1 proof')"
    )
    for surface, outcome in (
        ("a/one", "negative"),
        ("a/two", "finding"),
        ("a/three", "partial"),
        ("a/four", "blocked"),
    ):
        conn.execute(
            "INSERT INTO angles(ts, surface, vuln_class, technique, outcome) "
            "VALUES ('2026-10-01T00:00:00Z', ?, 'idor', 'id-swap', ?)",
            (surface, outcome),
        )
    conn.commit()
    conn.close()


def table_shape(store: Store, table: str) -> list[tuple[str, str]]:
    return [
        (row["name"], row["type"])
        for row in store.conn.execute(f"PRAGMA table_info({table})")
    ]


def test_a_fresh_database_is_stamped_at_the_current_version(tmp_path):
    db = Store(tmp_path / "fresh.sqlite3")
    assert db.get_meta("schema_version") == str(SCHEMA_VERSION)
    assert db.schema_version() == SCHEMA_VERSION
    db.close()


def test_the_migration_list_reaches_the_published_version():
    """A column added without an entry here is a column old engagements never get."""
    versions = [version for version, _desc, _apply in MIGRATIONS]
    assert versions == sorted(set(versions)), "migrations must be ordered and unique"
    assert all(v > BASE_VERSION for v in versions)
    assert versions[-1] == SCHEMA_VERSION


def test_a_v1_database_migrates(tmp_path):
    path = tmp_path / "v1.sqlite3"
    write_v1_database(path)

    db = Store(path)
    assert db.schema_version() == SCHEMA_VERSION

    columns = {name for name, _type in table_shape(db, "findings")}
    assert {"blocked_reason", "unblock_condition", "counterevidence", "confidence",
            "confidence_rationale", "severity_change_conditions", "delivery",
            "frozen_sha256"} <= columns
    assert "role" in {name for name, _type in table_shape(db, "evidence")}
    assert {"source", "control", "next_test"} <= {
        name for name, _type in table_shape(db, "angles")
    }
    assert table_shape(db, "prerequisites")

    # The rows that were already there survive, with sane values in the new columns.
    row = db.get_finding("F-001")
    assert (row["title"], row["state"], row["severity"]) == ("Old finding", "verified", "high")
    assert row["counterevidence"] is None
    assert db.evidence_for("F-001")[0]["role"] == "context"
    db.close()


def test_migration_rewrites_the_v1_angle_vocabulary(tmp_path):
    path = tmp_path / "v1-angles.sqlite3"
    write_v1_database(path)
    db = Store(path)
    assert {row["surface"]: row["outcome"] for row in db.angles()} == {
        "a/one": "ruled_out",
        "a/two": "confirmed",
        "a/three": "open_gap",
        "a/four": "blocked",
    }
    assert all(row["source"] == "agent" for row in db.angles())
    db.close()


def test_a_migrated_database_is_usable(tmp_path):
    """Columns in place is not the same as a working store."""
    path = tmp_path / "v1-usable.sqlite3"
    write_v1_database(path)
    db = Store(path)
    db.advance("F-001", "blocked", "no second account on this tenant")
    assert db.get_finding("F-001")["blocked_reason"] == "no second account on this tenant"
    assert db.add_prerequisite("F-001", "victim document id", verdict="not_reachable") > 0
    assert db.add_evidence("F-001", "note", caption="x", role="baseline") > 0
    db.close()


def test_migrating_twice_changes_nothing(tmp_path):
    path = tmp_path / "v1-twice.sqlite3"
    write_v1_database(path)
    first = Store(path)
    shape = table_shape(first, "findings")
    first.close()

    second = Store(path)
    assert second.schema_version() == SCHEMA_VERSION
    assert table_shape(second, "findings") == shape
    assert second.get_finding("F-001")["title"] == "Old finding"
    assert len(second.angles()) == 4
    second.close()


def test_a_migrated_database_has_the_same_shape_as_a_fresh_one(tmp_path):
    """The drift guard: new shape belongs in a migration, not in the base DDL."""
    fresh = Store(tmp_path / "fresh.sqlite3")
    legacy_path = tmp_path / "legacy.sqlite3"
    write_v1_database(legacy_path)
    migrated = Store(legacy_path)

    tables = sorted(
        row["name"]
        for row in fresh.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    )
    migrated_tables = sorted(
        row["name"]
        for row in migrated.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    )
    assert tables == migrated_tables
    assert "prerequisites" in tables
    for table in tables:
        assert table_shape(fresh, table) == table_shape(migrated, table), table
    fresh.close()
    migrated.close()


def test_a_database_with_no_recorded_version_is_migrated(tmp_path):
    """Unknown version means "needs every migration": replaying them is safe."""
    path = tmp_path / "no-version.sqlite3"
    write_v1_database(path, version=None)
    db = Store(path)
    assert db.schema_version() == SCHEMA_VERSION
    assert "counterevidence" in {name for name, _ in table_shape(db, "findings")}
    db.close()


def test_an_unreadable_version_is_treated_as_the_base_version(tmp_path):
    path = tmp_path / "junk-version.sqlite3"
    write_v1_database(path, version="not a number")
    db = Store(path)
    assert db.schema_version() == SCHEMA_VERSION
    db.close()


def test_a_newer_database_is_refused_rather_than_written(tmp_path):
    path = tmp_path / "future.sqlite3"
    write_v1_database(path, version=str(SCHEMA_VERSION + 7))
    with pytest.raises(StoreError) as exc:
        Store(path)
    assert "older harness" in str(exc.value)
    assert "git -C ~/claude-harness pull" in str(exc.value), "an error names the fix"


def test_migrations_are_atomic(tmp_path, monkeypatch):
    """A migration that cannot finish leaves the old shape, not half the new one."""
    import bbh.store as store_module

    def half_applied(conn):
        store_module._add_column(conn, "findings", "blocked_reason", "TEXT")
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(
        store_module, "MIGRATIONS", ((2, "deliberately broken", half_applied),)
    )
    path = tmp_path / "broken.sqlite3"
    write_v1_database(path)
    with pytest.raises(StoreError) as exc:
        Store(path)
    assert "migration to schema v2" in str(exc.value)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
    version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    conn.close()
    assert "blocked_reason" not in columns, "the failed migration was rolled back"
    assert version["value"] == "1"


# ---------------------------------------------------------------------------
# the blocked state
# ---------------------------------------------------------------------------


def test_blocked_is_published_but_not_terminal():
    assert "blocked" in STATES
    assert TERMINAL_STATES == {"rejected", "duplicate"}
    assert "blocked" not in TERMINAL_STATES
    assert OFF_LADDER_STATES == {"blocked"}
    assert LADDER == ("candidate", "validated", "verified", "gated", "ready")


def test_blocking_needs_a_reason(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError) as exc:
        store.advance("F-001", "blocked")
    assert "needs a reason" in str(exc.value)
    assert "bb finding advance F-001 blocked --reason" in str(exc.value)
    assert store.get_finding("F-001")["state"] == "candidate"


def test_a_whitespace_reason_is_not_a_reason(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="needs a reason"):
        store.advance("F-001", "blocked", "   ")


def test_a_block_records_what_is_missing_and_what_clears_it(store):
    store.add_finding("F-001", "t", "idor")
    store.advance(
        "F-001",
        "blocked",
        "the tenant has no second account to read across",
        unblock_condition="operator provisions a second account on tenant 42",
    )
    row = store.get_finding("F-001")
    assert row["state"] == "blocked"
    assert row["blocked_reason"] == "the tenant has no second account to read across"
    assert row["unblock_condition"].startswith("operator provisions")


@pytest.mark.parametrize("rung", LADDER)
def test_blocked_is_reachable_from_every_live_state(store, rung):
    store.add_finding("F-001", "t", "idor")
    validatable(store)
    store.advance("F-001", rung)
    store.advance("F-001", "blocked", "rate limited out of the surface")
    assert store.get_finding("F-001")["state"] == "blocked"


@pytest.mark.parametrize("terminal", sorted(TERMINAL_STATES))
def test_a_terminal_finding_cannot_be_blocked(store, terminal):
    """blocked is not terminal, so it must not be a way back into the ladder."""
    store.add_finding("F-001", "t", "idor")
    store.advance("F-001", terminal, "done with it")
    with pytest.raises(StoreError, match="cannot be revived"):
        store.advance("F-001", "blocked", "actually, let us reopen this")


def test_a_later_run_can_unblock(store):
    store.add_finding("F-001", "t", "idor")
    validatable(store)
    store.advance("F-001", "blocked", "no second account")
    store.advance("F-001", "validated")
    row = store.get_finding("F-001")
    assert row["state"] == "validated"
    assert row["blocked_from"] is None, "the resume marker is spent"


def test_unblocking_cannot_rewind_the_ladder(store):
    """A block is not a way to launder a verified finding back to a candidate."""
    store.add_finding("F-001", "t", "idor")
    validatable(store)
    store.advance("F-001", "verified")
    store.advance("F-001", "blocked", "lost the account")
    assert store.get_finding("F-001")["blocked_from"] == "verified"
    with pytest.raises(StoreError, match="backwards"):
        store.advance("F-001", "validated")
    store.advance("F-001", "gated")
    assert store.get_finding("F-001")["state"] == "gated"


def test_re_blocking_keeps_the_rung_it_was_parked_from(store):
    store.add_finding("F-001", "t", "idor")
    validatable(store)
    store.advance("F-001", "verified")
    store.advance("F-001", "blocked", "first block")
    store.advance("F-001", "blocked", "still blocked, different reason")
    row = store.get_finding("F-001")
    assert row["blocked_from"] == "verified"
    assert row["blocked_reason"] == "still blocked, different reason"


def test_a_block_that_never_clears_can_be_rejected(store):
    store.add_finding("F-001", "t", "idor")
    store.advance("F-001", "blocked", "the surface was retired mid-hunt")
    store.advance("F-001", "rejected", "unreachable surface")
    assert store.get_finding("F-001")["state"] == "rejected"


def test_a_blocked_finding_is_counted_by_state(store):
    store.add_finding("F-001", "t", "idor")
    store.advance("F-001", "blocked", "no second account")
    assert store.stats()["by_state"] == {"blocked": 1}


# ---------------------------------------------------------------------------
# what `validated` costs
# ---------------------------------------------------------------------------


def test_validated_refuses_a_finding_nobody_argued_against(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError) as exc:
        store.advance("F-001", "validated")
    message = str(exc.value)
    assert "counterevidence is empty" in message
    assert "bb finding set F-001 --counterevidence" in message
    assert "severity_change_conditions is empty" in message
    assert "bb finding set F-001 --severity-change-conditions" in message
    assert store.get_finding("F-001")["state"] == "candidate"


@pytest.mark.parametrize(
    "stub",
    ["none", "None.", "n/a", "N/A", "na", "nothing", "Nothing found",
     "no counterevidence", "Not applicable here"],
)
def test_validated_rejects_stub_counterevidence(store, stub):
    store.add_finding("F-001", "t", "idor")
    store.update_finding(
        "F-001",
        counterevidence=stub + " " + "x" * COUNTEREVIDENCE_MIN_CHARS,
        severity_change_conditions=GOOD_CONDITIONS,
        confidence="high",
    )
    with pytest.raises(StoreError, match="non-answer"):
        store.advance("F-001", "validated")


def test_validated_rejects_counterevidence_too_short_to_be_an_argument(store):
    store.add_finding("F-001", "t", "idor")
    store.update_finding(
        "F-001",
        counterevidence="could be a cache",
        severity_change_conditions=GOOD_CONDITIONS,
        confidence="high",
    )
    with pytest.raises(StoreError, match=f"the bar is {COUNTEREVIDENCE_MIN_CHARS}"):
        store.advance("F-001", "validated")


def test_the_length_bar_is_measured_after_stripping(store):
    store.add_finding("F-001", "t", "idor")
    store.update_finding(
        "F-001",
        counterevidence="  " + "a" * (COUNTEREVIDENCE_MIN_CHARS - 1) + "  \n",
        severity_change_conditions=GOOD_CONDITIONS,
        confidence="high",
    )
    with pytest.raises(StoreError, match="characters"):
        store.advance("F-001", "validated")


def test_validated_needs_severity_change_conditions(store):
    store.add_finding("F-001", "t", "idor")
    store.update_finding(
        "F-001", counterevidence=GOOD_COUNTEREVIDENCE, confidence="high",
    )
    with pytest.raises(StoreError, match="severity_change_conditions is empty"):
        store.advance("F-001", "validated")


@pytest.mark.parametrize("confidence", ["medium", "low", None])
def test_anything_short_of_high_confidence_has_to_say_why(store, confidence):
    store.add_finding("F-001", "t", "idor")
    store.update_finding(
        "F-001",
        counterevidence=GOOD_COUNTEREVIDENCE,
        severity_change_conditions=GOOD_CONDITIONS,
        confidence=confidence,
    )
    with pytest.raises(StoreError) as exc:
        store.advance("F-001", "validated")
    assert "confidence_rationale is empty" in str(exc.value)
    assert "--confidence-rationale" in str(exc.value)

    store.update_finding("F-001", confidence_rationale="the id might be an unguessable uuid")
    store.advance("F-001", "validated")
    assert store.get_finding("F-001")["state"] == "validated"


def test_high_confidence_needs_no_rationale(store):
    store.add_finding("F-001", "t", "idor")
    validatable(store)
    store.advance("F-001", "validated")
    assert store.get_finding("F-001")["state"] == "validated"


def test_the_backwards_rule_still_answers_first(store):
    """The state machine's own refusal is the clearer one; keep it in front."""
    store.add_finding("F-001", "t", "idor")
    store.advance("F-001", "verified")  # skipping validated is an older hole, not this one
    with pytest.raises(StoreError, match="backwards"):
        store.advance("F-001", "validated")


def test_a_rejected_finding_is_refused_before_its_fields_are_judged(store):
    store.add_finding("F-001", "t", "idor")
    store.advance("F-001", "rejected", "no impact")
    with pytest.raises(StoreError, match="cannot be revived"):
        store.advance("F-001", "validated")


@pytest.mark.parametrize(
    "text, ok",
    [
        (None, False),
        ("", False),
        ("   ", False),
        ("none at all, I checked nothing" + " " * 60 + "x", False),
        ("x" * (COUNTEREVIDENCE_MIN_CHARS - 1), False),
        ("x" * COUNTEREVIDENCE_MIN_CHARS, True),
        (GOOD_COUNTEREVIDENCE, True),
        ("nonetheless the 403 path " + "y" * 80, True),
    ],
)
def test_counterevidence_problem_is_the_shared_rule(text, ok):
    """Exposed so a gate and the state machine cannot disagree about the bar."""
    assert (counterevidence_problem(text) is None) is ok


# ---------------------------------------------------------------------------
# evidence roles
# ---------------------------------------------------------------------------


def test_evidence_defaults_to_context(store):
    store.add_finding("F-001", "t", "idor")
    store.add_evidence("F-001", "note", caption="observed twice")
    assert store.evidence_for("F-001")[0]["role"] == "context"


def test_evidence_roles_round_trip_and_filter(store):
    store.add_finding("F-001", "t", "idor")
    base = store.add_request(source="client", method="GET", url="https://a/1", host="a")
    attack = store.add_request(source="client", method="GET", url="https://a/2", host="a")
    store.add_evidence("F-001", "request", request_id=base, role="baseline")
    store.add_evidence("F-001", "request", request_id=attack, role="attack")
    store.add_evidence("F-001", "note", caption="aside")

    assert [r["role"] for r in store.evidence_for("F-001")] == [
        "baseline", "attack", "context",
    ]
    assert [r["request_id"] for r in store.evidence_for("F-001", role="attack")] == [attack]
    assert store.evidence_for("F-001", role="verification") == []


@pytest.mark.parametrize("role", EVIDENCE_ROLES)
def test_every_published_role_is_accepted(store, role):
    store.add_finding("F-001", "t", "idor")
    assert store.add_evidence("F-001", "note", caption="x", role=role) > 0


def test_an_unknown_evidence_role_is_refused(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="evidence role must be one of"):
        store.add_evidence("F-001", "note", caption="x", role="proof")


def test_filtering_by_an_unknown_role_is_refused_rather_than_empty(store):
    """Returning [] for a typo would read as "no baseline evidence" to a gate."""
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="evidence role must be one of"):
        store.evidence_for("F-001", role="baselines")


# ---------------------------------------------------------------------------
# the prerequisite reachability ledger
# ---------------------------------------------------------------------------


def test_a_prerequisite_records_how_an_attacker_gets_there(store):
    store.add_finding("F-001", "t", "idor")
    rid = store.add_request(
        source="client", actor="attacker", method="GET", url="https://a/invites",
        host="a", status=200,
    )
    store.add_prerequisite(
        "F-001",
        "victim document id",
        attacker_start="an unauthenticated visitor with a free trial account",
        acquisition="the public invite page leaks the document id in its JSON",
        request_id=rid,
        verdict="reachable",
        searched="every 200 response body in the request log, grepped for the id",
    )
    row = store.prerequisites_for("F-001")[0]
    assert row["name"] == "victim document id"
    assert row["verdict"] == "reachable"
    assert row["request_id"] == rid
    assert "invite page" in row["acquisition"]
    assert "grepped" in row["searched"]


def test_a_prerequisite_is_not_reachable_until_someone_traces_it(store):
    """The default has to be the one that keeps a finding out of a report."""
    store.add_finding("F-001", "t", "idor")
    store.add_prerequisite("F-001", "victim account id")
    assert store.prerequisites_for("F-001")[0]["verdict"] == "not_reachable"


def test_prerequisites_are_unique_per_finding_and_name(store):
    store.add_finding("F-001", "t", "idor")
    first = store.add_prerequisite(
        "F-001", "victim document id", searched="the invite page", verdict="not_reachable"
    )
    second = store.add_prerequisite("F-001", "victim document id", verdict="blocked")
    assert first == second
    rows = store.prerequisites_for("F-001")
    assert len(rows) == 1
    assert rows[0]["verdict"] == "blocked"
    assert rows[0]["searched"] == "the invite page", "a refinement keeps what was known"


def test_the_same_name_on_another_finding_is_its_own_row(store):
    store.add_finding("F-001", "a", "idor")
    store.add_finding("F-002", "b", "idor")
    store.add_prerequisite("F-001", "victim document id")
    store.add_prerequisite("F-002", "victim document id")
    assert len(store.prerequisites_for("F-001")) == 1
    assert len(store.prerequisites_for("F-002")) == 1


@pytest.mark.parametrize("verdict", PREREQUISITE_VERDICTS)
def test_every_published_verdict_is_accepted(store, verdict):
    store.add_finding("F-001", "t", "idor")
    assert store.add_prerequisite("F-001", f"thing-{verdict}", verdict=verdict) > 0


def test_an_unknown_verdict_is_refused(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError) as exc:
        store.add_prerequisite("F-001", "victim id", verdict="probably fine")
    assert "prerequisite verdict must be one of" in str(exc.value)
    assert "--verdict reachable --request-id" in str(exc.value)


def test_a_prerequisite_needs_a_name(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="needs a name"):
        store.add_prerequisite("F-001", "  ")


def test_a_prerequisite_on_an_unknown_finding_is_refused(store):
    with pytest.raises(StoreError, match="no such finding"):
        store.add_prerequisite("F-404", "victim id")


def test_a_cited_request_has_to_exist(store):
    """"cites a request_id that resolves" is cheaper to enforce than to check."""
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(sqlite3.IntegrityError):
        store.add_prerequisite("F-001", "victim id", request_id=99999, verdict="reachable")


def test_prerequisites_for_an_unknown_finding_is_empty(store):
    assert store.prerequisites_for("F-404") == []


# ---------------------------------------------------------------------------
# the angle ledger
# ---------------------------------------------------------------------------


def test_the_published_angle_vocabulary_is_the_contract_one():
    assert ANGLE_OUTCOMES == (
        "confirmed", "ruled_out", "open_gap", "blocked", "not_applicable",
    )


def test_ruling_an_angle_out_needs_the_control_that_rules_it_out(store):
    with pytest.raises(StoreError) as exc:
        store.record_angle("a/docs", "idor", "id-swap", "ruled_out")
    assert "needs the control" in str(exc.value)
    assert "--control" in str(exc.value)
    assert "the outcome is open_gap" in str(exc.value), "name the honest alternative"
    assert store.angles() == []


def test_a_blank_control_is_not_a_control(store):
    with pytest.raises(StoreError, match="needs the control"):
        store.record_angle("a/docs", "idor", "id-swap", "ruled_out", control="  ")


def test_a_ruled_out_angle_with_a_control_is_recorded(store):
    store.record_angle(
        "a/docs", "idor", "id-swap", "ruled_out",
        control="server-side ownership check: 403 for every id but the owner's",
    )
    row = store.angles()[0]
    assert row["outcome"] == "ruled_out"
    assert row["control"].startswith("server-side ownership check")


def test_an_open_gap_needs_the_next_test(store):
    with pytest.raises(StoreError) as exc:
        store.record_angle("a/docs", "idor", "id-swap", "open_gap")
    assert "needs the next test" in str(exc.value)
    assert "--next-test" in str(exc.value)


def test_an_open_gap_with_a_next_test_is_recorded(store):
    store.record_angle(
        "a/docs", "idor", "id-swap", "open_gap",
        next_test="PATCH /api/docs/2 with the attacker session once an account exists",
    )
    assert store.angles()[0]["next_test"].startswith("PATCH")


@pytest.mark.parametrize("outcome", ["confirmed", "blocked", "not_applicable"])
def test_a_decided_outcome_needs_neither(store, outcome):
    store.record_angle("a/docs", "idor", "id-swap", outcome)
    assert store.angles()[0]["outcome"] == outcome


@pytest.mark.parametrize(
    "legacy, stored",
    [("negative", "ruled_out"), ("finding", "confirmed"),
     ("partial", "open_gap"), ("blocked", "blocked")],
)
def test_v1_words_are_accepted_and_stored_as_v2(store, legacy, stored):
    """The shim that keeps v1 prompts and `bb angle add` working."""
    store.record_angle("a/docs", "idor", "id-swap", legacy)
    assert store.angles()[0]["outcome"] == stored


def test_an_unknown_outcome_still_names_the_vocabulary(store):
    with pytest.raises(StoreError) as exc:
        store.record_angle("a", "idor", "swap", "moved-on")
    assert "outcome must be one of" in str(exc.value)
    assert "confirmed" in str(exc.value)


def test_angles_default_to_the_agent_as_their_source(store):
    store.record_angle("a", "idor", "swap", "confirmed")
    assert store.angles()[0]["source"] == "agent"


def test_a_machine_derived_angle_says_so(store):
    store.record_angle("a", "idor", "swap", "not_applicable", source="machine")
    assert store.angles()[0]["source"] == "machine"


def test_an_unknown_angle_source_is_refused(store):
    with pytest.raises(StoreError, match="angle source must be one of"):
        store.record_angle("a", "idor", "swap", "confirmed", source="vibes")


def test_re_recording_an_angle_keeps_what_the_earlier_row_knew(store):
    store.record_angle(
        "a", "idor", "swap", "open_gap", next_test="retry with a second account"
    )
    store.record_angle("a", "idor", "swap", "confirmed", note="found it")
    row = store.angles()[0]
    assert (row["outcome"], row["note"]) == ("confirmed", "found it")
    assert row["next_test"] == "retry with a second account"


def test_unfinished_ground_is_not_covered_ground(store):
    """`open_gap` exists so a later phase re-tests it; counting it as tested
    would turn "I moved on" back into a result."""
    store.record_angle("a", "idor", "settled", "ruled_out", control="403 for every id")
    store.record_angle("a", "idor", "partial", "open_gap", next_test="try PATCH")
    store.record_angle("a", "idor", "stopped", "blocked")
    store.record_angle("a", "idor", "irrelevant", "not_applicable")
    assert store.angle_tested("a", "idor", "settled") is True
    assert store.angle_tested("a", "idor", "irrelevant") is True
    assert store.angle_tested("a", "idor", "partial") is False
    assert store.angle_tested("a", "idor", "stopped") is False
    assert store.angle_tested("a", "idor", "never") is False


# ---------------------------------------------------------------------------
# finding fields
# ---------------------------------------------------------------------------


def test_severity_can_be_cleared(store):
    """An asserted severity that turns out not to be derivable has to be removable."""
    store.add_finding("F-001", "t", "idor", severity="critical")
    store.update_finding("F-001", severity=None)
    assert store.get_finding("F-001")["severity"] is None


def test_clearing_severity_does_not_disturb_the_other_fields(store):
    store.add_finding("F-001", "t", "idor", severity="critical", summary="s")
    store.update_finding("F-001", severity=None)
    assert store.get_finding("F-001")["summary"] == "s"


def test_a_bogus_severity_is_still_refused(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="severity must be one of"):
        store.update_finding("F-001", severity="catastrophic")


@pytest.mark.parametrize("confidence", CONFIDENCE_LEVELS)
def test_every_published_confidence_level_is_accepted(store, confidence):
    store.add_finding("F-001", "t", "idor")
    store.update_finding("F-001", confidence=confidence)
    assert store.get_finding("F-001")["confidence"] == confidence


def test_an_unknown_confidence_is_refused(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="confidence must be one of"):
        store.update_finding("F-001", confidence="pretty sure")


@pytest.mark.parametrize("delivery", DELIVERY_MODES)
def test_every_published_delivery_mode_is_accepted(store, delivery):
    store.add_finding("F-001", "t", "idor")
    store.update_finding("F-001", delivery=delivery)
    assert store.get_finding("F-001")["delivery"] == delivery


def test_an_unknown_delivery_mode_is_refused(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="delivery must be one of"):
        store.update_finding("F-001", delivery="works on my machine")


def test_the_freeze_hash_has_to_look_like_a_hash(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError) as exc:
        store.update_finding("F-001", frozen_sha256="frozen")
    assert "bb finding freeze F-001" in str(exc.value)
    store.update_finding("F-001", frozen_sha256="a" * 64)
    assert store.get_finding("F-001")["frozen_sha256"] == "a" * 64


def test_the_new_prose_fields_round_trip(store):
    store.add_finding("F-001", "t", "idor")
    store.update_finding(
        "F-001",
        counterevidence=GOOD_COUNTEREVIDENCE,
        confidence="medium",
        confidence_rationale="the id may be a uuid",
        severity_change_conditions=GOOD_CONDITIONS,
        delivery="production_realistic",
        unblock_condition="a second account on tenant 42",
    )
    row = store.get_finding("F-001")
    assert row["counterevidence"] == GOOD_COUNTEREVIDENCE
    assert row["confidence_rationale"] == "the id may be a uuid"
    assert row["severity_change_conditions"] == GOOD_CONDITIONS
    assert row["delivery"] == "production_realistic"
    assert row["unblock_condition"] == "a second account on tenant 42"


def test_state_is_still_not_settable_by_hand(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="cannot set"):
        store.update_finding("F-001", state="blocked")


@pytest.mark.parametrize(
    "call, match",
    [
        (lambda s: s.add_evidence("F-001", "note", caption="x", role=None),
         "evidence role must be one of"),
        (lambda s: s.add_prerequisite("F-001", "victim id", verdict=None),
         "prerequisite verdict must be one of"),
        (lambda s: s.record_angle("a", "idor", "swap", "confirmed", source=None),
         "angle source must be one of"),
    ],
)
def test_the_not_null_columns_refuse_none_with_a_readable_message(store, call, match):
    """Without this the caller gets a bare IntegrityError from the column itself."""
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match=match):
        call(store)
