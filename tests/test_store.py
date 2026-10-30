"""The store: the ledger a finding cannot be reported without.

The schema encodes the harness's central rule — nothing is proven by
assertion. These tests pin the parts that enforce it: the forward-only state
machine, evidence that must point at a real file, and hashes that are
re-checked rather than trusted.
"""

from __future__ import annotations

import sqlite3

import pytest

from bbh import paths
from bbh.store import SEVERITIES, STATES, Store, StoreError, sha256_bytes
from conftest import VALIDATED_FIELDS


# -- construction ------------------------------------------------------------


def test_store_opens_and_initialises_its_schema(tmp_path):
    """Regression: executescript() inside tx() made every Store() raise."""
    db = Store(tmp_path / "new.sqlite3")
    assert db.get_meta("schema_version") == "3"
    db.close()


def test_opening_an_existing_store_twice_is_fine(tmp_path):
    path = tmp_path / "again.sqlite3"
    first = Store(path)
    first.add_finding("F-001", "t", "idor")
    first.close()
    second = Store(path)
    assert len(second.list_findings()) == 1
    second.close()


def test_two_live_handles_can_both_write(tmp_path):
    """WAL mode: the proxy and the client write the same database concurrently."""
    path = tmp_path / "shared.sqlite3"
    a, b = Store(path), Store(path)
    a.add_request(source="client", method="GET", url="https://x/", host="x")
    b.add_request(source="proxy", method="GET", url="https://y/", host="y")
    assert a.request_count() == 2
    a.close()
    b.close()


# -- the state machine -------------------------------------------------------


def test_a_new_finding_starts_as_a_candidate(store):
    store.add_finding("F-001", "t", "idor")
    assert store.get_finding("F-001")["state"] == "candidate"


def test_states_advance_forward(store):
    store.add_finding("F-001", "t", "idor")
    store.update_finding("F-001", **VALIDATED_FIELDS)
    for state in ("validated", "verified", "gated", "ready"):
        store.advance("F-001", state)
        assert store.get_finding("F-001")["state"] == state


def test_the_state_machine_refuses_to_go_backwards(store):
    store.add_finding("F-001", "t", "idor")
    store.advance("F-001", "verified")
    with pytest.raises(StoreError, match="backwards"):
        store.advance("F-001", "validated")


def test_a_rejected_finding_cannot_be_revived(store):
    store.add_finding("F-001", "t", "idor")
    store.advance("F-001", "rejected", "no impact")
    with pytest.raises(StoreError, match="cannot be revived"):
        store.advance("F-001", "validated")


def test_a_duplicate_can_still_be_marked_rejected(store):
    """Both terminal states are reachable from each other; neither reopens a finding."""
    store.add_finding("F-001", "t", "idor")
    store.advance("F-001", "duplicate")
    store.advance("F-001", "rejected")
    assert store.get_finding("F-001")["state"] == "rejected"


def test_any_live_state_can_jump_straight_to_terminal(store):
    store.add_finding("F-001", "t", "idor")
    store.advance("F-001", "rejected", "killed at triage")
    assert store.get_finding("F-001")["reject_reason"] == "killed at triage"


def test_an_unknown_state_is_refused(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="state must be one of"):
        store.advance("F-001", "probably-fine")


def test_advancing_a_missing_finding_raises(store):
    with pytest.raises(StoreError, match="no such finding"):
        store.advance("F-404", "validated")


def test_the_published_state_vocabulary_is_the_contract_one():
    assert STATES == (
        "candidate", "validated", "verified", "gated", "ready", "rejected", "duplicate",
        "blocked",
    )
    assert SEVERITIES == ("info", "low", "medium", "high", "critical")


# -- findings ----------------------------------------------------------------


def test_severity_is_validated_on_write(store):
    with pytest.raises(StoreError, match="severity must be one of"):
        store.add_finding("F-001", "t", "idor", severity="catastrophic")


def test_update_finding_refuses_to_set_state_behind_the_state_machine(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="cannot set"):
        store.update_finding("F-001", state="ready")


def test_get_finding_resolves_a_uid_or_an_id(store):
    row_id = store.add_finding("F-001", "t", "idor")
    assert store.get_finding("F-001")["id"] == row_id
    assert store.get_finding(row_id)["uid"] == "F-001"


def test_list_findings_can_filter_by_state(store):
    store.add_finding("F-001", "a", "idor")
    store.add_finding("F-002", "b", "xss")
    store.update_finding("F-002", **VALIDATED_FIELDS)
    store.advance("F-002", "validated")
    assert [r["uid"] for r in store.list_findings("validated")] == ["F-002"]


def test_duplicate_uid_is_refused(store):
    store.add_finding("F-001", "a", "idor")
    with pytest.raises(sqlite3.IntegrityError):
        store.add_finding("F-001", "b", "xss")


# -- evidence ----------------------------------------------------------------


def test_evidence_path_must_exist(store, tmp_path):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="does not exist"):
        store.add_evidence("F-001", "file", path=tmp_path / "imaginary.txt")


def test_evidence_refusal_explains_why(store, tmp_path):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="will not record a claim as proof"):
        store.add_evidence("F-001", "file", path=tmp_path / "nope.png")


def test_evidence_records_the_hash_and_size_at_capture(store, tmp_path):
    store.add_finding("F-001", "t", "idor")
    artifact = tmp_path / "response.json"
    artifact.write_bytes(b'{"owner":"victim"}')
    store.add_evidence("F-001", "file", path=artifact)
    row = store.evidence_for("F-001")[0]
    assert row["sha256"] == sha256_bytes(b'{"owner":"victim"}')
    assert row["bytes"] == 18


def test_verify_evidence_catches_a_mutated_artifact(store, tmp_path):
    store.add_finding("F-001", "t", "idor")
    artifact = tmp_path / "response.json"
    artifact.write_bytes(b'{"owner":"victim"}')
    store.add_evidence("F-001", "file", path=artifact)
    assert store.verify_evidence("F-001") == []

    artifact.write_bytes(b'{"owner":"attacker"}')  # someone edited the proof
    problems = store.verify_evidence("F-001")
    assert len(problems) == 1
    assert "changed on disk since capture" in problems[0]


def test_verify_evidence_catches_a_deleted_artifact(store, tmp_path):
    store.add_finding("F-001", "t", "idor")
    artifact = tmp_path / "shot.png"
    artifact.write_bytes(b"\x89PNG")
    store.add_evidence("F-001", "screenshot", path=artifact)
    artifact.unlink()
    assert "missing" in store.verify_evidence("F-001")[0]


def test_request_evidence_needs_no_path(store):
    store.add_finding("F-001", "t", "idor")
    rid = store.add_request(source="client", method="GET", url="https://x/", host="x")
    assert store.add_evidence("F-001", "request", request_id=rid) > 0


def test_non_note_evidence_without_a_path_or_request_is_refused(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="needs either a path or a request_id"):
        store.add_evidence("F-001", "screenshot")


def test_a_note_may_stand_alone(store):
    store.add_finding("F-001", "t", "idor")
    assert store.add_evidence("F-001", "note", caption="observed twice") > 0


def test_evidence_for_an_unknown_finding_raises(store):
    with pytest.raises(StoreError, match="no such finding"):
        store.add_evidence("F-404", "note", caption="x")


# -- the angle ledger --------------------------------------------------------


def test_recording_the_same_angle_twice_upserts_rather_than_duplicating(store):
    store.record_angle("api.acme.example/docs", "idor", "id-swap", "negative", note="first")
    store.record_angle("api.acme.example/docs", "idor", "id-swap", "finding", note="second")
    rows = store.angles()
    assert len(rows) == 1
    assert rows[0]["outcome"] == "confirmed", "the v1 word is an input alias, not storage"
    assert rows[0]["note"] == "second"


def test_angles_differing_in_any_key_are_separate_rows(store):
    store.record_angle("a", "idor", "swap", "negative")
    store.record_angle("a", "idor", "fuzz", "negative")
    store.record_angle("a", "xss", "swap", "negative")
    store.record_angle("b", "idor", "swap", "negative")
    assert len(store.angles()) == 4


def test_angles_can_be_filtered_by_surface(store):
    store.record_angle("a", "idor", "swap", "negative")
    store.record_angle("b", "idor", "swap", "negative")
    assert [r["surface"] for r in store.angles("b")] == ["b"]


def test_an_unknown_outcome_is_refused(store):
    with pytest.raises(StoreError, match="outcome must be"):
        store.record_angle("a", "idor", "swap", "moved-on")


def test_angle_tested_distinguishes_blocked_from_covered(store):
    store.record_angle("a", "idor", "swap", "negative")
    store.record_angle("a", "idor", "fuzz", "blocked")
    assert store.angle_tested("a", "idor", "swap") is True
    assert store.angle_tested("a", "idor", "fuzz") is False, "blocked ground is not covered"
    assert store.angle_tested("a", "idor", "never") is False


# -- full text search --------------------------------------------------------


def test_fts_finds_a_finding_by_title(store):
    store.add_finding("F-001", "IDOR in invoice export", "idor")
    store.add_finding("F-002", "Reflected XSS in search", "xss")
    assert [r["uid"] for r in store.search_findings("invoice")] == ["F-001"]


def test_fts_searches_the_prose_columns(store):
    store.add_finding(
        "F-001", "Something", "idor",
        summary="any account can read another account's purchase order",
        impact="mass disclosure of order data",
    )
    assert [r["uid"] for r in store.search_findings("purchase")] == ["F-001"]
    assert [r["uid"] for r in store.search_findings("disclosure")] == ["F-001"]


def test_fts_index_follows_an_update(store):
    store.add_finding("F-001", "placeholder", "idor")
    assert store.search_findings("tenant") == []
    store.update_finding("F-001", summary="cross tenant read")
    assert [r["uid"] for r in store.search_findings("tenant")] == ["F-001"]


def test_fts_index_follows_a_title_change(store):
    store.add_finding("F-001", "old title", "idor")
    store.update_finding("F-001", title="brand new heading")
    assert store.search_findings("old") == []
    assert [r["uid"] for r in store.search_findings("heading")] == ["F-001"]


# -- requests ----------------------------------------------------------------


def test_add_request_requires_the_identifying_columns(store):
    with pytest.raises(StoreError, match="add_request needs host"):
        store.add_request(source="client", method="GET", url="https://x/")


def test_headers_are_json_encoded_on_the_way_in(store):
    rid = store.add_request(
        source="client", method="GET", url="https://x/", host="x",
        req_headers={"Accept": "*/*"},
    )
    row = store.conn.execute("SELECT req_headers FROM requests WHERE id=?", (rid,)).fetchone()
    assert row["req_headers"] == '{"Accept": "*/*"}'


def test_request_count_can_be_scoped_to_a_host(store):
    store.add_request(source="client", method="GET", url="https://a/", host="a")
    store.add_request(source="client", method="GET", url="https://b/", host="b")
    assert (store.request_count(), store.request_count("a")) == (2, 1)


def test_search_requests_matches_a_url_fragment(store):
    store.add_request(source="client", method="GET", url="https://a/api/docs/2", host="a")
    store.add_request(source="client", method="GET", url="https://a/health", host="a")
    assert len(store.search_requests("docs")) == 1


# -- accounts and objects ----------------------------------------------------


def test_adding_an_account_twice_updates_it(store):
    store.add_account("victim", "victim", email="a@x")
    store.add_account("victim", "admin", email="b@x")
    rows = store.accounts()
    assert len(rows) == 1
    assert (rows[0]["role"], rows[0]["email"]) == ("admin", "b@x")


def test_owner_of_resolves_a_registered_object(store):
    store.add_account("victim", "victim")
    store.add_object("doc", "document", "8831", "victim")
    assert store.owner_of("document", "8831") == "victim"
    assert store.owner_of("document", "9999") is None


def test_objects_can_be_filtered_by_owner(store):
    store.add_account("victim", "victim")
    store.add_account("attacker", "attacker")
    store.add_object("a", "document", "1", "victim")
    store.add_object("b", "document", "2", "attacker")
    assert [r["identifier"] for r in store.objects("victim")] == ["1"]


def test_an_object_cannot_claim_an_unregistered_owner(store):
    """The foreign key is what makes owner_of trustworthy at gate time."""
    with pytest.raises(sqlite3.IntegrityError):
        store.add_object("a", "document", "1", "ghost")


# -- phase runs and cost -----------------------------------------------------


def test_phase_status_reports_the_latest_attempt(store):
    first = store.start_phase("00-recon")
    store.finish_phase(first, "failed")
    second = store.start_phase("00-recon")
    store.finish_phase(second, "ok")
    assert store.phase_status("00-recon") == "ok"


def test_attempts_increment_per_phase(store):
    store.finish_phase(store.start_phase("00-recon"), "failed")
    store.start_phase("00-recon")
    assert [r["attempt"] for r in store.phase_runs()] == [1, 2]


def test_phase_status_is_none_before_a_phase_has_run(store):
    assert store.phase_status("00-recon") is None


def test_total_cost_sums_every_attempt(store):
    store.finish_phase(store.start_phase("00-recon"), "ok", cost_usd=1.25)
    store.finish_phase(store.start_phase("01-access"), "ok", cost_usd=0.75)
    assert store.total_cost() == pytest.approx(2.0)


def test_total_cost_is_zero_with_no_runs(store):
    assert store.total_cost() == 0.0


def test_stats_summarises_the_engagement(store, tmp_path):
    store.add_request(source="client", method="GET", url="https://a/", host="a")
    store.add_finding("F-001", "t", "idor")
    store.update_finding("F-001", **VALIDATED_FIELDS)
    store.advance("F-001", "validated")
    store.record_angle("a", "idor", "swap", "negative")
    artifact = tmp_path / "f.txt"
    artifact.write_text("x")
    store.add_evidence("F-001", "file", path=artifact)
    stats = store.stats()
    assert stats["requests"] == 1
    assert stats["findings"] == 1
    assert stats["by_state"] == {"validated": 1}
    assert stats["angles"] == 1
    assert stats["evidence"] == 1


# -- gates -------------------------------------------------------------------


def test_record_gate_only_accepts_pass_or_fail(store):
    store.add_finding("F-001", "t", "idor")
    with pytest.raises(StoreError, match="pass"):
        store.record_gate("F-001", "gate_x", "maybe")


def test_gate_detail_is_json_encoded(store):
    store.add_finding("F-001", "t", "idor")
    store.record_gate("F-001", "gate_x", "pass", "fine", {"request_ids": [1, 2]})
    assert store.gates_for("F-001")[0]["detail"] == '{"request_ids": [1, 2]}'
