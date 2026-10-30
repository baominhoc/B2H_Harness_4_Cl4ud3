"""The deterministic gates.

A model can be argued round; these cannot. Each gate gets both paths tested,
and `gate_access_control_ownership` gets the most, because "I changed id=1 to
id=2 and got a 200" is the most common false positive in bug bounty and the
gate exists precisely to tell it apart from a real one.
"""

from __future__ import annotations

import pytest

from bbh import triage
from bbh.triage import (
    NO_OBJECT_RATIONALE,
    GateResult,
    TriageError,
    apply_gates,
    gate_access_control_ownership,
    gate_evidence_exists,
    gate_has_request_proof,
    gate_in_scope,
    gate_not_duplicate,
    gate_repro_present,
    gate_severity_floor,
    is_access_control_class,
    run_gates,
)
from bbh.store import StoreError
from conftest import (
    GOOD_REPRO,
    VALIDATED_FIELDS,
    make_scope,
    seed_access_control_finding,
)


def finding(store, uid="F-001"):
    return store.get_finding(uid)


# ---------------------------------------------------------------------------
# gate_evidence_exists
# ---------------------------------------------------------------------------


def test_evidence_gate_fails_with_nothing_attached(store):
    store.add_finding("F-001", "t", "idor")
    result = gate_evidence_exists(store, finding(store))
    assert not result.passed
    assert "no evidence is attached" in result.rationale


def test_evidence_gate_fails_on_a_bare_note(store):
    """A free-text note is not an artifact."""
    store.add_finding("F-001", "t", "idor")
    store.add_evidence("F-001", "note", caption="I definitely saw it")
    result = gate_evidence_exists(store, finding(store))
    assert not result.passed
    assert "a note is not proof" in result.rationale


def test_evidence_gate_passes_with_a_real_artifact(store, tmp_path):
    store.add_finding("F-001", "t", "idor")
    artifact = tmp_path / "resp.json"
    artifact.write_text('{"owner":"victim"}')
    store.add_evidence("F-001", "file", path=artifact)
    assert gate_evidence_exists(store, finding(store)).passed


def test_evidence_gate_fails_when_the_artifact_was_edited(store, tmp_path):
    store.add_finding("F-001", "t", "idor")
    artifact = tmp_path / "resp.json"
    artifact.write_text('{"owner":"victim"}')
    store.add_evidence("F-001", "file", path=artifact)
    artifact.write_text('{"owner":"attacker"}')
    result = gate_evidence_exists(store, finding(store))
    assert not result.passed
    assert "no longer matches what was captured" in result.rationale


def test_an_artifact_the_harness_can_no_longer_read_parks_the_finding(store, tmp_path):
    """A file that moved is the harness failing to read its own record.

    The artifact hashed clean when it was captured, so a mismatch now says
    nothing about the bug -- a moved tree or a deleted file does this. Binning
    the finding for it would be permanent, and the remedy (`bb evidence add`)
    needs the finding alive.
    """
    store.add_finding("F-001", "t", "idor")
    artifact = tmp_path / "resp.json"
    artifact.write_text('{"owner":"victim"}')
    store.add_evidence("F-001", "file", path=artifact)
    artifact.unlink()
    result = gate_evidence_exists(store, finding(store))
    assert result.blocked
    assert "bb evidence verify F-001" in result.unblock


# ---------------------------------------------------------------------------
# gate_has_request_proof
# ---------------------------------------------------------------------------


def test_request_proof_gate_fails_without_a_request_citation(store, tmp_path):
    store.add_finding("F-001", "t", "idor")
    artifact = tmp_path / "shot.png"
    artifact.write_bytes(b"\x89PNG")
    store.add_evidence("F-001", "screenshot", path=artifact)
    result = gate_has_request_proof(store, finding(store))
    assert not result.passed
    assert "no recorded request backs this finding" in result.rationale


def test_request_proof_gate_passes_with_a_resolvable_request(store):
    seed_access_control_finding(store)
    result = gate_has_request_proof(store, finding(store))
    assert result.passed
    assert result.detail["request_ids"] == [1]


def test_request_proof_gate_fails_on_a_dangling_request_id(store):
    """A citation pointing at a row that is not there proves nothing.

    The foreign key stops this happening through the API, so the row is
    orphaned the way a damaged or partially restored store would be: the gate
    must still fail closed rather than trust the citation.
    """
    seed_access_control_finding(store)
    store.conn.execute("PRAGMA foreign_keys=OFF")
    store.conn.execute("DELETE FROM requests WHERE id = 1")
    store.conn.execute("PRAGMA foreign_keys=ON")
    result = gate_has_request_proof(store, finding(store))
    assert not result.passed
    assert "does not resolve to a recorded request" in result.rationale


# ---------------------------------------------------------------------------
# gate_in_scope
# ---------------------------------------------------------------------------


def test_in_scope_gate_passes_for_an_in_scope_host(store):
    store.add_finding("F-001", "t", "idor", host="www.acme.example")
    assert gate_in_scope(make_scope(), finding(store)).passed


def test_in_scope_gate_fails_for_an_out_of_scope_host(store):
    store.add_finding("F-001", "t", "idor", host="evil.example")
    result = gate_in_scope(make_scope(), finding(store))
    assert not result.passed
    assert "cannot be reported" in result.rationale


def test_in_scope_gate_fails_when_no_host_is_named(store):
    store.add_finding("F-001", "t", "idor")
    result = gate_in_scope(make_scope(), finding(store))
    assert not result.passed
    assert "names no host" in result.rationale


def test_in_scope_gate_fails_closed_with_no_scope(store):
    store.add_finding("F-001", "t", "idor", host="www.acme.example")
    result = gate_in_scope(None, finding(store))
    assert not result.passed
    assert "no compiled scope" in result.rationale


def test_in_scope_gate_fails_on_an_expired_attestation(store):
    store.add_finding("F-001", "t", "idor", host="www.acme.example")
    result = gate_in_scope(make_scope(hours=-1), finding(store))
    assert not result.passed


# ---------------------------------------------------------------------------
# gate_severity_floor
# ---------------------------------------------------------------------------


def test_severity_gate_fails_when_unset(store):
    store.add_finding("F-001", "t", "idor")
    result = gate_severity_floor(store, finding(store))
    assert not result.passed
    assert "severity is not set" in result.rationale


def test_info_never_ships_even_at_the_info_floor(store):
    store.add_finding("F-001", "t", "idor", severity="info")
    result = gate_severity_floor(store, finding(store), floor="info")
    assert not result.passed
    assert "never shipped" in result.rationale


def test_severity_below_the_floor_fails(store):
    store.add_finding("F-001", "t", "idor", severity="low")
    result = gate_severity_floor(store, finding(store), floor="high")
    assert not result.passed
    assert "below this engagement's floor" in result.rationale


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
def test_severity_at_or_above_the_floor_passes(store, severity):
    store.add_finding("F-001", "t", "idor", severity=severity)
    assert gate_severity_floor(store, finding(store), floor="low").passed


def test_an_unknown_floor_is_a_caller_bug_not_a_verdict(store):
    store.add_finding("F-001", "t", "idor", severity="high")
    with pytest.raises(TriageError):
        gate_severity_floor(store, finding(store), floor="catastrophic")


# ---------------------------------------------------------------------------
# gate_repro_present
# ---------------------------------------------------------------------------


def test_repro_gate_fails_with_no_steps(store):
    store.add_finding("F-001", "t", "idor")
    result = gate_repro_present(store, finding(store))
    assert not result.passed
    assert "no reproduction steps" in result.rationale


def test_repro_gate_fails_with_a_single_step(store):
    store.add_finding("F-001", "t", "idor", repro="1. GET https://www.acme.example/x")
    result = gate_repro_present(store, finding(store))
    assert not result.passed
    assert "at least 2" in result.rationale


def test_repro_gate_fails_without_a_concrete_url(store):
    store.add_finding(
        "F-001", "t", "idor",
        repro="1. Log in as the attacker.\n2. Request the victim's document.",
    )
    result = gate_repro_present(store, finding(store))
    assert not result.passed
    assert "no concrete http(s) URL" in result.rationale


def test_repro_gate_rejects_a_placeholder_url(store):
    store.add_finding(
        "F-001", "t", "idor",
        repro="1. Sign in.\n2. GET https://<host>/api/docs/2 and read it.",
    )
    assert not gate_repro_present(store, finding(store)).passed


def test_repro_gate_passes_on_numbered_steps_naming_a_url(store):
    store.add_finding("F-001", "t", "idor", repro=GOOD_REPRO)
    result = gate_repro_present(store, finding(store))
    assert result.passed
    assert result.detail["steps"] == ["1", "2", "3"]


def test_repro_gate_normalises_escaped_newlines_from_the_cli(store):
    """Steps set through a shell often arrive with literal \\n."""
    store.add_finding(
        "F-001", "t", "idor",
        repro="1. Sign in.\\n2. GET https://www.acme.example/api/docs/2\\n3. Read it.",
    )
    assert gate_repro_present(store, finding(store)).passed


def test_repro_gate_counts_distinct_step_numbers(store):
    store.add_finding(
        "F-001", "t", "idor",
        repro="1. GET https://www.acme.example/a\n1. GET https://www.acme.example/b",
    )
    assert not gate_repro_present(store, finding(store)).passed


# ---------------------------------------------------------------------------
# gate_access_control_ownership -- the one that earns its keep
# ---------------------------------------------------------------------------


def test_ownership_gate_passes_a_genuine_cross_account_read(store):
    seed_access_control_finding(store)
    result = gate_access_control_ownership(store, finding(store))
    assert result.passed
    assert result.detail["actor"] == "attacker"
    assert result.detail["owner"] == "victim"


def test_ownership_gate_rejects_changing_an_id_you_own(store):
    """The central false positive: the object reached belongs to the actor."""
    seed_access_control_finding(store, actor="attacker", owner="attacker")
    result = gate_access_control_ownership(store, finding(store))
    assert not result.passed
    assert "changing an identifier you own is not broken access control" in result.rationale


def test_ownership_gate_fails_when_no_object_is_registered(store):
    seed_access_control_finding(store, register_object=False)
    result = gate_access_control_ownership(store, finding(store))
    assert not result.passed
    assert result.rationale == NO_OBJECT_RATIONALE


def test_ownership_gate_fails_without_a_cited_request(store):
    seed_access_control_finding(store, cite_request=False)
    result = gate_access_control_ownership(store, finding(store))
    assert not result.passed
    assert "no request evidence is cited" in result.rationale


def test_ownership_gate_rejects_an_unregistered_actor(store):
    """An unlabelled request could be the agent's own victim session."""
    seed_access_control_finding(store, actor="anon", register_actor=False)
    result = gate_access_control_ownership(store, finding(store))
    assert not result.passed
    assert "not a registered account" in result.rationale


def test_ownership_gate_fails_when_the_object_has_no_recorded_owner(store, tmp_path):
    store.add_account("attacker", "attacker")
    rid = store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://www.acme.example/api/docs/2", host="www.acme.example",
        path="/api/docs/2", status=200,
    )
    store.conn.execute(
        "INSERT INTO objects(label, kind, identifier, owner_account) VALUES (?,?,?,NULL)",
        ("mystery doc", "document", "2"),
    )
    store.add_finding("F-001", "t", "idor", host="www.acme.example")
    store.add_evidence("F-001", "request", request_id=rid)
    result = gate_access_control_ownership(store, finding(store))
    assert not result.passed
    assert "no owner is recorded" in result.rationale


def test_ownership_gate_does_not_apply_to_other_classes(store):
    store.add_finding("F-001", "Reflected XSS", "xss", host="www.acme.example")
    result = gate_access_control_ownership(store, finding(store))
    assert result.passed
    assert "not an access-control class" in result.rationale


@pytest.mark.parametrize(
    "vuln_class",
    ["idor", "bac", "BAC", "auth-bypass", "Broken Access Control",
     "broken_access_control", "improper-access-control", "privilege-escalation"],
)
def test_access_control_classes_are_recognised(vuln_class):
    assert is_access_control_class(vuln_class), vuln_class


@pytest.mark.parametrize("vuln_class", ["xss", "ssrf", "callback-ssrf", "feedback-form-csrf", ""])
def test_unrelated_classes_are_not_swept_in(vuln_class):
    assert not is_access_control_class(vuln_class), vuln_class


def test_ownership_gate_matches_an_identifier_as_a_whole_token(store):
    """id 1 must not match /v1/ in the path."""
    store.add_account("attacker", "attacker")
    store.add_account("victim", "victim")
    rid = store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://www.acme.example/api/v1/profile", host="www.acme.example",
        path="/api/v1/profile", status=200,
    )
    store.add_object("victim doc", "document", "1", "victim")
    store.add_finding("F-001", "t", "idor", host="www.acme.example")
    store.add_evidence("F-001", "request", request_id=rid)
    result = gate_access_control_ownership(store, finding(store))
    assert not result.passed, "'1' inside /v1/ is not the object identifier"


def test_ownership_gate_finds_an_identifier_in_the_query_string(store):
    store.add_account("attacker", "attacker")
    store.add_account("victim", "victim")
    rid = store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://www.acme.example/export?doc=8831", host="www.acme.example",
        path="/export", query="doc=8831", status=200,
    )
    store.add_object("victim doc", "document", "8831", "victim")
    store.add_finding("F-001", "t", "idor", host="www.acme.example")
    store.add_evidence("F-001", "request", request_id=rid)
    assert gate_access_control_ownership(store, finding(store)).passed


# ---------------------------------------------------------------------------
# gate_not_duplicate
# ---------------------------------------------------------------------------


def test_duplicate_gate_passes_for_a_finding_with_no_live_twin(store):
    seed_access_control_finding(store)
    result = gate_not_duplicate(store, finding(store))
    assert result.passed
    # The key is the harness's, not the model's: nothing wrote a dedup_key here.
    assert result.detail["computed_key"]["path_shape"] == "www.acme.example/api/docs/{id}"
    assert result.detail["stored_dedup_key"] is None


def test_duplicate_gate_blocks_when_it_cannot_compute_the_key(store):
    """A gate that cannot compute its answer fails, and fails without rejecting.

    The old gate passed this finding: nothing had written a dedup_key, so
    nothing could collide with it. That is the permissive branch, reached by
    leaving a field blank.
    """
    store.add_finding("F-001", "t", "idor")
    result = gate_not_duplicate(store, finding(store))
    assert not result.passed
    assert result.blocked and "bb evidence add F-001 request" in result.unblock
    assert "cannot compute a dedup key" in result.rationale


def test_duplicate_gate_ignores_the_stored_key_and_reads_the_traffic(store):
    """Two reports of one bug, each with its own key, still collide.

    This is the whole defect: `dedup_key` was a model-written field, so two
    different strings were all it took for both findings to survive.
    """
    seed_access_control_finding(store, uid="F-001", identifier="2")
    seed_access_control_finding(store, uid="F-002", identifier="3")
    store.update_finding("F-001", dedup_key="idor:docs:read")
    store.update_finding("F-002", dedup_key="idor:documents:disclosure")
    result = gate_not_duplicate(store, store.get_finding("F-002"))
    assert not result.passed
    assert "F-001" in result.rationale
    assert "bb finding merge F-002 --into" in result.rationale


def test_duplicate_gate_ignores_terminal_findings(store):
    """A correctly merged duplicate must not fail its survivor."""
    seed_access_control_finding(store, uid="F-001", identifier="2")
    seed_access_control_finding(store, uid="F-002", identifier="3")
    store.advance("F-001", "duplicate")
    assert gate_not_duplicate(store, store.get_finding("F-002")).passed


def test_duplicate_gate_does_not_collapse_two_bugs_sharing_one_careless_key(store):
    """One key copied onto two real bugs is not a duplicate either.

    The two routes are three segments apart on purpose: routes one segment
    apart are a near miss, because one handler reached two ways is the usual
    shape of a bug reported twice (test_triage_v2 covers that).
    """
    seed_access_control_finding(store, uid="F-001", identifier="2")
    rid = store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://www.acme.example/api/v1/billing/invoices/9", host="www.acme.example",
        path="/api/v1/billing/invoices/9", status=200,
    )
    store.add_finding(
        "F-002", "Cross-account invoice read", "idor", host="www.acme.example",
        endpoint="/api/v1/billing/invoices/9", severity="high", repro=GOOD_REPRO,
        dedup_key="idor:docs:read",
    )
    store.add_evidence("F-002", "request", request_id=rid)
    store.update_finding("F-001", dedup_key="idor:docs:read")
    assert gate_not_duplicate(store, store.get_finding("F-001")).passed
    assert gate_not_duplicate(store, store.get_finding("F-002")).passed


# ---------------------------------------------------------------------------
# run_gates / apply_gates
# ---------------------------------------------------------------------------


def test_run_gates_runs_every_published_gate(store):
    seed_access_control_finding(store)
    results = run_gates(store, make_scope(), finding(store))
    assert {r.name for r in results} == {
        "gate_evidence_exists", "gate_has_request_proof", "gate_in_scope",
        "gate_severity_floor", "gate_repro_present",
        "gate_access_control_ownership", "gate_not_duplicate",
    }
    assert all(isinstance(r, GateResult) for r in results)


def test_run_gates_accepts_a_uid_as_well_as_a_row(store):
    seed_access_control_finding(store)
    assert len(run_gates(store, make_scope(), "F-001")) == 7


def test_run_gates_accepts_a_short_gate_name(store):
    seed_access_control_finding(store)
    results = run_gates(store, make_scope(), "F-001", gates=["in_scope"])
    assert [r.name for r in results] == ["gate_in_scope"]


def test_run_gates_accepts_a_gate_by_reference(store):
    seed_access_control_finding(store)
    results = run_gates(store, make_scope(), "F-001", gates=[gate_in_scope])
    assert [r.name for r in results] == ["gate_in_scope"]


def test_an_empty_gate_list_is_refused(store):
    seed_access_control_finding(store)
    with pytest.raises(TriageError, match="no gates were selected"):
        run_gates(store, make_scope(), "F-001", gates=[])


def test_an_unknown_gate_name_is_refused(store):
    seed_access_control_finding(store)
    with pytest.raises(TriageError, match="unknown gate"):
        run_gates(store, make_scope(), "F-001", gates=["gate_vibes"])


def test_run_gates_writes_nothing(store):
    seed_access_control_finding(store)
    run_gates(store, make_scope(), "F-001")
    assert store.gates_for("F-001") == []
    assert store.get_finding("F-001")["state"] == "candidate"


def test_apply_gates_advances_a_clean_finding_to_gated(store):
    seed_access_control_finding(store)
    # The published seven are gates; `validated` also carries a bar inside
    # `store.advance`, and the climb to `gated` goes through that rung.
    store.update_finding("F-001", **VALIDATED_FIELDS)
    assert apply_gates(store, make_scope(), "F-001") is True
    assert store.get_finding("F-001")["state"] == "gated"
    assert len(store.gates_for("F-001")) == 7


def test_apply_gates_climbs_the_ladder_rather_than_jumping_to_the_target(store):
    """Passing the seven is not permission to skip what the rungs below ask.

    `store.advance(..., "validated")` refuses a claim nobody argued against.
    Moving a candidate straight to `gated` asked that rung for nothing, which
    is how a finding with no counterevidence reached the state `bb report`
    renders from.
    """
    seed_access_control_finding(store)
    with pytest.raises(StoreError, match="counterevidence is empty"):
        apply_gates(store, make_scope(), "F-001")
    assert store.get_finding("F-001")["state"] == "candidate"


def test_apply_gates_rejects_on_any_failure_and_records_why(store):
    seed_access_control_finding(store, owner="attacker")  # owns the object
    assert apply_gates(store, make_scope(), "F-001") is False
    row = store.get_finding("F-001")
    assert row["state"] == "rejected"
    assert "gate_access_control_ownership" in row["reject_reason"]


def test_apply_gates_records_every_verdict_not_just_the_failures(store):
    seed_access_control_finding(store, owner="attacker")
    apply_gates(store, make_scope(), "F-001")
    verdicts = {r["gate"]: r["verdict"] for r in store.gates_for("F-001")}
    assert len(verdicts) == 7
    assert verdicts["gate_access_control_ownership"] == "fail"
    assert verdicts["gate_in_scope"] == "pass"


def test_apply_gates_is_idempotent_for_a_passing_finding(store):
    seed_access_control_finding(store)
    store.update_finding("F-001", **VALIDATED_FIELDS)
    assert apply_gates(store, make_scope(), "F-001") is True
    assert apply_gates(store, make_scope(), "F-001") is True
    assert store.get_finding("F-001")["state"] == "gated"


def test_apply_gates_raises_rather_than_rejecting_without_a_scope(store):
    """Rejection is permanent; a harness misconfiguration must not cause one."""
    seed_access_control_finding(store)
    with pytest.raises(TriageError, match="needs a compiled scope"):
        apply_gates(store, None, "F-001")
    assert store.get_finding("F-001")["state"] == "candidate"


def test_apply_gates_raises_rather_than_rejecting_on_a_stale_attestation(store):
    seed_access_control_finding(store)
    with pytest.raises(TriageError, match="unusable"):
        apply_gates(store, make_scope(hours=-1), "F-001")
    assert store.get_finding("F-001")["state"] == "candidate"


def test_apply_gates_raises_for_an_unknown_finding(store):
    with pytest.raises(TriageError, match="no such finding"):
        apply_gates(store, make_scope(), "F-404")


def test_every_published_gate_name_is_in_the_registry():
    """The contract names these seven; run_gates must not silently drop one."""
    assert set(triage.DEFAULT_GATES) == {
        "gate_evidence_exists", "gate_has_request_proof", "gate_in_scope",
        "gate_severity_floor", "gate_repro_present",
        "gate_access_control_ownership", "gate_not_duplicate",
    }
