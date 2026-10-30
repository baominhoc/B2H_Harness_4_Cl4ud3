"""The waiver: can an agent get one, and does a stale one stay quiet.

Every test here is written from the bypass side. A waiver is the one mechanism
in this harness whose purpose is to let a finding through a check, so the
interesting cases are not "does granting work" but the five ways a waiver stops
being a decision a person made about a finding they read:

* an agent grants one for itself, by any path reachable from inside a hunt;
* an operator waives a gate that is supposed to be immovable;
* a waiver granted for one finding or gate is read as covering another;
* a waiver outlives its review, or the finding changes under it;
* a waived gate is displayed, or reported, as a pass.

`seed` builds the finding each test waives something on. The audit log matters
as much as the file does -- `grant()` refuses when it cannot write one -- so
several tests read `paths.AUDIT_LOG` directly rather than through `bb audit`.
"""

from __future__ import annotations

import json

import pytest

from bbh import paths, triage, waiver
from bbh.waiver import WaiverError
from conftest import VALIDATED_FIELDS, seed_access_control_finding

OPERATOR = "tester@example.com"
REASON = (
    "the endpoint is unauthenticated by design, so there is no control to show working and "
    "no second account from whose side the effect could be observed"
)


def seed(store, *, uid: str = "F-001", vuln_class: str = "xss") -> dict:
    """A finding on the record, with the fields `advance` demands already set."""
    seed_access_control_finding(store, uid=uid, vuln_class=vuln_class)
    store.update_finding(uid, **VALIDATED_FIELDS)
    return dict(store.get_finding(uid))


def grant(store, uid: str = "F-001", gate: str = "gate_evidence_roles", **kw):
    kw.setdefault("reason", REASON)
    kw.setdefault("waived_by", OPERATOR)
    return waiver.grant(store, "acme", uid, gate, **kw)


def audit_lines() -> list[dict]:
    if not paths.AUDIT_LOG.exists():
        return []
    return [
        json.loads(line)
        for line in paths.AUDIT_LOG.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# the allowlist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "gate",
    [
        "gate_evidence_exists",
        "gate_has_request_proof",
        "gate_in_scope",
        "gate_severity_derived",
        "gate_prerequisites_reachable",
    ],
)
def test_the_gates_that_stop_fabrication_cannot_be_waived_at_all(store, gate):
    """The five the contract names. Nothing an operator types moves them."""
    seed(store)
    with pytest.raises(WaiverError) as exc:
        grant(store, gate=gate)
    assert gate in str(exc.value)
    assert "not waivable" in str(exc.value)
    assert not waiver.waivers_dir("acme").exists()


def test_ownership_and_repro_reconciliation_are_unwaivable_too(store):
    """Not on the brief's list; forbidden here for the reasons in the docstring."""
    seed(store)
    for gate in ("gate_access_control_ownership", "gate_repro_cites_real_requests"):
        with pytest.raises(WaiverError, match="not waivable"):
            grant(store, gate=gate)


def test_the_counterevidence_bar_is_unwaivable(store):
    """No artifact is involved, so there is no case where one cannot exist."""
    seed(store)
    with pytest.raises(WaiverError, match="not waivable"):
        grant(store, gate="gate_counterevidence_recorded")
    assert "argued with" in waiver.UNWAIVABLE["gate_counterevidence_recorded"]


def test_a_gate_nobody_decided_about_is_unwaivable_by_default(store):
    seed(store)
    with pytest.raises(WaiverError) as exc:
        grant(store, gate="gate_invented_last_tuesday")
    assert "no waiver policy is recorded" in str(exc.value)
    assert "gate_evidence_roles" in str(exc.value)  # names what can be waived


def test_every_published_gate_has_a_recorded_waiver_decision():
    """A gate added without a decision is one nobody argued about."""
    assert waiver.coverage_problem(triage.GATES) is None
    assert not set(waiver.WAIVABLE) & set(waiver.UNWAIVABLE)


def test_the_coverage_check_notices_a_gate_added_without_a_decision():
    problem = waiver.coverage_problem(list(triage.GATES) + ["gate_added_later"])
    assert "gate_added_later" in problem
    assert "unwaivable by default" in problem
    assert "gate_was_deleted" in waiver.coverage_problem(["gate_was_deleted"])


# ---------------------------------------------------------------------------
# an agent cannot grant itself one
# ---------------------------------------------------------------------------


def test_the_agents_own_entry_point_records_a_failure_not_a_pass(store):
    """Asking is a request. The row it writes says the gate still failed."""
    seed(store)
    row_id = waiver.request_waiver(store, "F-001", "gate_evidence_roles", reason=REASON)

    rows = [r for r in store.gates_for("F-001") if r["id"] == row_id]
    assert len(rows) == 1
    assert rows[0]["verdict"] == "fail"
    assert "not granted" in rows[0]["rationale"]
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is False


def test_a_requested_waiver_is_visible_to_the_operator_who_decides_it(store):
    seed(store)
    waiver.request_waiver(store, "F-001", "gate_evidence_roles", reason=REASON, asked_by="05")
    asked = waiver.requests_for(store, "F-001")
    assert [a["gate"] for a in asked] == ["gate_evidence_roles"]
    assert asked[0]["asked_by"] == "05"
    assert asked[0]["granted"] is False


def test_an_agent_cannot_ask_for_a_gate_that_is_never_waivable(store):
    seed(store)
    with pytest.raises(WaiverError, match="not waivable"):
        waiver.request_waiver(store, "F-001", "gate_in_scope", reason=REASON)


def test_the_library_refuses_while_a_phase_is_running_not_only_the_cli(store):
    """`bb gate waive` is not the only way to reach the signing routine.

    `grant()` signs with the armkey itself, so an agent that runs
    `python3 -c 'from bbh import waiver; ...'` -- which `guard.SANCTIONED`
    permits -- walks around a refusal that lives in the CLI. The window the
    refusal exists for is exactly the one an agent is typing in.
    """
    seed(store)
    store.start_phase("07-gate")
    with pytest.raises(WaiverError) as exc:
        grant(store)
    assert "07-gate is running" in str(exc.value)
    assert "bb gate waive-request" in str(exc.value)
    assert not waiver.waiver_path("acme", "F-001", "gate_evidence_roles").exists()


def test_a_finished_phase_does_not_block_the_operator(store):
    seed(store)
    run_id = store.start_phase("07-gate")
    store.finish_phase(run_id, "ok")
    assert grant(store).finding_uid == "F-001"


def test_an_unreadable_phase_table_refuses_rather_than_assuming_nobody_is_there(store):
    """Fail closed: not knowing whether an agent is typing is not knowing it is safe."""
    seed(store)
    store.conn.execute("DROP TABLE phase_runs")
    with pytest.raises(WaiverError) as exc:
        grant(store)
    assert "phase table could not be read" in str(exc.value)
    assert not waiver.waiver_path("acme", "F-001", "gate_evidence_roles").exists()


def test_a_waiver_shaped_gate_row_written_straight_to_the_store_waives_nothing(store):
    """The old literal `not-applicable:` note, which an agent could write itself."""
    seed(store)
    store.record_gate(
        "F-001", "gate_evidence_roles", "pass", "waived", f"not-applicable: {REASON}"
    )
    store.record_gate(
        "F-001",
        "gate_evidence_roles",
        "pass",
        "waived",
        {"waived": {"waiver_id": "deadbeefdeadbeef", "waived_by": "me", "reason": REASON}},
    )
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is False
    assert waiver.active(store, "F-001", "gate_evidence_roles") is None


def test_a_waiver_file_the_armkey_did_not_sign_is_not_honored(store):
    """Writing the file is not enough; the signature is the operator's act."""
    seed(store)
    path = waiver.waiver_path("acme", "F-001", "gate_evidence_roles")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "engagement": "acme",
                "finding_uid": "F-001",
                "gate": "gate_evidence_roles",
                "reason": REASON,
                "waived_by": "the agent itself",
                "granted_at": "2026-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "subject": waiver.subject_of(store, "F-001"),
                "subject_sha256": "0" * 64,
                "waiver_id": "f0rg3d",
                "sig": "0" * 64,
            }
        ),
        encoding="utf-8",
    )
    status = waiver.check(store, "F-001", "gate_evidence_roles")
    assert status.honored is False
    assert status.waiver is None
    assert "signature does not match" in " ".join(status.problems)


def test_a_waiver_edited_after_it_was_granted_stops_counting(store):
    seed(store)
    granted = grant(store)
    path = waiver.waiver_path("acme", "F-001", "gate_evidence_roles")
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["expires_at"] = "2099-01-01T00:00:00Z"
    path.write_text(json.dumps(doc), encoding="utf-8")

    status = waiver.check(store, "F-001", "gate_evidence_roles")
    assert status.honored is False
    assert "edited after it was granted" in " ".join(status.problems)
    assert granted.expires_at != doc["expires_at"]


# ---------------------------------------------------------------------------
# granting: the operator's half
# ---------------------------------------------------------------------------


def test_a_granted_waiver_names_who_when_and_why_and_is_honored(store):
    seed(store)
    granted = grant(store)

    assert granted.waived_by == OPERATOR
    assert granted.reason == REASON
    assert granted.gate == "gate_evidence_roles"
    assert granted.finding_uid == "F-001"

    status = waiver.check(store, "F-001", "gate_evidence_roles")
    assert status.honored is True
    assert status.problems == []
    assert waiver.active(store, "F-001", "gate_evidence_roles").waiver_id == granted.waiver_id


def test_the_grant_lands_in_the_hash_chained_audit_log(store):
    seed(store)
    granted = grant(store)

    waives = [r for r in audit_lines() if r.get("action") == "waive"]
    assert len(waives) == 1
    assert waives[0]["prev"]  # chained, not a flat append
    assert waives[0]["finding"] == "F-001"
    assert waives[0]["gate"] == "gate_evidence_roles"
    assert waives[0]["waived_by"] == OPERATOR
    assert waives[0]["reason"] == REASON
    assert waives[0]["waiver_id"] == granted.waiver_id


def test_a_waiver_that_cannot_be_audited_is_not_granted(store, monkeypatch):
    """The log is this mechanism's only remaining control, so it fails closed."""
    seed(store)
    monkeypatch.setattr("bbh.cli.audit_record", lambda *a, **kw: False)

    with pytest.raises(WaiverError) as exc:
        grant(store)
    assert "indistinguishable from a bypass" in str(exc.value)
    assert "bb doctor --verify-chain" in str(exc.value)
    assert not waiver.waiver_path("acme", "F-001", "gate_evidence_roles").exists()
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is False


def test_a_shrug_is_not_a_reason(store):
    seed(store)
    for reason in ("n/a", "not applicable", "see above", "no owner side", "", "none"):
        with pytest.raises(WaiverError) as exc:
            grant(store, reason=reason)
        assert "reason" in str(exc.value)
        assert "bb gate waive F-001 gate_evidence_roles" in str(exc.value)


def test_an_anonymous_waiver_is_refused(store):
    seed(store)
    for who in ("", "   ", "none", "null"):
        with pytest.raises(WaiverError, match="no name was given"):
            grant(store, waived_by=who)


def test_every_problem_with_a_grant_is_reported_at_once(store):
    """One round trip: the operator should not have to guess the next complaint."""
    seed(store)
    with pytest.raises(WaiverError) as exc:
        grant(store, reason="n/a", waived_by="", hours=0)
    message = str(exc.value)
    assert "no name was given" in message
    assert "non-answer" in message
    assert "already expired" in message


def test_a_typo_in_the_expiry_refuses_rather_than_defaulting(store):
    seed(store)
    for hours in ("twelve", -1, 0, 1000, None, float("nan")):
        with pytest.raises(WaiverError):
            grant(store, hours=hours)
    assert not waiver.waiver_path("acme", "F-001", "gate_evidence_roles").exists()


def test_a_waiver_is_not_granted_against_an_unarmed_engagement(store):
    seed(store)
    paths.lock_path("acme").unlink()
    with pytest.raises(WaiverError) as exc:
        grant(store)
    assert "could not be trusted" in str(exc.value)
    assert "bb arm acme" in str(exc.value)


def test_a_waiver_cannot_outlive_the_authorization_it_was_granted_under(store):
    """The arm expires in two hours; a 24h waiver is clamped to it."""
    seed(store)
    granted = grant(store, hours=waiver.MAX_HOURS)
    armed = json.loads(paths.lock_path("acme").read_text(encoding="utf-8"))
    assert granted.expires_at == armed["authorization"]["expires_at"]


def test_a_terminal_finding_cannot_be_waived(store):
    seed(store)
    store.advance("F-001", "rejected", "killed by a gate")
    with pytest.raises(WaiverError) as exc:
        grant(store)
    assert "terminal" in str(exc.value)


def test_a_parked_finding_can_be_waived_because_blocked_is_not_terminal(store):
    """The state a waivable gate now leaves its subject in has to be waivable.

    `grant()` refuses a terminal finding, and until the waivable gates parked
    rather than rejected, every route to learning which gate to waive went
    through a rejection first. `blocked` is the siding this depends on: the
    finding is alive, the gates will run on it again, and the waiver has
    something to apply to.
    """
    seed(store)
    store.advance(
        "F-001", "blocked", "no control to photograph on an unauthenticated endpoint",
        unblock_condition="a baseline evidence row, or an operator's stand-down",
    )
    granted = grant(store)
    assert granted.finding_uid == "F-001"
    assert waiver.check(store, "F-001", "gate_evidence_roles", engagement="acme").honored


def test_a_reason_carrying_a_credential_is_refused(store):
    """The reason is printed into a submitted report, so it is scanned like one."""
    from bbh import secrets

    seed(store)
    secrets.put("victim_token", "s3cret-victim-token", engagement="acme")
    with pytest.raises(WaiverError) as exc:
        grant(store, reason=f"the only observer is the token s3cret-victim-token {REASON}")
    assert "victim_token" in str(exc.value)
    assert not waiver.waiver_path("acme", "F-001", "gate_evidence_roles").exists()


# ---------------------------------------------------------------------------
# scoping: one finding, one gate
# ---------------------------------------------------------------------------


def test_a_waiver_covers_only_the_gate_it_names(store):
    seed(store)
    grant(store, gate="gate_evidence_roles")
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is True
    assert waiver.check(store, "F-001", "gate_independent_verification").honored is False


def test_a_waiver_covers_only_the_finding_it_names(store):
    seed(store)
    seed(store, uid="F-002")
    grant(store, "F-001")
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is True
    assert waiver.check(store, "F-002", "gate_evidence_roles").honored is False


def test_a_waiver_copied_onto_another_findings_name_is_not_honored(store):
    """Renaming the file does not re-scope it: the scope is inside the signature."""
    seed(store)
    seed(store, uid="F-002")
    grant(store, "F-001")
    source = waiver.waiver_path("acme", "F-001", "gate_evidence_roles")
    target = waiver.waiver_path("acme", "F-002", "gate_evidence_roles")
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    status = waiver.check(store, "F-002", "gate_evidence_roles")
    assert status.honored is False
    assert "scoped to something else" in " ".join(status.problems)


def test_a_waiver_from_another_engagement_is_not_honored(store):
    from conftest import write_engagement

    seed(store)
    write_engagement("other")
    grant(store)
    source = waiver.waiver_path("acme", "F-001", "gate_evidence_roles")
    target = waiver.waiver_path("other", "F-001", "gate_evidence_roles")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    status = waiver.check(store, "F-001", "gate_evidence_roles", engagement="other")
    assert status.honored is False
    assert "scoped to something else" in " ".join(status.problems)


def test_with_no_engagement_selected_nothing_is_honored(store):
    """A question that cannot be answered is answered 'no', with the reason."""
    seed(store)
    grant(store)
    paths.ACTIVE_FILE.unlink()
    status = waiver.check(store, "F-001", "gate_evidence_roles")
    assert status.honored is False
    assert "bb use <engagement>" in " ".join(status.problems)


# ---------------------------------------------------------------------------
# staleness
# ---------------------------------------------------------------------------


def test_an_expired_waiver_is_not_a_silent_pass(store):
    seed(store)
    granted = grant(store, hours=1)
    late = "2099-01-01T00:00:00Z"
    status = waiver.check(store, "F-001", "gate_evidence_roles", now=late)
    assert status.honored is False
    assert granted.expires_at in " ".join(status.problems)
    assert "bb gate waive F-001 gate_evidence_roles" in " ".join(status.problems)


def test_reclassifying_the_finding_voids_the_waiver(store):
    """The operator argued about a reflected XSS, not about whatever this is now."""
    seed(store, vuln_class="xss")
    grant(store)
    store.update_finding("F-001", vuln_class="idor")

    status = waiver.check(store, "F-001", "gate_evidence_roles")
    assert status.honored is False
    problems = " ".join(status.problems)
    assert "vuln_class 'xss' -> 'idor'" in problems
    assert "bb finding show F-001" in problems


def test_moving_the_finding_to_another_asset_voids_the_waiver(store):
    seed(store)
    grant(store)
    store.update_finding("F-001", endpoint="/api/admin/export")
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is False


def test_changing_the_evidence_set_voids_the_waiver(store):
    """The premise was 'the artifact cannot exist'. New artifacts re-open it."""
    seed(store)
    grant(store)
    extra = store.add_request(
        source="client",
        actor="victim",
        method="GET",
        url="https://www.acme.example/api/docs/2",
        host="www.acme.example",
        path="/api/docs/2",
        status=200,
    )
    store.add_evidence("F-001", "request", request_id=extra, role="verification")

    status = waiver.check(store, "F-001", "gate_evidence_roles")
    assert status.honored is False
    assert "evidence set changed" in " ".join(status.problems)


def test_rewording_the_prose_does_not_void_the_waiver(store):
    """Over-strictness is how a control gets deleted; a typo fix is not a new bug."""
    seed(store)
    grant(store)
    store.update_finding(
        "F-001",
        title="Stored XSS in the public profile renderer",
        summary="rewritten for the report",
        severity="medium",
    )
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is True


def test_advancing_the_finding_does_not_void_the_waiver(store):
    """A waiver exists to let a blocked finding move; moving must not void it."""
    seed(store)
    grant(store)
    store.advance("F-001", "validated")
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is True


# ---------------------------------------------------------------------------
# revoking
# ---------------------------------------------------------------------------


def test_revoking_removes_the_waiver_and_records_who_did_it(store):
    seed(store)
    granted = grant(store)
    removed, audited = waiver.revoke(store, "acme", "F-001", "gate_evidence_roles",
                                     revoked_by=OPERATOR)
    assert removed.waiver_id == granted.waiver_id
    assert audited is True
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is False
    assert [r["revoked_by"] for r in audit_lines() if r.get("action") == "unwaive"] == [OPERATOR]


def test_a_waiver_is_taken_away_even_when_the_audit_log_fails(store, monkeypatch):
    """Revoking is the strict direction; refusing would leave the hole standing."""
    seed(store)
    grant(store)
    monkeypatch.setattr("bbh.cli.audit_record", lambda *a, **kw: False)

    _removed, audited = waiver.revoke(store, "acme", "F-001", "gate_evidence_roles",
                                      revoked_by=OPERATOR)
    assert audited is False  # the caller is told, so it can warn
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is False


def test_revoking_something_that_was_never_granted_refuses(store):
    seed(store)
    with pytest.raises(WaiverError, match="nothing to revoke"):
        waiver.revoke(store, "acme", "F-001", "gate_evidence_roles", revoked_by=OPERATOR)


def test_an_anonymous_revocation_is_refused(store):
    seed(store)
    grant(store)
    with pytest.raises(WaiverError, match="no name was given"):
        waiver.revoke(store, "acme", "F-001", "gate_evidence_roles", revoked_by="")
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is True


# ---------------------------------------------------------------------------
# listing
# ---------------------------------------------------------------------------


def test_the_listing_shows_live_and_dead_waivers_with_their_reasons(store):
    seed(store)
    seed(store, uid="F-002")
    grant(store, "F-001")
    grant(store, "F-002", gate="gate_independent_verification")
    store.update_finding("F-002", vuln_class="idor")

    rows = {s.gate: s for s in waiver.listing(store, "acme")}
    assert rows["gate_evidence_roles"].honored is True
    assert rows["gate_independent_verification"].honored is False
    assert "vuln_class" in " ".join(rows["gate_independent_verification"].problems)


def test_the_listing_reports_a_waiver_file_with_no_grant_in_the_log(store):
    """Detection, not enforcement: see the module docstring on why check() ignores it."""
    seed(store)
    grant(store)
    paths.AUDIT_LOG.write_text("", encoding="utf-8")

    only = waiver.listing(store, "acme")[0]
    assert "no grant of this waiver" in " ".join(only.notes)
    # A note, not a problem: the waiver still stands, and the operator is told to look.
    assert only.problems == []
    assert only.honored is True
    assert waiver.check(store, "F-001", "gate_evidence_roles").honored is True


def test_a_file_named_for_an_unwaivable_gate_is_listed_as_never_honorable(store):
    seed(store)
    root = waiver.waivers_dir("acme")
    root.mkdir(parents=True, exist_ok=True)
    (root / "F-001.gate_in_scope.json").write_text("{}", encoding="utf-8")

    only = waiver.listing(store, "acme")[0]
    assert only.honored is False
    assert "would ever honor" in " ".join(only.problems)


def test_listing_an_engagement_with_no_waivers_is_empty(store):
    seed(store)
    assert waiver.listing(store, "acme") == []


# ---------------------------------------------------------------------------
# display: waived is never pass
# ---------------------------------------------------------------------------


def test_a_waived_gate_row_displays_as_waived_not_pass(store):
    seed(store)
    granted = grant(store)
    store.record_gate(
        "F-001", "gate_evidence_roles", "pass", "stood down", waiver.stamp_for(granted)
    )
    store.record_gate("F-001", "gate_repro_present", "pass", "three numbered steps")
    store.record_gate("F-001", "gate_not_duplicate", "fail", "collides with F-009")

    verdicts = {r["gate"]: waiver.gate_verdict(r) for r in store.gates_for("F-001")}
    assert verdicts == {
        "gate_evidence_roles": "waived",
        "gate_repro_present": "pass",
        "gate_not_duplicate": "fail",
    }


def test_the_waived_label_survives_the_waiver_being_revoked(store):
    """Relabelling history as a plain pass is exactly the silent pass to avoid."""
    seed(store)
    granted = grant(store)
    store.record_gate(
        "F-001", "gate_evidence_roles", "pass", "stood down", waiver.stamp_for(granted)
    )
    waiver.revoke(store, "acme", "F-001", "gate_evidence_roles", revoked_by=OPERATOR)

    row = [r for r in store.gates_for("F-001") if r["gate"] == "gate_evidence_roles"][-1]
    assert waiver.gate_verdict(row) == "waived"


def test_the_report_says_which_gate_was_waived_by_whom_and_why(store):
    seed(store)
    granted = grant(store)
    store.record_gate(
        "F-001", "gate_evidence_roles", "pass", "stood down", waiver.stamp_for(granted)
    )
    text = "\n".join(waiver.report_lines(store, "F-001"))

    assert "gate_evidence_roles" in text
    assert OPERATOR in text
    assert REASON in text
    assert "not a passed gate" in text
    assert granted.expires_at in text


def test_the_report_warns_when_the_waiver_a_pass_leaned_on_has_lapsed(store):
    seed(store)
    granted = grant(store, hours=1)
    store.record_gate(
        "F-001", "gate_evidence_roles", "pass", "stood down", waiver.stamp_for(granted)
    )
    text = "\n".join(waiver.report_lines(store, "F-001", now="2099-01-01T00:00:00Z"))

    assert "no longer stands" in text
    assert "Do not submit" in text
    assert "bb gate F-001" in text


def test_a_finding_with_nothing_waived_adds_nothing_to_its_report(store):
    seed(store)
    store.record_gate("F-001", "gate_evidence_roles", "pass", "earned it")
    assert waiver.report_lines(store, "F-001") == []


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------


def test_waivers_live_outside_the_directory_the_agent_is_handed(store):
    """`runner.run_phase` --add-dirs the engagement directory. This is not in it."""
    seed(store)
    grant(store)
    path = waiver.waiver_path("acme", "F-001", "gate_evidence_roles")
    assert paths.engagement_dir("acme") not in path.parents
    assert paths.STATE_DIR in path.parents


def test_a_finding_uid_that_is_not_a_safe_filename_is_refused(store):
    store.add_finding("../../etc/passwd", "Traversal via uid", "xss")
    with pytest.raises(WaiverError, match="not a safe filename"):
        grant(store, "../../etc/passwd")


def test_a_gate_asking_about_an_unsafe_uid_gets_an_answer_not_a_crash(store):
    """check() is called from inside a gate; it must never abort the hunt."""
    store.add_finding("bad/uid", "Odd uid", "xss")
    status = waiver.check(store, "bad/uid", "gate_evidence_roles")
    assert status.honored is False
    assert "not a safe filename" in " ".join(status.problems)


def test_waiving_an_unknown_finding_refuses(store):
    with pytest.raises(WaiverError, match="no finding"):
        grant(store, "F-404")


def test_the_subject_fingerprint_is_recomputed_not_stored_by_a_caller(store):
    """Nothing a model wrote decides whether a waiver still applies."""
    seed(store)
    before = waiver.subject_of(store, "F-001")
    store.update_finding("F-001", summary="a model rewrote this")
    assert waiver.subject_of(store, "F-001") == before
    store.update_finding("F-001", host="other.acme.example")
    assert waiver.subject_of(store, "F-001") != before


def test_a_waiver_whose_finding_is_gone_is_listed_rather_than_crashing(store):
    """A recreated database leaves orphan files; `bb gate waivers` must still run."""
    seed(store)
    grant(store)
    store.conn.execute("DELETE FROM findings WHERE uid = 'F-001'")
    store.conn.commit()

    only = waiver.listing(store, "acme")[0]
    assert only.honored is False
    assert "no finding" in " ".join(only.problems)
