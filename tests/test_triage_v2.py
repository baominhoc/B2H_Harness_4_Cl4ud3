"""The v2 gates: the ones that decide whether a human ever sees a finding.

Every failing case here is a finding that would read well in a report. That is
deliberate: a gate that only catches a malformed record catches nothing worth
catching, because the records that reach a triager are the plausible ones. So
the fakes below are the real shapes -- severity inflated past the metrics, an
identifier the harness handed to itself, one response standing in for a
comparison, a repro step nobody ever sent, a "re-verification" that re-cites the
request it is meant to be checking.

`wire_finding` builds the complete, honest version of that finding once, and
each test knocks out exactly one leg of it, so what the gate is actually
reading is visible in the test body rather than buried in a fixture.
"""

from __future__ import annotations

import hashlib

import pytest

from bbh import runner, triage, waiver
from bbh.store import StoreError
from bbh.triage import (
    DEDUPE_MERGE_GATE,
    DEDUPE_OVERRIDE_GATE,
    DEDUPE_VERDICT_GATE,
    SHIP_GATES,
    VERIFY_GATES,
    DedupUnavailable,
    TriageError,
    adjudicate_duplicates,
    apply_gates,
    dedup_key,
    dedup_parts,
    gate_access_control_ownership,
    gate_counterevidence_recorded,
    gate_evidence_exists,
    gate_evidence_roles,
    gate_in_scope,
    gate_independent_verification,
    gate_not_duplicate,
    gate_prerequisites_reachable,
    gate_repro_cites_real_requests,
    gate_severity_derived,
    gate_severity_floor,
    gates_for_state,
    merge_findings,
    normalize_path_shape,
    record_dedupe_verdict,
    record_not_duplicate,
    refresh_dedup_key,
    review_duplicates,
    run_gates,
)
from conftest import VALIDATED_FIELDS, make_scope, seed_access_control_finding

# AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N scores 6.5, which is medium: one
# authenticated account reading another's document over the network.
IDOR_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"

REPRO = (
    "1. Sign in as the attacker and GET https://www.acme.example/api/public/invites,"
    " which lists other tenants' document ids.\n"
    "2. GET https://www.acme.example/api/docs/2 with the attacker session.\n"
    "3. Observe the document owned by victim@acme.example in the response body."
)


def wire_finding(store, *, uid="F-001", vuln_class="idor", method="GET") -> dict[str, int]:
    """The finding a hunt should produce: every leg of the proof on the record.

    One account that owns nothing, a leak that hands it the victim's id, the
    authorization break, and a second reproduction from an account registered
    later. Returns the request ids so a test can knock one leg out.
    """
    store.add_account("attacker", "attacker")
    store.add_account("attacker-v6", "attacker")  # registered in 06-verify
    store.add_account("victim", "victim")
    store.add_object("victim doc", "document", "2", "victim")

    def request(actor, verb, path, phase):
        return store.add_request(
            source="client", actor=actor, method=verb,
            url=f"https://www.acme.example{path}", host="www.acme.example",
            path=path, status=200, phase=phase,
        )

    baseline = request("victim", "GET", "/api/docs/2", "05-validate")
    leak = request("attacker", "GET", "/api/public/invites", "05-validate")
    attack = request("attacker", method, "/api/docs/2", "05-validate")
    recheck = request("attacker-v6", method, "/api/docs/2", "06-verify")

    finding_id = store.add_finding(
        uid, "Cross-account document read", vuln_class,
        host="www.acme.example", endpoint="/api/docs/2", severity="medium",
        repro=REPRO, dedup_key=f"idor:/api/docs/{{id}}:{uid}",
    )
    # The three fields `store.advance(..., "validated")` demands, which
    # `gate_counterevidence_recorded` recomputes at every rung above it. A
    # complete proof carries its own case against itself; the tests that are
    # about that gate clear them again.
    store.update_finding(uid, cvss_vector=IDOR_VECTOR, **VALIDATED_FIELDS)
    store.add_evidence(uid, "request", request_id=baseline, role="baseline")
    store.add_evidence(uid, "request", request_id=attack, role="attack")
    store.add_evidence(uid, "request", request_id=recheck, role="attack")
    store.add_prerequisite(
        uid, "document identifier 2",
        attacker_start="a free-trial account with no relationship to the victim",
        acquisition="the public invite listing returns other tenants' document ids",
        request_id=leak, verdict="reachable",
        searched="every 200 response body in the request log, grepped for the id",
    )
    # The claim is pinned, the way `run_phase` pins it before briefing 06-verify
    # and the way `bb finding freeze` does by hand. `gate_frozen_claim_intact`
    # recomputes it, so a proof built without this step is a proof whose
    # independent verification cannot be held to anything.
    runner.freeze_finding(store, uid)
    return {
        "finding": finding_id, "baseline": baseline, "leak": leak,
        "attack": attack, "recheck": recheck,
    }


def finding(store, uid="F-001"):
    return store.get_finding(uid)


# ---------------------------------------------------------------------------
# gate_severity_derived
# ---------------------------------------------------------------------------


def test_severity_derived_passes_when_the_rating_is_what_the_metrics_score(store):
    wire_finding(store)
    result = gate_severity_derived(store, finding(store))
    assert result.passed
    assert result.detail["base_score"] == 6.5
    assert result.detail["derived_severity"] == "medium"


def test_severity_derived_catches_an_inflated_rating(store):
    """The realistic fake: a real IDOR, written up as critical.

    Everything else about the finding is true. Only the number a triager reads
    first has been rounded up, which is the cheapest over-claim there is.
    """
    wire_finding(store)
    store.update_finding("F-001", severity="critical")
    result = gate_severity_derived(store, finding(store))
    assert not result.passed
    assert "does not match the metrics" in result.rationale
    assert "6.5" in result.rationale and "medium" in result.rationale
    assert "--severity medium" in result.rationale


def test_free_text_severity_is_accepted_only_below_medium(store):
    store.add_finding("F-001", "Verbose error page", "info-leak", severity="low")
    assert gate_severity_derived(store, finding(store)).passed

    store.update_finding("F-001", severity="high")
    result = gate_severity_derived(store, finding(store))
    assert not result.passed
    assert "no CVSS vector is recorded" in result.rationale
    assert "--cvss" in result.rationale


def test_a_vector_the_harness_cannot_score_fails_closed(store):
    """An unreadable vector must not fall back to the severity column."""
    wire_finding(store)
    store.update_finding("F-001", cvss_vector="CVSS:3.1/AV:N/AC:L/C:H", severity="high")
    result = gate_severity_derived(store, finding(store))
    assert not result.passed
    assert "cannot be scored" in result.rationale


def test_an_unrated_finding_with_a_vector_is_told_what_the_metrics_say(store):
    wire_finding(store)
    store.update_finding("F-001", severity=None)
    result = gate_severity_derived(store, finding(store))
    assert not result.passed
    assert "--severity medium" in result.rationale


def test_the_severity_floor_applies_to_the_derived_rating_not_the_claim(store):
    """Audit of an existing gate: where severity is recomputable, recompute it."""
    wire_finding(store)
    store.update_finding("F-001", severity="critical")
    result = gate_severity_floor(store, finding(store), floor="high")
    assert not result.passed, "6.5 is medium, whatever the column says"
    assert "below this engagement's floor" in result.rationale


# ---------------------------------------------------------------------------
# gate_prerequisites_reachable -- the highest-value quality gate
# ---------------------------------------------------------------------------


def test_prerequisites_pass_when_the_attacker_acquired_the_identifier(store):
    ids = wire_finding(store)
    result = gate_prerequisites_reachable(store, finding(store))
    assert result.passed
    assert f"request {ids['leak']}" in result.rationale


def test_prerequisites_reject_an_identifier_only_the_harness_knew(store):
    """The realistic fake, and the single most common false positive.

    The authorization break is genuine and the repro works. The id was read out
    of the victim's own session -- which is to say, out of the harness's own
    setup -- so nothing here shows an attacker could ever name the document.
    """
    ids = wire_finding(store)
    store.add_prerequisite(
        "F-001", "document identifier 2",
        acquisition="read from the victim's own document list while signed in as the victim",
        request_id=ids["baseline"], verdict="reachable",
    )
    result = gate_prerequisites_reachable(store, finding(store))
    assert not result.passed
    assert not result.blocked
    assert "not one of this engagement's attacker accounts" in result.rationale
    assert "'victim'" in result.rationale


def test_a_not_reachable_prerequisite_rejects_the_finding_naming_the_row(store):
    """The UUIDv4 case: a clean authorization break nobody can reach."""
    wire_finding(store)
    store.add_prerequisite(
        "F-001", "document identifier 2",
        verdict="not_reachable",
        searched="every response body, the sitemap, and the public API; the id is a UUIDv4",
    )
    result = gate_prerequisites_reachable(store, finding(store))
    assert not result.passed
    assert not result.blocked
    assert "'document identifier 2'" in result.rationale
    assert "not_reachable" in result.rationale
    assert "UUIDv4" in result.detail["determined"][0]


def test_a_blocked_prerequisite_parks_the_finding_and_never_rejects_it(store):
    wire_finding(store)
    store.add_prerequisite(
        "F-001", "document identifier 2", verdict="blocked",
        acquisition="the invite listing needs a second tenant and signup is behind a captcha",
    )
    result = gate_prerequisites_reachable(store, finding(store))
    assert not result.passed
    assert result.blocked
    assert "parked, not rejected" in result.rationale
    assert "not_reachable" in result.unblock


def test_a_determined_negative_outranks_an_unfinished_measurement(store):
    """One blocked row does not save a finding another row already killed."""
    wire_finding(store)
    store.add_prerequisite("F-001", "document identifier 2", verdict="not_reachable",
                           searched="the whole request log")
    store.add_prerequisite("F-001", "second tenant", verdict="blocked",
                           acquisition="signup is behind a captcha")
    result = gate_prerequisites_reachable(store, finding(store))
    assert not result.passed
    assert not result.blocked, "a traced negative is an answer; a block is not"


def test_an_access_control_finding_with_no_prerequisite_row_fails(store):
    seed_access_control_finding(store)
    result = gate_prerequisites_reachable(store, finding(store))
    assert not result.passed
    assert "no prerequisite is recorded" in result.rationale
    assert "bb prereq add" in result.rationale


def test_no_prerequisite_row_parks_rather_than_binning_the_finding(store):
    """No row is strictly less measured than a `blocked` row, which parks.

    The gate's own rule is that an unfinished measurement is not a negative.
    Rejecting here would also bin the finding that the `bb prereq add` in this
    gate's own rationale is addressed to.
    """
    seed_access_control_finding(store)
    result = gate_prerequisites_reachable(store, finding(store))
    assert result.blocked
    assert "bb prereq add F-001" in result.unblock


def test_a_class_that_needs_no_prerequisite_passes_with_none(store):
    store.add_finding("F-001", "Reflected XSS", "xss", host="www.acme.example")
    assert gate_prerequisites_reachable(store, finding(store)).passed


def test_a_reachable_claim_with_a_dangling_citation_does_not_pass(store):
    wire_finding(store)
    # The foreign key stops this through the API, so the row is orphaned the way
    # a partially restored store would be; the gate must still fail closed.
    store.conn.execute("PRAGMA foreign_keys=OFF")
    store.conn.execute("UPDATE prerequisites SET request_id = 9999 WHERE finding_id = 1")
    store.conn.execute("PRAGMA foreign_keys=ON")
    result = gate_prerequisites_reachable(store, finding(store))
    assert not result.passed
    assert "not a request in the log" in result.rationale


def test_reachability_needs_a_declared_attacker_account(store):
    """Fail closed: with nobody declared as the attacker, position is unknowable."""
    wire_finding(store)
    store.conn.execute("UPDATE accounts SET role = 'tester' WHERE role = 'attacker'")
    result = gate_prerequisites_reachable(store, finding(store))
    assert not result.passed
    assert "--role attacker" in result.rationale


# ---------------------------------------------------------------------------
# gate_access_control_ownership produces the prerequisite row
# ---------------------------------------------------------------------------


def test_the_ownership_proof_produces_the_question_it_does_not_answer(store):
    seed_access_control_finding(store)
    assert store.prerequisites_for("F-001") == []

    result = gate_access_control_ownership(store, finding(store))
    assert result.passed

    rows = store.prerequisites_for("F-001")
    assert len(rows) == 1
    assert rows[0]["name"] == "document identifier 2"
    assert rows[0]["verdict"] == "not_reachable", "nobody has traced it, so it is not reachable"
    assert "zero evidence" in rows[0]["acquisition"]
    assert rows[0]["searched"] is None, "'not found' must stay distinguishable from 'never looked'"


def test_producing_the_prerequisite_row_is_idempotent(store):
    seed_access_control_finding(store)
    gate_access_control_ownership(store, finding(store))
    gate_access_control_ownership(store, finding(store))
    assert len(store.prerequisites_for("F-001")) == 1


def test_the_producer_never_overwrites_a_verdict_somebody_traced(store):
    ids = wire_finding(store)
    result = gate_access_control_ownership(store, finding(store))
    assert result.passed
    rows = store.prerequisites_for("F-001")
    assert len(rows) == 1
    assert rows[0]["verdict"] == "reachable"
    assert rows[0]["request_id"] == ids["leak"]


def test_a_failed_ownership_proof_produces_nothing(store):
    seed_access_control_finding(store, owner="attacker")
    assert not gate_access_control_ownership(store, finding(store)).passed
    assert store.prerequisites_for("F-001") == []


def test_relabelling_the_class_does_not_escape_the_access_control_gates(store):
    """vuln_class is model-written; the traffic is the artifact.

    The realistic fake: the same cross-account read, filed as an information
    disclosure, which is the one word that makes the ownership and reachability
    questions go away if a gate takes the label at face value.
    """
    wire_finding(store, vuln_class="info-disclosure")
    store.conn.execute("DELETE FROM prerequisites")

    assert gate_access_control_ownership(store, finding(store)).passed
    assert store.prerequisites_for("F-001")[0]["verdict"] == "not_reachable"

    result = gate_prerequisites_reachable(store, finding(store))
    assert not result.passed

    roles = gate_evidence_roles(store, finding(store))
    assert "by its own traffic" in roles.detail["matched"]


# ---------------------------------------------------------------------------
# gate_evidence_roles
# ---------------------------------------------------------------------------


def test_evidence_roles_pass_with_both_sides_of_the_comparison(store):
    wire_finding(store)
    result = gate_evidence_roles(store, finding(store))
    assert result.passed
    assert result.detail["roles"]["baseline"] and result.detail["roles"]["attack"]


def test_evidence_roles_fail_when_only_the_winning_response_was_kept(store):
    """The realistic fake: the attacker's 200 saved, the control case never run.

    One response is equally consistent with a public endpoint, a shared cache,
    two names for the same account, and the bug.
    """
    wire_finding(store)
    store.conn.execute("DELETE FROM evidence WHERE role = 'baseline'")
    result = gate_evidence_roles(store, finding(store))
    assert not result.passed
    assert "--role baseline" in result.rationale
    assert "nothing shows the control working" in result.rationale


def test_one_request_cannot_be_both_sides_of_a_comparison(store):
    """An agent that relabelled the same request rather than sending another."""
    ids = wire_finding(store)
    store.conn.execute("DELETE FROM evidence")
    store.add_evidence("F-001", "request", request_id=ids["attack"], role="baseline")
    store.add_evidence("F-001", "request", request_id=ids["attack"], role="attack")
    result = gate_evidence_roles(store, finding(store))
    assert not result.passed
    assert "same request" in result.rationale


def test_a_state_changing_claim_needs_the_owner_side_observed(store):
    wire_finding(store, method="DELETE")
    result = gate_evidence_roles(store, finding(store))
    assert not result.passed
    assert "--role verification" in result.rationale
    assert "DELETE as request" in result.rationale


def test_a_verification_from_the_attackers_own_side_is_not_one(store):
    ids = wire_finding(store, method="DELETE")
    store.add_evidence("F-001", "request", request_id=ids["attack"], role="verification")
    result = gate_evidence_roles(store, finding(store))
    assert not result.passed
    assert "same side of the test" in result.rationale


def test_a_state_changing_claim_passes_with_the_owner_side_observed(store):
    ids = wire_finding(store, method="DELETE")
    gone = store.add_request(
        source="client", actor="victim", method="GET",
        url="https://www.acme.example/api/docs/2", host="www.acme.example",
        path="/api/docs/2", status=404, phase="05-validate",
    )
    store.add_evidence("F-001", "request", request_id=gone, role="verification")
    assert gate_evidence_roles(store, finding(store)).passed
    assert ids["attack"]


def test_only_a_signed_waiver_stands_a_role_requirement_down(store, engagement):
    """Replaces the gate-row waiver, which the gate's own subject could write.

    The old version of this test asserted that a `gates` row whose detail
    carried the literal `not-applicable: <reason>` stood the requirement down.
    That is a row `store.record_gate` writes, and `guard.SANCTIONED` lets an
    agent run `python3 -c 'from bbh.store import Store; ...'`, so the agent
    being refused could grant itself the waiver. The intent is unchanged --
    only a real waiver stands this down -- but the waiver is now a signed file
    under `.state/` that only `bb gate waive` writes.
    """
    wire_finding(store)
    store.conn.execute("DELETE FROM evidence WHERE role = 'baseline'")
    assert not gate_evidence_roles(store, finding(store)).passed

    # The exact row that used to work, written straight to the store.
    store.record_gate(
        "F-001", "gate_evidence_roles", "pass", "waived by the operator",
        "not-applicable: the endpoint is unauthenticated by design, so there is no control "
        "to show working",
    )
    assert not gate_evidence_roles(store, finding(store)).passed

    waiver.grant(
        store, engagement, "F-001", "gate_evidence_roles",
        reason="the endpoint is unauthenticated by design, so there is no control working "
               "to photograph and no owner side to re-read from",
        waived_by="operator@example.com",
    )
    result = gate_evidence_roles(store, finding(store))
    assert result.passed
    assert "unauthenticated by design" in result.rationale
    assert waiver.gate_verdict(
        {"verdict": "pass", "detail": result.detail}
    ) == waiver.WAIVED, "a waived gate must not display as a passed one"


def test_a_waiver_that_has_lapsed_is_named_in_the_refusal(store, engagement):
    """Silently ignoring a granted waiver sends an operator to read the code."""
    wire_finding(store)
    store.conn.execute("DELETE FROM evidence WHERE role = 'baseline'")
    waiver.grant(
        store, engagement, "F-001", "gate_evidence_roles",
        reason="the endpoint is unauthenticated by design, so there is no control working "
               "to photograph and no owner side to re-read from",
        waived_by="operator@example.com",
    )
    assert gate_evidence_roles(store, finding(store)).passed

    store.update_finding("F-001", vuln_class="xss")  # the finding they argued about moved
    result = gate_evidence_roles(store, finding(store))
    assert not result.passed
    assert "does NOT stand" in result.rationale
    assert result.detail["waiver_problems"]


def test_the_gates_own_failure_row_cannot_waive_it_on_the_next_run(store):
    """A gate must not be able to launder its own complaint into a reason."""
    wire_finding(store)
    store.conn.execute("DELETE FROM evidence WHERE role = 'baseline'")
    first = gate_evidence_roles(store, finding(store))
    store.record_gate("F-001", first.name, first.verdict, first.rationale, first.detail)
    assert not gate_evidence_roles(store, finding(store)).passed


def test_a_class_whose_proof_is_one_response_needs_no_roles(store):
    store.add_finding("F-001", "Reflected XSS", "xss", host="www.acme.example")
    assert gate_evidence_roles(store, finding(store)).passed


def test_a_role_backed_by_nothing_readable_does_not_count(store, tmp_path):
    """A row with a role is not evidence of that role unless it points at something."""
    wire_finding(store)
    store.conn.execute("DELETE FROM evidence WHERE role = 'baseline'")
    store.add_evidence("F-001", "note", caption="the control returns 403 normally",
                       role="baseline")
    assert not gate_evidence_roles(store, finding(store)).passed

    artifact = tmp_path / "baseline.txt"
    artifact.write_text("HTTP/1.1 403 Forbidden\n")
    store.add_evidence("F-001", "file", path=artifact, role="baseline")
    assert gate_evidence_roles(store, finding(store)).passed


# ---------------------------------------------------------------------------
# gate_repro_cites_real_requests -- the anti-hallucination control
# ---------------------------------------------------------------------------


def test_a_repro_built_from_the_log_passes(store):
    wire_finding(store)
    result = gate_repro_cites_real_requests(store, finding(store))
    assert result.passed
    assert "/api/public/invites" in result.detail["repro_urls"][0]


def test_an_endpoint_the_harness_never_requested_is_flagged_as_fabrication(store):
    """The realistic fake: a true finding with one invented escalation step.

    Steps 1 and 2 happened. Step 3 is the sentence that sells the report, and
    nothing in the request log corresponds to it.
    """
    wire_finding(store)
    store.update_finding(
        "F-001",
        repro=REPRO + "\n4. GET https://www.acme.example/api/admin/users to dump every account.",
    )
    result = gate_repro_cites_real_requests(store, finding(store))
    assert not result.passed
    assert "FABRICATION FLAG" in result.rationale
    assert "/api/admin/users" in result.rationale
    assert result.detail["unmatched_urls"] == [
        "https://www.acme.example/api/admin/users"
    ]


def test_a_host_the_harness_never_touched_is_flagged_too(store):
    wire_finding(store)
    store.update_finding(
        "F-001",
        repro=REPRO + "\n4. The same request against api.acme.example returns the same data.",
    )
    result = gate_repro_cites_real_requests(store, finding(store))
    assert not result.passed
    assert "FABRICATION FLAG" in result.rationale
    assert result.detail["unmatched_hosts"] == ["api.acme.example"]


def test_a_query_string_in_the_steps_is_not_a_mismatch(store):
    """Matching is host and path; a tracking parameter is not a fabrication."""
    wire_finding(store)
    store.update_finding(
        "F-001",
        repro=(
            "1. GET https://www.acme.example/api/public/invites?page=1 as the attacker.\n"
            "2. GET https://www.acme.example/api/docs/2?format=json with the attacker session.\n"
            "3. The victim's document comes back."
        ),
    )
    assert gate_repro_cites_real_requests(store, finding(store)).passed


def test_a_researcher_owned_callback_host_is_not_a_fabrication(store):
    """A blind finding has to name infrastructure the harness never requests."""
    wire_finding(store)
    store.update_finding(
        "F-001",
        repro=REPRO + "\n4. The callback arrives at abc123.oast.example within a second.",
    )
    scope = make_scope(rules={"oob_hosts": ["oast.example"]})
    assert not gate_repro_cites_real_requests(store, finding(store)).passed
    assert gate_repro_cites_real_requests(store, finding(store), scope).passed


def test_a_finding_with_no_linked_traffic_at_all_is_flagged(store):
    store.add_finding(
        "F-001", "Cross-account document read", "idor", host="www.acme.example", repro=REPRO,
    )
    result = gate_repro_cites_real_requests(store, finding(store))
    assert not result.passed
    assert "FABRICATION FLAG" in result.rationale
    assert "no recorded request is linked" in result.rationale


def test_steps_with_nothing_to_reconcile_fail_closed(store):
    wire_finding(store)
    store.update_finding("F-001", repro=None)
    result = gate_repro_cites_real_requests(store, finding(store))
    assert not result.passed
    assert "no reproduction steps" in result.rationale


# ---------------------------------------------------------------------------
# gate_independent_verification
# ---------------------------------------------------------------------------


def test_independent_verification_passes_on_fresh_later_traffic(store):
    ids = wire_finding(store)
    result = gate_independent_verification(store, finding(store))
    assert result.passed
    assert result.detail["verification_request_id"] == ids["recheck"]
    assert ids["attack"] in result.detail["earlier_request_ids"]


def test_replaying_a_cited_request_is_not_a_verification(store):
    """The realistic fake: 06-verify "re-confirms" by citing 05-validate's request.

    The report then says two phases agreed, when one response was read twice.
    """
    ids = wire_finding(store)
    store.conn.execute("DELETE FROM evidence WHERE request_id = ?", (ids["recheck"],))
    store.add_evidence("F-001", "request", request_id=ids["attack"], role="attack")
    result = gate_independent_verification(store, finding(store))
    assert not result.passed
    assert "already cited" in result.rationale
    assert "read twice" in result.rationale


def test_a_single_reproduction_is_not_an_independent_one(store):
    wire_finding(store)
    store.conn.execute("DELETE FROM evidence WHERE role = 'attack' AND id = 3")
    result = gate_independent_verification(store, finding(store))
    assert not result.passed
    assert "only attack reproduction" in result.rationale


def test_older_traffic_dressed_up_as_the_re_test_is_refused(store):
    """A sweep request from an earlier phase is not a later verification."""
    ids = wire_finding(store)
    store.conn.execute("DELETE FROM evidence WHERE request_id = ?", (ids["recheck"],))
    old = store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://www.acme.example/api/docs/2", host="www.acme.example",
        path="/api/docs/2", status=200, phase="02-sweep",
    )
    store.conn.execute("UPDATE requests SET ts = '2020-01-01T00:00:00Z' WHERE id = ?", (old,))
    store.add_evidence("F-001", "request", request_id=old, role="attack")
    result = gate_independent_verification(store, finding(store))
    assert not result.passed
    assert "not later than every request already cited" in result.rationale


def test_a_finding_with_no_attack_role_cannot_be_verified(store):
    wire_finding(store)
    store.conn.execute("UPDATE evidence SET role = 'context' WHERE role = 'attack'")
    result = gate_independent_verification(store, finding(store))
    assert not result.passed
    assert "--role attack" in result.rationale


# ---------------------------------------------------------------------------
# audit of the v1 gates: no gate trusts what it could recompute
# ---------------------------------------------------------------------------


def test_evidence_that_only_cites_a_missing_request_is_not_evidence(store):
    """A citation is an artifact: resolve it, or it is a note with a number on it."""
    seed_access_control_finding(store)
    store.conn.execute("PRAGMA foreign_keys=OFF")
    store.conn.execute("DELETE FROM requests WHERE id = 1")
    store.conn.execute("PRAGMA foreign_keys=ON")
    result = gate_evidence_exists(store, finding(store))
    assert not result.passed
    assert "not in the requests table" in result.rationale


def test_in_scope_checks_the_traffic_as_well_as_the_claimed_host(store):
    """The finding names an in-scope asset; its proof was gathered elsewhere."""
    wire_finding(store)
    stray = store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://evil.example/api/docs/2", host="evil.example",
        path="/api/docs/2", status=200, phase="05-validate",
    )
    store.add_evidence("F-001", "request", request_id=stray, role="context")
    result = gate_in_scope(make_scope(), finding(store), store)
    assert not result.passed
    assert "traffic the program did not authorize" in result.rationale
    assert "evil.example" in result.rationale


def test_in_scope_still_passes_when_every_cited_request_is_in_scope(store):
    wire_finding(store)
    result = gate_in_scope(make_scope(), finding(store), store)
    assert result.passed
    assert len(result.detail["requests_checked"]) == 4


@pytest.mark.parametrize("state", ["candidate", "validated", "verified", "gated", "ready"])
def test_no_verdict_depends_on_the_findings_state(store, state):
    """State is what gates produce. A finding that gates itself is not gated."""
    wire_finding(store)
    baseline = {r.name: r.verdict for r in run_gates(store, make_scope(), "F-001", SHIP_GATES)}

    store.conn.execute("UPDATE findings SET state = ? WHERE uid = 'F-001'", (state,))
    assert {
        r.name: r.verdict for r in run_gates(store, make_scope(), "F-001", SHIP_GATES)
    } == baseline


# ---------------------------------------------------------------------------
# gate_counterevidence_recorded -- the `validated` bar, carried upward
#
# The hole this closes: `store.advance` asks for counterevidence, a confidence
# rating and what would change the severity only when a finding enters
# `validated`, and `apply_gates` can enter `gated` straight from `candidate`.
# Every finding `bb gate` moved skipped the rung, so the bar had never run on
# the path to a report.
# ---------------------------------------------------------------------------


def strip_validated_fields(store, uid="F-001"):
    store.update_finding(
        uid, counterevidence=None, severity_change_conditions=None,
        confidence=None, confidence_rationale=None,
    )


def test_the_bar_passes_a_finding_that_argued_against_itself(store):
    wire_finding(store)
    result = gate_counterevidence_recorded(store, finding(store))
    assert result.passed
    assert result.detail["confidence"] == "high"


def test_the_bar_names_all_three_missing_fields_in_one_refusal(store):
    """One round trip: an agent should not have to run the gate three times."""
    wire_finding(store)
    strip_validated_fields(store)
    result = gate_counterevidence_recorded(store, finding(store))
    assert not result.passed
    assert "counterevidence is empty" in result.rationale
    assert "severity_change_conditions is empty" in result.rationale
    assert "confidence is not set" in result.rationale
    for flag in ("--counterevidence", "--severity-change-conditions", "--confidence-rationale"):
        assert f"bb finding set F-001 {flag}" in result.rationale


def test_the_bar_parks_rather_than_binning_an_unargued_claim(store):
    """An unwritten sentence is not a demonstration that the bug is absent."""
    wire_finding(store)
    strip_validated_fields(store)
    result = gate_counterevidence_recorded(store, finding(store))
    assert result.blocked
    assert "bb finding set F-001 --counterevidence" in result.unblock


def test_the_bar_rejects_stub_counterevidence_the_same_way_the_store_does(store):
    wire_finding(store)
    store.update_finding("F-001", counterevidence="None found.")
    result = gate_counterevidence_recorded(store, finding(store))
    assert not result.passed
    assert "non-answer" in result.rationale


def test_a_high_confidence_claim_owes_no_rationale_but_a_medium_one_does(store):
    wire_finding(store)
    store.update_finding("F-001", confidence="medium", confidence_rationale=None)
    assert not gate_counterevidence_recorded(store, finding(store)).passed

    store.update_finding("F-001", confidence_rationale="the id may be a guessable sequence")
    assert gate_counterevidence_recorded(store, finding(store)).passed


# Every shape varies one leg of a complete record, so a gate that stopped
# checking any single field disagrees with the store on exactly one row here.
# A matrix that knocked out several legs at once would stay in agreement
# through the remaining ones and pin nothing.
BAR_SHAPES: tuple[dict[str, str], ...] = (
    {},
    dict(VALIDATED_FIELDS),
    {k: v for k, v in VALIDATED_FIELDS.items() if k != "counterevidence"},
    {k: v for k, v in VALIDATED_FIELDS.items() if k != "severity_change_conditions"},
    {k: v for k, v in VALIDATED_FIELDS.items() if k != "confidence"},
    dict(VALIDATED_FIELDS, counterevidence="None found; the endpoint is simply broken."),
    dict(VALIDATED_FIELDS, counterevidence="too short to argue anything"),
    dict(VALIDATED_FIELDS, confidence="low"),
    dict(VALIDATED_FIELDS, confidence="medium"),
    dict(VALIDATED_FIELDS, confidence="low", confidence_rationale="one response, one account"),
)


def test_the_gate_and_the_state_machine_cannot_disagree_about_the_bar(store):
    """Two copies of one rule would drift, and a drift is a hole in whichever
    copy is laxer. This pins them together over every shape of the record.

    One finding per shape, because `advance` is the second half of the
    comparison and it is a write: reusing one row would measure the shapes in
    the order they happened to be listed.
    """
    outcomes = []
    for index, fields in enumerate(BAR_SHAPES):
        uid = f"F-{index:03d}"
        wire_finding(store, uid=uid)
        strip_validated_fields(store, uid)
        store.update_finding(uid, **fields)

        gate_passed = gate_counterevidence_recorded(store, finding(store, uid)).passed
        try:
            store.advance(uid, "validated")
        except StoreError:
            store_passed = False
        else:
            store_passed = True
        assert gate_passed is store_passed, f"{uid} {fields}"
        outcomes.append(gate_passed)

    # A matrix that only ever fails would pin nothing: the laxer copy has to be
    # exercised in both directions.
    assert set(outcomes) == {True, False}


def test_the_bar_reads_the_store_and_not_the_row_it_was_handed(store):
    """A gate that judged its argument would judge whatever the caller composed."""
    wire_finding(store)
    strip_validated_fields(store)
    composed = dict(finding(store))
    composed.update(VALIDATED_FIELDS)

    assert not gate_counterevidence_recorded(store, composed).passed


def test_the_bar_refuses_a_finding_the_store_does_not_have(store):
    """Fail closed: no answer is not a pass."""
    wire_finding(store)
    row = dict(finding(store))
    row["id"] = 9999
    row["uid"] = "F-404"
    result = gate_counterevidence_recorded(store, row)
    assert result.blocked
    assert "cannot answer" in result.rationale


def test_the_bar_guards_every_rung_above_validated_but_not_validated_itself(store):
    """At `validated` the state machine is the authority; above it, nobody was."""
    assert "gate_counterevidence_recorded" not in gates_for_state("validated")
    for rung in ("verified", "gated", "ready"):
        assert "gate_counterevidence_recorded" in gates_for_state(rung)


def test_the_full_set_parks_a_finding_nobody_argued_against(store):
    """The reproduction: 13/13 gates and a report, with counterevidence NULL."""
    wire_finding(store)
    strip_validated_fields(store)
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is False
    row = store.get_finding("F-001")
    assert row["state"] == "blocked"
    assert row["reject_reason"] is None
    assert "counterevidence is empty" in row["blocked_reason"]
    assert "bb finding set F-001 --counterevidence" in row["unblock_condition"]


def test_a_finding_parked_on_the_bar_ships_once_it_is_argued(store):
    wire_finding(store)
    strip_validated_fields(store)
    apply_gates(store, make_scope(), "F-001", SHIP_GATES)
    assert store.get_finding("F-001")["state"] == "blocked"

    store.update_finding("F-001", **VALIDATED_FIELDS)
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is True
    assert store.get_finding("F-001")["state"] == "gated"


def test_the_bar_is_recomputed_on_every_run_not_read_off_the_state(store):
    """Climbing the rung once is not permission to empty the fields afterwards."""
    wire_finding(store)
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is True
    assert store.get_finding("F-001")["state"] == "gated"

    strip_validated_fields(store)
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is False
    assert store.get_finding("F-001")["state"] == "blocked"


def test_the_bar_is_not_waivable(store):
    assert "gate_counterevidence_recorded" in waiver.UNWAIVABLE
    assert "gate_counterevidence_recorded" not in waiver.WAIVABLE


# ---------------------------------------------------------------------------
# the gate sets and apply_gates
# ---------------------------------------------------------------------------


def test_the_ship_set_contains_every_verified_check(store):
    """apply_gates can take a candidate straight to gated, so skipping a rung
    must not skip the checks that rung carried."""
    assert set(VERIFY_GATES) <= set(SHIP_GATES)
    assert set(triage.DEFAULT_GATES) <= set(SHIP_GATES)
    assert set(SHIP_GATES) == set(triage.GATES)


def test_every_gate_in_a_published_set_is_in_the_registry():
    for gates in (triage.DEFAULT_GATES, VERIFY_GATES, SHIP_GATES, *triage.GATES_FOR_STATE.values()):
        assert set(gates) <= set(triage.GATES)


def test_the_ownership_gate_runs_before_the_prerequisite_gate_it_feeds():
    for gates in (VERIFY_GATES, SHIP_GATES):
        assert gates.index("gate_access_control_ownership") < gates.index(
            "gate_prerequisites_reachable"
        )


def test_gates_for_state_refuses_a_state_it_does_not_guard():
    assert gates_for_state("verified") == triage.GATES_FOR_STATE["verified"]
    with pytest.raises(TriageError, match="guards no transition"):
        gates_for_state("candidate")


def test_the_full_set_moves_a_complete_finding_to_gated(store):
    wire_finding(store)
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is True
    assert store.get_finding("F-001")["state"] == "gated"
    recorded = {r["gate"]: r["verdict"] for r in store.gates_for("F-001")}
    assert recorded == {name: "pass" for name in SHIP_GATES}


def test_the_full_set_rejects_a_finding_that_only_passes_the_v1_gates(store):
    """The v1 bar: a real authorization break with an asserted severity, one
    response, and nobody asking how an attacker would reach it."""
    seed_access_control_finding(store)
    assert all(run_gates(store, make_scope(), "F-001"))  # the published seven

    seed_access_control_finding(store, uid="F-002")
    assert apply_gates(store, make_scope(), "F-002", SHIP_GATES) is False
    row = store.get_finding("F-002")
    assert row["state"] == "rejected"
    for gate in ("gate_severity_derived", "gate_prerequisites_reachable",
                 "gate_evidence_roles", "gate_independent_verification"):
        assert gate in row["reject_reason"]


def test_a_blocked_gate_parks_the_finding_instead_of_killing_it(store):
    wire_finding(store)
    store.add_prerequisite(
        "F-001", "document identifier 2", verdict="blocked",
        acquisition="the invite listing needs a second tenant and signup is behind a captcha",
    )
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is False
    row = store.get_finding("F-001")
    assert row["state"] == "blocked"
    assert "captcha" in row["blocked_reason"]
    assert "not_reachable" in row["unblock_condition"]
    assert row["reject_reason"] is None

    # The ledger has to say why it was parked: a block and a rejection both read
    # as "fail" in the verdict column.
    parked = [r for r in store.gates_for("F-001") if r["gate"] == "gate_prerequisites_reachable"]
    assert '"disposition": "blocked"' in parked[0]["detail"]


def test_a_parked_finding_resumes_once_the_prerequisite_is_traced(store):
    ids = wire_finding(store)
    store.add_prerequisite("F-001", "document identifier 2", verdict="blocked",
                           acquisition="signup is behind a captcha")
    apply_gates(store, make_scope(), "F-001", SHIP_GATES)
    assert store.get_finding("F-001")["state"] == "blocked"

    store.add_prerequisite("F-001", "document identifier 2", verdict="reachable",
                           request_id=ids["leak"])
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is True
    assert store.get_finding("F-001")["state"] == "gated"


def test_gating_a_transition_moves_the_finding_to_that_rung(store):
    wire_finding(store)
    assert apply_gates(
        store, make_scope(), "F-001", gates_for_state("verified"), target_state="verified"
    ) is True
    assert store.get_finding("F-001")["state"] == "verified"


def test_a_target_state_off_the_ladder_is_a_caller_bug(store):
    wire_finding(store)
    with pytest.raises(TriageError, match="rung on the ladder"):
        apply_gates(store, make_scope(), "F-001", SHIP_GATES, target_state="blocked")
    assert store.get_finding("F-001")["state"] == "candidate"


def test_a_rejected_finding_is_not_revived_by_a_later_pass(store):
    wire_finding(store)
    store.advance("F-001", "rejected", "killed by hand")
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is True
    assert store.get_finding("F-001")["state"] == "rejected"


def test_a_blocked_disposition_cannot_revive_a_terminal_finding(store):
    wire_finding(store)
    store.add_prerequisite("F-001", "document identifier 2", verdict="blocked",
                           acquisition="signup is behind a captcha")
    store.advance("F-001", "rejected", "killed by hand")
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is False
    assert store.get_finding("F-001")["state"] == "rejected"


def test_the_store_still_refuses_a_validated_transition_nobody_argued_against(store):
    """The gates do not replace the store's own bar; both have to be cleared."""
    wire_finding(store)
    store.update_finding(
        "F-001", counterevidence=None, severity_change_conditions=None, confidence=None
    )
    with pytest.raises(StoreError, match="counterevidence"):
        apply_gates(
            store, make_scope(), "F-001", gates_for_state("validated"), target_state="validated"
        )
    assert store.get_finding("F-001")["state"] == "candidate"


# ---------------------------------------------------------------------------
# a waivable gate parks its subject, because the waiver needs it alive
#
# The hole this closes: `bb gate <uid>` is the first command the gate phase
# runs and it is the only way to learn which gate is refusing, both waivable
# gates failed with a plain `fail`, `apply_gates` rejected on that, and
# `waiver.grant` refuses a terminal finding. So the waiver could only be
# granted before the one command that tells you to grant it, and the mechanism
# was dead on arrival.
# ---------------------------------------------------------------------------


def break_the_comparison(store, uid="F-001"):
    """Leave the attack on the record and remove the control it bypassed."""
    store.conn.execute("DELETE FROM evidence WHERE role = 'baseline'")
    store.conn.commit()


def test_a_waivable_gate_parks_its_subject_instead_of_binning_it(store):
    wire_finding(store)
    break_the_comparison(store)
    result = gate_evidence_roles(store, finding(store))
    assert not result.passed
    assert result.blocked
    assert "bb gate waive F-001 gate_evidence_roles" in result.unblock


def test_the_independent_verification_gate_parks_its_subject_too(store):
    wire_finding(store)
    store.conn.execute("DELETE FROM evidence WHERE id = (SELECT MAX(id) FROM evidence)")
    store.conn.commit()
    result = gate_independent_verification(store, finding(store))
    assert not result.passed
    assert result.blocked
    assert "bb gate waive F-001 gate_independent_verification" in result.unblock


def test_every_waivable_gate_parks_rather_than_rejecting(store):
    """Structural, not per-gate: a third entry in WAIVABLE inherits this.

    A gate an operator may stand down must leave its subject alive, because
    `waiver.grant` refuses a terminal finding and the gate to waive is not
    knowable until the gates have run.
    """
    wire_finding(store)
    break_the_comparison(store)
    store.conn.execute("DELETE FROM evidence WHERE role = 'attack'")
    store.conn.commit()
    results = {r.name: r for r in run_gates(store, make_scope(), "F-001", SHIP_GATES)}

    for name in waiver.WAIVABLE:
        assert name in results, f"{name} is in WAIVABLE but not in the ship set"
        assert not results[name].passed, f"{name} should be failing in this fixture"
        assert results[name].blocked, f"{name} binned its subject; a waiver needs it alive"


def test_only_waivable_gates_park_on_this_path(store):
    """The asymmetry is the point: an unwaivable gate is untouched."""
    seed_access_control_finding(store, owner="attacker")  # reaches its own object
    results = {r.name: r for r in run_gates(store, make_scope(), "F-001", SHIP_GATES)}
    ownership = results["gate_access_control_ownership"]
    assert not ownership.passed and not ownership.blocked


def test_a_finding_that_only_fails_waivable_gates_is_parked_not_rejected(store):
    wire_finding(store)
    break_the_comparison(store)
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is False
    row = store.get_finding("F-001")
    assert row["state"] == "blocked"
    assert row["reject_reason"] is None
    assert "gate_evidence_roles" in row["blocked_reason"]


def test_the_waiver_can_be_granted_after_the_gate_run_that_names_it(store, engagement):
    """The reproduction, end to end, in the order `prompts/07-gate.md` teaches."""
    wire_finding(store)
    break_the_comparison(store)

    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is False
    assert store.get_finding("F-001")["state"] == "blocked"

    # The agent's half: recorded, grants nothing, verdict is still "fail".
    waiver.request_waiver(
        store, "F-001", "gate_evidence_roles",
        reason="the endpoint answers with no credential at all, so there is no control "
               "working to photograph and no owner side to re-read from",
    )
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is False

    # The operator's half, which the rejection used to make impossible.
    waiver.grant(
        store, engagement, "F-001", "gate_evidence_roles",
        reason="the endpoint answers with no credential at all, so there is no control "
               "working to photograph and no owner side to re-read from",
        waived_by="operator@example.com",
    )
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is True
    assert store.get_finding("F-001")["state"] == "gated"

    # ... and it ships as waived, never as a pass it did not earn.
    rows = {r["gate"]: r for r in store.gates_for("F-001")}
    assert waiver.gate_verdict(rows["gate_evidence_roles"]) == waiver.WAIVED


def test_a_waiver_granted_mid_ladder_does_not_rewind_the_finding(store, engagement):
    """A parked finding resumes from the rung it was parked at, not from the floor."""
    wire_finding(store)
    apply_gates(
        store, make_scope(), "F-001", gates_for_state("verified"), target_state="verified"
    )
    assert store.get_finding("F-001")["state"] == "verified"

    break_the_comparison(store)
    apply_gates(store, make_scope(), "F-001", SHIP_GATES)
    assert store.get_finding("F-001")["blocked_from"] == "verified"

    waiver.grant(
        store, engagement, "F-001", "gate_evidence_roles",
        reason="the endpoint answers with no credential at all, so there is no control "
               "working to photograph and no owner side to re-read from",
        waived_by="operator@example.com",
    )
    assert apply_gates(store, make_scope(), "F-001", SHIP_GATES) is True
    assert store.get_finding("F-001")["state"] == "gated"


# ---------------------------------------------------------------------------
# dedupe: the key, the near misses, and who gets to say "not a duplicate"
#
# The fakes here are the two shapes a model-written dedup_key cannot catch: one
# bug written up twice with a different key each time, and one key copied onto
# two real bugs. Neither is malicious to write -- the first is what a model does
# when it wants both findings to survive, the second is what a careless one does
# in a hurry -- and the old gate passed both.
# ---------------------------------------------------------------------------

GOOD_REASON = "two separate handlers, each with its own ownership check and its own fix"


def keyed_finding(
    store,
    uid: str,
    *,
    vuln_class: str = "idor",
    path: str = "/api/docs/2",
    host: str = "www.acme.example",
    actor: str = "attacker",
    role: str | None = "attacker",
    endpoint: str | None = None,
    method: str = "GET",
) -> int:
    """The least record a dedup key can be computed from: traffic, and a route.

    Returns the request id, so a test can cite the same traffic from a second
    finding. `role=None` leaves the actor unregistered, which is what a proxy
    capture of a browser session looks like.
    """
    if role is not None:
        store.add_account(actor, role)
    route, _, query = path.partition("?")
    request_id = store.add_request(
        source="client", actor=actor, method=method,
        url=f"https://{host}{path}", host=host, path=route, query=query or None,
        status=200, phase="05-validate",
    )
    store.add_finding(
        uid, f"finding {uid}", vuln_class, host=host,
        endpoint=route if endpoint is None else endpoint,
        severity="medium", repro=REPRO,
    )
    store.add_evidence(uid, "request", request_id=request_id, role="attack")
    return request_id


def cite(store, uid: str, request_id: int, role: str = "baseline") -> None:
    store.add_evidence(uid, "request", request_id=request_id, role=role)


# ---- the key itself --------------------------------------------------------


def test_the_key_is_four_components_recomputed_from_the_traffic(store):
    keyed_finding(store, "F-001", path="/api/docs/2?include=owner")
    key = dedup_parts(store, store.get_finding("F-001"))
    assert key.vuln_class == "idor"
    assert key.path_shape == "www.acme.example/api/docs/{id}"
    assert key.param == "include"
    assert key.auth_state == "attacker"
    assert key.canonical == "idor|www.acme.example/api/docs/{id}|include|attacker"
    assert key.digest == hashlib.sha256(key.canonical.encode()).hexdigest()


def test_the_stored_column_cannot_move_the_key(store):
    """The defect, directly: two keys, one bug, and the gate used to pass both."""
    keyed_finding(store, "F-001", path="/api/docs/2")
    keyed_finding(store, "F-002", path="/api/docs/7")
    store.update_finding("F-001", dedup_key="idor:docs:read")
    store.update_finding("F-002", dedup_key="idor:documents:cross-tenant-disclosure")
    assert dedup_key(store, store.get_finding("F-001")) == dedup_key(
        store, store.get_finding("F-002")
    )
    result = gate_not_duplicate(store, store.get_finding("F-002"))
    assert not result.passed
    assert "F-001" in result.rationale


def test_a_stored_key_that_disagrees_is_reported_and_not_an_error(store):
    keyed_finding(store, "F-001")
    store.update_finding("F-001", dedup_key="whatever the model felt like")
    result = gate_not_duplicate(store, store.get_finding("F-001"))
    assert result.passed
    assert result.detail["stored_key_disagrees"] is True
    assert "was ignored" in result.rationale
    assert "--write-key" in result.rationale


def test_the_key_uses_the_account_role_so_one_bug_proven_twice_is_one_key(store):
    """06-verify re-tests from a fresh account; that must not be a second bug."""
    keyed_finding(store, "F-001", actor="attacker")
    keyed_finding(store, "F-002", actor="attacker-v6", path="/api/docs/9")
    assert dedup_parts(store, store.get_finding("F-002")).auth_state == "attacker"
    assert dedup_key(store, store.get_finding("F-001")) == dedup_key(
        store, store.get_finding("F-002")
    )


def test_the_position_is_a_set_over_the_cited_traffic_not_the_role_column(store):
    """Relabelling an evidence row must not be able to move the key."""
    keyed_finding(store, "F-001")
    store.add_account("victim", "victim")
    baseline = store.add_request(
        source="client", actor="victim", method="GET",
        url="https://www.acme.example/api/docs/2", host="www.acme.example",
        path="/api/docs/2", status=200,
    )
    cite(store, "F-001", baseline, role="baseline")
    before = dedup_parts(store, store.get_finding("F-001")).auth_state
    store.conn.execute("UPDATE evidence SET role = 'attack' WHERE request_id = ?", (baseline,))
    assert dedup_parts(store, store.get_finding("F-001")).auth_state == before == "attacker+victim"


def test_an_anonymous_attack_is_not_the_same_position_as_a_signed_in_one(store):
    keyed_finding(store, "F-001", actor="anon", role=None)
    assert dedup_parts(store, store.get_finding("F-001")).auth_state == "anon"


def test_an_unregistered_actor_keys_by_label_and_is_still_referred(store):
    """A proxy capture is `browser`, not an account; it must not ship twice."""
    keyed_finding(store, "F-001", actor="browser", role=None)
    keyed_finding(store, "F-002", path="/api/docs/5")
    assert dedup_parts(store, store.get_finding("F-001")).auth_state == "account:browser"
    result = gate_not_duplicate(store, store.get_finding("F-002"))
    assert not result.passed
    assert "auth_state differs" in result.rationale


def test_a_request_with_no_recorded_actor_is_unknown_not_anonymous(store):
    """`unknown` is the absence of a claim; `anon` is a claim about the attack."""
    store.add_request(
        source="import", method="GET", url="https://www.acme.example/api/docs/2",
        host="www.acme.example", path="/api/docs/2", status=200,
    )
    store.add_finding("F-001", "t", "idor", host="www.acme.example", endpoint="/api/docs/2")
    store.add_evidence("F-001", "request", request_id=1, role="attack")
    assert dedup_parts(store, store.get_finding("F-001")).auth_state == "unknown"


def test_parameter_names_come_from_the_traffic_and_values_do_not(store):
    keyed_finding(store, "F-001", path="/api/export?doc=2&format=pdf")
    assert dedup_parts(store, store.get_finding("F-001")).param == "doc,format"


def test_identifier_segments_collapse_and_route_segments_do_not():
    assert normalize_path_shape("/api/docs/2") == "/api/docs/{id}"
    assert normalize_path_shape("/u/550e8400-e29b-41d4-a716-446655440000") == "/u/{id}"
    assert normalize_path_shape("/f/507f1f77bcf86cd799439011") == "/f/{id}"
    assert normalize_path_shape("/o/01ARZ3NDEKTSV4RRFFQ69G5FAV") == "/o/{id}"
    # A version is part of the route, and an encoded id is still an id.
    assert normalize_path_shape("/api/v2/docs/") == "/api/v2/docs"
    assert normalize_path_shape("/api/docs/%32") == "/api/docs/{id}"
    assert normalize_path_shape("") == "/"


def test_the_shift_key_is_not_a_way_round_the_key(store):
    keyed_finding(store, "F-001", path="/api/docs/2")
    keyed_finding(store, "F-002", path="/API/Docs/7")
    assert dedup_key(store, store.get_finding("F-001")) == dedup_key(
        store, store.get_finding("F-002")
    )


def test_a_key_cannot_be_computed_without_a_resolvable_citation(store):
    store.add_finding("F-001", "t", "idor", host="www.acme.example", endpoint="/api/docs/2")
    with pytest.raises(DedupUnavailable, match="no cited request resolves") as exc:
        dedup_key(store, store.get_finding("F-001"))
    assert "bb evidence add F-001 request" in " ".join(exc.value.problems)


def test_an_endpoint_no_cited_request_hit_is_refused(store):
    """A key built from a route the harness never requested proves nothing."""
    keyed_finding(store, "F-001", path="/api/docs/2", endpoint="/api/admin/users/2")
    with pytest.raises(DedupUnavailable, match="none of the cited requests hit"):
        dedup_key(store, store.get_finding("F-001"))


def test_two_routes_and_no_endpoint_is_refused_rather_than_guessed(store):
    rid = keyed_finding(store, "F-001")
    other = store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://www.acme.example/api/invoices/4", host="www.acme.example",
        path="/api/invoices/4", status=200,
    )
    cite(store, "F-001", other, role="context")
    store.update_finding("F-001", host=None, endpoint=None)
    with pytest.raises(DedupUnavailable, match="names no route"):
        dedup_key(store, store.get_finding("F-001"))
    assert rid  # the first citation is still there; the ambiguity is the problem


def test_every_problem_with_the_record_is_reported_in_one_round_trip(store):
    store.add_finding("F-001", "t", "   ", host="www.acme.example", endpoint="/api/docs/2")
    with pytest.raises(DedupUnavailable) as exc:
        dedup_key(store, store.get_finding("F-001"))
    assert len(exc.value.problems) == 2
    assert "vuln_class is empty" in exc.value.problems[0]
    assert "no cited request resolves" in exc.value.problems[1]


# ---- what counts as ambiguous ----------------------------------------------


def test_a_relabelled_class_is_a_near_miss_not_a_second_bug(store):
    keyed_finding(store, "F-001", vuln_class="idor")
    keyed_finding(store, "F-002", vuln_class="broken-access-control", path="/api/docs/4")
    result = gate_not_duplicate(store, store.get_finding("F-002"))
    assert not result.passed
    assert "same class family" in result.rationale


def test_an_unrelated_class_on_the_same_route_is_not_referred(store):
    keyed_finding(store, "F-001", vuln_class="idor")
    keyed_finding(store, "F-002", vuln_class="xss", path="/api/docs/4")
    assert gate_not_duplicate(store, store.get_finding("F-002")).passed


def test_routes_one_segment_apart_are_a_near_miss(store):
    """One ownership check missing from one shared handler is one report."""
    keyed_finding(store, "F-001", path="/api/docs/2")
    keyed_finding(store, "F-002", path="/api/invoices/2")
    result = gate_not_duplicate(store, store.get_finding("F-002"))
    assert not result.passed
    assert "differ by one path segment" in result.rationale


def test_routes_further_apart_than_one_segment_are_two_bugs(store):
    keyed_finding(store, "F-001", path="/api/docs/2")
    keyed_finding(store, "F-002", path="/api/v1/billing/invoices/2")
    assert gate_not_duplicate(store, store.get_finding("F-002")).passed


def test_the_same_route_on_another_host_is_two_bugs(store):
    keyed_finding(store, "F-001", host="www.acme.example")
    keyed_finding(store, "F-002", host="shop.acme.example")
    assert gate_not_duplicate(store, store.get_finding("F-002")).passed


def test_a_shared_parameter_is_a_near_miss_and_a_disjoint_one_is_not(store):
    keyed_finding(store, "F-001", path="/api/search?q=a&sort=b")
    keyed_finding(store, "F-002", path="/api/search?q=c")
    assert not gate_not_duplicate(store, store.get_finding("F-002")).passed

    keyed_finding(store, "F-003", path="/api/search?page=2")
    result = gate_not_duplicate(store, store.get_finding("F-003"))
    assert [pair["other_uid"] for pair in result.detail["pairs"]] == []


def test_more_than_one_component_apart_is_distinct_without_a_judge(store):
    keyed_finding(store, "F-001", vuln_class="idor", path="/api/docs/2")
    keyed_finding(store, "F-002", vuln_class="xss", path="/api/search?q=1")
    assert gate_not_duplicate(store, store.get_finding("F-002")).passed
    assert review_duplicates(store, store.get_finding("F-002")).pairs == ()


# ---- the gate --------------------------------------------------------------


def test_the_gate_blocks_an_ambiguous_pair_rather_than_rejecting_it(store):
    """`rejected` is permanent and is the wrong word for an unanswered question."""
    seed_access_control_finding(store, uid="F-001", identifier="2")
    seed_access_control_finding(store, uid="F-002", identifier="3")
    assert apply_gates(store, make_scope(), "F-002") is False
    row = store.get_finding("F-002")
    assert row["state"] == "blocked"
    assert "F-001" in row["blocked_reason"]
    assert "bb finding dedupe F-002 --against F-001" in row["unblock_condition"]
    assert row["reject_reason"] is None
    assert store.get_finding("F-001")["state"] == "candidate"


def test_a_finding_whose_key_will_not_compute_is_named_not_silently_skipped(store):
    keyed_finding(store, "F-001")
    store.add_finding("F-002", "a candidate nobody finished", "idor")
    result = gate_not_duplicate(store, store.get_finding("F-001"))
    assert result.passed
    assert [row["uid"] for row in result.detail["not_compared"]] == ["F-002"]
    assert "not compared against F-002" in result.rationale
    # And the incomplete one is the one that cannot ship.
    assert not gate_not_duplicate(store, store.get_finding("F-002")).passed


def test_the_gate_is_blocked_when_its_own_key_will_not_compute(store):
    store.add_finding("F-001", "t", "idor")
    result = gate_not_duplicate(store, store.get_finding("F-001"))
    assert result.blocked
    assert "cannot compute a dedup key" in result.rationale


def test_refresh_writes_the_computed_key_into_the_column(store):
    keyed_finding(store, "F-001")
    store.update_finding("F-001", dedup_key="stale")
    digest = refresh_dedup_key(store, "F-001")
    assert store.get_finding("F-001")["dedup_key"] == digest
    assert not review_duplicates(store, store.get_finding("F-001")).stored_disagrees


# ---- verdicts --------------------------------------------------------------


def colliding_pair(store) -> None:
    keyed_finding(store, "F-001", path="/api/docs/2")
    keyed_finding(store, "F-002", path="/api/docs/7")


def test_only_a_distinct_verdict_clears_the_gate(store):
    colliding_pair(store)
    record_dedupe_verdict(store, "F-002", "F-001", "distinct", reason=GOOD_REASON)
    result = gate_not_duplicate(store, store.get_finding("F-002"))
    assert result.passed
    assert GOOD_REASON in result.rationale


def test_a_verdict_is_recorded_on_both_findings(store):
    colliding_pair(store)
    record = record_dedupe_verdict(store, "F-002", "F-001", "distinct", reason=GOOD_REASON)
    assert record.rows[0] and record.rows[1]
    assert gate_not_duplicate(store, store.get_finding("F-001")).passed
    for uid in ("F-001", "F-002"):
        rows = [r for r in store.gates_for(uid) if r["gate"] == DEDUPE_VERDICT_GATE]
        assert len(rows) == 1 and rows[0]["verdict"] == "pass"


def test_an_undetermined_verdict_leaves_the_gate_failing(store):
    colliding_pair(store)
    record_dedupe_verdict(
        store, "F-002", "F-001", "undetermined", reason="cannot tell from the record"
    )
    result = gate_not_duplicate(store, store.get_finding("F-002"))
    assert not result.passed
    assert "returned undetermined" in result.rationale


def test_a_duplicate_verdict_points_at_the_merge_and_does_not_transition(store):
    colliding_pair(store)
    record_dedupe_verdict(
        store, "F-002", "F-001", "duplicate",
        reason="the same missing ownership check on the same handler",
    )
    result = gate_not_duplicate(store, store.get_finding("F-002"))
    assert not result.passed
    assert "bb finding merge F-002 --into F-001" in result.rationale
    # Advisory output never moves a finding; only merge_findings does.
    assert store.get_finding("F-002")["state"] == "candidate"


def test_a_verdict_lapses_when_either_finding_changes(store):
    colliding_pair(store)
    record_dedupe_verdict(store, "F-002", "F-001", "distinct", reason=GOOD_REASON)
    assert gate_not_duplicate(store, store.get_finding("F-002")).passed

    # The pair is still a near miss, but it is not the pair that was judged.
    store.update_finding("F-001", vuln_class="broken-access-control")
    result = gate_not_duplicate(store, store.get_finding("F-002"))
    assert not result.passed
    assert "no verdict is recorded" in result.rationale


def test_a_verdict_is_refused_for_a_pair_the_harness_does_not_compute(store):
    keyed_finding(store, "F-001", path="/api/docs/2")
    keyed_finding(store, "F-002", vuln_class="xss", path="/api/search?q=1")
    with pytest.raises(TriageError, match="no collision and no near miss"):
        record_dedupe_verdict(store, "F-002", "F-001", "distinct", reason=GOOD_REASON)


def test_a_distinct_verdict_needs_a_reason_someone_can_argue_with(store):
    colliding_pair(store)
    with pytest.raises(TriageError, match="needs a reason"):
        record_dedupe_verdict(store, "F-002", "F-001", "distinct", reason="different")


def test_an_unknown_verdict_word_is_refused_with_the_three_that_exist(store):
    colliding_pair(store)
    with pytest.raises(TriageError, match="duplicate, distinct, undetermined"):
        record_dedupe_verdict(store, "F-002", "F-001", "not-a-dup", reason=GOOD_REASON)


# ---- the judge -------------------------------------------------------------


def test_only_ambiguous_pairs_reach_the_judge(store):
    keyed_finding(store, "F-001", path="/api/docs/2")
    keyed_finding(store, "F-002", path="/api/docs/7")
    keyed_finding(store, "F-003", vuln_class="xss", path="/api/search?q=1")
    seen = []

    def judge(pair):
        seen.append(pair.other_uid)
        return "distinct", GOOD_REASON

    adjudicate_duplicates(store, "F-002", judge)
    assert seen == ["F-001"]


def test_a_judge_that_raises_is_undetermined_never_distinct(store):
    colliding_pair(store)

    def judge(pair):
        raise RuntimeError("the model timed out")

    records = adjudicate_duplicates(store, "F-002", judge)
    assert [r.verdict for r in records] == ["undetermined"]
    assert "RuntimeError" in records[0].reason
    assert not gate_not_duplicate(store, store.get_finding("F-002")).passed


def test_a_judge_that_answers_something_that_is_not_a_verdict_is_undetermined(store):
    colliding_pair(store)
    records = adjudicate_duplicates(store, "F-002", lambda pair: {"opinion": "probably fine"})
    assert records[0].verdict == "undetermined"
    assert "is not one of" in records[0].reason


def test_a_judge_that_answers_distinct_with_no_reason_is_undetermined(store):
    """A verdict nobody can argue with is not a verdict."""
    colliding_pair(store)
    records = adjudicate_duplicates(store, "F-002", lambda pair: "distinct")
    assert records[0].verdict == "undetermined"
    assert not gate_not_duplicate(store, store.get_finding("F-002")).passed


def test_a_judge_is_asked_again_about_a_pair_it_could_not_decide(store):
    colliding_pair(store)
    adjudicate_duplicates(store, "F-002", lambda pair: ("undetermined", "no idea"))
    records = adjudicate_duplicates(store, "F-002", lambda pair: ("distinct", GOOD_REASON))
    assert [r.verdict for r in records] == ["distinct"]
    assert gate_not_duplicate(store, store.get_finding("F-002")).passed


def test_the_judge_sees_what_the_harness_computed_about_the_pair(store):
    colliding_pair(store)
    seen = {}

    def judge(pair):
        seen.update(
            relation=pair.relation,
            route=pair.key.path_shape,
            other_route=pair.other_key.path_shape,
            requests=pair.other_key.request_ids,
        )
        return "undetermined", "recorded what I was given"

    adjudicate_duplicates(store, "F-002", judge)
    assert seen["relation"] == "same_key"
    assert seen["route"] == seen["other_route"] == "www.acme.example/api/docs/{id}"
    assert seen["requests"] == (1,)


# ---- the operator override -------------------------------------------------


def test_the_override_clears_the_gate_and_says_it_was_an_override(store):
    colliding_pair(store)
    records = record_not_duplicate(store, "F-002", reason=GOOD_REASON)
    assert [r.gate for r in records] == [DEDUPE_OVERRIDE_GATE]
    assert gate_not_duplicate(store, store.get_finding("F-002")).passed
    # What a human reads in the report's gate table.
    row = [r for r in store.gates_for("F-002") if r["gate"] == DEDUPE_OVERRIDE_GATE][0]
    assert row["verdict"] == "pass"
    assert "operator" in row["rationale"] and GOOD_REASON in row["rationale"]


def test_the_override_can_overrule_a_judge_and_both_rows_stay(store):
    colliding_pair(store)
    record_dedupe_verdict(
        store, "F-002", "F-001", "duplicate", reason="looks like the same handler to me"
    )
    record_not_duplicate(store, "F-002", reason=GOOD_REASON)
    assert gate_not_duplicate(store, store.get_finding("F-002")).passed
    rows = [(r["gate"], r["verdict"]) for r in store.gates_for("F-002")]
    # The judge's verdict stays on the record, the override is named as one, and
    # the judge's row is superseded so the report stops warning about it.
    assert rows == [
        (DEDUPE_VERDICT_GATE, "fail"),
        (DEDUPE_OVERRIDE_GATE, "pass"),
        (DEDUPE_VERDICT_GATE, "pass"),
    ]
    assert "superseded by the dedupe_override row" in store.gates_for("F-002")[2]["rationale"]


def test_a_merge_settles_the_survivors_earlier_verdict_rows(store):
    """A report must not keep warning about a question the merge answered."""
    colliding_pair(store)
    record_dedupe_verdict(
        store, "F-002", "F-001", "undetermined", reason="cannot tell them apart"
    )
    merge_findings(store, "F-001", "F-002", reason="one handler, two write-ups of it")
    latest = {}
    for row in store.gates_for("F-002"):
        latest[row["gate"]] = row["verdict"]
    assert latest == {DEDUPE_VERDICT_GATE: "pass", DEDUPE_MERGE_GATE: "pass"}


def test_the_override_is_refused_when_there_is_nothing_to_override(store):
    keyed_finding(store, "F-001")
    with pytest.raises(TriageError, match="no unresolved duplicate question"):
        record_not_duplicate(store, "F-001", reason=GOOD_REASON)


def test_the_override_is_refused_for_a_pair_the_harness_does_not_compute(store):
    keyed_finding(store, "F-001", path="/api/docs/2")
    keyed_finding(store, "F-002", vuln_class="xss", path="/api/search?q=1")
    with pytest.raises(TriageError, match="no unresolved collision or near miss"):
        record_not_duplicate(store, "F-002", reason=GOOD_REASON, against="F-001")


def test_the_override_refuses_a_shrug(store):
    colliding_pair(store)
    with pytest.raises(TriageError, match="needs a reason"):
        record_not_duplicate(store, "F-002", reason="not a dup")


def test_the_override_covers_only_the_pairs_the_gate_reports(store):
    keyed_finding(store, "F-001", path="/api/docs/2")
    keyed_finding(store, "F-002", path="/api/docs/7")
    record_not_duplicate(store, "F-002", reason=GOOD_REASON)
    # A later finding collides with the same key and is not pre-cleared.
    keyed_finding(store, "F-003", path="/api/docs/9")
    result = gate_not_duplicate(store, store.get_finding("F-002"))
    assert not result.passed
    assert "F-003" in result.rationale


# ---- merging ---------------------------------------------------------------


def test_merge_marks_the_duplicate_and_records_both_sides(store):
    colliding_pair(store)
    result = merge_findings(
        store, "F-002", "F-001", reason="the same missing check on the documents handler"
    )
    assert result.relation == "same_key"
    assert store.get_finding("F-002")["state"] == "duplicate"
    assert "duplicate of F-001" in store.get_finding("F-002")["reject_reason"]
    assert store.get_finding("F-001")["state"] == "candidate"

    survivor = [r for r in store.gates_for("F-001") if r["gate"] == DEDUPE_MERGE_GATE][0]
    assert survivor["verdict"] == "pass"
    assert "F-002 was merged into this finding" in survivor["rationale"]
    loser = [r for r in store.gates_for("F-002") if r["gate"] == DEDUPE_MERGE_GATE][0]
    assert loser["verdict"] == "fail"


def test_merge_leaves_the_survivor_able_to_pass_the_gate(store):
    colliding_pair(store)
    merge_findings(store, "F-002", "F-001", reason="the same missing check, reached two ways")
    assert gate_not_duplicate(store, store.get_finding("F-001")).passed


def test_merge_shares_the_computed_key_so_the_pair_is_queryable(store):
    colliding_pair(store)
    result = merge_findings(store, "F-002", "F-001", reason="one handler, two write-ups of it")
    assert result.key_written
    rows = store.conn.execute(
        "SELECT uid FROM findings WHERE dedup_key = ? ORDER BY uid", (result.canonical_key,)
    ).fetchall()
    assert [r["uid"] for r in rows] == ["F-001", "F-002"]


def test_merge_records_that_the_harness_computed_two_different_bugs(store):
    """Allowed -- a shared root cause is not visible in a request log -- but logged."""
    keyed_finding(store, "F-001", path="/api/docs/2")
    keyed_finding(store, "F-002", vuln_class="xss", path="/api/search?q=1")
    result = merge_findings(
        store, "F-002", "F-001", reason="both are the same unescaped template helper"
    )
    assert result.relation == "distinct"
    assert any("rests on the reason given" in note for note in result.notes)
    assert store.get_finding("F-002")["state"] == "duplicate"


def test_merge_collects_every_refusal_in_one_message(store):
    colliding_pair(store)
    store.advance("F-001", "rejected", "killed by hand")
    with pytest.raises(TriageError) as exc:
        merge_findings(store, "F-002", "F-001", reason="dup")
    message = str(exc.value)
    assert "needs a reason" in message and "terminal" in message
    assert "bb finding merge F-002 --into F-001" in message


def test_merge_refuses_a_finding_into_itself(store):
    keyed_finding(store, "F-001")
    with pytest.raises(TriageError, match="merged into itself"):
        merge_findings(store, "F-001", "F-001", reason=GOOD_REASON)


def test_merge_refuses_to_re_merge_a_duplicate(store):
    colliding_pair(store)
    merge_findings(store, "F-002", "F-001", reason="one handler, two write-ups of it")
    with pytest.raises(TriageError, match="already marked duplicate"):
        merge_findings(store, "F-002", "F-001", reason="one handler, two write-ups of it")


def test_merge_refuses_an_unknown_finding(store):
    keyed_finding(store, "F-001")
    with pytest.raises(TriageError, match="no such finding"):
        merge_findings(store, "F-404", "F-001", reason=GOOD_REASON)


def test_merging_a_rejected_finding_keeps_why_it_was_rejected(store):
    """`advance` overwrites the reason column, and nothing else remembers it."""
    colliding_pair(store)
    store.advance("F-002", "rejected", "killed by hand")
    result = merge_findings(store, "F-002", "F-001", reason="one handler, two write-ups of it")
    row = store.get_finding("F-002")
    assert row["state"] == "duplicate"
    assert "duplicate of F-001" in row["reject_reason"]
    assert "killed by hand" in row["reject_reason"]
    assert any("kept inside the merge reason" in note for note in result.notes)
