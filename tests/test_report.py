"""Report rendering.

A report is the last place a live credential could escape and the last place a
false claim could be laundered into something a human acts on, so the tests
here are mostly about refusing to render and about re-redacting.
"""

from __future__ import annotations

import pytest

from bbh import paths
from bbh.report import ReportError, render, render_summary, write_report
from conftest import (
    VALIDATED_FIELDS,
    make_scope,
    record_gate_passes,
    seed_access_control_finding,
)


@pytest.fixture
def gated(store):
    """A finding that has passed the gates, ready to report."""
    seed_access_control_finding(store)
    store.update_finding(
        "F-001",
        summary="Any authenticated account can read any document by id.",
        impact="Full disclosure of every customer document.",
        remediation="Check document ownership server-side before returning it.",
        **VALIDATED_FIELDS,
    )
    store.advance("F-001", "validated")
    store.advance("F-001", "verified")
    store.advance("F-001", "gated")
    record_gate_passes(store, "F-001")
    return store.get_finding("F-001")


# -- refusals ----------------------------------------------------------------


def test_a_candidate_finding_is_refused(store):
    seed_access_control_finding(store)
    with pytest.raises(ReportError):
        render(store, make_scope(), "F-001")


def test_a_rejected_finding_is_refused(store):
    seed_access_control_finding(store)
    store.advance("F-001", "rejected", "no impact")
    with pytest.raises(ReportError):
        render(store, make_scope(), "F-001")


@pytest.mark.parametrize("state", ["gated", "ready"])
def test_the_reportable_states_render(store, state):
    seed_access_control_finding(store)
    store.update_finding("F-001", **VALIDATED_FIELDS)
    for step in ("validated", "verified", "gated", "ready"):
        store.advance("F-001", step)
        if step == state:
            break
    record_gate_passes(store, "F-001", state=state)
    assert render(store, make_scope(), "F-001")


def test_an_unknown_finding_is_refused(store):
    with pytest.raises(ReportError):
        render(store, make_scope(), "F-404")


def test_a_finding_whose_evidence_vanished_is_refused(store, tmp_path, gated):
    artifact = tmp_path / "proof.json"
    artifact.write_text('{"owner":"victim"}')
    store.add_evidence("F-001", "file", path=artifact)
    artifact.unlink()
    with pytest.raises(ReportError):
        render(store, make_scope(), "F-001")


def test_a_finding_whose_evidence_was_edited_is_refused(store, tmp_path, gated):
    artifact = tmp_path / "proof.json"
    artifact.write_text('{"owner":"victim"}')
    store.add_evidence("F-001", "file", path=artifact)
    artifact.write_text('{"owner":"attacker"}')
    with pytest.raises(ReportError):
        render(store, make_scope(), "F-001")


def test_a_finding_on_an_out_of_scope_asset_is_refused(store):
    """A report names an asset the program authorized, or it is not written."""
    store.add_finding(
        "F-009", "Off-scope thing", "xss", host="evil.example", severity="high",
        summary="s", impact="i",
        repro="1. Visit https://evil.example/x\n2. Observe the payload fire.",
    )
    store.update_finding("F-009", **VALIDATED_FIELDS)
    for step in ("validated", "verified", "gated"):
        store.advance("F-009", step)
    record_gate_passes(store, "F-009")
    with pytest.raises(ReportError, match="matches no in-scope rule"):
        render(store, make_scope(), "F-009")


def test_the_asset_is_taken_from_the_cited_request_when_there_is_one(store, gated):
    """url_prefix rules can only match a URL, so the request log decides the target."""
    text = render(store, make_scope(), "F-001")
    assert "https://www.acme.example/api/docs/2" in text


# -- content -----------------------------------------------------------------


def test_the_report_carries_every_contract_section(store, gated):
    text = render(store, make_scope(), "F-001")
    for heading in (
        "## Severity", "## Affected asset", "## Summary", "## Impact",
        "## Steps to reproduce", "## Evidence", "## Remediation",
        "## Scope statement", "## Harness provenance",
    ):
        assert heading in text, heading


def test_the_steps_carry_the_real_request_from_the_store(store, gated):
    text = render(store, make_scope(), "F-001")
    assert "GET /api/docs/2 HTTP/1.1" in text
    assert "request #1" in text


def test_the_scope_statement_names_the_rule_that_covers_the_asset(store, gated):
    text = render(store, make_scope(), "F-001")
    assert "## Scope statement" in text
    assert "acme.example" in text
    assert "in-scope rule" in text


def test_the_provenance_section_lists_the_gate_results(store, gated):
    store.record_gate("F-001", "gate_access_control_ownership", "pass", "cross-account read")
    text = render(store, make_scope(), "F-001")
    assert "gate_access_control_ownership" in text
    assert "cross-account read" in text


def test_the_provenance_names_the_engagement_and_request_ids(store, gated):
    text = render(store, make_scope(), "F-001")
    assert "acme" in text
    assert "#1" in text


def test_write_report_lands_under_reports(store, gated, engagement):
    path = write_report(store, make_scope(), "F-001")
    assert path == paths.engagement_dir(engagement) / "reports" / "F-001.md"
    assert path.read_text().startswith("# ")


# -- redaction ---------------------------------------------------------------


def test_a_credential_is_not_re_emitted_into_the_report(store, gated):
    """Imported or proxy traffic may not have been redacted at capture."""
    rid = store.add_request(
        source="import", actor="attacker", method="GET",
        url="https://www.acme.example/api/docs/2", host="www.acme.example",
        path="/api/docs/2", status=200,
        req_headers={"Authorization": "Bearer sk-live-SECRET"},
        resp_headers={"Set-Cookie": "sid=ANOTHERSECRET"},
    )
    store.add_evidence("F-001", "request", request_id=rid)
    text = render(store, make_scope(), "F-001")
    assert "sk-live-SECRET" not in text
    assert "ANOTHERSECRET" not in text
    assert "<redacted" in text


def test_url_userinfo_is_stripped_from_displayed_urls(store, gated):
    rid = store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://admin:hunter2@www.acme.example/api/docs/2",
        host="www.acme.example", path="/api/docs/2", status=200,
    )
    store.add_evidence("F-001", "request", request_id=rid)
    text = render(store, make_scope(), "F-001")
    assert "hunter2" not in text


# -- warnings rather than silence --------------------------------------------


def test_a_thin_report_says_so_instead_of_omitting_it(store):
    """A gated finding that is thin renders with a visible flag: the gates
    vouched for it, and a silent omission would be worse than a flagged one."""
    store.add_finding(
        "F-010", "Unrated thing", "xss", host="www.acme.example",
        summary="s", impact="i",
        repro="1. Visit https://www.acme.example/x\n2. Observe it.",
    )  # severity deliberately unset
    store.update_finding("F-010", **VALIDATED_FIELDS)
    for step in ("validated", "verified", "gated"):
        store.advance("F-010", step)
    record_gate_passes(store, "F-010")
    text = render(store, make_scope(), "F-010")
    assert "warning" in text.lower() or "not set" in text.lower()


def test_an_expired_attestation_does_not_block_a_post_engagement_report(store, gated):
    """scope.decide() denies on expiry; a report written afterwards is still true."""
    text = render(store, make_scope(hours=-1), "F-001")
    assert "## Scope statement" in text


# -- summary -----------------------------------------------------------------


def test_the_summary_renders_across_findings(store, gated):
    store.add_finding("F-002", "Reflected XSS", "xss", host="www.acme.example",
                      severity="medium")
    text = render_summary(store, make_scope())
    assert "F-001" in text
    assert "acme" in text


def test_the_summary_works_with_no_findings_at_all(store):
    assert render_summary(store, make_scope())
