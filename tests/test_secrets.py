"""Secret indirection and leak scanning.

A credential has one home, so these tests are about the ways it could leave it:
a request kwarg that was never resolved, a report that quotes the value, a
transcript, a world-readable raw/ tree. The refusals matter as much as the
substitutions -- an unresolvable reference must stop the request rather than be
sent as the literal string `secret://attacker`.
"""

from __future__ import annotations

import json
import types
from base64 import b64encode
from urllib.parse import quote

import pytest

from bbh import http, paths, secrets
from bbh.report import ReportError, render
from conftest import (
    VALIDATED_FIELDS,
    make_scope,
    record_gate_passes,
    seed_access_control_finding,
)

VALUE = "s3cr3t-session-token-9f2a"


@pytest.fixture
def recorded(engagement) -> str:
    """One secret on disk, the way `bb secret put` leaves it."""
    return secrets.put("attacker-session", VALUE, engagement=engagement)


# ---------------------------------------------------------------------------
# recording
# ---------------------------------------------------------------------------


def test_put_returns_the_reference_an_agent_writes(engagement):
    assert secrets.put("attacker-session", VALUE) == "secret://attacker-session"


def test_the_store_and_its_directory_are_not_readable_by_other_accounts(recorded, engagement):
    path = secrets.secrets_file(engagement)
    assert path.stat().st_mode & 0o777 == 0o600, "the value file must be 0600"
    assert path.parent.stat().st_mode & 0o777 == 0o700, "sensitive/ must be 0700"
    assert json.loads(path.read_text())["secrets"]["attacker-session"]["value"] == VALUE


def test_a_value_too_short_to_scan_for_is_refused(engagement):
    """Fail closed at the one boundary where it can still be fixed: a value the
    scanner cannot distinguish from prose would make it flag everything."""
    with pytest.raises(secrets.SecretError, match="shorter than"):
        secrets.put("pin", "abc")


def test_a_reference_cannot_be_stored_as_a_value(engagement):
    with pytest.raises(secrets.SecretError, match="is a reference, not a value"):
        secrets.put("loop", "secret://loop")


def test_an_unusable_label_names_the_command_that_works(engagement):
    with pytest.raises(secrets.SecretError, match="bb secret put"):
        secrets.put("not a label", VALUE)


def test_a_missing_label_is_a_remedy_not_a_placeholder(recorded, engagement):
    with pytest.raises(secrets.SecretError) as exc:
        secrets.get("victim-session")
    message = str(exc.value)
    assert "bb secret put victim-session" in message
    assert "attacker-session" in message, "it should say which labels do exist"
    assert VALUE not in message, "a refusal must not print the value it does hold"


def test_list_shows_labels_and_hashes_but_never_values(recorded, engagement):
    rows = secrets.entries(engagement)
    assert [r["label"] for r in rows] == ["attacker-session"]
    assert rows[0]["ref"] == "secret://attacker-session"
    assert VALUE not in json.dumps(rows)


# ---------------------------------------------------------------------------
# resolving, on the way out
# ---------------------------------------------------------------------------


def test_a_reference_inside_a_header_is_resolved(recorded, engagement):
    resolved = secrets.resolve_text("Bearer secret://attacker-session", engagement)
    assert resolved == f"Bearer {VALUE}"


def test_references_nested_in_request_kwargs_are_resolved(recorded, engagement):
    kw = {
        "headers": {"Authorization": "Bearer secret://attacker-session"},
        "json": {"creds": ["secret://attacker-session", 7], "keep": None},
        "data": b"token=secret://attacker-session",
    }
    out = secrets.resolve_sendables(kw, engagement)
    assert out["headers"]["Authorization"] == f"Bearer {VALUE}"
    assert out["json"]["creds"] == [VALUE, 7]
    assert out["data"] == f"token={VALUE}".encode()
    assert kw["headers"]["Authorization"].endswith("secret://attacker-session"), (
        "the caller's own dict must not be mutated"
    )


def test_an_unknown_reference_fails_closed(recorded, engagement):
    """Sending the literal string would authenticate as nobody and read as a
    403 from the target, which is the most expensive kind of false negative."""
    with pytest.raises(secrets.SecretError, match="no secret labelled 'typo'"):
        secrets.resolve_sendables({"headers": {"X": "secret://typo"}}, engagement)


def test_the_session_substitutes_the_value_at_send_time(recorded, engagement, monkeypatch):
    """The hook in bbh.http: the value reaches the socket and nothing else."""
    sent: dict[str, object] = {}

    def transport(method, url, **kw):
        sent.update(kw)
        raise OSError("no network in this test")

    session = http.Session(engagement, actor="anon")
    monkeypatch.setattr(
        http.Session, "_client", lambda self: types.SimpleNamespace(request=transport)
    )
    try:
        with pytest.raises(http.TransportError):
            session.request(
                "GET",
                "https://www.acme.example/api/me",
                headers={"Authorization": "Bearer secret://attacker-session"},
            )
    finally:
        session.close()

    assert sent["headers"]["Authorization"] == f"Bearer {VALUE}"


# ---------------------------------------------------------------------------
# scanning, on the way in
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "form",
    [
        VALUE,
        b64encode(VALUE.encode()).decode(),
        quote(VALUE, safe=""),
        json.dumps({"text": f"Bearer {VALUE}"}),
    ],
    ids=["raw", "base64", "percent-encoded", "json-escaped"],
)
def test_scan_text_finds_every_written_form_of_the_value(recorded, engagement, form):
    assert secrets.scan_text(f"...{form}...", engagement) == ["attacker-session"]


def test_scan_text_is_quiet_about_text_that_carries_nothing(recorded, engagement):
    assert secrets.scan_text("GET /api/me -> 200, 412 bytes", engagement) == []


def test_scan_text_with_no_store_has_nothing_to_match(engagement):
    assert secrets.scan_text(VALUE, engagement) == []


def test_an_unparseable_store_fails_closed(recorded, engagement):
    """A store that cannot be read is a store nothing can be checked against."""
    secrets.secrets_file(engagement).write_text("{not json", encoding="utf-8")
    with pytest.raises(secrets.SecretError, match="cannot read the secret store"):
        secrets.scan_text("anything", engagement)


def test_redact_swaps_the_value_for_its_reference_and_keeps_json_valid(recorded, engagement):
    line = json.dumps({"type": "assistant", "text": f"used Bearer {VALUE} to read it"})
    cleaned = secrets.redact(line, engagement)
    assert VALUE not in cleaned
    assert "secret://attacker-session" in cleaned
    assert json.loads(cleaned)["type"] == "assistant", "a stream-json line must stay parseable"


# ---------------------------------------------------------------------------
# the report boundary
# ---------------------------------------------------------------------------


@pytest.fixture
def gated(store):
    seed_access_control_finding(store)
    store.update_finding(
        "F-001",
        summary="Any authenticated account can read any document by id.",
        impact="Full disclosure of every customer document.",
        remediation="Check document ownership server-side.",
        **VALIDATED_FIELDS,
    )
    for step in ("validated", "verified", "gated"):
        store.advance("F-001", step)
    record_gate_passes(store, "F-001")
    return store.get_finding("F-001")


def test_a_report_that_quotes_a_secret_is_refused(store, gated, recorded, engagement):
    store.update_finding("F-001", repro=f"1. curl -H 'Cookie: sid={VALUE}'\n2. Read the doc.")
    with pytest.raises(ReportError) as exc:
        render(store, make_scope(), "F-001")
    message = str(exc.value)
    assert "attacker-session" in message
    assert "bb finding set" in message, "the refusal has to say how to fix the finding"
    assert VALUE not in message


def test_a_clean_report_still_renders_with_secrets_recorded(store, gated, recorded, engagement):
    assert "## Scope statement" in render(store, make_scope(), "F-001")


# ---------------------------------------------------------------------------
# the raw/ tree
# ---------------------------------------------------------------------------


def test_harden_raw_restricts_the_whole_tree(engagement):
    bodies = paths.engagement_dir(engagement) / "raw" / "bodies" / "deep"
    bodies.mkdir(parents=True, exist_ok=True)
    for directory in (bodies, bodies.parent, bodies.parent.parent):
        directory.chmod(0o755)

    root = secrets.harden_raw(engagement)

    assert root == paths.engagement_dir(engagement) / "raw"
    for directory in (root, bodies.parent, bodies):
        assert directory.stat().st_mode & 0o777 == 0o700, directory


def test_recording_a_secret_also_hardens_raw(engagement):
    raw = paths.engagement_dir(engagement) / "raw"
    raw.chmod(0o755)
    secrets.put("attacker-session", VALUE, engagement=engagement)
    assert raw.stat().st_mode & 0o777 == 0o700
