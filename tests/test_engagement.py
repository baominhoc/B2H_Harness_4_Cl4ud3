"""Engagement lifecycle: create, compile, arm, disarm, select, status.

Arming is the act that turns a directory of notes into an authorization, so
the tests here are mostly about refusing to arm, and about the attestation
really reaching the lock the enforcement layers read.
"""

from __future__ import annotations

import json

import pytest
import yaml

from bbh import engagement, paths
from bbh.engagement import EngagementError
from bbh.scope import Scope


def new_engagement(name="acme", **kw):
    kw.setdefault("program_url", "https://hackerone.com/acme")
    return engagement.create(name, **kw)


# -- create ------------------------------------------------------------------


def test_create_writes_a_scope_yaml_and_the_tree():
    scope_file = new_engagement()
    assert scope_file == paths.scope_path("acme")
    assert scope_file.is_file()
    for sub in paths.ENGAGEMENT_SUBDIRS:
        assert (paths.engagement_dir("acme") / sub).is_dir(), sub


def test_the_published_template_is_valid_yaml():
    assert isinstance(yaml.safe_load(engagement.TEMPLATE_SCOPE), dict)


def test_a_created_scope_parses_and_names_its_engagement():
    new_engagement(targets=["*.acme.example"])
    doc = yaml.safe_load(paths.scope_path("acme").read_text())
    assert doc["engagement"] == "acme"
    assert doc["program_url"] == "https://hackerone.com/acme"
    assert "*.acme.example" in doc["in_scope"]


def test_the_template_documents_every_default_rule():
    doc = yaml.safe_load(engagement.TEMPLATE_SCOPE)
    from bbh.scope import DEFAULT_RULES

    assert set(doc["rules"]) == set(DEFAULT_RULES), "a new rule must reach the template"


def test_create_refuses_to_overwrite_an_existing_engagement():
    new_engagement()
    with pytest.raises(EngagementError, match="already exists"):
        new_engagement()


def test_create_refuses_a_name_that_would_escape_the_engagements_directory():
    with pytest.raises(EngagementError, match="not a usable engagement name"):
        engagement.create("../../etc", program_url="https://x/")


def test_create_refuses_a_target_that_is_not_a_scope_rule():
    with pytest.raises(EngagementError, match="not a usable scope rule"):
        new_engagement(targets=["not a host!!"])


# -- compile -----------------------------------------------------------------


def test_compile_writes_a_signed_lock_outside_the_engagement_directory():
    new_engagement(targets=["*.acme.example"])
    lock = engagement.compile_scope("acme")
    assert "sig" in lock, "an unsigned lock makes every reader fail closed"
    lock_file = paths.lock_path("acme")
    assert lock_file.is_file()
    assert paths.engagement_dir("acme") not in lock_file.parents


def test_the_compiled_lock_loads_through_the_verifying_reader():
    new_engagement(targets=["*.acme.example"])
    engagement.compile_scope("acme")
    scope = Scope.from_lock_file(paths.lock_path("acme"))
    assert scope.engagement == "acme"


def test_compile_refuses_a_scope_whose_name_disagrees_with_its_directory():
    new_engagement(targets=["*.acme.example"])
    path = paths.scope_path("acme")
    path.write_text(path.read_text().replace("engagement: acme", "engagement: other"))
    with pytest.raises(EngagementError, match="sits in the"):
        engagement.compile_scope("acme")


def test_compile_refuses_a_scope_with_no_in_scope_rules():
    new_engagement()  # no targets: in_scope is all comments
    with pytest.raises(EngagementError, match="does not compile"):
        engagement.compile_scope("acme")


def test_compile_reports_broken_yaml_as_a_remedy_not_a_traceback():
    new_engagement(targets=["*.acme.example"])
    paths.scope_path("acme").write_text("engagement: acme\n  bad: [indent\n")
    with pytest.raises(EngagementError, match="not valid YAML"):
        engagement.compile_scope("acme")


# -- arm ---------------------------------------------------------------------


def test_arm_records_the_attestation_in_scope_yaml_and_the_lock():
    new_engagement(targets=["*.acme.example"])
    engagement.compile_scope("acme")
    record = engagement.arm("acme", attested_by="Jo Tester", hours=4)

    assert record["attested_by"] == "Jo Tester"
    assert record["statement"] == (
        "I confirm I am authorized to test the assets in this scope under "
        "https://hackerone.com/acme."
    )

    doc = yaml.safe_load(paths.scope_path("acme").read_text())
    assert doc["authorization"]["attested_by"] == "Jo Tester"

    scope = Scope.from_lock_file(paths.lock_path("acme"))
    assert scope.authorization_error() is None, "the expiry must reach the lock"
    assert scope.authorization["expires_at"] == record["expires_at"]


def test_arm_keeps_the_comments_in_scope_yaml():
    """The file is mostly comments on purpose; a YAML round-trip would eat them."""
    new_engagement(targets=["*.acme.example"])
    engagement.compile_scope("acme")
    engagement.arm("acme", attested_by="Jo")
    text = paths.scope_path("acme").read_text()
    assert "# -- in_scope" in text
    assert "out_of_scope ALWAYS wins" in text


def test_arm_refuses_without_a_program_url():
    engagement.create("acme")
    with pytest.raises(EngagementError, match="no program_url"):
        engagement.arm("acme", attested_by="Jo")


def test_arm_refuses_without_an_attester():
    new_engagement(targets=["*.acme.example"])
    with pytest.raises(EngagementError, match="name of the person attesting"):
        engagement.arm("acme", attested_by="  ")


@pytest.mark.parametrize("hours", [0, -1, 10_000, "forever"])
def test_arm_refuses_an_unusable_window(hours):
    new_engagement(targets=["*.acme.example"])
    with pytest.raises(EngagementError, match="--hours"):
        engagement.arm("acme", attested_by="Jo", hours=hours)


def test_the_expiry_is_written_as_a_string_not_a_datetime():
    """PyYAML would otherwise read 2026-10-30T07:38:42Z back as a datetime."""
    new_engagement(targets=["*.acme.example"])
    engagement.arm("acme", attested_by="Jo", hours=1)
    doc = yaml.safe_load(paths.scope_path("acme").read_text())
    assert isinstance(doc["authorization"]["expires_at"], str)


def test_arming_twice_replaces_rather_than_stacks_the_block():
    new_engagement(targets=["*.acme.example"])
    engagement.arm("acme", attested_by="First", hours=1)
    engagement.arm("acme", attested_by="Second", hours=1)
    text = paths.scope_path("acme").read_text()
    assert text.count("attested_by:") == 1
    assert "Second" in text and "First" not in text


# -- disarm ------------------------------------------------------------------


def test_disarm_makes_every_layer_deny_again():
    new_engagement(targets=["*.acme.example"])
    engagement.arm("acme", attested_by="Jo", hours=1)
    assert Scope.from_lock_file(paths.lock_path("acme")).authorization_error() is None

    engagement.disarm("acme")
    scope = Scope.from_lock_file(paths.lock_path("acme"))
    assert scope.authorization_error() is not None
    assert not scope.decide("www.acme.example").allowed


# -- use ---------------------------------------------------------------------


def test_use_selects_the_engagement():
    new_engagement(targets=["*.acme.example"])
    engagement.use("acme")
    assert paths.active_engagement() == "acme"


def test_use_refuses_an_engagement_that_does_not_exist():
    with pytest.raises(EngagementError, match="does not exist"):
        engagement.use("ghost")


def test_use_refuses_when_the_environment_overrides_the_selection(monkeypatch):
    new_engagement(targets=["*.acme.example"])
    monkeypatch.setenv("BBH_ENGAGEMENT", "other")
    with pytest.raises(EngagementError, match="overrides the selection"):
        engagement.use("acme")


# -- require_armed -----------------------------------------------------------


def test_require_armed_returns_the_scope_when_armed():
    new_engagement(targets=["*.acme.example"])
    engagement.arm("acme", attested_by="Jo", hours=1)
    assert engagement.require_armed("acme").engagement == "acme"


def test_require_armed_refuses_an_uncompiled_engagement():
    new_engagement(targets=["*.acme.example"])
    with pytest.raises(EngagementError, match="no compiled scope"):
        engagement.require_armed("acme")


def test_require_armed_refuses_an_unarmed_engagement():
    new_engagement(targets=["*.acme.example"])
    engagement.compile_scope("acme")
    with pytest.raises(EngagementError, match="not armed"):
        engagement.require_armed("acme")


def test_require_armed_refuses_a_lock_compiled_from_a_since_edited_file():
    """The lock must be what the operator approved, not what it used to be."""
    new_engagement(targets=["*.acme.example"])
    engagement.arm("acme", attested_by="Jo", hours=1)
    path = paths.scope_path("acme")
    path.write_text(path.read_text() + "\n# a later edit\n")
    with pytest.raises(EngagementError, match="changed since it was compiled"):
        engagement.require_armed("acme")


def test_require_armed_refuses_a_tampered_lock():
    new_engagement(targets=["*.acme.example"])
    engagement.arm("acme", attested_by="Jo", hours=1)
    lock_file = paths.lock_path("acme")
    data = json.loads(lock_file.read_text())
    data["in_scope"].append({"type": "domain", "value": "evil.example", "note": None})
    lock_file.write_text(json.dumps(data))
    with pytest.raises(EngagementError, match="unusable scope lock"):
        engagement.require_armed("acme")


# -- status ------------------------------------------------------------------


def test_status_reports_scope_attestation_and_counts():
    new_engagement(targets=["*.acme.example"])
    engagement.arm("acme", attested_by="Jo", hours=3)
    engagement.use("acme")
    data = engagement.status("acme")
    assert data["engagement"] == "acme"
    assert data["armed"] is True
    assert data["active"] is True
    assert data["attested_by"] == "Jo"
    assert data["problems"] == []
    assert data["stats"]["findings"] == 0
    assert any("acme.example" in line for line in data["scope_summary"])


def test_status_lists_problems_rather_than_raising_when_unarmed():
    new_engagement(targets=["*.acme.example"])
    data = engagement.status("acme")
    assert data["armed"] is False
    assert any("scope compile" in p for p in data["problems"])


def test_status_of_a_missing_engagement_raises_with_a_remedy():
    with pytest.raises(EngagementError, match="bb new"):
        engagement.status("ghost")


# -- audit -------------------------------------------------------------------


def test_lifecycle_events_reach_the_audit_log():
    new_engagement(targets=["*.acme.example"])
    engagement.arm("acme", attested_by="Jo", hours=1)
    engagement.disarm("acme")
    actions = [
        json.loads(line).get("action")
        for line in paths.AUDIT_LOG.read_text().splitlines()
    ]
    assert {"create", "arm", "disarm"} <= set(actions)
