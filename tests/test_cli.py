"""The CLI, as the integration seam.

Most of these are not about argparse: they are about the modules agreeing.
A remedy string that names a command the parser rejects is a dead end for an
agent mid-hunt, so the spellings the other modules emit are asserted here.
"""

from __future__ import annotations

import json

import pytest

from conftest import VALIDATED_FIELDS

from bbh import cli, paths
from bbh.store import Store


def run(*argv) -> int:
    return cli.main(list(argv))


def parses(*argv) -> bool:
    """True when the real parser accepts this argv."""
    try:
        cli.build_parser().parse_args(list(argv))
        return True
    except SystemExit:
        return False


# ---------------------------------------------------------------------------
# remedy strings must name commands that exist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        # triage.py and the phase prompts spell object add this way
        ("object", "add", "--label", "L", "--kind", "document",
         "--identifier", "2", "--owner-account", "victim"),
        # the contract spells it positionally
        ("object", "add", "L", "--kind", "document", "--identifier", "2",
         "--owner", "victim"),
        # runner.py's refusal text
        ("sandbox", "up", "acme"),
        ("sandbox", "verify", "acme"),
        ("hunt", "acme", "--unsandboxed"),
        ("hunt", "acme", "--resume", "--allow-unpriced"),
        ("hunt", "acme", "--resume", "--budget-usd", "40"),
        # triage.py remedies
        ("finding", "set", "F-1", "--severity", "high"),
        ("finding", "set", "F-1", "--repro", "1. a\n2. b"),
        ("finding", "set", "F-1", "--dedup-key", "k"),
        ("finding", "set", "F-1", "--host", "h"),
        ("finding", "advance", "F-1", "rejected"),
        ("finding", "advance", "F-1", "duplicate"),
        ("evidence", "add", "F-1", "request", "--request-id", "3"),
        ("evidence", "add", "F-1", "file", "/tmp/x"),
        ("account", "add", "attacker", "--role", "attacker"),
        ("req", "GET", "https://x/", "--actor", "attacker"),
        ("scope", "compile", "acme"),
        ("finding", "list"),
        ("gate", "F-1"),
        # report.py remedies
        ("report", "F-1"),
        ("report", "--all"),
        ("finding", "set", "F-1", "--endpoint", "/x"),
        ("finding", "set", "F-1", "--summary", "s"),
        ("finding", "set", "F-1", "--impact", "i"),
        ("finding", "set", "F-1", "--remediation", "r"),
        ("angle", "add", "surface", "idor", "technique", "negative"),
        ("status", "acme"),
    ],
)
def test_every_remedy_spelling_is_accepted_by_the_parser(argv):
    assert parses(*argv), f"a remedy names a command the CLI rejects: bb {' '.join(argv)}"


def test_the_contract_subcommand_list_is_present():
    parser = cli.build_parser()
    known: set[str] = set()
    for action in parser._actions:
        if getattr(action, "choices", None):
            known |= set(action.choices)
    assert {
        "new", "list", "use", "status", "scope", "arm", "disarm", "hunt", "phase",
        "req", "finding", "evidence", "angle", "account", "object", "gate",
        "report", "proxy", "audit", "doctor", "install-hook",
    } <= known


# ---------------------------------------------------------------------------
# lifecycle through the CLI
# ---------------------------------------------------------------------------


def test_new_compile_arm_check_round_trip(capsys):
    assert run("new", "acme", "--program-url", "https://hackerone.com/acme",
               "--target", "*.acme.example", "--use") == 0
    assert run("scope", "compile", "acme") == 0
    assert run("arm", "acme", "--as", "tester", "--hours", "2") == 0
    capsys.readouterr()

    assert run("scope", "check", "https://www.acme.example/login") == 0
    assert "ALLOW" in capsys.readouterr().out

    assert run("scope", "check", "https://evil.example/") == 1, (
        "a denial is a verdict, reported as exit 1"
    )
    assert "DENY" in capsys.readouterr().out


def test_scope_check_exit_code_is_a_verdict_not_an_error(engagement, capsys):
    assert run("scope", "check", "www.acme.example") == 0
    assert run("scope", "check", "www.acme.example", "evil.example") == 1


def test_status_json_is_machine_readable(engagement, capsys):
    assert run("status", "acme", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["engagement"] == "acme"
    assert data["armed"] is True


def test_list_shows_the_active_engagement(engagement, capsys):
    assert run("list") == 0
    out = capsys.readouterr().out
    assert "acme" in out and "armed" in out


def test_disarm_makes_scope_check_deny(engagement, capsys):
    assert run("disarm", "acme") == 0
    capsys.readouterr()
    assert run("scope", "check", "www.acme.example") == 1


def test_an_unknown_engagement_is_a_remedy_not_a_traceback(capsys):
    assert run("status", "ghost") == 1
    assert "bb new" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# findings, evidence, gates, reports
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded(engagement, capsys):
    """An engagement with the accounts, object and request a real proof needs."""
    run("account", "add", "attacker", "--role", "attacker")
    run("account", "add", "victim", "--role", "victim")
    store = Store(paths.db_path(engagement))
    store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://www.acme.example/api/docs/2", host="www.acme.example",
        path="/api/docs/2", status=200,
    )
    store.close()
    run("object", "add", "--label", "victim-doc", "--kind", "document",
        "--identifier", "2", "--owner-account", "victim")
    capsys.readouterr()
    return engagement


def test_object_add_accepts_both_spellings(seeded, capsys):
    assert run("object", "add", "doc-b", "--kind", "document",
               "--identifier", "3", "--owner", "victim") == 0
    capsys.readouterr()
    assert run("object", "list", "--json") == 0
    labels = {row["label"] for row in json.loads(capsys.readouterr().out)}
    assert {"victim-doc", "doc-b"} <= labels


def test_object_add_refuses_an_owner_that_is_not_an_account(seeded, capsys):
    assert run("object", "add", "x", "--kind", "document",
               "--identifier", "9", "--owner", "ghost") == 1
    assert "not a recorded account" in capsys.readouterr().err


def test_object_add_refuses_with_no_label_at_all(seeded, capsys):
    assert run("object", "add", "--kind", "document",
               "--identifier", "9", "--owner", "victim") == 1
    assert "needs a label" in capsys.readouterr().err


def test_the_full_gate_and_report_chain(seeded, capsys):
    """A proof that satisfies every gate, built the way an agent has to build it.

    v2 raised this bar and `bb gate` now runs all twelve gates rather than the
    published seven, so the finding this test walks through needs what the new
    ones ask for: severity derived from a CVSS vector rather than asserted, a
    baseline alongside the attack, the victim's identifier traced to a request an
    attacker could have made, and a second attack reproduction that is not a
    replay of the first. The old version of this test passed on the v1 seven with
    an asserted severity, one response and no prerequisite trace -- which is
    exactly the finding CONTRACT v2 items 4, 5, 7, 8 and 9 exist to stop.
    """
    store = Store(paths.db_path(seeded))
    # 2: the listing that leaks the victim's document id to an attacker, which is
    # what makes the identifier reachable rather than harness-supplied.
    leak = store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://www.acme.example/api/docs?page=1", host="www.acme.example",
        path="/api/docs", query="page=1", status=200,
    )
    # 3: the control working -- the owner reading their own document.
    baseline = store.add_request(
        source="client", actor="victim", method="GET",
        url="https://www.acme.example/api/docs/2", host="www.acme.example",
        path="/api/docs/2", status=200,
    )
    # 4: the independent re-test, later than everything already cited.
    retest = store.add_request(
        source="client", actor="attacker", method="GET",
        url="https://www.acme.example/api/docs/2", host="www.acme.example",
        path="/api/docs/2", status=200,
    )
    store.close()

    assert run("finding", "add", "--title", "Cross-account document read",
               "--class", "idor", "--host", "www.acme.example",
               "--endpoint", "/api/docs/2") == 0
    # Roles, in capture order: the attack first, then the control it bypassed,
    # then the reproduction that could have disagreed with both.
    assert run("evidence", "add", "F-001", "request",
               "--request-id", "1", "--role", "attack") == 0
    assert run("evidence", "add", "F-001", "request",
               "--request-id", str(baseline), "--role", "baseline") == 0
    assert run("evidence", "add", "F-001", "request",
               "--request-id", str(retest), "--role", "attack") == 0
    assert run(
        "prereq", "add", "F-001", "document identifier 2",
        "--attacker-start", "a registered account with no relationship to the victim",
        "--acquisition", "the /api/docs listing returns every tenant's document ids",
        "--verdict", "reachable", "--request-id", str(leak),
    ) == 0
    assert run(
        "finding", "set", "F-001",
        "--cvss", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "--repro",
        "1. Sign in as attacker.\n"
        "2. GET https://www.acme.example/api/docs/2\n"
        "3. Read the victim's document.",
        "--summary", "Any account reads any document.",
        "--impact", "Full disclosure.",
        "--remediation", "Check ownership.",
        # The bar `store.advance` carries at `validated`. v2 made it a gate as
        # well (`gate_counterevidence_recorded`), so every rung above
        # `validated` applies it too -- including `gated`, which this chain
        # walks to. A complete proof carries its own case against itself.
        "--counterevidence", VALIDATED_FIELDS["counterevidence"],
        "--severity-change-conditions", VALIDATED_FIELDS["severity_change_conditions"],
        "--confidence", VALIDATED_FIELDS["confidence"],
    ) == 0
    # The claim is pinned before the gates read it, which is what `run_phase`
    # does for 06-verify and what `gate_frozen_claim_intact` recomputes: a
    # finding whose claim was never fixed has an independent verification that
    # cannot be held to anything, so it blocks rather than ships.
    assert run("finding", "freeze", "F-001") == 0
    capsys.readouterr()

    assert run("gate", "F-001") == 0, "every gate should pass for a real proof"
    printed = capsys.readouterr().out
    assert "PASS" in printed
    # The point of the change: the v2 gates ran, not just the published seven.
    for gate in ("gate_severity_derived", "gate_evidence_roles",
                 "gate_prerequisites_reachable", "gate_independent_verification",
                 "gate_repro_cites_real_requests"):
        assert gate in printed, gate

    assert run("report", "F-001") == 0
    capsys.readouterr()
    report = paths.engagement_dir(seeded) / "reports" / "F-001.md"
    assert report.is_file()
    text = report.read_text()
    assert "## Scope statement" in text
    # Severity was computed from the vector, never asserted.
    assert "high" in text.lower()


def test_a_failing_gate_exits_one_and_rejects(seeded, capsys):
    """An agent that owns the object it touched must not pass."""
    run("object", "add", "own-doc", "--kind", "document",
        "--identifier", "2", "--owner", "attacker")  # re-owns id 2
    run("finding", "add", "--title", "Not really an IDOR", "--class", "idor",
        "--host", "www.acme.example")
    run("evidence", "add", "F-001", "request", "--request-id", "1")
    run("finding", "set", "F-001", "--severity", "high",
        "--repro", "1. a\n2. GET https://www.acme.example/api/docs/2")
    capsys.readouterr()

    assert run("gate", "F-001") == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "verdict, not a tool error" in out

    store = Store(paths.db_path(seeded))
    assert store.get_finding("F-001")["state"] == "rejected"
    store.close()


def test_report_refuses_a_finding_that_was_never_gated(seeded, capsys):
    run("finding", "add", "--title", "t", "--class", "xss", "--host", "www.acme.example")
    capsys.readouterr()
    assert run("report", "F-001") == 1


def test_evidence_verify_catches_a_mutated_artifact(seeded, tmp_path, capsys):
    artifact = tmp_path / "proof.json"
    artifact.write_text('{"owner":"victim"}')
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    run("evidence", "add", "F-001", "file", str(artifact))
    capsys.readouterr()
    assert run("evidence", "verify", "F-001") == 0

    artifact.write_text('{"owner":"attacker"}')
    capsys.readouterr()
    assert run("evidence", "verify", "F-001") == 1


def test_finding_add_assigns_sequential_uids(engagement, capsys):
    run("finding", "add", "--title", "a", "--class", "idor")
    run("finding", "add", "--title", "b", "--class", "xss")
    capsys.readouterr()
    run("finding", "list", "--json")
    uids = [row["uid"] for row in json.loads(capsys.readouterr().out)]
    assert uids == ["F-001", "F-002"]


def test_angle_add_and_list_round_trip(engagement, capsys):
    assert run("angle", "add", "api.acme.example/docs/{id}", "idor",
               "cross-account-get", "negative", "--note", "403 for every id") == 0
    capsys.readouterr()
    run("angle", "list", "--json")
    rows = json.loads(capsys.readouterr().out)
    # v2 vocabulary: the v1 word is accepted on input and stored as its v2 equivalent.
    assert rows[0]["outcome"] == "ruled_out"
    assert rows[0]["note"] == "403 for every id"


# ---------------------------------------------------------------------------
# bb req, offline
# ---------------------------------------------------------------------------


def test_req_denies_an_out_of_scope_target_with_exit_two(engagement, capsys):
    assert run("req", "GET", "https://evil.example/") == 2
    assert "not in the scope" in capsys.readouterr().err


def test_req_with_no_arguments_explains_itself(engagement, capsys):
    assert run("req") == 1
    assert "bb req GET" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# hunt and phase, without spawning anything
# ---------------------------------------------------------------------------


def test_hunt_dry_run_prints_prompts_and_spawns_nothing(engagement, capsys):
    assert run("hunt", "acme", "--dry-run") == 0
    out = capsys.readouterr().out
    for phase in ("00-recon", "04-triage", "09-report"):
        assert phase in out
    assert "no subprocess will be started" in out


def test_phase_dry_run_prints_one_prompt_and_spawns_nothing(engagement, capsys):
    assert run("phase", "00-recon", "acme", "--dry-run") == 0
    out = capsys.readouterr().out
    assert "no subprocess was started" in out
    assert "acme.example" in out


def test_hunt_refuses_an_unarmed_engagement(engagement, capsys):
    run("disarm", "acme")
    capsys.readouterr()
    assert run("hunt", "acme", "--unsandboxed") == 1
    assert "not armed" in capsys.readouterr().err


def test_an_unknown_phase_lists_the_real_ones(engagement, capsys):
    assert run("phase", "99-magic", "acme") == 1
    assert "00-recon" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# doctor and install-hook
# ---------------------------------------------------------------------------


def test_doctor_reports_the_enforcement_checks(engagement, capsys):
    run("doctor")
    out = capsys.readouterr().out
    assert "enforcement" in out
    assert "scope" in out
    assert "store" in out


def test_doctor_json_lists_every_check(engagement, capsys):
    run("doctor", "--json")
    data = json.loads(capsys.readouterr().out)
    names = {c["name"] for c in data["checks"]}
    assert {"python", "requests", "shims", "hook", "scope", "armed"} <= names


def test_install_hook_writes_a_pretooluse_hook_into_a_fresh_settings_file(
    tmp_path, monkeypatch, capsys
):
    settings = tmp_path / "settings.json"
    monkeypatch.setattr(cli, "settings_file", lambda scope: settings)
    assert run("install-hook") == 0
    capsys.readouterr()

    hooks = json.loads(settings.read_text())["hooks"]["PreToolUse"]
    assert hooks[0]["matcher"] == "Bash"
    assert hooks[0]["hooks"][0]["command"].endswith("bin/bb-guard")


def test_install_hook_merges_rather_than_clobbering_existing_hooks(
    tmp_path, monkeypatch, capsys
):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [
                {"matcher": "Write",
                 "hooks": [{"type": "command", "command": "/usr/bin/true"}]}
            ]
        },
        "model": "opus",
    }))
    monkeypatch.setattr(cli, "settings_file", lambda scope: settings)
    assert run("install-hook") == 0
    capsys.readouterr()

    data = json.loads(settings.read_text())
    assert data["model"] == "opus", "unrelated settings must survive"
    commands = [
        h["command"]
        for entry in data["hooks"]["PreToolUse"]
        for h in entry["hooks"]
    ]
    assert "/usr/bin/true" in commands, "the pre-existing hook must survive"
    assert any(c.endswith("bin/bb-guard") for c in commands)


def test_install_hook_is_idempotent(tmp_path, monkeypatch, capsys):
    settings = tmp_path / "settings.json"
    monkeypatch.setattr(cli, "settings_file", lambda scope: settings)
    run("install-hook")
    run("install-hook")
    capsys.readouterr()
    entries = json.loads(settings.read_text())["hooks"]["PreToolUse"]
    guards = [
        h for entry in entries for h in entry["hooks"]
        if str(h["command"]).endswith("bin/bb-guard")
    ]
    assert len(guards) == 1, "installing twice must not duplicate the hook"


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def test_audit_renders_guard_and_lifecycle_records(engagement, capsys):
    run("req", "GET", "https://evil.example/")
    capsys.readouterr()
    assert run("audit", "--tail", "10") == 0
    assert "evil.example" in capsys.readouterr().out


def test_audit_denied_filters_to_refusals(engagement, capsys):
    run("req", "GET", "https://evil.example/")
    capsys.readouterr()
    assert run("audit", "--denied") == 0
    out = capsys.readouterr().out
    assert "evil.example" in out


# ---------------------------------------------------------------------------
# error handling
# ---------------------------------------------------------------------------


def test_a_group_with_no_subcommand_exits_two(engagement, capsys):
    assert run("scope") == 2


def test_errors_are_remedies_not_tracebacks(capsys):
    assert run("use", "ghost") == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "bb " in err
