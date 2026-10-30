"""v2 hardening at the CLI seam: the audit chain, output bounds, search.

What these cover is not argparse. Each one is a way the harness used to hand an
agent a wrong conclusion: a filter it passed as the literal string "none" that
silently matched nothing, a thousand-line dump that pushed the task out of
context, an audit log anything could edit, a documented `--search` that did not
exist. The report-layer tests at the end belong here too, because what they
check is the same thing: the store decides, not the prose.
"""

from __future__ import annotations

import json

import pytest

from bbh import cli, paths
from bbh.report import ReportError, render, render_summary
from bbh.scope import Scope
from bbh.store import Store
from conftest import (
    VALIDATED_FIELDS,
    make_scope,
    record_gate_passes,
    seed_access_control_finding,
)


def run(*argv) -> int:
    return cli.main(list(argv))


# ---------------------------------------------------------------------------
# the audit chain
# ---------------------------------------------------------------------------


def audit_lines() -> list[str]:
    return paths.AUDIT_LOG.read_text(encoding="utf-8").splitlines()


def test_appends_are_chained_onto_the_previous_line(engagement):
    for n in range(3):
        assert cli.audit_append("test_event", {"n": n}) is True

    records = [json.loads(line) for line in audit_lines()]
    assert [r["event"] for r in records] == ["test_event"] * 3
    assert records[0]["prev"] == cli.AUDIT_GENESIS
    report = cli.verify_audit_chain()
    assert report.ok
    assert (report.lines, report.chained, report.unchained) == (3, 3, 0)


def test_an_edited_line_is_detected(engagement):
    for n in range(4):
        cli.audit_append("test_event", {"n": n})

    lines = audit_lines()
    tampered = json.loads(lines[1])
    tampered["data"]["n"] = 99
    lines[1] = json.dumps(tampered)
    paths.AUDIT_LOG.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = cli.verify_audit_chain()
    assert not report.ok
    # The edit shows up at the line that recorded the hash of the one before it.
    assert "line 3" in report.problems[0]
    assert "at or before 2 was edited, inserted or removed" in report.problems[0]


def test_a_line_longer_than_one_read_block_still_chains(engagement):
    """The tail read walks backwards in blocks; a long denial reason spans them."""
    cli.audit_append("test_event", {"command": "curl " + "A" * 9000})
    cli.audit_append("test_event", {"n": 1})
    report = cli.verify_audit_chain()
    assert report.ok and report.chained == 2


def test_a_removed_line_is_detected(engagement):
    for n in range(4):
        cli.audit_append("test_event", {"n": n})
    lines = audit_lines()
    del lines[1]
    paths.AUDIT_LOG.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not cli.verify_audit_chain().ok


def test_doctor_verify_chain_reports_the_break_and_exits_one(engagement, capsys):
    cli.audit_append("test_event", {"n": 0})
    cli.audit_append("test_event", {"n": 1})
    lines = audit_lines()
    lines[0] = json.dumps({**json.loads(lines[0]), "event": "something_else"})
    paths.AUDIT_LOG.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert run("doctor", "--verify-chain") == 1
    out = capsys.readouterr().out
    assert "BROKEN" in out
    assert "tampered" in out, "it must say to keep the log before anything is rewritten"


def test_doctor_verify_chain_is_json_readable(engagement, capsys):
    cli.audit_append("test_event", {})
    assert run("doctor", "--verify-chain", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {
        "ok": True,
        "path": str(paths.AUDIT_LOG),
        "lines": 1,
        "chained": 1,
        "unchained": 0,
        "problems": [],
    }


def test_doctor_verify_chain_on_an_empty_log_is_not_a_failure(engagement, capsys):
    assert run("doctor", "--verify-chain") == 0
    assert "empty" in capsys.readouterr().out


def test_a_flat_line_from_another_writer_is_unchained_not_tampering(engagement, capsys):
    """bbh.guard and bbh.http still append flat records. Those are not
    tamper-evident, which is a build state to report, not a break to cry about."""
    paths.AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with paths.AUDIT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": "2026-10-30T00:00:00Z", "allowed": False, "tool": "Bash"}))
        fh.write("\n")
    cli.audit_append("test_event", {})

    report = cli.verify_audit_chain()
    assert report.ok
    assert (report.chained, report.unchained) == (1, 1)
    assert run("doctor", "--verify-chain") == 0
    assert "unchained" in capsys.readouterr().out


def test_an_append_after_a_truncated_line_does_not_glue_onto_it(engagement):
    paths.AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    paths.AUDIT_LOG.write_text('{"ts": "2026-10-30T00:00:00Z", "allo', encoding="utf-8")

    assert cli.audit_append("after_crash", {}) is True

    lines = audit_lines()
    assert len(lines) == 2, "the half-written line must stay its own line"
    assert json.loads(lines[1])["event"] == "after_crash"
    problems = cli.verify_audit_chain().problems
    assert len(problems) == 1 and "not JSON" in problems[0]


def test_bb_audit_renders_a_chained_record(engagement, capsys):
    cli.audit_append(
        "proxy_block",
        {"allowed": False, "tool": "proxy", "command": "GET https://evil.example/",
         "reasons": ["out of scope"]},
    )
    assert run("audit", "--denied") == 0
    out = capsys.readouterr().out
    assert "evil.example" in out
    assert "DENY" in out


def test_the_chain_shows_up_in_a_plain_doctor_run(engagement, capsys):
    cli.audit_append("test_event", {})
    run("doctor", "--json")
    data = json.loads(capsys.readouterr().out)
    chain = [c for c in data["checks"] if c["name"] == "audit chain"]
    assert chain and chain[0]["level"] == "pass"


# ---------------------------------------------------------------------------
# output bounding
# ---------------------------------------------------------------------------


def test_short_output_is_left_exactly_as_it_was():
    text = "one\ntwo\nthree\n"
    assert cli.bound_output(text, "bb test") == (text, None)


def test_the_slice_keeps_both_ends_and_counts_what_it_dropped(engagement):
    text = "\n".join(f"line {n}" for n in range(1, 1001)) + "\n"
    shown, spill = cli.bound_output(text, "bb test")

    assert spill is not None
    assert "line 1" in shown and "line 1000" in shown, "head and tail, not just the head"
    assert "line 500" not in shown
    assert spill.lines == 1000
    assert spill.shown_lines == cli.MAX_OUT_LINES
    assert spill.dropped_lines == 1000 - cli.MAX_OUT_LINES
    assert spill.dropped_bytes == len(text.encode()) - len(
        "\n".join(shown.splitlines()[: cli.HEAD_LINES] + shown.splitlines()[-cli.TAIL_LINES :])
        .encode()
    )
    assert spill.path is not None and spill.path.read_text() == text, (
        "the spill is the full text, verbatim, so grep -n line numbers are real"
    )


def test_a_single_enormous_line_is_clipped_rather_than_printed(engagement):
    shown, spill = cli.bound_output("x" * 200_000 + "\n", "bb test")
    assert spill is not None
    assert len(shown.encode()) < 200_000
    assert "line clipped" in shown or spill.dropped_bytes > 0


def test_a_long_listing_is_bounded_spilled_and_explained(engagement, capsys):
    with Store(paths.db_path(engagement)) as store:
        for n in range(300):
            store.record_angle(f"api.acme.example/r{n}", "idor", "cross-account-get", "negative")

    assert run("angle", "list") == 0
    out = capsys.readouterr().out
    lines = out.splitlines()

    assert len(lines) <= cli.MAX_OUT_LINES + 8, "the notice is the only thing above the bound"
    assert "are NOT shown here" in out
    assert "grep -n 'PATTERN'" in out
    spilled = [line.split("is at ", 1)[1] for line in lines if "the complete output is at" in line]
    assert len(spilled) == 1
    path = paths.engagement_dir(engagement) / "raw" / "out"
    assert spilled[0].startswith(str(path)), "the full text belongs under raw/out/"
    full = (path / spilled[0].rsplit("/", 1)[1]).read_text()
    assert full.count("api.acme.example/r299") == 1


def test_bounded_json_output_stays_parseable(engagement, capsys):
    with Store(paths.db_path(engagement)) as store:
        for n in range(300):
            store.record_angle(f"api.acme.example/r{n}", "idor", "cross-account-get", "negative")

    assert run("angle", "list", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["bounded"] is True
    assert data["dropped_lines"] > 0
    assert data["command"] == "bb angle list"
    assert json.loads(open(data["spill"]).read())[0]["surface"].startswith("api.acme.example")


def test_the_raw_out_directory_is_not_world_readable(engagement):
    cli.bound_output("\n".join(str(n) for n in range(500)), "bb test")
    out_dir = paths.engagement_dir(engagement) / "raw" / "out"
    assert out_dir.stat().st_mode & 0o777 == 0o700
    assert (paths.engagement_dir(engagement) / "raw").stat().st_mode & 0o777 == 0o700


# ---------------------------------------------------------------------------
# "null" / "none" / "nil" / "undefined" / "" as omitted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("literal", ["null", "none", "None", "nil", "undefined", ""])
def test_a_literal_placeholder_filter_does_not_silently_match_nothing(
    engagement, capsys, literal
):
    run("finding", "add", "--title", "Cross-account read", "--class", "idor")
    capsys.readouterr()

    assert run("finding", "list", "--state", literal) == 0
    captured = capsys.readouterr()
    assert "F-001" in captured.out, "a placeholder filter must not hide the findings"
    assert "read as 'not given'" in captured.err


def test_a_placeholder_search_is_not_treated_as_a_query(engagement, capsys):
    run("finding", "add", "--title", "Cross-account read", "--class", "idor")
    capsys.readouterr()
    assert run("finding", "list", "--search", "undefined") == 0
    assert "F-001" in capsys.readouterr().out


def test_a_placeholder_field_is_not_written_into_a_finding(engagement, capsys):
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    capsys.readouterr()
    assert run("finding", "set", "F-001", "--endpoint", "null") == 1
    assert "nothing to set" in capsys.readouterr().err
    with Store(paths.db_path(engagement)) as store:
        assert store.get_finding("F-001")["endpoint"] is None


def test_a_placeholder_severity_is_not_an_argparse_usage_dump(engagement, capsys):
    """argparse would answer `--severity none` with exit 2 and a usage block,
    which tells an agent nothing about what to pass instead."""
    assert run("finding", "add", "--title", "t", "--class", "idor", "--severity", "none") == 0
    with Store(paths.db_path(engagement)) as store:
        assert store.get_finding("F-001")["severity"] is None


def test_a_real_filter_still_filters(engagement, capsys):
    run("finding", "add", "--title", "a", "--class", "idor")
    run("finding", "add", "--title", "b", "--class", "xss")
    capsys.readouterr()
    run("finding", "list", "--state", "candidate", "--json")
    assert len(json.loads(capsys.readouterr().out)) == 2


# ---------------------------------------------------------------------------
# bb finding list --search
# ---------------------------------------------------------------------------


@pytest.fixture
def three_findings(engagement, capsys):
    run("finding", "add", "--title", "Invoice readable across tenants", "--class", "idor",
        "--summary", "Any account downloads any invoice pdf.")
    run("finding", "add", "--title", "Reflected XSS in search", "--class", "xss",
        "--summary", "The q parameter is echoed unescaped.")
    run("finding", "add", "--title", "Billing export leaks emails", "--class", "info-leak",
        "--summary", "The export includes every customer address.")
    capsys.readouterr()
    return engagement


def test_search_finds_a_finding_by_its_prose(three_findings, capsys):
    assert run("finding", "list", "--search", "invoice", "--json") == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["uid"] for r in rows] == ["F-001"]


def test_search_accepts_the_spelling_the_dedupe_prompt_documents(three_findings, capsys):
    assert run("finding", "list", "--search", "invoice OR billing", "--json") == 0
    rows = json.loads(capsys.readouterr().out)
    assert {r["uid"] for r in rows} == {"F-001", "F-003"}


def test_the_query_alias_still_works(three_findings, capsys):
    assert run("finding", "list", "-q", "xss", "--json") == 0
    assert [r["uid"] for r in json.loads(capsys.readouterr().out)] == ["F-002"]


def test_search_and_state_are_both_applied(three_findings, capsys):
    assert run("finding", "list", "--search", "invoice", "--state", "rejected", "--json") == 0
    assert json.loads(capsys.readouterr().out) == []


def test_a_search_with_no_hits_says_which_filter_found_nothing(three_findings, capsys):
    assert run("finding", "list", "--search", "ssrf") == 0
    out = capsys.readouterr().out
    assert "matching --search 'ssrf'" in out
    assert "bb finding list" in out


@pytest.mark.parametrize("query", ["tenants' invoice", 'NEAR("a" "b"', "invoice*(", "export -"])
def test_prose_fts_cannot_parse_is_retried_as_a_phrase(three_findings, capsys, query):
    """A model searching prose writes apostrophes and brackets. FTS5 rejects
    those outright; the retry means the agent gets rows or an empty list, never
    an OperationalError traceback."""
    assert run("finding", "list", "--search", query, "--json") == 0
    assert isinstance(json.loads(capsys.readouterr().out), list)


# ---------------------------------------------------------------------------
# bb proxy start
# ---------------------------------------------------------------------------


def test_the_proxy_gets_its_own_ca_and_a_non_null_phase(engagement):
    confdir = paths.engagement_dir(engagement) / ".state" / "mitmproxy"
    argv = cli.proxy_command(
        engagement,
        mitmdump="/usr/bin/mitmdump",
        addon=paths.REPO / "bbh" / "proxy_addon.py",
        confdir=confdir,
        phase="02-sweep",
        listen_host="127.0.0.1",
        port=8080,
    )
    assert f"confdir={confdir}" in argv
    assert "bbh_phase=02-sweep" in argv
    assert f"bbh_engagement={engagement}" in argv
    assert str(confdir).startswith(str(paths.engagement_dir(engagement))), (
        "a shared CA would outlive the engagement"
    )


def test_the_phase_falls_back_to_a_label_rather_than_null(engagement):
    assert cli.DEFAULT_PROXY_PHASE
    assert cli._running_phase(engagement) is None
    with Store(paths.db_path(engagement)) as store:
        store.start_phase("02-sweep")
    assert cli._running_phase(engagement) == "02-sweep"


# ---------------------------------------------------------------------------
# the report is generated from the store
# ---------------------------------------------------------------------------


@pytest.fixture
def gated(store):
    seed_access_control_finding(store)
    store.update_finding(
        "F-001",
        summary="Any authenticated account can read any document by id.",
        impact="Full disclosure of every customer document.",
        remediation="Check ownership server-side.",
        **VALIDATED_FIELDS,
    )
    for step in ("validated", "verified", "gated"):
        store.advance("F-001", step)
    record_gate_passes(store, "F-001")
    return store.get_finding("F-001")


def test_the_numbered_steps_come_from_the_request_log_not_the_write_up(store, gated):
    store.update_finding("F-001", repro="1. Trust me.\n2. It is broken at /api/invented.")
    text = render(store, make_scope(), "F-001")
    steps = text.split("## Steps to reproduce", 1)[1].split("## Evidence", 1)[0]

    assert "**Step 1" in steps
    assert "GET /api/docs/2 HTTP/1.1" in steps, "the step is the recorded request"
    # The prose survives, below the steps and labelled as what it is.
    narrative = steps.index("Narrative recorded during the hunt")
    assert narrative > steps.index("**Step 1")
    assert "nothing here is load-bearing" in steps


def test_a_summary_that_disagrees_with_the_store_is_refused(store, gated):
    with pytest.raises(ReportError) as exc:
        render_summary(store, make_scope(), findings=["F-001", "F-404"])
    message = str(exc.value)
    assert "F-404" in message
    assert "bb finding list --state gated" in message


def test_a_summary_that_omits_a_reportable_finding_is_refused(store, gated):
    with pytest.raises(ReportError, match="reportable but not listed: F-001"):
        render_summary(store, make_scope(), findings=[])


def test_a_summary_that_agrees_renders(store, gated):
    text = render_summary(store, make_scope(), findings=[gated])
    assert "F-001" in text
    assert "1 finding(s) reached a reportable state" in text


def test_the_coverage_section_speaks_the_stores_angle_vocabulary(store):
    store.record_angle("api.acme.example/docs/{id}", "idor", "cross-account-get", "ruled_out",
                       control="server-side ownership check returns 403 for every id")
    text = render_summary(store, make_scope())
    assert "ruled out" in text
    assert "ownership check returns 403" in text
    assert "no settled negatives" not in text


# ---------------------------------------------------------------------------
# the commands the v2 modules were built behind
# ---------------------------------------------------------------------------
#
# Each of these is a module that was green on its own and unreachable: coverage
# arithmetic nothing printed, a pinned claim no gate read, a duplicate merge
# with no command, a process registry nothing registered into, and a body
# reader the prompts pointed at while `bb req` died on `URL '12' has no scheme`.


def complete_finding(uid: str = "F-001", *, freeze: bool = True) -> None:
    """A finding wired the way the phase prompts tell an agent to wire one.

    Built through the CLI on purpose: the point of these tests is the seam, so
    a helper that reached into the store would be testing the wrong layer.
    """
    with Store(paths.db_path("acme")) as store:
        store.add_account("attacker", "attacker")
        store.add_account("attacker-v6", "attacker")
        store.add_account("victim", "victim")
        store.add_object("victim doc", "document", "2", "victim")

        def request(actor, path, phase, query=None):
            return store.add_request(
                source="client", actor=actor, method="GET",
                url=f"https://www.acme.example{path}" + (f"?{query}" if query else ""),
                host="www.acme.example", path=path, query=query, status=200, phase=phase,
            )

        leak = request("attacker", "/api/docs", "00-recon", query="page=1")
        baseline = request("victim", "/api/docs/2", "05-validate")
        attack = request("attacker", "/api/docs/2", "05-validate")
        recheck = request("attacker-v6", "/api/docs/2", "06-verify")

    run("finding", "add", "--uid", uid, "--title", "Cross-account document read",
        "--class", "idor", "--host", "www.acme.example", "--endpoint", "/api/docs/2")
    run("evidence", "add", uid, "request", "--request-id", str(attack), "--role", "attack")
    run("evidence", "add", uid, "request", "--request-id", str(baseline), "--role", "baseline")
    run("evidence", "add", uid, "request", "--request-id", str(recheck), "--role", "attack")
    run("prereq", "add", uid, "document identifier 2",
        "--attacker-start", "a registered account with no relationship to the victim",
        "--acquisition", "the /api/docs listing returns every tenant's document ids",
        "--verdict", "reachable", "--request-id", str(leak),
        "--searched", "every 200 response body in the request log")
    run("finding", "set", uid, "--cvss", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "--repro", "1. Sign in as attacker.\n"
                   "2. GET https://www.acme.example/api/docs/2\n"
                   "3. Read the victim's document.",
        "--summary", "Any account reads any document.", "--impact", "Full disclosure.",
        "--remediation", "Check ownership server side.",
        "--counterevidence", VALIDATED_FIELDS["counterevidence"],
        "--severity-change-conditions", VALIDATED_FIELDS["severity_change_conditions"],
        "--confidence", "high", "--delivery", "production_realistic")
    if freeze:
        run("finding", "freeze", uid)


def test_a_finding_can_be_walked_from_candidate_to_a_rendered_report(engagement, capsys):
    """The acceptance test: only commands the phase prompts name, nothing else.

    Everything below is a line a prompt teaches. If this ever needs a call into
    the store or a hand-written file to pass, an agent following the prompts
    cannot finish a hunt.
    """
    complete_finding()
    capsys.readouterr()
    assert run("gate", "F-001") == 0
    assert run("report", "F-001") == 0
    report = paths.engagement_dir(engagement) / "reports" / "F-001.md"
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    assert "## Scope statement" in text
    with Store(paths.db_path(engagement)) as store:
        assert store.get_finding("F-001")["state"] == "gated"


# -- the pinned claim is read by a gate --------------------------------------


def test_an_unpinned_claim_blocks_the_gate_chain(engagement, capsys):
    """Watch a finding fail on the new gate, in the chain `bb gate` runs."""
    complete_finding(freeze=False)
    capsys.readouterr()
    assert run("gate", "F-001") == 1
    printed = capsys.readouterr().out
    assert "gate_frozen_claim_intact" in printed
    assert "has no pinned claim" in printed
    with Store(paths.db_path(engagement)) as store:
        assert store.get_finding("F-001")["state"] == "blocked"


def test_the_remedy_the_block_names_is_what_clears_it(engagement, capsys):
    complete_finding(freeze=False)
    run("gate", "F-001")
    capsys.readouterr()
    assert run("finding", "freeze", "F-001") == 0
    assert "pinned F-001  sha256:" in capsys.readouterr().out
    assert run("gate", "F-001") == 0
    with Store(paths.db_path(engagement)) as store:
        assert store.get_finding("F-001")["state"] == "gated"


def test_a_claim_edited_after_it_was_verified_stops_shipping(engagement, capsys):
    complete_finding()
    run("gate", "F-001")
    run("finding", "set", "F-001",
        "--repro", "1. Sign in as attacker.\n"
                   "2. GET https://www.acme.example/api/docs/2\n"
                   "3. Read the victim's document, and also every other tenant's.")
    capsys.readouterr()
    assert run("gate", "F-001") == 1
    assert "changed after it was pinned" in capsys.readouterr().out


def test_the_gate_summary_reads_the_state_the_store_holds(engagement, capsys):
    """It used to say every failure was rejected. A block is not a rejection."""
    complete_finding(freeze=False)
    capsys.readouterr()
    run("gate", "F-001")
    printed = capsys.readouterr().out
    assert "F-001 is now 'blocked'" in printed
    assert "parked, not binned" in printed
    assert "moved to 'rejected'" not in printed


def test_a_blocked_finding_prints_what_would_clear_it(engagement, capsys):
    """The refusal points at `bb finding show`, which did not print either field."""
    complete_finding(freeze=False)
    run("gate", "F-001")
    capsys.readouterr()
    assert run("finding", "show", "F-001") == 0
    printed = capsys.readouterr().out
    assert "blocked_reason:" in printed
    assert "unblock_condition:" in printed
    assert "bb finding freeze F-001" in printed


def test_the_gate_run_shows_only_the_gates_that_ran(engagement, capsys):
    """A stale row from another rung used to print beside this run's verdicts."""
    complete_finding()
    run("gate", "F-001")
    capsys.readouterr()
    run("gate", "F-001", "--target", "validated")
    printed = capsys.readouterr().out
    assert "gating to validated: 7 gate(s)" in printed
    assert "gate_frozen_claim_intact" not in printed, "a gate that did not run was shown"


def test_freeze_check_reports_without_pinning(engagement, capsys):
    complete_finding(freeze=False)
    capsys.readouterr()
    assert run("finding", "freeze", "F-001", "--check") == 1
    assert "no pinned claim" in capsys.readouterr().out
    with Store(paths.db_path(engagement)) as store:
        assert store.get_finding("F-001")["frozen_sha256"] is None


# -- coverage ----------------------------------------------------------------


def test_coverage_prints_a_row_per_class_and_a_verdict(engagement, capsys):
    complete_finding()
    capsys.readouterr()
    assert run("coverage") == 0
    printed = capsys.readouterr().out
    assert "idor" in printed and "unrouted" in printed
    assert "not a clean sweep" in printed


def test_coverage_require_clean_fails_while_anything_is_unaccounted_for(engagement, capsys):
    complete_finding()
    capsys.readouterr()
    assert run("coverage", "--require-clean") == 1
    assert "--require-clean" in capsys.readouterr().err


def test_the_reason_command_the_gap_text_names_closes_an_unrouted_class(engagement, capsys):
    complete_finding()
    capsys.readouterr()
    assert run("coverage", "--class", "auth-bypass") == 0
    assert "unrouted" in capsys.readouterr().out

    assert run("coverage", "reason", "auth-bypass", "n/a") == 1
    assert "non-answer" in capsys.readouterr().err

    assert run("coverage", "reason", "auth-bypass",
               "no mapped surface was ever reached both with a credential and without, so "
               "nothing here can show an auth check being skipped") == 0
    capsys.readouterr()
    assert run("coverage", "--class", "auth-bypass") == 0
    assert "explained" in capsys.readouterr().out


def test_a_misspelled_class_is_refused_rather_than_reported_as_clean(engagement, capsys):
    assert run("coverage", "--class", "idorr") == 1
    assert "not a known vulnerability class" in capsys.readouterr().err


def test_status_carries_the_coverage_verdict(engagement, capsys):
    complete_finding()
    capsys.readouterr()
    assert run("status", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert "classes closed or explained" in data["coverage"]
    assert not data["coverage"].startswith("coverage:")


# -- handoff -----------------------------------------------------------------


def test_handoff_write_separates_problems_from_gaps(engagement, capsys):
    """Gaps must never fail a phase that produced work."""
    root = paths.engagement_dir(engagement)
    (root / "handoff").mkdir(parents=True, exist_ok=True)
    (root / "handoff" / "00-recon.json").write_text(
        json.dumps({"hosts": [], "endpoints": [], "tech": [], "auth_surfaces": []}),
        encoding="utf-8",
    )
    complete_finding()
    capsys.readouterr()
    assert run("handoff", "write", "00-recon", "--json") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["problems"] == []
    assert payload["coverage_gaps"], "the gaps are the whole point of the command"


def test_handoff_write_fails_on_a_missing_file(engagement, capsys):
    assert run("handoff", "write", "02-sweep") == 1
    assert "was never written" in capsys.readouterr().out


def test_handoff_write_refuses_a_phase_key_typo(engagement, capsys):
    assert run("handoff", "write", "02-sweeep") == 1
    assert "unknown phase" in capsys.readouterr().err


# -- dedupe and merge --------------------------------------------------------


def test_an_unadjudicated_pair_blocks_and_the_merge_clears_it(engagement, capsys):
    complete_finding("F-001")
    complete_finding("F-002")
    capsys.readouterr()

    assert run("finding", "dedupe", "F-001") == 1
    printed = capsys.readouterr().out
    assert "same_key" in printed and "F-002" in printed

    assert run("gate", "F-001") == 1
    assert "gate_not_duplicate" in capsys.readouterr().out

    assert run("finding", "merge", "F-002", "--into", "F-001",
               "--reason", "one root cause: the same missing ownership check") == 0
    capsys.readouterr()
    with Store(paths.db_path(engagement)) as store:
        assert store.get_finding("F-002")["state"] == "duplicate"
    assert run("finding", "dedupe", "F-001") == 0


def test_a_verdict_without_a_reason_is_refused_with_the_full_command(engagement, capsys):
    complete_finding("F-001")
    complete_finding("F-002")
    capsys.readouterr()
    assert run("finding", "dedupe", "F-001", "--against", "F-002",
               "--verdict", "distinct") == 1
    err = capsys.readouterr().err
    assert "--because" in err
    assert "bb finding dedupe F-001 --against <uid> --verdict distinct" in err


def test_write_key_prints_the_computed_digest(engagement, capsys):
    complete_finding()
    capsys.readouterr()
    assert run("finding", "dedupe", "F-001", "--write-key") == 0
    digest = capsys.readouterr().out.strip()
    assert len(digest) == 64 and int(digest, 16) >= 0


# -- the waiver commands -----------------------------------------------------


def test_waive_request_records_the_argument_and_grants_nothing(engagement, capsys):
    complete_finding()
    with Store(paths.db_path(engagement)) as store:
        store.conn.execute("DELETE FROM evidence WHERE role = 'baseline'")
        store.conn.commit()
    capsys.readouterr()
    assert run("gate", "waive-request", "F-001", "gate_evidence_roles",
               "--reason", "the endpoint answers with no credential, so there is no "
                           "control working to photograph") == 0
    assert "grants nothing" in capsys.readouterr().out
    assert run("gate", "F-001") == 1
    assert "gate_evidence_roles" in capsys.readouterr().out


def test_a_granted_waiver_displays_as_waived_and_never_as_passed(engagement, capsys):
    complete_finding()
    with Store(paths.db_path(engagement)) as store:
        store.conn.execute("DELETE FROM evidence WHERE role = 'baseline'")
        store.conn.commit()
    capsys.readouterr()
    assert run("gate", "waive", "F-001", "gate_evidence_roles",
               "--reason", "the endpoint answers with no credential at all, so there is no "
                           "control working to photograph and no owner side",
               "--as", "operator@example.com") == 0
    assert "not a passed gate" in capsys.readouterr().out
    assert run("gate", "F-001") == 0
    printed = capsys.readouterr().out
    assert "waived gate_evidence_roles" in printed

    assert run("gate", "waivers") == 0
    assert "LIVE" in capsys.readouterr().out

    assert run("report", "F-001") == 0
    capsys.readouterr()
    text = (paths.engagement_dir(engagement) / "reports" / "F-001.md").read_text()
    assert "## Gates waived for this finding" in text
    assert "| gate_evidence_roles | **waived** |" in text


def test_an_agent_inside_a_running_phase_cannot_waive_its_own_gate(engagement, capsys):
    """The asymmetry made mechanical rather than written in a prompt."""
    complete_finding()
    with Store(paths.db_path(engagement)) as store:
        store.start_phase("07-gate")
    capsys.readouterr()
    assert run("gate", "waive", "F-001", "gate_evidence_roles",
               "--reason", "the endpoint answers with no credential at all, so there is no "
                           "control working to photograph and no owner side",
               "--as", "agent") == 1
    err = capsys.readouterr().err
    assert "while phase 07-gate is running" in err
    assert "bb gate waive-request" in err
    assert not list((paths.STATE_DIR / "waivers").rglob("*.json"))


def test_waive_without_a_grantor_is_refused(engagement, capsys):
    complete_finding()
    capsys.readouterr()
    assert run("gate", "waive", "F-001", "gate_evidence_roles", "--reason", "x" * 50) == 1
    assert "--as <who>" in capsys.readouterr().err


def test_a_mistyped_gate_subcommand_is_not_read_as_a_finding(engagement, capsys):
    assert run("gate", "wiave", "F-001", "gate_evidence_roles") == 1
    err = capsys.readouterr().err
    assert "does not understand" in err
    assert "bb gate waive <finding> <gate>" in err


# -- the process registry and the body reader --------------------------------


def test_cleanup_on_an_empty_registry_says_so_rather_than_all_clear(engagement, capsys):
    assert run("cleanup") == 0
    printed = capsys.readouterr().out
    assert "nothing registered" in printed
    assert "ps -o pid" in printed, "a process it never registered is not in here"


def test_proc_register_prints_the_cmdline_it_recorded(engagement, capsys):
    """The identity check defends against a recycled pid, not a mistyped one.

    So the registered argv is printed: the only reader who can catch the wrong
    pid is the one looking at that line.
    """
    import subprocess
    import sys

    child = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time\nwhile True: time.sleep(1)"]
    )
    try:
        assert run("proc", "register", str(child.pid), "--kind", "scan") == 0
        printed = capsys.readouterr().out
        assert f"registered pid {child.pid}" in printed
        assert "time.sleep" in printed, "the recorded argv has to be on screen"
        assert "bb cleanup" in printed
        assert run("proc", "list") == 0
        assert str(child.pid) in capsys.readouterr().out
    finally:
        child.kill()
        child.wait(timeout=5)


def test_registering_the_harness_itself_is_refused(engagement, capsys):
    """`bb cleanup` would then kill the shell that is running it."""
    import os

    assert run("proc", "register", str(os.getpid()), "--kind", "scan") == 1
    assert "kill the harness" in capsys.readouterr().err


def recorded_body(engagement: str, body: bytes) -> int:
    from bbh import http

    with Store(paths.db_path(engagement)) as store:
        stored = http.persist_body(paths.engagement_dir(engagement) / "raw" / "bodies", body)
        return store.add_request(
            source="client", actor="anon", method="GET",
            url="https://www.acme.example/api/docs/2", host="www.acme.example",
            path="/api/docs/2", status=200, resp_body_path=stored.path,
            resp_body_sha256=stored.sha256, resp_bytes=stored.length,
        )


def test_req_show_grep_separates_a_hit_a_clean_miss_and_a_refusal(engagement, capsys):
    """Three exit codes because they mean three different things to a caller."""
    rid = recorded_body(engagement, b'{"owner":"victim","marker":"CANARY"}' + b"x" * 4000)
    capsys.readouterr()

    assert run("req", "show", str(rid), "--grep", "CANARY") == 0
    assert "1 match(es)" in capsys.readouterr().out

    assert run("req", "show", str(rid), "--grep", "NOT-IN-THE-BODY") == 1
    capsys.readouterr()

    assert run("req", "show", "9999", "--grep", "CANARY") == 2
    assert "no request 9999" in capsys.readouterr().err


def test_req_show_reads_none_as_not_given_and_says_so(engagement, capsys):
    rid = recorded_body(engagement, b'{"owner":"victim"}' + b"x" * 4000)
    capsys.readouterr()
    assert run("req", "show", str(rid), "--grep", "none") == 0
    captured = capsys.readouterr()
    assert "read as 'not given'" in captured.err
    assert "response body" in captured.out


def test_req_show_does_not_shadow_a_real_request(engagement, capsys):
    """`show` is dispatched before bbh.http sees the argv; GET still routes there."""
    assert run("req") == 1
    assert "bb req show <id>" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# the suite's own isolation
# ---------------------------------------------------------------------------


def test_doctor_cannot_read_the_operators_real_settings_file(engagement, capsys):
    """House rule: no test touches ~/.claude/settings.json, reads included.

    `_check_hook` reads it, so without the conftest redirect this check's
    verdict depends on whether the developer running the suite happens to have
    `bb install-hook`ed -- a green run that means nothing on another machine.
    """
    from pathlib import Path

    assert cli.settings_file("global") != Path.home() / ".claude" / "settings.json"
    run("doctor", "--json")
    data = json.loads(capsys.readouterr().out)
    hook = next(c for c in data["checks"] if c["name"] == "hook")
    # Reported, but as a warning. It used to be a failure, which made `bb
    # doctor` say "not ready to hunt" when the harness was ready: `run_phase`
    # passes every phase its own `--settings` registering this same guard, so a
    # hunt is covered without the global hook. The hook covers what the
    # OPERATOR types, and it costs them `curl`/`wget`/`ssh` in every unrelated
    # project when no engagement is active. Both halves are pinned here so the
    # level cannot drift back to `fail` without someone reading why, and cannot
    # become `pass` while the hook is absent.
    assert hook["level"] == "warn", "a fresh settings file has no guard hook"
    assert "guard" in hook["detail"]
    assert "curl" in (hook["remedy"] or ""), "the cost of installing it has to be on the label"


# ---------------------------------------------------------------------------
# bb go: one command from a target to a running hunt
# ---------------------------------------------------------------------------
#
# What these cover is the seam, not argparse. `bb go` writes scope.yaml, arms
# the engagement and hands the result to the hunt, so the ways it can be wrong
# are all ways an operator loses something: an engagement rebuilt on top of a
# night's findings, a target that silently never reached the lock, an
# attestation that runs out before the hunt it was made for, or a record saying
# somebody read a policy page when nobody did.


@pytest.fixture
def hunts(monkeypatch) -> list:
    """Capture the HuntConfig `bb go` hands to run_hunt; never start one."""
    from bbh import runner

    seen: list = []

    def fake_run_hunt(cfg, on_event=None):
        seen.append(cfg)
        return {"status": "complete", "ok": True}

    monkeypatch.setattr(runner, "run_hunt", fake_run_hunt)
    return seen


def go_scope_text(name: str) -> str:
    return paths.scope_path(name).read_text(encoding="utf-8")


def go_in_scope(name: str) -> list[str]:
    """The hosts and networks the compiled lock authorizes, as the lock holds them."""
    lock = Scope.from_lock_file(paths.lock_path(name)).lock
    return [str(rule["value"]) for rule in lock["in_scope"]]


# -- the derived name --------------------------------------------------------


@pytest.mark.parametrize(
    "target,expected",
    [
        ("*.example.com", "example.com"),
        ("example.com", "example.com"),
        ("WWW.Example.COM", "www.example.com"),
        ("https://www.example.com/api/", "www.example.com"),
        ("198.51.100.0/24", "198.51.100.0-24"),
    ],
)
def test_the_engagement_name_is_derived_from_the_canonical_target(target, expected):
    assert cli.go_engagement_name(target) == expected


def test_a_wildcard_and_its_apex_name_the_same_engagement(hunts, capsys):
    """Otherwise `bb go example.com` after `bb go '*.example.com'` starts a second
    engagement beside the first, with none of its findings in it."""
    assert run("go", "*.example.com", "--hours", "2") == 0
    assert run("go", "example.com", "--hours", "2") == 0
    capsys.readouterr()
    assert paths.list_engagements() == ["example.com"]


def test_name_overrides_the_derivation(hunts, capsys):
    assert run("go", "*.example.com", "--name", "acme-prod", "--dry-run") == 0
    assert "acme-prod" in capsys.readouterr().out
    assert hunts == []


# -- the plan ----------------------------------------------------------------


def test_the_plan_states_every_default_before_anything_happens(hunts, capsys):
    """Each of these spends money or sends traffic; none of them is discoverable
    from the summary afterwards, which is printed when it is too late."""
    assert run("go", "*.example.com", "--dry-run") == 0
    out = capsys.readouterr().out
    assert "uncapped" in out
    assert f"{cli.GO_HOURS:g}h" in out
    assert cli.GO_MODEL in out
    assert "example.com" in out


def test_the_plan_is_printed_before_the_hunt_starts(monkeypatch, capsys):
    """A plan printed after the fact is a summary, and the point is consent."""
    from bbh import runner

    seen: list[str] = []

    def fake_run_hunt(cfg, on_event=None):
        seen.append(capsys.readouterr().out)
        return {"status": "complete", "ok": True}

    monkeypatch.setattr(runner, "run_hunt", fake_run_hunt)
    assert run("go", "*.example.com", "--hours", "2") == 0
    assert seen and "bb go -> engagement 'example.com'" in seen[0]
    assert "armed as" in seen[0]


def test_the_plan_names_what_is_not_running_in_one_line(hunts, capsys):
    """One line, because the operator settled this; a paragraph is a lecture."""
    assert run("go", "*.example.com", "--dry-run") == 0
    lines = [l for l in capsys.readouterr().out.splitlines() if "sandbox" in l]
    assert len(lines) == 1
    assert "--sandbox" in lines[0]


def test_dry_run_creates_compiles_and_starts_nothing(hunts, capsys):
    assert run("go", "*.example.com", "--dry-run") == 0
    assert "example.com" in capsys.readouterr().out
    assert paths.list_engagements() == []
    assert not paths.lock_path("example.com").exists()
    assert hunts == []


def test_dry_run_is_json_readable(hunts, capsys):
    assert run("go", "*.example.com", "--budget-usd", "40", "--hours", "8",
               "--dry-run", "--json") == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["engagement"] == "example.com"
    assert (plan["budget_usd"], plan["hours"]) == (40.0, 8.0)
    assert plan["reused"] is False and plan["sandbox"] is False


# -- creating, and then never clobbering -------------------------------------


def test_one_command_creates_compiles_arms_and_hunts(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    assert go_in_scope("example.com") == ["example.com"]
    assert cli.armed_state("example.com").armed
    assert paths.active_engagement() == "example.com"
    assert len(hunts) == 1


def test_a_rerun_keeps_the_findings_evidence_and_requests(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2") == 0
    with Store(paths.db_path("example.com")) as store:
        request_id = store.add_request(
            source="client", actor="attacker", method="GET",
            url="https://www.example.com/a", host="www.example.com", path="/a",
            status=200, phase="00-recon",
        )
        finding_id = store.add_finding("F-001", "kept", "idor", host="www.example.com")
        store.add_evidence(finding_id, "request", request_id=request_id)

    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    with Store(paths.db_path("example.com")) as store:
        assert store.get_finding("F-001") is not None
        assert store.request_count() == 1
        assert store.stats()["evidence"] == 1


def test_a_rerun_leaves_operator_edits_in_scope_yaml_untouched(hunts, capsys):
    """Exclusions, rules and program_constraints are the operator's own work.

    They are also the half of scope.yaml that only ever narrows what may be
    touched, so a re-run that dropped them would widen the boundary silently.
    """
    assert run("go", "*.example.com", "--hours", "2") == 0
    edited = go_scope_text("example.com").replace(
        "out_of_scope:\n", 'out_of_scope:\n  - "*.cdn.example.com"\n', 1
    ).replace(
        "# program_constraints:\n", "program_constraints:\n  max_rps: 0.5\n", 1
    )
    paths.scope_path("example.com").write_text(edited, encoding="utf-8")

    assert run("go", "*.example.com", "api.example.net", "--hours", "2") == 0
    capsys.readouterr()
    after = go_scope_text("example.com")
    assert '  - "*.cdn.example.com"' in after
    assert "program_constraints:\n  max_rps: 0.5" in after
    # Nothing else was dropped: every line that was in the file still is, bar
    # the three the fresh attestation replaces.
    replaced = ("attested_at", "expires_at", "statement:")
    kept = [l for l in edited.splitlines() if not any(k in l for k in replaced)]
    survivors = set(after.splitlines())
    assert [l for l in kept if l not in survivors] == []

    lock = Scope.from_lock_file(paths.lock_path("example.com")).lock
    assert lock["program_constraints"]["max_rps"] == 0.5
    assert [r["value"] for r in lock["out_of_scope"]] == ["cdn.example.com"]


def test_a_new_target_is_added_to_an_existing_engagement(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2") == 0
    assert run("go", "*.example.com", "api.example.net", "--hours", "2") == 0
    capsys.readouterr()
    assert sorted(go_in_scope("example.com")) == ["api.example.net", "example.com"]


def test_a_target_already_listed_is_not_written_a_second_time(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2") == 0
    before = go_scope_text("example.com").count("- '*.example.com'")
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    assert go_scope_text("example.com").count("- '*.example.com'") == before
    assert go_in_scope("example.com") == ["example.com"]


def test_a_rerun_resumes_rather_than_repeating_finished_phases(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2") == 0
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    assert [cfg.resume for cfg in hunts] == [False, True]


def test_a_splice_that_would_not_compile_puts_scope_yaml_back(hunts, capsys, monkeypatch):
    """A half-widened boundary is the one outcome worth protecting against."""
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    before = go_scope_text("example.com")

    from bbh import engagement as engagement_mod

    def refuse(name=None):
        raise engagement_mod.EngagementError("compile refused by the test")

    monkeypatch.setattr(engagement_mod, "compile_scope", refuse)
    assert run("go", "*.example.com", "api.example.net", "--hours", "2") == 1
    assert "put back exactly as it was" in capsys.readouterr().err
    assert go_scope_text("example.com") == before


# -- arming ------------------------------------------------------------------


def test_the_attestation_window_covers_the_hunt(hunts, capsys):
    """`run_hunt` refuses to start when the attestation lapses before the
    deadline, which is the check a 12h arming under a 12h hunt always failed."""
    from bbh import runner

    assert run("go", "*.example.com", "--hours", "12") == 0
    capsys.readouterr()
    cfg = hunts[0]
    _soft, hard = runner.deadlines(cfg)
    expiry = runner.authorization_expiry(Scope.from_lock_file(paths.lock_path("example.com")))
    assert hard is not None
    assert expiry > hard, "the hunt would die mid-run with every request denied"


def test_the_attestation_says_only_what_happened(hunts, capsys):
    """It is the record an operator may later have to stand behind, and nobody
    opened a policy page: `bb arm`'s sentence would be a false statement."""
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    auth = Scope.from_lock_file(paths.lock_path("example.com")).authorization
    assert "bb go" in auth["statement"]
    assert auth["policy_url"] is None
    assert "No program policy page was named or read" in auth["statement"]
    assert "I confirm I am authorized" not in auth["statement"]


def test_a_program_url_is_recorded_when_one_is_given(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2",
               "--program-url", "https://hackerone.com/example") == 0
    capsys.readouterr()
    auth = Scope.from_lock_file(paths.lock_path("example.com")).authorization
    assert auth["policy_url"] == "https://hackerone.com/example"
    assert "https://hackerone.com/example" in auth["statement"]
    assert "did not read" in auth["statement"]


def test_the_attestation_names_whoever_ran_the_command(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2", "--as", "a tester") == 0
    capsys.readouterr()
    auth = Scope.from_lock_file(paths.lock_path("example.com")).authorization
    assert auth["attested_by"] == "a tester"


def test_arming_through_go_lands_in_the_audit_chain(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    records = [json.loads(line) for line in audit_lines()]
    armed = [r for r in records if r.get("event") == "arm"]
    assert len(armed) == 1
    assert armed[0]["via"] == "bb go"
    assert cli.verify_audit_chain().ok


# -- the sandbox the operator turned off -------------------------------------


def test_the_hunt_runs_unsandboxed_unless_sandbox_is_asked_for(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    assert hunts[0].unsandboxed is True


def test_sandbox_opts_back_in(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2", "--sandbox") == 0
    capsys.readouterr()
    assert hunts[0].unsandboxed is False


# -- what reaches the hunt ---------------------------------------------------


def test_the_overrides_reach_the_hunt(hunts, capsys):
    assert run("go", "*.example.com", "--budget-usd", "40", "--hours", "8",
               "--model", "sonnet", "--phases", "00-recon", "--max-retries", "3") == 0
    capsys.readouterr()
    cfg = hunts[0]
    assert (cfg.budget_usd, cfg.model, cfg.max_retries) == (40.0, "sonnet", 3)
    assert cfg.phases == ["00-recon"]
    assert cfg.deadline is not None


@pytest.mark.parametrize("status,code", [("complete", 0), ("budget", 1), ("deadline", 1)])
def test_the_exit_code_is_the_hunts(monkeypatch, capsys, status, code):
    """A cron line or a wrapper reads nothing else."""
    from bbh import runner

    monkeypatch.setattr(
        runner, "run_hunt", lambda cfg, on_event=None: {"status": status, "reason": "r"}
    )
    assert run("go", "*.example.com", "--hours", "2") == code
    capsys.readouterr()


# -- refusals ----------------------------------------------------------------


def test_a_target_that_cannot_be_compiled_is_named_not_skipped(hunts, capsys):
    assert run("go", "*.example.com", "not a host", "--hours", "2") == 1
    err = capsys.readouterr().err
    assert "'not a host'" in err
    assert hunts == [] and paths.list_engagements() == []


def test_every_problem_is_reported_together(hunts, capsys):
    assert run("go", "nope nope", "--hours", "0", "--budget-usd", "0") == 1
    err = capsys.readouterr().err
    assert "'nope nope'" in err
    assert "--hours" in err and "--budget-usd" in err
    assert "Then retry: bb go" in err


def test_an_hours_value_the_attestation_cannot_cover_is_refused(hunts, capsys):
    """The cap is MAX_ARM_HOURS less the margin: arming past it would be refused
    by the engagement module after scope.yaml had already been written."""
    from bbh import engagement as engagement_mod

    assert run("go", "*.example.com", "--hours", str(engagement_mod.MAX_ARM_HOURS)) == 1
    assert "--hours" in capsys.readouterr().err
    assert hunts == []


def test_an_engagement_flag_that_disagrees_with_the_target_is_refused(hunts, capsys):
    assert run("-e", "somewhere-else", "go", "*.example.com") == 1
    err = capsys.readouterr().err
    assert "somewhere-else" in err and "--name" in err
    assert hunts == []


def test_go_needs_a_target(hunts, capsys):
    assert run("go", "   ") == 1
    assert "at least one target" in capsys.readouterr().err


def test_a_setup_failure_exits_before_the_hunt_with_its_own_message(hunts, capsys,
                                                                    monkeypatch):
    from bbh import secrets as secrets_mod

    def refuse(name=None):
        raise secrets_mod.SecretError("cannot secure raw/: test")

    monkeypatch.setattr(secrets_mod, "harden_raw", refuse)
    assert run("go", "*.example.com", "--hours", "2") == 1
    assert "cannot secure raw/" in capsys.readouterr().err
    assert hunts == []


def test_an_inline_in_scope_list_is_refused_rather_than_rewritten(hunts, capsys):
    """Rewriting the line would lose whatever the operator put around it."""
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    text = go_scope_text("example.com")
    start = text.index("in_scope:")
    end = text.index("out_of_scope:")
    paths.scope_path("example.com").write_text(
        text[:start] + 'in_scope: ["*.example.com"]\n\n' + text[end:], encoding="utf-8"
    )
    assert run("go", "*.example.com", "api.example.net", "--hours", "2") == 1
    assert "block list" in capsys.readouterr().err


def test_go_on_an_engagement_bb_new_made_does_not_duplicate_its_targets(hunts, capsys):
    """`bb new` writes the targets but compiles nothing, so there is no lock to
    diff against; diffing against nothing wrote a second copy of each one."""
    assert run("new", "example.com", "--target", "*.example.com") == 0
    assert not paths.lock_path("example.com").exists()
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    assert go_in_scope("example.com") == ["example.com"]


def test_go_fills_in_the_target_an_empty_engagement_is_missing(hunts, capsys):
    """`bb new <name>` with no target leaves a scope.yaml that cannot compile;
    the target `bb go` is adding is exactly what fixes it."""
    assert run("new", "example.com") == 0
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    assert go_in_scope("example.com") == ["example.com"]
    assert cli.armed_state("example.com").armed


def test_a_phase_typo_is_refused_before_an_engagement_is_armed(hunts, capsys):
    """`cmd_hunt` checks the same list, but only after `bb go` has created and
    armed one; a typo should not leave an armed engagement behind it."""
    assert run("go", "*.example.com", "--phases", "00-recon,99-magic") == 1
    err = capsys.readouterr().err
    assert "99-magic" in err and "00-recon" in err
    assert paths.list_engagements() == [] and hunts == []


def test_a_blank_model_is_refused(hunts, capsys):
    assert run("go", "*.example.com", "--model", "") == 1
    assert "--model" in capsys.readouterr().err
    assert hunts == []


@pytest.mark.parametrize("literal", ["none", "nil", "null", "undefined", "None"])
def test_a_placeholder_target_is_not_read_as_a_host(hunts, capsys, literal):
    """`none` is the literal a model passes where it means 'no value'. Reading it
    as a hostname would start an engagement against a host nobody chose, and
    `compile_rule` accepts every one of these as a single-label domain."""
    assert run("go", literal) == 1
    err = capsys.readouterr().err
    assert repr(literal) in err, "the refusal has to name the value it would not read"
    assert f"bb go https://{literal.lower()}/" in err, "and say how to mean it literally"
    assert paths.list_engagements() == [] and hunts == []


def test_a_placeholder_among_real_targets_refuses_instead_of_vanishing(hunts, capsys):
    """The dangerous shape is not `bb go none`, which has nowhere to go: it is a
    placeholder beside a real host, where dropping it leaves a hunt running
    against a narrower scope than the one that was typed."""
    assert run("go", "nil", "www.example.com") == 1
    err = capsys.readouterr().err
    assert "'nil'" in err
    assert paths.list_engagements() == [] and hunts == []


def test_a_blank_target_among_real_ones_refuses_instead_of_vanishing(hunts, capsys):
    """`bb go "$A" "$B"` with B unset is the same mistake the shell makes for you."""
    assert run("go", "www.example.com", "") == 1
    err = capsys.readouterr().err
    assert "1 of the 2 targets" in err
    assert paths.list_engagements() == [] and hunts == []


def test_a_literal_host_is_still_reachable_as_a_url_prefix(hunts):
    """The refusal above has to leave a way to mean it, or it is just a block."""
    assert run("go", "https://nil/", "--dry-run") == 0
    assert paths.list_engagements() == [] and hunts == []
    assert cli.go_engagement_name("https://nil/") == "nil"


def test_the_plan_leads_the_log_even_when_the_output_is_redirected():
    """Driven as a real process, because the defect only exists in a real one.

    In-process, capsys keeps stdout and stderr apart and any order looks right.
    Redirected to a file -- which is how an unattended hunt is run -- CPython
    block-buffers stdout and leaves stderr unbuffered, so the plan that was
    printed first arrived last and the log opened on a refusal with no mention
    of which domain had just been armed.

    `--sandbox` on a machine with no sandbox built is the shortest path to a
    run that prints the plan and then fails: the refusal comes from the hunt,
    so nothing spawns.
    """
    import subprocess

    done = subprocess.run(
        [str(paths.REPO / "bin" / "bb"), "go", "*.example.test", "--sandbox"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # one pipe, so what comes back IS the order
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=180,
    )
    assert done.returncode == 1
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    assert lines, done.stdout
    assert lines[0].startswith("bb go -> engagement 'example.test'"), done.stdout
    assert "*.example.test" in lines[1], done.stdout
    refusal = next(i for i, line in enumerate(lines) if "egress containment" in line)
    plan_end = next(i for i, line in enumerate(lines) if line.startswith("  output "))
    assert plan_end < refusal, "the whole plan belongs above the refusal"


def test_a_required_value_is_never_read_as_a_placeholder(engagement, capsys):
    """`target` is optional for `bb new --target` and required for `bb scope
    check`; one flat set of dest names made the required one as blankable as
    the optional one, and the command crashed on the None it was handed."""
    assert run("scope", "check", "none") == 1, "a host outside the scope is a DENY, not a crash"
    captured = capsys.readouterr()
    assert "DENY" in captured.out and "none" in captured.out
    assert "unexpected TypeError" not in captured.err
    assert "read as 'not given'" not in captured.err


def test_an_optional_filter_of_the_same_name_is_still_read_as_a_placeholder(
    engagement, capsys
):
    """The other half of the same rule: `state` is required by `bb finding
    advance` and optional for `bb finding list`, and scoping the normalisation
    to the subcommand that parsed is what lets both be true at once."""
    run("finding", "add", "--title", "Cross-account read", "--class", "idor")
    capsys.readouterr()
    assert run("finding", "list", "--state", "none") == 0
    captured = capsys.readouterr()
    assert "F-001" in captured.out
    assert "read as 'not given'" in captured.err


# ---------------------------------------------------------------------------
# the dollar cap: optional on `bb hunt`, absent by default on `bb go`
# ---------------------------------------------------------------------------
#
# The operator asked not to be stopped by what a hunt has spent, and not to
# have to pass a flag to say so. What these cover is that the choice is real
# everywhere it has to be -- the config the hunt runs under, the plan printed
# before it starts, the one-line header -- and that nothing else arrives at
# "no cap" by accident: a number that cannot be read is still a refusal, and
# `bb hunt`'s own ceiling is still there for anyone relying on it.


def test_bb_go_hunts_with_no_dollar_cap_unless_one_is_asked_for(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2") == 0
    capsys.readouterr()
    assert hunts[0].budget_usd is None


def test_bb_go_takes_a_cap_back(hunts, capsys):
    assert run("go", "*.example.com", "--hours", "2", "--budget-usd", "40") == 0
    capsys.readouterr()
    assert hunts[0].budget_usd == 40.0


def test_the_uncapped_plan_names_what_stops_the_hunt_instead(hunts, capsys):
    """The word "uncapped" alone reads as unbounded, and the hunt is not."""
    assert run("go", "*.example.com", "--dry-run") == 0
    printed = capsys.readouterr().out
    lines = [l for l in printed.splitlines() if l.startswith("  ")]
    budget = next(l for l in lines if l.startswith("  budget"))
    bound = next(l for l in lines if l.startswith("  bounded by"))
    assert "uncapped" in budget and "recorded" in budget
    assert "turns across 10 phases" in bound
    assert "$0.00" not in printed and "None" not in printed


def test_the_uncapped_plan_is_machine_readable_as_a_null_not_a_zero(hunts, capsys):
    """A wrapper that reads the plan has to be able to tell the two apart."""
    assert run("go", "*.example.com", "--dry-run", "--json") == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["budget_usd"] is None
    assert "turns across 10 phases" in plan["turn_budget"]


def test_a_cap_that_cannot_be_read_is_still_a_refusal(hunts, capsys):
    """Fail closed. 0 is what `--budget-usd ${CAP:-0}` expands to when nobody
    set CAP, and reading the commonest way to lose a number as a request for
    unlimited spend is the opposite of what a default of none is for."""
    assert run("go", "*.example.com", "--hours", "2", "--budget-usd", "0") == 1
    err = capsys.readouterr().err
    assert "--budget-usd is 0" in err and "--no-budget" not in err
    assert "bb go <target>" in err
    assert hunts == []


def test_bb_hunt_keeps_its_own_ceiling(hunts, engagement, capsys):
    """The explicit-control path: an upgrade must not quietly remove a cap."""
    assert run("hunt", engagement) == 0
    capsys.readouterr()
    assert hunts[0].budget_usd == cli.HUNT_BUDGET_USD


def test_bb_hunt_gives_the_cap_up_by_name(hunts, engagement, capsys):
    assert run("hunt", engagement, "--no-budget") == 0
    out = capsys.readouterr().out
    assert hunts[0].budget_usd is None
    assert "budget uncapped" in out
    assert "turns across 10 phases" in out


def test_the_uncapped_header_counts_only_the_phases_that_will_run(
    hunts, engagement, capsys
):
    assert run("hunt", engagement, "--no-budget", "--phases", "00-recon,02-sweep") == 0
    assert "180 turns across 2 phases" in capsys.readouterr().out


def test_asking_for_both_a_cap_and_no_cap_is_refused_not_resolved(
    hunts, engagement, capsys
):
    """Either precedence rule silently throws away something that was typed."""
    assert run("hunt", engagement, "--no-budget", "--budget-usd", "40") == 1
    err = capsys.readouterr().err
    assert "--no-budget and --budget-usd 40" in err
    assert f"bb hunt {engagement} --no-budget" in err
    assert f"bb hunt {engagement} --budget-usd 40" in err
    assert hunts == []


def test_a_zero_cap_on_bb_hunt_names_the_flag_that_does_mean_unlimited(
    hunts, engagement, capsys
):
    assert run("hunt", engagement, "--budget-usd", "0") == 1
    err = capsys.readouterr().err
    assert "--budget-usd is 0" in err
    assert f"bb hunt {engagement} --no-budget" in err
    assert hunts == []


def test_bb_phase_refusals_name_bb_phase(engagement, capsys):
    """`bb phase` and `bb hunt` share the builder; sending a `bb phase` caller
    to `bb hunt` changes what the command does, not just the flag it carries."""
    assert run("phase", "00-recon", engagement, "--budget-usd", "0") == 1
    assert f"bb phase 00-recon {engagement} --no-budget" in capsys.readouterr().err


def test_every_budget_flag_the_refusals_name_actually_parses():
    """A remedy that does not parse is worse than no remedy."""
    for argv in (
        ("hunt", "acme", "--no-budget"),
        ("hunt", "acme", "--resume", "--no-budget"),
        ("hunt", "acme", "--budget-usd", "25"),
        ("phase", "00-recon", "acme", "--no-budget"),
        ("go", "*.example.com", "--budget-usd", "25"),
    ):
        cli.build_parser().parse_args(list(argv))


def test_bb_go_can_say_the_default_out_loud(hunts, capsys):
    """An operator who learned --no-budget from `bb hunt` should not meet an
    'unrecognized arguments' from the command the flag is already true for."""
    assert run("go", "*.example.com", "--hours", "2", "--no-budget") == 0
    capsys.readouterr()
    assert hunts[0].budget_usd is None


def test_bb_go_refuses_a_cap_and_no_cap_together_too(hunts, capsys):
    assert run("go", "*.example.com", "--no-budget", "--budget-usd", "40") == 1
    err = capsys.readouterr().err
    assert "--no-budget and --budget-usd 40" in err
    assert hunts == []
