"""The v2 modules reaching each other through the CLI.

The v2 hardening landed as several modules built in parallel, and each one was
green on its own while the seam between it and the CLI was not. These tests pin
the seams, because every one of them was a real break: the store understood
`ruled_out` and argparse rejected it before the store ever saw it; `bb gate` ran
the published seven and never the five gates that decide whether a human reads a
report; `gate_evidence_roles` and `gate_prerequisites_reachable` named remedies
for flags and a subcommand that did not exist, so a finding could not be made to
satisfy its own gate; and four modules appended audit lines that nothing chained.

A module being green is not the same as a module being connected. These are the
connection.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pytest

from bbh import cli, paths
from bbh.store import ANGLE_OUTCOMES as STORE_ANGLE_OUTCOMES
from bbh.store import Store


def run(*argv) -> int:
    return cli.main(list(argv))


def parses(*argv) -> bool:
    try:
        cli.build_parser().parse_args(list(argv))
        return True
    except SystemExit:
        return False


# ---------------------------------------------------------------------------
# the angle ledger speaks one vocabulary
# ---------------------------------------------------------------------------


def test_every_store_outcome_word_is_reachable_through_the_cli():
    """The CLI held a second, v1-only copy of this list. The store is the source."""
    for word in STORE_ANGLE_OUTCOMES:
        assert word in cli.ANGLE_OUTCOMES, word


@pytest.mark.parametrize("word", list(STORE_ANGLE_OUTCOMES))
def test_the_parser_accepts_every_v2_outcome(word):
    assert parses("angle", "add", "s", "idor", "t", word)


def test_ruled_out_records_the_control_it_names(engagement, capsys):
    assert run("angle", "add", "app.acme.example/docs", "idor", "id-swap", "ruled_out",
               "--control", "server-side ownership check 403s every other id") == 0
    capsys.readouterr()
    with Store(paths.db_path(engagement)) as store:
        row = store.angles()[0]
    assert row["outcome"] == "ruled_out"
    assert "ownership check" in row["control"]


def test_ruled_out_without_a_control_is_refused_with_the_retry_line(engagement, capsys):
    """The store's requirement has to be reachable, not bypassed by argparse."""
    assert run("angle", "add", "s", "idor", "id-swap", "ruled_out") == 1
    err = capsys.readouterr().err
    assert "--control" in err and "open_gap" in err


def test_open_gap_without_a_next_test_is_refused(engagement, capsys):
    assert run("angle", "add", "s", "idor", "id-swap", "open_gap") == 1
    assert "--next-test" in capsys.readouterr().err


def test_open_gap_records_the_test_it_did_not_get_to(engagement, capsys):
    assert run("angle", "add", "s", "ssrf", "redirect-chain", "open_gap",
               "--next-test", "POST /api/fetch with a 302 to 169.254.169.254") == 0
    capsys.readouterr()
    with Store(paths.db_path(engagement)) as store:
        row = store.angles()[0]
    assert row["outcome"] == "open_gap"
    assert "169.254.169.254" in row["next_test"]


def test_a_v1_word_still_works_and_is_stored_as_its_v2_equivalent(engagement, capsys):
    """The phase prompts still teach `negative`; it must not start failing."""
    assert run("angle", "add", "s", "idor", "id-swap", "negative") == 0
    out = capsys.readouterr().out
    with Store(paths.db_path(engagement)) as store:
        assert store.angles()[0]["outcome"] == "ruled_out"
    assert "v1 word" in out


def test_the_machine_source_is_settable(engagement, capsys):
    assert run("angle", "add", "s", "availability", "rate-limit", "blocked",
               "--source", "machine") == 0
    capsys.readouterr()
    with Store(paths.db_path(engagement)) as store:
        assert store.angles()[0]["source"] == "machine"


# ---------------------------------------------------------------------------
# bb gate runs the gates that guard the rung
# ---------------------------------------------------------------------------


@pytest.fixture
def v1_bar(engagement, capsys):
    """A finding that passes the published seven and nothing more."""
    run("account", "add", "attacker", "--role", "attacker")
    run("account", "add", "victim", "--role", "victim")
    with Store(paths.db_path(engagement)) as store:
        store.add_request(
            source="client", actor="attacker", method="GET",
            url="https://www.acme.example/api/docs/2", host="www.acme.example",
            path="/api/docs/2", status=200,
        )
    run("object", "add", "victim-doc", "--kind", "document",
        "--identifier", "2", "--owner", "victim")
    run("finding", "add", "--title", "Cross-account document read", "--class", "idor",
        "--host", "www.acme.example", "--endpoint", "/api/docs/2")
    run("evidence", "add", "F-001", "request", "--request-id", "1")
    run("finding", "set", "F-001", "--severity", "high",
        "--repro", "1. Sign in as attacker.\n"
                   "2. GET https://www.acme.example/api/docs/2\n3. Read it.")
    capsys.readouterr()
    return engagement


def test_gate_runs_the_v2_gates_not_only_the_published_seven(v1_bar, capsys):
    """This finding used to pass `bb gate`. Under v2 it must not."""
    assert run("gate", "F-001") == 1
    printed = capsys.readouterr().out
    assert "gate_severity_derived" in printed
    assert "gate_evidence_roles" in printed
    assert "gate_prerequisites_reachable" in printed
    assert "gate_independent_verification" in printed


def test_gate_names_how_many_gates_it_ran(v1_bar, capsys):
    """The count comes from triage, so a gate added there cannot leave this stale."""
    from bbh import triage

    run("gate", "F-001")
    expected = len(triage.gates_for_state("gated"))
    assert expected >= 13, "the v2 gates plus the frozen-claim gate"
    assert f"gating to gated: {expected} gate(s)" in capsys.readouterr().out


def test_gate_target_validated_runs_only_the_rung_below(v1_bar, capsys):
    """A rung has its own gates; the later bar is not applied to the earlier rung."""
    run("finding", "set", "F-001",
        "--counterevidence",
        "Repeated with a fresh profile and with no session at all: the first returned the "
        "victim document, the second a 401, so neither a cache nor a public route explains it.",
        "--severity-change-conditions", "critical if document ids are enumerable",
        "--confidence", "high")
    capsys.readouterr()
    assert run("gate", "F-001", "--target", "validated") == 0
    printed = capsys.readouterr().out
    assert "gating to validated: 7 gate(s)" in printed
    assert "gate_severity_derived" not in printed
    with Store(paths.db_path(v1_bar)) as store:
        assert store.get_finding("F-001")["state"] == "validated"


def test_passing_every_gate_does_not_bypass_the_advance_bar(v1_bar, capsys):
    """Two independent brakes, and the one that is not a gate still holds.

    `advance(..., 'validated')` refuses a finding with no counterevidence,
    whatever the gates said. A caller that reads an all-pass gate run as
    permission to move the finding is wrong, and the refusal has to arrive as a
    readable message rather than a traceback, because an agent acts on it.
    """
    assert run("gate", "F-001", "--target", "validated") == 1
    err = capsys.readouterr().err
    assert "counterevidence is empty" in err
    assert "bb finding set F-001 --counterevidence" in err
    with Store(paths.db_path(v1_bar)) as store:
        assert store.get_finding("F-001")["state"] == "candidate"


def test_an_unguarded_rung_is_refused_by_name(v1_bar, capsys):
    assert not parses("gate", "F-001", "--target", "rejected")


# ---------------------------------------------------------------------------
# severity is derived, so the CLI has to derive it
# ---------------------------------------------------------------------------


def test_the_contract_spelling_of_the_cvss_flag_parses():
    """triage.py's remedy and CONTRACT v2 item 9 both write `--cvss`."""
    assert parses("finding", "set", "F-1", "--cvss", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert parses("finding", "set", "F-1", "--cvss-vector", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")


def test_setting_a_vector_computes_the_severity(engagement, capsys):
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    capsys.readouterr()
    assert run("finding", "set", "F-001",
               "--cvss", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 0
    assert "base score 7.5" in capsys.readouterr().out
    with Store(paths.db_path(engagement)) as store:
        row = store.get_finding("F-001")
    assert row["severity"] == "high"
    assert row["cvss_vector"] == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def test_a_severity_that_contradicts_the_vector_is_refused(engagement, capsys):
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    capsys.readouterr()
    assert run("finding", "set", "F-001", "--severity", "critical",
               "--cvss", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 1
    err = capsys.readouterr().err
    assert "contradicts" in err and "7.5" in err
    with Store(paths.db_path(engagement)) as store:
        assert store.get_finding("F-001")["severity"] is None


def test_an_unusable_vector_is_refused_with_an_example(engagement, capsys):
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    capsys.readouterr()
    assert run("finding", "set", "F-001", "--cvss", "AV:N/AC:L") == 1
    err = capsys.readouterr().err
    assert "CVSS" in err and "bb finding set" in err


def test_the_validated_fields_are_settable_from_the_cli(engagement, capsys):
    """advance(..., 'validated') refuses while these are empty."""
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    capsys.readouterr()
    assert run(
        "finding", "set", "F-001",
        "--counterevidence",
        "Repeated with a fresh profile and with no session: the first returned the victim "
        "document, the second a 401, so neither a cache nor a public route explains it.",
        "--severity-change-conditions", "critical if ids are enumerable",
        "--confidence", "high",
        "--confidence-rationale", "reproduced twice from separate sessions",
        "--delivery", "production_realistic",
    ) == 0
    capsys.readouterr()
    assert run("finding", "advance", "F-001", "validated") == 0


# ---------------------------------------------------------------------------
# the reachability ledger is writable
# ---------------------------------------------------------------------------


def test_the_prerequisite_remedy_spelling_parses():
    """gate_prerequisites_reachable emits this exact command."""
    assert parses("prereq", "add", "F-1", "victim document id",
                  "--attacker-start", "a", "--acquisition", "b",
                  "--verdict", "reachable", "--request-id", "4", "--searched", "c")
    assert parses("prereq", "list", "F-1")


def test_a_prerequisite_defaults_to_not_reachable(engagement, capsys):
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    capsys.readouterr()
    assert run("prereq", "add", "F-001", "victim document id") == 0
    capsys.readouterr()
    with Store(paths.db_path(engagement)) as store:
        rows = store.prerequisites_for("F-001")
    assert [r["verdict"] for r in rows] == ["not_reachable"]


def test_reachable_without_a_request_says_it_will_not_verify(engagement, capsys):
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    capsys.readouterr()
    assert run("prereq", "add", "F-001", "victim document id",
               "--verdict", "reachable") == 0
    assert "does not reach 'verified'" in capsys.readouterr().out


def test_prereq_add_refuses_an_unknown_finding(engagement, capsys):
    assert run("prereq", "add", "F-404", "x") == 1
    assert "no finding" in capsys.readouterr().err


def test_prereq_list_renders_the_ledger(engagement, capsys):
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    run("prereq", "add", "F-001", "victim document id",
        "--acquisition", "the listing endpoint enumerates every tenant")
    capsys.readouterr()
    assert run("prereq", "list", "F-001") == 0
    printed = capsys.readouterr().out
    assert "victim document id" in printed and "not_reachable" in printed


# ---------------------------------------------------------------------------
# evidence roles are recordable
# ---------------------------------------------------------------------------


def test_the_evidence_role_remedy_spelling_parses():
    """gate_evidence_roles emits this exact command."""
    for role in ("baseline", "attack", "verification", "context"):
        assert parses("evidence", "add", "F-1", "request", "--request-id", "3",
                      "--role", role), role


def test_a_role_is_stored_at_capture_time(engagement, capsys):
    with Store(paths.db_path(engagement)) as store:
        store.add_request(source="client", actor="victim", method="GET",
                          url="https://www.acme.example/a", host="www.acme.example")
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    capsys.readouterr()
    assert run("evidence", "add", "F-001", "request", "--request-id", "1",
               "--role", "baseline") == 0
    assert "role=baseline" in capsys.readouterr().out
    with Store(paths.db_path(engagement)) as store:
        assert [r["role"] for r in store.evidence_for("F-001", "baseline")] == ["baseline"]


def test_an_unroled_capture_says_which_classes_need_a_pair(engagement, capsys):
    with Store(paths.db_path(engagement)) as store:
        store.add_request(source="client", actor="victim", method="GET",
                          url="https://www.acme.example/a", host="www.acme.example")
    run("finding", "add", "--title", "t", "--class", "idor", "--host", "www.acme.example")
    capsys.readouterr()
    run("evidence", "add", "F-001", "request", "--request-id", "1")
    printed = capsys.readouterr().out
    assert "role=context" in printed
    assert "baseline" in printed and "attack" in printed


# ---------------------------------------------------------------------------
# every writer chains its audit line
# ---------------------------------------------------------------------------


def chain() -> cli.ChainReport:
    return cli.verify_audit_chain()


def test_a_guard_denial_is_chained(engagement, tmp_path):
    """The guard writes the line a steered agent would most want to remove."""
    from bbh import guard

    payload = {"tool_name": "Bash", "cwd": str(tmp_path),
               "tool_input": {"command": "curl -sS https://evil.example/"}}
    guard._audit(payload, guard.check_command(payload["tool_input"]["command"], tmp_path))
    report = chain()
    assert report.lines == 1
    assert report.chained == 1, "the guard's line is not being chained"
    assert report.unchained == 0
    assert report.ok


def test_the_guard_record_keeps_its_flat_shape(engagement, tmp_path):
    """Chaining must not move the keys `bb audit` and the tests read."""
    from bbh import guard

    payload = {"tool_name": "Bash", "cwd": str(tmp_path),
               "tool_input": {"command": "curl -sS https://evil.example/"}}
    guard._audit(payload, guard.check_command(payload["tool_input"]["command"], tmp_path))
    record = json.loads(paths.AUDIT_LOG.read_text().splitlines()[-1])
    assert record["allowed"] is False
    assert record["tool"] == "curl"
    assert "evil.example" in record["command"]
    assert record["prev"] == cli.AUDIT_GENESIS
    assert record["event"] == "guard_decision"


def test_a_lifecycle_event_is_chained(engagement):
    from bbh import engagement as lifecycle

    lifecycle.disarm(engagement)
    report = chain()
    assert report.chained == report.lines >= 1
    assert report.ok


def test_mixed_writers_still_form_one_chain(engagement, tmp_path):
    from bbh import engagement as lifecycle
    from bbh import guard

    cli.audit_append("secret_put", {"label": "x"})
    guard._audit(
        {"tool_name": "Bash", "cwd": str(tmp_path),
         "tool_input": {"command": "curl -sS https://evil.example/"}},
        guard.check_command("curl -sS https://evil.example/", tmp_path),
    )
    lifecycle.disarm(engagement)
    report = chain()
    assert report.lines >= 3
    assert report.unchained == 0, "every writer chains"
    assert report.ok


def test_editing_any_writers_line_is_detected(engagement, tmp_path):
    from bbh import guard

    for _ in range(2):
        guard._audit(
            {"tool_name": "Bash", "cwd": str(tmp_path),
             "tool_input": {"command": "curl -sS https://evil.example/"}},
            guard.check_command("curl -sS https://evil.example/", tmp_path),
        )
    cli.audit_append("later", {})
    lines = paths.AUDIT_LOG.read_text().splitlines()
    first = json.loads(lines[0])
    first["allowed"] = True  # the edit an agent that did not like a denial would make
    lines[0] = json.dumps(first)
    paths.AUDIT_LOG.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = chain()
    assert not report.ok
    assert "breaks the chain" in report.problems[0]


def test_bb_audit_still_renders_a_chained_guard_record(engagement, tmp_path, capsys):
    from bbh import guard

    guard._audit(
        {"tool_name": "Bash", "cwd": str(tmp_path),
         "tool_input": {"command": "curl -sS https://evil.example/"}},
        guard.check_command("curl -sS https://evil.example/", tmp_path),
    )
    capsys.readouterr()
    assert run("audit", "--denied") == 0
    printed = capsys.readouterr().out
    assert "DENY" in printed
    assert "evil.example" in printed
    assert "prev" not in printed, "the chain field is machinery, not a decision"


def test_doctor_no_longer_warns_that_writers_do_not_chain(engagement, tmp_path):
    from bbh import guard

    guard._audit(
        {"tool_name": "Bash", "cwd": str(tmp_path),
         "tool_input": {"command": "curl -sS https://evil.example/"}},
        guard.check_command("curl -sS https://evil.example/", tmp_path),
    )
    checks = {c.name: c for c in cli._chain_checks()}
    assert checks["audit chain"].level == "pass"


# ---------------------------------------------------------------------------
# the phase prompts only teach commands that exist
# ---------------------------------------------------------------------------
#
# Every phase prompt is handed to a model with no way to check a command before
# running it, so a prompt naming a subcommand or a flag the CLI does not have
# costs the agent a turn and teaches it the harness is unreliable. Both halves
# of this went stale when v2 landed: the preamble taught `bb req <METHOD> <URL>`
# after --actor became mandatory, and `bb angle add ... negative` after the
# store moved to the v2 vocabulary.


def _subparsers(parser):
    for action in argparse_actions(parser):
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    return {}


def argparse_actions(parser):
    return list(parser._actions)


def _resolve(words):
    """The parser for a subcommand path, or None if the path does not exist."""
    current = cli.build_parser()
    for word in words:
        children = _subparsers(current)
        if word not in children:
            return None
        current = children[word]
    return current


def _options(parser):
    found = set()
    for action in argparse_actions(parser):
        found.update(action.option_strings)
    return found


def prompt_commands():
    """(file, subcommand words, flags, line) for every `bb ...` a prompt names."""
    command = re.compile(r"\bbb ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?")
    flag = re.compile(r"(?<![\w-])(--[a-z][a-z-]+)")
    for path in sorted(paths.PROMPTS.glob("*.md")):
        # Shell line continuations first: a flag on the next line belongs to the
        # command on this one.
        text = re.sub(r"\\\n\s*", " ", path.read_text(encoding="utf-8"))
        for raw in text.splitlines():
            line = raw.strip()
            match = command.search(line)
            if not match:
                continue
            words = [match.group(1)]
            top = _resolve(words)
            if top is not None and match.group(2) in _subparsers(top):
                words.append(match.group(2))
            yield path.name, tuple(words), flag.findall(line[match.start():]), line


def test_the_prompts_name_only_subcommands_that_exist():
    missing = {
        (name, words)
        for name, words, _flags, _line in prompt_commands()
        if _resolve(list(words)) is None
    }
    assert not missing, f"prompts name subcommands the CLI does not have: {sorted(missing)}"


def _known_flags(words, line):
    """The options the parser that would handle this line actually accepts.

    `bb req` and `bb gate` both take their arguments positionally rather than as
    subparsers -- `bb req`'s first word is an HTTP method and `bb gate`'s is a
    finding reference, so neither can be a subparser group -- which means a flag
    on one of their hand-dispatched forms has to be checked against the parser
    that really reads it. `bb req show` has its own; `bb gate waive` declares
    its flags on `bb gate`.
    """
    from bbh.http import _req_parser

    if words == ("req",):
        after = line.split()
        if len(after) > 2 and after[2].lower() == "show":
            return _options(cli._req_show_parser())
        return _options(_req_parser())
    parser = _resolve(list(words))
    return _options(parser) if parser is not None else None


def test_the_prompts_name_only_flags_that_exist():
    problems = set()
    for name, words, flags, line in prompt_commands():
        if _resolve(list(words)) is None:
            continue
        known = _known_flags(words, line)
        for found in flags:
            if found not in known:
                problems.add((name, "bb " + " ".join(words), found, line[:100]))
    assert not problems, "prompts name flags that do not exist: " + "\n".join(
        f"{n}: {c} {f}  ({l})" for n, c, f, l in sorted(problems)
    )


def test_every_bb_command_a_module_refusal_names_also_parses():
    """A remedy naming a flag that does not parse is a dead end for an agent.

    The prompts have been checked since v2; the refusal messages the modules
    themselves emit had not been, and that is where an agent meets most of them
    -- mid-hunt, with no way to check a spelling before running it. This found
    `bb angle add --outcome blocked` in the guard's own socket refusal, where
    the outcome has always been positional.
    """
    import re as _re

    problems = set()
    for path in sorted((paths.REPO / "bbh").glob("*.py")):
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "bb " not in raw:
                continue
            # f-string interpolations stand in for a value, not a flag.
            text = _re.sub(r"\{[^{}]*\}", "X", raw)
            # One line can hold two commands: `bb scope compile X && bb arm X --as Y`.
            for piece in _re.split(r"&&|\|\||;", text):
                for chunk in _re.split(r"(?=\bbb )", piece):
                    chunk = chunk.strip()
                    match = re.compile(r"\bbb ([a-z][a-z0-9-]*)(?: ([a-z][a-z0-9-]*))?").search(
                        chunk
                    )
                    if not match:
                        continue
                    words = [match.group(1)]
                    top = _resolve(words)
                    if top is None:
                        continue  # prose such as "bb scans every report"
                    if match.group(2) and match.group(2) in _subparsers(top):
                        words.append(match.group(2))
                    known = _known_flags(tuple(words), chunk)
                    if known is None:
                        continue
                    rest = chunk[match.start():]
                    # A flag wrapped in its own backticks or quotes is prose
                    # about the flag (`a `--json` written after the`, `-d
                    # '--json'`), not a flag in a command line. One preceded by
                    # a space is the real thing.
                    for found in _re.findall(r"(?<=[ ])(--[a-z][a-z-]+)", rest):
                        if found not in known:
                            problems.add(
                                (f"{path.name}:{number}", "bb " + " ".join(words), found)
                            )
    assert not problems, "refusal text names flags that do not parse: " + "\n".join(
        f"{where}: {command} {flag}" for where, command, flag in sorted(problems)
    )


def test_the_preamble_teaches_the_mandatory_actor():
    """--actor is enforced at request time, so every prompt has to say so."""
    for path in sorted(paths.PROMPTS.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        assert "--actor" in text, path.name
        assert "bb req <METHOD> <URL> --actor" in text, path.name


def test_no_prompt_still_teaches_the_v1_angle_vocabulary_as_the_whole_list():
    """The v1 words still work, but a prompt offering only them hides open_gap."""
    for path in sorted(paths.PROMPTS.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        assert "<negative|blocked|finding|partial>" not in text, path.name
        for word in ("ruled_out", "open_gap"):
            assert word in text, f"{path.name} does not mention {word}"


# ---------------------------------------------------------------------------
# the one vocabulary that is deliberately defined twice
# ---------------------------------------------------------------------------


def test_the_omitted_literals_agree_across_the_cli_and_the_client():
    """Two modules, one list, and they have to mean the same thing.

    `bb finding list --state none` and `bb req --actor none` both have to read
    as "not given". The CLI normalises its own arguments and bbh.http has to
    make the same judgement for a Session built in a script, so the vocabulary
    exists in both. Neither is obviously the owner, so rather than move it, this
    pins that they agree: a word added to one and not the other is a filter that
    silently does nothing in half the harness.
    """
    from bbh import http

    assert set(cli.OMITTED_LITERALS) == set(http._OMITTED_WORDS)


# ---------------------------------------------------------------------------
# raw/ is private however the tree was built
# ---------------------------------------------------------------------------


def test_the_engagement_tree_restricts_raw_to_this_user(tmp_path):
    """A library caller that builds the tree directly must not leave raw/ open."""
    root = paths.ensure_engagement_tree("fresh")
    for private in ("raw", "sensitive"):
        assert (root / private).stat().st_mode & 0o077 == 0, private


# ---------------------------------------------------------------------------
# information-isolated verification reaches the phase the CLI actually runs
# ---------------------------------------------------------------------------


def _validated_claim(store):
    """One finding sitting where 06-verify picks it up, with a conclusion attached."""
    import conftest

    conftest.seed_access_control_finding(store)
    store.update_finding(
        "F-001",
        severity="critical",
        summary="SEAMLEAK-summary: any user reads any document",
        impact="SEAMLEAK-impact: every customer record is readable",
        confidence="high",
        counterevidence=conftest.VALIDATED_FIELDS["counterevidence"],
        severity_change_conditions=conftest.VALIDATED_FIELDS["severity_change_conditions"],
    )
    store.advance("F-001", "validated")


def test_bb_phase_dry_run_renders_the_isolated_verify_prompt(engagement, capsys):
    """`bb phase --dry-run` builds its own prompt, so the dispatch has to be in
    build_prompt and not in the hunt loop: this is the path that would have
    handed the verifier triage's conclusion."""
    with Store(paths.db_path(engagement)) as store:
        _validated_claim(store)

    assert run("phase", "06-verify", engagement, "--dry-run") == 0
    out = capsys.readouterr().out
    assert "The claims to re-prove" in out
    assert "SEAMLEAK-summary" not in out, "the previous pass's write-up reached the verifier"
    assert "SEAMLEAK-impact" not in out
    assert "critical" not in out
    assert "FINDINGS SO FAR" not in out


def test_bb_phase_dry_run_pins_nothing(engagement, capsys):
    """A dry run reads. The pin is a write, and `--dry-run` promises none."""
    with Store(paths.db_path(engagement)) as store:
        _validated_claim(store)
    assert run("phase", "06-verify", engagement, "--dry-run") == 0
    capsys.readouterr()
    with Store(paths.db_path(engagement)) as store:
        assert store.get_finding("F-001")["frozen_sha256"] is None


def test_the_freeze_entry_point_has_the_signature_the_cli_must_wire(engagement, capsys):
    """`bb finding freeze <ref>` is not wired yet; this pins what it has to call.

    Kept as a check on the library side rather than a failing test for someone
    else's file: when the subcommand lands, the assertions below say whether it
    reached the right function.
    """
    import inspect

    from bbh import runner

    signature = inspect.signature(runner.freeze_finding)
    assert list(signature.parameters) == ["store", "ref"]

    with Store(paths.db_path(engagement)) as store:
        _validated_claim(store)
        digest = runner.freeze_finding(store, "F-001")
        assert store.get_finding("F-001")["frozen_sha256"] == digest
    assert re.fullmatch(r"[0-9a-f]{64}", digest)

    freeze = _resolve(["finding", "freeze"])
    if freeze is None:
        pytest.skip(
            "bb finding freeze is not wired; it must call "
            "runner.freeze_finding(store, ref) and print the digest"
        )
    assert "ref" in {action.dest for action in argparse_actions(freeze)}


def test_the_pinned_claim_check_is_recomputable_by_a_gate(engagement):
    """Whatever gates `verified` has to be able to recompute this from the store.

    `triage.VERIFY_GATES` does not include a frozen-claim gate yet, so this pins
    the primitive it needs: problems recomputed from the row, the recorded digest
    and the hashed file, each naming the field that moved and the command that
    re-pins it.
    """
    from bbh import runner

    with Store(paths.db_path(engagement)) as store:
        _validated_claim(store)
        runner.freeze_finding(store, "F-001")
        assert runner.frozen_claim_problems(store, "F-001") == []

        store.update_finding("F-001", repro="1. a different claim entirely")
        problems = runner.frozen_claim_problems(store, "F-001")

    assert problems and all(isinstance(p, str) for p in problems)
    assert any("repro" in p for p in problems)
    assert any("bb finding freeze F-001" in p for p in problems)


def test_the_pinned_claim_is_not_stored_where_the_phase_can_rewrite_it(engagement):
    """The engagement root is --add-dir'd into the phase; the pin must not be."""
    from bbh import runner

    path = runner.frozen_path(engagement, "F-001")
    assert paths.engagement_dir(engagement) not in path.parents
    assert paths.STATE_DIR in path.parents


# ---------------------------------------------------------------------------
# no `choices=` list is a second copy of a vocabulary another module owns
# ---------------------------------------------------------------------------
#
# This is the shape of the defect that made every v2 angle word unreachable:
# the store understood `ruled_out` and argparse rejected it first. A second
# copy of a vocabulary fails closed in the wrong place -- the refusal comes
# from argparse, which cannot say why the word matters.


def _choices_for(words, flag):
    parser = _resolve(list(words))
    assert parser is not None, words
    for action in argparse_actions(parser):
        if flag in action.option_strings:
            return action.choices
    raise AssertionError(f"{words} has no {flag}")


@pytest.mark.parametrize(
    "words,flag,owner",
    [
        (("finding", "set"), "--confidence", "CONFIDENCE_LEVELS"),
        (("finding", "set"), "--delivery", "DELIVERY_MODES"),
        (("finding", "advance"), "state", "STATES"),
        (("evidence", "add"), "--role", "EVIDENCE_ROLES"),
        (("prereq", "add"), "--verdict", "PREREQUISITE_VERDICTS"),
        (("angle", "add"), "--source", "ANGLE_SOURCES"),
    ],
)
def test_a_constrained_flag_takes_its_vocabulary_from_the_store(words, flag, owner):
    from bbh import store as store_module

    expected = set(getattr(store_module, owner))
    if flag.startswith("--"):
        found = set(_choices_for(words, flag))
    else:  # a positional
        parser = _resolve(list(words))
        found = {
            c
            for action in argparse_actions(parser)
            if action.dest == flag
            for c in (action.choices or ())
        }
    # The sentinel literals are added on purpose, so a `--role none` is
    # normalised rather than killed by argparse with a usage dump.
    assert expected <= found, f"{flag} rejects a word the store accepts"
    assert found - expected <= set(cli.OMITTED_CHOICES), (
        f"{flag} accepts a word the store does not"
    )


def test_the_gate_target_list_is_sliced_off_the_stores_ladder():
    """Written out by hand, it would keep the CLI from reaching a new rung."""
    from bbh.store import LADDER

    assert cli.GATE_TARGETS == LADDER[1:]
    assert set(_choices_for(("gate",), "--target")) == set(LADDER[1:])
    assert not parses("gate", "F-1", "--target", "candidate")


def test_every_gate_target_is_a_rung_triage_guards():
    from bbh import triage

    for target in cli.GATE_TARGETS:
        assert triage.gates_for_state(target), target


def test_a_lazily_checked_vocabulary_refuses_a_word_outside_it():
    """`choices=` would need the owning module imported to build the parser."""
    assert parses("finding", "dedupe", "F-1", "--verdict", "undetermined")
    assert not parses("finding", "dedupe", "F-1", "--verdict", "maybe")
    assert not parses("proc", "register", "1", "--kind", "bogus")
    assert not parses("cleanup", "--kind", "bogus")


def test_the_verdict_help_text_names_exactly_the_vocabulary_triage_owns():
    """The words are prose here because the list is not imported to build the
    parser, so a test is what stops the prose drifting from the list."""
    from bbh import triage

    parser = _resolve(["finding", "dedupe"])
    help_text = next(
        a.help for a in argparse_actions(parser) if "--verdict" in a.option_strings
    )
    named = {word.strip(" .") for word in help_text.replace(" or ", ", ").split(",")}
    assert named == set(triage.DEDUPE_VERDICTS)


# ---------------------------------------------------------------------------
# every command a builder handed over exists, with the flags it published
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ("coverage",),
        ("coverage", "--class", "idor"),
        ("coverage", "--require-clean"),
        ("coverage", "--refresh"),
        ("coverage", "reason", "race", "the rate limiter serialises every request"),
        ("coverage", "reason", "race", "x", "--phase", "02-sweep"),
        ("handoff", "write", "02-sweep"),
        ("finding", "freeze", "F-1"),
        ("finding", "freeze", "F-1", "--check"),
        ("finding", "merge", "F-2", "--into", "F-1", "--reason", "one root cause"),
        ("finding", "dedupe", "F-1"),
        ("finding", "dedupe", "F-1", "--against", "F-2", "--verdict", "distinct",
         "--because", "two bugs"),
        ("finding", "dedupe", "F-1", "--not-duplicate-because", "two bugs"),
        ("finding", "dedupe", "F-1", "--write-key"),
        ("finding", "advance", "F-1", "blocked", "--reason", "x",
         "--unblock-condition", "y"),
        ("gate", "F-1"),
        ("gate", "--all"),
        ("gate", "waive", "F-1", "gate_evidence_roles", "--reason", "x", "--as", "me"),
        ("gate", "waive", "--revoke", "F-1", "gate_evidence_roles", "--as", "me"),
        ("gate", "waive", "F-1", "gate_evidence_roles", "--reason", "x", "--as", "me",
         "--hours", "4"),
        ("gate", "waivers"),
        ("gate", "waive-request", "F-1", "gate_evidence_roles", "--reason", "x"),
        ("proc", "register", "42", "--kind", "proxy", "--port", "8080", "--note", "n"),
        ("proc", "list", "--kind", "proxy"),
        ("proc", "forget", "42", "--reason", "stopped by hand"),
        ("cleanup",),
        ("cleanup", "--kind", "proxy", "--pid", "42", "--dry-run", "--grace", "2"),
        ("req", "show", "12"),
    ],
)
def test_every_published_command_parses(argv):
    assert parses(*argv), " ".join(argv)


def test_req_show_parses_the_flags_the_body_reader_published():
    show = cli._req_show_parser()
    known = _options(show)
    for flag in ("--side", "--grep", "--ignore-case", "--max-matches", "--window",
                 "--preview-bytes", "--budget", "--json"):
        assert flag in known, flag


def test_the_bounding_envelope_sees_json_asked_for_behind_a_remainder():
    """`bb req show <id> --json` hides the flag from the namespace.

    Without this, an oversized document is sliced as text and the caller gets
    something that does not parse.
    """
    args = cli.build_parser().parse_args(["req", "show", "12", "--json"])
    assert cli.json_mode(args) is True
    body = cli.build_parser().parse_args(["req", "GET", "https://x/", "-d", "--json"])
    assert cli.json_mode(body) is False, "a body is not a flag"


# ---------------------------------------------------------------------------
# the gate chain reaches the gates the v2 modules built
# ---------------------------------------------------------------------------


def test_the_frozen_claim_gate_is_in_the_set_that_guards_shipping():
    """It exists, it is recomputable, and now something runs it."""
    from bbh import triage

    assert "gate_frozen_claim_intact" in triage.GATES
    assert "gate_frozen_claim_intact" in triage.gates_for_state("verified")
    assert "gate_frozen_claim_intact" in triage.gates_for_state("gated")


def test_the_frozen_claim_gate_parks_rather_than_rejects(engagement):
    """An unpinned claim is a measurement nobody took; `rejected` is permanent."""
    from bbh import triage

    with Store(paths.db_path(engagement)) as store:
        _validated_claim(store)
        result = triage.gate_frozen_claim_intact(store, store.get_finding("F-001"))
    assert not result.passed
    assert result.blocked
    assert "bb finding freeze F-001" in result.unblock


def test_the_waiver_policy_covers_the_gate_registry_exactly():
    """A gate added without a recorded decision is unwaivable and noisy about it."""
    from bbh import triage, waiver

    assert waiver.coverage_problem(triage.GATES) is None


def test_the_literal_gate_row_waiver_is_gone_from_triage():
    """It was writable by the agent being refused, through the sanctioned store."""
    from bbh import triage

    assert not hasattr(triage, "WAIVER_PREFIX")
    assert not hasattr(triage, "_recorded_waiver")
    assert triage.DEDUPE_MIN_REASON_CHARS == 20


# ---------------------------------------------------------------------------
# coverage gaps reach the next phase's prompt, fenced
# ---------------------------------------------------------------------------


def test_the_gaps_reach_the_next_phase_and_arrive_as_data(engagement):
    """Hosts and path shapes are target-derived, so they are fenced like the rest."""
    from bbh import runner
    from bbh.untrusted import fence

    with Store(paths.db_path(engagement)) as store:
        store.add_request(source="client", actor="anon", method="GET",
                          url="https://www.acme.example/api/CANARY-ROUTE/7",
                          host="www.acme.example", path="/api/CANARY-ROUTE/7", status=200)
        cfg = runner.HuntConfig(engagement=engagement)
        prompt = runner.build_prompt(cfg, runner.phase_by_key("02-sweep"), store)

    assert "CANARY-ROUTE" in prompt
    nonce = re.search(r"<untrusted:([0-9a-f]{6})", prompt).group(1)
    opener = fence("x", source="s", nonce=nonce).split(">", 1)[0]
    assert opener  # the fence shape exists
    outside = re.sub(
        rf"<untrusted:{nonce}[^>]*>.*?</untrusted:{nonce}>", "", prompt, flags=re.S
    )
    assert "CANARY-ROUTE" not in outside, "a target-named route reached the prompt unfenced"


def test_the_verifier_is_not_handed_coverage_lines(engagement):
    """Coverage names prior-phase ground; the verify brief is a whitelist."""
    from bbh import runner

    assert "coverage_gaps" in runner.PROMPT_TOKENS
    assert "coverage_gaps" not in runner.VERIFY_PROMPT_TOKENS


# ---------------------------------------------------------------------------
# the engagement name, positionally, wherever a module prints it that way
# ---------------------------------------------------------------------------
#
# `bb sandbox up <engagement>` parsed and `bb proxy start <engagement>` did not,
# while bbh/sandbox.py printed the second form four times as the next command to
# run. A remedy the parser answers with `unrecognized arguments: acme` costs an
# unattended agent a turn and teaches it the harness is unreliable, which is the
# same defect class as a remedy naming a flag that does not exist -- so it is
# pinned the same way, structurally, rather than by listing today's commands.


@pytest.mark.parametrize(
    "argv",
    [
        ("proxy", "start", "acme"),
        ("proxy", "start", "acme", "--listen-host", "10.0.0.1", "--port", "8080"),
        ("proxy", "stop", "acme"),
        ("proxy", "status", "acme"),
        ("finding", "list", "acme"),
    ],
)
def test_the_engagement_name_parses_positionally(argv):
    assert parses(*argv), "bb " + " ".join(argv)


def test_the_positional_engagement_selects_it_over_the_active_one(engagement, capsys):
    """Accepting the word is not enough; it has to be the engagement acted on."""
    from bbh import engagement as engagement_mod

    engagement_mod.create("other", program_url="https://h1.example/other")
    paths.set_active("other")
    capsys.readouterr()

    assert run("proxy", "status", "acme") == 0
    assert "acme" in capsys.readouterr().out

    with Store(paths.db_path("acme")) as store:
        store.add_finding("F-001", "Only in acme", "idor", host="www.acme.example")
    capsys.readouterr()
    assert run("finding", "list", "acme") == 0
    assert "Only in acme" in capsys.readouterr().out


def _positional_capacity(parser) -> float:
    """How many bare words this parser will take before argparse refuses."""
    total = 0.0
    for action in argparse_actions(parser):
        if action.option_strings:
            continue
        if isinstance(action, argparse._SubParsersAction):
            return float("inf")  # the subcommand word plus whatever it takes
        nargs = action.nargs
        if nargs in ("*", "+", argparse.REMAINDER, "...") or isinstance(nargs, str) and nargs == "A...":
            return float("inf")
        total += 1 if nargs in (None, "?") else float(nargs)
    return total


def _bare_words(rest: str) -> list[str]:
    """The positional words of a command line, as a module's own source spells it.

    Cut at the first `\\n` escape or closing backtick, because what follows is
    a new line of the refusal rather than an argument. Stops at the first flag,
    comment or shell operator. A word opened with a quote is one positional however many spaces
    it holds ('<what the attack needs>'), and the scan ends there rather than
    guessing where the quote closes.
    """
    for stop in ("\\n", "\\t", "`"):
        rest = rest.split(stop, 1)[0]
    words: list[str] = []
    for token in rest.split():
        if token[:1] in "-#" or token in ("&&", "||", ";", "|", ">", "2>", "then"):
            break
        if token[:1] in "\"'" and token[-1:] != token[:1]:
            words.append(token)  # a quoted argument with spaces in it
            break
        word = token.strip("\"'")
        if not word or '"' in word or "'" in word:
            break
        words.append(word)
    return words


def test_no_module_prints_a_command_with_more_positionals_than_it_takes():
    """`bb proxy start {engagement}` is a dead end if `proxy start` takes none.

    Only a chunk whose first positional came from an f-string is checked, which
    is how the harness writes a command it means literally. Prose about a
    command ("bb doctor ends by running ...") never reaches that shape, so this
    stays a check on instructions rather than a style rule about sentences.
    """
    import re as _re

    problems = set()
    for path in sorted((paths.REPO / "bbh").glob("*.py")):
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "bb " not in raw:
                continue
            text = _re.sub(r"\{[^{}]*\}", "X", raw)
            for chunk in _re.split(r"(?=\bbb )", text):
                match = _re.match(r"bb ([a-z][a-z0-9-]*)(?: ([a-z][a-z0-9-]*))?", chunk.strip())
                if not match:
                    continue
                words = [match.group(1)]
                parser = _resolve(words)
                if parser is None:
                    continue
                if match.group(2) and match.group(2) in _subparsers(parser):
                    words.append(match.group(2))
                    parser = _resolve(words)
                bare = _bare_words(chunk.strip()[match.end():])
                if not bare or bare[0] != "X":
                    continue  # prose, or a literal example rather than a command
                if len(bare) > _positional_capacity(parser):
                    problems.add(
                        (f"{path.name}:{number}", "bb " + " ".join(words), len(bare))
                    )
    assert not problems, "modules print commands the parser rejects: " + "\n".join(
        f"{where}: {command} takes {n} positional(s) that do not parse"
        for where, command, n in sorted(problems)
    )


# ---------------------------------------------------------------------------
# what the phase subprocess is actually launched with
# ---------------------------------------------------------------------------
#
# Half of v2's hardening is where a file lives: the scope lock, the token
# bucket, the circuit breaker, the spend ledger and the guard-hook settings all
# moved out of the engagement directory because `run_phase` hands that
# directory to the agent with `--add-dir`. Each module was checked on its own.
# What was not checked is the argv the CLI finally builds, which is the only
# place the two facts meet.


@pytest.fixture
def spawned(monkeypatch, tmp_path):
    """Run a phase through `bb phase` without spawning anything. Returns the argv."""
    from bbh import runner

    calls: list[list[str]] = []
    binary = tmp_path / "claude"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    monkeypatch.setattr(runner, "claude_binary", lambda: str(binary))

    def fake(cmd, *, cwd, env, raw_path, stderr_path, timeout_s, events, phase_key, attempt):
        calls.append(list(cmd))
        phase = runner.phase_by_key(phase_key)
        handoff = paths.engagement_dir(env["BBH_ENGAGEMENT"]) / "handoff" / f"{phase_key}.json"
        handoff.parent.mkdir(parents=True, exist_ok=True)
        handoff.write_text(json.dumps({k: [f"{k}-1"] for k in phase.produces}))
        return (
            runner._StreamOutcome(cost_usd=0.5, turns=2, session_id="s", saw_result=True),
            0,
            False,
        )

    monkeypatch.setattr(runner, "_spawn_and_stream", fake)
    return calls


def test_the_guard_settings_file_is_not_inside_the_directory_the_agent_is_handed(
    engagement, spawned, capsys
):
    """--add-dir and --settings, read off the same argv rather than separately."""
    assert run("phase", "00-recon", "acme", "--unsandboxed") == 0
    capsys.readouterr()
    cmd = spawned[0]

    added = Path(cmd[cmd.index("--add-dir") + 1]).resolve()
    settings = Path(cmd[cmd.index("--settings") + 1]).resolve()
    assert added == paths.engagement_dir(engagement).resolve()
    assert added not in settings.parents, (
        f"the file that arms the PreToolUse guard is at {settings}, inside the directory "
        f"the phase was handed with --add-dir, so the phase can disarm its own guard"
    )
    assert settings == paths.settings_path(engagement).resolve()
    assert json.loads(settings.read_text())["hooks"]["PreToolUse"][0]["matcher"] == "Bash"


def test_no_runtime_control_is_inside_the_directory_the_agent_is_handed(
    engagement, spawned, capsys
):
    """Every file the harness re-derives per phase, against the real argv."""
    assert run("phase", "00-recon", "acme", "--unsandboxed") == 0
    capsys.readouterr()
    cmd = spawned[0]
    added = Path(cmd[cmd.index("--add-dir") + 1]).resolve()
    for label, path in (
        ("settings", paths.settings_path(engagement)),
        ("rate bucket", paths.rate_path(engagement)),
        ("circuit breaker", paths.breaker_path(engagement)),
        ("spend ledger", paths.ledger_path(engagement)),
        ("scope lock", paths.lock_path(engagement)),
        ("armkey", paths.ARMKEY),
    ):
        assert added not in Path(path).resolve().parents, label


# ---------------------------------------------------------------------------
# a phase that ran out of authorization under itself
# ---------------------------------------------------------------------------
#
# `--resume` skips a phase recorded `ok` and nothing else, so what a dead hour
# is recorded as decides whether the hunt ever comes back to it. An attestation
# that lapsed mid-phase means every request after that point was denied: the
# handoff can still be complete and the ground is still untested.


def _expire_mid_phase(monkeypatch, engagement: str):
    """Let the attestation lapse while the subprocess is 'running'."""
    from bbh import engagement as engagement_mod
    from bbh import runner

    real = runner._spawn_and_stream

    def fake(cmd, *, cwd, env, raw_path, stderr_path, timeout_s, events, phase_key, attempt):
        phase = runner.phase_by_key(phase_key)
        handoff = paths.engagement_dir(env["BBH_ENGAGEMENT"]) / "handoff" / f"{phase_key}.json"
        handoff.parent.mkdir(parents=True, exist_ok=True)
        handoff.write_text(json.dumps({k: [f"{k}-1"] for k in phase.produces}))
        # The agent worked, wrote a complete handoff, and the clock ran out.
        engagement_mod.disarm(env["BBH_ENGAGEMENT"])
        return (
            runner._StreamOutcome(cost_usd=0.5, turns=2, session_id="s", saw_result=True),
            0,
            False,
        )

    assert real is not fake
    monkeypatch.setattr(runner, "_spawn_and_stream", fake)


def test_a_phase_whose_attestation_lapsed_is_not_recorded_ok(
    engagement, monkeypatch, tmp_path, capsys
):
    from bbh import runner

    binary = tmp_path / "claude"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    monkeypatch.setattr(runner, "claude_binary", lambda: str(binary))
    _expire_mid_phase(monkeypatch, engagement)

    assert run("phase", "00-recon", "acme", "--unsandboxed") == 1
    out = capsys.readouterr().out
    assert "expired" in out

    with Store(paths.db_path(engagement)) as store:
        assert store.phase_status("00-recon") == "expired"
        # `--resume` skips `ok` and only `ok`, so this is the property that
        # keeps the dead hour from being believed.
        assert store.phase_status("00-recon") != "ok"


def test_resume_re_runs_a_phase_that_expired_rather_than_skipping_it(
    engagement, monkeypatch, tmp_path, capsys
):
    from bbh import runner

    binary = tmp_path / "claude"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    monkeypatch.setattr(runner, "claude_binary", lambda: str(binary))
    _expire_mid_phase(monkeypatch, engagement)
    assert run("phase", "00-recon", "acme", "--unsandboxed") == 1
    capsys.readouterr()

    run("arm", "acme", "--as", "tester", "--hours", "2")
    capsys.readouterr()
    launched: list[str] = []

    def fake(cmd, *, cwd, env, raw_path, stderr_path, timeout_s, events, phase_key, attempt):
        launched.append(phase_key)
        phase = runner.phase_by_key(phase_key)
        handoff = paths.engagement_dir(env["BBH_ENGAGEMENT"]) / "handoff" / f"{phase_key}.json"
        handoff.write_text(json.dumps({k: [f"{k}-1"] for k in phase.produces}))
        return (
            runner._StreamOutcome(cost_usd=0.1, turns=1, session_id="s", saw_result=True),
            0,
            False,
        )

    monkeypatch.setattr(runner, "_spawn_and_stream", fake)
    run("hunt", "acme", "--phases", "00-recon", "--resume", "--unsandboxed")
    assert launched == ["00-recon"], "--resume skipped a phase that never had authorization"


# ---------------------------------------------------------------------------
# a hunt that stopped short says so in its exit code
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stopped", ["budget", "deadline", "expired", "disk", "complete"])
def test_bb_hunt_exits_non_zero_for_every_status_that_is_not_a_finished_plan(
    engagement, monkeypatch, capsys, stopped
):
    """`run_phase` gained `expired` and `disk`; the CLI listed three names.

    An unattended hunt is started by a cron line or a wrapper, and the exit
    code is the only thing either of them reads. A night that stopped on the
    first phase because the attestation had lapsed reported success.
    """
    from bbh import runner

    monkeypatch.setattr(
        runner, "run_hunt", lambda cfg, on_event=None: {"status": stopped, "reason": "r"}
    )
    code = run("hunt", "acme", "--unsandboxed")
    capsys.readouterr()
    assert code == (0 if stopped == "complete" else 1), stopped


def test_an_unrecognised_hunt_status_is_a_failure_not_a_success(engagement, monkeypatch, capsys):
    """Fail closed: a status this CLI has never heard of is not a finished plan."""
    from bbh import runner

    monkeypatch.setattr(
        runner, "run_hunt", lambda cfg, on_event=None: {"status": "something-new"}
    )
    assert run("hunt", "acme", "--unsandboxed") == 1
    assert "stopped short" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# one token bucket, however the traffic leaves
# ---------------------------------------------------------------------------


def test_the_client_and_the_proxy_share_one_rate_bucket(engagement, monkeypatch):
    """Two buckets means two full rates at the target, both reported compliant.

    `bbh.http` moved its bucket to `paths.rate_path` this release, because a
    brake inside the directory `run_phase` `--add-dir`s is a brake the braked
    process can release. The addon still built `<root>/.state/rate.json` by
    hand, so the move quietly split one limit into two.
    """
    from test_proxy_addon import install_mitmproxy_stub, load_addon_like_mitmproxy

    from bbh import http
    from bbh.scope import Scope

    install_mitmproxy_stub(monkeypatch)
    addon = load_addon_like_mitmproxy()
    binding = addon.resolve(engagement)
    assert binding.limiter is not None, binding.deny_reason

    scope = Scope.from_lock_file(paths.lock_path(engagement))
    client_bucket = http.Session(engagement=engagement)._rate_limiter(scope)
    assert binding.limiter.path == paths.rate_path(engagement)
    assert client_bucket.path == binding.limiter.path
    root = paths.engagement_dir(engagement).resolve()
    assert root not in binding.limiter.path.resolve().parents


# ---------------------------------------------------------------------------
# the gate ladder is not optional
# ---------------------------------------------------------------------------
#
# `store.advance` is forward-only but permits any forward jump, and the state
# it writes is just a column. One command took a candidate with no evidence,
# no severity and no gate row at all to `gated`, and `bb report` wrote the
# document a human acts on from it -- so every gate the v2 pass added was one
# word away from being skipped entirely.


def test_a_finding_advanced_by_hand_cannot_be_reported(engagement, capsys):
    from conftest import seed_access_control_finding

    with Store(paths.db_path(engagement)) as store:
        seed_access_control_finding(store)
    capsys.readouterr()

    assert run("finding", "advance", "F-001", "gated") == 0, "the store still allows it"
    capsys.readouterr()
    assert run("report", "F-001") == 1
    message = capsys.readouterr().err
    assert "never recorded a verdict" in message
    assert "bb gate F-001" in message
    reports = paths.engagement_dir(engagement) / "reports"
    assert not list(reports.glob("*.md")), "a refusal must leave no file behind"


def test_a_gate_set_that_really_ran_still_reports(engagement, capsys):
    from conftest import VALIDATED_FIELDS, record_gate_passes, seed_access_control_finding

    with Store(paths.db_path(engagement)) as store:
        seed_access_control_finding(store)
        store.update_finding("F-001", summary="s", impact="i", remediation="r",
                             **VALIDATED_FIELDS)
        for rung in ("validated", "verified", "gated"):
            store.advance("F-001", rung)
        record_gate_passes(store, "F-001")
    capsys.readouterr()
    assert run("report", "F-001") == 0


def test_one_missing_gate_is_enough_to_refuse(engagement, capsys):
    """Fail closed per gate, not "some gates ran, close enough"."""
    from bbh import triage
    from conftest import VALIDATED_FIELDS, record_gate_passes, seed_access_control_finding

    dropped = triage.gates_for_state("gated")[-1]
    with Store(paths.db_path(engagement)) as store:
        seed_access_control_finding(store)
        store.update_finding("F-001", summary="s", impact="i", remediation="r",
                             **VALIDATED_FIELDS)
        for rung in ("validated", "verified", "gated"):
            store.advance("F-001", rung)
        record_gate_passes(store, "F-001")
        # The newest row for one gate says it failed after it had passed.
        store.record_gate(store.get_finding("F-001")["id"], dropped, "fail", "it stopped holding")
    capsys.readouterr()
    assert run("report", "F-001") == 1
    assert dropped in capsys.readouterr().err


# ---------------------------------------------------------------------------
# a re-run is told what the earlier attempt got as far as
# ---------------------------------------------------------------------------


def test_a_second_run_of_a_phase_is_handed_what_the_first_one_recorded(engagement):
    """`prior_attempts` is a PROMPT_TOKEN no template spells, so it has to reach
    the agent through `build_prompt`'s appendix or it reaches nothing."""
    from bbh import runner

    phase = runner.phase_by_key("02-sweep")
    with Store(paths.db_path(engagement)) as store:
        first = runner.build_prompt(runner.HuntConfig(engagement=engagement), phase, store)
        assert "WHAT AN EARLIER RUN" not in first, "nothing has run yet"

        run_id = store.start_phase(phase.key)
        store.finish_phase(run_id, "timeout", cost_usd=1.25, turns=7)
        store.add_request(source="client", actor="anon", method="GET",
                          url="https://www.acme.example/a", host="www.acme.example",
                          path="/a", status=200, phase=phase.key)
        second = runner.build_prompt(runner.HuntConfig(engagement=engagement), phase, store)

    assert "WHAT AN EARLIER RUN OF THIS PHASE ALREADY DID" in second
    assert "timeout" in second
    assert "$1.25" in second


def test_the_prompt_teaches_the_counterevidence_the_ladder_now_demands(engagement):
    """05-validate's own bar: `advance validated` refuses without these three."""
    text = (paths.PROMPTS / "05-validate.md").read_text(encoding="utf-8")
    for flag in ("--counterevidence", "--severity-change-conditions", "--confidence"):
        assert flag in text, flag


def test_the_gate_prompt_teaches_the_order_a_waiver_actually_works_in(engagement):
    """A waivable failure parks now, so the finding is still there to be waived."""
    from bbh import waiver

    text = (paths.PROMPTS / "07-gate.md").read_text(encoding="utf-8")
    assert "bb gate waive-request <uid> <gate>" in text
    assert "bb gate waive <uid> <gate>" in text
    for gate in waiver.WAIVABLE:
        assert gate in text, gate
    assert "refused while a phase is running" in text


# ---------------------------------------------------------------------------
# program_constraints: wired into the compiler, the lock and one enforcer
# ---------------------------------------------------------------------------


def _write_scope_with_constraints(name: str = "acme") -> None:
    text = paths.scope_path(name).read_text(encoding="utf-8")
    paths.scope_path(name).write_text(
        text + "\nprogram_constraints:\n  max_rps: 0.5\n  allowed_methods: [GET, HEAD]\n",
        encoding="utf-8",
    )


def test_the_generated_template_offers_program_constraints_and_still_compiles(capsys):
    """Commented out in the starter, because the starter has to compile as written."""
    from bbh import engagement as engagement_mod

    engagement_mod.create("fresh", program_url="https://h1.example/fresh",
                          targets=["*.fresh.example"])
    capsys.readouterr()
    text = paths.scope_path("fresh").read_text(encoding="utf-8")
    assert "# program_constraints:" in text
    assert "#   max_rps: 0.5" in text
    assert run("scope", "compile", "fresh") == 0


def test_program_constraints_reach_the_lock_and_clamp_the_client(engagement, capsys):
    """Dead branch before v2: the compiler dropped the key, so nothing clamped."""
    from bbh import http
    from bbh.scope import Scope

    _write_scope_with_constraints()
    capsys.readouterr()
    assert run("scope", "compile", "acme") == 0

    lock = json.loads(paths.lock_path("acme").read_text())
    assert lock["program_constraints"] == {"max_rps": 0.5, "allowed_methods": ["GET", "HEAD"]}
    rules = http.effective_rules(Scope(lock))
    assert rules["max_rps"] == 0.5
    assert rules["allowed_methods"] == ["GET", "HEAD"], "DELETE survived a program's clamp"


def test_compiling_a_clamped_scope_says_which_layers_ignore_it(engagement, capsys):
    """Honest where the belief forms: the proxy and the guard read rules.* raw."""
    _write_scope_with_constraints()
    capsys.readouterr()
    assert run("scope", "compile", "acme") == 0
    printed = capsys.readouterr().out
    assert "program_constraints are applied by the sanctioned client" in printed
    assert "bb proxy" in printed


def test_an_unclamped_scope_says_nothing_about_clamps(engagement, capsys):
    capsys.readouterr()
    assert run("scope", "compile", "acme") == 0
    assert "program_constraints are applied" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# the README's own command lines parse
# ---------------------------------------------------------------------------


def _readme_commands() -> list[str]:
    """Every `bb ...` line inside a fenced code block in README.md."""
    lines = (paths.REPO / "README.md").read_text(encoding="utf-8").splitlines()
    fenced, found = False, []
    for raw in lines:
        if raw.startswith("```"):
            fenced = not fenced
            continue
        if fenced and raw.strip().startswith("bb "):
            found.append(raw.strip())
    return found


def test_the_readme_only_shows_commands_the_parser_accepts():
    """README:59 told the operator `bb proxy start acme`, which did not parse."""
    import shlex

    assert _readme_commands(), "no fenced bb commands found; the harvest broke"
    problems = []
    for line in _readme_commands():
        text = line.split("#", 1)[0].split("&&")[0].strip()
        text = re.sub(r"<[^>]*>", "PLACEHOLDER", text)
        argv = shlex.split(text)[1:]
        if not parses(*argv):
            problems.append(line)
    assert not problems, "README shows commands bb rejects:\n" + "\n".join(problems)
