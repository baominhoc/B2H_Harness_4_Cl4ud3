"""Shared fixtures.

Every test runs against a throwaway BBH_HOME under tmp_path. `bbh.paths`
computes its locations once at import time, so setting the environment variable
alone is not enough: the module-level constants are repointed too, and every
other module reads them through `paths.<NAME>` at call time, so repointing here
redirects the whole package.

paths.REPO and paths.PROMPTS deliberately keep pointing at the real repository.
The prompt templates and bin/bb-guard are code under test, not state.

No test in this suite makes a network request or starts a real `claude`
process. The runner tests monkeypatch the subprocess call; a test that reaches
either is a bug in the test.
"""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from bbh import paths  # noqa: E402
from bbh.scope import Scope, compile_scope, sign_lock  # noqa: E402
from bbh.store import Store  # noqa: E402

ENGAGEMENT = "acme"


# ---------------------------------------------------------------------------
# isolation
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def bbh_home(tmp_path, monkeypatch):
    """Point the whole package at a throwaway root for the duration of a test."""
    home = tmp_path / "bbh-home"
    home.mkdir()

    monkeypatch.setenv("BBH_HOME", str(home))
    monkeypatch.delenv("BBH_ENGAGEMENT", raising=False)

    monkeypatch.setattr(paths, "HOME", home)
    monkeypatch.setattr(paths, "ENGAGEMENTS", home / "engagements")
    monkeypatch.setattr(paths, "STATE_DIR", home / ".state")
    monkeypatch.setattr(paths, "ACTIVE_FILE", home / ".state" / "active")
    monkeypatch.setattr(paths, "AUDIT_LOG", home / ".state" / "audit.jsonl")
    monkeypatch.setattr(paths, "LOCKS_DIR", home / ".state" / "locks")
    monkeypatch.setattr(paths, "ARMKEY", home / ".state" / "armkey")
    return home


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any socket a test opens is a test bug. Fail loudly instead of dialling out."""

    def refuse(*args, **kwargs):
        raise AssertionError(
            "a test tried to open a network connection; the suite must stay offline"
        )

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture(autouse=True)
def no_real_settings(tmp_path, monkeypatch):
    """`bb doctor` reads ~/.claude/settings.json; no test may see the real one.

    Reading it is enough to break the rule: the hook check's verdict would then
    depend on whether the developer running the suite happens to have installed
    the guard, and a green run on one machine would mean nothing on another.
    `bbh.cli` is imported lazily so that a test which never touches the CLI does
    not pay for it.
    """
    try:
        from bbh import cli
    except ImportError:  # pragma: no cover - the CLI is part of the package
        return
    settings = tmp_path / "claude-settings" / "settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(cli, "settings_file", lambda scope: settings)


@pytest.fixture(autouse=True)
def no_claude(monkeypatch):
    """Nothing in this suite may spawn a subprocess that is not explicitly allowed."""
    import subprocess

    real = subprocess.Popen

    class Guarded(real):  # type: ignore[misc,valid-type]
        def __init__(self, args, *a, **kw):
            argv = args if isinstance(args, (list, tuple)) else [args]
            # Match the program being run, not any path that mentions claude:
            # the repository itself lives under ~/claude-harness.
            program = Path(str(argv[0])).name if argv else ""
            if program == "claude" or program.startswith("claude-"):
                raise AssertionError(f"a test tried to spawn the claude CLI: {argv!r}")
            super().__init__(args, *a, **kw)

    monkeypatch.setattr(subprocess, "Popen", Guarded)


# ---------------------------------------------------------------------------
# scope helpers
# ---------------------------------------------------------------------------


def scope_doc(
    *,
    engagement: str = ENGAGEMENT,
    in_scope=("*.acme.example",),
    out_of_scope=(),
    rules=None,
    hours: float = 2.0,
    program_url: str = "https://hackerone.com/acme",
    program_constraints=None,
) -> dict:
    """A scope document with a live attestation, ready for compile_scope()."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc).replace(microsecond=0)
    auth = {}
    if hours is not None:
        auth = {
            "attested_by": "tester",
            "attested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "policy_url": program_url,
            "statement": f"I confirm I am authorized to test the assets in this scope under {program_url}.",
        }
    return {
        "engagement": engagement,
        "platform": "hackerone",
        "program_url": program_url,
        "authorization": auth,
        "rules": dict(rules or {}),
        "in_scope": list(in_scope),
        "out_of_scope": list(out_of_scope),
        # Top level, which is where the contract and the generated template put
        # it; `rules.program_constraints` is the other accepted placement.
        **({"program_constraints": dict(program_constraints)} if program_constraints else {}),
    }


def make_scope(**kw) -> Scope:
    """An in-memory Scope. Not signed: Scope(dict) does not verify by design."""
    return Scope(compile_scope(scope_doc(**kw), source_text="test"))


@pytest.fixture
def scope() -> Scope:
    return make_scope()


# ---------------------------------------------------------------------------
# a real engagement on disk
# ---------------------------------------------------------------------------


def write_engagement(name: str = ENGAGEMENT, **kw) -> Scope:
    """Build an engagement tree with a signed lock, the way `bb arm` leaves it."""
    import yaml

    paths.ensure_engagement_tree(name)
    doc = scope_doc(engagement=name, **kw)
    # Block YAML, not JSON: engagement.arm/disarm splice the top-level
    # `authorization:` key in place, which needs a real block mapping.
    text = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
    paths.scope_path(name).write_text(text, encoding="utf-8")
    lock = sign_lock(compile_scope(doc, source_text=text))
    lock_file = paths.lock_path(name)
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    lock_file.write_text(json.dumps(lock, indent=2), encoding="utf-8")
    paths.set_active(name)
    return Scope(lock)


@pytest.fixture
def engagement() -> str:
    """An armed engagement named `acme`, selected as active."""
    write_engagement()
    return ENGAGEMENT


@pytest.fixture
def store(engagement) -> Store:
    db = Store(paths.db_path(engagement))
    yield db
    db.close()


@pytest.fixture
def armed(engagement) -> Scope:
    return Scope.from_lock_file(paths.lock_path(engagement))


# ---------------------------------------------------------------------------
# finding helpers
# ---------------------------------------------------------------------------

GOOD_REPRO = (
    "1. Sign in as attacker.\n"
    "2. GET https://www.acme.example/api/docs/2 with the attacker session.\n"
    "3. Observe the victim's document in the response body."
)

# v2: `advance(ref, "validated")` refuses a finding nobody argued against, so
# every test that walks a finding up the ladder has to set these first. Splat
# them into `update_finding` when the test is about something else.
VALIDATED_FIELDS = {
    "counterevidence": (
        "Repeated the request with a fresh browser profile and with no session at all: "
        "the first returned the victim document, the second a 401, so neither a shared "
        "cache nor an unauthenticated route explains it."
    ),
    "severity_change_conditions": (
        "critical if document ids turn out to be enumerable; low if reaching one needs "
        "the victim's own session"
    ),
    "confidence": "high",
}


def record_gate_passes(store: Store, ref: str = "F-001", *, state: str = "gated") -> list[str]:
    """Write the `pass` rows `bb gate` would leave, without running the gates.

    v2: `report.render` refuses a finding whose reportable state no gate ever
    produced, because `bb finding advance <uid> gated` is one command and
    without that check the whole ladder was optional -- a candidate with no
    evidence rendered a report. A test about the *renderer* still needs a
    finding that cleared the gates, and most of these fixtures deliberately
    cannot pass the real set (no pinned claim, a single attack request, no
    severity at all), so the rows are written here, explicitly, standing in for
    the gate run their docstrings already claim happened.

    Use this only where the subject is something other than gating. A test
    about the gates themselves should go through `triage.apply_gates`.
    """
    from bbh.triage import gates_for_state

    row = store.get_finding(ref)
    if row is None:
        raise AssertionError(f"no finding {ref!r} to record gates for")
    names = list(gates_for_state(state))
    for gate in names:
        store.record_gate(row["id"], gate, "pass", "recorded by a test fixture, not computed")
    return names


def seed_access_control_finding(
    store: Store,
    *,
    uid: str = "F-001",
    actor: str = "attacker",
    owner: str = "victim",
    identifier: str = "2",
    vuln_class: str = "idor",
    register_actor: bool = True,
    register_object: bool = True,
    cite_request: bool = True,
) -> int:
    """A finding wired up the way a real access-control proof would be."""
    if register_actor:
        store.add_account(actor, "attacker")
    if owner:
        store.add_account(owner, "victim")
    request_id = store.add_request(
        source="client",
        actor=actor,
        method="GET",
        url=f"https://www.acme.example/api/docs/{identifier}",
        host="www.acme.example",
        path=f"/api/docs/{identifier}",
        status=200,
        phase="05-validate",
    )
    if register_object:
        store.add_object("victim doc", "document", identifier, owner or None)
    finding_id = store.add_finding(
        uid,
        "Cross-account document read",
        vuln_class,
        host="www.acme.example",
        endpoint=f"/api/docs/{identifier}",
        severity="high",
        repro=GOOD_REPRO,
    )
    if cite_request:
        store.add_evidence(finding_id, "request", request_id=request_id)
    return finding_id
