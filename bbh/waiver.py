"""Operator waivers: a narrow, signed, expiring stand-down for two gates.

A control that blocks legitimate work does not survive. `gate_evidence_roles`
demands a `baseline` and an `attack`, and a `verification` seen from the owner's
side when the claim changed state. For a reflected payload on a public page or
an information disclosure on an unauthenticated endpoint there is no owner side
and no working control to photograph: the artifact the gate asks for cannot
exist, the finding is real, and today it cannot ship. The next person in a hurry
does not narrow that gate, they delete it, and then nothing is checked. So the
narrow waiver is the cheaper of two bad options -- but only while it stays
narrow, which is what every refusal in this module is for.

What makes this a waiver and not a bypass:

* **An allowlist, not a flag.** `WAIVABLE` has two entries and `UNWAIVABLE`
  records the decision for every other published gate, so a gate added later is
  unwaivable by default and `coverage_problem()` says the list drifted.
* **An operator act, structurally.** A granted waiver is a signed file under
  `.state/waivers/`, outside the engagement directory `runner.run_phase` hands
  the agent with `--add-dir`, HMAC'd with `.state/armkey` -- the same key and
  the same place as the scope lock, because a waiver is an authorization
  statement of exactly that kind. The agent's own entry point is
  `request_waiver()`, which writes a gates row whose verdict is the literal
  `"fail"`. There is no argument an agent can make, in any prompt, that turns
  the second into the first: one needs a key it was never handed, the other does
  not, and asking is recorded as a failure because that is what it is.
* **Not while a phase is running.** A live phase is an agent at the keyboard,
  and a gate's subject may not stand its own gate down. The check is here and
  not only in `bb gate waive` because `grant()` signs with `paths.armkey()`
  itself: an agent that can run `python3 -c 'from bbh import waiver; ...'` --
  and `guard.SANCTIONED` lets it -- would otherwise reach a signing routine by
  walking around the command the refusal was attached to. It reads the store's
  own `phase_runs`, so passing it means first marking the running phase
  finished, which ends the run and is recorded. An unreadable phase table
  refuses rather than assuming nobody is at the keyboard.
* **Accountable or refused.** `grant()` appends to the hash-chained audit log
  *before* it writes the file and raises if that append fails. Elsewhere in the
  harness auditing never breaks its caller, because there the control is the
  denial and the log merely records it. Here the log *is* the control: the only
  thing between a waiver and a bypass is a human reading later that it happened.
* **One finding, one gate, and it expires.** The record is scoped to a uid and a
  gate name, carries a fingerprint of the finding recomputed from the store, and
  dies at `expires_at`, clamped to the engagement's own authorization expiry --
  a waiver cannot outlive the attestation it was granted under. A re-opened
  finding whose class, asset or evidence set moved under the waiver voids it,
  because the operator's "that artifact cannot exist here" was about the finding
  they read, not about the uid.
* **Waived is not passed.** `gate_verdict()` returns the third word, and
  `report_lines()` puts who waived what and why into the report as prose a
  triager cannot miss. The gate never reports a clean pass it did not earn.

## The allowlist, gate by gate

Waivable:

* `gate_evidence_roles` -- the motivating case above. The waiver stands down a
  *comparison* requirement, not the requirement that anything was observed:
  `gate_evidence_exists` and `gate_has_request_proof` still hold, so a waived
  finding still has a hashed artifact and a recorded request behind it.
* `gate_independent_verification` -- a single-shot bug cannot be re-attacked. A
  coupon redeemed once, a race won once, a deletion that deleted the object:
  the second disjoint attack request the gate wants either cannot be sent or can
  only be sent by doing the target more harm than the report is worth, and a
  program would rather you did not. What is missing is a repetition, not the
  underlying artifact, so waiving it degrades `verified` to one honest
  observation rather than to an assertion.

Not waivable, and why nothing an operator types should move them:

* `gate_evidence_exists`, `gate_has_request_proof` -- these two are the
  difference between a finding and a sentence. Waiving either admits a claim
  with no artifact and no traffic, which is precisely the confident nonsense the
  harness exists to stop.
* `gate_in_scope` -- scope is the program's grant, not the operator's to stand
  down per finding. An exception belongs in `scope.yaml`, where it is visible
  and signed, and `bb arm` is where someone attests to it.
* `gate_severity_derived` -- the score is arithmetic over the CVSS vector. There
  is no case where the metrics cannot be filled in and the number is still
  defensible; the fix is always `bb finding set --cvss`.
* `gate_prerequisites_reachable` -- the gate that answers "could an attacker
  ever get here". Waiving it is how a harness-only finding reaches a report, and
  `delivery=harness_only` already exists to say that honestly.
* `gate_access_control_ownership` -- not on the brief's forbidden list, and
  forbidden here anyway. It is the gate that distinguishes a real IDOR from
  changing an id you already own, and waiving it means taking the agent's word
  for who owns the object, which is the single most common false positive in
  bug bounty. It is also the producer of the prerequisite row the gate above
  reads, so waiving it would quietly skip a write.
* `gate_repro_cites_real_requests` -- the fabrication detector. A waiver here is
  by construction "let the write-up name traffic that never left this machine".
  Out-of-band steps are fixed by recording the traffic, not by excusing it.
* `gate_counterevidence_recorded` -- the three fields it reads are the agent's
  own argument against its own claim. No artifact is involved, so there is no
  case where one cannot exist; waiving it is permission to ship a claim nobody
  argued with.
* `gate_repro_present` -- writing the steps is free and is the deliverable.
* `gate_severity_floor` -- `info` never ships, and the floor above that is a
  policy choice for the whole engagement rather than for one finding. (This
  build hardcodes the floor at `low`; `scope.yaml` has no `policy:` key, and
  saying otherwise sent the operator to write one the compiler now refuses.)
* `gate_not_duplicate` -- it reads a model-written `dedup_key` and is therefore
  already the softest gate here; a waiver on it is pure widening. The real fix
  is the harness-computed key and `bb finding merge --into`.

## Honest bound

Tamper-**evident**, not tamper-proof, and the same bound the scope lock carries:
the agent runs as the same uid, so a determined process can read `.state/armkey`
and mint a waiver, and can append a correctly chained audit line for it too.
What this stops is the realistic case -- a confused or injection-steered agent
that writes files in its working tree and argues with its instructions. Because
appending to the chain is available to a forger, `check()` does **not** require
a matching audit line: coupling a live control to a log that may legitimately be
rotated would void real waivers for no gain in strength. `listing()` reports a
waiver file with no grant in the log instead, which is detection where it
informs rather than enforcement where it cannot bite.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import paths, secrets
from .scope import Scope, ScopeError, canonical_bytes
from .store import TERMINAL_STATES, Store, utcnow

# The third verdict word. A waived gate is displayed with this and never with
# "pass": the requirement was stood down, not met.
WAIVED = "waived"

# Gates an operator may stand down, mapped to the clause a refusal quotes back.
# Two entries. Adding a third is a design decision, not a configuration change;
# the module docstring argues each of these and every exclusion.
WAIVABLE: dict[str, str] = {
    "gate_evidence_roles": (
        "a public, unauthenticated or single-party bug has no owner side and no working "
        "control to photograph, so the comparison this gate wants cannot exist"
    ),
    "gate_independent_verification": (
        "a single-shot bug cannot be re-attacked without doing the target further harm, so "
        "the second disjoint attack request this gate wants cannot be sent"
    ),
}

# Every other published gate, with why no operator may stand it down. Kept
# explicit rather than derived: a gate missing from both maps is unwaivable by
# default, and `coverage_problem()` is how a test notices the omission.
UNWAIVABLE: dict[str, str] = {
    "gate_evidence_exists": (
        "it is the difference between a finding and a sentence; waiving it admits a claim "
        "with no artifact on disk"
    ),
    "gate_has_request_proof": (
        "it is the difference between a finding and a sentence; waiving it admits a claim "
        "no recorded traffic supports"
    ),
    "gate_in_scope": (
        "scope is the program's grant and not an operator's to stand down per finding; an "
        "exception belongs in scope.yaml, where it is signed and visible"
    ),
    "gate_severity_derived": (
        "the score is arithmetic over the CVSS vector, so there is nothing a reason could "
        "excuse that `bb finding set --cvss` does not fix"
    ),
    "gate_prerequisites_reachable": (
        "it is the only check that an attacker could ever reach this, and "
        "`--delivery harness_only` already exists to say honestly that they could not"
    ),
    "gate_access_control_ownership": (
        "waiving it means taking the agent's word for who owns the object, which is the "
        "most common false positive in bug bounty, and it would skip the prerequisite row "
        "this gate writes"
    ),
    "gate_repro_cites_real_requests": (
        "it is the fabrication detector, so a waiver on it is by construction permission to "
        "name traffic that never left this machine"
    ),
    "gate_counterevidence_recorded": (
        "the three fields it reads are the agent's own argument against its own claim, so "
        "no artifact has to exist for it and a waiver is permission to ship a claim nobody "
        "argued with"
    ),
    "gate_repro_present": (
        "writing the steps is free and is the deliverable a triager acts on"
    ),
    "gate_severity_floor": (
        "it is one engagement-wide line -- info never ships -- and a per-finding waiver "
        "would bury a policy choice where nobody reads it"
    ),
    "gate_not_duplicate": (
        "it already reads a model-written dedup_key and is the softest gate here, so a "
        "waiver on it widens without unblocking anything real"
    ),
    "gate_frozen_claim_intact": (
        "both ways it can fail have a command rather than an argument -- pin the claim, or "
        "re-run the independent pass against the claim as it now stands -- and waiving it "
        "means shipping a verification that was about different text"
    ),
}

# A waiver is granted during a review and should not outlive it. The ceiling
# matches engagement.MAX_ARM_HOURS, and `grant()` clamps to the engagement's own
# expiry on top, so in practice the arm is usually the shorter leash.
DEFAULT_HOURS = 24
MAX_HOURS = 168

# The reason is read by a triager in a submitted report, so it has to be a
# sentence. Shorter than this is a shrug, and the gate-row waiver this replaced
# (20) was low enough to admit one.
MIN_REASON_CHARS = 40

_ISO = "%Y-%m-%dT%H:%M:%SZ"

# Domain separation: the armkey also signs scope locks, and a MAC that is valid
# for one document type must not be valid for another.
_MAC_DOMAIN = b"bbh-waiver-v1\n"

# A uid becomes a path component, so it is checked rather than trusted:
# `store.add_finding` does not constrain it.
_UID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_STUB_REASON = re.compile(
    r"^(none|n/?a|nothing|not applicable|no reason|see above|as discussed|per the)\b",
    re.IGNORECASE,
)

# Treated as an absent argument rather than as a value, per the contract's
# output-bounding rule: `--reason none` is a missing reason, not a reason.
_OMITTED = frozenset({"", "null", "none", "nil", "undefined"})


class WaiverError(RuntimeError):
    """A waiver could not be granted, removed, or trusted. Never a gate verdict."""


@dataclass(frozen=True)
class Waiver:
    """One signature-verified stand-down of one gate on one finding."""

    engagement: str
    finding_uid: str
    gate: str
    reason: str
    waived_by: str
    granted_at: str
    expires_at: str
    subject: dict[str, Any]
    subject_sha256: str
    waiver_id: str

    def expired(self, now: str | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at

    def line(self) -> str:
        """One line for a terminal listing."""
        return (
            f"{self.finding_uid}  {self.gate}  waived by {self.waived_by} "
            f"until {self.expires_at}: {self.reason}"
        )


@dataclass(frozen=True)
class WaiverStatus:
    """Whether a waiver stands, and every reason it does not.

    `honored` is true exactly when a waiver parsed and `problems` is empty.
    `problems` is the list a gate appends to its own refusal, so each entry
    names what is wrong, why that matters, and the command that fixes it; a
    waiver that is simply absent is not a problem, it is the normal case.

    `notes` is kept separate because the two are not the same kind of statement.
    A problem is enforcement -- it is why the gate still refuses. A note is
    detection, something an operator should look at that this harness will not
    act on, and folding the second into the first would make a honored waiver
    read as a refused one.
    """

    finding_uid: str
    gate: str
    path: Path
    found: bool = False
    waiver: Waiver | None = None
    honored: bool = False
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---- time ------------------------------------------------------------------


def _parse_stamp(text: Any) -> datetime | None:
    try:
        return datetime.strptime(str(text), _ISO).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _format_stamp(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime(_ISO)


# ---- paths and signing -----------------------------------------------------


def waivers_dir(engagement: str) -> Path:
    """Where granted waivers live: beside the scope lock, not in the agent's tree.

    Read off `paths.STATE_DIR` at call time rather than computed at import, so a
    test that repoints the harness root repoints this too.
    """
    return paths.STATE_DIR / "waivers" / engagement


def waiver_path(engagement: str, finding_uid: str, gate: str) -> Path:
    """The one file that can waive `gate` on `finding_uid`.

    Both components are validated, not escaped: a uid is unconstrained by the
    store and a gate name that is not in the allowlist has no file to name.
    """
    uid = str(finding_uid or "").strip()
    if not _UID_RE.match(uid):
        raise WaiverError(
            f"finding uid {finding_uid!r} is not a safe filename and a waiver is stored "
            f"under one, so this cannot be recorded. Use the uid `bb finding list` prints, "
            f"which matches {_UID_RE.pattern}"
        )
    if gate not in WAIVABLE:
        raise WaiverError(_not_waivable(gate))
    return waivers_dir(engagement) / f"{uid}.{gate}.json"


def _mac(body: Mapping[str, Any]) -> str:
    return hmac.new(
        paths.armkey(), _MAC_DOMAIN + canonical_bytes(dict(body)), hashlib.sha256
    ).hexdigest()


def _sign(body: Mapping[str, Any]) -> dict[str, Any]:
    signed = {k: v for k, v in dict(body).items() if k != "sig"}
    signed["sig"] = _mac(signed)
    return signed


def _signature_problem(doc: Mapping[str, Any]) -> str | None:
    sig = doc.get("sig")
    if not sig:
        return "it is unsigned"
    try:
        expected = _mac(doc)
    except OSError as exc:
        return f"the signing key {paths.ARMKEY} cannot be read ({exc})"
    if not hmac.compare_digest(expected, str(sig)):
        return "its signature does not match: it was edited after it was granted"
    return None


# ---- the subject fingerprint -----------------------------------------------


def subject_of(store: Store, finding: Any) -> dict[str, Any]:
    """What the operator was looking at, recomputed from the store.

    An operator waives a requirement for *a finding*, not for a uid. If the
    class, the asset or the evidence set moves afterwards, the argument they
    made was about something else, so the waiver has to be re-read rather than
    inherited -- that is the stale-waiver-on-a-reopened-finding case.

    The content of these columns is not trusted here, only their stability: the
    question is whether the record changed since a human read it, so a reworded
    title or a re-derived severity deliberately does not count, while a changed
    vuln_class, host, endpoint or evidence set does.
    """
    row = _finding_row(store, finding)
    return {
        "uid": str(row["uid"]),
        "vuln_class": str(row["vuln_class"] or "").strip(),
        "host": str(row["host"] or "").strip(),
        "endpoint": str(row["endpoint"] or "").strip(),
        "evidence": sorted(_evidence_marks(store, row["uid"])),
    }


def _evidence_marks(store: Store, uid: str) -> list[str]:
    """One stable mark per evidence row: its role and the artifact behind it."""
    marks = []
    for ev in store.evidence_for(uid):
        role = str(ev["role"] or "context")
        if ev["sha256"]:
            marks.append(f"{role}:sha256:{ev['sha256']}")
        elif ev["request_id"] is not None:
            marks.append(f"{role}:request:{int(ev['request_id'])}")
        else:
            marks.append(f"{role}:row:{int(ev['id'])}")
    return marks


def _subject_digest(subject: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(dict(subject))).hexdigest()


def _subject_changes(was: Mapping[str, Any], now: Mapping[str, Any]) -> list[str]:
    """Human-readable differences, so a stale waiver says what moved."""
    changes = []
    for key in ("vuln_class", "host", "endpoint"):
        before = str(was.get(key) or "") or "(unset)"
        after = str(now.get(key) or "") or "(unset)"
        if before != after:
            changes.append(f"{key} {before!r} -> {after!r}")
    before_ev, after_ev = list(was.get("evidence") or []), list(now.get("evidence") or [])
    if before_ev != after_ev:
        changes.append(
            f"the evidence set changed ({len(before_ev)} row(s) when it was granted, "
            f"{len(after_ev)} now)"
        )
    return changes or ["the record no longer hashes to what was signed"]


# ---- reading the store -----------------------------------------------------


def _finding_row(store: Store, finding: Any) -> sqlite3.Row:
    """Re-read the finding from the store, whatever shape the caller holds.

    Always a fresh read: a waiver's whole job is to be checked against the
    record as it stands now, not against a row a caller has been carrying.
    """
    ref: Any = finding
    if not isinstance(finding, (str, int)):
        ref = _attr(finding, "uid")
        if ref is None:
            ref = _attr(finding, "id")
    row = store.get_finding(ref) if ref is not None else None
    if row is None:
        raise WaiverError(
            f"no finding {ref!r} in this engagement, so there is nothing to waive. List "
            f"them: `bb finding list`"
        )
    return row


def _attr(obj: Any, name: str) -> Any:
    try:
        value = obj[name]
    except (KeyError, IndexError, TypeError):
        value = getattr(obj, name, None)
    return value


# ---- argument checking -----------------------------------------------------


def _omitted(value: Any) -> bool:
    return str(value or "").strip().casefold() in _OMITTED


def _not_waivable(gate: str) -> str:
    """Why this gate has no waiver, in the words the allowlist records."""
    if gate in UNWAIVABLE:
        return (
            f"{gate} is not waivable: {UNWAIVABLE[gate]}. Nothing an operator types moves "
            f"it. Satisfy it or kill the finding: `bb gate <uid>` prints what it wants, and "
            f"`bb finding advance <uid> rejected --reason '<why>'` closes it honestly"
        )
    return (
        f"no waiver policy is recorded for {gate!r}, so it is not waivable. The gates that "
        f"can be waived are {', '.join(sorted(WAIVABLE))}; a gate added since this list was "
        f"written is unwaivable until someone argues it into bbh/waiver.py:WAIVABLE"
    )


def _grant_cmd(uid: str, gate: str) -> str:
    return (
        f"bb gate waive {uid} {gate} --reason '<why the artifact cannot exist, at least "
        f"{MIN_REASON_CHARS} characters>' --as '<your name>'"
    )


def _reason_problem(reason: str) -> str | None:
    body = " ".join(str(reason or "").split())
    if _omitted(body):
        return "no reason was given"
    if _STUB_REASON.match(body):
        return f"the reason begins with a non-answer ({body.split()[0]!r})"
    if len(body) < MIN_REASON_CHARS:
        return (
            f"the reason is {len(body)} characters and the bar is {MIN_REASON_CHARS}, "
            f"because a triager reads it in the report and anything shorter tells them "
            f"nothing"
        )
    return None


def _phase_problem(store: Store) -> str | None:
    """Why no waiver may be granted right now: an agent is at the keyboard.

    Fails closed, unlike the display-side helper in the CLI: a phase table this
    cannot read is not evidence that nobody is running a phase, and the whole
    value of the refusal is that it holds in exactly the window where the agent
    and not the operator is typing.
    """
    try:
        live = sorted(
            {
                str(row["phase"])
                for row in store.phase_runs()
                if str(row["status"] or "") == "running"
            }
        )
    except sqlite3.Error as exc:
        return (
            f"the phase table could not be read ({exc}), so this harness cannot tell whether "
            f"a phase is running, and a waiver granted by the agent being gated is not a "
            f"waiver. Check the engagement with `bb status` and retry"
        )
    if not live:
        return None
    return (
        f"phase {', '.join(live)} is running, and a running phase is an agent at the "
        f"keyboard: a gate's subject may not stand its own gate down. Let it finish or stop "
        f"it (`bb status`), then retry. From inside a phase the command that exists is "
        f"`bb gate waive-request <finding> <gate> --reason '<why>'`, which records the "
        f"argument and grants nothing"
    )


def _hours_problem(hours: Any) -> str | None:
    if _omitted(hours) and not isinstance(hours, (int, float)):
        return f"no expiry was given; omit --hours for the default of {DEFAULT_HOURS}"
    try:
        value = float(hours)
    except (TypeError, ValueError):
        return f"--hours {hours!r} is not a number"
    if value != value or value in (float("inf"), float("-inf")):
        return f"--hours {hours!r} is not a finite number"
    if value <= 0:
        return f"--hours {hours!r} would grant a waiver that is already expired"
    if value > MAX_HOURS:
        return f"--hours {hours!r} is longer than the {MAX_HOURS}h ceiling"
    return None


# ---- granting --------------------------------------------------------------


def grant(
    store: Store,
    engagement: str,
    finding_ref: str | int,
    gate: str,
    *,
    reason: str,
    waived_by: str,
    hours: float = DEFAULT_HOURS,
    now: str | None = None,
) -> Waiver:
    """Record an operator's stand-down of one gate on one finding.

    Refuses, with every problem at once, unless all of this holds: the gate is
    on the allowlist, the finding exists and is not terminal, no phase is
    running, the engagement is armed and its lock verifies, the reason is an
    argument rather than a shrug, the expiry is a positive span inside the
    ceiling, and nothing in the text carries a recorded secret value.

    The audit line is written first and a failure to write it aborts the grant,
    because the human who reads that line is the control this whole mechanism
    leans on; a waiver nobody can discover afterwards is just a bypass.
    """
    stamp = now or utcnow()
    problems: list[str] = []

    if gate not in WAIVABLE:
        # Nothing below can be computed for a gate that has no waiver, and a
        # list of further complaints would read as if fixing them would help.
        raise WaiverError(_not_waivable(gate))

    row = _finding_row(store, finding_ref)
    uid = str(row["uid"])
    if row["state"] in TERMINAL_STATES:
        problems.append(
            f"{uid} is {row['state']}, which is terminal, so no gate will run on it again "
            f"and a waiver would change nothing. Raise the bug as a fresh finding instead: "
            f"`bb finding add`"
        )

    phase_problem = _phase_problem(store)
    if phase_problem:
        problems.append(phase_problem)

    who = " ".join(str(waived_by or "").split())
    if _omitted(who):
        problems.append(
            "no name was given for who is waiving this; a waiver with no author is an "
            "anonymous exception to a control, which is what this mechanism exists to "
            "prevent. Pass `--as '<your name>'`"
        )

    reason_problem = _reason_problem(reason)
    if reason_problem:
        problems.append(
            f"{reason_problem}; the reason is the whole justification a triager gets for a "
            f"requirement nobody checked. Pass `--reason '<why the artifact the gate wants "
            f"cannot exist for this finding>'`"
        )
    body = " ".join(str(reason or "").split())

    hours_problem = _hours_problem(hours)
    if hours_problem:
        problems.append(
            f"{hours_problem}; a waiver that does not expire is a permanent hole in a gate. "
            f"Pass `--hours <1-{MAX_HOURS}>`"
        )

    leak = secrets.leak_problem(
        f"{body}\n{who}", where=f"the waiver of {gate} on {uid}", engagement=engagement
    )
    if leak:
        problems.append(leak)

    expires = _expiry(engagement, stamp, hours, problems)
    if not expires and not problems:
        problems.append(
            f"the expiry could not be computed from --hours {hours!r} and no reason for that "
            f"was recorded, so nothing is written: an unexpiring waiver is a permanent hole "
            f"in a gate. Pass `--hours <1-{MAX_HOURS}>`"
        )

    if problems:
        raise WaiverError(
            f"refusing to waive {gate} on {uid}:\n"
            + "\n".join(f"  - {p}" for p in problems)
            + f"\nThen retry:\n  {_grant_cmd(uid, gate)}"
        )

    subject = subject_of(store, row)
    digest = _subject_digest(subject)
    # Identifies this grant in the audit log and in the gates row the next run
    # records, so the two can be matched without comparing free text.
    waiver_id = hashlib.sha256(
        canonical_bytes(
            {
                "engagement": engagement,
                "uid": uid,
                "gate": gate,
                "granted_at": stamp,
                "waived_by": who,
                "subject_sha256": digest,
            }
        )
    ).hexdigest()[:16]

    record = {
        "engagement": engagement,
        "finding_uid": uid,
        "gate": gate,
        "reason": body,
        "waived_by": who,
        "granted_at": stamp,
        "expires_at": expires,
        "subject": subject,
        "subject_sha256": digest,
        "waiver_id": waiver_id,
    }
    path = waiver_path(engagement, uid, gate)
    _audit_grant(record)
    try:
        _write_signed(path, _sign(record))
    except OSError as exc:
        raise WaiverError(
            f"the waiver of {gate} on {uid} is recorded in {paths.AUDIT_LOG} but could not be "
            f"written to {path} ({exc}), so the gate will still refuse. The log line is "
            f"harmless; fix the path and retry:\n  {_grant_cmd(uid, gate)}"
        ) from exc
    granted = _from_doc(record)
    if granted is None:  # unreachable unless a field above stops being written
        raise WaiverError(
            f"the waiver of {gate} on {uid} was written incomplete, so nothing would honor "
            f"it. Remove it and retry:\n  rm {path}\n  {_grant_cmd(uid, gate)}"
        )
    return granted


def _expiry(engagement: str, stamp: str, hours: Any, problems: list[str]) -> str:
    """When the waiver dies: `hours` from now, clamped to the engagement's expiry.

    A waiver is a statement made under an authorization that itself expires, so
    it cannot outlive it. The clamp is also why `check()` needs no second
    liveness test against the lock.
    """
    scope = _armed_scope(engagement, problems)
    started = _parse_stamp(stamp)
    if started is None:
        problems.append(
            f"the clock returned {stamp!r}, which is not a {_ISO} timestamp, so the expiry "
            f"cannot be computed and an unexpiring waiver will not be written. Check the "
            f"system clock: `date -u`"
        )
        return ""
    try:
        wanted = _format_stamp(started + timedelta(hours=float(hours)))
    except (TypeError, ValueError, OverflowError):
        return ""  # _hours_problem already recorded why
    if scope is None:
        return wanted
    # Lexicographic min is a real min for this fixed-width UTC format.
    return min(wanted, str(scope.authorization.get("expires_at") or wanted))


def _armed_scope(engagement: str, problems: list[str]) -> Scope | None:
    """The engagement's verified lock, or None with the refusal already recorded."""
    lock = paths.lock_path(engagement)
    try:
        scope = Scope.from_lock_file(lock)
    except (ScopeError, OSError, ValueError) as exc:
        problems.append(
            f"the scope lock for {engagement!r} could not be trusted ({exc}), and a waiver "
            f"is an authorization statement, so it is not written against a lock that does "
            f"not verify. Re-arm: `bb arm {engagement} --as '<your name>'`"
        )
        return None
    auth_problem = scope.authorization_error()
    if auth_problem:
        problems.append(
            f"{engagement!r} is not armed right now ({auth_problem}), and a waiver cannot "
            f"outlive the attestation it is granted under. Re-arm first: "
            f"`bb arm {engagement} --as '<your name>'`"
        )
        return None
    return scope


def _write_signed(path: Path, doc: Mapping[str, Any]) -> None:
    """Replace the waiver file in one step, so a crash leaves no half record."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _audit_grant(record: Mapping[str, Any]) -> None:
    """Chain the grant into the audit log, or raise and grant nothing.

    The import is deferred because `bbh.cli` imports the gates that import this
    module. Unlike `guard._audit` and `engagement._audit` there is no unchained
    fallback and no swallowed failure: for those two the control is the decision
    and the log records it, while a waiver's only remaining control is that
    somebody can find out it happened.
    """
    # Ordered for `bb audit`, which prints the remaining keys as `k=v` and
    # truncates: the finding, the gate and the author matter most.
    line = {
        "ts": record["granted_at"],
        "action": "waive",
        "engagement": record["engagement"],
        "finding": record["finding_uid"],
        "gate": record["gate"],
        "waived_by": record["waived_by"],
        "expires_at": record["expires_at"],
        "reason": record["reason"],
        "waiver_id": record["waiver_id"],
        "subject_sha256": record["subject_sha256"],
    }
    landed = False
    try:
        from .cli import audit_record

        landed = bool(audit_record("gate_waive", line))
    except Exception as exc:  # noqa: BLE001 - re-raised below as a refusal
        raise WaiverError(
            f"refusing to waive {record['gate']} on {record['finding_uid']}: the audit log "
            f"{paths.AUDIT_LOG} could not be written ({exc}), and an unrecorded waiver is "
            f"indistinguishable from a bypass. Fix the log, then retry:\n"
            f"  bb doctor --verify-chain\n  {_grant_cmd(record['finding_uid'], record['gate'])}"
        ) from exc
    if not landed:
        raise WaiverError(
            f"refusing to waive {record['gate']} on {record['finding_uid']}: the grant could "
            f"not be appended to {paths.AUDIT_LOG}, and an unrecorded waiver is "
            f"indistinguishable from a bypass. Check the log is writable, then retry:\n"
            f"  bb doctor --verify-chain\n  {_grant_cmd(record['finding_uid'], record['gate'])}"
        )


def revoke(
    store: Store,
    engagement: str,
    finding_ref: str | int,
    gate: str,
    *,
    revoked_by: str,
) -> tuple[Waiver | None, bool]:
    """Remove a granted waiver. Returns (what was removed, did the audit land).

    Taking a waiver away can only make the gates stricter, so this is the one
    place that proceeds when the audit log fails: refusing would leave the
    permissive thing standing because a log was unwritable. The caller is handed
    the flag so it can say so.
    """
    if gate not in WAIVABLE:
        raise WaiverError(_not_waivable(gate))
    who = " ".join(str(revoked_by or "").split())
    if _omitted(who):
        raise WaiverError(
            f"no name was given for who is revoking this; removing a control decision is "
            f"itself a decision someone made. Retry:\n"
            f"  bb gate waive --revoke <uid> {gate} --as '<your name>'"
        )
    row = _finding_row(store, finding_ref)
    uid = str(row["uid"])
    path = waiver_path(engagement, uid, gate)
    if not path.exists():
        raise WaiverError(
            f"no waiver of {gate} is recorded for {uid}, so there is nothing to revoke. See "
            f"what is outstanding: `bb gate waivers`"
        )
    removed = _read(path, engagement, uid, gate).waiver
    path.unlink()
    landed = False
    try:
        from .cli import audit_record

        landed = bool(
            audit_record(
                "gate_unwaive",
                {
                    "ts": utcnow(),
                    "action": "unwaive",
                    "engagement": engagement,
                    "finding": uid,
                    "gate": gate,
                    "revoked_by": who,
                    "waiver_id": removed.waiver_id if removed else None,
                },
            )
        )
    except Exception:  # noqa: BLE001 - reported through `landed`, never swallowed silently
        landed = False
    return removed, landed


# ---- the agent's side ------------------------------------------------------


def request_waiver(
    store: Store,
    finding_ref: str | int,
    gate: str,
    *,
    reason: str,
    asked_by: str = "agent",
) -> int:
    """Record that a gate's requirement was argued to be impossible. Grants nothing.

    This is the asymmetry made structural rather than textual. The row's verdict
    is the literal `"fail"`, because the gate has not passed and asking does not
    change that; `_read()` only ever looks at a signed file under `.state/`, so
    no sequence of calls available here can produce a honored waiver. What it
    does buy is that the argument lands where the operator already looks --
    `bb finding show <uid>` -- instead of in prose nobody reads.
    """
    if gate not in WAIVABLE:
        raise WaiverError(_not_waivable(gate))
    row = _finding_row(store, finding_ref)
    uid = str(row["uid"])
    problem = _reason_problem(reason)
    if problem:
        raise WaiverError(
            f"refusing to record a waiver request for {gate} on {uid}: {problem}; an "
            f"operator decides this from the reason alone, so it has to argue something. "
            f"Retry:\n  bb gate waive-request {uid} {gate} --reason '<why the artifact the "
            f"gate wants cannot exist for this finding>'"
        )
    body = " ".join(str(reason or "").split())
    who = " ".join(str(asked_by or "").split()) or "agent"
    return store.record_gate(
        row["id"],
        gate,
        "fail",
        f"waiver requested by {who} (not granted): {body}",
        {"waiver_request": {"gate": gate, "asked_by": who, "reason": body, "granted": False}},
    )


def requests_for(store: Store, finding_ref: str | int, gate: str | None = None) -> list[dict]:
    """Outstanding waiver requests on a finding, oldest first."""
    out = []
    for row in store.gates_for(finding_ref):
        asked = _request_stamp(row)
        if asked and (gate is None or str(row["gate"]) == gate):
            out.append(
                {"id": int(row["id"]), "ts": str(row["ts"]), "gate": str(row["gate"]), **asked}
            )
    return out


def _request_stamp(row: Any) -> dict[str, Any] | None:
    detail = _decode_detail(_attr(row, "detail"))
    asked = detail.get("waiver_request") if isinstance(detail, dict) else None
    return asked if isinstance(asked, dict) else None


# ---- reading a waiver ------------------------------------------------------


def check(
    store: Store,
    finding: Any,
    gate: str,
    *,
    engagement: str | None = None,
    now: str | None = None,
) -> WaiverStatus:
    """Does a waiver of `gate` stand for this finding right now, and if not, why.

    The gate calls this on its failure path. Every answer is recomputed: the
    signature over the file, the finding's fingerprint over the store, the
    expiry against the clock. Nothing a model wrote is consulted, and a question
    that cannot be answered -- an unreadable file, an unknown engagement -- is
    answered `honored=False` with the reason, never with a pass.
    """
    stamp = now or utcnow()
    row = _finding_row(store, finding)
    uid = str(row["uid"])

    name = (engagement or "").strip() or (paths.active_engagement() or "")
    if not name:
        return WaiverStatus(
            uid,
            gate,
            Path(),
            problems=[
                "no engagement is selected, so this harness cannot tell which waiver store "
                "to read and will not assume an unwaived gate was waived. Select it: "
                "`bb use <engagement>`"
            ],
        )

    if gate not in WAIVABLE:
        # Belt and braces: a file named for an unwaivable gate is never honored,
        # whatever put it there.
        return WaiverStatus(uid, gate, Path(), problems=[_not_waivable(gate)])

    try:
        path = waiver_path(name, uid, gate)
    except WaiverError as exc:
        # A gate asking "is this waived" must get an answer, not an abort: a uid
        # the store accepted but a filesystem will not is the harness's problem,
        # and the answer to it is still "no waiver stands".
        return WaiverStatus(uid, gate, Path(), problems=[str(exc)])
    if not path.exists():
        return WaiverStatus(uid, gate, path)

    status = _read(path, name, uid, gate)
    if status.waiver is None:
        return status

    waiver = status.waiver
    problems = list(status.problems)
    if waiver.expired(stamp):
        problems.append(
            f"the waiver of {gate} on {uid} expired at {waiver.expires_at} (now {stamp}); a "
            f"waiver that outlives its review is a silent pass, so it stops counting. If it "
            f"still holds, say so again with today's date:\n  {_grant_cmd(uid, gate)}"
        )
    current = subject_of(store, row)
    if _subject_digest(current) != waiver.subject_sha256:
        changes = "; ".join(_subject_changes(waiver.subject, current))
        problems.append(
            f"{uid} changed after {waiver.waived_by} waived {gate} on it ({changes}), so the "
            f"finding they argued about is not the one being gated. Re-read it and waive it "
            f"again if it still holds:\n  bb finding show {uid}\n  {_grant_cmd(uid, gate)}"
        )
    return WaiverStatus(uid, gate, path, True, waiver, not problems, problems)


def active(
    store: Store,
    finding: Any,
    gate: str,
    *,
    engagement: str | None = None,
    now: str | None = None,
) -> Waiver | None:
    """The waiver standing down `gate`, or None. Sugar over `check()`."""
    status = check(store, finding, gate, engagement=engagement, now=now)
    return status.waiver if status.honored else None


def _read(path: Path, engagement: str, uid: str, gate: str) -> WaiverStatus:
    """Parse and verify one waiver file. `waiver` is None when it cannot be trusted."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return WaiverStatus(
            uid,
            gate,
            path,
            True,
            problems=[
                f"{path} is not readable as a waiver ({exc}), so it cannot be trusted and is "
                f"ignored. Remove it and grant the waiver again if it still holds:\n"
                f"  rm {path}\n  {_grant_cmd(uid, gate)}"
            ],
        )
    if not isinstance(doc, dict):
        doc = {}
    problem = _signature_problem(doc)
    if problem:
        return WaiverStatus(
            uid,
            gate,
            path,
            True,
            problems=[
                f"the waiver at {path} is not trusted: {problem}. A waiver is an "
                f"authorization statement, so an unverifiable one counts for nothing. "
                f"Check the log for what was granted, then grant it again:\n"
                f"  bb audit --tail 50\n  {_grant_cmd(uid, gate)}"
            ],
        )
    mismatch = [
        f"it was granted for {key.replace('_', ' ')} {str(doc.get(key))!r}, not {want!r}"
        for key, want in (("engagement", engagement), ("finding_uid", uid), ("gate", gate))
        if str(doc.get(key) or "") != want
    ]
    if mismatch:
        return WaiverStatus(
            uid,
            gate,
            path,
            True,
            problems=[
                f"the waiver at {path} is scoped to something else ({'; '.join(mismatch)}), "
                f"so it does not apply here -- a waiver covers one finding and one gate by "
                f"design. Grant one for this pair if it is warranted:\n"
                f"  {_grant_cmd(uid, gate)}"
            ],
        )
    waiver = _from_doc(doc)
    if waiver is None:
        return WaiverStatus(
            uid,
            gate,
            path,
            True,
            problems=[
                f"the waiver at {path} is signed but incomplete, so the harness cannot say "
                f"who waived what until when. Grant it again:\n  {_grant_cmd(uid, gate)}"
            ],
        )
    return WaiverStatus(uid, gate, path, True, waiver, True, [])


def _from_doc(doc: Mapping[str, Any]) -> Waiver | None:
    """Build the record, or None when a field a reader needs is missing."""
    subject = doc.get("subject")
    needed = ("engagement", "finding_uid", "gate", "reason", "waived_by", "granted_at",
              "expires_at", "subject_sha256", "waiver_id")
    if not isinstance(subject, dict) or any(not str(doc.get(k) or "").strip() for k in needed):
        return None
    if _parse_stamp(doc["expires_at"]) is None:
        return None
    return Waiver(
        engagement=str(doc["engagement"]),
        finding_uid=str(doc["finding_uid"]),
        gate=str(doc["gate"]),
        reason=str(doc["reason"]),
        waived_by=str(doc["waived_by"]),
        granted_at=str(doc["granted_at"]),
        expires_at=str(doc["expires_at"]),
        subject=dict(subject),
        subject_sha256=str(doc["subject_sha256"]),
        waiver_id=str(doc["waiver_id"]),
    )


# ---- listing ---------------------------------------------------------------


def listing(store: Store, engagement: str, *, now: str | None = None) -> list[WaiverStatus]:
    """Every granted waiver in this engagement, with why each does or does not stand.

    Also the one place that cross-checks the audit log, reporting a waiver file
    with no grant recorded for it. That is detection, not enforcement: a forger
    who can sign a file can append a chained line too, so `check()` deliberately
    does not depend on the log -- see the module docstring.
    """
    root = waivers_dir(engagement)
    if not root.is_dir():
        return []
    granted = _audited_waiver_ids()
    out = []
    for path in sorted(root.glob("*.json")):
        # rpartition, not partition: a gate name holds no dot but a uid may.
        uid, _, gate = path.stem.rpartition(".")
        if gate not in WAIVABLE or not _UID_RE.match(uid):
            out.append(
                WaiverStatus(
                    uid,
                    gate,
                    path,
                    True,
                    problems=[
                        f"{path} is not a waiver this harness would ever honor: "
                        f"{_not_waivable(gate)}"
                    ],
                )
            )
            continue
        try:
            status = check(store, uid, gate, engagement=engagement, now=now)
        except WaiverError as exc:
            # A waiver file whose finding is gone -- a recreated database, a
            # hand-removed row. Listing it is the point; crashing is not.
            out.append(WaiverStatus(uid, gate, path, True, problems=[str(exc)]))
            continue
        if (
            status.waiver is not None
            and granted is not None
            and status.waiver.waiver_id not in granted
        ):
            status = WaiverStatus(
                status.finding_uid,
                status.gate,
                status.path,
                status.found,
                status.waiver,
                status.honored,
                status.problems,
                status.notes
                + [
                    f"no grant of this waiver ({status.waiver.waiver_id}) is recorded in "
                    f"{paths.AUDIT_LOG}, although `bb gate waive` always writes one before "
                    f"the file. Either the log was rotated or this file did not come from "
                    f"it: `bb doctor --verify-chain`"
                ],
            )
        out.append(status)
    return out


def _audited_waiver_ids() -> set[str] | None:
    """Waiver ids with a grant in the audit log, or None when it cannot be read.

    Streamed, not slurped: the log carries every guard decision for the whole
    engagement and is the one file here that grows without bound.
    """
    found: set[str] = set()
    try:
        with paths.AUDIT_LOG.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, dict):
                    continue
                inner = record.get("data") if isinstance(record.get("data"), dict) else record
                if inner.get("action") == "waive" and inner.get("waiver_id"):
                    found.add(str(inner["waiver_id"]))
    except OSError:
        return None
    return found


# ---- display ---------------------------------------------------------------


def stamp_for(waiver: Waiver) -> dict[str, Any]:
    """The `detail` key `apply_gates` records so a display can tell the two apart.

    A gates row carries the verdict word the store knows (`pass`), so without
    this a waived stand-down and an earned pass are the same row. The values are
    a copy of what was signed: the row says what happened then, and `check()`
    says whether it still stands now.
    """
    return {
        "waived": {
            "waiver_id": waiver.waiver_id,
            "gate": waiver.gate,
            "waived_by": waiver.waived_by,
            "reason": waiver.reason,
            "granted_at": waiver.granted_at,
            "expires_at": waiver.expires_at,
            "subject_sha256": waiver.subject_sha256,
        }
    }


def gate_verdict(gate_row: Any) -> str:
    """The word to display for one gates row: "pass", "fail" or "waived".

    Pure and local to the row on purpose. Resolving the file here would relabel
    a historical waived pass as a plain `pass` the moment the waiver expired or
    was revoked, which is the silent pass this mechanism exists to prevent: the
    ledger has to keep saying that the requirement was stood down.
    """
    if str(_attr(gate_row, "verdict") or "") != "pass":
        return "fail"  # anything that is not the store's "pass" displays as a failure
    return WAIVED if _waived_stamp(gate_row) else "pass"


def _waived_stamp(gate_row: Any) -> dict[str, Any] | None:
    detail = _decode_detail(_attr(gate_row, "detail"))
    waived = detail.get("waived") if isinstance(detail, dict) else None
    return waived if isinstance(waived, dict) else None


def _decode_detail(detail: Any) -> dict[str, Any]:
    if isinstance(detail, dict):
        return detail
    if isinstance(detail, (str, bytes)):
        try:
            parsed = json.loads(detail)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def report_lines(
    store: Store,
    finding: Any,
    *,
    engagement: str | None = None,
    now: str | None = None,
) -> list[str]:
    """Markdown for every gate this finding shipped with waived. Empty when none.

    Spliced into the report by `bbh.report`. The point is that the last human in
    the chain cannot miss it: a waived gate was not checked by anything, so they
    are the check, and a note they have to go looking for is no note at all. The
    lines are prose rather than a table because the reason is free text an
    operator typed.
    """
    row = _finding_row(store, finding)
    uid = str(row["uid"])
    latest: dict[str, Any] = {}
    for gate_row in store.gates_for(uid):  # oldest first, so the last write wins
        latest[str(gate_row["gate"])] = gate_row
    waived = [
        (name, _waived_stamp(row))
        for name, row in sorted(latest.items())
        if gate_verdict(row) == WAIVED
    ]
    if not waived:
        return []

    out = ["## Gates waived for this finding", ""]
    for name, granted in waived:
        granted = granted or {}
        who = str(granted.get("waived_by") or "an unnamed operator")
        out += [
            f"> **This finding shipped with `{name}` waived by {who}.**",
            f"> Reason given, in their words: {granted.get('reason') or '(none recorded)'}",
            f"> Waived at {granted.get('granted_at') or '?'}, expiring "
            f"{granted.get('expires_at') or '?'}.",
            ">",
            "> A waived gate is not a passed gate. Its requirement was stood down by the "
            "person named above and nothing mechanical checked what it would have checked, "
            "so you are that check. Why this gate can be waived at all: "
            f"{WAIVABLE.get(name, 'no recorded reason, which is itself a problem')}.",
        ]
        status = check(store, row, name, engagement=engagement, now=now)
        if not status.honored:
            detail = " ".join(" ".join(p.split()) for p in status.problems) or (
                "the waiver is no longer on record"
            )
            out += [
                ">",
                f"> **WARNING: the waiver this pass leaned on no longer stands.** {detail}",
                f"> Do not submit this until the gates have been run again: `bb gate {uid}`",
            ]
        out.append("")
    return out


# ---- self-check ------------------------------------------------------------


def coverage_problem(known_gates: Iterable[str]) -> str | None:
    """Why the allowlist and the gate registry disagree, or None.

    A gate in neither map is already unwaivable -- `check()` requires membership
    in `WAIVABLE` -- so this does not guard a bypass. It guards the argument: a
    gate added without a recorded decision is one nobody thought about, and a
    name in the maps that no longer exists means a justification is being read
    for a gate that is gone.
    """
    known = set(known_gates)
    decided = set(WAIVABLE) | set(UNWAIVABLE)
    problems = []
    both = sorted(set(WAIVABLE) & set(UNWAIVABLE))
    if both:
        problems.append(
            f"{', '.join(both)} appear in both WAIVABLE and UNWAIVABLE, so the policy "
            f"contradicts itself"
        )
    undecided = sorted(known - decided)
    if undecided:
        problems.append(
            f"{', '.join(undecided)} have no recorded waiver decision; they are unwaivable "
            f"by default, which may be right, but say so in bbh/waiver.py:UNWAIVABLE with "
            f"the reason"
        )
    stale = sorted(decided - known)
    if stale:
        problems.append(
            f"{', '.join(stale)} are named in the waiver policy but are not gates any more; "
            f"drop them from bbh/waiver.py"
        )
    if not problems:
        return None
    return "the waiver policy and the gate registry disagree: " + "; ".join(problems)
