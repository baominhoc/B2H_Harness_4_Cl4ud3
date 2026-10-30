"""CVSS 3.1 base score, so severity is derived from metrics instead of asserted.

A severity an agent types is a claim; a score computed from the eight base
metrics is an artifact a triager can recheck in a calculator. That is the whole
reason this module exists: `triage.gate_severity_derived` recomputes the score
from `findings.cvss_vector` and fails on a mismatch, so "critical" has to be
argued in metrics that someone can disagree with one at a time.

Stdlib only, and no I/O: the formula is from the CVSS v3.1 specification
(section 7.1, Base), including the two details people usually get wrong -- the
roundup is a ceiling on one decimal computed in integer arithmetic, not
`round(x, 1)`, and a vector with no impact at all scores 0.0 however reachable
the component is.
"""

from __future__ import annotations

import math
import re
from typing import Mapping

__all__ = [
    "CvssError",
    "BASE_METRICS",
    "EXAMPLE_VECTOR",
    "parse_vector",
    "base_score",
    "severity_label",
]


class CvssError(ValueError):
    """A vector that cannot be scored. Carries the fix in its message."""


# Weights from the specification. PR is the one metric whose weight depends on
# another (Scope), so it keeps a column per scope value.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# The eight base metrics, in vector order, with the values each accepts.
BASE_METRICS: dict[str, tuple[str, ...]] = {
    "AV": tuple(_AV),
    "AC": tuple(_AC),
    "PR": tuple(_PR["U"]),
    "UI": tuple(_UI),
    "S": ("U", "C"),
    "C": tuple(_CIA),
    "I": tuple(_CIA),
    "A": tuple(_CIA),
}

EXAMPLE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

# Temporal and environmental metrics are accepted and ignored: they are part of
# a legitimate full vector and none of them enters the base score.
_NON_BASE = frozenset(
    "E RL RC CR IR AR MAV MAC MPR MUI MS MC MI MA".split()
)

_PREFIX_RE = re.compile(r"^CVSS:3\.[01]$", re.I)


def parse_vector(vector: str) -> dict[str, str]:
    """Validate a vector string and return its eight base metrics.

    Accepts an optional `CVSS:3.1/` (or 3.0) prefix and any temporal or
    environmental metrics, which are ignored. Anything else raises, because a
    vector the harness cannot read must not silently score as something else.
    """
    text = str(vector or "").strip().strip("/")
    if not text:
        raise CvssError(f"no CVSS vector given; it looks like {EXAMPLE_VECTOR}")
    parts = text.split("/")
    if ":" in parts[0] and parts[0].upper().startswith("CVSS"):
        if not _PREFIX_RE.match(parts[0]):
            raise CvssError(
                f"{parts[0]!r} is not a CVSS 3.0/3.1 prefix; this harness scores CVSS 3.1 "
                f"only, e.g. {EXAMPLE_VECTOR}"
            )
        parts = parts[1:]

    found: dict[str, str] = {}
    for part in parts:
        metric, _, value = part.partition(":")
        metric, value = metric.strip().upper(), value.strip().upper()
        if not metric or not value:
            raise CvssError(
                f"{part!r} is not a METRIC:VALUE pair; a vector looks like {EXAMPLE_VECTOR}"
            )
        if metric in _NON_BASE:
            continue  # legitimate, and not part of the base score
        if metric not in BASE_METRICS:
            raise CvssError(
                f"unknown CVSS metric {metric!r}; the base metrics are "
                f"{', '.join(BASE_METRICS)}, e.g. {EXAMPLE_VECTOR}"
            )
        if metric in found:
            raise CvssError(f"metric {metric} appears twice in {text!r}")
        if value not in BASE_METRICS[metric]:
            raise CvssError(
                f"{metric}:{value} is not a valid value; {metric} is one of "
                f"{'/'.join(BASE_METRICS[metric])}"
            )
        found[metric] = value

    missing = [m for m in BASE_METRICS if m not in found]
    if missing:
        raise CvssError(
            f"CVSS vector {text!r} is missing {', '.join(missing)}; all eight base metrics "
            f"are required, e.g. {EXAMPLE_VECTOR}"
        )
    return found


def _roundup(value: float) -> float:
    """Ceiling to one decimal, in integer arithmetic, per CVSS 3.1 Appendix A.

    `round(x, 1)` is wrong here: 8.749999 must become 8.8, and binary floats
    make the naive comparison flip at the boundary.
    """
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def base_score(vector: str | Mapping[str, str]) -> float:
    """CVSS 3.1 base score, 0.0-10.0, rounded up to one decimal."""
    metrics = parse_vector(vector) if isinstance(vector, str) else parse_vector(
        "/".join(f"{k}:{v}" for k, v in vector.items())
    )

    scope_changed = metrics["S"] == "C"
    iss = 1.0 - (
        (1.0 - _CIA[metrics["C"]]) * (1.0 - _CIA[metrics["I"]]) * (1.0 - _CIA[metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        # No confidentiality, integrity or availability effect: nothing to score,
        # however trivially reachable the component is.
        return 0.0

    exploitability = (
        8.22
        * _AV[metrics["AV"]]
        * _AC[metrics["AC"]]
        * _PR["C" if scope_changed else "U"][metrics["PR"]]
        * _UI[metrics["UI"]]
    )
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return _roundup(min(raw, 10.0))


def severity_label(score: float) -> str:
    """The harness severity word for a base score.

    The CVSS 3.1 rating scale calls 0.0 "None"; the harness word for it is
    `info`, so that `store.SEVERITIES` stays the one vocabulary and a 0.0 vector
    lands on the severity that never ships.
    """
    value = float(score)
    if not 0.0 <= value <= 10.0 or value != value:  # NaN fails both comparisons
        raise CvssError(f"a CVSS base score is between 0.0 and 10.0, got {score!r}")
    if value == 0.0:
        return "info"
    if value < 4.0:
        return "low"
    if value < 7.0:
        return "medium"
    if value < 9.0:
        return "high"
    return "critical"
