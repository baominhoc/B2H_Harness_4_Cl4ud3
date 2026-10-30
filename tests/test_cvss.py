"""The CVSS 3.1 base score.

These tests are pinned against the published worked examples rather than
against the implementation, because a scoring function that is only
self-consistent is worthless: the whole point of deriving severity is that a
triager can recompute it in someone else's calculator and get the same number.
Each vector below is a real CVE with a score published alongside it in the CVSS
v3.1 examples, so a formula error shows up as a specific CVE disagreeing.

The three parts people get wrong have their own tests: the roundup is a ceiling
to one decimal and not `round(x, 1)`, the scope-changed branch has its own
impact formula and a 1.08 multiplier, and a vector with no confidentiality,
integrity or availability effect scores 0.0 however reachable the component is.
"""

from __future__ import annotations

import pytest

from bbh.cvss import (
    EXAMPLE_VECTOR,
    CvssError,
    base_score,
    parse_vector,
    severity_label,
)

# (name, vector, published base score, rating) from the CVSS v3.1 examples.
PUBLISHED = [
    ("CVE-2013-1937", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    ("CVE-2013-0375", "AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "medium"),
    ("CVE-2014-3566", "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N", 3.4, "low"),
    ("CVE-2012-1516", "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "critical"),
    ("CVE-2009-0658", "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "high"),
    ("CVE-2014-0160", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
    ("CVE-2014-6271", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVE-2008-1447", "AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", 6.8, "medium"),
    ("CVE-2014-2005", "AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8, "medium"),
    ("CVE-2010-0467", "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", 5.8, "medium"),
    ("CVE-2012-1342", "AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8, "medium"),
    ("CVE-2015-1098", "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "high"),
]


@pytest.mark.parametrize("name,vector,score,label", PUBLISHED, ids=[c[0] for c in PUBLISHED])
def test_the_published_examples_score_as_published(name, vector, score, label):
    assert base_score(vector) == score, name
    assert severity_label(base_score(vector)) == label, name


def test_the_prefix_is_optional_and_changes_nothing():
    bare = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert base_score(bare) == base_score(f"CVSS:3.1/{bare}") == 7.5
    assert base_score(f"CVSS:3.0/{bare}") == 7.5


def test_temporal_and_environmental_metrics_are_ignored():
    """A full vector is legitimate; only the base metrics enter the base score."""
    full = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C/CR:H/MAV:L"
    assert base_score(full) == 7.5


def test_a_vector_with_no_impact_scores_zero_however_reachable_it_is():
    """The trivially-reachable-but-harmless case, which is the one that inflates."""
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N") == 0.0
    assert severity_label(0.0) == "info"


def test_the_maximum_is_ten_not_more():
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0


def test_the_scope_changed_branch_is_not_the_unchanged_one():
    """Same metrics, different Scope: the formula and the 1.08 both apply."""
    unchanged = base_score("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    changed = base_score("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    assert unchanged == 8.8
    assert changed == 9.9


def test_privileges_required_is_weighted_differently_when_scope_changes():
    """PR:L is worth 0.62 unchanged and 0.68 changed; nothing else differs."""
    assert base_score("AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N") == 6.4
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N") == 7.2


def test_the_roundup_is_a_ceiling_on_one_decimal():
    """6.0072 is 6.1, not 6.0: `round(x, 1)` would ship the wrong severity."""
    assert base_score("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    # 3.3010 -> 3.4, and a score that lands exactly on a tenth stays there.
    assert base_score("AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N") == 3.4
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5


@pytest.mark.parametrize(
    "score,label",
    [
        (0.0, "info"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"),
        (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical"),
    ],
)
def test_the_rating_bands_are_the_published_ones(score, label):
    assert severity_label(score) == label


def test_a_score_off_the_scale_is_a_caller_bug():
    with pytest.raises(CvssError):
        severity_label(11.0)
    with pytest.raises(CvssError):
        severity_label(-0.1)


# -- parsing -----------------------------------------------------------------


def test_parse_returns_the_eight_base_metrics_normalised():
    assert parse_vector("cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:n/a:n") == {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N",
    }


def test_a_parsed_vector_can_be_scored_again():
    """base_score accepts the mapping, so a caller can inspect then score."""
    metrics = parse_vector(EXAMPLE_VECTOR)
    assert base_score(metrics) == base_score(EXAMPLE_VECTOR)


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("", "no CVSS vector given"),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N", "missing A"),
        ("AV:N/AC:L/UI:N/S:U/C:H/I:N/A:N", "missing PR"),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:X", "A:X is not a valid value"),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:N/A:N", "C:M is not a valid value"),
        ("AV:N/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "appears twice"),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/XX:Y", "unknown CVSS metric"),
        ("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "not a CVSS 3.0/3.1 prefix"),
        # The realistic mistake: the severity word passed where a vector belongs.
        ("critical", "METRIC:VALUE"),
        ("severity: critical", "unknown CVSS metric"),
    ],
)
def test_an_unscoreable_vector_raises_and_says_what_is_wrong(vector, expected):
    """Fail closed: a vector the harness cannot read must never score as something."""
    with pytest.raises(CvssError) as exc:
        base_score(vector)
    assert expected in str(exc.value)


def test_every_parse_error_shows_a_vector_that_would_work():
    """The message is read by an agent mid-hunt, so it carries the shape to copy."""
    with pytest.raises(CvssError) as exc:
        parse_vector("AV:N")
    assert EXAMPLE_VECTOR in str(exc.value)
