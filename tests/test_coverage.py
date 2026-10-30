"""Coverage derived from runtime facts (CONTRACT v2 item 10).

The thing under test is a distinction, not a feature: a class that was never
routed must not read like a class that was tested and found clean. So most of
these tests are about what does *not* count as coverage -- a settled angle on a
surface the request log never touched, a declared endpoint nobody requested, an
empty eligible set with nobody to explain it -- because every one of those,
counted the generous way, turns one tooling failure into a permanent false
negative.

The path-shaping tests look like trivia and are not. Each one pins a decision
about what counts as the same surface, and the dangerous direction is always
over-collapsing: an unrecognised identifier costs one noisy row, while a route
wrongly merged into another shape disappears from the inventory and reads as
covered.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from bbh import coverage, paths
from bbh.coverage import (
    CLASSES,
    DATE,
    ELIGIBILITY,
    ID,
    MAX_GAP_LINES,
    REASON_MIN_CHARS,
    STATUS_CLOSED,
    STATUS_EXPLAINED,
    STATUS_PARTIAL,
    STATUS_UNROUTED,
    STATUS_UNTESTED,
    CoverageError,
    Surface,
)
from bbh.store import MIGRATIONS, SCHEMA_VERSION, Store

CONTROL = "server-side ownership check: every other tenant id returns 403"
GOOD_REASON = (
    "no mapped surface accepts a file upload, and recon found no multipart form on any host"
)

# Classes the eligibility table does not narrow, so they are eligible on every
# surface in the inventory.
BROAD_CLASSES = tuple(c for c in CLASSES if c not in ELIGIBILITY)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def recon_handoff(engagement: str = "acme", **keys) -> None:
    """Write the recon handoff. Without one, coverage reports an incomplete map."""
    doc = {"hosts": [], "endpoints": [], "tech": [], "auth_surfaces": [], **keys}
    path = paths.engagement_dir(engagement) / "handoff" / "00-recon.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def record(
    store: Store,
    path: str,
    *,
    method: str = "GET",
    host: str = "www.acme.example",
    actor: str = "attacker",
    credential: bool = True,
    query: str | None = None,
    status: int = 200,
) -> int:
    """One recorded request, the way the sanctioned client leaves it."""
    url = f"https://{host}{path}" + (f"?{query}" if query else "")
    headers = {"Accept": "*/*"}
    if credential:
        headers["Cookie"] = "sid=<redacted sha256:deadbeef>"
    return store.add_request(
        source="client",
        actor=actor,
        method=method,
        url=url,
        host=host,
        path=path,
        query=query,
        status=status,
        req_headers=headers,
    )


def close_broad_classes(store: Store, surface: str) -> None:
    """Settle every class with no narrowing rule on one surface."""
    for cls in BROAD_CLASSES:
        store.record_angle(surface, cls, "sweep", "ruled_out", control=CONTROL)


def labels(surfaces) -> set[str]:
    return {s.label for s in surfaces}


# ---------------------------------------------------------------------------
# the migration
# ---------------------------------------------------------------------------


def test_the_inventory_arrives_as_a_migration(store):
    """A table added to the base DDL is a table an old engagement never gets."""
    assert (3, "derived surface inventory and recorded coverage reasons") in [
        (version, description) for version, description, _apply in MIGRATIONS
    ]
    assert SCHEMA_VERSION == 3
    tables = {
        row["name"]
        for row in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"surfaces", "coverage_reasons"} <= tables


def test_the_inventory_is_unique_per_host_shape_and_method(store):
    stamp = "2026-10-30T00:00:00Z"
    with store.tx() as conn:
        conn.execute(
            "INSERT INTO surfaces(host, path_shape, method, derived_at) VALUES (?,?,?,?)",
            ("a.acme.example", "/x", "GET", stamp),
        )
    with pytest.raises(sqlite3.IntegrityError):
        with store.tx() as conn:
            conn.execute(
                "INSERT INTO surfaces(host, path_shape, method, derived_at) VALUES (?,?,?,?)",
                ("a.acme.example", "/x", "GET", stamp),
            )


# ---------------------------------------------------------------------------
# path shaping: one test per documented decision
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,expected",
    [
        # numeric ids
        ("/api/docs/8831", "/api/docs/{id}"),
        ("/api/docs/0", "/api/docs/{id}"),
        # a version segment is a name, not an id
        ("/api/v1/docs", "/api/v1/docs"),
        # uuid, any case
        ("/d/550E8400-E29B-41D4-A716-446655440000", "/d/{id}"),
        # long hex: 12 or more. md5, sha1 and a mongo ObjectId all land here.
        ("/u/d41d8cd98f00b204e9800998ecf8427e", "/u/{id}"),
        ("/u/507f1f77bcf86cd7", "/u/{id}"),
        # ...and a short hex run is a word, kept as itself
        ("/theme/cafe", "/theme/cafe"),
        ("/api/beef", "/api/beef"),
        # opaque token: long, mixed case, two or more digits
        ("/s/01ARZ3NDEKTSV4RRFFQ69G5FAV", "/s/{id}"),
        ("/t/eyJhbGciOiJIUzI1NiJ9", "/t/{id}"),
        # ...but a long route name is not a token: one digit, or all lowercase
        ("/api/getUserProfileV2Data", "/api/getUserProfileV2Data"),
        ("/blog/this-is-a-very-long-slug-2024", "/blog/this-is-a-very-long-slug-2024"),
        ("/api/authorize-callback-v2", "/api/authorize-callback-v2"),
        # dates get their own placeholder: a date is a range to query, not an
        # object to enumerate
        ("/reports/2026-10-30", "/reports/{date}"),
        ("/reports/2026-10", "/reports/{date}"),
        ("/logs/2026-10-30T12:00:00Z", "/logs/{date}"),
        # a bare run of digits is an id even when it reads like a date
        ("/reports/20261030", "/reports/{id}"),
        # the extension stays: it selects the handler, so .pdf is not .json
        ("/files/1234.pdf", "/files/{id}.pdf"),
        ("/files/550e8400-e29b-41d4-a716-446655440000.json", "/files/{id}.json"),
        ("/static/app.js", "/static/app.js"),
        # ids an agent or a spec already templated
        ("/api/docs/{id}", "/api/docs/{id}"),
        ("/api/docs/{document_id}", "/api/docs/{id}"),
        ("/api/docs/:id", "/api/docs/{id}"),
        ("/api/docs/<id>", "/api/docs/{id}"),
        ("/api/docs/*", "/api/docs/{id}"),
        ("/api/reports/{date}", "/api/reports/{date}"),
        # trailing and duplicate slashes are routing details, not surfaces
        ("/api/docs/", "/api/docs"),
        ("//api//docs//", "/api/docs"),
        ("", "/"),
        ("/", "/"),
        (None, "/"),
        # query and fragment belong to the request, not the shape
        ("/search?q=1", "/search"),
        ("/page#frag", "/page"),
        # a percent-encoded identifier reaches the same handler as a plain one
        ("/api/docs/%328", "/api/docs/{id}"),
        # ...but an encoded slash must not restructure the path into another
        # route's shape, so a segment that is not an identifier stays as written
        ("/api/b%2Fc", "/api/b%2Fc"),
    ],
)
def test_path_shape_decisions(path, expected):
    assert coverage.path_shape(path) == expected


def test_the_dedupe_shaper_and_the_coverage_shaper_agree_on_the_common_core():
    """A dedup key and a coverage surface must mean the same thing by "one route".

    `triage.normalize_path_shape` (v2 item 11) and `coverage.path_shape` are two
    normalisers on purpose: dedupe is safe when it over-collapses, because two
    reports of one bug have to collide, while coverage is safe when it
    under-collapses, because two routes merged into one shape disappear from the
    inventory and read as covered. Case folding is where that bites -- it is
    right for a dedup key and wrong for a surface -- so the relationship pinned
    here is that triage's shape is coverage's, folded.

    They still diverge where coverage collapses more: `{date}` segments, a kept
    file extension, and `:id` / `<id>` / `*` templates, none of which triage
    treats as identifiers. That makes coverage coarser there, not finer, so the
    divergence costs dedupe a collision rather than costing coverage a surface.
    """
    triage = pytest.importorskip("bbh.triage")
    for path in (
        "/api/docs/8831",
        "/d/550e8400-e29b-41d4-a716-446655440000",
        "/u/d41d8cd98f00b204e9800998ecf8427e",
        "/s/01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "/api/v1/docs",
        "/API/Docs",
        "/about",
        "/",
    ):
        assert triage.normalize_path_shape(path) == coverage.path_shape(path).casefold(), path


def test_a_date_segment_is_not_an_identifier():
    """`/reports/{date}` is the same document for every tenant, so it is not an IDOR."""
    dated = Surface("h", f"/reports/{DATE}", "GET", observations=1)
    identified = Surface("h", f"/docs/{ID}", "GET", observations=1)
    assert not coverage.HAS_IDENTIFIER.holds(dated)
    assert coverage.HAS_IDENTIFIER.holds(identified)


def test_a_deep_path_keeps_a_marker_rather_than_folding_into_its_prefix():
    """Two different deep paths must not become one row."""
    deep = "/" + "/".join(f"seg{i}" for i in range(40))
    shaped = coverage.path_shape(deep)
    assert shaped.endswith("/...")
    assert shaped != coverage.path_shape("/" + "/".join(f"seg{i}" for i in range(40, 80)))


def test_an_empty_method_becomes_unknown_and_counts_as_state_changing():
    """An unparseable method must not excuse a surface from the write classes."""
    assert coverage.normalize_method("") == "?"
    assert coverage.normalize_method(" post ") == "POST"
    assert coverage.is_state_changing("?")
    assert coverage.is_state_changing("POST")
    assert not coverage.is_state_changing("get")


def test_query_keys_are_names_only():
    """A value can be a credential; the inventory is read into prompts and reports."""
    assert coverage.query_keys("token=hunter2&Doc_Id=5") == ("doc_id", "token")
    assert "hunter2" not in "".join(coverage.query_keys("token=hunter2"))
    assert coverage.query_keys(None) == ()


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("api.acme.example/api/docs/5", ("api.acme.example", "/api/docs/{id}")),
        ("https://API.Acme.example:8443/a/1", ("api.acme.example", "/a/{id}")),
        # a bare host is the host's root surface and nothing more
        ("api.acme.example", ("api.acme.example", "/")),
        ("not a host at all", None),
        ("", None),
        (None, None),
    ],
)
def test_split_surface(raw, expected):
    assert coverage.split_surface(raw) == expected


# ---------------------------------------------------------------------------
# deriving the inventory
# ---------------------------------------------------------------------------


def test_surfaces_are_derived_from_the_request_log(store, engagement):
    recon_handoff()
    record(store, "/api/docs/2")
    record(store, "/api/docs/3")
    record(store, "/api/docs", method="POST")

    result = coverage.refresh(store)
    assert result.requests_folded == 3
    assert result.surfaces == 2, "two ids collapse into one shape; POST is its own row"
    assert labels(coverage.load_surfaces(store)) == {
        "GET www.acme.example/api/docs/{id}",
        "POST www.acme.example/api/docs",
    }
    row = next(s for s in coverage.load_surfaces(store) if s.method == "GET")
    assert row.observations == 2
    assert row.observed is True


def test_auth_state_comes_from_the_recorded_headers_not_the_actor_label(store, engagement):
    """The actor label is chosen by the agent; the headers are what was sent."""
    recon_handoff()
    record(store, "/api/docs/2", actor="attacker", credential=True)
    # An agent that labels an unauthenticated request "attacker" does not get an
    # authenticated observation out of it.
    record(store, "/api/docs/3", actor="attacker", credential=False)

    coverage.refresh(store)
    surface = coverage.load_surfaces(store)[0]
    assert (surface.authed, surface.anon) == (1, 1)


def test_the_recon_handoff_adds_surfaces_nobody_requested(store, engagement):
    """The gap this module exists for: mapped, never touched, and visible as such."""
    recon_handoff(
        hosts=[{"host": "www.acme.example", "scheme": "https"}],
        endpoints=[{"url": "https://www.acme.example/api/v1/users/{id}", "method": "GET"}],
    )
    result = coverage.refresh(store)
    assert result.observed == 0
    assert result.declared_only == 2
    declared = {s.label for s in coverage.load_surfaces(store) if not s.observed}
    assert declared == {
        "GET www.acme.example/",
        "GET www.acme.example/api/v1/users/{id}",
    }


def test_a_declared_endpoint_out_of_scope_is_not_listed_as_work(store, engagement):
    recon_handoff(endpoints=[{"url": "https://evil.example/x", "method": "GET"}])
    result = coverage.refresh(store)
    assert result.surfaces == 0
    assert any("outside the armed scope" in note for note in result.notes)
    assert not result.problems, "dropping an unscoped host is correct, not a gap"


def test_a_missing_recon_handoff_is_a_blocker_not_a_silent_pass(store, engagement):
    record(store, "/api/docs/2")
    result = coverage.refresh(store)
    assert result.problems
    problem = result.problems[0]
    assert "does not exist" in problem
    assert "bb phase 00-recon" in problem, "a refusal names the command that fixes it"

    report = coverage.report(store)
    assert report.blockers
    assert report.clean is False, "an incomplete inventory is never a clean sweep"


def test_an_unusable_scope_lock_refuses_to_ingest_declared_endpoints(store, engagement):
    recon_handoff(endpoints=[{"url": "https://www.acme.example/a", "method": "GET"}])
    paths.lock_path("acme").write_text("{not json", encoding="utf-8")
    result = coverage.refresh(store)
    assert result.surfaces == 0, "unscoped endpoints are not surfaces"
    assert any("scope lock" in p and "bb scope compile" in p for p in result.problems)


def test_a_store_outside_an_engagement_tree_says_so(tmp_path):
    db = Store(tmp_path / "loose.sqlite3")
    result = coverage.refresh(db)
    assert coverage.engagement_of(db) is None
    assert any("could not be matched to an engagement" in p for p in result.problems)
    db.close()


def test_refresh_rebuilds_rather_than_amends(store, engagement):
    """The table is a cache of a derivation; rebuilding is how it cannot drift."""
    recon_handoff()
    record(store, "/api/docs/2")
    first = coverage.refresh(store)
    before = coverage.load_surfaces(store)

    again = coverage.refresh(store)
    assert (again.surfaces, again.requests_folded) == (first.surfaces, first.requests_folded)
    assert coverage.load_surfaces(store) == before, "a second pass is the same derivation"

    # A hand-inserted row that derives from nothing does not survive a rebuild.
    with store.tx() as conn:
        conn.execute(
            "INSERT INTO surfaces(host, path_shape, method, derived_at) VALUES (?,?,?,?)",
            ("ghost.acme.example", "/invented", "GET", "2026-01-01T00:00:00Z"),
        )
    coverage.refresh(store)
    assert "ghost.acme.example" not in {s.host for s in coverage.load_surfaces(store)}


def test_a_stale_inventory_is_refused_rather_than_answered(store, engagement):
    recon_handoff()
    record(store, "/api/docs/2")
    coverage.refresh(store)
    assert coverage.stale_reason(store) is None

    record(store, "/api/admin/panel")
    reason = coverage.stale_reason(store)
    assert reason is not None and "since the surface inventory was derived" in reason
    with pytest.raises(CoverageError) as exc:
        coverage.remaining(store, "idor")
    assert "bb coverage" in str(exc.value)


def test_a_never_derived_inventory_is_refused(store, engagement):
    with pytest.raises(CoverageError) as exc:
        coverage.eligible(store, "idor")
    assert "never been derived" in str(exc.value)
    assert "bb coverage" in str(exc.value)


def test_report_rebuilds_so_it_cannot_answer_from_a_stale_table(store, engagement):
    recon_handoff()
    record(store, "/api/docs/2")
    coverage.refresh(store)
    record(store, "/api/admin/panel")
    report = coverage.report(store)
    assert report.surfaces == 2, "the new surface is in the table report() answered from"


# ---------------------------------------------------------------------------
# eligibility: a routing hint, never a kill list
# ---------------------------------------------------------------------------


def test_idor_needs_an_identifier_in_the_request(store, engagement):
    recon_handoff()
    record(store, "/api/docs/2")
    record(store, "/about")
    record(store, "/search", query="doc_id=5")
    coverage.refresh(store)

    assert labels(coverage.eligible(store, "idor")) == {
        "GET www.acme.example/api/docs/{id}",
        "GET www.acme.example/search",
    }


def test_auth_bypass_needs_the_surface_seen_both_ways(store, engagement):
    recon_handoff()
    record(store, "/api/docs/2", credential=True)
    record(store, "/api/docs/3", credential=False)
    record(store, "/api/only-authed", credential=True)
    coverage.refresh(store)

    assert labels(coverage.eligible(store, "auth-bypass")) == {
        "GET www.acme.example/api/docs/{id}"
    }


def test_the_write_classes_need_a_state_changing_method(store, engagement):
    recon_handoff()
    record(store, "/api/docs", method="POST")
    record(store, "/api/docs")
    coverage.refresh(store)

    for cls in ("csrf", "race", "file-upload"):
        assert labels(coverage.eligible(store, cls)) == {"POST www.acme.example/api/docs"}


def test_open_redirect_needs_a_parameter_to_travel_in(store, engagement):
    recon_handoff()
    record(store, "/login", query="next=/home")
    record(store, "/about")
    coverage.refresh(store)
    assert labels(coverage.eligible(store, "open-redirect")) == {
        "GET www.acme.example/login"
    }


def test_every_narrowing_rule_names_a_class_in_the_vocabulary():
    """A key that matches nothing is a rule that silently never applies."""
    assert set(ELIGIBILITY) <= set(CLASSES)
    for cls, rule in ELIGIBILITY.items():
        assert rule.requires, f"{cls} has an empty rule, which narrows nothing"
        assert rule.why.strip(), f"{cls} narrows eligibility without saying why"


def test_a_class_with_no_rule_is_eligible_everywhere(store, engagement):
    """The table narrows where to look first; it never decides where a bug cannot be."""
    recon_handoff()
    record(store, "/about")
    record(store, "/api/docs", method="POST")
    coverage.refresh(store)

    everything = labels(coverage.load_surfaces(store))
    for cls in ("sqli", "xss", "ssrf", "rce", "business-logic"):
        assert labels(coverage.eligible(store, cls)) == everything
    assert labels(coverage.eligible(store, "a-class-nobody-has-heard-of")) == everything


def test_the_eligibility_table_cannot_mark_a_class_impossible(store, engagement):
    """An empty eligible set is "never routed", which is worse than untested."""
    recon_handoff()
    record(store, "/about")  # no id, no query, read-only
    coverage.refresh(store)

    assert coverage.eligible(store, "idor") == ()
    row = coverage.class_report(store, "idor")
    assert row.status == STATUS_UNROUTED
    assert coverage.report(store).clean is False


# ---------------------------------------------------------------------------
# tested / remaining
# ---------------------------------------------------------------------------


def test_a_settled_angle_with_matching_traffic_counts_as_tested(store, engagement):
    recon_handoff()
    record(store, "/api/docs/2")
    coverage.refresh(store)
    store.record_angle(
        "www.acme.example/api/docs/{id}", "idor", "cross-account", "ruled_out",
        control=CONTROL,
    )
    assert labels(coverage.tested(store, "idor")) == {
        "GET www.acme.example/api/docs/{id}"
    }
    assert coverage.remaining(store, "idor") == ()


@pytest.mark.parametrize("outcome,kw", [
    ("open_gap", {"next_test": "swap the id as the second account"}),
    ("blocked", {}),
])
def test_an_unsettled_angle_leaves_the_ground_remaining(store, engagement, outcome, kw):
    """"I moved on" and "I could not" are not results. Neither closes a surface."""
    recon_handoff()
    record(store, "/api/docs/2")
    coverage.refresh(store)
    store.record_angle(
        "www.acme.example/api/docs/{id}", "idor", "cross-account", outcome, **kw
    )
    assert coverage.tested(store, "idor") == ()
    assert labels(coverage.remaining(store, "idor")) == {
        "GET www.acme.example/api/docs/{id}"
    }


def test_a_settled_angle_with_no_traffic_is_reported_not_counted(store, engagement):
    """A ruled_out on ground the request log never touched is a claim, not a result."""
    recon_handoff(
        endpoints=[{"url": "https://www.acme.example/api/docs/{id}", "method": "GET"}]
    )
    coverage.refresh(store)
    store.record_angle(
        "www.acme.example/api/docs/{id}", "idor", "cross-account", "ruled_out",
        control=CONTROL,
    )

    assert coverage.tested(store, "idor") == (), "declared is not tested"
    report = coverage.report(store)
    assert report.unsupported
    assert "no request to that surface" in report.unsupported[0]
    assert report.clean is False


def test_a_declared_only_surface_can_never_be_tested(store, engagement):
    recon_handoff(endpoints=[{"url": "https://www.acme.example/api/v1/users/7"}])
    record(store, "/api/docs/2")
    coverage.refresh(store)
    for cls in ("idor", "sqli"):
        store.record_angle("www.acme.example/api/v1/users/{id}", cls, "t", "ruled_out",
                           control=CONTROL)
    assert "GET www.acme.example/api/v1/users/{id}" not in labels(
        coverage.tested(store, "idor")
    )
    assert "GET www.acme.example/api/v1/users/{id}" in labels(
        coverage.remaining(store, "idor")
    )


def test_a_technique_naming_a_method_narrows_the_credit(store, engagement):
    """Model-written text may narrow what counts as tested; it may never widen it."""
    recon_handoff()
    record(store, "/api/docs/2")
    record(store, "/api/docs/2", method="DELETE")
    coverage.refresh(store)

    store.record_angle(
        "www.acme.example/api/docs/{id}", "business-logic", "cross-account-get",
        "ruled_out", control=CONTROL,
    )
    assert labels(coverage.tested(store, "business-logic")) == {
        "GET www.acme.example/api/docs/{id}"
    }
    assert labels(coverage.remaining(store, "business-logic")) == {
        "DELETE www.acme.example/api/docs/{id}"
    }


def test_a_technique_naming_no_method_credits_every_eligible_variant(store, engagement):
    recon_handoff()
    record(store, "/api/docs/2")
    record(store, "/api/docs/2", method="DELETE")
    coverage.refresh(store)
    store.record_angle(
        "www.acme.example/api/docs/{id}", "business-logic", "id-swap", "ruled_out",
        control=CONTROL,
    )
    assert len(coverage.tested(store, "business-logic")) == 2
    assert coverage.remaining(store, "business-logic") == ()


def test_a_host_only_angle_covers_the_root_surface_only(store, engagement):
    """"I tested the host" is not a claim about forty routes under it."""
    recon_handoff()
    record(store, "/")
    record(store, "/api/docs/2")
    coverage.refresh(store)
    store.record_angle("www.acme.example", "sqli", "quote-pair", "ruled_out", control=CONTROL)

    assert labels(coverage.tested(store, "sqli")) == {"GET www.acme.example/"}
    assert labels(coverage.remaining(store, "sqli")) == {
        "GET www.acme.example/api/docs/{id}"
    }


def test_an_angle_surface_that_does_not_parse_is_reported_not_dropped(store, engagement):
    recon_handoff()
    record(store, "/api/docs/2")
    coverage.refresh(store)
    store.record_angle("not a surface at all", "idor", "t", "ruled_out", control=CONTROL)

    gaps = coverage.handoff_gaps(store, "02-sweep")
    assert any("does not parse as a host" in line for line in gaps)
    assert coverage.tested(store, "idor") == ()


def test_the_v1_angle_vocabulary_still_credits_coverage(store, engagement):
    """`bb angle add ... negative` is stored as ruled_out, so it must count."""
    recon_handoff()
    record(store, "/api/docs/2")
    coverage.refresh(store)
    store.record_angle("www.acme.example/api/docs/{id}", "idor", "t", "negative")
    assert len(coverage.tested(store, "idor")) == 1


# ---------------------------------------------------------------------------
# an empty eligible set needs a recorded reason
# ---------------------------------------------------------------------------


def test_an_unexplained_empty_eligible_set_is_unrouted(store, engagement):
    recon_handoff()
    record(store, "/about")
    coverage.refresh(store)
    row = coverage.class_report(store, "file-upload")
    assert (row.eligible, row.status) == (0, STATUS_UNROUTED)

    gaps = coverage.handoff_gaps(store, "02-sweep")
    line = next(l for l in gaps if l.startswith("file-upload:"))
    assert "never routed rather than clean" in line
    assert "bb coverage reason file-upload" in line


def test_a_recorded_reason_accounts_for_an_empty_eligible_set(store, engagement):
    recon_handoff()
    record(store, "/about")
    coverage.refresh(store)
    coverage.record_reason(store, "file-upload", GOOD_REASON, phase="02-sweep")

    row = coverage.class_report(store, "file-upload")
    assert row.status == STATUS_EXPLAINED
    assert row.reason == GOOD_REASON
    assert row.accounted_for is True
    assert not [
        l for l in coverage.handoff_gaps(store, "02-sweep") if l.startswith("file-upload:")
    ]


@pytest.mark.parametrize("reason", ["", "   ", "n/a", "none", "no reason", "too short"])
def test_a_stub_reason_is_refused(store, engagement, reason):
    with pytest.raises(CoverageError) as exc:
        coverage.record_reason(store, "file-upload", reason)
    message = str(exc.value)
    assert "never routed" in message
    assert "bb coverage reason file-upload" in message


def test_both_problems_with_a_reason_come_back_together(store, engagement):
    """One round trip: a misspelled class and a stub reason are reported at once."""
    with pytest.raises(CoverageError) as exc:
        coverage.record_reason(store, "idorr", "n/a")
    message = str(exc.value)
    assert "not a known vulnerability class" in message
    assert "non-answer" in message


def test_a_reason_at_the_bar_is_accepted(store, engagement):
    reason = "x" * REASON_MIN_CHARS
    assert coverage.record_reason(store, "crypto", reason) == "crypto"
    assert coverage.reasons(store)["crypto"] == reason


def test_a_reason_for_an_unknown_class_is_refused(store, engagement):
    """Accounting for ground no phase is looking at is not accounting for anything."""
    with pytest.raises(CoverageError) as exc:
        coverage.record_reason(store, "idorr", GOOD_REASON)
    assert "not a known vulnerability class" in str(exc.value)
    assert "idor" in str(exc.value), "the refusal lists the vocabulary"


def test_a_reason_for_a_class_the_ledger_names_is_accepted(store, engagement):
    """An off-vocabulary class a phase actually routed is still a real class."""
    store.record_angle("www.acme.example/x", "graphql-batching", "t", "open_gap",
                       next_test="batch 100 aliases")
    assert coverage.record_reason(store, "graphql-batching", GOOD_REASON) == "graphql-batching"


def test_recording_a_reason_twice_updates_it(store, engagement):
    coverage.record_reason(store, "crypto", GOOD_REASON)
    second = "the only TLS endpoint is terminated by the CDN, which is out of scope here"
    coverage.record_reason(store, "crypto", second)
    assert coverage.reasons(store) == {"crypto": second}


def test_a_class_name_is_normalised_on_the_way_in(store, engagement):
    coverage.record_reason(store, "File_Upload", GOOD_REASON)
    assert "file-upload" in coverage.reasons(store)


# ---------------------------------------------------------------------------
# the report, the verdict, and the refusal to call anything clean
# ---------------------------------------------------------------------------


def test_the_table_has_a_row_per_class_with_the_rule_that_narrowed_it(store, engagement):
    recon_handoff()
    record(store, "/api/docs/2")
    coverage.refresh(store)
    report = coverage.report(store)

    assert len(report.classes) == len(CLASSES)
    assert coverage.TABLE_HEADERS[:5] == (
        "class", "eligible", "tested", "remaining", "status",
    )
    idor = next(r for r in report.table() if r[0] == "idor")
    assert idor[5] == "identifier-in-request"
    sqli = next(r for r in report.table() if r[0] == "sqli")
    assert sqli[5] == "-", "a class with no rule says so rather than inventing one"


def test_a_class_only_the_ledger_knows_gets_a_row(store, engagement):
    recon_handoff()
    record(store, "/graphql", method="POST")
    coverage.refresh(store)
    store.record_angle("www.acme.example/graphql", "graphql-batching", "t", "open_gap",
                       next_test="batch 100 aliases")
    report = coverage.report(store)
    row = next(r for r in report.classes if r.vuln_class == "graphql-batching")
    assert row.in_vocabulary is False
    assert row.status == STATUS_UNTESTED
    assert any("not in the class vocabulary" in r[6] for r in report.table())


def test_the_verdict_is_one_line_and_refuses_to_call_a_partial_sweep_clean(
    store, engagement
):
    recon_handoff()
    record(store, "/api/docs/2")
    coverage.refresh(store)
    store.record_angle("www.acme.example/api/docs/{id}", "idor", "t", "ruled_out",
                       control=CONTROL)
    report = coverage.report(store)

    assert "\n" not in report.verdict
    assert report.verdict.startswith("coverage:")
    assert coverage.verdict(store) == report.verdict, "bb status shows the same line"
    assert "not a clean sweep" in report.verdict
    assert "bb coverage" in report.verdict
    assert report.clean is False
    assert next(r for r in report.classes if r.vuln_class == "idor").status == STATUS_CLOSED


def test_a_genuinely_swept_engagement_reads_as_clean(store, engagement):
    """The positive case, so "not clean" is a measurement and not a constant."""
    recon_handoff()
    record(store, "/")
    coverage.refresh(store)
    close_broad_classes(store, "www.acme.example/")
    for cls, reason in (
        ("idor", "the only mapped surface is the root document, which carries no identifier"),
        ("auth-bypass", "the root document was only ever reachable without a credential"),
        ("csrf", "no mapped surface accepts a state-changing method at all"),
        ("race", "no mapped surface accepts a state-changing method at all"),
        ("file-upload", GOOD_REASON),
        ("open-redirect", "no mapped surface takes a query parameter of any kind"),
    ):
        coverage.record_reason(store, cls, reason)

    report = coverage.report(store)
    assert report.blockers == ()
    assert report.unsupported == ()
    assert [c.vuln_class for c in report.classes if not c.accounted_for] == []
    assert report.clean is True
    assert "nothing is left untested" in report.verdict
    assert coverage.handoff_gaps(store, "03-deepen") == []


def test_one_unexplained_class_is_enough_to_lose_clean(store, engagement):
    recon_handoff()
    record(store, "/")
    coverage.refresh(store)
    close_broad_classes(store, "www.acme.example/")
    for cls in ("idor", "auth-bypass", "csrf", "race", "file-upload"):
        coverage.record_reason(store, cls, GOOD_REASON)
    # open-redirect left unexplained
    report = coverage.report(store)
    assert report.clean is False
    assert [c.vuln_class for c in report.unrouted] == ["open-redirect"]


def test_class_report_refuses_a_misspelled_class(store, engagement):
    """"Nothing left" for a typo is exactly how a class ends up looking covered."""
    recon_handoff()
    record(store, "/api/docs/2")
    with pytest.raises(CoverageError) as exc:
        coverage.class_report(store, "idorr")
    assert "not a known vulnerability class" in str(exc.value)
    assert "bb coverage --class" in str(exc.value)


def test_class_report_gives_the_whole_remaining_list(store, engagement):
    recon_handoff()
    for n in range(5):
        record(store, f"/api/docs/{n}")
        record(store, f"/api/files/{n}")
    coverage.refresh(store)
    store.record_angle("www.acme.example/api/docs/{id}", "idor", "t", "ruled_out",
                       control=CONTROL)
    row = coverage.class_report(store, "idor")
    assert (row.eligible, row.tested, row.remaining, row.status) == (
        2, 1, 1, STATUS_PARTIAL,
    )
    assert labels(row.remaining_surfaces) == {"GET www.acme.example/api/files/{id}"}


# ---------------------------------------------------------------------------
# handoff gaps
# ---------------------------------------------------------------------------


def test_handoff_gaps_are_lines_naming_the_phase_and_the_fix(store, engagement):
    recon_handoff()
    record(store, "/api/docs/2")
    coverage.refresh(store)
    gaps = coverage.handoff_gaps(store, "02-sweep")

    assert isinstance(gaps, list) and all(isinstance(line, str) for line in gaps)
    assert gaps[0].startswith("coverage after 02-sweep:")
    assert any("bb angle add" in line for line in gaps)


def test_handoff_gaps_are_bounded(store, engagement):
    recon_handoff()
    for n in range(30):
        record(store, f"/api/thing{n}/5")
    coverage.refresh(store)
    gaps = coverage.handoff_gaps(store, "02-sweep")
    assert len(gaps) <= MAX_GAP_LINES + 1
    assert all(len(line) <= coverage.MAX_GAP_LINE_CHARS for line in gaps)
    if len(gaps) == MAX_GAP_LINES + 1:
        assert gaps[-1].startswith("...and")


def test_handoff_gaps_refuse_a_missing_phase(store, engagement):
    with pytest.raises(CoverageError) as exc:
        coverage.handoff_gaps(store, "  ")
    assert "bb handoff write <phase>" in str(exc.value)


def test_an_empty_engagement_says_the_inventory_is_empty_once(store, engagement):
    """Not twenty-three identical lines saying the same single thing."""
    recon_handoff()
    gaps = coverage.handoff_gaps(store, "00-recon")
    empty = [line for line in gaps if "the surface inventory is empty" in line]
    assert len(empty) == 1
    assert "bb req GET" in empty[0]


def test_the_gap_lines_lead_with_the_ledger_being_wrong(store, engagement):
    """A prompt loses the bottom of the list, so the worst problems go first."""
    recon_handoff(endpoints=[{"url": "https://www.acme.example/api/ghost/1"}])
    record(store, "/api/docs/2")
    coverage.refresh(store)
    store.record_angle("www.acme.example/api/ghost/{id}", "idor", "t", "ruled_out",
                       control=CONTROL)
    gaps = coverage.handoff_gaps(store, "02-sweep")
    assert "no request to that surface" in gaps[1], "unsupported claims before more work"
