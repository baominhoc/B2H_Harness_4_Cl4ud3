"""The sanctioned HTTP client.

Nothing here touches the network: the pre-flight checks (steps 1-5) are
exercised directly, and the parts that need a response use a fake transport
standing in for `requests.Session`. The conftest `no_network` fixture is the
backstop.
"""

from __future__ import annotations

import json

import pytest

from bbh import paths
from bbh.http import (
    BODY_INLINE_MAX,
    BudgetExceeded,
    OutOfScope,
    RateLimiter,
    Session,
    TransportError,
    cli_req,
    flatten_headers,
    persist_body,
    redact_headers,
    redact_value,
    redirect_method,
    transcript,
)
from bbh.store import Store


# ---------------------------------------------------------------------------
# a fake transport
# ---------------------------------------------------------------------------


class FakeHeaders(dict):
    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == str(key).lower():
                return v
        return default


class FakePrepared:
    def __init__(self, method, url, headers=None, body=None):
        self.method, self.url = method, url
        self.headers = dict(headers or {})
        self.body = body


class FakeResponse:
    def __init__(self, status, url, headers=None, content=b"", reason="OK",
                 request=None):
        self.status_code = status
        self.url = url
        self.headers = FakeHeaders(headers or {})
        self.content = content
        self.reason = reason
        self.request = request or FakePrepared("GET", url)


class FakeTransport:
    """Replaces requests.Session. Serves scripted responses, records calls."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if not self._responses:
            raise AssertionError(f"unscripted request: {method} {url}")
        response = self._responses.pop(0)
        response.request = FakePrepared(
            method, url, kw.get("headers") or {}, kw.get("data")
        )
        if not response.url:
            response.url = url
        return response

    def close(self):
        pass


@pytest.fixture
def session(engagement, monkeypatch):
    """A Session whose transport is scripted; `session.serve([...])` installs it."""
    sess = Session(engagement, actor="attacker", phase="02-sweep")

    def serve(responses):
        transport = FakeTransport(responses)
        monkeypatch.setattr(sess, "_client", lambda: transport)
        return transport

    sess.serve = serve  # type: ignore[attr-defined]
    yield sess
    sess.close()


@pytest.fixture
def bodies_dir(tmp_path):
    """A directory of its own: tmp_path already holds the throwaway BBH_HOME."""
    return tmp_path / "bodies"


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------


def test_redact_value_is_stable_and_not_reversible():
    first = redact_value("Bearer sk-live-123")
    assert first == redact_value("Bearer sk-live-123"), "correlatable across requests"
    assert "sk-live-123" not in first
    assert first.startswith("<redacted sha256:")


@pytest.mark.parametrize(
    "header", ["Authorization", "Cookie", "Set-Cookie", "X-API-Key", "authorization", "COOKIE"]
)
def test_the_always_redacted_headers_never_reach_the_store(header):
    out = redact_headers({header: "secret-value"})
    assert "secret-value" not in json.dumps(out)
    assert out[header].startswith("<redacted")


def test_rules_redact_headers_extends_the_list():
    out = redact_headers({"X-Tenant-Token": "abc"}, extra=["x-tenant-token"])
    assert out["X-Tenant-Token"].startswith("<redacted")


def test_ordinary_headers_are_left_readable():
    out = redact_headers({"Content-Type": "application/json", "Authorization": "Bearer x"})
    assert out["Content-Type"] == "application/json"


def test_flatten_headers_joins_repeats():
    assert flatten_headers([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]) == {
        "Set-Cookie": "a=1, b=2"
    }


def test_flatten_headers_accepts_a_mapping_or_pairs():
    assert flatten_headers({"A": "1"}) == {"A": "1"}
    assert flatten_headers([("A", "1")]) == {"A": "1"}


# ---------------------------------------------------------------------------
# bodies
# ---------------------------------------------------------------------------


def test_a_small_body_is_kept_inline(bodies_dir):
    stored = persist_body(bodies_dir, b'{"ok":true}')
    assert stored.inline == {"text": '{"ok":true}'}
    assert stored.path is None
    assert not bodies_dir.exists() or not list(bodies_dir.iterdir())


def test_a_large_body_spills_to_a_content_addressed_file(bodies_dir):
    data = b"A" * (BODY_INLINE_MAX + 1)
    stored = persist_body(bodies_dir, data)
    assert stored.path is not None
    assert stored.inline is None
    assert stored.sha256 in stored.path
    assert open(stored.path, "rb").read() == data


def test_an_identical_large_body_is_stored_once(bodies_dir):
    data = b"B" * (BODY_INLINE_MAX + 1)
    first = persist_body(bodies_dir, data)
    second = persist_body(bodies_dir, data)
    assert first.path == second.path
    assert len(list(bodies_dir.iterdir())) == 1


def test_a_non_utf8_body_is_base64_encoded_inline(bodies_dir):
    stored = persist_body(bodies_dir, b"\xff\xfe\x00binary")
    assert "base64" in stored.inline


def test_an_absent_body_is_distinguished_from_an_empty_one(bodies_dir):
    assert persist_body(bodies_dir, None).sha256 is None
    assert persist_body(bodies_dir, b"").sha256 is not None


# ---------------------------------------------------------------------------
# the rate limiter
# ---------------------------------------------------------------------------


def test_the_first_request_to_a_host_is_not_throttled(tmp_path):
    limiter = RateLimiter(tmp_path / "rate.json", rps=2.0)
    assert limiter.reserve("a.example", now=1000.0) == 0.0


def test_a_burst_beyond_the_bucket_is_made_to_wait(tmp_path):
    limiter = RateLimiter(tmp_path / "rate.json", rps=2.0)
    waits = [limiter.reserve("a.example", now=1000.0) for _ in range(4)]
    assert waits[0] == 0.0
    assert waits[-1] > 0, "a burst at a 2 rps cap must queue"
    assert waits == sorted(waits), "each further request waits at least as long"


def test_the_bucket_refills_over_time(tmp_path):
    limiter = RateLimiter(tmp_path / "rate.json", rps=2.0)
    for _ in range(4):
        limiter.reserve("a.example", now=1000.0)
    assert limiter.reserve("a.example", now=1100.0) == 0.0


def test_hosts_are_throttled_independently(tmp_path):
    limiter = RateLimiter(tmp_path / "rate.json", rps=1.0)
    limiter.reserve("a.example", now=1000.0)
    limiter.reserve("a.example", now=1000.0)
    assert limiter.reserve("b.example", now=1000.0) == 0.0


def test_the_bucket_survives_a_process_restart(tmp_path):
    path = tmp_path / "rate.json"
    first = RateLimiter(path, rps=1.0)
    for _ in range(3):
        first.reserve("a.example", now=1000.0)
    second = RateLimiter(path, rps=1.0)
    assert second.reserve("a.example", now=1000.0) > 0, "state must outlive the process"


def test_a_corrupt_bucket_file_resets_rather_than_stopping_the_hunt(tmp_path):
    path = tmp_path / "rate.json"
    path.write_text("{{{ not json")
    assert RateLimiter(path, rps=2.0).reserve("a.example", now=1000.0) == 0.0


# ---------------------------------------------------------------------------
# pre-flight checks (no network involved)
# ---------------------------------------------------------------------------


def test_no_engagement_refuses_before_any_request(monkeypatch, tmp_path):
    monkeypatch.delenv("BBH_ENGAGEMENT", raising=False)
    with Session() as sess:
        with pytest.raises(OutOfScope, match="no engagement"):
            sess.get("https://www.acme.example/")


def test_an_out_of_scope_url_is_refused(session):
    with pytest.raises(OutOfScope, match="not in the scope"):
        session.get("https://evil.example/")


def test_a_disallowed_method_is_refused(engagement, monkeypatch):
    from conftest import write_engagement

    write_engagement(engagement, rules={"allowed_methods": ["GET"]})
    with Session(engagement) as sess:
        with pytest.raises(OutOfScope, match="method DELETE is not allowed"):
            sess.delete("https://www.acme.example/x")


def test_an_expired_attestation_refuses_every_request(engagement):
    from conftest import write_engagement

    write_engagement(engagement, hours=-1)
    with Session(engagement) as sess:
        with pytest.raises(OutOfScope, match="expired"):
            sess.get("https://www.acme.example/")


def test_a_non_http_scheme_is_refused(engagement):
    from conftest import write_engagement

    write_engagement(engagement, in_scope=["*.acme.example"])
    with Session(engagement) as sess:
        with pytest.raises(OutOfScope):
            sess.get("ftp://www.acme.example/x")


def test_the_request_budget_is_enforced(engagement):
    from conftest import write_engagement

    write_engagement(engagement, rules={"max_requests": 2})
    store = Store(paths.db_path(engagement))
    for _ in range(2):
        store.add_request(source="client", method="GET", url="https://a/", host="a")
    with Session(engagement, store=store) as sess:
        with pytest.raises(BudgetExceeded, match="budget exhausted"):
            sess.get("https://www.acme.example/")
    store.close()


def test_a_denial_is_written_to_the_audit_log(session):
    with pytest.raises(OutOfScope):
        session.get("https://evil.example/")
    records = [json.loads(l) for l in paths.AUDIT_LOG.read_text().splitlines()]
    assert any(r["tool"] == "bbh.http" and r["allowed"] is False for r in records)


def test_disarming_takes_effect_without_a_new_session(session, engagement):
    """The lock is re-stat'ed per request, so `bb disarm` lands immediately."""
    from conftest import write_engagement

    session.serve([FakeResponse(200, "https://www.acme.example/a")])
    session.get("https://www.acme.example/a")

    write_engagement(engagement, hours=-1)
    with pytest.raises(OutOfScope, match="expired"):
        session.get("https://www.acme.example/b")


# ---------------------------------------------------------------------------
# recording
# ---------------------------------------------------------------------------


def test_a_response_is_recorded_and_the_id_attached(session):
    session.serve([FakeResponse(200, "https://www.acme.example/api", content=b'{"a":1}')])
    response = session.get("https://www.acme.example/api")
    assert response.bbh_request_id > 0

    row = session.store.conn.execute(
        "SELECT * FROM requests WHERE id=?", (response.bbh_request_id,)
    ).fetchone()
    assert row["source"] == "client"
    assert row["actor"] == "attacker"
    assert row["phase"] == "02-sweep"
    assert row["host"] == "www.acme.example"
    assert row["path"] == "/api"
    assert row["status"] == 200


def test_credentials_are_redacted_in_the_stored_row(session):
    session.serve([
        FakeResponse(200, "https://www.acme.example/", headers={"Set-Cookie": "sid=secret"})
    ])
    response = session.get(
        "https://www.acme.example/", headers={"Authorization": "Bearer live-token"}
    )
    row = session.store.conn.execute(
        "SELECT req_headers, resp_headers FROM requests WHERE id=?",
        (response.bbh_request_id,),
    ).fetchone()
    assert "live-token" not in row["req_headers"]
    assert "secret" not in row["resp_headers"]
    assert "<redacted" in row["req_headers"]


def test_a_small_response_body_lands_inline_in_the_note(session):
    session.serve([FakeResponse(200, "https://www.acme.example/", content=b'{"ok":1}')])
    response = session.get("https://www.acme.example/")
    row = session.store.conn.execute(
        "SELECT note FROM requests WHERE id=?", (response.bbh_request_id,)
    ).fetchone()
    assert json.loads(row["note"])["resp_body"] == {"text": '{"ok":1}'}


def test_a_large_response_body_lands_under_raw_bodies(session, engagement):
    big = b"X" * (BODY_INLINE_MAX + 10)
    session.serve([FakeResponse(200, "https://www.acme.example/", content=big)])
    response = session.get("https://www.acme.example/")
    row = session.store.conn.execute(
        "SELECT resp_body_path, resp_body_sha256 FROM requests WHERE id=?",
        (response.bbh_request_id,),
    ).fetchone()
    assert row["resp_body_path"].startswith(
        str(paths.engagement_dir(engagement) / "raw" / "bodies")
    )
    assert open(row["resp_body_path"], "rb").read() == big


def test_a_transport_failure_is_still_recorded(session):
    class Exploding:
        def request(self, *a, **kw):
            raise OSError("connection reset")

        def close(self):
            pass

    session._client = lambda: Exploding()
    with pytest.raises(TransportError, match="connection reset"):
        session.get("https://www.acme.example/")
    row = session.store.conn.execute("SELECT note, status FROM requests").fetchone()
    assert row["status"] is None
    assert "connection reset" in json.loads(row["note"])["error"]


# ---------------------------------------------------------------------------
# redirects
# ---------------------------------------------------------------------------


def test_an_in_scope_redirect_is_followed_one_hop_at_a_time(session):
    transport = session.serve([
        FakeResponse(302, "https://www.acme.example/a",
                     headers={"Location": "https://api.acme.example/b"}),
        FakeResponse(200, "https://api.acme.example/b", content=b"landed"),
    ])
    response = session.get("https://www.acme.example/a")
    assert response.status_code == 200
    assert [c[1] for c in transport.calls] == [
        "https://www.acme.example/a", "https://api.acme.example/b",
    ]
    assert len(response.bbh_request_ids) == 2, "every hop that left gets its own row"


def test_a_redirect_to_an_out_of_scope_host_is_not_followed(session):
    transport = session.serve([
        FakeResponse(302, "https://www.acme.example/a",
                     headers={"Location": "https://evil.example/steal"}),
    ])
    response = session.get("https://www.acme.example/a")
    assert response.status_code == 302, "the 3xx is returned, not followed"
    assert len(transport.calls) == 1
    assert "not in the scope" in response.bbh_stopped


def test_the_refused_hop_is_recorded_so_it_can_be_cited(session):
    session.serve([
        FakeResponse(302, "https://www.acme.example/a",
                     headers={"Location": "https://evil.example/steal"}),
    ])
    response = session.get("https://www.acme.example/a")
    note = json.loads(
        session.store.conn.execute(
            "SELECT note FROM requests WHERE id=?", (response.bbh_request_id,)
        ).fetchone()["note"]
    )
    assert note["redirect"]["followed"] is False
    assert note["redirect"]["to"] == "https://evil.example/steal"


def test_credentials_are_dropped_on_a_cross_host_hop(session):
    transport = session.serve([
        FakeResponse(302, "https://www.acme.example/a",
                     headers={"Location": "https://api.acme.example/b"}),
        FakeResponse(200, "https://api.acme.example/b"),
    ])
    session.get(
        "https://www.acme.example/a",
        headers={"Authorization": "Bearer live", "Accept": "application/json"},
    )
    second_hop_headers = transport.calls[1][2]["headers"]
    assert "Authorization" not in second_hop_headers
    assert second_hop_headers["Accept"] == "application/json"


def test_no_follow_returns_the_three_x_x(session):
    transport = session.serve([
        FakeResponse(302, "https://www.acme.example/a",
                     headers={"Location": "https://api.acme.example/b"}),
    ])
    response = session.get("https://www.acme.example/a", allow_redirects=False)
    assert response.status_code == 302
    assert len(transport.calls) == 1


def test_a_redirect_chain_is_bounded(session):
    hops = [
        FakeResponse(302, f"https://www.acme.example/{i}",
                     headers={"Location": f"https://www.acme.example/{i + 1}"})
        for i in range(40)
    ]
    transport = session.serve(hops)
    response = session.get("https://www.acme.example/0")
    assert len(transport.calls) <= 12
    assert "exceeded" in (response.bbh_stopped or "")


@pytest.mark.parametrize(
    "method,status,expected",
    [("POST", 301, "GET"), ("POST", 302, "GET"), ("POST", 303, "GET"),
     ("POST", 307, "POST"), ("POST", 308, "POST"), ("GET", 302, "GET")],
)
def test_redirect_method_rewriting_matches_browsers(method, status, expected):
    assert redirect_method(method, status) == expected


# ---------------------------------------------------------------------------
# transcripts
# ---------------------------------------------------------------------------


def test_a_saved_transcript_is_redacted(session):
    session.serve([
        FakeResponse(200, "https://www.acme.example/api",
                     headers={"Set-Cookie": "sid=supersecret"}, content=b"body")
    ])
    response = session.get(
        "https://www.acme.example/api", headers={"Authorization": "Bearer live-token"}
    )
    text = transcript(response)
    assert "live-token" not in text
    assert "supersecret" not in text
    assert "<redacted" in text
    assert "GET /api HTTP/1.1" in text


# ---------------------------------------------------------------------------
# bb req
# ---------------------------------------------------------------------------


def test_cli_req_returns_two_for_an_out_of_scope_target(engagement, capsys):
    assert cli_req(["GET", "https://evil.example/"]) == 2
    assert "not in the scope" in capsys.readouterr().err


def test_cli_req_returns_two_for_a_disallowed_method(engagement, capsys):
    from conftest import write_engagement

    write_engagement(engagement, rules={"allowed_methods": ["GET"]})
    assert cli_req(["DELETE", "https://www.acme.example/x"]) == 2


def test_cli_req_refuses_a_scheme_less_url(engagement, capsys):
    """http and https are different attack surfaces; no silent upgrade."""
    assert cli_req(["GET", "www.acme.example/x"]) == 1
    assert "has no scheme" in capsys.readouterr().err


def test_cli_req_refuses_a_malformed_header(engagement, capsys):
    assert cli_req(["GET", "https://www.acme.example/", "-H", "nocolon"]) == 1
    assert "is not 'Name: value'" in capsys.readouterr().err


def test_cli_req_refuses_a_path_as_save_as(engagement, capsys):
    code = cli_req(
        ["GET", "https://www.acme.example/", "--save-as", "../../etc/passwd"]
    )
    assert code == 1
    assert "must be a plain name" in capsys.readouterr().err


def test_cli_req_returns_three_when_the_budget_is_gone(engagement, capsys):
    from conftest import write_engagement

    write_engagement(engagement, rules={"max_requests": 1})
    store = Store(paths.db_path(engagement))
    store.add_request(source="client", method="GET", url="https://a/", host="a")
    store.close()
    assert cli_req(["GET", "https://www.acme.example/"]) == 3
