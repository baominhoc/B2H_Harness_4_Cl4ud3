"""The mitmproxy addon: the third enforcement layer.

mitmproxy is not a harness dependency, so these tests load the addon the way
mitmproxy does — by path, deliberately NOT registered in sys.modules — against
a minimal stub of the mitmproxy API. That loading style is the point: it is
what broke `@dataclass` when the module carried
`from __future__ import annotations`, and it is invisible to a plain import.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

from bbh import paths
from bbh.store import Store

ADDON = Path(__file__).resolve().parent.parent / "bbh" / "proxy_addon.py"


# ---------------------------------------------------------------------------
# a minimal mitmproxy stand-in
# ---------------------------------------------------------------------------


def install_mitmproxy_stub(monkeypatch):
    """Enough of the mitmproxy API for the addon to import and run."""
    if "mitmproxy" in sys.modules:  # the real thing is installed; use it
        return

    mitmproxy = types.ModuleType("mitmproxy")
    http_mod = types.ModuleType("mitmproxy.http")
    addonmanager = types.ModuleType("mitmproxy.addonmanager")
    log_mod = types.ModuleType("mitmproxy.log")
    flow_mod = types.ModuleType("mitmproxy.flow")

    class HTTPFlow:
        pass

    class Error:
        # The literal mitmproxy 12.3.1 uses. The addon compares against the
        # class attribute rather than this string, so a rename upstream is an
        # ImportError there rather than a check that quietly stops matching.
        KILLED_MESSAGE = "Connection killed."

        def __init__(self, msg="", timestamp=None):
            self.msg = msg
            self.timestamp = timestamp

    flow_mod.Error = Error

    class Loader:
        def __init__(self):
            self.options = {}

        def add_option(self, name, typespec, default, help=""):
            self.options[name] = default

    http_mod.HTTPFlow = HTTPFlow
    addonmanager.Loader = Loader
    log_mod.ALERT = 45

    class Options:
        bbh_engagement = None
        bbh_phase = None

    ctx = types.SimpleNamespace(options=Options())
    mitmproxy.ctx = ctx
    mitmproxy.http = http_mod
    mitmproxy.flow = flow_mod

    for name, module in [
        ("mitmproxy", mitmproxy),
        ("mitmproxy.http", http_mod),
        ("mitmproxy.addonmanager", addonmanager),
        ("mitmproxy.log", log_mod),
        ("mitmproxy.flow", flow_mod),
    ]:
        monkeypatch.setitem(sys.modules, name, module)


def load_addon_like_mitmproxy():
    """Execute the addon by path WITHOUT registering it in sys.modules.

    This is exactly what mitmproxy's script loader does, and it is the only
    way the dataclass annotation bug reproduces.
    """
    spec = importlib.util.spec_from_file_location("bbh_proxy_addon_under_test", ADDON)
    module = importlib.util.module_from_spec(spec)
    # deliberately NOT: sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def addon_module(monkeypatch):
    install_mitmproxy_stub(monkeypatch)
    return load_addon_like_mitmproxy()


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------


def test_the_addon_loads_the_way_mitmproxy_loads_it(addon_module):
    """Regression: `from __future__ import annotations` here breaks @dataclass,
    because mitmproxy does not register the script in sys.modules."""
    assert hasattr(addon_module, "addons")
    assert addon_module.addons, "mitmdump needs a non-empty addons list"


def test_the_addon_does_not_need_requests(addon_module):
    """It runs under mitmproxy's interpreter, which has no harness venv."""
    source = ADDON.read_text()
    assert "import requests" not in source
    assert "\nimport requests" not in source


def test_it_shares_redaction_and_rate_limiting_with_the_client(addon_module):
    """Imported, not reimplemented, so proxy rows and client rows cannot drift."""
    from bbh import http as client

    assert addon_module.redact_headers is client.redact_headers
    assert addon_module.persist_body is client.persist_body
    assert addon_module.RateLimiter is client.RateLimiter


# ---------------------------------------------------------------------------
# binding
# ---------------------------------------------------------------------------


def test_binding_to_an_armed_engagement_enforces(addon_module, engagement):
    binding = addon_module.resolve(engagement)
    assert binding.enforcing
    assert binding.scope.engagement == engagement
    binding.store.close()


def test_no_engagement_means_nothing_is_enforced(addon_module, monkeypatch, tmp_path):
    monkeypatch.delenv("BBH_ENGAGEMENT", raising=False)
    binding = addon_module.resolve(None)
    assert not binding.enforcing
    assert "no engagement is selected" in binding.deny_reason


def test_an_uncompiled_engagement_fails_closed(addon_module, engagement):
    paths.lock_path(engagement).unlink()
    binding = addon_module.resolve(engagement)
    assert not binding.enforcing
    assert "no compiled scope" in binding.deny_reason


def test_an_expired_attestation_fails_closed(addon_module, engagement):
    from conftest import write_engagement

    write_engagement(engagement, hours=-1)
    binding = addon_module.resolve(engagement)
    assert not binding.enforcing
    assert "expired" in binding.deny_reason


def test_a_tampered_lock_fails_closed(addon_module, engagement):
    import json

    lock_file = paths.lock_path(engagement)
    data = json.loads(lock_file.read_text())
    data["in_scope"].append({"type": "domain", "value": "evil.example", "note": None})
    lock_file.write_text(json.dumps(data))
    binding = addon_module.resolve(engagement)
    assert not binding.enforcing
    assert "integrity check failed" in binding.deny_reason


# ---------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------


@pytest.fixture
def proxy(addon_module, engagement):
    instance = addon_module.addons[0]
    instance.binding = addon_module.resolve(engagement)
    instance.phase = "02-sweep"
    yield instance
    if instance.binding.store is not None:
        instance.binding.store.close()


def test_an_in_scope_url_is_allowed_through(proxy):
    assert proxy.deny_reason("https://www.acme.example/login", "GET") is None


def test_an_out_of_scope_url_is_refused(proxy):
    reason = proxy.deny_reason("https://evil.example/", "GET")
    assert reason and "not in the scope" in reason


def test_a_disallowed_method_is_refused(addon_module, engagement):
    """Excluded by scope.yaml, which the operator may widen -- so say where."""
    from conftest import write_engagement

    write_engagement(engagement, rules={"allowed_methods": ["GET"]})
    instance = addon_module.addons[0]
    instance.binding = addon_module.resolve(engagement)
    try:
        reason = instance.deny_reason("https://www.acme.example/x", "DELETE")
        assert reason
        assert "allowed_methods" in reason
        assert "bb scope compile" in reason, "this one the operator may change"
    finally:
        instance.binding.store.close()


def test_a_method_the_program_forbade_is_refused_and_not_offered_a_widening(
    addon_module, engagement
):
    """The clamp has to reach the CONDITION, not only the message.

    A program expresses "do not send DELETE" as
    `program_constraints.forbidden_tests`, which never lands in
    `scope.rules.allowed_methods` at all. The addon checked
    `scope.method_allowed()` -- the raw list -- so a DELETE the program had
    forbidden was forwarded to the target, against a program's written rule,
    while `bb scope compile` and the proxy banner both reported compliance.

    The refusal must also NOT offer `bb scope compile`: widening scope.yaml
    cannot lift a program constraint, and suggesting it invites the operator to
    break the rule they are testing under.
    """
    from conftest import write_engagement

    write_engagement(
        engagement,
        rules={"allowed_methods": ["GET", "DELETE"]},
        program_constraints={"forbidden_tests": ["delete"]},
    )
    instance = addon_module.addons[0]
    instance.binding = addon_module.resolve(engagement)
    try:
        assert instance.deny_reason("https://www.acme.example/x", "GET") is None
        reason = instance.deny_reason("https://www.acme.example/x", "DELETE")
        assert reason, "scope.yaml permits DELETE; only the program's constraint forbids it"
        assert "forbidden_tests" in reason
        assert "cannot widen" in reason
        assert "bb scope compile" not in reason
    finally:
        instance.binding.store.close()


def test_the_program_rate_limit_reaches_the_proxys_token_bucket(addon_module, engagement):
    """`bb req` honoured the program's 0.5 rps and every browser flow used 2.0."""
    from conftest import write_engagement

    write_engagement(engagement, rules={"max_rps": 2.0},
                     program_constraints={"max_rps": 0.5})
    instance = addon_module.addons[0]
    binding = addon_module.resolve(engagement)
    try:
        assert binding.rules["max_rps"] == 0.5
        assert binding.limiter.rps == 0.5, "the bucket itself, not just the reported figure"
    finally:
        if binding.store is not None:
            binding.store.close()


def test_a_program_constraint_this_build_cannot_apply_stops_the_proxy(addon_module, engagement):
    """A limit the harness cannot apply is a program rule it is about to break."""
    from conftest import write_engagement

    write_engagement(engagement, rules={}, program_constraints={"max_rps": 0.5})
    instance = addon_module.addons[0]
    binding = addon_module.resolve(engagement)
    try:
        instance.binding = binding

        def boom(scope):
            raise ValueError("max_concurrent_sessions is not implemented")

        addon_module.effective_rules_original = addon_module.effective_rules
        addon_module.effective_rules = boom
        try:
            broken = addon_module.resolve(engagement)
        finally:
            addon_module.effective_rules = addon_module.effective_rules_original
        assert not broken.enforcing
        assert "cannot apply" in (broken.deny_reason or "")
        instance.binding = broken
        assert instance.deny_reason("https://www.acme.example/x", "GET"), "nothing forwards"
        if broken.store is not None:
            broken.store.close()
    finally:
        if binding.store is not None:
            binding.store.close()


def test_connect_is_not_method_checked(proxy):
    """CONNECT is an instruction to the proxy, not a request to the target."""
    assert proxy.deny_reason("https://www.acme.example/", None) is None


def test_the_request_budget_is_enforced(addon_module, engagement):
    from conftest import write_engagement

    write_engagement(engagement, rules={"max_requests": 1})
    store = Store(paths.db_path(engagement))
    store.add_request(source="proxy", method="GET", url="https://a/", host="a")
    store.close()

    instance = addon_module.addons[0]
    instance.binding = addon_module.resolve(engagement)
    try:
        reason = instance.deny_reason("https://www.acme.example/", "GET")
        assert reason and "budget exhausted" in reason
    finally:
        instance.binding.store.close()


def test_an_unbound_proxy_refuses_everything(addon_module):
    instance = addon_module.BBHProxy()
    reason = instance.deny_reason("https://www.acme.example/", "GET")
    assert reason is not None, "a proxy that is not bound must not forward anything"


# ---------------------------------------------------------------------------
# attempts that left and were never answered
#
# Measured against real mitmproxy 12.3.1: a plain HTTP upstream failure arrives
# at the `error` hook with `flow.response is None`, while a failed CONNECT
# arrives at `http_connect_error` with a 502 mitmproxy generated itself. Before
# this path existed, neither was recorded, so `rules.max_requests` -- counted as
# COUNT(*) FROM requests by this addon and by bbh.http alike -- did not move for
# a host that answers nothing. That is the one traffic pattern most likely to
# annoy a program, and the circuit breaker misses it too: it trips on a status
# code and there is no status.
# ---------------------------------------------------------------------------


class _Headers(dict):
    def items(self):  # redact_headers iterates these
        return dict.items(self)


class _Request:
    def __init__(self, method="GET", url="https://www.acme.example/x", host=None):
        self.method = method
        self.pretty_url = url
        self.pretty_host = host or "www.acme.example"
        self.headers = _Headers({"user-agent": "bbh-test", "authorization": "Bearer hunter2"})
        self.timestamp_start = 1000.0

    def get_content(self, strict=False):
        return b""


class _Response:
    def __init__(self, status_code=502, body=b""):
        self.status_code = status_code
        self.headers = _Headers({"content-length": str(len(body))})
        self._body = body

    def get_content(self, strict=False):
        return self._body


class _Flow:
    def __init__(self, request=None, response=None, error=None):
        self.request = request if request is not None else _Request()
        self.response = response
        self.error = error
        self.metadata = {}


def _error(addon_module, msg, timestamp=1000.25):
    return sys.modules["mitmproxy.flow"].Error(msg, timestamp)


def requests_in(engagement):
    store = Store(paths.db_path(engagement))
    try:
        return [dict(r) for r in store.conn.execute("SELECT * FROM requests ORDER BY id")]
    finally:
        store.close()


def test_a_request_that_got_no_response_is_still_recorded(proxy, addon_module, engagement):
    flow = _Flow(error=_error(addon_module, "[Errno -2] Name or service not known"))
    proxy.error(flow)

    rows = requests_in(engagement)
    assert len(rows) == 1, "an attempt that left the machine has to be in the log"
    row = rows[0]
    assert row["status"] is None, "there was no response; NULL is not the same as a 0 or a 502"
    assert row["resp_headers"] is None
    assert "Name or service not known" in row["note"]
    assert row["source"] == "proxy"
    assert flow.metadata["bbh_request_id"] == row["id"]


def test_the_failed_attempt_counts_against_the_request_budget(proxy, addon_module, engagement):
    """The whole reason this path exists."""
    for _ in range(3):
        proxy.error(_Flow(error=_error(addon_module, "TimeoutError")))
    store = Store(paths.db_path(engagement))
    try:
        assert store.request_count() == 3
    finally:
        store.close()


def test_a_flow_the_addon_killed_is_never_recorded_as_sent(proxy, addon_module, engagement):
    """A blocked request must not be able to satisfy an evidence gate.

    One of the gates asserts that every URL in a reproduction appears in a
    request the harness really sent. A denied flow in `requests` would satisfy
    it without a packet having left, so the denial stays in the audit log only.
    """
    tagged = _Flow(error=_error(addon_module, "Connection killed."))
    tagged.metadata["bbh_killed"] = "out of scope"
    proxy.error(tagged)

    # Killed before `gate` could tag it: mitmproxy's own marker still catches it.
    untagged = _Flow(error=_error(addon_module, "Connection killed."))
    proxy.error(untagged)

    assert requests_in(engagement) == []


def test_a_failed_connect_records_null_not_mitmproxys_own_502(proxy, addon_module, engagement):
    """mitmproxy synthesises the 502. Recording it would invent a target reply."""
    body = (
        b"Cannot connect to www.acme.example:443: [Errno -2] Name or service not known "
        b"If you plan to redirect requests away from this server, consider setting "
        b"`connection_strategy` to `lazy` to suppress early connections."
    )
    flow = _Flow(
        request=_Request(method="CONNECT", url="www.acme.example:443"),
        response=_Response(502, body),
    )
    proxy.http_connect_error(flow)

    rows = requests_in(engagement)
    assert len(rows) == 1
    assert rows[0]["status"] is None, "a fabricated 502 must never be stored as a status"
    note = rows[0]["note"]
    assert "Cannot connect to www.acme.example:443" in note
    assert "connection_strategy" not in note, "mitmproxy's own advice is not engagement data"


def test_the_error_hook_leaves_a_flow_that_has_a_response_alone(proxy, engagement):
    """The response hook owns those, and recording twice would double the budget."""
    proxy.error(_Flow(response=_Response(200, b"ok")))
    assert requests_in(engagement) == []


def test_an_already_recorded_flow_is_not_recorded_again(proxy, addon_module, engagement):
    flow = _Flow(error=_error(addon_module, "TimeoutError"))
    flow.metadata["bbh_request_id"] = 41
    proxy.error(flow)
    assert requests_in(engagement) == []


def test_a_flow_with_no_request_does_not_brick_the_proxy(proxy, addon_module, engagement):
    """A client that drops mid-handshake is a non-event, not an outage.

    Nothing was sent, so there is nothing to record -- and it must not reach the
    fail-closed branch, which stops the proxy forwarding anything at all.
    """
    flow = _Flow(error=_error(addon_module, "connection closed early"))
    flow.request = None
    proxy.error(flow)

    assert requests_in(engagement) == []
    assert proxy.binding.deny_reason is None, "the proxy must still be forwarding"


def test_a_failure_that_cannot_be_recorded_stops_the_proxy(proxy, addon_module, monkeypatch):
    """Losing evidence quietly is the failure this harness exists to prevent."""
    def boom(**kw):
        raise RuntimeError("disk full")

    monkeypatch.setattr(proxy.binding.store, "add_request", boom)
    proxy.error(_Flow(error=_error(addon_module, "TimeoutError")))

    assert proxy.binding.deny_reason
    assert "could not record" in proxy.binding.deny_reason
    assert proxy.deny_reason("https://www.acme.example/", "GET"), "and nothing more forwards"


def test_credentials_are_redacted_out_of_a_failed_attempt(proxy, addon_module, engagement):
    proxy.error(_Flow(error=_error(addon_module, "TimeoutError")))
    recorded = requests_in(engagement)[0]["req_headers"]
    assert "hunter2" not in recorded, "a failed attempt is recorded, not exempted from redaction"
    assert "bbh-test" in recorded
