"""mitmproxy addon: scope enforcement and capture for browser traffic.

The PreToolUse guard sees shell commands and bbh.http sees harness requests,
but a browser the agent drives -- headless Chrome, Playwright, a manual walk of
an app -- goes around both. This addon is the third enforcement layer: every
flow is scope-checked before it is forwarded, throttled against the same token
bucket the client uses, and recorded as an ordinary request row, so browser
traffic can be cited as evidence like any other request.

It runs under mitmproxy's own interpreter, not the harness venv, so it imports
nothing beyond the standard library, mitmproxy, and harness modules that are
import-safe without `requests` or PyYAML. sys.path is bootstrapped from
__file__ below because `bbh` is not installed in that interpreter.

Run it:

    mitmdump -s ~/claude-harness/bbh/proxy_addon.py \\
        --set bbh_engagement=<engagement> --set bbh_phase=02-sweep \\
        --listen-host 127.0.0.1 --listen-port 8080 \\
        --set confdir=~/claude-harness/engagements/<engagement>/.state/mitmproxy

Then point the browser or tool at it:

    export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080
    # TLS interception needs <confdir>/mitmproxy-ca-cert.pem trusted by the client.

Omitting --set bbh_engagement falls back to the engagement selected with
`bb use`. The addon fails closed: if the engagement is missing, uncompiled,
unarmed or unrecordable, every flow is killed rather than forwarded
unenforced. The lock is re-stat'ed per flow, so `bb disarm` and a recompiled
scope take effect without restarting the proxy.
"""

# No `from __future__ import annotations` here, unlike the rest of the package:
# mitmproxy executes an addon script without registering it in sys.modules, and
# @dataclass resolves string annotations through sys.modules[cls.__module__],
# which is then None. Evaluating annotations eagerly sidesteps that; every name
# used in one is imported or defined above its first use.

import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from mitmproxy import ctx, http
from mitmproxy.addonmanager import Loader
from mitmproxy.flow import Error as MitmError
from mitmproxy.log import ALERT

# A CONNECT failure's reason comes out of a response body, so it is bounded
# before it goes anywhere near the request log.
CONNECT_REASON_CAP = 300

# mitmproxy loads this file by path, so it is not part of the `bbh` package and
# relative imports do not resolve. Put the repo root on sys.path first.
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from bbh import paths  # noqa: E402  (everything below needs the bootstrap above)
from bbh.scope import Scope, ScopeError  # noqa: E402
from bbh.store import Store, utcnow  # noqa: E402

# Redaction, body spilling and the rate limiter are imported rather than
# reimplemented so proxy rows and client rows cannot drift apart. bbh.http
# imports `requests` on demand for exactly this reason; if that ever changes
# the addon fails to load, which leaves no traffic unenforced.
from bbh.http import (  # noqa: E402
    RateLimiter, effective_rules, persist_body, redact_headers,
)

logger = logging.getLogger("bbh.proxy")

# A throttle longer than this is worth telling the agent about; shorter waits
# are the normal cost of the engagement's rate limit and would only be noise.
THROTTLE_LOG_SECONDS = 1.0


@dataclass
class Binding:
    """What the addon enforces, or the reason it cannot enforce anything."""

    engagement: Optional[str] = None
    scope: Optional[Scope] = None
    store: Optional[Store] = None
    limiter: Optional[RateLimiter] = None
    lock_stamp: Optional[tuple] = None  # (mtime_ns, size) of the lock when loaded
    deny_reason: Optional[str] = None
    # `scope.rules` with the program's own `program_constraints` applied, which
    # is the only form anything here may enforce against. Read the comment on
    # `effective_rules` in resolve() for why the raw rules are not good enough.
    rules: dict = field(default_factory=dict)

    @property
    def enforcing(self) -> bool:
        return self.scope is not None and self.store is not None and self.deny_reason is None


def _was_killed(flow: http.HTTPFlow) -> bool:
    """Did this flow die because the addon killed it, rather than upstream?

    Belt and braces alongside the `bbh_killed` metadata `gate` sets: a flow
    killed before it could be tagged must still not be recorded as an attempt
    that left the machine. The literal is mitmproxy's own, read from the class
    rather than copied, so a rename breaks the import instead of silently
    turning this into `return False`.
    """
    message = getattr(flow.error, "msg", None)
    return bool(message) and message == MitmError.KILLED_MESSAGE


def _connect_error_reason(flow: http.HTTPFlow) -> Optional[str]:
    """The real reason a CONNECT failed, out of the 502 mitmproxy generated.

    mitmproxy's body reads `Cannot connect to host:443: <errno>` and then
    appends advice about its own `connection_strategy` setting, which is noise
    in an engagement's request log. The first sentence is the part that says
    what happened.
    """
    response = flow.response
    if response is None:
        return getattr(flow.error, "msg", None)
    try:
        body = (response.get_content(strict=False) or b"").decode("utf-8", "replace")
    except Exception:  # a body that cannot be read is not worth failing over
        body = ""
    text = " ".join(body.split())
    text = text.split("If you plan to", 1)[0].strip()
    if text:
        return text[:CONNECT_REASON_CAP]
    return f"CONNECT failed and the proxy reported {response.status_code}"


def resolve_name(option: Optional[str]) -> Optional[str]:
    """The engagement this proxy serves: the option, else the selected one."""
    return (option or "").strip() or paths.active_engagement()


def lock_stamp(name: Optional[str]) -> Optional[tuple]:
    """Cheap change detector for the scope lock. None when there is no lock."""
    if not name:
        return None
    try:
        info = paths.lock_path(name).stat()
    except OSError:
        return None
    return (info.st_mtime_ns, info.st_size)


def resolve(option: Optional[str]) -> Binding:
    """Load the engagement's scope and store. Never raises; returns the reason."""
    name = resolve_name(option)
    if not name:
        return Binding(
            deny_reason=(
                "no engagement is selected, so no target is authorized. Restart the proxy "
                "with --set bbh_engagement=<name>, or select one: bb use <name>"
            )
        )

    # Stamped before the read: a lock rewritten mid-load is reloaded next flow.
    stamp = lock_stamp(name)
    lock = paths.lock_path(name)
    if stamp is None:
        return Binding(
            engagement=name,
            deny_reason=(
                f"engagement {name!r} has no compiled scope at {lock}. "
                f"Run: bb scope compile {name}"
            ),
        )
    try:
        scope = Scope.from_lock_file(lock)
    except ScopeError as exc:
        return Binding(engagement=name, lock_stamp=stamp, deny_reason=str(exc))
    except (OSError, ValueError) as exc:
        return Binding(
            engagement=name,
            lock_stamp=stamp,
            deny_reason=(
                f"engagement {name!r} has an unreadable scope lock ({exc}). "
                f"Run: bb scope compile {name}"
            ),
        )

    problem = scope.authorization_error()
    if problem:
        # scope.py writes "<engagement>" where it has no name to hand; fill it
        # in, because the agent reading this is expected to run the command.
        return Binding(
            engagement=name,
            scope=scope,
            lock_stamp=stamp,
            deny_reason=problem.replace("<engagement>", name),
        )

    try:
        store = Store(paths.db_path(name))
    except Exception as exc:  # sqlite fails for permissions, disk, corruption
        return Binding(
            engagement=name,
            scope=scope,
            lock_stamp=stamp,
            deny_reason=(
                f"cannot open the engagement database {paths.db_path(name)} "
                f"({type(exc).__name__}: {exc}); traffic could not be recorded. "
                f"Run: bb status {name}"
            ),
        )
    # The program's own limits, not scope.yaml's. `effective_rules` clamps
    # `scope.rules` with `program_constraints`, and it can only ever tighten.
    # The addon read the raw rules until now, so a program that mandated
    # `max_rps: 0.5` got 0.5 from `bb req` and 2.0 from every browser flow --
    # a rate limit broken against the program while both layers reported
    # themselves compliant. It raises rather than guess, including on a
    # constraint key it does not implement, so a limit the harness cannot apply
    # stops the proxy instead of being skipped: that is a program rule it would
    # otherwise be about to break.
    try:
        rules = effective_rules(scope)
    except Exception as exc:
        return Binding(
            engagement=name,
            scope=scope,
            store=store,
            lock_stamp=stamp,
            deny_reason=(
                f"engagement {name!r} declares a program constraint this build cannot apply "
                f"({type(exc).__name__}: {exc}), so no flow may be forwarded -- forwarding "
                f"one would break a limit the program set. "
                f"Fix it in {paths.scope_path(name)} then run: bb scope compile {name}"
            ),
        )

    # `paths.rate_path`, not a path built here: `bbh.http.Session` moved its
    # bucket out of the engagement root this release, and a second bucket next
    # to the old location would mean the client and the proxy each hold the
    # full rate -- an engagement driving both would emit 2x max_rps at the
    # target while both layers reported themselves inside the limit.
    limiter = RateLimiter(paths.rate_path(name), float(rules.get("max_rps", 2.0)))
    return Binding(
        engagement=name, scope=scope, store=store, limiter=limiter,
        lock_stamp=stamp, rules=rules,
    )


class BBHProxy:
    """Scope gate and recorder for every flow through the proxy."""

    def __init__(self) -> None:
        self.binding = Binding(deny_reason="the proxy addon has not finished starting")
        self.phase: Optional[str] = None
        self.started = False

    # -- lifecycle --------------------------------------------------------

    def load(self, loader: Loader) -> None:
        loader.add_option(
            name="bbh_engagement",
            typespec=Optional[str],
            default=None,
            help=(
                "Harness engagement whose scope this proxy enforces. "
                "Defaults to the engagement selected with `bb use`."
            ),
        )
        loader.add_option(
            name="bbh_phase",
            typespec=Optional[str],
            default=None,
            help="Hunt phase key recorded on every captured request, e.g. 02-sweep.",
        )

    def running(self) -> None:
        self.started = True
        self.bind()

    def configure(self, updated: set) -> None:
        # Re-resolve when an option is changed from the console mid-run, so the
        # banner and the enforced scope can never disagree.
        if self.started and ("bbh_engagement" in updated or "bbh_phase" in updated):
            self.bind()

    def done(self) -> None:
        if self.binding.store is not None:
            self.binding.store.close()

    def bind(self) -> None:
        previous = self.binding.store
        self.binding = resolve(ctx.options.bbh_engagement)
        self.phase = ctx.options.bbh_phase
        if previous is not None and previous is not self.binding.store:
            previous.close()
        self.announce()

    def refresh(self) -> None:
        """Pick up `bb arm`, `bb disarm` and a recompiled scope without a restart."""
        name = resolve_name(ctx.options.bbh_engagement)
        if (name, lock_stamp(name)) != (self.binding.engagement, self.binding.lock_stamp):
            self.bind()

    def announce(self) -> None:
        binding = self.binding
        if not binding.enforcing:
            logger.log(ALERT, "bbh proxy: NOT ENFORCING -- %s", binding.deny_reason)
            logger.log(
                ALERT,
                "bbh proxy: every flow is killed until that is fixed; no traffic "
                "passes through this proxy unenforced.",
            )
            return

        scope = binding.scope
        rules = binding.rules
        logger.log(
            ALERT,
            "bbh proxy: ENFORCING engagement %r%s",
            binding.engagement,
            " (phase %s)" % self.phase if self.phase else "",
        )
        logger.log(
            ALERT,
            "bbh proxy:   scope  %d in-scope rule(s), %d exclusion(s) from %s",
            len(scope.in_scope),
            len(scope.out_of_scope),
            paths.lock_path(binding.engagement),
        )
        logger.log(
            ALERT,
            "bbh proxy:   limits %s requests used of %s, %s req/s, methods %s",
            binding.store.request_count(),
            rules.get("max_requests"),
            rules.get("max_rps"),
            ",".join(rules.get("allowed_methods", [])),
        )
        logger.log(ALERT, "bbh proxy:   store  %s", binding.store.path)

    # -- enforcement ------------------------------------------------------

    async def http_connect(self, flow: http.HTTPFlow) -> None:
        """Gate the CONNECT tunnel, so an out-of-scope host is never dialled.

        The method is not checked here: CONNECT is an instruction to the proxy,
        not a request to the target, and it is not one a program's rules list.
        """
        self.gate(flow, check_method=False)

    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.response or flow.error or not flow.live:
            return
        if self.gate(flow, check_method=True):
            return
        await self.throttle(flow)

    def gate(self, flow: http.HTTPFlow, check_method: bool) -> bool:
        """Kill the flow if it may not be forwarded. True when it was killed."""
        self.refresh()
        reason = self.deny_reason(
            flow.request.pretty_url, flow.request.method if check_method else None
        )
        if reason is None:
            return False
        logger.error(
            "bbh proxy: BLOCKED %s %s -- %s",
            flow.request.method,
            flow.request.pretty_url,
            reason,
        )
        self.audit(flow, reason)
        flow.metadata["bbh_killed"] = reason
        # Killed, not answered with a synthetic 403: a fabricated response could
        # be mistaken for the target's own and end up cited as evidence.
        if flow.killable:
            flow.kill()
        return True

    def deny_reason(self, url: str, method: Optional[str]) -> Optional[str]:
        """Why this flow must not be forwarded, or None if it may be."""
        binding = self.binding
        if not binding.enforcing:
            return binding.deny_reason or "the proxy is not bound to an armed engagement"
        scope = binding.scope

        # decide() re-checks the attestation every call, so an expiry part way
        # through a session starts denying on its own.
        decision = scope.decide(url)
        if not decision.allowed:
            return decision.reason

        # Against the CLAMPED list, not `scope.method_allowed`, which reads
        # `scope.rules` directly: a program that forbids DELETE expresses it as
        # `program_constraints.forbidden_tests`, which never reaches
        # `scope.rules` at all. Checking the raw list there and printing the
        # clamped one here would let the method through while the refusal text
        # claimed it had not been.
        allowed = [str(m).upper() for m in binding.rules.get("allowed_methods", [])]
        if method is not None and method.upper() not in allowed:
            # Which of the two restrictions stopped it decides what the operator
            # may do about it, so the refusal says. `rules.allowed_methods` is
            # theirs to widen; a method the program itself forbade is not, and
            # offering `bb scope compile` for that one would be inviting them to
            # break the rule they are testing under.
            in_scope_yaml = method.upper() in [
                str(m).upper() for m in scope.rules.get("allowed_methods", [])
            ]
            where = (
                f"the program's own program_constraints.forbidden_tests, which scope.yaml "
                f"cannot widen -- the program forbade it"
                if in_scope_yaml
                else f"rules.allowed_methods in {paths.scope_path(scope.engagement)}; if the "
                f"program's rules permit it, add it there then run: "
                f"bb scope compile {scope.engagement}"
            )
            return (
                f"{method} is not among the methods this engagement may send "
                f"({', '.join(allowed) or 'none'}) for engagement {scope.engagement!r}. "
                f"It is excluded by {where}"
            )

        limit = int(binding.rules.get("max_requests", 20000))
        made = binding.store.request_count()
        if made >= limit:
            return (
                f"request budget exhausted for engagement {scope.engagement!r}: "
                f"{made} requests recorded, limit is {limit}. "
                f"Raise rules.max_requests in {paths.scope_path(scope.engagement)} then run: "
                f"bb scope compile {scope.engagement}"
            )
        return None

    async def throttle(self, flow: http.HTTPFlow) -> None:
        """Queue behind the same per-host token bucket bbh.http uses.

        The sleep is awaited rather than blocking, so one slow host does not
        stall the flows mitmproxy is serving for the others.
        """
        binding = self.binding
        if binding.limiter is None:
            return
        host = flow.request.pretty_host
        try:
            wait = binding.limiter.reserve(host)
        except OSError as exc:
            logger.warning("bbh proxy: rate limiter unavailable (%s); not throttling", exc)
            return
        if wait <= 0:
            return
        if wait >= THROTTLE_LOG_SECONDS:
            logger.info(
                "bbh proxy: holding %s for %.1fs to stay inside %s req/s",
                host,
                wait,
                binding.rules.get("max_rps"),
            )
        # mitmproxy timestamps the request before this hook runs, so the wait is
        # subtracted later: duration_ms must be the target's latency, not ours.
        flow.metadata["bbh_waited_ms"] = int(wait * 1000)
        await asyncio.sleep(wait)

    # -- capture ----------------------------------------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        binding = self.binding
        if not binding.enforcing or flow.response is None:
            return
        if flow.metadata.get("bbh_request_id"):
            return  # a replayed flow can reach this hook twice

        try:
            flow.metadata["bbh_request_id"] = self.record(flow)
        except Exception as exc:
            # Losing evidence quietly is the one failure this harness exists to
            # prevent, so stop forwarding anything until it is fixed.
            reason = (
                f"the proxy could not record a request ({type(exc).__name__}: {exc}); "
                f"further flows are blocked rather than run unrecorded. Check "
                f"{paths.db_path(binding.engagement)} and restart: bb proxy start"
            )
            logger.error("bbh proxy: %s", reason)
            binding.deny_reason = reason

    def error(self, flow: http.HTTPFlow) -> None:
        """Record an attempt that left the machine and was never answered.

        Without this the only row ever written is one with a response, and a
        request the target blackholed is a request that happened and that
        nothing can show. Two consequences, both measured:

        * `rules.max_requests` is counted as `COUNT(*) FROM requests` by this
          addon and by `bbh.http` alike, so an endpoint that answers nothing --
          a WAF that drops instead of refusing, a tarpit, a host that stops
          responding after N requests -- can be hammered indefinitely without
          the program's authorized request budget moving. The circuit breaker
          misses the same case, because it trips on a status code and there is
          no status.
        * The operator cannot say what their agent did overnight. "We never
          sent that" has to be answerable from the log, not from the absence of
          a row that was never written.

        `bbh.http.Session` already records its failures this way and names the
        row id in the exception it raises; this is the proxy half of the same
        contract, and the row is shaped identically so a reader cannot tell
        which client made the attempt.

        Two flows are deliberately NOT recorded. One the addon killed itself
        never left, and a blocked request that appeared in `requests` could go
        on to satisfy the gate asserting a reproduction's URLs were really
        sent -- the denial belongs in the audit log, where it already is. One
        that already has a response is the `response` hook's to record.
        """
        if flow.response is not None:
            return  # the response hook owns it
        self._record_attempt(flow, reason=getattr(flow.error, "msg", None))

    def http_connect_error(self, flow: http.HTTPFlow) -> None:
        """A CONNECT that was allowed through and could not be established.

        Separate from `error` because mitmproxy reports this one differently:
        `flow.error` is unset and `flow.response` holds a 502 that mitmproxy
        itself generated. That 502 is never recorded as the status. The target
        did not answer -- it was never reached -- and a fabricated response in
        the request log is the thing this addon refuses to create when it
        blocks a flow, for the same reason: it could be read later as the
        target's own and cited as evidence. The status stays NULL and the
        reason goes in the note.
        """
        self._record_attempt(flow, reason=_connect_error_reason(flow))

    def _record_attempt(self, flow: http.HTTPFlow, *, reason: Optional[str]) -> None:
        binding = self.binding
        if not binding.enforcing:
            return
        if flow.metadata.get("bbh_killed") or _was_killed(flow):
            return
        if flow.metadata.get("bbh_request_id"):
            return
        if flow.request is None:
            # Nothing was ever sent -- a client that dropped mid-handshake, for
            # instance. Returning is right, and it must not reach the
            # fail-closed branch below: bricking the proxy over a client that
            # went away would turn a non-event into an outage.
            return

        try:
            flow.metadata["bbh_request_id"] = self.record_failure(flow, reason)
        except Exception as exc:
            # Same treatment as a lost response: stop forwarding rather than
            # keep running with a hole in the ledger.
            reason = (
                f"the proxy could not record a failed request ({type(exc).__name__}: {exc}); "
                f"further flows are blocked rather than run unrecorded. Check "
                f"{paths.db_path(binding.engagement)} and restart: bb proxy start"
            )
            logger.error("bbh proxy: %s", reason)
            binding.deny_reason = reason

    def record_failure(self, flow: http.HTTPFlow, reason: Optional[str] = None) -> int:
        """Persist an attempt with no response, the way bbh.http records one.

        A failed CONNECT is recorded too. It is not a request to the target --
        `http_connect` says as much -- but it is a TCP connection that was
        opened against the program's asset, and the budget exists to bound
        exactly that. A successful CONNECT is not recorded, so the inner
        requests cannot be double counted.
        """
        binding = self.binding
        request = flow.request
        extra = binding.rules.get("redact_headers") or ()
        bodies = paths.engagement_dir(binding.engagement) / "raw" / "bodies"
        req_body = persist_body(bodies, request.get_content(strict=False))

        note = {"error": reason or "the flow failed and mitmproxy gave no reason"}
        if req_body.inline is not None:
            note["req_body"] = req_body.inline

        url = request.pretty_url
        parts = urlsplit(url)
        duration = None
        ended = getattr(flow.error, "timestamp", None)
        if ended and request.timestamp_start:
            elapsed = int((ended - request.timestamp_start) * 1000)
            duration = max(0, elapsed - int(flow.metadata.get("bbh_waited_ms", 0)))

        return binding.store.add_request(
            phase=self.phase,
            source="proxy",
            actor="browser",
            method=request.method,
            url=url,
            host=request.pretty_host,
            path=parts.path or "/",
            query=parts.query or None,
            # NULL throughout the response half, not empty: there was no
            # response at all, which is not a response that carried nothing.
            status=None,
            req_headers=redact_headers(request.headers, extra),
            req_body_path=req_body.path,
            req_body_sha256=req_body.sha256,
            resp_headers=None,
            resp_body_path=None,
            resp_body_sha256=None,
            resp_len=None,
            duration_ms=duration,
            note=json.dumps(note, ensure_ascii=False),
        )

    def record(self, flow: http.HTTPFlow) -> int:
        """Persist one exchange exactly the way bbh.http persists its own."""
        binding = self.binding
        scope = binding.scope
        request, response = flow.request, flow.response

        extra = binding.rules.get("redact_headers") or ()
        bodies = paths.engagement_dir(binding.engagement) / "raw" / "bodies"
        req_body = persist_body(bodies, request.get_content(strict=False))
        resp_body = persist_body(bodies, response.get_content(strict=False))

        note = {}
        if req_body.inline is not None:
            note["req_body"] = req_body.inline
        if resp_body.inline is not None:
            note["resp_body"] = resp_body.inline

        url = request.pretty_url
        parts = urlsplit(url)
        duration = None
        if response.timestamp_end and request.timestamp_start:
            elapsed = int((response.timestamp_end - request.timestamp_start) * 1000)
            duration = max(0, elapsed - int(flow.metadata.get("bbh_waited_ms", 0)))

        return binding.store.add_request(
            phase=self.phase,
            source="proxy",
            actor="browser",
            method=request.method,
            url=url,
            host=request.pretty_host,
            path=parts.path or "/",
            query=parts.query or None,
            status=response.status_code,
            req_headers=redact_headers(request.headers, extra),
            req_body_path=req_body.path,
            req_body_sha256=req_body.sha256,
            resp_headers=redact_headers(response.headers, extra),
            resp_body_path=resp_body.path,
            resp_body_sha256=resp_body.sha256,
            resp_len=resp_body.length,
            duration_ms=duration,
            note=json.dumps(note, ensure_ascii=False) if note else None,
        )

    # -- audit ------------------------------------------------------------

    def audit(self, flow: http.HTTPFlow, reason: str) -> None:
        """Append the block to the log the PreToolUse guard also writes.

        Through cli.audit_record, so the record is hash chained onto whatever
        was written last and a later edit of it is detectable by
        `bb doctor --verify-chain`, and so a killed flow lands in the log with
        the same flat shape as the guard's own denial -- it is the same kind of
        event, a refused request, and `bb audit` should not have to render it
        two ways. The import is deferred: a blocked flow is rare, and the
        addon's load path stays as small as it was.
        """
        record = {
            "ts": utcnow(),
            "engagement": self.binding.engagement,
            "phase": self.phase,
            "tool": "proxy",
            "allowed": False,
            "command": f"{flow.request.method} {flow.request.pretty_url}"[:2000],
            "checked": [f"DENY {flow.request.pretty_host}"],
            "reasons": [reason],
        }
        try:
            from bbh.cli import audit_record

            if audit_record("proxy_block", record):
                return
        except Exception:
            pass  # fall through to the plain append below
        try:
            paths.STATE_DIR.mkdir(parents=True, exist_ok=True)
            with paths.AUDIT_LOG.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:
            pass  # auditing must never break the proxy


addons = [BBHProxy()]
