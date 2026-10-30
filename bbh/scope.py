"""Scope model and matching.

This module is the single source of truth for "may I touch this host?". Three
enforcement layers consume it: the PreToolUse guard (static, pre-execution),
the sanctioned HTTP client (runtime), and the mitmproxy addon (browser traffic).

Runtime matching is stdlib-only so the addon can run under mitmproxy's own
interpreter. YAML is only touched when compiling a human-authored scope.yaml
into scope.lock.json; everything downstream reads the lock.

Matching rules, in order:
  1. out_of_scope match  -> DENY (always wins)
  2. in_scope match      -> ALLOW
  3. no match            -> DENY (default deny)

Two things the compiler does that look like fussiness and are not.

**It refuses a key it does not know.** The lock used to be a fixed key set built
from the keys the compiler recognised, and everything else in scope.yaml was
dropped without a word. `program_constraints:` -- the block that carries the
program's *own* rate limit and its forbidden tests -- was one of the dropped
keys, so a scope file that clamped the harness to 0.5 rps compiled clean,
produced a lock that said 2.0, and the attestation signed under it was a false
statement. A key this build cannot enforce is a rule it is about to break, so an
unrecognised key at the top level, under `rules:` or inside `program_constraints`
stops the compile instead.

**It refuses operator text that could forge harness output.** `Scope.summary()`
and the deny reasons from `decide()` are rendered into agent prompts and tool
results *outside* every untrusted fence -- that is what makes them the harness's
own voice. A newline plus a `#` in a `program_url`, a `url_prefix` path or a
rule `note` is therefore enough to forge a heading, and a `<` is enough to forge
a fence tag. Those characters are refused where the operator can still see the
mistake, rather than escaped at render time: a URL that needs mangling to be
printable is a URL that was mistyped.
"""

from __future__ import annotations

import difflib
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

SCHEMA_VERSION = 1

RULE_TYPES = ("domain", "wildcard", "cidr", "url_prefix")

DEFAULT_RULES = {
    "max_rps": 2.0,
    "max_requests": 20000,
    "allowed_methods": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
    "allow_tools": [],
    "allow_private_ranges": False,
    # Researcher-owned callback hosts (interactsh, Collaborator). Reachable so blind
    # vulnerabilities can be proven, but tracked separately from the target's scope:
    # a callback host is infrastructure, not an asset under test.
    "oob_hosts": [],
    "redact_headers": [],
}

# Program-mandated limits, which may only ever *clamp* `rules`. `bbh.http`
# imports this list rather than keeping its own copy: the compiler refuses an
# unknown key here and the client refuses one that reached a lock some other
# way, and the two have to refuse the same set or one of them is a gap.
PROGRAM_CONSTRAINT_KEYS = (
    "max_rps",
    "max_requests",
    "max_nonowned_objects",
    "allowed_methods",
    "required_headers",
    "forbidden_tests",
    "redact_headers",
)

# Top-level keys a scope.yaml may carry. Anything else is a compile error.
TOP_LEVEL_KEYS = frozenset(
    {
        "engagement",
        "platform",
        "program_url",
        "authorization",
        "rules",
        "in_scope",
        "out_of_scope",
        "program_constraints",
    }
)

# Keys allowed under `rules:`. Wider than DEFAULT_RULES, because three of the
# limits default inside `bbh.http` (which owns the controls that read them)
# rather than here, and because `program_constraints` is accepted in both
# placements -- the contract writes it at the top level, and a lock that carries
# it under `rules:` still clamps.
RULE_KEYS = frozenset(DEFAULT_RULES) | {
    "max_nonowned_objects",
    "required_headers",
    "forbidden_tests",
    "program_constraints",
}

# Longest `program_url` and rule `note` the compiler will accept. Both are
# printed in full in prompts, so an unbounded one is a prompt-budget hole as
# well as an eyesore.
PROGRAM_URL_MAX = 200
NOTE_MAX = 200

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")

# C0, DEL, C1 and the two Unicode line separators: everything that can end a
# line, blank one or move a terminal cursor in text the harness prints as its
# own.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")

# RFC 3986's unreserved + reserved + percent. Deliberately no `<`, `>`, `"`,
# backtick, space or non-ASCII: a real policy URL needs none of them, and each
# of them is a character a forged tag or heading would need.
_URL_CHARS_RE = re.compile(r"\A[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*\Z")


class ScopeError(ValueError):
    """Raised when a scope document is malformed."""


@dataclass(frozen=True)
class Decision:
    """The verdict for one target, with a reason fit to show an agent."""

    allowed: bool
    target: str
    reason: str
    rule: dict[str, Any] | None = None

    def __bool__(self) -> bool:
        return self.allowed


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_host(raw: str | None) -> str | None:
    """Lowercase, de-port, de-userinfo, punycode a hostname. None if unusable."""
    if not raw:
        return None
    h = raw.strip().strip(".").lower()
    if not h:
        return None
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    if h.startswith("["):
        end = h.find("]")
        if end == -1:
            return None
        h = h[1:end]
    elif h.count(":") == 1:
        h = h.split(":", 1)[0]
    elif h.count(":") > 1:
        # bare IPv6 without brackets; keep as-is for ip parsing
        pass
    if not h:
        return None
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii").lower()
        except Exception:
            return None
    if is_ip(h):
        return h
    if len(h) > 253 or any(not _LABEL_RE.match(lbl) for lbl in h.split(".")):
        return None
    return h


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_private(host: str) -> bool:
    """True for loopback/private/link-local/reserved IPs and localhost names."""
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    )


def host_from_url(url: str) -> str | None:
    """Extract a normalized host from a URL, tolerating a missing scheme."""
    if not url:
        return None
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "//" + candidate
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    return normalize_host(parts.hostname or "")


def _norm_url_prefix(value: str) -> str:
    raw = value.strip()
    # Checked before urlsplit as well as after: urlsplit silently deletes tab,
    # CR and LF, so a prefix written with one in it would compile to a rule the
    # operator did not write rather than be refused. The post-split check below
    # is the one that matters for output safety; this one is about the rule
    # meaning what the file says.
    found = _CONTROL_RE.search(raw)
    if found:
        raise ScopeError(
            f"url_prefix {raw!r} contains {found.group()!r}, a control character; the rule "
            f"would compile to a different prefix than the one written"
        )

    parts = urlsplit(raw)
    if not parts.scheme or not parts.hostname:
        raise ScopeError(f"url_prefix needs scheme and host: {value!r}")
    host = normalize_host(parts.hostname)
    if host is None:
        raise ScopeError(f"url_prefix has an unusable host: {value!r}")
    port = f":{parts.port}" if parts.port else ""
    prefix = f"{parts.scheme.lower()}://{host}{port}{parts.path or '/'}"
    # The scheme, host and port are normalized above; the path is whatever was
    # typed, and `Scope.summary()` prints the whole prefix outside every fence.
    problem = render_problem(prefix, f"url_prefix {value!r}", PROGRAM_URL_MAX)
    if problem:
        raise ScopeError(problem)
    return prefix


def render_problem(value: str, where: str, cap: int) -> str | None:
    """Why `value` cannot be printed in the harness's own voice, or None.

    Applied to every scope.yaml string that reaches a prompt or a tool result
    outside an untrusted fence. See the module docstring for why that set gets
    its own rule.
    """
    found = _CONTROL_RE.search(value)
    if found:
        return (
            f"{where} contains {found.group()!r}, a control character; this text is printed "
            f"outside every untrusted fence, so one of those can forge a line of harness "
            f"output"
        )
    if "<" in value:
        return f"{where} contains '<', which is how a forged fence tag starts"
    if len(value) > cap:
        return f"{where} is {len(value)} characters; the limit is {cap}"
    return None


def program_url_problem(value: Any) -> str | None:
    """Why `program_url` is unusable, or None. An absent URL is not a problem."""
    if value is None:
        return None
    if not isinstance(value, str):
        return (
            f"program_url is a {type(value).__name__}; it must be the program's policy "
            f"page, as a string"
        )
    text = value.strip()
    if not text:
        return None

    problem = render_problem(text, "program_url", PROGRAM_URL_MAX)
    if problem:
        return problem
    if not _URL_CHARS_RE.match(text):
        stray = next(ch for ch in text if not _URL_CHARS_RE.match(ch))
        return f"program_url contains {stray!r}, which is not a URL character"
    try:
        parts = urlsplit(text)
    except ValueError as exc:
        return f"program_url does not parse as a URL ({exc})"
    if parts.scheme.lower() not in ("http", "https"):
        return (
            f"program_url has scheme {parts.scheme!r}; a policy page is reached over "
            f"http or https"
        )
    if normalize_host(parts.hostname or "") is None:
        return "program_url has no usable hostname"
    return None


def compile_program_constraints(raw: Any, where: str = "program_constraints") -> dict[str, Any]:
    """Validate the program's own limits. Returns them unchanged, or raises.

    Shape only: the values are left exactly as the operator wrote them, and
    `bbh.http.effective_rules` is the one place that coerces and applies them.
    A lock can reach the client without passing through here -- hand written,
    or built in memory -- so the client validates everything again regardless,
    and a second canonicaliser here would only be a second thing to drift.
    """
    if not isinstance(raw, dict):
        raise ScopeError(
            f"{where} is a {type(raw).__name__}; it must be a mapping of the program's own "
            f"limits, e.g. {{max_rps: 0.5, forbidden_tests: [delete]}}"
        )

    problems: list[str] = []
    for key in sorted(set(raw) - set(PROGRAM_CONSTRAINT_KEYS)):
        problems.append(
            f"{where}.{key} is not a limit this build can clamp with"
            + _did_you_mean(key, PROGRAM_CONSTRAINT_KEYS)
        )

    if "max_rps" in raw and _as_float(raw["max_rps"]) is None:
        problems.append(f"{where}.max_rps is {raw['max_rps']!r}, which is not a number")
    for key in ("max_requests", "max_nonowned_objects"):
        if key in raw and _as_int(raw[key]) is None:
            problems.append(f"{where}.{key} is {raw[key]!r}, which is not a whole number")
    for key in ("allowed_methods", "forbidden_tests", "redact_headers"):
        value = raw.get(key)
        if key in raw and (isinstance(value, str) or not isinstance(value, (list, tuple))):
            problems.append(f"{where}.{key} is {value!r}, which is not a list")
    if "required_headers" in raw and not isinstance(raw["required_headers"], (dict, list, tuple)):
        problems.append(
            f"{where}.required_headers is {raw['required_headers']!r}, which is not a "
            f"mapping of header names to values"
        )

    if problems:
        raise ScopeError(
            "; ".join(problems)
            + ". A program limit the harness cannot apply is a program rule it would break, "
            "so nothing compiles until every one of them is enforceable"
        )
    return dict(raw)


def _as_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return None if number != number else number  # NaN compares unequal to itself


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None  # YAML `true` is an int in Python, and is not a count
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _did_you_mean(key: str, known: Iterable[str]) -> str:
    close = difflib.get_close_matches(str(key), [str(k) for k in known], n=1, cutoff=0.7)
    return f" (did you mean {close[0]!r}?)" if close else ""


def normalize_url(url: str) -> str | None:
    """Canonical scheme://host[:port]/path form, for url_prefix comparison."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    host = normalize_host(parts.hostname or "")
    if not host or not parts.scheme:
        return None
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme.lower()}://{host}{port}{parts.path or '/'}"


def compile_rule(raw: Any) -> dict[str, Any]:
    """Validate and canonicalize one scope rule."""
    if isinstance(raw, str):
        raw = {"value": raw}
    if not isinstance(raw, dict):
        raise ScopeError(f"rule must be a string or mapping, got {type(raw).__name__}")

    value = str(raw.get("value", "")).strip()
    if not value:
        raise ScopeError(f"rule is missing a value: {raw!r}")

    rtype = raw.get("type")
    if not rtype:
        if value.startswith("*."):
            rtype = "wildcard"
        elif "://" in value:
            rtype = "url_prefix"
        elif "/" in value and is_ip(value.split("/", 1)[0]):
            rtype = "cidr"
        else:
            rtype = "domain"
    rtype = str(rtype).strip().lower()
    if rtype not in RULE_TYPES:
        raise ScopeError(f"unknown rule type {rtype!r}; expected one of {RULE_TYPES}")

    note = str(raw.get("note", "")) or None
    if note is not None:
        # A note is quoted back verbatim in the deny reason the agent reads, so
        # it is harness-voice text that an operator wrote.
        problem = render_problem(note, f"the note on rule {value!r}", NOTE_MAX)
        if problem:
            raise ScopeError(problem)
    rule: dict[str, Any] = {"type": rtype, "note": note}

    if rtype == "domain":
        host = normalize_host(value)
        if host is None:
            raise ScopeError(f"domain rule has an unusable host: {value!r}")
        rule["value"] = host
    elif rtype == "wildcard":
        bare = value[2:] if value.startswith("*.") else value
        host = normalize_host(bare)
        if host is None:
            raise ScopeError(f"wildcard rule has an unusable host: {value!r}")
        rule["value"] = host
        # Platform convention (HackerOne/Bugcrowd): *.example.com covers the apex.
        rule["include_apex"] = bool(raw.get("include_apex", True))
    elif rtype == "cidr":
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ScopeError(f"bad cidr {value!r}: {exc}") from exc
        rule["value"] = str(net)
    else:
        rule["value"] = _norm_url_prefix(value)

    return rule


def _rule_matches(rule: dict[str, Any], host: str, url: str | None) -> bool:
    rtype = rule["type"]
    value = rule["value"]

    if rtype == "domain":
        return host == value
    if rtype == "wildcard":
        if host == value:
            return bool(rule.get("include_apex", True))
        return host.endswith("." + value)
    if rtype == "cidr":
        if not is_ip(host):
            return False
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(value)
        except ValueError:
            return False
    if rtype == "url_prefix":
        if url is None:
            return False
        canon = normalize_url(url)
        return bool(canon and canon.startswith(value))
    return False


class Scope:
    """A compiled engagement scope. Construct from a lock dict."""

    def __init__(self, lock: dict[str, Any]):
        if lock.get("schema") != SCHEMA_VERSION:
            raise ScopeError(
                f"scope lock schema {lock.get('schema')!r}; this build expects {SCHEMA_VERSION}. "
                "Re-run: bb scope compile"
            )
        self.lock = lock
        self.engagement: str = lock["engagement"]
        self.rules: dict[str, Any] = {**DEFAULT_RULES, **(lock.get("rules") or {})}
        self.in_scope: list[dict] = lock.get("in_scope") or []
        self.out_of_scope: list[dict] = lock.get("out_of_scope") or []
        self.authorization: dict = lock.get("authorization") or {}

    # -- loading ---------------------------------------------------------

    @classmethod
    def from_lock_file(cls, path: str | Path, *, verify: bool = True) -> "Scope":
        """Load a lock from disk, checking its signature.

        Disk is the trust boundary: a lock read from a file may have been edited
        by whatever else runs as this user, so it is verified here. Constructing
        a Scope from a dict in memory is not verified -- the caller already holds
        the authoritative object.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if verify:
            problem = verify_lock(data)
            if problem:
                raise ScopeError(
                    f"{problem} ({path}). The compiled scope could not be trusted, so no "
                    f"target is authorized. Re-arm the engagement: "
                    f"bb arm {data.get('engagement', '<engagement>')}"
                )
        return cls(data)

    # -- authorization ---------------------------------------------------

    def authorization_error(self, now: str | None = None) -> str | None:
        """Return why this scope is not usable right now, or None if it is."""
        auth = self.authorization
        if not auth.get("attested_by"):
            return "engagement has no authorization attestation; run: bb arm <engagement>"
        expires = auth.get("expires_at")
        if not expires:
            return "authorization has no expiry; re-run: bb arm <engagement>"
        stamp = now or _utcnow()
        if stamp >= expires:
            return (
                f"authorization expired at {expires} (now {stamp}); "
                f"re-run: bb arm {self.engagement}"
            )
        return None

    # -- matching --------------------------------------------------------

    def decide(self, target: str) -> Decision:
        """Decide one target. Accepts a URL or a bare host."""
        raw = (target or "").strip()
        if not raw:
            return Decision(False, raw, "empty target")

        looks_like_url = "://" in raw
        url = raw if looks_like_url else None
        host = host_from_url(raw) if looks_like_url else normalize_host(raw)

        if host is None:
            return Decision(False, raw, f"could not parse a hostname out of {raw!r}")

        auth_problem = self.authorization_error()
        if auth_problem:
            return Decision(False, host, auth_problem)

        for rule in self.out_of_scope:
            if _rule_matches(rule, host, url):
                note = f" ({rule['note']})" if rule.get("note") else ""
                return Decision(
                    False, host, f"{host} matches OUT-OF-SCOPE rule {rule['value']}{note}", rule
                )

        for oob in self.rules.get("oob_hosts", []):
            bare = oob[2:] if oob.startswith("*.") else oob
            if host == bare or host.endswith("." + bare):
                return Decision(
                    True,
                    host,
                    f"{host} is a researcher-owned OOB callback host, not a target asset",
                    {"type": "oob", "value": oob},
                )

        # An explicit in-scope rule is an explicit authorization, so it is checked before
        # the private-address heuristic: a researcher who writes a CIDR or a literal host
        # into scope.yaml meant it. The heuristic exists to catch addresses nobody listed,
        # which is how an SSRF pivot or a stray 169.254.169.254 would arrive.
        for rule in self.in_scope:
            if _rule_matches(rule, host, url):
                return Decision(True, host, f"{host} matches in-scope rule {rule['value']}", rule)

        if is_private(host) and not self.rules.get("allow_private_ranges"):
            return Decision(
                False,
                host,
                f"{host} is a private, loopback or reserved address and is not listed in "
                f"the scope of engagement {self.engagement!r}. If it is genuinely in scope, "
                f"add it as an explicit cidr or domain rule.",
            )

        return Decision(
            False,
            host,
            f"{host} is not in the scope of engagement {self.engagement!r} (default deny)",
        )

    def decide_many(self, targets: Iterable[str]) -> list[Decision]:
        return [self.decide(t) for t in targets]

    def method_allowed(self, method: str) -> bool:
        allowed = [m.upper() for m in self.rules.get("allowed_methods", [])]
        return method.upper() in allowed

    def summary(self) -> str:
        lines = [f"engagement: {self.engagement}"]
        program = self.lock.get("program_url")
        if program:
            # Re-checked here even though compile_scope refuses a bad one:
            # Scope(dict) does not verify a signature, so this string may have
            # reached memory without ever passing the compiler, and it is the
            # one piece of non-harness text this function prints.
            lines.append(
                f"program:    {program}"
                if program_url_problem(program) is None
                else f"program:    (withheld: not a printable URL; "
                f"run: bb scope compile {self.engagement})"
            )
        constrained: set[str] = set()
        for holder in (self.lock, self.rules):
            block = holder.get("program_constraints")
            if isinstance(block, dict):
                constrained.update(str(k) for k in block)
        if constrained:
            # Names only, never values: the limits themselves are applied by the
            # client, and this line exists so the figures below are not read as
            # the whole story.
            named = ", ".join(sorted(constrained))
            lines.append(f"program limits: {named} (clamped tighter than the figures below)")
        lines.append(f"in scope:   {len(self.in_scope)} rule(s)")
        for r in self.in_scope:
            lines.append(f"  + {r['type']:<10} {r['value']}")
        if self.out_of_scope:
            lines.append(f"excluded:   {len(self.out_of_scope)} rule(s)")
            for r in self.out_of_scope:
                lines.append(f"  - {r['type']:<10} {r['value']}")
        lines.append(
            f"limits:     {self.rules['max_rps']} rps, {self.rules['max_requests']} requests max"
        )
        return "\n".join(lines)


def compile_scope(doc: dict[str, Any], source_text: str = "") -> dict[str, Any]:
    """Turn a human-authored scope document into a lock dict.

    Every problem in the document is collected and reported together: an
    operator fixing a scope file should get one list, not one error per edit.
    The engagement name is the exception, because without it there is no
    `bb scope compile <name>` to print.
    """
    if not isinstance(doc, dict):
        raise ScopeError("scope document must be a mapping")

    engagement = str(doc.get("engagement", "")).strip()
    if not engagement:
        raise ScopeError("scope is missing required field: engagement")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", engagement):
        raise ScopeError(
            f"engagement name {engagement!r} must be lowercase alphanumeric with . _ - (<=64 chars)"
        )

    problems: list[tuple[str, str]] = []
    _collect_unknown_keys(doc, TOP_LEVEL_KEYS, "", problems)

    raw_rules = doc.get("rules") or {}
    if not isinstance(raw_rules, dict):
        problems.append((
            f"rules is a {type(raw_rules).__name__}; it must be a mapping",
            "rules:\n      max_rps: 2.0",
        ))
        raw_rules = {}
    _collect_unknown_keys(raw_rules, RULE_KEYS, "rules.", problems)

    constraints: dict[str, Any] | None = None
    for where, holder in (("program_constraints", doc), ("rules.program_constraints", raw_rules)):
        block = holder.get("program_constraints")
        if block is None:
            continue
        try:
            compiled = compile_program_constraints(block, where)
        except ScopeError as exc:
            problems.append((
                str(exc),
                f"write only {list(PROGRAM_CONSTRAINT_KEYS)} under {where}, "
                f"copied from the program's policy page",
            ))
            continue
        # Both placements clamp, so both are kept; the top-level block is the
        # one the contract documents and the one the lock carries.
        if where == "program_constraints":
            constraints = compiled

    in_scope: list[dict[str, Any]] = []
    out_of_scope: list[dict[str, Any]] = []
    bad_rules = False
    for field, destination in (("in_scope", in_scope), ("out_of_scope", out_of_scope)):
        for raw in doc.get(field) or ():
            try:
                destination.append(compile_rule(raw))
            except ScopeError as exc:
                bad_rules = bad_rules or field == "in_scope"
                problems.append((
                    f"{field} entry {raw!r} does not compile: {exc}",
                    f"{field}:\n      - www.example.com      # or \"*.example.com\", "
                    f"a CIDR, or an https:// prefix",
                ))
    # Only when nothing was *offered*: "you listed no assets" on top of "this
    # asset does not parse" sends an operator looking for a second mistake.
    if not in_scope and not bad_rules:
        problems.append((
            "scope has no in_scope rules; nothing would be testable",
            'in_scope:\n      - "*.example.com"',
        ))

    program_url = doc.get("program_url")
    url_problem = program_url_problem(program_url)
    if url_problem:
        problems.append((
            url_problem,
            "program_url: https://hackerone.com/<program>",
        ))
    elif isinstance(program_url, str):
        program_url = program_url.strip() or None

    rules = {**DEFAULT_RULES, **raw_rules}
    rate = _as_float(rules["max_rps"])
    count = _as_int(rules["max_requests"])
    if rate is None or count is None:
        problems.append((
            f"rules.max_rps is {rules['max_rps']!r} and rules.max_requests is "
            f"{rules['max_requests']!r}; both have to be numbers the client can enforce",
            "rules:\n      max_rps: 2.0\n      max_requests: 20000",
        ))
    elif rate <= 0 or rate > 50:
        problems.append((
            f"rules.max_rps is {rate}; it must be in (0, 50], and program rules usually "
            f"cap it far lower",
            "rules:\n      max_rps: 2.0",
        ))
    else:
        rules["max_rps"], rules["max_requests"] = rate, count

    # Checked before the comprehensions below iterate them: `allowed_methods:
    # GET` reads fine and would otherwise compile to ['G', 'E', 'T'], and an
    # int would leave a TypeError rather than a refusal naming the fix.
    for key in ("allowed_methods", "allow_tools", "oob_hosts", "redact_headers"):
        value = rules.get(key)
        if isinstance(value, str) or not isinstance(value, (list, tuple, set, frozenset)):
            problems.append((
                f"rules.{key} is {value!r}, which is not a list",
                f"rules:\n      {key}: [{value!r}]",
            ))
            rules[key] = []

    rules["allowed_methods"] = [str(m).upper() for m in rules["allowed_methods"]]
    rules["allow_tools"] = sorted({str(t).lower() for t in rules["allow_tools"]})
    rules["redact_headers"] = sorted({str(h).lower() for h in rules.get("redact_headers", [])})

    oob: list[str] = []
    for raw_host in rules.get("oob_hosts", []):
        candidate = str(raw_host).strip().lower()
        bare = candidate[2:] if candidate.startswith("*.") else candidate
        if normalize_host(bare) is None:
            problems.append((
                f"rules.oob_hosts entry {raw_host!r} is not a usable hostname",
                'rules:\n      oob_hosts: ["*.oast.fun"]',
            ))
            continue
        oob.append(candidate)
    rules["oob_hosts"] = sorted(set(oob))

    if problems:
        detail = "\n".join(f"  - {what}\n    fix: {how}" for what, how in problems)
        raise ScopeError(
            f"scope for engagement {engagement!r} does not compile:\n{detail}\n"
            f"Then retry: bb scope compile {engagement}"
        )

    return {
        "schema": SCHEMA_VERSION,
        "engagement": engagement,
        "platform": doc.get("platform"),
        "program_url": program_url,
        "authorization": doc.get("authorization") or {},
        "program_constraints": constraints,
        "rules": rules,
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "compiled_at": _utcnow(),
        "source_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        if source_text
        else None,
    }


def _collect_unknown_keys(
    holder: dict[str, Any],
    allowed: Iterable[str],
    prefix: str,
    problems: list[tuple[str, str]],
) -> None:
    """Append one problem per key this build does not read.

    The permissive alternative -- keep the keys it knows, drop the rest -- is
    what let `program_constraints:` sit in a scope file for a whole engagement
    without ever reaching the client.
    """
    known = set(allowed)
    for key in sorted(set(holder) - known):
        problems.append((
            f"{prefix}{key} is not a key this build reads, so writing it would have no "
            f"effect on anything the harness enforces" + _did_you_mean(key, known),
            f"delete {prefix}{key} from scope.yaml, or correct the spelling; "
            f"this build reads {sorted(known)}",
        ))


def canonical_bytes(lock: dict[str, Any]) -> bytes:
    """Stable serialization of a lock, excluding its own signature."""
    body = {k: v for k, v in lock.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_lock(lock: dict[str, Any], key: bytes | None = None) -> dict[str, Any]:
    """Return a copy of the lock carrying an HMAC over its canonical form."""
    import hmac

    from . import paths

    signed = {k: v for k, v in lock.items() if k != "sig"}
    secret = key if key is not None else paths.armkey()
    signed["sig"] = hmac.new(secret, canonical_bytes(signed), hashlib.sha256).hexdigest()
    return signed


def verify_lock(lock: dict[str, Any], key: bytes | None = None) -> str | None:
    """Return a problem description, or None when the signature is good."""
    import hmac

    from . import paths

    sig = lock.get("sig")
    if not sig:
        return "scope lock is unsigned"
    try:
        secret = key if key is not None else paths.armkey()
    except OSError as exc:
        return f"cannot read the signing key ({exc})"
    expected = hmac.new(secret, canonical_bytes(lock), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(sig)):
        return "scope lock integrity check failed: it was modified after it was armed"
    return None


def compile_scope_file(yaml_path: str | Path) -> dict[str, Any]:
    """Compile scope.yaml -> lock dict. Requires PyYAML (CLI-side only)."""
    import yaml  # imported lazily: runtime consumers stay stdlib-only

    text = Path(yaml_path).read_text(encoding="utf-8")
    return compile_scope(yaml.safe_load(text) or {}, source_text=text)
