"""PreToolUse guard: static scope enforcement on every shell command.

Claude Code runs this before each Bash call. It parses the command, finds any
network-capable tool, extracts the hosts that tool would contact, and denies
the call unless every one of them is in the armed engagement's scope.

The guard fails closed. If a command is network-capable but its targets cannot
be resolved statically -- a variable, a command substitution, a pipe feeding
stdin -- it is denied with instructions for making the target explicit. A
false deny costs the agent one retry; a false allow costs an unauthorized
request against someone else's infrastructure.

Commands with no network tool in them are never touched: local analysis, file
edits and git stay fast.

Two rules shape everything below. A flag whose value names a destination the
guard cannot resolve -- a proxy, a resolver, a `--resolve` pin, a config file
that carries its own URLs -- is DENIED rather than skipped, because skipping it
makes the audit line claim the URL's host was contacted when the packets went
somewhere else, and a record naming a host nothing reached is worse than no
record at all. And the sanctioned-client exemption for a script means "every
network call in this script goes through the client", never "this script
mentions the client somewhere": a comment, a string literal or a variable name
must not buy a pass, or an agent persuaded by a fenced response body can write
itself one in a single line.

Wire-up (settings.json):
    {"hooks": {"PreToolUse": [{"matcher": "Bash",
      "hooks": [{"type": "command",
                 "command": "~/claude-harness/bin/bb-guard"}]}]}}
"""

from __future__ import annotations

import ast
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import paths
from .scope import Scope, ScopeError, host_from_url, normalize_host

# Commands that wrap another command; skipped to find the real tool.
WRAPPERS = {
    "sudo": {"flagsets": {"-u", "-g", "-p", "-U", "--user", "--group"}},
    "doas": {"flagsets": {"-u"}},
    "env": {"flagsets": {"-u", "--unset", "-C", "--chdir"}},
    "nohup": {"flagsets": set()},
    "stdbuf": {"flagsets": {"-i", "-o", "-e"}},
    "nice": {"flagsets": {"-n"}},
    "ionice": {"flagsets": {"-c", "-n", "-p"}},
    "time": {"flagsets": {"-f", "-o"}},
    "timeout": {"flagsets": {"-s", "--signal", "-k", "--kill-after"}, "positional": 1},
    "unbuffer": {"flagsets": set()},
    "xargs": {"flagsets": {"-n", "-P", "-I", "-d", "-a", "-L", "-s"}},
}

# Constructs whose value cannot be known before the shell runs.
UNRESOLVABLE = ("$(", "`", "${", "<(", ">(")

# Which inspector a runner gets. Only the python family has a parser in the
# standard library, and that difference decides how far each one is trusted.
RUNNER_FAMILY = {
    "python": "python", "python3": "python", "python2": "python",
    "node": "node", "nodejs": "node", "deno": "node", "bun": "node",
    "ruby": "ruby", "perl": "perl", "php": "php",
}
SCRIPT_RUNNERS = frozenset(RUNNER_FAMILY)

# Flags whose value is the program text itself, by family.
BODY_FLAGS: dict[str, tuple[str, ...]] = {
    "python": ("-c",),
    "node": ("-e", "--eval", "-p", "--print"),
    "ruby": ("-e",),
    "perl": ("-e", "-E"),
    "php": ("-r",),
}

# Python flags that consume a value of their own. Without this table the token
# after one of them reads as a script path, and `python3 -m pytest` would be
# refused as a script the guard cannot open.
PY_VALUE_FLAGS = ("-m", "-W", "-X", "-Q", "--check-hash-based-pycs")

# Modules whose import means the script opens its own connections. Matched on
# the dotted name an `import` statement actually binds, so `urllib.parse` --
# string manipulation, no socket -- is not swept up with `urllib.request`.
PY_NET_MODULES = frozenset({
    "aiohttp", "ftplib", "http.client", "httplib", "httpx", "paramiko", "playwright",
    "pycurl", "requests", "scapy", "selenium", "smtplib", "socket", "telnetlib",
    "urllib.error", "urllib.request", "urllib3", "websocket", "websockets",
})

# Handing the work to another process puts the command past this guard: the
# hook sees `python3 -c ...`, never the `curl` inside it.
PY_SHELL_MODULES = frozenset({"subprocess", "pty"})
PY_SHELL_CALL_PREFIXES = ("os.exec", "os.spawn")
PY_SHELL_CALLS = frozenset({"os.system", "os.popen", "os.posix_spawn", "os.posix_spawnp"})

# Code the guard cannot read. Without these the AST check below is one
# `exec("import requests; ...")` away from meaning nothing. `compile` is not
# here on purpose: a code object still needs an exec or an eval to run, and
# `from re import compile` would otherwise be refused for nothing.
PY_OPAQUE_CALLS = frozenset({"exec", "eval"})
PY_DYNAMIC_IMPORTS = frozenset({"__import__", "importlib.import_module"})

# For the runners with no parser, detection only. There is no exemption to
# weigh these against (see `inspect_script`), so a pattern that also fires on a
# comment costs a rephrase, which is the cheap direction.
NON_PY_NET = {
    "node": re.compile(
        r"\b(?:fetch\s*\(|XMLHttpRequest\b|new\s+WebSocket\b|"
        r"require\s*\(\s*['\"](?:node:)?(?:axios|node-fetch|got|superagent|undici|https?|net|"
        r"tls|dgram|ws|puppeteer|playwright|child_process)['\"]|"
        r"from\s+['\"](?:node:)?(?:axios|node-fetch|got|undici|ws|playwright|https?|net|"
        r"child_process)['\"]|"
        r"(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\()"
    ),
    "ruby": re.compile(
        r"\b(?:require\s*['\"](?:net/https?|open-uri|socket|httparty|faraday|rest-client|"
        r"typhoeus|excon|mechanize|selenium-webdriver)['\"]|Net::HTTP\b|TCPSocket\b|"
        r"UDPSocket\b|URI\.(?:open|parse)|(?:system|exec|spawn)\s*\(|IO\.popen\b)"
    ),
    "perl": re.compile(
        r"\b(?:use\s+(?:LWP|HTTP::(?:Tiny|Request)|Net::[A-Za-z]+|IO::Socket[A-Za-z:]*|"
        r"WWW::Mechanize|Furl|Mojo::UserAgent)\b|LWP::UserAgent\b|IO::Socket\b|"
        r"(?:system|exec|qx)\s*[(\{]|open\s*\(\s*[^,]+,\s*['\"][^'\"]*\|)"
    ),
    "php": re.compile(
        r"\b(?:curl_init|curl_exec|fsockopen|stream_socket_client|socket_create|get_headers|"
        r"shell_exec|passthru|proc_open|popen|system|exec)\s*\(|"
        r"\b(?:file_get_contents|fopen|readfile|file)\s*\(\s*['\"]https?://"
    ),
}

# Bash's own socket pseudo-files. `exec 3<>/dev/tcp/host/80` opens a TCP
# connection with no command to look up in NET_TOOLS and no argument to parse,
# so the table-driven path above walks straight past it -- which it demonstrably
# did until this was added. It is caught here, on the raw segment, because a
# redirection target is shell syntax rather than an argv element.
#
# This does not make the guard complete and is not meant to: a compiled binary
# or an interpreter nobody modelled has the same effect and cannot be caught by
# reading a command line at all. The network namespace is the boundary (it was
# measured closing exactly this hole). What this buys is the thing the guard is
# for -- an agent that tries it gets told why, by name, instead of a bare
# connection error it will misread as the target being down.
DEV_SOCKET = re.compile(r"/dev/(?P<proto>tcp|udp)/(?P<host>[^/\s;|&)'\"]+)/(?P<port>[^/\s;|&)'\"]*)")

# Every mention of the path prefix, so one that the pattern above cannot read in
# full is denied rather than skipped: `/dev/tcp/$(hostname -f)/80` must not pass
# because the host was unparseable. This does deny a literal grep for the string
# too. That is the cheaper mistake -- the message says what to do about it in one
# line, while the other direction is the hole this exists to close.
DEV_SOCKET_PREFIX = re.compile(r"/dev/(?:tcp|udp)/")


@dataclass
class ToolSpec:
    """How to pull targets out of one tool's argv."""

    name: str
    target_flags: tuple[str, ...] = ()
    list_flags: tuple[str, ...] = ()
    positional_targets: bool = False
    value_flags: tuple[str, ...] = ()  # flags that consume a value we must skip
    requires_optin: bool = False
    optin_reason: str = ""
    rate_flags: tuple[str, ...] = ()  # one of these must be present and <= max_rps
    deny_flags: dict[str, str] = field(default_factory=dict)
    # Flags whose *value* sends the traffic somewhere the guard cannot resolve:
    # flag -> what it does, rendered into one refusal by `_divert_problem`. Kept
    # apart from deny_flags because these consume their value, and a denial that
    # leaves the value behind re-reads it as a positional target and reports a
    # second, wrong problem for the same flag.
    divert_flags: dict[str, str] = field(default_factory=dict)
    # getopt-style bundling (`curl -sSx proxy`). Off by default: the Go tools
    # here spell long options with one dash, so expanding `-rl` into `-r -l`
    # would refuse a rate limit as a resolver override.
    clusters: bool = False
    stdin_capable: bool = False  # reads targets from stdin when no flag given


def _spec(name: str, **kw: Any) -> tuple[str, ToolSpec]:
    return name, ToolSpec(name=name, **kw)


# The shapes of "this flag decides where the packets go, and the guard cannot
# follow", written once so the refusal reads the same whichever tool produced it.
_PROXY = "routes the traffic through a proxy"
_RESOLVER = "sends the DNS queries to a resolver of its own"
_PIN = "pins the hostname to an address of its own"
_CONFFILE = "loads options from a file, which can carry its own targets"
_WGETRC = "sets a wgetrc command, which can name a proxy"
_REQFILE = "takes the request, and its destination, from a file"
_TUNNEL = "opens a tunnel to a third host"
_CODE = "runs code of its own on every request"

_CURL_PROXY = {f: _PROXY for f in (
    "-x", "--proxy", "--preproxy", "--proxy1.0", "--socks4", "--socks4a",
    "--socks5", "--socks5-hostname",
)}

_SSH_DIVERT = {
    "-L": _TUNNEL, "-R": _TUNNEL, "-D": _TUNNEL, "-W": _TUNNEL, "-J": _TUNNEL,
    "-o": "can carry ProxyCommand or ProxyJump, which hand the connection to another host",
    "-F": _CONFFILE,
}

_BROWSER_DIVERT = {
    "--proxy-server": _PROXY, "--proxy-pac-url": _PROXY,
    "--host-resolver-rules": _PIN, "--host-rules": _PIN,
}

NET_TOOLS: dict[str, ToolSpec] = dict(
    [
        _spec(
            "curl",
            positional_targets=True,
            target_flags=("--url",),
            value_flags=(
                "-H", "--header", "-d", "--data", "--data-raw", "--data-binary",
                "--data-urlencode", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie",
                "-c", "--cookie-jar", "-o", "--output", "-X", "--request", "-u", "--user",
                "-F", "--form", "-m", "--max-time", "--connect-timeout", "-w", "--write-out",
                "--retry", "-T", "--upload-file", "--cacert",
                "--cert", "--key", "--limit-rate", "--max-filesize",
            ),
            # -L is deliberately absent: a redirect's destination is not in the
            # command at all, so refusing the flag would refuse ordinary
            # fetches while the hop still has to be checked where it can be
            # seen -- in the sanctioned client, which already follows it.
            divert_flags={
                **_CURL_PROXY,
                "--resolve": _PIN,
                "--connect-to": _PIN,
                "--dns-servers": _RESOLVER,
                "--dns-ipv4-addr": _RESOLVER,
                "--dns-ipv6-addr": _RESOLVER,
                "--dns-interface": _RESOLVER,
                "-K": _CONFFILE,
                "--config": _CONFFILE,
            },
            clusters=True,
        ),
        _spec(
            "wget",
            positional_targets=True,
            list_flags=("-i", "--input-file"),
            value_flags=("-O", "-o", "-U", "--user-agent", "--header", "-P", "--timeout", "-t", "--tries"),
            divert_flags={
                # `wget -e http_proxy=http://host/` is a wgetrc line on the
                # command line, so it is the config-file hole with no file.
                "-e": _WGETRC,
                "--execute": _WGETRC,
                "--config": _CONFFILE,
            },
            deny_flags={
                "-r": "recursive download is mass retrieval; fetch specific URLs instead",
                "--recursive": "recursive download is mass retrieval; fetch specific URLs instead",
                "-m": "--mirror is mass retrieval; fetch specific URLs instead",
                "--mirror": "--mirror is mass retrieval; fetch specific URLs instead",
            },
            clusters=True,
        ),
        _spec(
            "httpx",
            target_flags=("-u", "-target", "-host"),
            list_flags=("-l", "-list"),
            value_flags=("-o", "-output", "-H", "-header", "-t", "-threads", "-timeout", "-mc", "-fc", "-p", "-ports"),
            divert_flags={
                "-proxy": _PROXY, "-http-proxy": _PROXY, "-socks-proxy": _PROXY,
                "-r": _RESOLVER, "-resolvers": _RESOLVER,
                "-rr": _REQFILE, "-request": _REQFILE,
            },
            rate_flags=("-rl", "-rate-limit"),
            stdin_capable=True,
        ),
        _spec(
            "nuclei",
            target_flags=("-u", "-target"),
            list_flags=("-l", "-list"),
            value_flags=("-t", "-templates", "-o", "-output", "-severity", "-s", "-tags", "-c", "-concurrency", "-H", "-header", "-timeout", "-retries", "-es", "-etags"),
            divert_flags={
                "-p": _PROXY, "-proxy": _PROXY,
                "-pi": _PROXY, "-proxy-internal": _PROXY,
                "-r": _RESOLVER, "-resolvers": _RESOLVER,
                "-config": _CONFFILE,
            },
            rate_flags=("-rl", "-rate-limit"),
            stdin_capable=True,
        ),
        _spec(
            "katana",
            target_flags=("-u", "-list"),
            list_flags=("-list",),
            value_flags=("-o", "-output", "-d", "-depth", "-c", "-concurrency", "-H", "-headers", "-timeout"),
            divert_flags={
                "-proxy": _PROXY, "-resolvers": _RESOLVER, "-config": _CONFFILE,
            },
            rate_flags=("-rl", "-rate-limit"),
            stdin_capable=True,
        ),
        _spec(
            "ffuf",
            target_flags=("-u",),
            value_flags=("-w", "-o", "-of", "-H", "-d", "-X", "-t", "-mc", "-fc", "-fs", "-ac", "-timeout", "-recursion-depth"),
            divert_flags={
                "-x": _PROXY, "-replay-proxy": _PROXY,
                "-request": _REQFILE, "-config": _CONFFILE,
            },
            rate_flags=("-rate",),
        ),
        _spec(
            "gobuster",
            target_flags=("-u", "--url"),
            value_flags=("-w", "--wordlist", "-o", "--output", "-t", "--threads", "-x", "-H", "--delay"),
            divert_flags={
                "--proxy": _PROXY,
                # -r is --follow-redirect in dir mode and --resolver in dns
                # mode. The guard does not read the subcommand, so it refuses
                # the ambiguous spelling and names the unambiguous one.
                "-r": "is --resolver in dns mode, which sends the queries to a server of its "
                      "own (spell --follow-redirect out in full if that is what you meant)",
                "--resolver": _RESOLVER,
            },
            rate_flags=("--delay",),
            requires_optin=True,
            optin_reason="directory brute force generates heavy traffic",
        ),
        _spec("dirb", positional_targets=True, divert_flags={"-p": _PROXY}, clusters=True, requires_optin=True, optin_reason="directory brute force generates heavy traffic"),
        _spec("nikto", target_flags=("-h", "-host"), value_flags=("-o", "-Format", "-p"), divert_flags={"-useproxy": _PROXY, "-config": _CONFFILE}, requires_optin=True, optin_reason="noisy vulnerability scanner, often out of program rules"),
        _spec("wpscan", target_flags=("--url",), value_flags=("-o", "--format", "--api-token"), divert_flags={"--proxy": _PROXY}, requires_optin=True, optin_reason="noisy vulnerability scanner"),
        _spec(
            "sqlmap",
            target_flags=("-u", "--url"),
            list_flags=("-m",),
            value_flags=("--data", "--cookie", "-p", "--level", "--risk", "--dbms", "--output-dir", "--delay", "--threads"),
            divert_flags={
                "--proxy": _PROXY, "--proxy-file": _PROXY,
                "-r": _REQFILE, "-l": _REQFILE, "--logfile": _REQFILE,
                "-c": _CONFFILE, "--configfile": _CONFFILE,
                "-g": "takes its targets from a search engine", "--google-dork": "takes its targets from a search engine",
                "-x": "takes its targets from a sitemap URL", "--sitemap-url": "takes its targets from a sitemap URL",
                "--eval": _CODE,
            },
            deny_flags={
                "--tor": "routing through Tor puts the request beyond the scope check and the "
                         "request log; drop --tor and target the host directly",
            },
            requires_optin=True,
            optin_reason="automated SQL injection can mutate or dump data; bounded manual proof is preferred",
        ),
        _spec(
            "nmap",
            positional_targets=True,
            list_flags=("-iL",),
            value_flags=("-oN", "-oX", "-oG", "-oA", "-p", "--script", "-T", "--top-ports", "-e"),
            divert_flags={
                "--proxies": _PROXY, "--dns-servers": _RESOLVER,
                "-b": "bounces the scan off an FTP relay",
                "-S": "forges the source address, so the scan is attributed to someone else",
            },
            deny_flags={
                "-iR": "-iR picks its targets at random from the whole internet, which cannot "
                       "be in any program's scope; name the hosts or use -iL <file>",
            },
            requires_optin=True,
            optin_reason="port scanning is out of scope for most web programs",
        ),
        _spec("masscan", positional_targets=True, list_flags=("-iL",), value_flags=("-p", "--rate", "-oX", "-oJ"), divert_flags={"-c": _CONFFILE, "--conf": _CONFFILE, "--resume": _CONFFILE}, requires_optin=True, optin_reason="mass port scanning"),
        _spec("naabu", target_flags=("-host",), list_flags=("-l", "-list"), value_flags=("-p", "-ports", "-o", "-rate"), divert_flags={"-proxy": _PROXY, "-r": _RESOLVER, "-resolvers": _RESOLVER, "-config": _CONFFILE}, requires_optin=True, optin_reason="port scanning is out of scope for most web programs"),
        _spec("subfinder", target_flags=("-d", "-domain"), list_flags=("-dL",), value_flags=("-o", "-output", "-t", "-timeout", "-sources"), divert_flags={"-proxy": _PROXY, "-r": _RESOLVER, "-rL": _RESOLVER, "-rlist": _RESOLVER}),
        _spec("amass", target_flags=("-d",), list_flags=("-df",), value_flags=("-o", "-timeout"), divert_flags={"-config": _CONFFILE, "-r": _RESOLVER, "-rf": _RESOLVER, "-tr": _RESOLVER, "-trf": _RESOLVER}),
        _spec("dnsx", target_flags=("-d", "-domain"), list_flags=("-l", "-list"), value_flags=("-o", "-t", "-rl"), divert_flags={"-r": _RESOLVER, "-resolver": _RESOLVER, "-resolvers": _RESOLVER, "-proxy": _PROXY}, stdin_capable=True),
        _spec("puredns", positional_targets=True, value_flags=("-w", "--wordlist", "--write"), divert_flags={"-r": _RESOLVER, "--resolvers": _RESOLVER, "--resolvers-trusted": _RESOLVER}, requires_optin=True, optin_reason="DNS brute force generates heavy query volume"),
        _spec("shuffledns", target_flags=("-d",), value_flags=("-w", "-o"), divert_flags={"-r": _RESOLVER, "-list": _RESOLVER}, requires_optin=True, optin_reason="DNS brute force generates heavy query volume"),
        _spec("massdns", positional_targets=True, value_flags=("-o", "-w", "-t"), divert_flags={"-r": _RESOLVER, "--resolvers": _RESOLVER}, requires_optin=True, optin_reason="DNS brute force generates heavy query volume"),
        _spec("gau", positional_targets=True, value_flags=("-o", "--threads", "--providers"), divert_flags={"--proxy": _PROXY}, stdin_capable=True),
        _spec("waybackurls", positional_targets=True, stdin_capable=True),
        _spec("dig", positional_targets=True, value_flags=("-t", "-c", "-p")),
        _spec("host", positional_targets=True, value_flags=("-t", "-c")),
        _spec("nslookup", positional_targets=True),
        _spec("whois", positional_targets=True, divert_flags={"-h": _RESOLVER, "--host": _RESOLVER}, clusters=True),
        _spec("ping", positional_targets=True, value_flags=("-c", "-i", "-W", "-s")),
        _spec("ping6", positional_targets=True, value_flags=("-c", "-i", "-W")),
        _spec("traceroute", positional_targets=True, value_flags=("-m", "-p", "-w"), divert_flags={"-g": _TUNNEL}),
        _spec("mtr", positional_targets=True, value_flags=("-c", "-i")),
        _spec("nc", positional_targets=True, value_flags=("-w", "-p", "-s"), divert_flags={"-x": _PROXY, "--proxy": _PROXY}, clusters=True, requires_optin=True, optin_reason="raw socket access bypasses request logging"),
        _spec("ncat", positional_targets=True, value_flags=("-w", "-p", "-s"), divert_flags={"-x": _PROXY, "--proxy": _PROXY}, clusters=True, requires_optin=True, optin_reason="raw socket access bypasses request logging"),
        _spec("socat", positional_targets=True, requires_optin=True, optin_reason="raw socket access bypasses request logging"),
        _spec("telnet", positional_targets=True, requires_optin=True, optin_reason="raw socket access bypasses request logging"),
        _spec("ssh", positional_targets=True, divert_flags=_SSH_DIVERT, clusters=True, requires_optin=True, optin_reason="shell access to a target is almost never in a bug bounty scope"),
        _spec("scp", positional_targets=True, divert_flags=_SSH_DIVERT, clusters=True, requires_optin=True, optin_reason="shell access to a target is almost never in a bug bounty scope"),
        _spec("sftp", positional_targets=True, divert_flags=_SSH_DIVERT, clusters=True, requires_optin=True, optin_reason="shell access to a target is almost never in a bug bounty scope"),
        _spec("ftp", positional_targets=True, requires_optin=True, optin_reason="raw protocol access bypasses request logging"),
        _spec("smbclient", positional_targets=True, divert_flags={"-I": _PIN}, clusters=True, requires_optin=True, optin_reason="raw protocol access bypasses request logging"),
        _spec("openssl", target_flags=("-connect",), value_flags=("-servername", "-CAfile", "-cert", "-key"), divert_flags={"-proxy": _PROXY}),
        _spec("chromium", positional_targets=True, divert_flags=_BROWSER_DIVERT),
        _spec("chromium-browser", positional_targets=True, divert_flags=_BROWSER_DIVERT),
        _spec("google-chrome", positional_targets=True, divert_flags=_BROWSER_DIVERT),
        _spec("firefox", positional_targets=True),
    ]
)

# Tools that are network-capable but whose traffic the harness already owns.
ALWAYS_OK = {"bb", "bb-guard", "mitmdump", "mitmproxy", "mitmweb", "interactsh-client"}

_URLISH = re.compile(r"^(?:[a-z][a-z0-9+.-]*://|//)", re.I)
_HOSTISH = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+\.?$", re.I)


# ---------------------------------------------------------------------------
# shell parsing
# ---------------------------------------------------------------------------


def split_segments(command: str) -> list[str]:
    """Split a command line on ; && || | & and newlines, respecting quotes."""
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(command[i + 1])
            i += 2
            continue
        if ch in ";\n&|":
            segments.append("".join(buf))
            buf = []
            if i + 1 < n and command[i + 1] == ch:
                i += 2
            else:
                i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


def strip_wrappers(argv: list[str]) -> list[str]:
    """Drop env assignments and command wrappers to reach the real tool."""
    out = list(argv)
    changed = True
    while changed and out:
        changed = False
        while out and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", out[0]):
            out.pop(0)
            changed = True
        if not out:
            break
        base = os.path.basename(out[0])
        spec = WRAPPERS.get(base)
        if spec is None:
            break
        out.pop(0)
        changed = True
        taken = 0
        while out:
            tok = out[0]
            if tok in spec["flagsets"]:
                out.pop(0)
                if out:
                    out.pop(0)
                continue
            if tok.startswith("-") and tok != "--":
                out.pop(0)
                continue
            if tok == "--":
                out.pop(0)
                break
            if taken < spec.get("positional", 0):
                out.pop(0)
                taken += 1
                continue
            break
    return out


def tokenize(segment: str) -> list[str] | None:
    try:
        return shlex.split(segment, comments=True)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# target extraction
# ---------------------------------------------------------------------------


def looks_like_target(token: str) -> bool:
    if not token or token.startswith("-"):
        return False
    if _URLISH.match(token):
        return True
    head = token.split("/", 1)[0].split("?", 1)[0]
    head = head.rsplit("@", 1)[-1]
    head = head.split(":", 1)[0]
    return bool(_HOSTISH.match(head)) or bool(normalize_host(head) and head.count(".") >= 1)


def unresolvable(token: str) -> bool:
    return any(m in token for m in UNRESOLVABLE) or bool(re.search(r"\$[A-Za-z_{]", token))


def read_list_file(raw: str, cwd: Path) -> tuple[list[str], str | None]:
    """Read a targets file. Returns (targets, error)."""
    p = Path(raw)
    if not p.is_absolute():
        p = cwd / p
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], f"cannot read target list {raw!r}: {exc.strerror or exc}"
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line.split()[0])
    if not out:
        return [], f"target list {raw!r} is empty; nothing to verify"
    return out, None


def _divert_problem(flag: str, what: str, value: str) -> str:
    """One refusal for a flag that decides where the traffic goes."""
    shown = f"{flag} {value}".strip()
    return (
        f"{flag} {what}; the guard cannot check where that sends it, and the audit line "
        f"would still record the target you passed as contacted -- a record naming a host "
        f"the packets never reached is worse than no record.\n"
        f"    fix: drop `{shown}` and run the command again"
    )


def _cluster_hit(spec: ToolSpec, token: str) -> tuple[str, str] | None:
    """A bundled short option hiding a denied flag: `curl -sSx <proxy>`.

    Only consulted for a token no table matched, and only on tools that bundle
    at all, so a Go-style `-rl` is never read as `-r -l`.
    """
    if not spec.clusters or len(token) < 3 or token.startswith("--"):
        return None
    for letter in token[1:]:
        flag = f"-{letter}"
        if flag in spec.divert_flags:
            return flag, spec.divert_flags[flag]
        if flag in spec.deny_flags:
            return flag, ""
    return None


def extract_targets(
    spec: ToolSpec, argv: list[str], cwd: Path
) -> tuple[list[str], list[str], list[str]]:
    """Return (targets, problems, flags_seen) for one tool invocation."""
    targets: list[str] = []
    problems: list[str] = []
    flags: list[str] = []
    args = argv[1:]
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            i += 1
            while i < len(args):
                if spec.positional_targets and looks_like_target(args[i]):
                    targets.append(args[i])
                i += 1
            break

        if tok.startswith("-"):
            flags.append(tok)
            name, _, inline = tok.partition("=")
            if name in spec.deny_flags:
                problems.append(spec.deny_flags[name])
                i += 1
                continue
            if name in spec.divert_flags:
                value = inline if inline else (args[i + 1] if i + 1 < len(args) else "")
                if not inline and i + 1 < len(args):
                    i += 1
                problems.append(_divert_problem(name, spec.divert_flags[name], value))
                i += 1
                continue
            if name in spec.target_flags:
                value = inline if inline else (args[i + 1] if i + 1 < len(args) else "")
                if not inline:
                    i += 1
                if not value:
                    problems.append(f"{name} has no value")
                elif unresolvable(value):
                    problems.append(
                        f"{name} value {value!r} contains a shell variable or substitution; "
                        "the guard cannot verify it. Write the literal target."
                    )
                else:
                    targets.extend(v for v in re.split(r"[,\s]+", value) if v)
                i += 1
                continue
            if name in spec.list_flags:
                value = inline if inline else (args[i + 1] if i + 1 < len(args) else "")
                if not inline:
                    i += 1
                if unresolvable(value):
                    problems.append(f"{name} path {value!r} is not statically resolvable")
                else:
                    listed, err = read_list_file(value, cwd)
                    if err:
                        problems.append(err)
                    targets.extend(listed)
                i += 1
                continue
            if name in spec.value_flags:
                if not inline and i + 1 < len(args):
                    i += 1
                i += 1
                continue
            hit = _cluster_hit(spec, name)
            if hit:
                flag, what = hit
                detail = _divert_problem(flag, what, "") if what else spec.deny_flags[flag]
                problems.append(f"{detail}\n    ({flag} is bundled into {name})")
            i += 1
            continue

        if spec.positional_targets and looks_like_target(tok):
            if unresolvable(tok):
                problems.append(
                    f"target {tok!r} contains a shell variable or substitution; "
                    "the guard cannot verify it. Write the literal target."
                )
            else:
                targets.append(tok)
        i += 1

    return targets, problems, flags


def _rate_ok(spec: ToolSpec, argv: list[str], max_rps: float) -> str | None:
    """Return a problem string when a required rate limit is missing or too high."""
    if not spec.rate_flags:
        return None
    args = argv[1:]
    for i, tok in enumerate(args):
        name, _, inline = tok.partition("=")
        if name in spec.rate_flags:
            value = inline or (args[i + 1] if i + 1 < len(args) else "")
            try:
                given = float(value)
            except ValueError:
                return f"{name} value {value!r} is not a number"
            if name == "--delay":  # gobuster: a delay, not a rate
                return None
            if given > max_rps:
                return (
                    f"{name} {given} exceeds the engagement limit of {max_rps} req/s; "
                    f"use {spec.rate_flags[0]} {int(max_rps) or 1}"
                )
            return None
    return (
        f"{spec.name} must be rate limited for this engagement: add "
        f"{spec.rate_flags[0]} {int(max_rps) or 1} (limit is {max_rps} req/s)"
    )


# ---------------------------------------------------------------------------
# script inspection
# ---------------------------------------------------------------------------
#
# The exemption for a script that uses the sanctioned client used to be a
# substring search over the whole body, so `python3 -c "import requests  # bb
# req"` skipped the check entirely, as did a string literal, a variable name or
# a first-line comment in a file. That is the one path by which a prompt
# injection in a fenced response body turns into an out-of-scope request: the
# fence stops the text being obeyed as instructions, but a persuaded agent
# writing a script with a harmless-looking comment walked straight through.
#
# So Python is read as Python. `ast` is in the standard library, an import is a
# node rather than a run of characters, and a body that will not parse is
# refused rather than waved past. Importing `bbh` no longer excuses anything
# else: what clears a script is the absence of a raw client, of a shell-out and
# of an `exec` the guard cannot read -- not the presence of a blessed name.
# Without those last two the parse check would be one `exec("import requests")`
# or one `subprocess.run(["curl", ...])` away from meaning nothing.
#
# The other runners get no exemption at all, because an honest one is not
# available: `bbh.http` is a Python package, so a node or ruby script cannot
# call it, and the only sanctioned route from them is shelling out to `bb req`
# -- which the guard would have to find inside a string to believe. With no
# parser it cannot tell a call from a comment that names one, and between
# refusing a legitimate script and clearing a hostile one, the first costs a
# rephrase and says so in the message.


SESSION_SNIPPET = (
    # actor is mandatory: a Session() with none is refused at request time, so
    # a remedy that omits it sends the agent round again.
    "from bbh.http import Session; s = Session(actor='anon'); r = s.get('https://host/path')"
)
SESSION_FIX = f"use the recorded client -- {SESSION_SNIPPET}"
SHELL_FIX = "run that command directly in Bash, where the guard can read it"


def _dotted_name(node: ast.AST) -> str:
    """The source spelling of an attribute chain, or "" if it is not one."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _net_module(name: str) -> str | None:
    """The PY_NET_MODULES entry `name` imports, if any. Dotted, not textual."""
    for mod in PY_NET_MODULES:
        if name == mod or name.startswith(mod + "."):
            return mod
    return None


def _python_problems(body: str) -> list[tuple[str, str]]:
    """(what is wrong, how to fix it) for one parsed Python body. May raise."""
    found: dict[str, str] = {}

    def note(what: str, how: str) -> None:
        found.setdefault(what, how)

    def note_module(name: str) -> None:
        mod = _net_module(name)
        if mod:
            note(f"it imports {mod}, which opens its own connections", SESSION_FIX)
            return
        root = name.split(".", 1)[0]
        if root in PY_SHELL_MODULES:
            note(f"it imports {root}, which runs a command this guard never sees", SHELL_FIX)

    for node in ast.walk(ast.parse(body)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                note_module(alias.name)
        elif isinstance(node, ast.ImportFrom):
            # A relative import binds nothing the guard can name, so it is left
            # alone; for an absolute one both the package and each name it pulls
            # out are checked, since `from urllib import request` is an import
            # of urllib.request however it is spelled.
            if node.level == 0 and node.module:
                note_module(node.module)
                for alias in node.names:
                    note_module(f"{node.module}.{alias.name}")
        elif isinstance(node, ast.Call):
            name = _dotted_name(node.func)
            if name in PY_DYNAMIC_IMPORTS:
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    note_module(arg.value)
                else:
                    note(
                        f"it imports a module the guard cannot name ({name}(...))",
                        "name the module in a plain `import` statement",
                    )
            elif name in PY_OPAQUE_CALLS:
                note(
                    f"it runs code the guard cannot read ({name}(...))",
                    f"inline the code so the guard can read it, and drop the {name}()",
                )
            elif name in PY_SHELL_CALLS or name.startswith(PY_SHELL_CALL_PREFIXES):
                note(f"it runs a command this guard never sees ({name}(...))", SHELL_FIX)
    return list(found.items())


def _python_problem(body: str) -> str | None:
    """Refuse a Python body that can reach the network outside the client."""
    try:
        problems = _python_problems(body)
    except (SyntaxError, ValueError, RecursionError) as exc:
        said = getattr(exc, "msg", None) or str(exc)
        where = f", line {exc.lineno}" if isinstance(exc, SyntaxError) and exc.lineno else ""
        return (
            f"this does not parse as Python ({said}{where}), so the guard cannot tell "
            f"whether it drives the network itself, and a script it cannot read is one it "
            f"cannot clear.\n"
            f"    fix: correct it and run it again -- `python3 -m py_compile <file>` prints "
            f"the same error with context"
        )
    if not problems:
        return None
    detail = "\n".join(f"  - {what}\n    fix: {how}" for what, how in problems)
    return (
        "this script can reach the network outside the sanctioned client, which bypasses "
        f"scope checking, rate limiting and request logging:\n{detail}\n"
        "Local-only scripts that touch no network are unaffected."
    )


# Shell redirections survive tokenizing as plain argv entries. One that feeds
# stdin is where the program text would come from, so it is refused; one that
# only captures output is stepped over, or `python3 2>/dev/null probe.py` would
# be refused for the wrong token.
_STDIN_REDIRECT = re.compile(r"^\d*<")
_OUTPUT_REDIRECT = re.compile(r"^\d*>")


def _read_script(raw: str, cwd: Path) -> tuple[str, str | None]:
    """(text, oserror) for a script path, resolved against the hook's cwd."""
    p = Path(raw)
    if not p.is_absolute():
        p = cwd / p
    try:
        return p.read_text(encoding="utf-8", errors="replace"), None
    except OSError as exc:
        return "", (exc.strerror or str(exc))


def _script_body(argv: list[str], cwd: Path) -> tuple[str, str | None]:
    """(program text, problem) for one interpreter invocation. Both may be empty."""
    family = RUNNER_FAMILY[os.path.basename(argv[0])]
    args = argv[1:]
    bodies: list[str] = []
    i = 0
    while i < len(args):
        tok = args[i]
        name, eq, inline = tok.partition("=")
        if name in BODY_FLAGS[family]:
            if eq:
                bodies.append(inline)
            elif i + 1 < len(args):
                bodies.append(args[i + 1])
                i += 1
            i += 1
            if family == "python":
                break  # python stops reading its own options after -c
            continue  # perl and node take more than one, and concatenate them
        if family == "python" and name in PY_VALUE_FLAGS:
            if name == "-m":
                # `-m` runs a module off the import path: the code is not on the
                # command line at all, and the guard does not resolve imports.
                # Left as a known gap rather than guessed at -- refusing it would
                # refuse `python3 -m pytest` for a reason nobody can act on.
                return "", None
            if not eq and i + 1 < len(args):
                i += 1
            i += 1
            continue
        if _OUTPUT_REDIRECT.match(tok):
            i += 2 if tok.endswith(">") else 1  # `> out` is two tokens, `2>out` one
            continue
        if tok.startswith("-") and tok != "-":
            i += 1
            continue
        break

    if bodies:
        return "\n".join(bodies), None
    if i >= len(args):
        return "", None  # an interactive interpreter: no program to inspect

    tok = args[i]
    if family != "python":
        # Flags like node's `-r <module>` or perl's `-M <module>` are not
        # modelled, so this token may not be a script path at all. Reading one
        # when it is is worth having; refusing when it is not would refuse
        # working commands for a reason the agent cannot act on.
        return _read_script(tok, cwd)[0], None

    if tok == "-" or _STDIN_REDIRECT.match(tok):
        return "", (
            "this script arrives on stdin, which the guard cannot read, so it cannot tell "
            "whether the script drives the network itself.\n"
            "    fix: put it in a file and run `python3 <file>`, or pass it inline with "
            "`python3 -c '<code>'`"
        )
    text, err = _read_script(tok, cwd)
    if err:
        return "", (
            f"the guard cannot read the script {tok!r} ({err}), so it cannot tell whether it "
            f"drives the network itself, and a script it cannot read is one it cannot clear.\n"
            f"    fix: run it by a path that exists from {str(cwd)!r}"
        )
    return text, None


def inspect_script(argv: list[str], cwd: Path) -> str | None:
    """Deny raw network use from inline or file scripts; point at the client.

    Python is parsed, so the exemption rests on what the script imports rather
    than on what it mentions, and a body that will not parse is refused. The
    other runners have no parser here and therefore no exemption at all: a
    network or shell call in one is denied, and the message says to write the
    probe in Python or make the request with `bb req`.

    Known gaps, which belong to the network namespace rather than to static
    analysis: `python3 -m <module>` runs code that is not on the command line,
    a heredoc or a pipe feeding a non-python runner is invisible, and a
    subcommand runner like `deno run x.ts` hides the script behind a verb.
    """
    base = os.path.basename(argv[0])
    family = RUNNER_FAMILY.get(base)
    if family is None:
        return None

    body, problem = _script_body(argv, cwd)
    if problem:
        return problem
    if not body.strip():
        return None

    if family == "python":
        return _python_problem(body)

    match = NON_PY_NET[family].search(body)
    if match is None:
        return None
    return (
        f"this script reaches the network or the shell itself (`{match.group(0).strip()}`), "
        f"which bypasses scope checking, rate limiting and request logging. There is no "
        f"sanctioned-client exemption for {base}: the client is a Python package, and with no "
        f"{base} parser the guard cannot tell a call from a comment that names one.\n"
        f"    fix: make the request with `bb req https://host/path`, or write the probe in "
        f'Python -- python3 -c "{SESSION_SNIPPET}"\n'
        "Local-only scripts that touch no network are unaffected."
    )


# ---------------------------------------------------------------------------
# the check
# ---------------------------------------------------------------------------


@dataclass
class GuardResult:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    tool: str | None = None

    def message(self) -> str:
        return "\n".join(self.reasons)


def _load_scope() -> tuple[Scope | None, str | None]:
    name = paths.active_engagement()
    if not name:
        return None, (
            "no engagement is selected, so no target is authorized.\n"
            "  bb list                 # engagements on this machine\n"
            "  bb use <engagement>     # select one\n"
            "  bb arm <engagement>     # attest authorization (expires)\n"
            "To read public pages for research, use the WebFetch or WebSearch tool instead of curl."
        )
    lock = paths.lock_path(name)
    if not lock.exists():
        return None, f"engagement {name!r} has no compiled scope. Run: bb scope compile {name}"
    try:
        return Scope.from_lock_file(lock), None
    except (ScopeError, OSError, json.JSONDecodeError) as exc:
        return None, f"engagement {name!r} has an unusable scope lock: {exc}"


def _dev_socket_problems(segment: str) -> list[str]:
    """Every `/dev/tcp` or `/dev/udp` redirection in one segment, as denials.

    Denied whatever the host is, including an in-scope one. The sanctioned
    client is not only where the scope check lives -- it is where the rate
    limit, the redirect-hop checking and the *recording* live, and an
    unrecorded request cannot be cited as evidence later. A finding whose
    reproduction rests on a request that is in no one's log is a finding that
    dies at the gate, so allowing this would cost the hunt work rather than
    save it. Same reasoning as a script importing `socket` directly.
    """
    problems: list[str] = []
    advice = (
        "Use the sanctioned client instead -- it is recorded, rate-limited and "
        "scope-checked:\n"
        "  bb req https://<host>/\n"
        "If you need a raw socket to prove something about the protocol itself, that is a "
        "real limitation rather than something to work around: say so in the handoff and "
        "record it with `bb angle add <surface> <class> <technique> blocked --note '<what "
        "stopped you>'`, so it reads as untested instead of as clean."
    )
    for prefix in DEV_SOCKET_PREFIX.finditer(segment):
        match = DEV_SOCKET.match(segment, prefix.start())
        if match is None or unresolvable(match.group("host")):
            problems.append(
                f"this names bash's socket redirection, which opens a network connection "
                f"directly, and the host it would connect to cannot be read from the "
                f"command:\n  {segment.strip()[:200]}\n"
                f"So scope cannot be verified, and the connection would be in no request "
                f"log.\n{advice}"
            )
            continue
        proto = match.group("proto")
        host = match.group("host")
        port = match.group("port") or "?"
        problems.append(
            f"this opens a raw {proto.upper()} socket to {host}:{port} with bash's "
            f"/dev/{proto} redirection, which bypasses the scope check, the rate limit "
            f"and the request log. A request nothing recorded cannot be cited as "
            f"evidence, so a finding built on one dies at the gates.\n"
            f"{advice.replace('<host>', host)}"
        )
    return problems


def check_command(command: str, cwd: Path, scope_loader=_load_scope) -> GuardResult:
    """Decide one Bash command."""
    segments = split_segments(command)
    scope: Scope | None = None
    scope_error: str | None = None
    loaded = False

    result = GuardResult(allowed=True)

    for segment in segments:
        # Before tokenizing: a socket redirection is syntax, so it survives
        # quoting this guard cannot parse, and it has no argv[0] to match.
        for socket_problem in _dev_socket_problems(segment):
            result.allowed = False
            result.tool = result.tool or "/dev/tcp"
            result.reasons.append(socket_problem)

        argv = tokenize(segment)
        if argv is None:
            # Unparseable quoting. Only a problem if it mentions a net tool.
            if any(re.search(rf"\b{re.escape(t)}\b", segment) for t in NET_TOOLS):
                result.allowed = False
                result.reasons.append(
                    f"could not parse this command safely, and it names a network tool:\n"
                    f"  {segment.strip()[:200]}\n"
                    "Rewrite it as a simple command with literal, quoted targets."
                )
            continue

        argv = strip_wrappers(argv)
        if not argv:
            continue

        base = os.path.basename(argv[0])
        if base in ALWAYS_OK:
            continue

        script_problem = inspect_script(argv, cwd)
        if script_problem:
            result.allowed = False
            result.tool = base
            result.reasons.append(script_problem)
            continue

        spec = NET_TOOLS.get(base)
        if spec is None:
            continue

        result.tool = base
        if not loaded:
            scope, scope_error = scope_loader()
            loaded = True
        if scope is None:
            result.allowed = False
            result.reasons.append(f"{base}: {scope_error}")
            continue

        auth_problem = scope.authorization_error()
        if auth_problem:
            result.allowed = False
            result.reasons.append(f"{base}: {auth_problem}")
            continue

        if spec.requires_optin and spec.name not in scope.rules.get("allow_tools", []):
            result.allowed = False
            result.reasons.append(
                f"{base} is not enabled for engagement {scope.engagement!r} "
                f"({spec.optin_reason}).\n"
                f"If the program's rules permit it, add it to scope.yaml:\n"
                f"  rules:\n    allow_tools: [{spec.name}]\n"
                f"then: bb scope compile {scope.engagement}"
            )
            continue

        targets, problems, _flags = extract_targets(spec, argv, cwd)

        if not targets:
            hint = (
                " It appears to read targets from stdin; the guard cannot see those."
                if spec.stdin_capable
                else ""
            )
            problems.append(
                f"no target could be extracted from this command, so scope cannot be "
                f"verified.{hint} Pass the target explicitly on the command line."
            )

        rate_problem = _rate_ok(spec, argv, float(scope.rules.get("max_rps", 2.0)))
        if rate_problem:
            problems.append(rate_problem)

        # Report every problem at once: an unattended agent should need one correction,
        # not one round trip per defect.
        if problems:
            result.allowed = False
            result.reasons.extend(f"{base}: {p}" for p in problems)
            continue

        for raw in targets:
            decision = scope.decide(raw)
            result.checked.append(f"{'ok ' if decision.allowed else 'DENY'} {decision.target}")
            if not decision.allowed:
                result.allowed = False
                result.reasons.append(f"{base}: {decision.reason}")

    if not result.allowed and result.tool:
        result.reasons.append(
            "\nThis is the scope guard, not a permission prompt. Fix the target or the "
            "engagement scope; do not try to work around it."
        )
    return result


# ---------------------------------------------------------------------------
# hook entrypoint
# ---------------------------------------------------------------------------


def _audit(payload: dict, result: GuardResult) -> None:
    """Record the decision, hash chained onto the line before it.

    Through cli.audit_record, so that editing this line afterwards breaks the
    chain the next line records and `bb doctor --verify-chain` finds it. The
    import is deferred because bbh.cli imports this module: the hook's own load
    path must not depend on the CLI being importable, and a flat append is kept
    as the fallback, since a decision that is recorded unchained still beats a
    decision that is not recorded at all.
    """
    try:
        paths.STATE_DIR.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "engagement": paths.active_engagement(),
            "session": payload.get("session_id"),
            "tool": result.tool,
            "allowed": result.allowed,
            "command": (payload.get("tool_input") or {}).get("command", "")[:2000],
            "checked": result.checked,
            "reasons": result.reasons if not result.allowed else [],
        }
    except Exception:
        return  # auditing must never break the hook
    try:
        from bbh.cli import audit_record

        if audit_record("guard_decision", record):
            return
    except Exception:
        pass  # fall through to the plain append below
    try:
        with paths.AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass  # auditing must never break the hook


def main(argv: list[str] | None = None) -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # malformed hook input: stay out of the way

    if payload.get("tool_name") not in ("Bash", "BashOutput"):
        return 0

    command = (payload.get("tool_input") or {}).get("command") or ""
    if not command.strip():
        return 0

    cwd = Path(payload.get("cwd") or os.getcwd())

    try:
        result = check_command(command, cwd)
    except Exception as exc:  # a crashed guard must not silently allow
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"scope guard crashed ({type(exc).__name__}: {exc}); "
                            "denying by default. Report this."
                        ),
                    }
                }
            )
        )
        return 0

    if result.tool:
        _audit(payload, result)

    if result.allowed:
        return 0

    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "[scope guard] " + result.message(),
                }
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
