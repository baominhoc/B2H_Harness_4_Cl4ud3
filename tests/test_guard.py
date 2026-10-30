"""The PreToolUse guard: static scope enforcement on shell commands.

The guard is the layer that runs before anything executes, so its failure mode
matters more than its coverage: it must fail closed on everything it cannot
read statically. Each test here is one way an unattended agent could get a
request out past it.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from bbh import guard, paths
from conftest import make_scope


@pytest.fixture
def check(tmp_path):
    """check(command, **scope_kw) -> GuardResult, against an in-memory scope."""
    scope_cache: dict = {}

    def _check(command: str, cwd: Path | None = None, **scope_kw):
        key = tuple(sorted((k, str(v)) for k, v in scope_kw.items()))
        if key not in scope_cache:
            scope_cache[key] = make_scope(**scope_kw) if scope_kw else make_scope()
        scope = scope_cache[key]
        return guard.check_command(command, cwd or tmp_path, scope_loader=lambda: (scope, None))

    return _check


# -- literal allow and deny --------------------------------------------------


def test_in_scope_curl_is_allowed(check):
    result = check("curl -sS https://www.acme.example/login")
    assert result.allowed
    assert result.checked == ["ok  www.acme.example"]


def test_out_of_scope_curl_is_denied(check):
    result = check("curl -sS https://evil.example/")
    assert not result.allowed
    assert "not in the scope" in result.message()


def test_a_denial_says_it_is_not_a_permission_prompt(check):
    """The agent must not read a deny as something to retry past."""
    message = check("curl https://evil.example/").message()
    assert "not a permission prompt" in message
    assert "do not try to work around it" in message


def test_one_out_of_scope_host_denies_the_whole_command(check):
    result = check("curl https://www.acme.example/ https://evil.example/")
    assert not result.allowed


def test_both_segments_of_a_chain_are_checked(check):
    assert not check("curl https://www.acme.example/ && curl https://evil.example/").allowed


# -- unresolvable targets fail closed ----------------------------------------


def test_variable_inside_a_url_is_denied(check):
    result = check("curl https://$HOST/path")
    assert not result.allowed
    assert "shell variable or substitution" in result.message()


def test_bare_variable_target_is_denied(check):
    result = check("curl $TARGET")
    assert not result.allowed
    assert "no target could be extracted" in result.message()


def test_command_substitution_is_denied(check):
    result = check('curl "https://$(cat hosts.txt)/"')
    assert not result.allowed
    assert "shell variable or substitution" in result.message()


def test_backtick_substitution_is_denied(check):
    assert not check("curl `echo www`.acme.example").allowed


def test_brace_expansion_variable_is_denied(check):
    assert not check("curl https://${HOST}/x").allowed


def test_pipe_to_stdin_is_denied_with_a_stdin_hint(check):
    result = check("cat hosts.txt | httpx -rl 1")
    assert not result.allowed
    assert "read targets from stdin" in result.message()


def test_unparseable_quoting_naming_a_net_tool_is_denied(check):
    result = check("curl 'https://www.acme.example/unclosed")
    assert not result.allowed
    assert "could not parse this command safely" in result.message()


def test_unparseable_quoting_without_a_net_tool_is_left_alone(check):
    assert check("echo 'unterminated").allowed


# -- target list files -------------------------------------------------------


def test_list_file_is_read_and_every_entry_checked(check, tmp_path):
    listing = tmp_path / "targets.txt"
    listing.write_text(
        "# comment\nwww.acme.example\n\napi.acme.example\n", encoding="utf-8"
    )
    result = check("httpx -l targets.txt -rl 1", cwd=tmp_path)
    assert result.allowed
    assert len(result.checked) == 2


def test_an_out_of_scope_entry_in_a_list_file_denies_the_command(check, tmp_path):
    listing = tmp_path / "targets.txt"
    listing.write_text("www.acme.example\nevil.example\n", encoding="utf-8")
    result = check("httpx -l targets.txt -rl 1", cwd=tmp_path)
    assert not result.allowed
    assert "evil.example" in result.message()


def test_a_missing_list_file_is_denied_not_ignored(check, tmp_path):
    result = check("httpx -l nope.txt -rl 1", cwd=tmp_path)
    assert not result.allowed
    assert "cannot read target list" in result.message()


def test_an_empty_list_file_is_denied(check, tmp_path):
    (tmp_path / "empty.txt").write_text("\n# only a comment\n", encoding="utf-8")
    result = check("httpx -l empty.txt -rl 1", cwd=tmp_path)
    assert not result.allowed
    assert "is empty" in result.message()


# -- rate limiting -----------------------------------------------------------


def test_scanner_without_a_rate_flag_is_denied(check):
    result = check("httpx -u https://www.acme.example/")
    assert not result.allowed
    assert "must be rate limited" in result.message()


def test_scanner_above_the_engagement_rate_is_denied(check):
    result = check("httpx -u https://www.acme.example/ -rl 50")
    assert not result.allowed
    assert "exceeds the engagement limit" in result.message()


def test_scanner_at_or_under_the_rate_is_allowed(check):
    assert check("httpx -u https://www.acme.example/ -rl 1").allowed


def test_rate_flag_is_read_from_an_inline_value(check):
    assert check("httpx -u https://www.acme.example/ -rl=2").allowed


def test_non_numeric_rate_flag_is_denied(check):
    result = check("httpx -u https://www.acme.example/ -rl fast")
    assert not result.allowed
    assert "is not a number" in result.message()


def test_the_rate_ceiling_follows_the_engagement(check):
    """A program that allows 10 rps should not have its scanners refused."""
    assert check(
        "httpx -u https://www.acme.example/ -rl 8", rules={"max_rps": 10.0}
    ).allowed


# -- opt-in tools ------------------------------------------------------------


def test_opt_in_tool_is_denied_by_default(check):
    result = check("sqlmap -u https://www.acme.example/?id=1")
    assert not result.allowed
    assert "is not enabled for engagement" in result.message()
    assert "allow_tools" in result.message()


def test_opt_in_tool_is_allowed_once_listed(check):
    assert check(
        "sqlmap -u https://www.acme.example/?id=1", rules={"allow_tools": ["sqlmap"]}
    ).allowed


def test_opt_in_is_checked_before_the_target(check):
    """Even an in-scope target does not buy an un-opted-in scanner."""
    assert not check("nmap www.acme.example").allowed


# -- wrappers ----------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "sudo curl https://evil.example/",
        "sudo -u nobody curl https://evil.example/",
        "timeout 30 curl https://evil.example/",
        "timeout -k 5 30 curl https://evil.example/",
        "env FOO=bar curl https://evil.example/",
        "FOO=bar BAZ=qux curl https://evil.example/",
        "nohup curl https://evil.example/",
        "nice -n 10 curl https://evil.example/",
        "stdbuf -o0 curl https://evil.example/",
    ],
)
def test_wrappers_do_not_hide_the_tool_from_the_guard(check, command):
    assert not check(command).allowed, command


def test_wrappers_still_allow_an_in_scope_target(check):
    assert check("timeout 30 curl https://www.acme.example/").allowed
    assert check("sudo curl https://www.acme.example/").allowed


def test_strip_wrappers_reaches_the_real_argv():
    assert guard.strip_wrappers(["FOO=1", "sudo", "-u", "x", "curl", "u"]) == ["curl", "u"]
    assert guard.strip_wrappers(["timeout", "30", "curl", "u"]) == ["curl", "u"]


# -- non-network commands ----------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status && git diff",
        "grep -rn 'token' .",
        "cat notes.md | wc -l",
        "jq '.hosts' handoff/00-recon.json",
        "bb finding list",
    ],
)
def test_commands_with_no_network_tool_are_untouched(check, command):
    result = check(command)
    assert result.allowed
    assert result.tool is None, command


def test_the_harness_own_tools_are_never_blocked(check):
    assert check("bb req GET https://evil.example/").allowed, (
        "bb does its own scope check; double-checking here would misparse its argv"
    )


# -- bash's own socket, which has no argv to parse ---------------------------
#
# This was a measured hole, not a hypothetical one: `exec 3<>/dev/tcp/host/80`
# passed the guard silently, because the table-driven path keys on argv[0] and a
# redirection has none. The network namespace was separately measured closing
# it. These tests are about the guard still *naming* it, so an agent that tries
# learns why instead of reading a connection error as a dead target.


@pytest.mark.parametrize(
    "command,host",
    [
        ("exec 3<>/dev/tcp/evil.example.com/80", "evil.example.com"),
        ("cat < /dev/tcp/1.2.3.4/22", "1.2.3.4"),
        ("echo probe > /dev/udp/evil.example.com/53", "evil.example.com"),
        ("exec {fd}<>/dev/tcp/evil.example.com/8080", "evil.example.com"),
    ],
)
def test_a_socket_redirection_is_denied_and_the_host_is_named(check, command, host):
    result = check(command)
    assert not result.allowed, command
    assert host in " ".join(result.reasons)
    assert "bb req" in " ".join(result.reasons), "the denial must name the way to do it"


def test_a_socket_redirection_to_an_in_scope_host_is_still_denied(check):
    """Scope is not the only thing the sanctioned client is for.

    An in-scope raw socket is still unrecorded and unrated, and an unrecorded
    request cannot be cited as evidence -- so a finding built on one dies at the
    gates anyway. Denying here costs the hunt one rephrase; allowing it costs a
    whole finding, late, with the reason hard to see.
    """
    result = check("exec 3<>/dev/tcp/app.example.com/443", in_scope=["*.example.com"])
    assert not result.allowed
    assert "request log" in " ".join(result.reasons)


@pytest.mark.parametrize(
    "command",
    [
        'exec 3<>/dev/tcp/$(hostname -f)/80',
        "exec 3<>/dev/tcp/${TARGET}/80",
        "exec 3<>/dev/udp/$H/53",
    ],
)
def test_a_socket_whose_host_cannot_be_read_fails_closed(check, command):
    result = check(command)
    assert not result.allowed, command
    assert "cannot be read" in " ".join(result.reasons)


@pytest.mark.parametrize(
    "command",
    [
        "echo /dev/tcpsomething",          # not the socket path at all
        "ls /dev/tty",
        "cat /dev/null",
    ],
)
def test_the_socket_check_does_not_fire_on_look_alikes(check, command):
    assert check(command).allowed, command


def test_searching_for_the_literal_string_is_denied_and_that_is_accepted(check):
    """Documenting a known false positive rather than leaving it undiscovered.

    Keying on the path prefix is what catches an unparseable host, and the cost
    is that grepping for the literal `/dev/tcp/` trips it too. The message tells
    the agent what to do in one line, so this is the cheaper direction.
    """
    result = check('grep -rn "/dev/tcp/" notes/')
    assert not result.allowed


# -- flags that decide where the packets go ----------------------------------
#
# Measured: `curl -x http://evil/ https://www.acme.example/` was ALLOWED, and
# the audit line it wrote was `{'tool': 'curl', 'allowed': True, 'checked':
# ['ok  www.acme.example']}` -- affirmatively naming a host the packets never
# reached. `-x`, `--proxy` and `--resolve` sat in curl's `value_flags`, where a
# value is skipped as "not a target" rather than checked or refused.


@pytest.mark.parametrize(
    "command",
    [
        "curl -x http://evil.example.net:8080 https://www.acme.example/",
        "curl --proxy socks5://evil.example.net:1080 https://www.acme.example/",
        "curl --proxy=http://evil.example.net:8080 https://www.acme.example/",
        "curl --preproxy socks5://evil.example.net:1080 https://www.acme.example/",
        "curl --socks5 evil.example.net:1080 https://www.acme.example/",
        "curl --resolve www.acme.example:443:203.0.113.9 https://www.acme.example/",
        "curl --connect-to www.acme.example:443:evil.example.net:443 https://www.acme.example/",
        "curl --dns-servers 203.0.113.9 https://www.acme.example/",
        "curl -K /tmp/curlrc https://www.acme.example/",
    ],
)
def test_a_flag_that_redirects_the_request_is_denied(check, command):
    assert not check(command).allowed, command


def test_a_redirected_request_is_not_recorded_as_having_reached_the_target(check):
    """The reason this is worse than saying nothing.

    A skipped proxy left `checked` claiming the in-scope host was contacted, so
    the audit log asserted a request that never happened to a host that never
    saw one. Nothing downstream can tell that line from a true one.
    """
    result = check("curl -x http://evil.example.net:8080 https://www.acme.example/")
    assert not result.allowed
    assert result.checked == [], "a refused command contacted nothing; claim nothing"


def test_the_refusal_names_the_exact_text_to_delete(check):
    message = check("curl -x http://evil.example.net:8080 https://www.acme.example/").message()
    assert "drop `-x http://evil.example.net:8080`" in message
    assert "worse than no record" in message, "the refusal says why it matters"


@pytest.mark.parametrize(
    "command",
    [
        "wget -e http_proxy=http://evil.example.net:8080 https://www.acme.example/",
        "wget --config=/tmp/wgetrc https://www.acme.example/",
        "httpx -u https://www.acme.example/ -rl 1 -proxy http://evil.example.net:8080",
        "httpx -u https://www.acme.example/ -rl 1 -r 203.0.113.9",
        "nuclei -u https://www.acme.example/ -rl 1 -p http://evil.example.net:8080",
        "katana -u https://www.acme.example/ -rl 1 -proxy http://evil.example.net:8080",
        "ffuf -u https://www.acme.example/FUZZ -w w.txt -rate 1 -x http://evil.example.net:8080",
        "nikto -h www.acme.example -useproxy http://evil.example.net:8080",
        "wpscan --url https://www.acme.example/ --proxy http://evil.example.net:8080",
        "sqlmap -u https://www.acme.example/?id=1 --proxy http://evil.example.net:8080",
        "nmap --dns-servers 203.0.113.9 www.acme.example",
        "naabu -host www.acme.example -proxy http://evil.example.net:8080",
        "subfinder -d acme.example -r 203.0.113.9",
        "dnsx -d acme.example -r 203.0.113.9",
        "whois -h evil.example.net acme.example",
        "openssl s_client -connect www.acme.example:443 -proxy evil.example.net:8080",
        "ssh -L 9000:evil.example.net:80 www.acme.example",
        "chromium --proxy-server=http://evil.example.net:8080 https://www.acme.example/",
    ],
)
def test_the_same_hole_is_closed_in_every_other_tool(check, command):
    """One audit, not one fix: the class is the flag, not the tool."""
    every_tool = {"allow_tools": sorted(guard.NET_TOOLS)}
    result = check(command, rules=every_tool)
    assert not result.allowed, command
    assert result.checked == [], command


@pytest.mark.parametrize(
    "name", sorted(n for n, s in guard.NET_TOOLS.items() if s.divert_flags)
)
def test_every_declared_divert_flag_refuses_and_names_itself(check, name):
    every_tool = {"allow_tools": sorted(guard.NET_TOOLS)}
    for flag in guard.NET_TOOLS[name].divert_flags:
        result = check(
            f"{name} {flag} 203.0.113.9 https://www.acme.example/", rules=every_tool
        )
        assert not result.allowed, f"{name} {flag}"
        assert flag in result.message(), f"{name} {flag}"
        assert result.checked == [], f"{name} {flag}"


# Spelling a destination into one of these words and parking it in `value_flags`
# is exactly the mistake this file was written to catch, so the audit is pinned
# rather than described: a tool added later cannot reintroduce it quietly.
_DIVERTING_WORDS = ("proxy", "socks", "resolv", "connect-to", "dns-", "config", "conf")


def test_no_tool_skips_a_flag_whose_value_names_a_destination():
    skipped = {
        (spec.name, flag)
        for spec in guard.NET_TOOLS.values()
        for flag in spec.value_flags
        if any(word in flag.lower() for word in _DIVERTING_WORDS)
    }
    assert skipped == set(), "these are skipped as non-targets; they belong in divert_flags"


def test_a_bundled_short_option_cannot_hide_a_proxy(check):
    """`curl -sSx <proxy>` is the same flag wearing a hat."""
    result = check("curl -sSx http://www.acme.example:8080 https://www.acme.example/")
    assert not result.allowed
    assert "-x" in result.message()


@pytest.mark.parametrize(
    "command",
    [
        "curl -sSL https://www.acme.example/",
        "curl -skI https://www.acme.example/",
        "wget -qO- https://www.acme.example/",
    ],
)
def test_bundling_does_not_fire_on_an_innocent_cluster(check, command):
    assert check(command).allowed, command


@pytest.mark.parametrize(
    "command",
    [
        "httpx -u https://www.acme.example/ -rl 1",
        "nuclei -u https://www.acme.example/ -rl 1",
        "katana -u https://www.acme.example/ -rl 1",
    ],
)
def test_a_one_dash_long_flag_is_never_read_as_a_bundle(check, command):
    """`-rl 1` is a rate limit; `-r` is a resolver override. Not the same flag."""
    assert check(command).allowed, command


def test_remote_name_is_not_mistaken_for_a_flag_that_eats_the_url(check):
    """`-O` takes no value, so listing it as one swallowed the target."""
    result = check("curl -O https://www.acme.example/f.txt")
    assert result.allowed
    assert result.checked == ["ok  www.acme.example"]


def test_a_domain_file_is_read_and_every_entry_checked(check, tmp_path):
    (tmp_path / "domains.txt").write_text("acme.example\nevil.example\n", encoding="utf-8")
    result = check("amass enum -df domains.txt", cwd=tmp_path)
    assert not result.allowed
    assert "evil.example" in result.message()


# -- script inspection -------------------------------------------------------


@pytest.mark.parametrize(
    "snippet",
    [
        "import requests; requests.get('https://www.acme.example/')",
        "import httpx",
        "from urllib.request import urlopen",
        "import socket",
        "import aiohttp",
    ],
)
def test_python_driving_a_network_library_directly_is_denied(check, snippet):
    result = check(f'python3 -c "{snippet}"')
    assert not result.allowed, snippet
    assert "bypasses scope checking" in result.message()


def test_python_using_the_sanctioned_client_is_allowed(check):
    assert check(
        'python3 -c "from bbh.http import Session; Session().get(\'https://www.acme.example/\')"'
    ).allowed


def test_a_script_file_is_read_and_inspected(check, tmp_path):
    script = tmp_path / "probe.py"
    script.write_text("import requests\nrequests.get('https://evil.example')\n")
    result = check("python3 probe.py", cwd=tmp_path)
    assert not result.allowed
    assert "bypasses scope checking" in result.message()


def test_a_script_file_using_the_client_is_allowed(check, tmp_path):
    script = tmp_path / "probe.py"
    script.write_text("from bbh.http import Session\nSession().get('https://www.acme.example')\n")
    assert check("python3 probe.py", cwd=tmp_path).allowed


def test_a_local_only_script_is_untouched(check, tmp_path):
    script = tmp_path / "count.py"
    script.write_text("import json\nprint(len(json.load(open('x.json'))))\n")
    assert check("python3 count.py", cwd=tmp_path).allowed


def test_node_fetch_is_denied(check):
    result = check("""node -e "fetch('https://evil.example/')" """)
    assert not result.allowed
    assert "bypasses scope checking" in result.message()


# -- the sanctioned-client exemption means what it says ----------------------
#
# Measured: the exemption was a substring search over the whole body, so any
# occurrence of `bb req`, `from bbh`, `import bbh` or `bbh.http` anywhere in it
# -- a comment, a string literal, a variable name -- skipped the entire raw
# network-library check. `python` is not in NET_TOOLS, so nothing downstream
# looked at the command again. That is the one path by which a prompt injection
# in a fenced response body becomes an out-of-scope request: the fence stops
# the text being obeyed, but a persuaded agent writing a script with a
# harmless-looking comment walked straight through.


@pytest.mark.parametrize(
    "snippet",
    [
        "import requests  # bb req",
        "import requests  # see bbh.http",
        "x = 'import bbh'\nimport socket; socket.create_connection(('evil.example.net', 80))",
        "x = 'bb req'\nimport urllib.request; urllib.request.urlopen('https://evil.example.net/')",
        "bb_req = 1\nimport httpx",
        '"""Uses from bbh.http import Session."""\nimport requests',
    ],
)
def test_mentioning_the_client_in_a_comment_or_a_string_buys_nothing(check, snippet):
    result = check("python3 -c " + shlex.quote(snippet))
    assert not result.allowed, snippet
    assert "bypasses scope checking" in result.message()


def test_a_script_file_whose_first_line_names_the_client_is_still_inspected(check, tmp_path):
    script = tmp_path / "probe.py"
    script.write_text("# bb req\nimport requests\nrequests.get('https://evil.example.net/')\n")
    assert not check("python3 probe.py", cwd=tmp_path).allowed


def test_importing_the_client_does_not_excuse_a_raw_socket_beside_it(check):
    """The exemption is about every call in the script, not about one import."""
    result = check(
        'python3 -c "from bbh.http import Session; import socket"'
    )
    assert not result.allowed
    assert "socket" in result.message()


def test_parsing_a_url_is_not_a_network_call(check):
    """`urllib.parse` has no socket in it; the old text match refused it anyway."""
    assert check(
        "python3 -c \"from urllib.parse import urlencode; print(urlencode({'a': 1}))\""
    ).allowed


@pytest.mark.parametrize(
    "snippet",
    [
        "exec('import requests; requests.get(\"https://evil.example.net/\")')",
        "eval(open('payload.txt').read())",
        "import importlib; importlib.import_module(name)",
    ],
)
def test_code_the_guard_cannot_read_is_denied(check, snippet):
    """Without this the parse check is one `exec` away from meaning nothing."""
    result = check("python3 -c " + shlex.quote(snippet))
    assert not result.allowed, snippet
    assert "cannot read" in result.message() or "cannot name" in result.message()


@pytest.mark.parametrize(
    "snippet",
    [
        "__import__('socket').create_connection(('evil.example.net', 80))",
        "import importlib; importlib.import_module('requests')",
    ],
)
def test_a_dynamic_import_the_guard_can_read_is_resolved_like_any_other(check, snippet):
    result = check("python3 -c " + shlex.quote(snippet))
    assert not result.allowed, snippet
    assert "opens its own connections" in result.message()


@pytest.mark.parametrize(
    "snippet",
    [
        "import subprocess; subprocess.run(['curl', 'https://evil.example.net/'])",
        "import os; os.system('curl https://evil.example.net/')",
        "import os; os.execvp('curl', ['curl', 'https://evil.example.net/'])",
    ],
)
def test_shelling_out_of_a_script_is_denied(check, snippet):
    """The hook sees `python3 -c ...`; it never sees the curl inside it."""
    result = check("python3 -c " + shlex.quote(snippet))
    assert not result.allowed, snippet
    assert "directly in Bash" in result.message()


def test_every_problem_in_one_script_is_reported_together(check):
    """One correction, not one round trip per defect -- as `advance()` does."""
    message = check(
        "python3 -c "
        + shlex.quote("import requests\nimport subprocess\nexec('x')\n")
    ).message()
    assert message.count("\n  - ") == 3, message
    assert "requests" in message and "subprocess" in message and "exec(" in message


def test_the_refusal_hands_back_a_client_call_that_works(check):
    message = check('python3 -c "import requests"').message()
    assert "from bbh.http import Session" in message
    assert "actor=" in message, "a Session with no actor is refused at request time"


@pytest.mark.parametrize(
    "snippet",
    [
        "def f(:",                       # a syntax error
        "print 'hello'",                 # python 2
    ],
)
def test_a_script_that_will_not_parse_is_denied_not_waved_past(check, snippet):
    result = check("python3 -c " + shlex.quote(snippet))
    assert not result.allowed, snippet
    assert "does not parse as Python" in result.message()


def test_a_script_the_guard_cannot_read_is_denied(check, tmp_path):
    result = check("python3 probe.py", cwd=tmp_path)
    assert not result.allowed
    assert "cannot read the script" in result.message()
    assert "No such file" in result.message(), "the refusal names what went wrong"


@pytest.mark.parametrize("command", ["python3 -", "cat probe.py | python3 -", "python3 <<'EOF'"])
def test_a_script_arriving_on_stdin_is_denied(check, command):
    result = check(command)
    assert not result.allowed, command
    assert "arrives on stdin" in result.message()


@pytest.mark.parametrize(
    "command",
    [
        "python3 -m pytest",
        "python3 -m pytest tests/ -q",
        "python3 --version",
        "python3 -W ignore probe.py",
        "python3 2>/dev/null probe.py",
        "python3 probe.py > out.txt",
    ],
)
def test_a_working_python_command_is_not_refused_for_its_shape(check, tmp_path, command):
    """`-m` runs a module off the import path, which is a gap, not a script.

    Refusing it would refuse `python3 -m pytest` for a reason nobody can act
    on; a redirection that only captures output is stepped over for the same
    reason. Both are named in the module docstring.
    """
    (tmp_path / "probe.py").write_text("from bbh.http import Session\n")
    assert check(command, cwd=tmp_path).allowed, command


# -- runners with no parser get no exemption ---------------------------------


@pytest.mark.parametrize(
    "command",
    [
        """node -e "require('child_process').execSync('curl https://evil.example.net/')" """,
        """ruby -e 'require "net/http"; Net::HTTP.get(URI("https://evil.example.net/"))' """,
        """perl -e 'use LWP::Simple; get("https://evil.example.net/")' """,
        """php -r 'echo file_get_contents("https://evil.example.net/");' """,
    ],
)
def test_the_other_runners_are_inspected_too(check, command):
    result = check(command)
    assert not result.allowed, command
    assert "bypasses scope checking" in result.message()


@pytest.mark.parametrize(
    "command",
    [
        """node -e "// bb req
fetch('https://evil.example.net/')" """,
        """ruby -e '# from bbh
require "net/http"' """,
    ],
)
def test_there_is_no_exemption_where_there_is_no_parser(check, command):
    """Said out loud rather than left as an accident.

    `bbh.http` is a Python package, so a node or ruby script cannot call it;
    the only sanctioned route from them is shelling out to `bb req`, which the
    guard would have to find inside a string to believe. With no parser it
    cannot tell a call from a comment that names one, so it refuses and the
    message says to write the probe in Python.
    """
    result = check(command)
    assert not result.allowed, command
    assert "no sanctioned-client exemption" in result.message()
    assert "bb req" in result.message()


@pytest.mark.parametrize(
    "command",
    [
        """node -e "console.log(JSON.parse(x).length)" """,
        """ruby -e 'puts File.read("notes.md").lines.count' """,
        """php -r 'echo strrev("abc");' """,
    ],
)
def test_a_local_only_script_in_another_language_is_untouched(check, command):
    assert check(command).allowed, command


def test_every_script_runner_has_an_inspector():
    """A runner listed without one would be exempt from the whole check."""
    assert set(guard.SCRIPT_RUNNERS) == set(guard.RUNNER_FAMILY)
    for runner, family in guard.RUNNER_FAMILY.items():
        assert family in guard.BODY_FLAGS, runner
        assert family == "python" or family in guard.NON_PY_NET, runner


# -- scope loading failures fail closed --------------------------------------


def test_no_engagement_denies_every_net_tool(tmp_path):
    result = guard.check_command(
        "curl https://www.acme.example/", tmp_path,
        scope_loader=lambda: (None, "no engagement is selected"),
    )
    assert not result.allowed
    assert "no engagement is selected" in result.message()


def test_an_expired_attestation_denies_every_net_tool(check):
    result = check("curl https://www.acme.example/", hours=-1)
    assert not result.allowed
    assert "expired" in result.message()


def test_default_loader_refuses_when_nothing_is_selected(tmp_path, monkeypatch):
    monkeypatch.delenv("BBH_ENGAGEMENT", raising=False)
    result = guard.check_command("curl https://www.acme.example/", tmp_path)
    assert not result.allowed
    assert "bb use" in result.message()


def test_default_loader_uses_the_armed_engagement(engagement, tmp_path):
    assert guard.check_command("curl https://www.acme.example/", tmp_path).allowed
    assert not guard.check_command("curl https://evil.example/", tmp_path).allowed


# -- the hook entrypoint -----------------------------------------------------


def _run_hook(payload: dict) -> tuple[int, str]:
    """Drive bin/bb-guard the way Claude Code does: JSON on stdin."""
    proc = subprocess.run(
        [str(paths.REPO / "bin" / "bb-guard")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.returncode, proc.stdout


def test_hook_shim_denies_an_out_of_scope_command(engagement, monkeypatch):
    code, stdout = _run_hook(
        {"tool_name": "Bash", "cwd": "/tmp",
         "tool_input": {"command": "curl -sS https://evil.example/"}}
    )
    assert code == 0, "a hook denies by printing, not by exiting non-zero"
    decision = json.loads(stdout)["hookSpecificOutput"]
    assert decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "deny"
    assert "evil.example" in decision["permissionDecisionReason"]


def test_hook_shim_stays_silent_for_an_in_scope_command(engagement):
    code, stdout = _run_hook(
        {"tool_name": "Bash", "cwd": "/tmp",
         "tool_input": {"command": "curl -sS https://www.acme.example/login"}}
    )
    assert code == 0
    assert stdout.strip() == "", "printing nothing is how a hook allows a call"


def test_hook_ignores_tools_other_than_bash(engagement):
    code, stdout = _run_hook(
        {"tool_name": "Read", "tool_input": {"file_path": "/etc/passwd"}}
    )
    assert (code, stdout.strip()) == (0, "")


def test_hook_survives_malformed_input(engagement):
    proc = subprocess.run(
        [str(paths.REPO / "bin" / "bb-guard")],
        input="not json at all",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""


def test_hook_denies_when_the_guard_itself_crashes(monkeypatch, capsys):
    def boom(*a, **kw):
        raise RuntimeError("exploded")

    monkeypatch.setattr(guard, "check_command", boom)
    monkeypatch.setattr(
        "sys.stdin",
        __import__("io").StringIO(
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "curl https://x/"}})
        ),
    )
    assert guard.main() == 0
    decision = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "crashed" in decision["permissionDecisionReason"]


def test_denials_are_written_to_the_audit_log(engagement, tmp_path):
    _run_hook(
        {"tool_name": "Bash", "cwd": "/tmp",
         "tool_input": {"command": "curl -sS https://evil.example/"}}
    )
    lines = paths.AUDIT_LOG.read_text(encoding="utf-8").strip().splitlines()
    record = json.loads(lines[-1])
    assert record["allowed"] is False
    assert record["tool"] == "curl"
    assert "evil.example" in record["command"]
