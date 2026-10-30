"""Network-namespace egress control.

No test here needs root, creates a namespace, loads an nftables rule or opens a
socket: the command construction is factored away from the execution, so the
generated argv, the generated script and the generated ruleset are all tested
as data, and the probe side is tested through the result parser. The two tests
that genuinely need privilege are skipped without it.

What is being pinned down is mostly the shape of a security boundary, so the
assertions are deliberately literal: the output chain's policy, the single
accept rule and the exact launch prefix are the control, and a change to any of
them should have to be made twice.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from bbh import paths, runner, sandbox
from bbh.runner import PHASES, HuntConfig, RunnerError
from bbh.sandbox import ASSERTIONS, SandboxCheck, SandboxError, SandboxVerification
from conftest import make_scope

FAKE_TOOLS = {
    "ip": "/usr/sbin/ip",
    "nft": "/usr/sbin/nft",
    "setpriv": "/usr/bin/setpriv",
    "env": "/usr/bin/env",
}


@pytest.fixture
def ca(tmp_path) -> Path:
    """A stand-in mitmproxy CA, so nothing has to look for the real one."""
    path = tmp_path / "mitmproxy-ca-cert.pem"
    path.write_text("-----BEGIN CERTIFICATE-----\nnot a real CA\n", encoding="utf-8")
    return path


@pytest.fixture
def fake_tools(monkeypatch):
    """Pretend ip/nft/setpriv are installed, wherever this suite is running."""
    monkeypatch.setattr(sandbox, "require_tools", lambda: dict(FAKE_TOOLS))
    return dict(FAKE_TOOLS)


@pytest.fixture
def spec(engagement, ca) -> sandbox.SandboxPlan:
    return sandbox.plan(engagement, ca_file=ca, tools=dict(FAKE_TOOLS))


@pytest.fixture
def built(spec) -> sandbox.SandboxPlan:
    """A sandbox whose plan is on disk, as `bb sandbox up` leaves it."""
    sandbox.save_plan(spec)
    return spec


@pytest.fixture
def no_subprocess(monkeypatch):
    """Any subprocess a test starts from here is a test bug."""

    def refuse(*args, **kwargs):
        raise AssertionError(f"a test tried to run a command: {args!r}")

    monkeypatch.setattr(sandbox.subprocess, "run", refuse)


@pytest.fixture
def no_address_scan(monkeypatch):
    """Skip the unprivileged `ip addr` read that picks a free link address."""
    monkeypatch.setattr(sandbox, "host_addresses", lambda: frozenset())


def script_commands(script: str) -> list[str]:
    """The script's lines with comments and blanks removed."""
    return [
        line.strip()
        for line in script.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


# ---------------------------------------------------------------------------
# names and addresses
# ---------------------------------------------------------------------------


def test_the_namespace_is_named_after_the_engagement():
    assert sandbox.namespace_for("acme") == "bbh-acme"


@pytest.mark.parametrize(
    "name",
    ["", "   ", "../../etc/passwd", "acme; rm -rf /", "$(id)", "a b", "ACME", "-acme"],
)
def test_an_unusable_engagement_name_is_refused_rather_than_quoted(name):
    """The name becomes a filename under /run/netns and a token in a root script."""
    with pytest.raises(SandboxError, match="not a usable engagement name"):
        sandbox.namespace_for(name)


def test_interface_names_fit_the_kernel_limit():
    host, guest = sandbox.interface_names("a" * 63)
    assert host != guest
    for iface in (host, guest):
        assert len(iface) <= 15, iface
        assert iface.startswith("bbh-")


def test_interface_names_do_not_collide_between_similar_engagements():
    """Truncating instead of hashing would point one engagement at the other's veth."""
    first = sandbox.interface_names("acme-staging")
    second = sandbox.interface_names("acme-staging-eu")
    assert first != second


def test_the_link_is_a_point_to_point_pair(spec):
    assert spec.prefix_len == 30
    assert spec.host_addr.endswith(".1")
    assert spec.ns_addr.endswith(".2")
    assert spec.host_addr.rsplit(".", 1)[0] == spec.ns_addr.rsplit(".", 1)[0]
    assert spec.proxy_endpoint == f"http://{spec.host_addr}:{spec.proxy_port}"


def test_the_link_is_the_same_on_every_run():
    assert sandbox.pick_link("acme") == sandbox.pick_link("acme")


def test_an_address_this_host_already_has_is_stepped_over():
    """Two engagements sandboxed at once must not land on the same /30."""
    default_host, _ = sandbox.pick_link("acme")
    host, guest = sandbox.pick_link("acme", taken={default_host})
    assert host != default_host
    assert host.rsplit(".", 1)[0] == guest.rsplit(".", 1)[0]


# ---------------------------------------------------------------------------
# the ruleset: policy drop, exactly one way out
# ---------------------------------------------------------------------------


def chain_rules(ruleset: str, chain: str) -> list[str]:
    """The rule lines of one chain, comments and blank lines dropped."""
    body = ruleset.split(f"chain {chain} {{", 1)[1].split("}", 1)[0]
    return [
        line.strip()
        for line in body.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_the_output_chain_drops_by_default(spec):
    rules = chain_rules(sandbox.nft_ruleset(spec), "output")
    assert rules[0] == "type filter hook output priority filter; policy drop;"


def test_exactly_one_accept_can_leave_the_namespace(spec):
    """The contract's single accept: the proxy's address and port, nothing else."""
    accepts = [r for r in chain_rules(sandbox.nft_ruleset(spec), "output") if "accept" in r]
    leaving = [r for r in accepts if 'oifname "lo"' not in r]
    assert leaving == [
        f"ip daddr {spec.host_addr} tcp dport {spec.proxy_port} counter accept"
    ]
    assert len(accepts) == 2, "loopback, which cannot leave, plus the one way out"


def test_blocked_egress_is_rejected_rather_than_dropped(spec):
    """Measured on the build machine: a dropped SYN hangs 135s, a reject is 0.00s.

    The hang is not merely slow. The agent sees a *timeout*, concludes the target
    is unresponsive, and writes that into the angle ledger as ground covered --
    a tooling failure laundered into a permanent false negative. Reverting these
    rules to a bare `policy drop` restores that, which is why it is pinned here
    rather than left to whoever next reads the chain and sees a redundant rule.
    """
    rules = chain_rules(sandbox.nft_ruleset(spec), "output")
    assert rules[-1] == "counter reject", "a catch-all reject must end the chain"
    assert "meta l4proto tcp counter reject with tcp reset" in rules, (
        "TCP needs a reset specifically: that is what makes connect() return "
        "ECONNREFUSED instead of waiting out the kernel's SYN retries"
    )
    # Order is the whole correctness argument in nftables: a reject placed above
    # the accept would contain the namespace by cutting off the proxy too.
    proxy_rule = next(i for i, r in enumerate(rules) if "accept" in r and "lo" not in r)
    first_reject = next(i for i, r in enumerate(rules) if "reject" in r)
    assert proxy_rule < first_reject
    # policy drop stays as the backstop for anything reject cannot answer.
    assert rules[0].endswith("policy drop;")


def test_the_input_chain_accepts_only_the_proxys_replies(spec):
    rules = chain_rules(sandbox.nft_ruleset(spec), "input")
    assert rules[0] == "type filter hook input priority filter; policy drop;"
    accepts = [r for r in rules if "accept" in r]
    assert [r for r in accepts if 'iifname "lo"' not in r] == [
        f"ip saddr {spec.host_addr} tcp sport {spec.proxy_port} accept"
    ]


def test_the_ruleset_opens_no_other_protocol(spec):
    ruleset = sandbox.nft_ruleset(spec)
    for never in ("udp", "icmp", "0.0.0.0/0", "masquerade", "policy accept"):
        assert never not in ruleset, never


def test_the_ruleset_is_replaced_atomically(spec):
    """create, delete, define: re-running up cannot leave a half-applied ruleset."""
    ruleset = sandbox.nft_ruleset(spec)
    first = ruleset.index(f"table inet {sandbox.NFT_TABLE}")
    deleted = ruleset.index(f"delete table inet {sandbox.NFT_TABLE}")
    defined = ruleset.index(f"table inet {sandbox.NFT_TABLE} {{")
    assert first < deleted < defined


def test_the_host_side_block_cannot_disturb_other_traffic(spec):
    """Second layer for a host that already forwards; its own table, policy accept."""
    host_rules = sandbox.nft_host_ruleset(spec)
    assert spec.host_table in host_rules
    assert "policy accept" in host_rules
    assert f'iifname "{spec.host_if}" drop' in host_rules
    assert f'oifname "{spec.host_if}" drop' in host_rules


# ---------------------------------------------------------------------------
# the one privileged script
# ---------------------------------------------------------------------------


def test_every_privileged_action_is_in_the_one_script(spec):
    script = sandbox.build_up_script(spec)
    assert script.startswith("#!/bin/sh")
    assert "set -eu" in script
    for action in (
        f'"$IP" netns add "$NS"',
        f'"$IP" link add "$HOST_IF" type veth peer name "$NS_IF"',
        f'"$IP" link set "$NS_IF" netns "$NS"',
        f'"$IP" addr add "$HOST_ADDR/$LEN" dev "$HOST_IF"',
        '"$IP" netns exec "$NS" "$NFT" -f -',
    ):
        assert action in script, action


def test_the_script_itself_never_calls_sudo(spec):
    """One sudo, applied to the whole script, so the operator reads one change."""
    for script in (sandbox.build_up_script(spec), sandbox.build_down_script(spec)):
        assert not [line for line in script_commands(script) if "sudo" in line]


def test_the_script_leaves_no_resolver_in_the_namespace(spec):
    script = sandbox.build_up_script(spec)
    assert '/etc/netns/$NS/resolv.conf' in script
    resolv = script.split("<<'RESOLV'", 1)[1].split("RESOLV", 1)[0]
    assert script_commands(resolv) == [], "any directive here would resolve a name"


def test_the_script_gives_the_namespace_a_default_route(spec):
    """So a dropped packet is dropped by the ruleset, not by a missing route."""
    assert '"$IP" -n "$NS" route replace default via "$HOST_ADDR"' in (
        sandbox.build_up_script(spec)
    )


def test_the_teardown_removes_everything_the_setup_made(spec):
    script = sandbox.build_down_script(spec)
    assert '"$IP" netns del "$NS"' in script
    assert '"$IP" link del "$HOST_IF"' in script
    assert '"$NFT" delete table inet "$HOST_TABLE"' in script
    assert 'rm -rf "/etc/netns/$NS"' in script


@pytest.mark.skipif(not shutil.which("sh"), reason="needs a POSIX shell")
def test_the_generated_scripts_are_valid_shell(spec, tmp_path):
    """Heredocs and quoting break silently; sh -n parses without running anything."""
    for name, text in (
        ("up.sh", sandbox.build_up_script(spec)),
        ("down.sh", sandbox.build_down_script(spec)),
    ):
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        done = subprocess.run(
            ["sh", "-n", str(path)], capture_output=True, text=True, timeout=30
        )
        assert done.returncode == 0, f"{name}: {done.stderr}"


def test_the_privileged_script_is_not_writable_by_the_contained_agent(
    engagement, ca, fake_tools, no_address_scan, monkeypatch
):
    """Root runs this file, so it must not live in the directory the agent gets."""
    monkeypatch.setenv("BBH_PROXY_CA", str(ca))
    result = sandbox.up(engagement, dry_run=True, out=lambda line: None)
    script = Path(result["script"])
    assert paths.STATE_DIR in script.parents
    assert paths.engagement_dir(engagement) not in script.parents


def test_the_narrative_goes_to_stderr_so_json_output_stays_clean(
    engagement, ca, fake_tools, no_address_scan, monkeypatch, no_subprocess, capsys
):
    """`bb sandbox up --json` writes its object to stdout; this must not land there."""
    monkeypatch.setenv("BBH_PROXY_CA", str(ca))
    sandbox.up(engagement, dry_run=True)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "policy drop" in captured.err


def test_a_dry_run_prints_the_whole_change_and_applies_nothing(
    engagement, ca, fake_tools, no_address_scan, monkeypatch, no_subprocess
):
    monkeypatch.setenv("BBH_PROXY_CA", str(ca))
    printed: list[str] = []
    result = sandbox.up(engagement, dry_run=True, out=printed.append)
    text = "\n".join(printed)

    assert result["applied"] is False
    assert "ip netns add" in text.replace('"$IP"', "ip")
    assert "policy drop" in text
    assert "[dry run]" in text
    # Nothing was recorded, so nothing can be launched into a namespace that
    # does not exist.
    assert not sandbox.state_path(engagement).exists()
    with pytest.raises(SandboxError, match="no sandbox has been built"):
        sandbox.wrap_argv(engagement, ["/bin/true"])


# ---------------------------------------------------------------------------
# the mitm CA
# ---------------------------------------------------------------------------


def test_the_ca_is_taken_from_the_environment_override(engagement, ca, monkeypatch):
    monkeypatch.setenv("BBH_PROXY_CA", str(ca))
    assert sandbox.find_ca(engagement) == ca.resolve()


def test_the_ca_is_found_in_the_engagements_proxy_state(engagement, monkeypatch, tmp_path):
    monkeypatch.delenv("BBH_PROXY_CA", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    confdir = paths.engagement_dir(engagement) / ".state" / "mitmproxy"
    confdir.mkdir(parents=True, exist_ok=True)
    cert = confdir / "mitmproxy-ca-cert.pem"
    cert.write_text("cert", encoding="utf-8")
    assert sandbox.find_ca(engagement) == cert.resolve()


def test_a_missing_ca_says_how_to_generate_one(engagement, monkeypatch, tmp_path):
    """Without the CA every HTTPS request inside the namespace fails verification."""
    monkeypatch.delenv("BBH_PROXY_CA", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(SandboxError, match=f"bb proxy start {engagement}"):
        sandbox.find_ca(engagement)


# ---------------------------------------------------------------------------
# wrap_argv: the launch prefix
# ---------------------------------------------------------------------------


def launch_slice(argv: list[str]) -> list[str]:
    """The argv from `ip` onwards, with any sudo escalation stripped."""
    index = next(i for i, part in enumerate(argv) if part.endswith("/ip") or part == "ip")
    return argv[index:]


def test_wrap_argv_prefixes_the_namespace_and_drops_privilege(built):
    argv = sandbox.wrap_argv(built.engagement, ["/home/u/.local/bin/claude", "-p", "go"])
    prefix = launch_slice(argv)
    assert prefix[:8] == [
        built.ip_bin,
        "netns",
        "exec",
        built.namespace,
        built.setpriv_bin,
        f"--reuid={os.getuid()}",
        f"--regid={os.getgid()}",
        "--clear-groups",
    ]
    assert argv[-3:] == ["/home/u/.local/bin/claude", "-p", "go"]


def test_the_command_is_handed_to_env_so_nothing_is_inherited(built):
    argv = sandbox.wrap_argv(built.engagement, ["/bin/true"])
    assert built.env_bin in argv
    assert argv.index(built.env_bin) < argv.index("/bin/true")


def test_root_needs_no_escalation_to_enter_the_namespace(built, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    argv = sandbox.wrap_argv(built.engagement, ["/bin/true"])
    assert argv[0] == built.ip_bin
    assert not any("sudo" in part for part in argv)


def test_an_unprivileged_launch_escalates_without_prompting(built, monkeypatch):
    """-n, not a prompt: an unattended hunt must fail the check, not hang on it."""
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    argv = sandbox.wrap_argv(built.engagement, ["/bin/true"])
    assert argv[0].endswith("sudo")
    assert argv[1] == "-n"


def test_the_proxy_and_the_ca_reach_the_phase(built):
    argv = sandbox.wrap_argv(built.engagement, ["/bin/true"])
    assignments = dict(part.split("=", 1) for part in argv if re.match(r"^[A-Za-z_]+=", part))
    for name in ("http_proxy", "https_proxy", "ALL_PROXY"):
        assert assignments[name] == built.proxy_endpoint
    for name in (
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "GIT_SSL_CAINFO",
    ):
        assert assignments[name] == built.ca_file
    assert assignments["BBH_SANDBOX"] == built.namespace


def test_the_harness_environment_survives_sudos_env_reset(built, monkeypatch):
    """sudo drops the environment, so BBH_HOME and PATH are restated as arguments."""
    monkeypatch.setenv("BBH_HOME", "/somewhere/bbh")
    monkeypatch.setenv("BBH_ENGAGEMENT", built.engagement)
    monkeypatch.setenv("PYTHONPATH", "/repo")
    argv = sandbox.wrap_argv(built.engagement, ["/bin/true"])
    assert "BBH_HOME=/somewhere/bbh" in argv
    assert f"BBH_ENGAGEMENT={built.engagement}" in argv
    assert "PYTHONPATH=/repo" in argv
    assert any(part.startswith("PATH=") for part in argv)


def test_an_inherited_proxy_cannot_override_the_sandbox_one(built, monkeypatch):
    monkeypatch.setenv("http_proxy", "http://attacker.example:3128")
    argv = sandbox.wrap_argv(built.engagement, ["/bin/true"])
    assert [p for p in argv if p.startswith("http_proxy=")] == [
        f"http_proxy={built.proxy_endpoint}"
    ]


def test_a_secret_in_the_environment_is_not_carried_in(built, monkeypatch):
    """The allowlist is the one place that decides what crosses the boundary."""
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s3cret")
    argv = sandbox.wrap_argv(built.engagement, ["/bin/true"])
    assert not any("s3cret" in part for part in argv)


def test_wrap_argv_fails_closed_without_a_built_sandbox(engagement):
    with pytest.raises(SandboxError, match=f"bb sandbox up {engagement}"):
        sandbox.wrap_argv(engagement, ["/bin/true"])


def test_wrap_argv_refuses_an_empty_command(built):
    with pytest.raises(SandboxError, match="empty command"):
        sandbox.wrap_argv(built.engagement, [])


def test_wrap_argv_refuses_a_flag_as_the_program(built):
    """env would read it as its own option and the phase would never start."""
    with pytest.raises(SandboxError, match="must be the executable"):
        sandbox.wrap_argv(built.engagement, ["--help"])


def test_a_corrupt_plan_is_rebuilt_rather_than_guessed(built):
    sandbox.state_path(built.engagement).write_text("{not json", encoding="utf-8")
    with pytest.raises(SandboxError, match="bb sandbox down"):
        sandbox.wrap_argv(built.engagement, ["/bin/true"])


def tamper(engagement: str, **fields) -> None:
    path = sandbox.state_path(engagement)
    data = json.loads(path.read_text())
    data["plan"].update(fields)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_a_plan_that_names_another_namespace_is_not_trusted(built):
    """The state file is only as trustworthy as the uid that can write it."""
    tamper(built.engagement, namespace="bbh-someone-else")
    with pytest.raises(SandboxError, match="does not match the engagement it claims"):
        sandbox.wrap_argv(built.engagement, ["/bin/true"])


def test_a_plan_with_a_relative_binary_is_not_trusted(built):
    """`ip` resolved through PATH would hand the privileged step to the agent."""
    tamper(built.engagement, ip_bin="ip")
    with pytest.raises(SandboxError, match="is not an absolute path"):
        sandbox.wrap_argv(built.engagement, ["/bin/true"])


def test_a_plan_with_a_mangled_address_is_not_trusted(built):
    tamper(built.engagement, host_addr="10.77.1.1; rm -rf /")
    with pytest.raises(SandboxError, match="is not an IPv4 address"):
        sandbox.wrap_argv(built.engagement, ["/bin/true"])


def test_a_plan_from_another_schema_is_refused(built):
    path = sandbox.state_path(built.engagement)
    data = json.loads(path.read_text())
    data["schema"] = sandbox.STATE_SCHEMA + 1
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SandboxError, match="schema"):
        sandbox.wrap_argv(built.engagement, ["/bin/true"])


# ---------------------------------------------------------------------------
# the probes: two negatives and a positive
# ---------------------------------------------------------------------------


def test_the_three_assertions_are_two_negatives_and_one_positive(spec):
    probes = sandbox.build_probes(spec, make_scope())
    assert [p.name for p in probes] == list(ASSERTIONS)
    assert [p.want_connected for p in probes] == [False, False, True]
    assert sum(1 for p in probes if p.via_proxy) == 1


def test_the_positive_assertion_goes_to_an_in_scope_host_through_the_proxy(spec):
    probe = sandbox.build_probes(spec, make_scope())[2]
    scope = make_scope()
    assert scope.decide(sandbox.in_scope_probe_host(scope)).allowed
    assert spec.host_addr in probe.argv
    assert str(spec.proxy_port) in probe.argv
    assert "CONNECT" in probe.argv[3]


def test_the_negative_assertions_target_hosts_the_scope_denies(spec):
    scope = make_scope()
    out_host = sandbox.out_of_scope_probe_host(scope)
    bare_ip = sandbox.bare_ip_probe_addr(scope)
    assert not scope.decide(out_host).allowed
    assert not scope.decide(bare_ip).allowed


def test_the_negative_assertions_are_not_vacuous(spec):
    """A name that resolves nowhere would fail everywhere; that proves nothing."""
    scope = make_scope()
    assert not sandbox.out_of_scope_probe_host(scope).endswith(".example")
    # The bare-IP assertion has to test the ruleset, not the missing resolver.
    assert sandbox.is_ip(sandbox.bare_ip_probe_addr(scope))


def test_the_probes_run_an_isolated_interpreter(spec):
    """-I: no cwd on sys.path, so a planted socket.py cannot answer for the kernel."""
    for probe in sandbox.build_probes(spec, make_scope()):
        assert probe.argv[1] == "-I"
        assert probe.argv[2] == "-c"


def test_a_scope_with_no_concrete_host_cannot_be_probed(spec):
    scope = make_scope(in_scope=("198.51.100.0/24",))
    with pytest.raises(SandboxError, match="bb scope compile"):
        sandbox.in_scope_probe_host(scope)


def test_an_apexless_wildcard_probes_a_subdomain(spec):
    scope = make_scope(in_scope=({"value": "*.acme.example", "include_apex": False},))
    assert sandbox.in_scope_probe_host(scope) == "www.acme.example"


# ---------------------------------------------------------------------------
# reading the probes back
# ---------------------------------------------------------------------------


def negative_probe() -> sandbox.Probe:
    return sandbox.Probe(
        name="bare_ip_direct",
        engagement="acme",
        expected="a direct connection fails",
        want_connected=False,
        argv=("/usr/bin/python3", "-I", "-c", "...", "1.1.1.1", "443", "3.0"),
        remedy="Rebuild it: bb sandbox down acme && bb sandbox up acme",
    )


def proxy_probe() -> sandbox.Probe:
    return sandbox.Probe(
        name="in_scope_host_via_proxy",
        engagement="acme",
        expected="CONNECT through the proxy returns 200",
        want_connected=True,
        via_proxy=True,
        argv=("/usr/bin/python3", "-I", "-c", "...", "10.77.1.1", "8080"),
        remedy="Start the proxy: bb proxy start acme --listen-host 10.77.1.1 --port 8080",
    )


def test_a_blocked_connection_passes_a_negative_assertion():
    # A refusal, which is what the generated reject rules produce. The timeout
    # case used to stand here; it now has its own test below, because a timeout
    # means something different from a refusal.
    out = json.dumps({"connected": False, "error": "ConnectionRefusedError: [Errno 111]"})
    check = sandbox.evaluate_probe(negative_probe(), 0, out, "")
    assert check.ok
    assert "as required" in check.observed


def test_a_timeout_means_a_stale_drop_based_namespace_and_fails():
    """Contained, but not by the rules this version writes -- so rebuild it.

    This is stricter than it reads, and deliberately so: the old behaviour
    passed here, because nothing left the namespace. It still didn't. But a
    `drop` makes every blocked attempt hang for the kernel's full SYN retry
    schedule, the agent reads that as an unresponsive target rather than as a
    harness denial, and the angle ledger then records ground as covered that was
    never tested. The usual cause is a namespace left up by an older version,
    and the remedy is one command, so failing is cheap and passing is not.
    """
    out = json.dumps({"connected": False, "error": "TimeoutError: timed out"})
    check = sandbox.evaluate_probe(negative_probe(), 0, out, "")
    assert not check.ok
    assert "silent drop" in check.observed
    assert "bb sandbox down acme" in check.problem


def test_a_connection_that_got_out_fails_the_assertion_loudly():
    out = json.dumps({"connected": True, "error": None})
    check = sandbox.evaluate_probe(negative_probe(), 0, out, "")
    assert not check.ok
    assert "left the namespace" in check.observed
    assert "bb sandbox up acme" in check.problem


def test_a_probe_that_says_nothing_fails_closed():
    """A control that cannot verify must deny, not assume."""
    check = sandbox.evaluate_probe(
        negative_probe(), 1, "", "sudo: a password is required"
    )
    assert not check.ok
    assert "a password is required" in check.observed
    assert "CAP_SYS_ADMIN" in check.remedy
    assert "bb sandbox up acme" in check.remedy


def test_a_tunnel_through_the_proxy_passes_the_positive_assertion():
    out = json.dumps(
        {"connected": True, "status": 200, "head": "HTTP/1.1 200 Connection established"}
    )
    check = sandbox.evaluate_probe(proxy_probe(), 0, out, "")
    assert check.ok


def test_a_proxy_that_refuses_the_tunnel_fails_the_positive_assertion():
    out = json.dumps({"connected": True, "status": 403, "head": "HTTP/1.1 403 Forbidden"})
    check = sandbox.evaluate_probe(proxy_probe(), 0, out, "")
    assert not check.ok
    assert "403" in check.observed
    assert "--listen-host" in check.problem


def test_a_proxy_nobody_started_fails_with_the_command_that_starts_it():
    out = json.dumps(
        {"connected": False, "status": None, "error": "ConnectionRefusedError: refused"}
    )
    check = sandbox.evaluate_probe(proxy_probe(), 0, out, "")
    assert not check.ok
    assert "bb proxy start acme" in check.problem


def test_a_tunnel_with_no_status_line_is_not_a_pass():
    out = json.dumps({"connected": True, "status": None, "head": ""})
    check = sandbox.evaluate_probe(proxy_probe(), 0, out, "")
    assert not check.ok


@pytest.mark.parametrize(
    "error",
    [
        # Measured inside a namespace running the generated ruleset: a rejected
        # packet is refused outright, a name with no resolver fails to resolve,
        # and the accepted path reaches a port with nothing on it. The point of
        # the parametrisation is that this must not be brittle about HOW the
        # kernel refused. `TimeoutError` is the one exception and has its own
        # test: it is the signature of a drop, which is a different situation.
        "gaierror: [Errno -2] Name or service not known",
        "ConnectionRefusedError: [Errno 111] Connection refused",
        "OSError: [Errno 101] Network is unreachable",
        "PermissionError: [Errno 1] Operation not permitted",
    ],
)
def test_every_way_the_kernel_refuses_counts_as_contained(error):
    out = json.dumps({"connected": False, "error": error})
    check = sandbox.evaluate_probe(negative_probe(), 0, out, "")
    assert check.ok
    assert error in check.observed


def test_the_probe_result_is_read_past_any_noise():
    noisy = "warning: something\n" + json.dumps({"connected": False}) + "\n"
    assert sandbox.parse_probe_output(noisy) == {"connected": False}


def test_the_last_result_line_wins():
    text = json.dumps({"connected": True}) + "\n" + json.dumps({"connected": False}) + "\n"
    assert sandbox.parse_probe_output(text) == {"connected": False}


@pytest.mark.parametrize("text", ["", "   ", "not json", "[1, 2]", "{broken"])
def test_output_that_is_not_a_result_object_is_no_result(text):
    assert sandbox.parse_probe_output(text) is None


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_a_verification_needs_all_three_assertions_to_pass():
    checks = tuple(
        SandboxCheck(name, True, "e", "o") for name in ASSERTIONS
    )
    good = SandboxVerification("acme", "bbh-acme", checks)
    assert good.ok and bool(good) and good.problems == ()
    assert list(good) == []
    assert good.as_dict()["assertions"] == {name: "pass" for name in ASSERTIONS}


def test_an_assertion_nobody_attempted_is_not_a_pass():
    """Asserting an absence is not a test: two of three proves nothing."""
    partial = SandboxVerification(
        "acme",
        "bbh-acme",
        tuple(SandboxCheck(name, True, "e", "o") for name in ASSERTIONS[:2]),
    )
    assert not partial.ok
    assert partial.not_attempted == (ASSERTIONS[2],)
    assert partial.problems, "a verification that is not ok must say something"
    assert ASSERTIONS[2] in partial.problems[0]
    assert partial.as_dict()["assertions"][ASSERTIONS[2]] == "not_attempted"


def test_a_failed_assertion_is_named_with_its_outcome():
    verification = SandboxVerification(
        "acme",
        "bbh-acme",
        (
            SandboxCheck(ASSERTIONS[0], True, "it fails", "it failed"),
            SandboxCheck(ASSERTIONS[1], False, "it fails", "it connected", "Run: bb x"),
            SandboxCheck(ASSERTIONS[2], True, "200", "200"),
        ),
    )
    assert not verification.ok
    data = verification.as_dict()
    assert data["assertions"] == {
        ASSERTIONS[0]: "pass",
        ASSERTIONS[1]: "fail",
        ASSERTIONS[2]: "pass",
    }
    assert data["contained"] is False
    assert "it connected" in data["problems"][0]


def test_verify_without_a_sandbox_is_not_contained(engagement, fake_tools, no_subprocess):
    result = sandbox.verify(engagement)
    assert not result.ok
    assert "sandbox" in result.problems[0]
    assert f"bb sandbox up {engagement}" in result.problems[0]
    assert result.as_dict()["assertions"] == {name: "not_attempted" for name in ASSERTIONS}


def test_verify_reports_a_missing_namespace_before_probing(built, fake_tools, no_subprocess):
    monkeypatched = sandbox.verify(built.engagement)
    assert not monkeypatched.ok
    assert any(c.name == "namespace" for c in monkeypatched.checks)
    assert f"bb sandbox up {built.engagement}" in monkeypatched.problems[0]


def test_verify_refuses_an_unarmed_engagement_before_touching_the_target(
    engagement, ca, fake_tools, monkeypatch, no_subprocess
):
    """The positive assertion is a real request, so it needs a live attestation."""
    from conftest import write_engagement

    write_engagement(engagement, hours=-1)
    sandbox.save_plan(sandbox.plan(engagement, ca_file=ca, tools=dict(FAKE_TOOLS)))
    monkeypatch.setattr(sandbox, "netns_file", lambda ns: Path("/run/netns") / ns)

    result = sandbox.verify(engagement)
    assert not result.ok
    assert [c.name for c in result.checks] == ["armed"]
    assert "expired" in result.problems[0]


def test_verify_refuses_a_sandbox_whose_ca_has_gone(built, fake_tools, monkeypatch, no_subprocess):
    monkeypatch.setattr(sandbox, "netns_file", lambda ns: Path("/run/netns") / ns)
    Path(built.ca_file).unlink()
    result = sandbox.verify(built.engagement)
    assert [c.name for c in result.checks] == ["ca_file"]
    assert "certificate verification" in result.problems[0]


def test_verify_says_which_package_provides_a_missing_tool(engagement, monkeypatch, no_subprocess):
    monkeypatch.setattr(sandbox.shutil, "which", lambda _name: None)
    result = sandbox.verify(engagement)
    assert not result.ok
    assert "iproute2" in result.problems[0]
    assert "nftables" in result.problems[0]


def test_verify_refuses_a_kernel_without_namespace_support(
    engagement, fake_tools, monkeypatch, no_subprocess, tmp_path
):
    """Say so and fail, rather than pretend something is contained."""
    monkeypatch.setattr(sandbox, "NETNS_PROC", tmp_path / "absent")
    result = sandbox.verify(engagement)
    assert [c.name for c in result.checks] == ["kernel"]
    assert "CONFIG_NET_NS" in result.problems[0]


def test_verify_never_raises_on_a_nonsense_engagement_name(no_subprocess):
    result = sandbox.verify("../../etc")
    assert not result.ok
    assert "sandbox" in result.problems[0]


def test_a_verification_that_cannot_finish_denies_rather_than_raises(engagement, monkeypatch):
    """The runner reads this to decide whether to start; it must get a verdict."""

    def explode():
        raise RuntimeError("the state directory is on fire")

    monkeypatch.setattr(sandbox, "kernel_problem", explode)
    result = sandbox.verify(engagement)
    assert not result.ok
    assert "on fire" in result.problems[0]
    contained, problems = runner.sandbox_state(engagement)
    assert contained is False and problems


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def test_status_of_an_unbuilt_sandbox_is_not_up(engagement):
    report = sandbox.status(engagement)
    assert report["up"] is False
    assert report["built"] is False
    assert f"bb sandbox up {engagement}" in report["problem"]


def test_status_names_the_proxy_the_namespace_must_reach(built):
    report = sandbox.status(built.engagement)
    assert report["built"] is True
    assert report["namespace"] == built.namespace
    assert report["proxy"] == built.proxy_endpoint
    assert "netns exec" in report["launch"]
    # The namespace was never really created, so it is not up.
    assert report["up"] is False


# ---------------------------------------------------------------------------
# the runner wiring
# ---------------------------------------------------------------------------


class FakePhaseRun:
    """Stands in for runner._spawn_and_stream; records argv, writes the handoff."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, cmd, *, cwd, env, raw_path, stderr_path, timeout_s, events,
                 phase_key, attempt):
        self.calls.append(list(cmd))
        phase = runner.phase_by_key(phase_key)
        handoff = paths.engagement_dir(env["BBH_ENGAGEMENT"]) / "handoff" / f"{phase_key}.json"
        handoff.parent.mkdir(parents=True, exist_ok=True)
        # Non-empty: a handoff whose every declared key is empty is a phase that
        # recorded no work, and the runner no longer calls that `ok`.
        handoff.write_text(
            json.dumps({k: [f"{k}-1"] for k in phase.produces}), encoding="utf-8"
        )
        return (
            runner._StreamOutcome(cost_usd=0.4, turns=2, session_id="s", saw_result=True),
            0,
            False,
        )


def test_the_runner_launches_a_phase_inside_the_namespace(built, store, monkeypatch):
    fake = FakePhaseRun()
    monkeypatch.setattr(runner, "_spawn_and_stream", fake)
    monkeypatch.setattr(runner, "sandbox_state", lambda _name: (True, []))

    cfg = HuntConfig(engagement=built.engagement, allow_unpriced=True)
    assert runner.run_phase(cfg, PHASES[0], store).status == "ok"

    argv = fake.calls[0]
    prefix = launch_slice(argv)
    assert prefix[:4] == [built.ip_bin, "netns", "exec", built.namespace]
    assert "--clear-groups" in prefix
    assert f"http_proxy={built.proxy_endpoint}" in argv
    # The phase's own argv is still intact at the end of the wrapped command.
    assert argv[argv.index("-p") + 2 :][:2] == ["--output-format", "stream-json"]


def test_a_phase_refuses_to_launch_uncontained_without_the_opt_out(
    engagement, store, fake_tools, monkeypatch, no_subprocess
):
    fake = FakePhaseRun()
    monkeypatch.setattr(runner, "_spawn_and_stream", fake)

    cfg = HuntConfig(engagement=engagement, allow_unpriced=True)
    with pytest.raises(RunnerError, match="without egress containment"):
        runner.run_phase(cfg, PHASES[0], store)
    assert fake.calls == [], "nothing may be spawned outside the namespace"


def test_the_opt_out_runs_the_phase_without_the_namespace(engagement, store, fake_tools, monkeypatch):
    fake = FakePhaseRun()
    monkeypatch.setattr(runner, "_spawn_and_stream", fake)

    cfg = HuntConfig(engagement=engagement, unsandboxed=True, allow_unpriced=True)
    assert runner.run_phase(cfg, PHASES[0], store).status == "ok"
    assert "netns" not in " ".join(fake.calls[0])


def test_the_runner_reads_this_module_as_the_containment_signal(engagement, fake_tools, no_subprocess):
    """runner.sandbox_state iterates verify(); an unbuilt sandbox is not a pass."""
    contained, problems = runner.sandbox_state(engagement)
    assert contained is False
    assert problems and "sandbox" in problems[0]


# ---------------------------------------------------------------------------
# root only
# ---------------------------------------------------------------------------

_ROOT = os.geteuid() == 0


@pytest.mark.skipif(not _ROOT or not shutil.which("nft"), reason="needs root and nftables")
def test_the_kernel_accepts_the_generated_ruleset(spec):
    """nft -c parses and validates against the kernel without applying anything."""
    done = subprocess.run(
        [shutil.which("nft"), "-c", "-f", "-"],
        input=sandbox.nft_ruleset(spec),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert done.returncode == 0, done.stderr


@pytest.mark.skipif(not _ROOT or not shutil.which("nft"), reason="needs root and nftables")
def test_the_kernel_accepts_the_generated_host_ruleset(spec):
    done = subprocess.run(
        [shutil.which("nft"), "-c", "-f", "-"],
        input=sandbox.nft_host_ruleset(spec),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
