# claude-harness

An autonomous bug bounty harness for Claude Code.

`bb hunt` runs an unattended hunt against **one authorized program**: recon, access setup,
a class sweep, impact work, then a chain of triage gates that kill most of what the hunt
produced. What survives gets a report assembled from recorded evidence.

The interesting part is not the hunting. It is everything built to stop the hunt lying to you.

---

## Why this exists

Two failure modes make AI bug bounty hunting useless, and the prompts are not the fix for
either.

**Out-of-scope traffic.** A human running a scan notices when it wanders. An unattended agent
does not, and a program's goodwill does not survive a researcher scanning assets they were
never authorized to touch. So scope here is not an instruction — it is a boundary the agent
cannot cross, checked before every command, every request, and every proxied flow.

**Confident nonsense.** An agent will report a plausible bug it cannot reproduce, and a
triager will close it and remember your handle. So no finding reaches a report on assertion:
evidence means a hashed artifact or a recorded request, and every gate recomputes from those
artifacts rather than trusting what the model wrote about them.

Roughly nine in ten candidates should die before submission. The gates are built so that
killing a finding is the cheap path and advancing one costs work.

---

## Install

```sh
git clone <this repo> ~/claude-harness
cd ~/claude-harness
uv venv .venv && uv pip install --python .venv/bin/python pytest requests pyyaml mitmproxy
./bin/bb install-hook      # registers the PreToolUse scope guard
./bin/bb doctor            # verifies the guard actually denies
```

`mitmproxy` is needed by `bb proxy` and by the sandbox, which routes all egress
through it. Without it `bb doctor` warns and the sanctioned HTTP client still
works, but there is no containment.

`bb doctor` ends by running a known out-of-scope command through the guard and confirming it
is denied. If that check does not pass, the harness is not protecting you, whatever else
reports green.

## A hunt

```sh
bb go '*.acme.com'
```

That is the whole thing. It derives an engagement name from the target, creates it, compiles
and signs the scope, arms an attestation long enough to cover the hunt, and runs all ten
phases. It prints the plan — name, targets, budget, hours, model, containment — before it
does any of it, so a mistyped domain is visible in the first five lines.

Defaults are **no dollar cap**, `--hours 12`, `--model opus`, and **no egress sandbox**.

With no cap the spend is still measured, recorded and printed per phase and in the summary —
you are simply never stopped by it. What stops the hunt instead is the clock and the turn
caps: every phase carries `--max-turns` (40–120, 720 across the ten) and the whole run carries
the deadline. `--budget-usd N` reinstates a cap; `bb hunt` keeps its own $25 default, so an
upgrade never silently removes a cap something is relying on.

Without the sandbox, the scope guard and the sanctioned client are the barrier. That is a real
step down from the network namespace — the guard parses 44 named tools, so `curl` is checked
and `git clone` is not — and the plan says so every run. `--sandbox` requires containment
instead, and then `bb sandbox up` has to have been run first.

**Re-running `bb go` on the same target continues that engagement.** Findings, evidence and
the request log are untouched, finished phases are not redone or re-paid for, and your own
edits to `scope.yaml` — exclusions, rate limits, program constraints — survive byte for byte.
So recovering an interrupted hunt is the same command again, and adding a target is the same
command with one more argument.

In Claude Code, `/bbh '*.acme.com'` does the same thing and reads the results back.

<details>
<summary>The long way, when you want each step</summary>

```sh
bb new acme --program-url https://hackerone.com/acme --target '*.acme.com'
$EDITOR engagements/acme/scope.yaml      # in_scope, out_of_scope, rate limits
bb scope compile acme
bb arm acme --as you@example.com --hours 12
bb sandbox up acme && bb sandbox verify acme   # network containment; one sudo
bb proxy start acme --listen-host <veth host addr>   # the sandbox's only exit
bb hunt acme --budget-usd 25 --deadline 2026-11-01T09:00Z
```

`bb hunt` refuses to start without containment unless you pass `--unsandboxed`. `bb sandbox
up` prints the exact `bb proxy start` line to run, including the address the proxy has to
bind, which is the veth host address and not `127.0.0.1` (loopback inside the namespace is the
namespace's own).

Arm for longer than the hunt. `bb hunt` refuses when the attestation expires before the
deadline, because those hours would be spent with every request denied and recorded as covered
ground — `bb go` computes the window for you, which is the main thing the long way gets wrong.

</details>

Interrupt it whenever; `bb go '*.acme.com'` or `bb hunt acme --resume` continues from the last
completed phase.
`bb cleanup` stops what the harness started, and only what it can still prove it started:
every registered pid is re-checked against `/proc/<pid>/cmdline`, its start time and the boot
id before a signal is sent, and a mismatch is refused rather than killed.

```sh
bb status acme          # phases, findings by state, cost, requests made
bb finding list         # what survived, and what died with the reason
bb report --all         # reports for findings in state gated or ready
```

Nothing is ever submitted for you. The last step is a human reading the report.

---

## Scope

`scope.yaml` compiles to a signed lock that every enforcement layer reads.

```yaml
engagement: acme
program_url: https://hackerone.com/acme

in_scope:
  - "*.acme.com"                   # wildcard; covers the apex by convention
  - type: url_prefix
    value: https://shop.acme.com/app/
  - type: cidr
    value: 203.0.113.0/24

out_of_scope:
  - support.acme.com               # out_of_scope always wins
  - "*.blog.acme.com"

rules:
  max_rps: 2
  max_requests: 20000
  allow_tools: []                  # opt in per tool: nmap, sqlmap, gobuster, ...
  oob_hosts: ["*.oob.example.net"] # your callback host: reachable, but not a target asset
```

Out-of-scope beats in-scope. Anything unlisted is denied. An explicit rule beats the
private-address heuristic, so a deliberately scoped CIDR works while a stray
`169.254.169.254` from an SSRF pivot does not. An unknown key anywhere in the file is a
compile error with a spelling suggestion, because `rules: {max_rsp: 0.5}` merging through and
limiting nothing is the worst of the three possible outcomes.

The program's own limits go in a separate block, and they can only ever **clamp**:

```yaml
program_constraints:          # copied from the policy page; never loosens `rules`
  max_rps: 0.5
  required_headers: {X-Bug-Bounty: <your handle>}
  forbidden_tests: [delete, account_takeover]
```

A constraint key this build cannot enforce stops the compile rather than being ignored:
dropping a program's own limit is what would make `bb arm`'s attestation a false statement.
The sanctioned client and the intercept proxy both apply them, so they hold for `bb req` and
for browser traffic alike. The PreToolUse guard does not — see "Still broken" below.

**Arming.** `bb arm` records who attested authorization and when it expires, then signs the
lock. An unarmed or expired engagement denies every target. The expiry means a forgotten
engagement goes quiet on its own instead of staying live.

---

## How enforcement actually works

Four layers, honestly ranked by how much they are worth.

**1. Network namespace** (`bb sandbox up`) — the real boundary. The phase runs in a netns with
exactly one permitted route, the harness proxy, and everything else **rejected** (`reject with
tcp reset` for TCP, plain `reject` otherwise) over a `policy drop` backstop. No resolver inside.
A raw socket, a compiled binary, `/dev/tcp`, `git clone`, an interpreter nobody modelled — all
of it either goes through the proxy and gets scope-checked, or goes nowhere.

Reject rather than drop, and the difference is not cosmetic: measured in a nested
`unshare -Urnm` testbed with two real namespaces and a real veth pair, containment was
identical on every probe and time-to-fail went from 135s to 0.00s. The 135s is the kernel's
SYN retry schedule, and what the agent sees at the end of it is a timeout — which it reads as
an unresponsive target and writes into the angle ledger as covered ground. A harness denial
laundered into a false negative is worse than a loud refusal. `bb sandbox verify` therefore
**fails** a negative probe that times out: a probe that waits is a drop-based namespace left
up by an older install, and the remedy is `bb sandbox down && bb sandbox up`.

**2. PreToolUse guard** — defence in depth, and the layer that gives *good error messages*. It
parses every Bash command, extracts targets, and denies what it cannot verify: a `$VAR` or
`$(...)` standing in for a host, a pipe feeding targets on stdin, a missing rate limit, a tool
not opted into. A `python3 -c` body is parsed with `ast` and cleared by the *absence* of a raw
network import, a shell-out and code the guard cannot read, rather than by the presence of a
blessed string; other interpreters get no exemption at all. Any flag whose value is a
destination the guard cannot resolve is denied by name — `curl -x`, `--proxy`, `--resolve`,
`ssh -D`, `-r resolvers.txt`, `--config` — and so is a bash `/dev/tcp` or `/dev/udp`
redirection, **including to an in-scope host**: the sanctioned client is where the recording
lives, and a request nothing recorded cannot be cited as evidence. Verified: hooks fire under
`bypassPermissions`, so unattended runs are covered.

**3. Sanctioned HTTP client** — `bb req` / `bbh.http.Session`. Scope-checks each redirect hop,
enforces the rate limit and request budget, trips a circuit breaker on `429`/lockout rather
than sleeping through it, and records every request so it can be cited as evidence. Everything
it prints back that the target produced is nonce-fenced and marked as data, the same way
prompt content is. The proxy records a request that left and was never answered, which is what
makes `rules.max_requests` a real brake against a host that drops rather than refuses — both
layers count the budget as rows in the requests table, and the circuit breaker cannot help
because it trips on a status code and there is no status.

**4. Signed scope lock** — the lock lives outside the directory the agent works in and carries
an HMAC. A modified lock fails closed in all layers: one flipped byte, a flipped signature or a
stripped signature each refuse the whole engagement rather than just the edited rule, in the
CLI, the guard hook, the HTTP client, the runner and the proxy's scope binding.

The audit log is hash-chained on top of this — every record carries the sha256 of the line
before it, and `bb doctor --verify-chain` reports any break. All five writers chain.

### What this does not protect against

Layers 2–4 run as your user, so a determined process could read the signing key or edit state
directly. They buy tamper-*evidence* against a confused or prompt-injected agent, which is the
realistic threat. Layer 1 is the one that buys containment, and it is the reason `bb hunt`
refuses to start unsandboxed unless you pass `--unsandboxed` and accept it in writing.

Target responses are untrusted input. Bodies are never interpolated into a prompt; anything
target-derived is nonce-fenced and marked as data. The harness deliberately contains **no**
language telling the agent not to question its authorization — that is the exact brake a
prompt injection in a target response would want removed.

---

## Phases

| | phase | what it does |
|---|---|---|
| 00 | recon | minimum surface map: live hosts, routes, auth surfaces, JS endpoints |
| 01 | access | researcher accounts, and **who owns which object** |
| 02 | sweep | broad shallow pass across vuln classes, recording every angle |
| 03 | deepen | chase real impact on the strongest candidates |
| 04 | triage | cheap kills; merge duplicates |
| 05 | validate | reproduce with real evidence attached |
| 06 | verify | re-prove from a clean position, information-isolated |
| 07 | gate | hostile triager: the prompt's 14 hard-fail checks on top of the 14 code gates |
| 08 | dedupe | collapse findings that are one underlying bug |
| 09 | report | assemble from the store; the model writes prose only |

Phase 01 matters more than it looks. Registering which account owns which object is what lets
the ownership gate tell a real access-control break from changing an id you already own — the
single most common fake IDOR.

Handoffs between phases are validated **mechanically**: a missing key fails the phase and
re-runs it. Budget, soft/hard deadlines and resume are enforced by the runner, not requested
in a prompt.

---

## Gates

Deterministic checks, run before any model judgement, so nothing passes on rhetoric:

- evidence exists, every artifact still hashes to what was recorded
- at least one cited request resolves to a real row in the store
- every URL in the reproduction appears in a request the harness actually sent
- for access-control classes, the touched object is owned by a *different* account
- prerequisites are attacker-reachable — owning both test accounts proves authz is broken and
  is zero evidence an attacker could obtain the identifier
- severity is derived from a CVSS vector, not asserted
- no other live finding holds the dedup key the harness computes from the cited traffic
- the claim still matches the bytes pinned before the independent pass re-proved it
- `info` never ships

A finding that cannot be reproduced is `blocked`, not `rejected`. Tooling failure laundered
into a false negative is worse than no result, because the angle ledger then tells every later
run that ground is covered. `bb finding show` prints the condition that clears a block, and
`bb finding advance <ref> blocked --unblock-condition '<what would clear it>'` is how one is
recorded by hand.

`bb gate` runs every gate that guards `gated` -- fourteen -- because that is the state `bb
report` emits from. `--target validated|verified` runs the gates that guard the earlier rungs
instead. A finding reaching `gated` is walked up the ladder one rung at a time, so each rung's
own bar is applied on the way: `advance(..., "validated")` refuses a finding with no
counterevidence, confidence or severity-change conditions, and `gate_counterevidence_recorded`
asks the same question again at every rung above it, recomputed from the store.

Passing the gates is also how a finding becomes reportable, not just how it changes state.
`bb report` reads the `gates` rows and refuses a finding whose state no gate produced, so
`bb finding advance <uid> gated` on an unproven candidate gets a refusal naming the gates with
no verdict on record rather than a document a human would act on.

**Waivers.** Two gates can be stood down, and only by an operator: `gate_evidence_roles`,
because a public or single-party bug has no owner side to photograph, and
`gate_independent_verification`, because a single-shot bug cannot be re-attacked without doing
the target further harm. `bb gate waive <finding> <gate> --reason '<why>' --as <who>` writes a
signed file outside the directory a phase can write, expiring and clamped to the engagement's
own authorization expiry, and it lapses by itself if the finding is reclassified, moves asset
or changes its evidence set. A waived gate displays and ships as `waived`, never as `pass`, and
the report carries a block saying the requirement was stood down and by whom. Everything else
is unwaivable, and a gate added later is unwaivable by default.

The asymmetry is mechanical, not written in a prompt. `bb gate waive` refuses while a phase is
running — a running phase is an agent at the keyboard, and the subject of a gate may not stand
its own gate down. What an agent has instead is `bb gate waive-request <finding> <gate>
--reason '<why>'`, which records the argument as a `fail` row and grants nothing.

---

## Coverage

The angle ledger records what an agent says it tried. `bb coverage` computes what was never
tried at all, from the request log rather than from that account:

```sh
bb coverage                      # a row per class: eligible, tested, remaining, status
bb coverage --class idor         # every surface still untested for one class
bb handoff write 02-sweep        # validate a phase's deliverable, and print the gaps it leaves
```

`remaining(cls) = eligible(cls) − tested(cls)` over a `surfaces` table derived mechanically
from the requests table plus the recon handoff, one row per `(host, path_shape, method)`.
`tested` needs corroboration — a settled angle *and* recorded traffic on that exact surface —
so a `ruled_out` on ground the request log never touched is reported as an unsupported claim
rather than counted. The recon handoff may only *add* surfaces: nothing a model writes can mark
ground covered.

The case this exists for is the empty one. A class with **no eligible surface** reads
`unrouted`, not clean, and closing it takes a recorded mechanical fact:

```sh
bb coverage reason file-upload 'no mapped surface accepts a file upload, and recon found no upload form'
```

The gaps are appended to the next phase's prompt, fenced like any other target-derived text, so
a phase cannot read silence as coverage.

## Still broken / not built

Current as of the third pass. `CHANGELOG-v2.md` has the detail; this is the honest short
list, because a harness whose README reads as if everything works is the problem it exists to
solve.

**Unproven, not unbuilt — the sandbox has never been brought up for real.** `bbh/sandbox.py`
is complete and its generated ruleset was applied by a real kernel inside throwaway
unprivileged `unshare -Urn` and `unshare -Urnm` namespaces, where the kernel's own dump
matched it exactly and every blocked probe was measurably blocked — including, in the nested
testbed, across a real veth pair between two namespaces. But `sudo` needs a password in the
environment this was built in, so the real `ip netns` plumbing and the live proxy path have
never run end to end as `bb sandbox up` would run them. The first real one may well fail; `bb
sandbox verify` is what will say so, and it fails closed. **Do not treat layer 1 as proven
until you have seen `bb sandbox verify` pass on your own machine.**

**Root is needed for more than setup.** Entering a named netns needs `CAP_SYS_ADMIN`, so each
phase launch is `sudo -n -- ip netns exec ... setpriv --reuid=<you>`. `setpriv` drops straight
back to the invoking uid, so the agent never holds more privilege than you did, but an
unattended hunt needs a `/etc/sudoers.d` line (`bb sandbox up` prints it) or the sandbox check
fails rather than hanging on a prompt nobody will answer.

**Not built at all:**

- **`program_constraints` does not reach the PreToolUse guard.** `bbh.http.effective_rules`
  applies the clamp and `bbh/proxy_addon.py` now calls it, so a program's `max_rps: 0.5` and
  its `forbidden_tests` hold for both `bb req` and browser traffic through `bb proxy`.
  `bbh/guard.py` still reads `scope.rules` unclamped for its scanner rate check, so
  `nuclei -rate-limit 2` is waved through on an engagement whose program said 0.5. Smaller
  than it was — the guard checks a flag, while the proxy was sending the packets — but still
  a figure the guard affirms and the program did not agree to. The fix is to move the clamp
  arithmetic out of `http.py` into `scope.py`, which every layer already imports; the earlier
  claim here that the addon "cannot import the clamp" was simply wrong, since it has always
  imported `bbh.http` for its rate limiter.
- **Nothing calls `bb cleanup` automatically.** `bb proxy start` registers the proxy and `bb
  proxy stop` goes through the registry, but a hunt that is interrupted leaves a registered
  proxy running and only a human running `bb cleanup` stops it. The runner does not register
  the processes it launches either; its own `claude -p` child is reaped by its process-group
  kill, so what is missing is anything longer-lived that a phase starts.
- **No `bb req list`.** `store.search_requests` has no CLI caller at all, so `bb req show <id>`
  can only be pointed at an id you already have, and its own "no request N" refusal can only
  send you to `bb status` and `bb evidence list`.
- **No brake on repeated unanswered requests to one host.** The request budget is now a real
  stop for a host that answers nothing, which was the hole; but N consecutive failures to one
  host is a tighter and much cheaper signal than waiting for 20000.
- **`http.persist_body` records an absolute `resp_body_path`** while `paths.py` promises the
  harness is "one movable directory". Move the tree or change `BBH_HOME` and every recorded
  body path is stale. `bb req show` recovers through the content-addressed filename;
  `store.verify_evidence`, triage's re-hashing and `report.render` read the stored path and
  would all report evidence as missing.
- **No per-program severity floor.** `gate_severity_floor` hardcodes `low`, `scope.yaml` has
  no `policy:` key, and the new unknown-key check means writing one is a compile error.
  CONTRACT's "do not copy" item 3 asked for it; it is not built.
- **Two path normalisers exist.** `triage.normalize_path_shape` (dedupe) and
  `coverage.path_shape` (the surface inventory) are deliberately different — dedupe is safe
  when it over-collapses, coverage is safe when it under-collapses — and a test pins that they
  agree on the common core. They still disagree on three cases where coverage is coarser
  (`{date}` segments, `{id}.ext` stems, `:id`/`<id>`/`*` templates), and in each of those
  dedupe loses a collision: `/files/1.pdf` and `/files/2.pdf` get different dedup keys and both
  ship.
- **`angles.surface` carries no method**, so an angle credits every method variant of a route
  unless its technique slug names one. Coverage narrows rather than widens, so the residual
  error is extra remaining work and never missing work.
- **`store.advance` overwrites `reject_reason`**, and nothing else records a prior one. There
  is no state-transition log, so "what did this finding say before" is unanswerable;
  `bb finding merge` works around it by folding the earlier reason into the merge reason.
- **`store.advance` still permits a multi-rung jump.** The gates are enforced on the way to a
  *report* (`bb report` recomputes from the `gates` rows), not on the way to a *state*, so
  `bb finding advance <uid> gated` on an unproven candidate still succeeds and still shows up
  in `bb finding list --state gated` and in the hunt summary's counts. Refusing a jump of more
  than one rung in `store.advance` is the other half and is not built.

**Where a control stops being containment.** Three of the four layers run as your uid, so
these are tamper-*evidence* against a confused or injection-steered agent, not barriers:

- The scope lock, the armkey, the signed waivers and the pinned claims are outside the
  directory a phase is handed, and so now are the guard-hook settings file, the rate bucket,
  the circuit breaker and the spend ledger. Same uid still reaches all of them. What moving
  them bought is that disarming a control is no longer an ordinary write in the agent's own
  working tree, and that the harness re-derives each one and checks it before the next spawn.
- `engagements/<name>/bbh.sqlite3` cannot move: findings, evidence, angles and accounts are
  the agent's own output and have nowhere else to live. So the dollar budget is also written
  to a ledger outside it by the runner (the only thing that ever learns a phase's cost), the
  request count is sampled at each phase boundary as a high-water mark, and `bb report` reads
  the `gates` rows rather than `findings.state`. Each of those raises the cost of the bypass
  from one command to fabricating rows; none of them closes the uid.
- Deleting the ledger alone gains nothing and is not refused — the store still holds every
  row. Deleting the ledger *and* the store's rows in the same breath is the attack, and only
  the process-local floor catches it, which does not survive a restart.
- The counterevidence bar is a length-and-stub predicate over text the agent writes. Eighty
  characters of plausible nonsense clears it.

**Known weaker-than-specified:** an unknown `actor` is refused only while a roster exists. With
an empty `accounts` table the label is accepted and audited once per session, because
`objects.owner_account` is a foreign key to `accounts(label)` — with no accounts there are no
ownership facts to protect, and recon runs before `01-access` registers anything. To make it
strict, register an account in the `session` fixture in `tests/test_http.py` and delete the
`if not labels:` branch in `Session._actor_refusal`.

**What the guard cannot see**, and does not claim to: `python3 -m <module>` runs code that is
not on the command line, a heredoc piped into a non-Python runner is shredded on newlines,
`deno run x.ts` hides the script behind a subcommand, and `f = exec; f("...")` escapes the
opaque-call check. `curl -L` follows a redirect to anywhere and the destination is not in the
command, so it is left to the client's redirect-hop checking. The netns is the boundary; the
guard is the layer that gives good error messages. Note one deliberate consequence: `puredns`,
`shuffledns` and `massdns` normally require `-r resolvers.txt`, which is now denied, so they
are effectively unusable.

**Performance:** `runner.sandbox_state` runs all three sandbox probes on every call — once per
hunt plus once per phase. It is deliberately not cached: a cache would stop the runner noticing
a sandbox that went away mid-hunt. The cost used to be ~6–7s because two blocked connects each
waited out a 3s timeout; with the ruleset rejecting rather than dropping they return
immediately, so re-measure before quoting a number.

**The phase prompts still teach the v1 angle words alongside the v2 ones.** `store.record_angle`
maps `negative → ruled_out`, `finding → confirmed`, `partial → open_gap`, so nothing breaks,
but the alias shim is the single place to delete once the prompts speak only v2.

---

## Authorized use

Point this at programs you are authorized to test, within their rules. `bb arm` exists to make
that a deliberate, recorded, expiring act rather than an assumption. The harness will not
submit anything for you, and the last reader before a report goes to a program is you.

## Layout

```
bbh/        paths scope guard store http runner triage report proxy_addon
            sandbox untrusted secrets cvss coverage proc waiver cli
prompts/    one file per phase
engagements/<name>/   scope.yaml, db, raw/ (0700), evidence/, findings/,
                      reports/, handoff/, sensitive/ (0700)
.state/     active engagement, signed locks, armkey, hash-chained audit log,
            sandbox plans, pinned claims (frozen/), signed waivers (waivers/),
            the process registry (procs.json), and runtime/<name>/ --
            the guard-hook settings file, the rate bucket, the circuit
            breaker and the spend ledger
```

`CONTRACT.md` is the build spec and records the design decisions, including what was
deliberately *not* copied from the systems this was studied against.
`CHANGELOG-v2.md` records what the v2 hardening added, which seams had to be closed to make
the parts work together, and the honest bound on each control.
