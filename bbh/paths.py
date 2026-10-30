"""Filesystem layout for the harness. Stdlib-only.

Everything lives under the harness root so the whole thing is one movable
directory: code in bbh/, engagement data in engagements/ (gitignored, since it
holds target traffic and researcher account pointers). Every path is
overridable by env var so tests can run against a throwaway root.
"""

from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOME = Path(os.environ.get("BBH_HOME") or REPO).expanduser().resolve()

ENGAGEMENTS = HOME / "engagements"
STATE_DIR = HOME / ".state"
ACTIVE_FILE = STATE_DIR / "active"
AUDIT_LOG = STATE_DIR / "audit.jsonl"
PROMPTS = REPO / "prompts"

# The compiled scope lock is the document that authorizes testing, so it does not
# live in the engagement directory the runner hands to the agent. It is also HMAC
# signed with ARMKEY (see scope.sign_lock): same-uid means a determined process can
# still read the key, so this buys tamper-evidence against a confused or
# injection-steered agent, not containment. Containment is the network sandbox.
LOCKS_DIR = STATE_DIR / "locks"
ARMKEY = STATE_DIR / "armkey"

# Live enforcement state, out here for the same reason the lock is: runner's
# run_phase hands the agent the engagement root with `--add-dir`, so anything
# under engagements/<name>/ that decides what the agent may do is a control the
# agent can edit with an ordinary file write. The guard-hook settings file, the
# rate-limit token bucket, the circuit breaker and the harness's own spend
# ledger are all in that class, so all four live here instead.
#
# Same honest bound as ARMKEY: same-uid means a determined process can still
# reach these. What moving them buys is that disarming a control is no longer
# an ordinary write inside the directory the agent was handed, and that the
# harness re-derives each one from here rather than from a path the agent
# could have replaced.
RUNTIME_DIR_NAME = "runtime"

# These paths are built from an engagement name that reaches the harness through
# BBH_ENGAGEMENT, which is an environment variable the phase subprocess sets for
# its own `bb` calls. A name carrying a separator would land the "outside the
# engagement root" files back inside it, or anywhere else, so the ones added
# here check. The older helpers above predate the check and are reached with a
# name that `scope.compile_scope` already validated.
_NAME_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def _engagement_name(name: str) -> str:
    text = str(name or "").strip()
    if text and text not in (".", "..") and set(text) <= _NAME_OK:
        return text
    raise ValueError(
        f"engagement name {name!r} is not a plain name, so harness-owned state for it has "
        f"no safe location and the controls keyed on it cannot be found. Use the name "
        f"`bb list` prints, for example: bb use acme"
    )

# Subdirectories created for every engagement.
ENGAGEMENT_SUBDIRS = (
    "raw",
    "evidence",
    "findings",
    "reports",
    "handoff",
    "notes",
    "sensitive",
)


def engagement_dir(name: str) -> Path:
    return ENGAGEMENTS / name


def lock_path(name: str) -> Path:
    return LOCKS_DIR / f"{name}.lock.json"


def runtime_dir(name: str) -> Path:
    """Harness-owned live state for one engagement, outside its data directory."""
    return STATE_DIR / RUNTIME_DIR_NAME / _engagement_name(name)


def settings_path(name: str) -> Path:
    """The generated `--settings` file that registers the PreToolUse scope guard."""
    return runtime_dir(name) / "settings.json"


def rate_path(name: str) -> Path:
    """The shared rate-limit token bucket (bbh.http.RateLimiter)."""
    return runtime_dir(name) / "rate.json"


def breaker_path(name: str) -> Path:
    """The shared per-host circuit breaker (bbh.http.CircuitBreaker)."""
    return runtime_dir(name) / "breaker.json"


def ledger_path(name: str) -> Path:
    """The harness's own spend ledger, written only by bbh.runner."""
    return runtime_dir(name) / "ledger.json"


def armkey() -> bytes:
    """Read the HMAC key used to sign scope locks, creating it on first use."""
    import os as _os
    import secrets

    if ARMKEY.exists():
        return ARMKEY.read_bytes()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    fd = _os.open(str(ARMKEY), _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
    try:
        _os.write(fd, key)
    finally:
        _os.close(fd)
    return key


def scope_path(name: str) -> Path:
    return engagement_dir(name) / "scope.yaml"


def db_path(name: str) -> Path:
    return engagement_dir(name) / "bbh.sqlite3"


def active_engagement() -> str | None:
    """Name of the engagement currently selected, or None."""
    override = os.environ.get("BBH_ENGAGEMENT")
    if override:
        return override.strip() or None
    try:
        name = ACTIVE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return name or None


def set_active(name: str | None) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if name is None:
        ACTIVE_FILE.unlink(missing_ok=True)
    else:
        ACTIVE_FILE.write_text(name + "\n", encoding="utf-8")


def ensure_engagement_tree(name: str) -> Path:
    root = engagement_dir(name)
    for sub in ENGAGEMENT_SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)
    # sensitive/ holds credentials; raw/ holds captured traffic, whole stream
    # transcripts and response bodies, which is the same exposure by a different
    # name. Restricted here as well as by secrets.harden_raw(), so a library
    # caller that builds the tree directly does not leave it at the umask
    # default. A filesystem without unix modes is not a reason to fail.
    for private in ("sensitive", "raw"):
        try:
            (root / private).chmod(0o700)
        except OSError:
            pass
    return root


def list_engagements() -> list[str]:
    if not ENGAGEMENTS.is_dir():
        return []
    return sorted(p.name for p in ENGAGEMENTS.iterdir() if (p / "scope.yaml").exists())
