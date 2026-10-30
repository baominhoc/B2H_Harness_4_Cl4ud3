"""One boundary for every string a target or an earlier phase wrote.

A bug bounty target is adversarial by definition, so the most likely
prompt-injection vector in this harness is a response body, and the second most
likely is a handoff written by a phase that read one. Both reach the next
phase's prompt, so they need a boundary the content itself cannot move.

The boundary is a nonce fence. The nonce is fresh per prompt and never leaves
the harness, so content captured before the prompt was built cannot name the
tag that would close it. That is the easy half. The hard half is content that
copies the tag *shape* and hopes the reader honours the first `</untrusted:` it
sees, so `scrub` neutralises every fence tag it finds in the body -- opening or
closing, whatever nonce it carries, partial, whitespace-padded, case-variant or
spelled with Unicode lookalikes -- before the real tags are wrapped around it.

Two deliberate choices, both of which read as weakenings until you look at the
threat:

* Tag neutralisation ignores the nonce. Killing only this fence's own closing
  tag would leave every near-miss standing, and a near-miss still reads like a
  fence close to a model skimming for one. Killing every fence tag means a
  breakout needs a tag shape this module does not model, not a lucky guess.
* Bare occurrences of the nonce are left alone. Masking them corrupts exactly
  the strings a hunt reasons about -- hash prefixes, request ids, ETags, session
  tokens -- and buys nothing, because six hex characters with no tag around them
  are not a boundary.

Matching runs over a folded copy of the text: one character in, one character
out, so match offsets stay valid in the original. That is what lets a lookalike
tag be rewritten in place without touching the evidence around it. The fold
answers one question per character -- what does a reader see here? -- and it
answers it by class rather than by codepoint, because an attacker picks the
codepoint and the harness does not get to pick first:

* Anything that renders as nothing, as a gap, or as a mark on its neighbour
  folds to a space. That is every control, format, surrogate, private-use and
  unassigned code point, every flavour of space and line separator, every
  combining mark, and the few letters and symbols Unicode draws with no ink at
  all. This test runs *before* the ASCII shortcut: U+0000-08, U+000E-001B and
  U+007F are ASCII and controls both, and letting them past unfolded is exactly
  how a tag with U+0001 after its slash once reached a prompt byte for byte.
* Otherwise a hand table answers first, because nothing in the standard library
  relates Cyrillic `е` to `e`. Then the character's own Unicode name is asked
  what it is drawn as -- "LATIN LETTER SMALL CAPITAL D" is a d, "HEAVY
  LEFT-POINTING ANGLE BRACKET ORNAMENT" is a chevron, "BIG SOLIDUS" is a slash
  -- and finally NFKD and NFKC resolve the fullwidth, circled and accented rest.

Reading the name is what closes a class instead of a codepoint, and it is why
`d` no longer needs the twenty-two entries a hand table would have taken. The
fold is still a floor rather than a complete confusables table, because the
cross-script class has no rule behind it and stays hand written. That is
survivable -- a lookalike tag is not the literal tag and so cannot close a fence
for any literal matcher anyway; folding stops it *looking* closed to a careless
reader.

Nothing here trusts itself: `fence` re-inspects the body it is about to wrap and
raises rather than emit a fence whose content could escape it. A phase that
cannot build a safe prompt aborts loudly instead of running on a degraded one.
"""

from __future__ import annotations

import re
import secrets
import unicodedata

TAG_NAME = "untrusted"

# 3 bytes -> 6 hex characters, per the contract. Short enough to stay readable in
# a prompt, and unguessable by content that was captured before it existed.
NONCE_BYTES = 3
DEFAULT_CAP = 4096

# The source label is rendered inside a quoted attribute, so it may not carry
# anything that could close the attribute or the tag. `<` is not in the
# allowlist, which is what makes the label inert whatever is passed.
SOURCE_CAP = 80
_SOURCE_DISALLOWED = re.compile(r"[^A-Za-z0-9 ._:/()+-]")

_NONCE_RE = re.compile(r"\A[0-9a-f]{6,32}\Z")

# Folded to a separator rather than to themselves: `untrusted` split by a
# zero-width joiner or padded with a non-breaking space is still the word a
# reader sees. The whole of category C is in here, unassigned and private-use
# included, because a code point this Unicode build cannot name is one whose
# glyph the harness cannot reason about -- and the fail-closed answer for an
# unknown is "it does not break the word", not "it does".
_SEPARATOR_CATEGORIES = frozenset(
    {
        "Cc", "Cf", "Cs", "Co", "Cn",  # control, format, surrogate, private use, unassigned
        "Zs", "Zl", "Zp",              # space, line and paragraph separators
        "Mn", "Me", "Mc",              # combining marks: ink on a neighbour, not a letter
    }
)

# Letters and symbols Unicode draws with no ink at all, which the categories
# above therefore miss. A tag with U+3164 after its slash renders exactly like
# one without it. Unicode's Default_Ignorable_Code_Point property names most of
# them and the standard library does not expose it, so they are spelled out --
# as escapes, because the whole point of these characters is that a reader
# cannot see which one is which.
_BLANK_GLYPHS = frozenset(
    "\u115f\u1160\u3164\uffa0"  # Hangul choseong/jungseong/compat/halfwidth fillers
    "\u2800"  # BRAILLE PATTERN BLANK
    "\U00013441\U00013442"  # EGYPTIAN HIEROGLYPH FULL / HALF BLANK
    "\U0001da7f\U0001da80"  # SIGNWRITING LOCATION-WALLPLANE / -FLOORPLANE SPACE
)

# Read off the character's own Unicode name, which states what it is drawn as.
# This is what closes a class rather than a codepoint: every small capital,
# every hooked, barred, boxed or parenthesised Latin letter, every chevron and
# every slash, instead of the handful an attacker happened to try first. A
# qualifier ("WITH STROKE", "WITH SMALL LETTER Z") names what was added to the
# base letter, so the base is whatever is left of the first " WITH ".
_LATIN_BASE_RE = re.compile(r"\bLATIN\b.*\bLETTER\s(?:.*\s)?(?P<base>[A-Z])\Z")
_ANGLE_RE = re.compile(r"\bLEFT(?:-POINTING)?\b.*\bANGLE\b.*\b(?:BRACKET|QUOTATION MARK)\b")
_SOLIDUS_RE = re.compile(r"\b(?:SOLIDUS|SLASH|RISING DIAGONAL)\b")

# Cross-script lookalikes, which no rule above can derive: nothing in the
# standard library relates Cyrillic `е` to `e`. Only the characters of `<`,
# `/` and `untrusted` matter, and this table is a floor, never a closed set.
_CONFUSABLES = {
    "‹": "<", "〈": "<", "⟨": "<", "❮": "<", "˂": "<", "ᐸ": "<",
    "∕": "/", "⁄": "/", "╱": "/", "⧸": "/", "ǀ": "/",
    "υ": "u", "Υ": "u", "ս": "u", "ᴜ": "u", "ц": "u",
    "ʋ": "u", "ʊ": "u",
    "ո": "n", "п": "n", "ᴎ": "n", "ɴ": "n",
    "τ": "t", "т": "t", "Т": "t", "ᴛ": "t",
    "г": "r", "ʀ": "r", "ᴦ": "r", "ґ": "r",
    "ѕ": "s", "Ѕ": "s", "ꜱ": "s", "ƽ": "s",
    "е": "e", "Е": "e", "ε": "e", "ℯ": "e", "ᴇ": "e",
    "є": "e", "ҽ": "e", "ϵ": "e",
    "ԁ": "d", "ɗ": "d", "Ꮷ": "d", "ԃ": "d",
}

# Matched against the folded view. The nonce, the closing `>` and even the `/`
# are all optional: the part that makes a reader stop reading is `<untrusted`,
# so that is the part that dies.
_SEP = r"\s*"
_TAG_RE = re.compile(
    r"<" + _SEP + r"(?P<slash>/)?" + _SEP + _SEP.join(TAG_NAME),
    re.IGNORECASE,
)


def new_nonce() -> str:
    """A fresh fence nonce: 6 hex characters, one per prompt."""
    return secrets.token_hex(NONCE_BYTES)


def fence(text: str, *, source: str, nonce: str, cap: int = DEFAULT_CAP) -> str:
    """Wrap untrusted `text` in a nonce fence that names where it came from.

    Clipped to `cap` characters first, then scrubbed, so scrubbing is the last
    thing that touches the body and truncation cannot leave a usable tag behind.
    """
    _check_nonce(nonce)
    label = _safe_source(source)
    if cap <= 0:
        raise ValueError(
            f"fence(cap={cap!r}) would put no bound on untrusted content, which is how one "
            f"enormous handoff blows the prompt budget. Pass a positive cap, e.g. "
            f"cap={DEFAULT_CAP}"
        )

    body = scrub(_clip(text, cap), nonce)
    if contains_fence_tag(body):
        # Unreachable unless scrub regressed. Refusing to build the prompt is the
        # fail-closed outcome: the alternative is handing the model a fence the
        # content can close.
        raise RuntimeError(
            f"refusing to fence content from {label!r}: a fence tag survived scrubbing, so "
            f"the content could close its own fence. This is a bug in bbh/untrusted.py; "
            f"reproduce it with: .venv/bin/python -m pytest tests/test_untrusted.py -x"
        )
    if not body.strip():
        body = "(empty)"
    return f'<{TAG_NAME}:{nonce} source="{label}">\n{body}\n</{TAG_NAME}:{nonce}>'


def scrub(text: str, nonce: str) -> str:
    """Neutralise every fence tag in `text`, so content cannot close its own fence.

    `nonce` is validated, not matched: see the module docstring for why a tag is
    killed whatever nonce it carries.
    """
    _check_nonce(nonce)
    if not text:
        return ""

    folded = _fold(text)
    out: list[str] = []
    cursor = 0
    for match in _TAG_RE.finditer(folded):
        out.append(text[cursor : match.start()])
        # One canonical inert spelling for every variant, so an injection attempt
        # is recognisable in the prompt rather than silently rewritten. The tail
        # (`:nonce>`, attributes) is left as it was: it is evidence, and without
        # an unescaped `<` it is inert.
        out.append("<\\" + ("/" if match.group("slash") else "") + TAG_NAME)
        cursor = match.end()
    out.append(text[cursor:])
    return "".join(out)


def contains_fence_tag(text: str) -> bool:
    """True when `text` holds something a reader could take for a fence tag."""
    return bool(text) and _TAG_RE.search(_fold(text)) is not None


# ---- internals ----


def _check_nonce(nonce: str) -> None:
    if not isinstance(nonce, str) or not _NONCE_RE.match(nonce):
        raise ValueError(
            f"fence nonce {nonce!r} is not 6-32 lowercase hex characters, so the tag built "
            f"from it would be malformed or guessable. Generate one per prompt with:\n"
            f"  from bbh.untrusted import new_nonce\n"
            f"  nonce = new_nonce()"
        )


def _safe_source(source: str) -> str:
    label = _SOURCE_DISALLOWED.sub("", str(source or "").strip())[:SOURCE_CAP]
    if not label:
        raise ValueError(
            f"fence(source={source!r}) must name where the content came from -- it is "
            f"printed in the tag so the agent can tell a prior handoff from a response "
            f"body. Call it as:\n"
            f'  fence(text, source="prior-phase handoff", nonce=new_nonce())'
        )
    return label


def _clip(text: str, cap: int) -> str:
    text = text or ""
    if len(text) <= cap:
        return text
    return text[:cap] + (
        f"\n... [truncated by the harness; {len(text) - cap} more characters are on disk]"
    )


def _renders_as_nothing(ch: str) -> bool:
    """True when a reader sees no ink here, so the character cannot break a word."""
    return unicodedata.category(ch) in _SEPARATOR_CATEGORIES or ch in _BLANK_GLYPHS


def _named_lookalike(ch: str) -> str | None:
    """The ASCII character `ch`'s Unicode name says it is drawn as, or None."""
    try:
        name = unicodedata.name(ch)
    except ValueError:
        # Nameless code points are the invisible categories, which have already
        # folded to a space by the time this runs, and the Tangut and Nushu
        # ideographs, which no reader takes for a Latin letter. "No opinion" is
        # the right answer for both; tests/test_untrusted.py keeps it true.
        return None
    match = _LATIN_BASE_RE.search(name.split(" WITH ", 1)[0])
    if match:
        # Lower case throughout: _TAG_RE is IGNORECASE, and the folded view is a
        # matching artefact that nobody reads.
        return match.group("base").lower()
    if _ANGLE_RE.search(name):
        return "<"
    if "REVERSE" not in name and _SOLIDUS_RE.search(name):
        # A REVERSE SOLIDUS is a backslash, which no fence tag contains.
        return "/"
    return None


def _fold_char(ch: str) -> str:
    """Canonical single character for `ch`. One in, one out, always."""
    # Ink first, ASCII second. A C0 control is both ASCII and invisible, and
    # answering "is it ASCII?" first is what let one hide inside a tag.
    current = ch
    for _ in range(3):
        if _renders_as_nothing(current):
            return " "
        if current.isascii():
            return current
        # The hand table, then the name, then NFKD (it strips accents and
        # resolves fullwidth and variant forms) and NFKC (which resolves a few
        # compatibility singletons NFKD leaves, such as U+017F long s). Bounded:
        # normalisation is idempotent, so three passes is already more than needed.
        mapped = _CONFUSABLES.get(current) or _named_lookalike(current)
        if mapped:
            return mapped
        for form in ("NFKD", "NFKC"):
            step = unicodedata.normalize(form, current)[:1]
            if step and step != current:
                current = step
                break
        else:
            break
    return current if len(current) == 1 else ch


def _fold(text: str) -> str:
    """A same-length view of `text` with lookalikes and invisibles canonicalised."""
    folded = "".join(_fold_char(ch) for ch in text)
    if len(folded) != len(text):
        # Offsets would no longer line up, so a match could be spliced into the
        # wrong place in the original. Deny instead.
        raise RuntimeError(
            "bbh/untrusted.py: the character fold changed the text length, so scrub cannot "
            "place its replacements. Every value in _CONFUSABLES and every character "
            "_named_lookalike returns must be exactly one character; check it with: "
            ".venv/bin/python -m pytest tests/test_untrusted.py -x"
        )
    return folded
