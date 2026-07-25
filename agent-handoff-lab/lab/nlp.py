"""A tiny, offline, stdlib-only 'semantic' layer for the handoff lab.

The marker-based lab (`[[SETROLE:..]]` etc.) is deliberately clean: injections
are *syntactically labelled*, so the "don't honor markers" defense is a perfect
regex. Real prompt injection is natural language, and that is what this module
models — WITHOUT a real model, but honestly, by separating two capabilities
that a marker-regex conflates:

  detect(text, level="llm")     - what the gullible model *comprehends* as an
                                  instruction. Broad: it normalizes obfuscation
                                  (zero-width chars, homoglyphs, base64) and
                                  knows synonyms ("superuser" == admin).

  detect(text, level="filter")  - what a static input GUARD catches. Narrow: it
                                  sees the raw bytes and only a fixed pattern
                                  list, so paraphrase and obfuscation slip past.

The `filter` set is a strict subset of what `llm` comprehends. That gap is the
whole point: a defense that *detects and strips* injections (the `filter`) will
always trail the model's comprehension, whereas the provenance/least-privilege
defenses are content-independent and cannot be paraphrased around. The metrics
harness measures exactly this gap.

Both levels return items shaped like the marker payloads the runtime already
understands, so the engine can treat a comprehended NL instruction and a literal
marker identically: [("SETROLE", "admin"), ("TOOL", "run_sql(SELECT ...)"), ...]
"""
from __future__ import annotations

import base64
import re

# --- obfuscation the *model* sees through but a byte-level filter does not ----
_ZERO_WIDTH_CHAR = "​"      # the char generators splice into keywords
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)
_HOMOGLYPHS = {  # Cyrillic/Greek/full-width look-alikes -> ASCII
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "ѕ": "s", "і": "i",
    "ԁ": "d", "ո": "n", "г": "r", "т": "t", "у": "y", "х": "x", "к": "k",
    "ѵ": "v", "ԝ": "w", "ｇ": "g", "ｈ": "h", "ｌ": "l", "ｕ": "u",
    "ｚ": "z", "ｆ": "f", "ｊ": "j", "ｑ": "q", "ｂ": "b",
    "ａ": "a", "ｄ": "d", "ｍ": "m", "ｉ": "i", "ｎ": "n",
}
# First look-alike per ASCII letter, for generating homoglyph obfuscations that
# defold cleanly back through `normalize()`. Keeping generation and detection on
# the same table guarantees the round-trip the measurement relies on.
_TO_HOMOGLYPH = {}
for _glyph, _ascii in _HOMOGLYPHS.items():
    _TO_HOMOGLYPH.setdefault(_ascii, _glyph)


def to_homoglyphs(t: str) -> str:
    """Swap each ASCII letter for a look-alike the filter reads as a foreign
    codepoint but `normalize()` folds straight back — the model sees through it,
    a byte-level guard does not."""
    return "".join(_TO_HOMOGLYPH.get(c.lower(), c) for c in t)


def _strip_zero_width(t: str) -> str:
    return t.translate(_ZERO_WIDTH)


def _defold_homoglyphs(t: str) -> str:
    return "".join(_HOMOGLYPHS.get(c, c) for c in t)


def _decode_base64_blobs(t: str) -> str:
    """Append the plaintext of any base64-looking token — a model that is asked
    to 'decode and follow' will read it; a literal-string guard will not."""
    extra = []
    for tok in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", t):
        try:
            dec = base64.b64decode(tok).decode("utf-8", "ignore")
        except Exception:
            continue
        if dec and dec.isprintable():
            extra.append(dec)
    return t + (" " + " ".join(extra) if extra else "")


# --- ASCII smuggling: instructions hidden in invisible Unicode code points ----
# Johann Rehberger's "ASCII Smuggling" (Unicode Tags block, U+E0000-U+E007F) and
# "Sneaky Bits". These characters render as nothing in a UI, yet many LLMs read
# the Tag block as ordinary ASCII — so a payload can be fully invisible on screen
# and still comprehended as an instruction. Variant selectors (U+FE00-U+FE0F,
# U+E0100-U+E01EF) are the other common invisible carrier.
_TAG_BASE = 0xE0000            # U+E0000 + ord(ascii) == the tag character
_INVISIBLE = dict.fromkeys(
    list(range(0xE0000, 0xE0080)) +      # Unicode Tags
    list(range(0xFE00, 0xFE10)) +        # Variant Selectors 1-16
    list(range(0xE0100, 0xE01F0)),       # Variant Selectors Supplement
    None,
)


def to_unicode_tags(s: str) -> str:
    """Encode ASCII `s` as invisible Unicode Tag characters — the smuggling
    carrier. The result displays as nothing but round-trips through reveal()."""
    return "".join(chr(_TAG_BASE + ord(c)) for c in s if ord(c) < 0x80)


def reveal_smuggled(t: str) -> str:
    """Model comprehension of invisible carriers: map Tag characters back to the
    ASCII they encode so a smuggled marker becomes visible to the parser."""
    return "".join(
        chr(ord(c) - _TAG_BASE) if 0xE0000 <= ord(c) <= 0xE007F else c
        for c in t
    )


def strip_invisibles(t: str) -> str:
    """A byte-level guard's mitigation: delete invisible carrier characters.
    Removes the known ranges — and, like every filter, only the ranges it
    knows."""
    return t.translate(_INVISIBLE)


def normalize(t: str) -> str:
    """The model's comprehension pre-pass: undo the cheap obfuscations, and
    reveal instructions smuggled in invisible Unicode carriers."""
    return _decode_base64_blobs(_defold_homoglyphs(_strip_zero_width(reveal_smuggled(t))))


# --- intent vocabulary --------------------------------------------------------
def _role(word: str) -> str:
    return "staff" if word.lower() == "staff" else "admin"


def _agent(word: str) -> str:
    w = word.lower()
    if w in ("ops", "operations"):
        return "OpsAgent"
    if w in ("knowledge", "kb"):
        return "KnowledgeAgent"
    return "AccountAgent"


# Patterns EVERY layer knows (a static guard and the model both catch these).
_FILTER_PATTERNS = [
    ("SETROLE", r"\b(?:treat me as|act as|i am|you are now|make me)\s+(?:an?\s+|the\s+)?(admin|administrator|staff)\b",
     lambda m: _role(m.group(1))),
    ("SETROLE", r"\bset my (?:role|access|privilege|access level) to\s+(?:an?\s+)?(admin|administrator|staff)\b",
     lambda m: _role(m.group(1))),
    ("HANDOFF", r"\b(?:transfer|hand off|handoff|escalate|route|connect)\b[^.]*?\bto (?:the )?(ops|operations|knowledge|kb|account)\b",
     lambda m: _agent(m.group(1))),
    ("HANDOFF", r"\bconsult (?:the )?(knowledge|kb)\b",
     lambda m: "KnowledgeAgent"),
    ("TOOL", r"\b(?:run|execute)\b[^.]*?\b(select\s+.+?)(?:$|[.\n])",
     lambda m: f"run_sql({m.group(1).strip()})"),
    ("TOOL", r"\bdump the (?:users? )?(?:table|database|db)\b",
     lambda m: "run_sql(SELECT * FROM users)"),
    ("TOOL", r"\bissue (?:a )?refund of \$?(\d+) to (\w+)\b",
     lambda m: f"issue_refund({m.group(2)}, {m.group(1)})"),
    ("TOOL", r"\brefund \$?(\d+) to (\w+)\b",
     lambda m: f"issue_refund({m.group(2)}, {m.group(1)})"),
    ("TOOL", r"\b(?:look ?up|pull(?: up)?|fetch|retrieve|get) (?:the )?account (?:for )?(\w+)\b",
     lambda m: f"get_account({m.group(1)})"),
    ("TOOL", r"\bread (?:the )?file (\S+)",
     lambda m: f"read_file({m.group(1)})"),
]

# Extra phrasings ONLY the model comprehends — synonyms/indirection the static
# guard's fixed list lacks. This is the semantic (not merely encoding) gap: no
# amount of pattern-listing closes it, because a paraphrase is unbounded.
_LLM_ONLY_PATTERNS = [
    # --- role escalation stated without the words "admin/administrator" ------
    ("SETROLE", r"\b(?:make me|i am|treat me as|promote me to)\s+(?:an?\s+|the\s+)?(superuser|root|sysadmin|system administrator)\b",
     lambda m: "admin"),
    ("SETROLE", r"\belevate (?:my )?(?:access|privileges?|role|clearance)\b",
     lambda m: "admin"),
    ("SETROLE", r"\belevate (?:me )?to\s+(?:an?\s+|the\s+)?(?:admin|administrator|superuser|root|sysadmin)\b",
     lambda m: "admin"),
    ("SETROLE", r"\b(?:grant|give) me\s+(?:the\s+)?(?:full\s+)?(?:sysadmin|admin(?:istrator)?|root|superuser)(?:\s+(?:rights|access|control|privileges?|mode))?\b",
     lambda m: "admin"),
    ("SETROLE", r"\bwith\s+(?:admin(?:istrator)?|superuser|sysadmin|root)\s+(?:rights|privileges?|access)\b",
     lambda m: "admin"),
    ("SETROLE", r"\bassume\s+(?:the\s+)?(?:role of\s+)?(?:an?\s+)?(?:admin(?:istrator)?|superuser|root|sysadmin)(?:\s+privileges?)?\b",
     lambda m: "admin"),
    ("SETROLE", r"\bas\s+(?:an?\s+)?(?:root|superuser|sysadmin)\b",
     lambda m: "admin"),
    ("SETROLE", r"\bunlock\s+(?:the\s+)?admin(?:istrator)?\s*(?:mode|panel|access)\b",
     lambda m: "admin"),
    ("SETROLE", r"\b(?:full|elevated|administrative)\s+(?:administrative\s+)?(?:control|access|privileges?|rights)\b",
     lambda m: "admin"),
    # --- routing stated as indirection --------------------------------------
    ("HANDOFF", r"\bsend (?:me|this)(?: case| one)?(?: over)? to (?:the )?(ops|operations)\b",
     lambda m: "OpsAgent"),
    ("HANDOFF", r"\b(?:refer|route|send this|go|loop|hand this)\s+(?:back\s+|this\s+)?to (?:the )?(?:knowledge base|kb)\b",
     lambda m: "KnowledgeAgent"),
    ("HANDOFF", r"\b(?:see|check|review|revisit)\s+(?:the )?(?:knowledge base|kb)\b",
     lambda m: "KnowledgeAgent"),
    # --- table dump stated as a business request ----------------------------
    ("TOOL", r"\bshow me every (?:user|account|customer)(?: record)?s?\b",
     lambda m: "run_sql(SELECT * FROM users)"),
    ("TOOL", r"\b(?:list|export|extract|give me|pull|leak|send me)\s+(?:all|every|the entire|the full|all of the)\s+[\w ]*?(?:customer|user|account)s?(?:\s+(?:records?|rows?|table|database))?\b",
     lambda m: "run_sql(SELECT * FROM users)"),
    ("TOOL", r"\bselect\s+everything\s+from\s+(?:the\s+)?users?\b",
     lambda m: "run_sql(SELECT * FROM users)"),
    # --- account read stated without the filter's verb list -----------------
    ("TOOL", r"\b(?:bring up|open|access|look into)\s+(?:the\s+)?(?:account|file|record)\s+(?:for|of)\s+(\w+)\b",
     lambda m: f"get_account({m.group(1)})"),
    ("TOOL", r"\baccount\s+(?:details|info(?:rmation)?)\s+(?:for|of)\s+(\w+)\b",
     lambda m: f"get_account({m.group(1)})"),
    # --- refund stated as a payout ------------------------------------------
    ("TOOL", r"\b(?:credit|reimburse)\s+(?:account\s+)?(\w+)\s+(?:with|for)\s+\$?(\d+)\b",
     lambda m: f"issue_refund({m.group(1)}, {m.group(2)})"),
    ("TOOL", r"\b(?:wire|send|transfer|pay)\s+\$?(\d+)\s+to\s+(?:account\s+)?(\w+)\b",
     lambda m: f"issue_refund({m.group(2)}, {m.group(1)})"),
    ("TOOL", r"\bprocess\s+(?:a\s+)?\$?(\d+)\s+(?:refund|payout|reimbursement)\s+to\s+(?:account\s+)?(\w+)\b",
     lambda m: f"issue_refund({m.group(2)}, {m.group(1)})"),
]

_COMPILED = {
    "filter": [(k, re.compile(rx, re.IGNORECASE), fn) for k, rx, fn in _FILTER_PATTERNS],
    "llm": [(k, re.compile(rx, re.IGNORECASE), fn)
            for k, rx, fn in _FILTER_PATTERNS + _LLM_ONLY_PATTERNS],
}


def detect(text: str, level: str = "llm") -> list:
    """Return [(KIND, payload), ...] the given layer extracts from `text`.

    level='llm'    -> comprehension: normalize obfuscation + full vocabulary.
    level='filter' -> static guard: raw bytes + the narrow shared vocabulary.
    """
    surface = normalize(text) if level == "llm" else text
    found = []
    for kind, rx, build in _COMPILED[level]:
        for m in rx.finditer(surface):
            found.append((kind, build(m)))
    # de-dup while preserving order
    seen, out = set(), []
    for it in found:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out
