"""Phase AI-1 Step 1 -- sanitization of UNTRUSTED input before it enters an AI prompt.

Every value derived from a scanned target (tool output, HTTP responses, vulnerability
title/description, matched location, banners) is hostile-by-default: it can carry a prompt-
injection payload ("ignore previous instructions ..."). This module neutralizes the most
dangerous shapes and, crucially, wraps untrusted content in explicit delimiters that the system
prompt tells the model to treat as DATA, never instructions (see the prompt hardening in Step 2).

Defense-in-depth -- the delimiter contract is the primary control; the light defanging here just
raises the bar. The non-bypassable backstops remain in code (tool allowlist, no-target schema,
scope enforcement, output validation in guards.py).
"""
import re

DEFAULT_MAX_LEN = 2000

# Our own delimiter tokens -- an untrusted value must never be able to forge/close them and then
# smuggle a fake "system" instruction after the boundary.
_DELIM_OPEN = "<<UNTRUSTED"
_DELIM_CLOSE = "<</UNTRUSTED"
_DELIM_PATTERN = re.compile(r"<{1,2}/?\s*UNTRUSTED", re.IGNORECASE)

# Control chars (keep \t \n \r) -- strip the rest so nothing hides framing via C0/C1 bytes.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Chat/role framing at a line start that a model might read as a turn boundary.
_ROLE_FRAMING = re.compile(r"(?im)^[ \t]*(system|assistant|developer|tool|user)[ \t]*:", )
# Explicit override phrasing ("ignore/disregard the previous instructions/prompt/rules").
_OVERRIDE = re.compile(
    r"(?i)\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,50}"
    r"\b(previous|prior|above|earlier|all|the)\b[^.\n]{0,30}"
    r"\b(instructions?|prompts?|rules?|context|system)\b"
)
# Model instruction-frame markers used by some providers.
_FRAME_MARKERS = re.compile(r"(?i)(<\|?(?:im_start|im_end|system|endoftext)\|?>|\[/?INST\]|<<SYS>>|<</SYS>>)")


def sanitize_untrusted(text, *, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Return a bounded, defanged copy of an untrusted string. Removes control chars, neutralizes
    our delimiter tokens + provider frame markers + role framing + explicit override phrasing, and
    truncates. Non-string / None -> ''."""
    if text is None:
        return ""
    s = str(text)
    s = _CONTROL.sub(" ", s)
    s = _DELIM_PATTERN.sub("(untrusted)", s)          # cannot forge/close our delimiters
    s = _FRAME_MARKERS.sub("(marker)", s)             # cannot inject provider frame tokens
    s = _ROLE_FRAMING.sub(r"\1-", s)                  # "System:" -> "system-" (not a turn boundary)
    s = _OVERRIDE.sub("[redacted-injection]", s)      # defang explicit override phrasing
    if len(s) > max_len:
        s = s[:max_len].rstrip() + " …[truncated]"
    return s


def wrap_untrusted(label: str, text, *, sanitize: bool = True, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Enclose untrusted content in labeled delimiters the model is told to treat as data.
    `sanitize=False` is for content already field-sanitized (e.g. a JSON blob whose string
    fields were passed through sanitize_untrusted) -- it only adds the delimiters, so valid JSON
    is not truncated/mangled."""
    body = sanitize_untrusted(text, max_len=max_len) if sanitize else str(text)
    return f"{_DELIM_OPEN}:{label}>>\n{body}\n{_DELIM_CLOSE}:{label}>>"


# Finding-dict fields that originate from the scanned target (hostile). `id` is our own UUID.
_UNTRUSTED_FIELDS = (
    "title", "description", "matched_at", "category", "tool", "name",
    "value", "evidence", "snippet", "detail", "reasoning", "rationale",
)


def sanitize_finding_dicts(findings: list[dict], *, max_len: int = 800) -> list[dict]:
    """Return copies of finding dicts with every untrusted string field defanged. Used before
    json.dumps for the correlator / FP-reducer, so injection cannot ride in through a field
    value. `id` and non-string values are left intact."""
    out: list[dict] = []
    for f in findings:
        g = dict(f)
        for k, v in list(g.items()):
            if k != "id" and isinstance(v, str) and (k in _UNTRUSTED_FIELDS or True):
                g[k] = sanitize_untrusted(v, max_len=max_len)
        out.append(g)
    return out
