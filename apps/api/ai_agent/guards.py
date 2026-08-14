"""Phase AI-1 Step 3 -- validation of AI OUTPUT before it reaches a user.

The free-text AI paths (remediation, assistant, correlator rationale) are shown to customers and
are NOT protected by the tool allowlist. A prompt-injected finding could try to make the model
emit exploit code, a destructive/"disable your security control" recommendation, or echo a secret
scraped from the target. This module scans generated text and, on a hit, substitutes a SAFE
fallback so poisoned content is never delivered. All outputs are also run through the central
log-redaction pass to strip any leaked secret/PII/token.

Fail-safe: a validation error degrades to the fallback, never to delivering unvalidated text.
"""
import re

from apps.api.core.log_redaction import redact_text

# Exploit code / payloads / destructive commands that must never appear in remediation or an
# assistant answer (the product explicitly promises "no exploit code / payloads").
_UNSAFE = re.compile(
    r"(?i)("
    r"rm\s+-rf\b|drop\s+table\b|truncate\s+table\b|;\s*shutdown\b|mkfs\b|chmod\s+777\b|"
    r":\(\)\s*\{\s*:\|:&\s*\}|"                       # fork bomb
    r"curl\s+[^\n|]*\|\s*(?:ba)?sh\b|wget\s+[^\n|]*\|\s*(?:ba)?sh\b|"   # curl|sh
    r"nc\s+-e\b|/etc/passwd\b|/etc/shadow\b|base64\s+-d\b|powershell\s+-e(?:nc)?\b|"
    r"<script>|onerror\s*=|javascript:|"              # xss payloads
    r"union\s+select\b|' or '1'='1|\bsleep\(\d|"      # sqli payloads
    r"disable\s+(?:the\s+)?(?:firewall|waf|authentication|auth|mfa|2fa|antivirus|security|encryption|logging)|"
    r"turn\s+off\s+(?:the\s+)?(?:firewall|waf|authentication|auth|mfa|2fa|antivirus|security|logging)|"
    r"allow\s+all\s+(?:traffic|origins)|0\.0\.0\.0/0\s+any"
    r")"
)

REMEDIATION_FALLBACK_SUMMARY = (
    "Automated remediation guidance was withheld because the generated content failed a safety "
    "check. Please review this finding manually and apply the standard fix for its category."
)
ASSISTANT_FALLBACK_ANSWER = (
    "I can't provide that. This request or the underlying finding content triggered a safety "
    "check, and MBS.SC never returns exploit code, payloads, or instructions to weaken a security "
    "control. Please rephrase your question."
)


def contains_unsafe(text: str) -> str | None:
    """Return a short reason if `text` contains an unsafe/exploit/destructive pattern, else None."""
    if not text:
        return None
    m = _UNSAFE.search(text)
    return m.group(0)[:60] if m else None


def redact_output(text: str) -> str:
    """Scrub secrets/PII/tokens/emails from user-facing AI text (defense-in-depth)."""
    return redact_text(text or "")


def validate_output(text: str, *, fallback: str) -> tuple[str, bool, str | None]:
    """Validate one AI free-text output. Returns (safe_text, ok, reason_category).
    - unsafe pattern  -> (fallback, False, "unsafe_output")
    - otherwise       -> (redacted_text, True, None)
    Any exception fails safe to the fallback with reason "guard_error".

    The reason is a CONTROLLED CATEGORY, never the matched substring -- the match could echo
    injected target content, so it must never be logged/returned for audit (AI-1 Step 4)."""
    try:
        if contains_unsafe(text or "") is not None:
            return fallback, False, "unsafe_output"
        return redact_output(text or ""), True, None
    except Exception:  # noqa: BLE001 -- never deliver unvalidated text on a guard error
        return fallback, False, "guard_error"
