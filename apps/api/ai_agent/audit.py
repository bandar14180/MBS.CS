"""Phase AI-1 Step 4 -- structured security audit for AI decisions.

Emits `mbs.ai.security` events so a poisoned/blocked AI output is forensically traceable. STRICT
rule: SAFE METADATA ONLY -- never a prompt, a raw finding, model reasoning, a secret, or PII. The
values passed here are controlled (agent name, decision/outcome enums, a reason CATEGORY, version
strings, counts, confidence). Correlation id is attached best-effort to join the event to its
originating request/scan.
"""
import logging

logger = logging.getLogger("mbs.ai.security")


def ai_security_event(event: str, *, agent: str, **fields) -> None:
    """Log one AI security event (ai.decision / ai.output_blocked / ai.injection_suspected).
    Callers MUST pass only safe metadata -- this function does not (and cannot) scrub content, so
    never hand it prompt/finding/answer text."""
    from apps.api.core.observability import get_correlation_id

    logger.info(
        event,
        extra={"event": event, "agent": agent, "correlation_id": get_correlation_id(), **fields},
    )
