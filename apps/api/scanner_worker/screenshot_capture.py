"""Screenshot evidence on the EXECUTION plane -- MBS.SC.

WHY THIS MODULE EXISTS
----------------------
Screenshot capture was written for the in-process orchestrator (`991b929`) and worked until
scan execution moved onto the isolated worker. It then fell into the gap between the two
planes and stopped producing anything:

  * the execution worker runs the tools but contained no screenshot code at all;
  * the manager, which now performs ingestion, is deliberately NOT on `mbs-scan-egress`, so
    it calls `ingest_vulnerability_findings(capture_screenshots=False)` -- correctly, since
    a control-plane process must never open connections to customer targets.

The capture therefore belongs HERE: this is the only process that is both allowed to reach
the target and already holds Chromium. Nothing about the capture itself is re-implemented --
`scanner_engine.screenshot` is imported and used verbatim, including all five eligibility
gates (severity -> http/https scheme -> hostname -> scope_guard -> net_guard SSRF).

WHAT THE WORKER MAY AND MAY NOT DECIDE
--------------------------------------
The worker holds no database and no object-store credential, so it cannot write an Evidence
row or resolve a `vulnerability.id`. It sends BYTES plus the finding's `fingerprint`, and the
manager resolves that fingerprint against the findings IT parsed from the raw output itself.

That asymmetry is the security property, not an inconvenience: a compromised worker can
submit an image for a fingerprint the manager never derived, and the manager will simply
find no vulnerability to attach it to and store nothing. The worker cannot invent a finding,
and cannot attach evidence to another tenant's -- `/v1/evidence` re-derives the workspace
from the scan row regardless of what is sent.

Parsing locally to decide eligibility is NOT the worker "sending conclusions". The parse is a
pure function of bytes the worker already has, its result is used only to choose which URLs
to photograph, and the manager re-parses the same bytes independently for the findings that
actually get persisted.

BEST EFFORT, ALWAYS
-------------------
Every failure path here returns quietly. A screenshot must never fail a tool, lose a finding,
or abort a scan -- the same contract `scanner_engine/screenshot.py` already states.
"""
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

# Cap on screenshots per tool run. A single nuclei run can emit hundreds of non-info findings
# across many URLs; without a ceiling one run could hold the worker in the browser for the
# rest of the scan. The cap is per RUN, not per scan, so each tool still gets its own budget.
MAX_SCREENSHOTS_PER_RUN = 10


def _dedupe_key(finding) -> tuple:
    """One capture per (fingerprint, location).

    Findings that dedupe to the same vulnerability upstream would otherwise each drive a
    separate browser launch at the same URL and produce byte-identical images -- which the
    report layer then discards by checksum anyway. Cheaper to not take them.
    """
    return (getattr(finding, "fingerprint", None), getattr(finding, "matched_at", None))


async def capture_for_findings(
    vuln_findings,
    *,
    target_type: str,
    target_value: str,
    extra_authorized_hosts=None,
    screenshot_mod=None,
) -> list[tuple[str, bytes]]:
    """Capture screenshots for the eligible findings of one tool run.

    Returns `[(fingerprint, png_bytes)]` -- only for findings that passed every gate AND
    produced real image bytes. An empty list is a completely normal outcome (feature off, no
    web findings, all info severity, capture failed) and never signals an error.

    `screenshot_mod` is injectable for tests ONLY; production always uses the real module, so
    there is no second, weaker copy of the eligibility rules.
    """
    if screenshot_mod is None:
        from apps.api.scanner_engine import screenshot as screenshot_mod

    # Feature flag first: a worker without Chromium must not try (and fail) on every finding.
    if not screenshot_mod.is_enabled():
        return []

    captured: list[tuple[str, bytes]] = []
    seen: set[tuple] = set()

    for finding in vuln_findings or []:
        if len(captured) >= MAX_SCREENSHOTS_PER_RUN:
            logger.info(
                "screenshot.run_budget_reached captured=%d", len(captured),
                extra={"event": "screenshot.run_budget_reached"},
            )
            break

        key = _dedupe_key(finding)
        if key in seen:
            continue
        seen.add(key)

        fingerprint = getattr(finding, "fingerprint", None)
        if not fingerprint:
            continue  # nothing the manager could associate this with

        # THE EXISTING 5-GATE MODEL, called verbatim. Not re-implemented, not relaxed:
        # severity -> http/https scheme -> hostname -> scope_guard -> net_guard SSRF.
        #
        # Offloaded to a thread because gates 4 and 5 are SYNCHRONOUS and resolve DNS
        # (scope_guard.host_in_scope and net_guard.resolve_and_validate, both of which
        # time.sleep() between retry attempts). This coroutine runs on the worker's only
        # event loop, alongside the heartbeat and lease tasks, so blocking here starves
        # them exactly as the executor's own scope check did. The gates themselves are
        # unchanged -- same function, same arguments, same fail-closed result; only the
        # thread it runs on differs. `to_thread` copies the current context, so the
        # scan's bound net_policy still governs the resolution.
        try:
            eligibility = await asyncio.to_thread(
                screenshot_mod.check_eligibility,
                getattr(finding, "matched_at", None),
                getattr(finding, "severity", None),
                target_type,
                target_value,
                extra_authorized_hosts=extra_authorized_hosts,
            )
        except Exception:  # noqa: BLE001 -- a guard that errors is a REFUSAL, never a pass
            logger.warning(
                "screenshot.eligibility_raised fingerprint=%s", fingerprint,
                extra={"event": "screenshot.eligibility_raised"}, exc_info=True,
            )
            continue

        if not eligibility.eligible:
            logger.debug(
                "screenshot.skipped fingerprint=%s reason=%s", fingerprint, eligibility.reason,
                extra={"event": "screenshot.skipped", "reason": eligibility.reason},
            )
            continue

        try:
            image = await screenshot_mod.capture_screenshot(
                eligibility.url,
                target_type,
                target_value,
                extra_authorized_hosts=extra_authorized_hosts,
            )
        except Exception:  # noqa: BLE001 -- capture already swallows; belt and braces
            logger.warning(
                "screenshot.capture_raised fingerprint=%s", fingerprint,
                extra={"event": "screenshot.capture_raised"}, exc_info=True,
            )
            continue

        if not image:
            continue  # already logged inside capture; never fabricate evidence

        captured.append((fingerprint, image))
        logger.info(
            "screenshot.captured fingerprint=%s bytes=%d", fingerprint, len(image),
            extra={"event": "screenshot.captured", "bytes": len(image)},
        )

    return captured
