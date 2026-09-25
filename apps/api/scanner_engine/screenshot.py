"""Screenshot evidence capture for web vulnerabilities.

Captures the affected page for a finding whose `matched_at` is a real HTTP(S) URL, so the
Technical Report can show what the tester would have seen. Runs in the WORKER during a scan
(never during report generation, which is synchronous inside the API request).

DESIGN CONSTRAINTS
------------------
* Best effort. Every failure path returns None. A screenshot must never fail a scan, lose a
  finding, or block report generation -- and an empty/placeholder image is never fabricated.
* Reuses the EXISTING security guards rather than reimplementing them: `scope_guard` for
  authorization scope and `net_guard` for the SSRF / private-address policy. There is no
  second, weaker copy of those rules here.
* Playwright is imported lazily inside the capture call, so a worker that never captures
  (feature disabled, or no eligible finding) pays no import or memory cost.
* Concurrency is capped process-wide: the worker already runs scanners, and unbounded
  Chromium processes would starve them.

The caller (orchestrator) owns persistence: this module only decides eligibility and returns
image bytes.
"""

import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

from apps.api.core.config import get_settings
from apps.api.scanner_engine import net_guard, scope_guard

logger = logging.getLogger("mbs.screenshot")

# Only these schemes are ever navigated. `ssh://`, `ftp://`, `file://`, `data:` and a bare
# `host:port` (which urlparse reads as scheme="host") are all rejected before any browser
# starts. Verified against production matched_at values: SSH findings store `host:port`.
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Severity gate (approved scope): info findings are detection-only, they do not affect the
# security score, and they are the bulk of the data (158 of 222 rows in production). Capturing
# them would spend most of the browser budget on findings nobody remediates.
_SKIP_SEVERITIES = frozenset({"info"})

# Hard limits. Navigation is the slow part; the total budget also covers rendering + encoding
# so one pathological page cannot hold a worker slot open indefinitely.
NAVIGATION_TIMEOUT_MS = 10_000
TOTAL_TIMEOUT_SECONDS = 20.0
VIEWPORT_WIDTH = 1920
VIEWPORT_HEIGHT = 1080
MAX_IMAGE_BYTES = 2 * 1024 * 1024  # ~2MB; a larger capture is discarded, not truncated
MAX_REDIRECTS = 5

# Process-wide cap on concurrent Chromium instances. Deliberately small: the worker's main
# job is scanning. Created lazily so importing this module starts nothing.
_MAX_CONCURRENT = 2
_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(_MAX_CONCURRENT)
    return _semaphore


@dataclass(frozen=True)
class EligibilityResult:
    """Why a location may or may not be screenshotted. `reason` is for logs/tests -- it is
    never shown to a report reader."""

    eligible: bool
    reason: str
    url: str | None = None
    hostname: str | None = None


def is_enabled() -> bool:
    """Feature flag. Off by default: capture requires Chromium in the image, so a deployment
    without it must not start trying (and failing) on every finding."""
    return bool(getattr(get_settings(), "screenshot_evidence_enabled", False))


def check_eligibility(
    matched_at: str | None,
    severity: str | None,
    target_type: str,
    target_value: str,
    *,
    extra_authorized_hosts=None,
) -> EligibilityResult:
    """Decide whether `matched_at` may be navigated. Pure and fail-closed: anything not
    positively proven safe is rejected.

    Gate order is deliberate -- the cheap, local checks run before DNS resolution:
      1. severity (info is out of approved scope)
      2. scheme must be http/https  -> rejects `host:port`, ssh://, payload strings
      3. hostname must parse        -> rejects malformed URLs
      4. scope_guard.host_in_scope  -> the EXISTING authorization boundary
      5. net_guard                  -> the EXISTING SSRF / private-address policy
    """
    if severity and severity.lower() in _SKIP_SEVERITIES:
        return EligibilityResult(False, "severity_excluded")
    if not matched_at:
        return EligibilityResult(False, "no_matched_at")

    try:
        parsed = urlparse(matched_at)
    except ValueError:
        return EligibilityResult(False, "unparseable")

    # `example.com:22` parses as scheme="example.com" with no hostname, so BOTH checks are
    # needed -- a scheme test alone would not reject it.
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return EligibilityResult(False, "scheme_not_http")
    hostname = parsed.hostname
    if not hostname:
        return EligibilityResult(False, "no_hostname")

    if not scope_guard.host_in_scope(
        target_type, target_value, hostname, extra_authorized_hosts=extra_authorized_hosts
    ):
        return EligibilityResult(False, "out_of_scope", hostname=hostname)

    if not _host_passes_ssrf_policy(hostname):
        return EligibilityResult(False, "ssrf_blocked", hostname=hostname)

    return EligibilityResult(True, "eligible", url=matched_at, hostname=hostname)


def _host_passes_ssrf_policy(hostname: str) -> bool:
    """Delegate to net_guard. A literal IP is checked directly; a name is resolved and every
    resolved address must be permitted (net_guard's DNS-rebinding defence). Any resolver or
    policy error is a rejection, never a pass."""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return net_guard.is_ip_allowed(hostname)
    try:
        net_guard.resolve_and_validate(hostname)
        return True
    except Exception:  # noqa: BLE001 -- TargetNotAllowed, resolver failure: all mean "no"
        return False


def _redirect_is_allowed(url: str, target_type: str, target_value: str, extra_authorized_hosts) -> bool:
    """Re-validate a redirect hop. A redirect is a fresh navigation to a fresh host, so the
    scope and SSRF gates must run again -- otherwise an in-scope URL could bounce the browser
    to an internal address."""
    result = check_eligibility(
        url, None, target_type, target_value, extra_authorized_hosts=extra_authorized_hosts
    )
    return result.eligible


async def capture_screenshot(
    url: str,
    target_type: str,
    target_value: str,
    *,
    extra_authorized_hosts=None,
) -> bytes | None:
    """Navigate to `url` and return PNG bytes, or None on ANY failure.

    The caller must have already passed `check_eligibility`; this re-checks redirects during
    navigation because the destination can change after the first gate.

    Never raises. Browser launch failure, timeout, oversize output, a rejected redirect and an
    encoding error all return None so the finding and the scan continue untouched."""
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT_SECONDS):
            async with _get_semaphore():
                return await _capture(url, target_type, target_value, extra_authorized_hosts)
    except TimeoutError:
        logger.warning("screenshot.timeout url=%s", url)
    except Exception as exc:  # noqa: BLE001 -- best effort by contract
        logger.warning("screenshot.failed url=%s error=%s", url, exc, exc_info=True)
    return None


async def _capture(url: str, target_type: str, target_value: str, extra_authorized_hosts) -> bytes | None:
    # Lazy import: a worker with the feature off never imports playwright.
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = None
        try:
            browser = await pw.chromium.launch(
                headless=True,
                # No --ignore-certificate-errors and no --disable-web-security: TLS
                # verification stays ON. The sandbox flags below are the standard container
                # requirements, not a security relaxation.
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            context = await browser.new_context(
                viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                ignore_https_errors=False,  # explicit: do not accept invalid certificates
            )
            page = await context.new_page()

            # Re-validate every redirect hop before it is followed, and cap the chain.
            redirects = {"count": 0}

            async def _on_route(route, request):
                if request.is_navigation_request() and request.url != url:
                    redirects["count"] += 1
                    if redirects["count"] > MAX_REDIRECTS:
                        await route.abort()
                        return
                    if not _redirect_is_allowed(
                        request.url, target_type, target_value, extra_authorized_hosts
                    ):
                        logger.info("screenshot.redirect_blocked url=%s", request.url)
                        await route.abort()
                        return
                await route.continue_()

            await page.route("**/*", _on_route)
            await page.goto(url, timeout=NAVIGATION_TIMEOUT_MS, wait_until="domcontentloaded")
            image = await page.screenshot(type="png", full_page=False)

            if not image:
                return None
            if len(image) > MAX_IMAGE_BYTES:
                # Discard rather than store a truncated (corrupt) image.
                logger.info("screenshot.oversize url=%s bytes=%d", url, len(image))
                return None
            return image
        finally:
            if browser is not None:
                try:
                    await browser.close()
                except Exception:  # noqa: BLE001 -- close must never mask the real outcome
                    logger.debug("screenshot.close_failed url=%s", url, exc_info=True)
