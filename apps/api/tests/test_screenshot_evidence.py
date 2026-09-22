"""Screenshot evidence: eligibility, safety, failure behaviour and report embedding.

Fully deterministic -- no test opens a browser or reaches a live site. Playwright and the
storage provider are mocked; `net_guard` / `scope_guard` are exercised for real, because the
whole point is that screenshot capture reuses those existing guards rather than a second,
weaker copy of them.
"""

import asyncio
import uuid
from unittest.mock import MagicMock, patch

import pytest

from apps.api.core.config import get_settings
from apps.api.modules.reports import render
from apps.api.modules.reports.data import ReportData, VulnRow
from apps.api.scanner_engine import screenshot

TARGET_TYPE = "domain"
TARGET_VALUE = "example.com"


def _eligibility(matched_at, severity="high", target_value=TARGET_VALUE):
    return screenshot.check_eligibility(matched_at, severity, TARGET_TYPE, target_value)


# --- Eligibility: scheme / shape ---------------------------------------------------------

@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_http_url_is_eligible(_ssrf):
    result = _eligibility("http://example.com/a")
    assert result.eligible and result.reason == "eligible"
    assert result.hostname == "example.com"


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_https_url_is_eligible(_ssrf):
    assert _eligibility("https://example.com/path?x=1").eligible


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_url_with_pipe_payload_is_eligible_and_unmodified(_ssrf):
    """A production matched_at whose URL contains an injection payload with '|'."""
    url = "https://example.com/?lang=|sleep+5"
    result = _eligibility(url)
    assert result.eligible
    assert result.url == url  # never truncated at the pipe


def test_host_port_is_rejected():
    """`example.com:22` parses as scheme='example.com' with no hostname -- a scheme check
    alone would not catch it, so both scheme AND hostname are required."""
    result = _eligibility("example.com:22")
    assert not result.eligible
    assert result.reason in {"scheme_not_http", "no_hostname"}


@pytest.mark.parametrize(
    "value",
    [
        "ssh://example.com",
        "ftp://example.com/x",
        "file:///etc/passwd",
        "data:text/html,<script>1</script>",
        "example.com",             # bare host, no scheme (DNS-style finding)
        "sleep+5",                 # payload-only string
        "dir",
        "",
        None,
    ],
)
def test_non_http_values_are_rejected(value):
    assert not _eligibility(value).eligible


def test_info_severity_is_never_captured():
    """Approved scope: info is detection-only and must not start a browser."""
    result = screenshot.check_eligibility(
        "https://example.com/a", "info", TARGET_TYPE, TARGET_VALUE
    )
    assert not result.eligible
    assert result.reason == "severity_excluded"
    # And the severity gate runs FIRST -- no scope/DNS work for an info finding.
    with patch.object(screenshot, "_host_passes_ssrf_policy") as ssrf:
        screenshot.check_eligibility("https://example.com/a", "info", TARGET_TYPE, TARGET_VALUE)
        ssrf.assert_not_called()


# --- Eligibility: the existing guards ----------------------------------------------------

@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_out_of_scope_url_is_rejected(_ssrf):
    """scope_guard decides authorization -- a real host outside the target is refused."""
    result = _eligibility("https://attacker.test/a")
    assert not result.eligible
    assert result.reason == "out_of_scope"


def test_private_and_internal_addresses_are_rejected_by_net_guard():
    """Uses the REAL net_guard policy (no mock): loopback / RFC1918 / metadata are refused
    even when the host is nominally in scope."""
    for host in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254"):
        with patch.object(screenshot.scope_guard, "host_in_scope", return_value=True):
            result = _eligibility(f"http://{host}/")
            assert not result.eligible, host
            assert result.reason == "ssrf_blocked", host


def test_ssrf_helper_rejects_when_resolution_fails():
    with patch.object(
        screenshot.net_guard, "resolve_and_validate", side_effect=RuntimeError("dns down")
    ):
        assert screenshot._host_passes_ssrf_policy("example.com") is False


# --- Redirects ---------------------------------------------------------------------------

def test_redirect_to_out_of_scope_is_rejected():
    with patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True):
        assert not screenshot._redirect_is_allowed(
            "https://attacker.test/x", TARGET_TYPE, TARGET_VALUE, None
        )


def test_redirect_to_private_address_is_rejected():
    with patch.object(screenshot.scope_guard, "host_in_scope", return_value=True):
        assert not screenshot._redirect_is_allowed(
            "http://169.254.169.254/latest/meta-data/", TARGET_TYPE, TARGET_VALUE, None
        )


def test_redirect_to_in_scope_public_url_is_allowed():
    with patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True):
        assert screenshot._redirect_is_allowed(
            "https://example.com/next", TARGET_TYPE, TARGET_VALUE, None
        )


# --- Capture failure modes: every one returns None, none raise ---------------------------

def _capture_sync(url="https://example.com/"):
    """Drive the async capture from a sync test -- this project has no async-test plugin,
    and adding one for four tests is not worth a new dev dependency."""
    return asyncio.run(screenshot.capture_screenshot(url, TARGET_TYPE, TARGET_VALUE))


def test_browser_launch_failure_returns_none():
    with patch.object(screenshot, "_capture", side_effect=RuntimeError("no chromium")):
        assert _capture_sync() is None


def test_navigation_timeout_returns_none():
    async def _slow(*a, **k):
        await asyncio.sleep(60)

    with patch.object(screenshot, "_capture", _slow), \
         patch.object(screenshot, "TOTAL_TIMEOUT_SECONDS", 0.05):
        assert _capture_sync() is None


def test_capture_never_raises_on_arbitrary_error():
    for exc in (ValueError("x"), OSError("y"), MemoryError()):
        with patch.object(screenshot, "_capture", side_effect=exc):
            assert _capture_sync() is None


def test_successful_capture_returns_bytes():
    async def _ok(*a, **k):
        return b"\x89PNG-image"

    with patch.object(screenshot, "_capture", _ok):
        assert _capture_sync() == b"\x89PNG-image"


def test_disabled_by_default():
    """The feature must be off unless explicitly enabled, since it needs Chromium."""
    assert screenshot.is_enabled() is False


def test_limits_are_conservative():
    assert screenshot.NAVIGATION_TIMEOUT_MS <= 10_000
    assert screenshot.TOTAL_TIMEOUT_SECONDS <= 20
    assert screenshot.MAX_IMAGE_BYTES <= 2 * 1024 * 1024
    assert (screenshot.VIEWPORT_WIDTH, screenshot.VIEWPORT_HEIGHT) == (1920, 1080)
    assert screenshot._MAX_CONCURRENT <= 2  # must not starve the scanners


# --- Report: grouping, dedup, embedding --------------------------------------------------

def _row(template_id="tpl", matched_at="https://example.com/a", severity="high", shots=()):
    return VulnRow(
        id=uuid.uuid4(), title=f"{template_id} title", severity=severity, status="open",
        category=None, cvss_score=9.8, cvss_vector=None, final_risk_score=10.0,
        risk_rationale=None, compliance=[], evidence_uris=[], screenshots=list(shots),
        template_id=template_id, matcher_name="m", matched_at=matched_at,
    )


def test_screenshots_are_attached_to_their_own_finding():
    a = _row("tpl-a", "https://example.com/a", shots=[("s3://b/a.png", "aaa")])
    b = _row("tpl-b", "https://example.com/b", shots=[("s3://b/b.png", "bbb")])
    groups = {g["template_id"]: g for g in render._finding_groups([a, b])}
    assert groups["tpl-a"]["screenshots"] == [("s3://b/a.png", "aaa")]
    assert groups["tpl-b"]["screenshots"] == [("s3://b/b.png", "bbb")]


def test_multiple_locations_stay_grouped_with_their_screenshots():
    rows = [
        _row("tpl", "https://example.com/a", shots=[("s3://b/a.png", "aaa")]),
        _row("tpl", "https://example.com/b", shots=[("s3://b/b.png", "bbb")]),
        _row("tpl", "https://example.com/c", shots=[("s3://b/c.png", "ccc")]),
    ]
    (group,) = render._finding_groups(rows)          # ONE finding block
    assert len(group["matched_ats"]) == 3            # three affected locations
    assert len(group["screenshots"]) == 3            # each keeps its own image


def test_byte_identical_screenshots_are_deduplicated_by_checksum():
    rows = [
        _row("tpl", "https://example.com/a", shots=[("s3://b/x.png", "same")]),
        _row("tpl", "https://example.com/b", shots=[("s3://b/x.png", "same")]),
    ]
    (group,) = render._finding_groups(rows)
    assert len(group["matched_ats"]) == 2   # both locations still reported
    assert len(group["screenshots"]) == 1   # one image, not two copies


def test_different_screenshots_are_never_collapsed():
    rows = [
        _row("tpl", "https://example.com/a", shots=[("s3://b/a.png", "aaa")]),
        _row("tpl", "https://example.com/b", shots=[("s3://b/b.png", "bbb")]),
    ]
    (group,) = render._finding_groups(rows)
    assert {c for _, c in group["screenshots"]} == {"aaa", "bbb"}


def test_findings_without_screenshots_are_unaffected():
    (group,) = render._finding_groups([_row("tpl")])
    assert group["screenshots"] == []


# --- Report rendering --------------------------------------------------------------------

_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    b"\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _data(rows, score=50):
    return ReportData(
        project_name="P", security_score=score,
        severity_counts={"critical": 0, "high": len(rows), "medium": 0, "low": 0, "info": 0},
        total_vulns=len(rows), active_vulns=len(rows), vulns=rows,
    )


def test_technical_report_embeds_the_screenshot():
    # The URI must name the real EVIDENCE bucket, as every production writer does
    # (evidence_store hardcodes settings.s3_bucket_evidence). Prompt 30 added a bucket
    # allow-check at the fetch site, so a placeholder bucket name is no longer fetched --
    # see test_evidence_artifact_boundary.py for why that read fails closed.
    bucket = get_settings().s3_bucket_evidence
    rows = [_row("tpl", "https://example.com/a", shots=[(f"s3://{bucket}/a.png", "abc123def456")])]
    provider = MagicMock()
    provider.get.return_value = _PNG
    with patch("apps.api.scanner_engine.storage_provider.get_storage_provider", return_value=provider):
        out = render.render("technical", _data(rows))
    assert out[:5] == b"%PDF-"
    provider.get.assert_called_once_with("a.png")   # bucket stripped, key used


def test_report_still_renders_when_screenshot_fetch_fails():
    """Storage outage must not break report generation."""
    rows = [_row("tpl", "https://example.com/a", shots=[("s3://bucket/a.png", "abc")])]
    provider = MagicMock()
    provider.get.side_effect = RuntimeError("storage down")
    with patch("apps.api.scanner_engine.storage_provider.get_storage_provider", return_value=provider):
        assert render.render("technical", _data(rows))[:5] == b"%PDF-"


def test_report_still_renders_when_screenshot_bytes_are_corrupt():
    rows = [_row("tpl", "https://example.com/a", shots=[("s3://bucket/a.png", "abc")])]
    provider = MagicMock()
    provider.get.return_value = b"not-an-image"
    with patch("apps.api.scanner_engine.storage_provider.get_storage_provider", return_value=provider):
        assert render.render("technical", _data(rows))[:5] == b"%PDF-"


def test_non_s3_uri_is_ignored_safely():
    from reportlab.lib.units import mm
    assert render._screenshot_flowable("unavailable://evidence-storage-failed/x", mm) is None
    assert render._screenshot_flowable("s3://bucket-only", mm) is None


def test_executive_report_never_embeds_screenshots():
    """The Executive Report stays concise -- screenshots are Technical-only."""
    rows = [_row("tpl", "https://example.com/a", shots=[("s3://bucket/a.png", "abc")])]
    provider = MagicMock()
    provider.get.return_value = _PNG
    with patch("apps.api.scanner_engine.storage_provider.get_storage_provider", return_value=provider):
        out = render.render("executive", _data(rows))
    assert out[:5] == b"%PDF-"
    provider.get.assert_not_called()


# --- Storage key ---------------------------------------------------------------------------

def test_screenshot_storage_key_is_per_vulnerability_and_content_addressed():
    from apps.api.scanner_engine import evidence_store

    vuln_id = uuid.uuid4()
    client = MagicMock()
    with patch.object(evidence_store, "_get_s3_client", return_value=client), \
         patch.object(evidence_store, "_ensure_bucket"):
        uri, checksum = evidence_store.store_screenshot(vuln_id, _PNG)

    kwargs = client.put_object.call_args.kwargs
    assert kwargs["ContentType"] == "image/png"          # binary, not text
    assert str(vuln_id) in kwargs["Key"]                 # addressable per FINDING
    assert checksum[:16] in kwargs["Key"]                # content-addressed => idempotent
    assert uri.startswith("s3://") and uri.endswith(".png")
    # Same bytes -> same checksum -> same key (a re-scan overwrites, never accumulates).
    with patch.object(evidence_store, "_get_s3_client", return_value=client), \
         patch.object(evidence_store, "_ensure_bucket"):
        uri2, checksum2 = evidence_store.store_screenshot(vuln_id, _PNG)
    assert (uri, checksum) == (uri2, checksum2)
