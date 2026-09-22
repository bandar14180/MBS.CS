"""Screenshot evidence on the ISOLATED EXECUTION PLANE.

WHY THIS FILE EXISTS

Screenshot capture (991b929) worked in the in-process orchestrator and then silently stopped
producing anything when scan execution moved to the isolated worker. Nothing failed: the
capture code was intact, its unit tests stayed green, and the report renderer kept working
perfectly -- it was simply never handed an image again, because

  * `scanner_worker` contained no screenshot code at all, and
  * the manager, which now ingests, passes `capture_screenshots=False` (correctly: it is on
    the control plane and must never connect to a customer target).

Measured on the live database: `evidence` gained 59 screenshot rows on 2026-09-08 and zero
on 2026-09-10, while `log_excerpt` kept growing normally. Every screenshot test passed
throughout, because they all tested the capture module in isolation and none tested that
anything ever CALLED it on the plane that now runs scans.

So these tests assert the WIRING, not the browser: that the execution plane attempts a
capture for an eligible finding, refuses an ineligible one, submits PNG bytes with the
finding identity attached, and never lets any of that endanger the scan.
"""
import asyncio
import uuid
from unittest.mock import patch

from apps.api.scanner_engine import screenshot
from apps.api.scanner_engine.tool_runners.base import RawToolOutput
from apps.api.scanner_worker import executor as executor_mod
from apps.api.scanner_worker import screenshot_capture

PNG = b"\x89PNG\r\n\x1a\n" + b"fake-image-bytes"
TARGET_TYPE = "domain"
TARGET_VALUE = "t.example.com"


class _Finding:
    """A VulnerabilityFinding-shaped stand-in (only the fields capture reads)."""

    def __init__(self, fingerprint, matched_at, severity="high"):
        self.fingerprint = fingerprint
        self.matched_at = matched_at
        self.severity = severity


class _FakeScreenshotMod:
    """Records what the REAL eligibility gates were asked, without launching a browser.

    Delegates `check_eligibility` to the real implementation, so the security model under
    test is the genuine one rather than a permissive copy.
    """

    def __init__(self, *, enabled=True, image=PNG, raises=None):
        self._enabled = enabled
        self._image = image
        self._raises = raises
        self.captured_urls = []

    def is_enabled(self):
        return self._enabled

    def check_eligibility(self, matched_at, severity, target_type, target_value, *,
                          extra_authorized_hosts=None):
        return screenshot.check_eligibility(
            matched_at, severity, target_type, target_value,
            extra_authorized_hosts=extra_authorized_hosts,
        )

    async def capture_screenshot(self, url, target_type, target_value, *,
                                 extra_authorized_hosts=None):
        self.captured_urls.append(url)
        if self._raises is not None:
            raise self._raises
        return self._image


def _capture(findings, **kw):
    mod = kw.pop("mod", None) or _FakeScreenshotMod(**kw)
    result = asyncio.run(screenshot_capture.capture_for_findings(
        findings, target_type=TARGET_TYPE, target_value=TARGET_VALUE, screenshot_mod=mod,
    ))
    return result, mod


# ---------------------------------------------------------------------------------------
# 1. Eligible finding -> capture is ATTEMPTED on the worker
# ---------------------------------------------------------------------------------------

@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_eligible_finding_is_captured_on_the_worker(_ssrf):
    """THE regression test: the execution plane must actually reach the capture code."""
    shots, mod = _capture([_Finding("tpl@a", f"https://{TARGET_VALUE}/admin")])
    assert mod.captured_urls == [f"https://{TARGET_VALUE}/admin"]
    assert shots == [("tpl@a", PNG)]


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_fingerprint_is_carried_with_the_image(_ssrf):
    """The image is useless without the identity the manager associates it by."""
    shots, _ = _capture([_Finding("exposed-git-config@https://t.example.com/.git/config",
                                  f"https://{TARGET_VALUE}/.git/config")])
    assert shots[0][0] == "exposed-git-config@https://t.example.com/.git/config"


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_findings_without_a_fingerprint_are_skipped(_ssrf):
    """Nothing the manager could ever attach -- do not spend a browser on it."""
    shots, mod = _capture([_Finding(None, f"https://{TARGET_VALUE}/x")])
    assert shots == [] and mod.captured_urls == []


# ---------------------------------------------------------------------------------------
# 2. Ineligible finding -> NOT captured   (6. SSRF/scope still enforced)
# ---------------------------------------------------------------------------------------

def test_info_severity_is_not_captured():
    shots, mod = _capture([_Finding("t@i", f"https://{TARGET_VALUE}/x", severity="info")])
    assert shots == [] and mod.captured_urls == [], "info findings are out of approved scope"


def test_non_http_location_is_not_captured():
    """`host:port` (SSH findings) and non-web schemes never reach a browser."""
    for value in (f"{TARGET_VALUE}:22", "ssh://t.example.com", "file:///etc/passwd",
                  "data:text/html,<h1>x", None, ""):
        shots, mod = _capture([_Finding("t@x", value)])
        assert shots == [] and mod.captured_urls == [], value


def test_out_of_scope_host_is_not_captured():
    """scope_guard: the authorization boundary is unchanged and still enforced here."""
    shots, mod = _capture([_Finding("t@x", "https://not-our-target.example.net/a")])
    assert shots == [] and mod.captured_urls == []


def test_private_address_is_blocked_by_net_guard():
    """net_guard SSRF policy, running for real -- the loopback literal must be refused."""
    shots, mod = _capture([_Finding("t@x", "https://127.0.0.1/admin")])
    assert shots == [] and mod.captured_urls == []


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_an_eligibility_error_is_a_refusal_not_a_pass(_ssrf):
    """A guard that raises must fail CLOSED."""
    class _Boom(_FakeScreenshotMod):
        def check_eligibility(self, *a, **kw):
            raise RuntimeError("resolver exploded")

    shots, mod = _capture([_Finding("t@x", f"https://{TARGET_VALUE}/a")], mod=_Boom())
    assert shots == [] and mod.captured_urls == []


def test_feature_flag_off_captures_nothing():
    shots, mod = _capture([_Finding("t@x", f"https://{TARGET_VALUE}/a")], enabled=False)
    assert shots == [] and mod.captured_urls == []


# ---------------------------------------------------------------------------------------
# 5. Capture failure is FAIL-SOFT
# ---------------------------------------------------------------------------------------

@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_capture_returning_none_yields_no_evidence(_ssrf):
    """Never fabricate a placeholder image."""
    shots, _ = _capture([_Finding("t@x", f"https://{TARGET_VALUE}/a")], image=None)
    assert shots == []


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_capture_raising_does_not_propagate(_ssrf):
    shots, _ = _capture([_Finding("t@x", f"https://{TARGET_VALUE}/a")],
                        raises=RuntimeError("chromium missing"))
    assert shots == []


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_one_bad_finding_does_not_stop_the_others(_ssrf):
    """A failure is per-finding, not per-run."""
    class _FailFirst(_FakeScreenshotMod):
        async def capture_screenshot(self, url, *a, **kw):
            self.captured_urls.append(url)
            if url.endswith("/bad"):
                raise RuntimeError("boom")
            return PNG

    shots, _ = _capture(
        [_Finding("t@bad", f"https://{TARGET_VALUE}/bad"),
         _Finding("t@good", f"https://{TARGET_VALUE}/good")],
        mod=_FailFirst(),
    )
    assert shots == [("t@good", PNG)]


# ---------------------------------------------------------------------------------------
# Budget + dedup: a browser must not run away with the scan
# ---------------------------------------------------------------------------------------

@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_duplicate_findings_are_captured_once(_ssrf):
    shots, mod = _capture([_Finding("t@same", f"https://{TARGET_VALUE}/same"),
                           _Finding("t@same", f"https://{TARGET_VALUE}/same")])
    assert len(mod.captured_urls) == 1 and len(shots) == 1


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
def test_per_run_budget_is_enforced(_ssrf):
    findings = [_Finding(f"t@{i}", f"https://{TARGET_VALUE}/{i}") for i in range(50)]
    shots, mod = _capture(findings)
    assert len(shots) == screenshot_capture.MAX_SCREENSHOTS_PER_RUN
    assert len(mod.captured_urls) == screenshot_capture.MAX_SCREENSHOTS_PER_RUN


# ---------------------------------------------------------------------------------------
# 3./4. The EXECUTOR submits PNG bytes with the finding identity attached
# ---------------------------------------------------------------------------------------

class _RecordingReporter:
    def __init__(self, fail=False):
        self.evidence = []
        self._fail = fail

    async def submit_tool_started(self, **kw):
        return {}

    async def submit_tool_result(self, **kw):
        return {}

    async def submit_evidence(self, **kw):
        self.evidence.append(kw)
        if self._fail and kw.get("content_type") == "image/png":
            raise RuntimeError("manager unreachable")
        return {}


class _StubRunner:
    name = "nuclei"
    phase = 5
    applicable_target_types = None
    benign_exit_codes = ()

    async def run(self, target_value, config, prior):
        return RawToolOutput(command="nuclei", stdout="out", stderr="", exit_code=0)

    def parse(self, raw):
        return []

    def parse_vulnerabilities(self, raw):
        return [_Finding("tpl@loc", f"https://{TARGET_VALUE}/admin")]

    def hard_failure(self, raw):
        return False


def _run_executor(reporter, runner=_StubRunner):
    job = {
        "scan_id": str(uuid.uuid4()),
        "execution_token": str(uuid.uuid4()),
        "target": {"type": TARGET_TYPE, "value": TARGET_VALUE},
        "requested_modules": ["nuclei"],
        "config": {},
    }
    return asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter, registry={"nuclei": runner},
    ))


async def _png(url, *a, **kw):
    return PNG


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
@patch.object(screenshot, "is_enabled", return_value=True)
@patch.object(screenshot, "capture_screenshot", side_effect=_png)
def test_executor_submits_screenshot_as_image_png(_cap, _en, _ssrf):
    """Requirements 3 + 4: PNG content type, and the finding identity travels with it."""
    reporter = _RecordingReporter()
    assert _run_executor(reporter) == "completed"

    shots = [e for e in reporter.evidence if e.get("content_type") == "image/png"]
    assert len(shots) == 1, f"no screenshot submitted: {reporter.evidence}"
    assert shots[0]["content"] == PNG
    assert shots[0]["fingerprint"] == "tpl@loc", "screenshot lost its finding association"
    # A PNG must NOT name a parser: tool_name is what makes the manager run the text
    # parser over the bytes, and image bytes are not parseable output.
    assert shots[0]["tool_name"] is None


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
@patch.object(screenshot, "is_enabled", return_value=True)
@patch.object(screenshot, "capture_screenshot", side_effect=_png)
def test_raw_output_evidence_is_submitted_before_the_screenshot(_cap, _en, _ssrf):
    """ORDERING IS LOAD-BEARING: the manager derives the vulnerability from the raw output,
    so a screenshot submitted first would have no finding to attach to."""
    reporter = _RecordingReporter()
    _run_executor(reporter)
    types = [e.get("content_type") for e in reporter.evidence]
    assert types == ["text/plain", "image/png"], types


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
@patch.object(screenshot, "is_enabled", return_value=True)
@patch.object(screenshot, "capture_screenshot", side_effect=_png)
def test_screenshot_submission_failure_does_not_fail_the_tool(_cap, _en, _ssrf):
    """Requirement 5 at the executor level."""
    reporter = _RecordingReporter(fail=True)
    assert _run_executor(reporter) == "completed", "a lost image must not fail the scan"


@patch.object(screenshot, "is_enabled", return_value=True)
def test_a_parser_that_raises_does_not_fail_the_tool(_en):
    class _BadParse(_StubRunner):
        def parse_vulnerabilities(self, raw):
            raise ValueError("unparseable")

    reporter = _RecordingReporter()
    assert _run_executor(reporter, runner=_BadParse) == "completed"
    assert not [e for e in reporter.evidence if e.get("content_type") == "image/png"]


@patch.object(screenshot, "is_enabled", return_value=True)
def test_inventory_only_tool_submits_no_screenshot(_en):
    """subfinder/httpx have no parse_vulnerabilities -- nothing to photograph."""
    class _InventoryOnly:
        name = "subfinder"
        phase = 1
        applicable_target_types = None
        benign_exit_codes = ()

        async def run(self, target_value, config, prior):
            return RawToolOutput(command="s", stdout="o", stderr="", exit_code=0)

        def parse(self, raw):
            return []

        def hard_failure(self, raw):
            return False

    reporter = _RecordingReporter()
    assert _run_executor(reporter, runner=_InventoryOnly) == "completed"
    assert not [e for e in reporter.evidence if e.get("content_type") == "image/png"]


def test_screenshot_flag_is_off_by_default_in_settings():
    """The capture must stay opt-in: an image without Chromium is a failure per finding."""
    from apps.api.core.config import Settings

    assert Settings.model_fields["screenshot_evidence_enabled"].default is False


# ---------------------------------------------------------------------------------------
# F2-10: a `failed`-classified tool run must not have screenshot evidence generated for
# vulnerabilities `_capture_and_submit_screenshots` independently re-parses from raw output
# -- mirrors F2-07's "don't trust output from a failed run" rule, applied to this function's
# own re-parse instead of the caller's already-zeroed `findings`/`vuln_findings`.
# ---------------------------------------------------------------------------------------

class _HardFailingRunner(_StubRunner):
    """Non-zero exit, parseable vulnerability output, but flagged a hard failure --
    classify_run() -> 'failed' regardless of what parse_vulnerabilities() returns."""

    async def run(self, target_value, config, prior):
        return RawToolOutput(
            command="nuclei", stdout="out", stderr="auth error", exit_code=1,
        )

    def hard_failure(self, raw):
        return True


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
@patch.object(screenshot, "is_enabled", return_value=True)
@patch.object(screenshot, "capture_screenshot", side_effect=_png)
def test_failed_run_captures_no_screenshots(_cap, _en, _ssrf):
    reporter = _RecordingReporter()
    outcome = _run_executor(reporter, runner=_HardFailingRunner)
    assert outcome == "failed"
    assert not [e for e in reporter.evidence if e.get("content_type") == "image/png"]
    _cap.assert_not_called()


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
@patch.object(screenshot, "is_enabled", return_value=True)
@patch.object(screenshot, "capture_screenshot", side_effect=_png)
def test_completed_run_still_captures_screenshots(_cap, _en, _ssrf):
    """Existing behavior for a non-failed status is unaffected by the F2-10 guard."""
    reporter = _RecordingReporter()
    assert _run_executor(reporter) == "completed"
    shots = [e for e in reporter.evidence if e.get("content_type") == "image/png"]
    assert len(shots) == 1


@patch.object(screenshot, "_host_passes_ssrf_policy", return_value=True)
@patch.object(screenshot, "is_enabled", return_value=True)
@patch.object(screenshot, "capture_screenshot", side_effect=_png)
def test_partial_run_still_captures_screenshots(_cap, _en, _ssrf):
    """A non-zero exit that still produced usable output (partial) must be unaffected."""
    class _PartialRunner(_StubRunner):
        async def run(self, target_value, config, prior):
            return RawToolOutput(
                command="nuclei", stdout="out", stderr="", exit_code=1,
            )

    reporter = _RecordingReporter()
    assert _run_executor(reporter, runner=_PartialRunner) == "completed_with_errors"
    shots = [e for e in reporter.evidence if e.get("content_type") == "image/png"]
    assert len(shots) == 1
