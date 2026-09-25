"""Regression coverage for Prompt 13, Finding #7: nuclei-dast trigger context preservation.

Before this change, the specific parameter/header/method context that triggered a nuclei-dast
finding was discarded entirely -- only template_id/matcher_name/cve/type/tags survived into
VulnerabilityFinding.metadata. This file proves apps.api.scanner_engine.tool_runners.
_dast_context.extract_dast_context (wired into nuclei_runner.parse_vulnerabilities, inherited
verbatim by NucleiDastRunner) now surfaces that context WHEN nuclei's own JSON output actually
contains it, never invents it when absent, and never persists sensitive header VALUES.
"""
import json

from apps.api.scanner_engine.tool_runners._dast_context import extract_dast_context
from apps.api.scanner_engine.tool_runners.base import RawToolOutput
from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner


def _line(matched_at: str, template="tpl", matcher="m", **extra):
    obj = {
        "template-id": template, "matcher-name": matcher, "matched-at": matched_at,
        "info": {"name": "X", "severity": "high"},
    }
    obj.update(extra)
    return json.dumps(obj)


# --- extract_dast_context: pure unit tests ----------------------------------------------------

def test_method_extracted_from_request_text():
    ctx = extract_dast_context(
        {"request": "POST /login HTTP/1.1\r\nHost: h\r\n\r\nuser=a&pass=b"},
        matched_at="https://h/login",
    )
    assert ctx["http_method"] == "POST"


def test_method_extracted_from_curl_command_with_dash_x():
    ctx = extract_dast_context({"curl-command": "curl -X 'PUT' -H 'Content-Type: json' 'https://h/x'"}, matched_at=None)
    assert ctx["http_method"] == "PUT"


def test_method_defaults_to_get_for_bare_curl_command():
    ctx = extract_dast_context({"curl-command": "curl 'https://h/x'"}, matched_at=None)
    assert ctx["http_method"] == "GET"


def test_no_method_when_neither_field_present():
    ctx = extract_dast_context({}, matched_at="https://h/x")
    assert "http_method" not in ctx


def test_parameter_names_extracted_from_matched_at_query_string():
    ctx = extract_dast_context({}, matched_at="https://h/search?q=1&sort=desc")
    assert ctx["parameter_names"] == ["q", "sort"]


def test_no_parameter_names_when_url_has_no_query():
    ctx = extract_dast_context({}, matched_at="https://h/search")
    assert "parameter_names" not in ctx


def test_no_parameter_names_when_matched_at_is_none():
    ctx = extract_dast_context({}, matched_at=None)
    assert "parameter_names" not in ctx


def test_notable_header_name_is_recorded_without_its_value():
    ctx = extract_dast_context(
        {"request": "GET /x HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 127.0.0.1' OR '1'='1\r\n\r\n"},
        matched_at="https://h/x",
    )
    assert ctx["notable_header_names"] == ["x-forwarded-for"]
    # The injected payload value must never appear anywhere in the returned context.
    assert "1'='1" not in json.dumps(ctx)


def test_sensitive_header_name_is_never_recorded_even_as_a_bare_name():
    ctx = extract_dast_context(
        {"request": "GET /x HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer secret-token-value\r\n\r\n"},
        matched_at="https://h/x",
    )
    assert "notable_header_names" not in ctx or "authorization" not in ctx.get("notable_header_names", [])
    assert "secret-token-value" not in json.dumps(ctx)


def test_cookie_header_value_never_persisted():
    ctx = extract_dast_context(
        {"request": "GET /x HTTP/1.1\r\nHost: h\r\nCookie: session=abc123secret\r\n\r\n"},
        matched_at="https://h/x",
    )
    assert "abc123secret" not in json.dumps(ctx)
    assert "cookie" not in ctx.get("notable_header_names", [])


def test_empty_context_when_nothing_available():
    """A signature-mode (non-DAST) finding with no request/curl-command data must contribute an
    EMPTY dict -- no fabricated fields, unchanged from pre-Finding-#7 behavior."""
    ctx = extract_dast_context({"template-id": "tpl", "matcher-name": "m"}, matched_at="https://h")
    assert ctx == {}


# --- wiring into nuclei_runner.parse_vulnerabilities -------------------------------------------

def test_nuclei_finding_metadata_includes_dast_context_when_present():
    raw = RawToolOutput(
        command="nuclei -dast",
        stdout=_line(
            "https://h/login?user=admin",
            request="POST /login?user=admin HTTP/1.1\r\nHost: h\r\n\r\npass=x",
        ),
        stderr="", exit_code=0,
    )
    findings = NucleiRunner().parse_vulnerabilities(raw)
    assert findings[0].metadata["http_method"] == "POST"
    assert findings[0].metadata["parameter_names"] == ["user"]


def test_nuclei_finding_metadata_unchanged_shape_when_no_dast_context():
    """Existing (signature-mode) fields are untouched, and no DAST keys are added when nuclei
    provided no request/curl-command data -- exact backward-compatible metadata shape."""
    raw = RawToolOutput(command="nuclei", stdout=_line("https://h/z"), stderr="", exit_code=0)
    findings = NucleiRunner().parse_vulnerabilities(raw)
    meta = findings[0].metadata
    assert set(meta.keys()) == {"template_id", "matcher_name", "cve", "type", "tags"}


def test_nuclei_dast_inherits_the_context_extraction():
    """NucleiDastRunner reuses NucleiRunner.parse_vulnerabilities verbatim (same JSONL schema),
    so the DAST context wiring applies to it automatically -- confirmed directly rather than
    assumed from the shared method identity already pinned by test_ingest_idempotency.py."""
    raw = RawToolOutput(
        command="nuclei -dast",
        stdout=_line("https://h/x?id=1", request="GET /x?id=1 HTTP/1.1\r\nHost: h\r\n\r\n"),
        stderr="", exit_code=0,
    )
    findings = NucleiDastRunner().parse_vulnerabilities(raw)
    assert findings[0].metadata["http_method"] == "GET"
    assert findings[0].metadata["parameter_names"] == ["id"]


def test_matched_at_field_itself_unaffected_by_dast_context_addition():
    """DAST context lives only in metadata; matched_at/fingerprint semantics (Finding #1/#2)
    are untouched by this addition."""
    raw = RawToolOutput(
        command="nuclei -dast",
        stdout=_line("https://h/x?id=1", request="POST /x?id=1 HTTP/1.1\r\nHost: h\r\n\r\n"),
        stderr="", exit_code=0,
    )
    finding = NucleiRunner().parse_vulnerabilities(raw)[0]
    assert finding.matched_at == "https://h/x?id=1"
    assert finding.fingerprint == "tpl|m|https://h/x?id=1"
