"""Prompt 17 -- Parameter Intelligence (adversarial).

Discovered parameters must become CORRECT, actionable security-test inputs. The attack
surface here is how a discovered param NAME is turned into a synthesised query the DAST
fuzzer then injects into. A malformed construction can FABRICATE a parameter the target
never exposed (evidence-integrity failure) or inject our own parameter pollution.

These tests attack duplicate param names, encoding, pollution, missing/empty values, and
parser-discrepancy inputs (`&`/`=`/space in a name). They pin that the discovered names are
preserved faithfully while the synthesised URL is always well-formed.
"""
import json

from apps.api.scanner_engine.tool_runners.arjun_runner import ArjunRunner
from apps.api.scanner_engine.tool_runners.base import RawToolOutput


def _parse(data):
    return ArjunRunner().parse(RawToolOutput("arjun", json.dumps(data), "", 0))


def test_duplicate_param_names_are_collapsed_not_polluted():
    """arjun may report a name twice; we must NOT emit `?q=1&q=1` -- that is parameter
    pollution WE inject, wasting fuzz budget and making the URL nondeterministic."""
    findings = _parse({"http://a/api": {"params": ["q", "q", "id", "id"]}})
    assert findings[0].value == "http://a/api?q=1&id=1"
    assert findings[0].metadata["params"] == ["q", "id"]


def test_param_name_with_ampersand_cannot_fabricate_a_phantom_parameter():
    """EVIDENCE-INTEGRITY GUARD: a discovered name `x&y` must not split into a phantom
    parameter `y` the target never exposed. It is encoded to a single param."""
    findings = _parse({"http://a/api": {"params": ["x&y"]}})
    # `x&y` -> `x%26y`, one parameter, no phantom `y`.
    assert findings[0].value == "http://a/api?x%26y=1"
    assert "&y=1" not in findings[0].value


def test_param_name_with_space_produces_a_valid_url():
    findings = _parse({"http://a/s": {"params": ["a b"]}})
    assert findings[0].value == "http://a/s?a%20b=1"
    assert " " not in findings[0].value


def test_param_name_with_equals_is_encoded():
    """An `=` inside a name would otherwise be read as name=...=1, a parser discrepancy."""
    findings = _parse({"http://a/s": {"params": ["a=b"]}})
    assert findings[0].value == "http://a/s?a%3Db=1"


def test_empty_and_whitespace_only_names_are_dropped():
    """A blank name cannot be a real parameter -- dropped, never emitted as `?=1`."""
    findings = _parse({"http://a/s": {"params": ["", "   ", "real"]}})
    assert findings[0].value == "http://a/s?real=1"
    assert findings[0].metadata["params"] == ["real"]


def test_url_that_already_has_a_query_uses_ampersand_separator():
    findings = _parse({"http://a/s?existing=1": {"params": ["new"]}})
    assert findings[0].value == "http://a/s?existing=1&new=1"


def test_no_params_yields_no_finding():
    """A URL arjun probed but found no params on is not an actionable param target."""
    assert _parse({"http://a/dead": {"params": []}}) == []


def test_metadata_records_the_deduped_discovered_names_for_provenance():
    """The synthesised value is for fuzzing; the metadata is the provenance record of what
    arjun actually discovered (deduped, encoding-free names)."""
    findings = _parse({"http://a/api": {"params": ["token", "token", "redirect"]}})
    assert findings[0].metadata["params"] == ["token", "redirect"]
    assert findings[0].metadata["source"] == "arjun"


def test_ordinary_params_are_unchanged_regression():
    """The common case must be byte-identical to before the hardening."""
    findings = _parse({"http://a/api/products": {"params": ["q", "sort", "category"]}})
    assert findings[0].value == "http://a/api/products?q=1&sort=1&category=1"


def test_cap_is_respected_after_dedup():
    """The MAX_PARAMS_PER_URL cap applies to DISTINCT names, so duplicates don't consume the
    budget."""
    from apps.api.scanner_engine.tool_runners.arjun_runner import MAX_PARAMS_PER_URL

    names = [f"p{i}" for i in range(MAX_PARAMS_PER_URL + 10)]
    findings = _parse({"http://a/x": {"params": names}})
    assert len(findings[0].metadata["params"]) == MAX_PARAMS_PER_URL
