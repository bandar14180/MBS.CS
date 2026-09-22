"""Prompt 16 -- Endpoint Intelligence (adversarial).

Discovered endpoints (katana crawl + JS) must become actionable, CANONICAL testing objects:
one endpoint identity per real endpoint, with duplicate spellings suppressed, so downstream
parameter-discovery / DAST budget is not wasted N-fold on the same surface. These tests
attack normalization, canonicalization, duplicate suppression, path equivalence, and
provenance -- and pin that we do NOT over-collapse genuinely different endpoints.
"""
from apps.api.scanner_engine.tool_runners._web import param_discovery_targets
from apps.api.scanner_engine.tool_runners.base import RawToolOutput
from apps.api.scanner_engine.tool_runners.katana_runner import KatanaRunner


def _parse(*lines):
    raw = RawToolOutput("katana", stdout="\n".join(lines) + "\n", stderr="", exit_code=0)
    return KatanaRunner().parse(raw)


def test_duplicate_spellings_collapse_to_one_endpoint():
    """host case, default port, empty path and #fragment are representational -- four
    spellings of ONE endpoint must yield ONE endpoint asset, not four."""
    findings = _parse(
        "http://a.com/x",
        "http://A.com/x",       # host case
        "http://a.com:80/x",    # redundant default port
        "http://a.com/x#frag",  # fragment (never sent to server)
    )
    assert [f.value for f in findings] == ["http://a.com/x"]


def test_https_default_port_collapses_too():
    findings = _parse("https://a.com:443/api", "https://a.com/api")
    assert [f.value for f in findings] == ["https://a.com/api"]


def test_raw_url_provenance_is_preserved_when_canonicalization_changes_it():
    """Canonicalization must never detach the finding from what the tool actually emitted:
    the raw URL is kept in metadata whenever it differed."""
    findings = _parse("http://A.com:80/x#frag")
    assert findings[0].value == "http://a.com/x"
    assert findings[0].metadata["raw_url"] == "http://A.com:80/x#frag"


def test_no_raw_url_key_when_already_canonical():
    """A URL that was already canonical carries no redundant raw_url key."""
    findings = _parse("http://a.com/x")
    assert findings[0].value == "http://a.com/x"
    assert "raw_url" not in findings[0].metadata


def test_trailing_slash_is_NOT_over_collapsed():
    """PATH EQUIVALENCE GUARD: `/foo` and `/foo/` can be materially different resources
    (directory listing vs file). They must remain DISTINCT endpoints -- over-collapsing would
    hide a real endpoint from testing."""
    findings = _parse("http://a.com/foo", "http://a.com/foo/")
    assert {f.value for f in findings} == {"http://a.com/foo", "http://a.com/foo/"}


def test_query_values_are_never_normalized_away():
    """A query value is often the injectable input itself -- two different values are two
    different test inputs and must stay distinct."""
    findings = _parse("http://a.com/s?q=A", "http://a.com/s?q=b")
    assert {f.value for f in findings} == {"http://a.com/s?q=A", "http://a.com/s?q=b"}


def test_non_default_port_is_preserved_as_a_distinct_endpoint():
    """A service on a non-default port is a genuinely different endpoint -- never collapsed
    into the default-port one."""
    findings = _parse("http://a.com:8080/x", "http://a.com/x")
    assert {f.value for f in findings} == {"http://a.com:8080/x", "http://a.com/x"}


def test_canonical_endpoints_dedupe_downstream_param_discovery_targets():
    """The whole point: canonical endpoints mean param discovery (arjun) is pointed at the
    real endpoint ONCE, not once per spelling -- the (expensive) per-URL budget is not
    wasted."""
    findings = _parse(
        "http://a.com/api/orders",
        "http://A.com:80/api/orders",   # same endpoint, different spelling
        "http://a.com/api/orders#x",
    )
    targets = param_discovery_targets(findings, max_targets=10)
    assert targets == ["http://a.com/api/orders"]


def test_has_params_flag_reflects_the_canonical_value():
    """The has_params flag drives downstream routing (param URL -> DAST, paramless ->
    arjun). A fragment-only URL is paramless after canonicalization."""
    findings = _parse("http://a.com/s?q=1#frag")
    assert findings[0].metadata["has_params"] is True
    findings = _parse("http://a.com/s#q=1")   # '#q=1' is a fragment, not a query
    assert findings[0].metadata["has_params"] is False


def test_non_url_lines_are_ignored():
    findings = _parse("not-a-url", "ftp://a.com/x", "http://a.com/real")
    assert [f.value for f in findings] == ["http://a.com/real"]
