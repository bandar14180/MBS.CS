"""http_service_urls() bare-host deduplication.

WHY THIS FILE EXISTS. A 29-target katana run against a real authorized engagement showed
`https://host` and `https://host/` both present as separate `http_service` findings, and
BOTH were fed to katana as independent targets -- doubling wall-clock/memory cost on exactly
the hosts already at the per-target timeout/OOM boundary (`new`, `www`, the root domain,
`cpanel`, `webmail`). The two strings name the same resource (the site root), so crawling
both is pure duplicated cost with no additional coverage.

The fix is narrow and lives ONLY on the `http_service_urls()` path: a lone trailing `/` on a
bare `scheme://host[:port]` collapses into the no-slash form. Every OTHER `_web.py` caller
(`content_discovery_targets`, `crawled_urls`, `param_discovery_targets`) keeps using the
original exact-match `_dedupe()`, where a trailing slash or a query string is part of a URL's
identity (`/api` vs `/api/`, `?a=1` vs `?a=2`).
"""

from apps.api.scanner_engine.tool_runners._web import (
    _dedupe,
    _dedupe_bare_hosts,
    http_service_urls,
)
from apps.api.scanner_engine.tool_runners.base import CommonFinding


def _http_service(value: str) -> CommonFinding:
    return CommonFinding(asset_type="http_service", value=value, metadata={})


# ============================ A/B: bare host + trailing slash =============================

def test_https_bare_host_and_trailing_slash_collapse_to_one() -> None:
    findings = [_http_service("https://example.com"), _http_service("https://example.com/")]
    assert http_service_urls(findings) == ["https://example.com"]


def test_http_bare_host_and_trailing_slash_collapse_to_one() -> None:
    findings = [_http_service("http://example.com"), _http_service("http://example.com/")]
    assert http_service_urls(findings) == ["http://example.com"]


def test_trailing_slash_first_then_bare_host_keeps_first_occurrence() -> None:
    """First occurrence wins -- order-preserving, matching `_dedupe()`'s existing contract."""
    findings = [_http_service("https://example.com/"), _http_service("https://example.com")]
    assert http_service_urls(findings) == ["https://example.com/"]


def test_bare_host_with_port_and_trailing_slash_collapse() -> None:
    findings = [_http_service("https://example.com:8443"), _http_service("https://example.com:8443/")]
    assert http_service_urls(findings) == ["https://example.com:8443"]


# ============================ C: distinct paths stay distinct =============================

def test_distinct_paths_remain_distinct() -> None:
    findings = [
        _http_service("https://example.com/api"),
        _http_service("https://example.com/api/"),
        _http_service("https://example.com/login"),
    ]
    assert http_service_urls(findings) == [
        "https://example.com/api",
        "https://example.com/api/",
        "https://example.com/login",
    ]


# ============================ D: query strings stay distinct ==============================

def test_query_strings_remain_distinct() -> None:
    findings = [
        _http_service("https://example.com/?a=1"),
        _http_service("https://example.com/?a=2"),
    ]
    assert http_service_urls(findings) == [
        "https://example.com/?a=1",
        "https://example.com/?a=2",
    ]


# ============================ E: existing exact-dedup behavior intact =====================

def test_exact_duplicates_still_collapse() -> None:
    findings = [_http_service("https://example.com"), _http_service("https://example.com")]
    assert http_service_urls(findings) == ["https://example.com"]


def test_mixed_hosts_all_represented() -> None:
    findings = [
        _http_service("https://a.example"),
        _http_service("https://a.example/"),
        _http_service("https://b.example"),
    ]
    assert http_service_urls(findings) == ["https://a.example", "https://b.example"]


def test_empty_input_returns_empty() -> None:
    assert http_service_urls([]) == []


def test_non_http_service_findings_are_ignored() -> None:
    findings = [
        CommonFinding(asset_type="url", value="https://example.com/", metadata={}),
        _http_service("https://example.com"),
    ]
    assert http_service_urls(findings) == ["https://example.com"]


# ============================ _dedupe() itself is untouched ===============================
# Regression guard: the generic dedupe used by every OTHER `_web.py` caller must stay
# exact-match. This is the safety property the fix depends on -- it must never start
# collapsing a trailing slash for content-discovery/crawled-URL/param-discovery targets.

def test_generic_dedupe_does_not_collapse_trailing_slash() -> None:
    assert _dedupe(["https://example.com", "https://example.com/"]) == [
        "https://example.com", "https://example.com/",
    ]


def test_bare_host_dedupe_helper_is_order_preserving() -> None:
    assert _dedupe_bare_hosts(
        ["https://a.example", "https://a.example/", "https://b.example", "https://b.example"]
    ) == ["https://a.example", "https://b.example"]
