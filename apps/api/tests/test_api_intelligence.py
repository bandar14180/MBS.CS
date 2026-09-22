"""Prompt 18 -- API Intelligence (adversarial).

Discovered API surfaces must be RECOGNISABLE and actionable, and the classifier must attack
the assumptions Prompt 18 names:
    documentation != complete API   (an OpenAPI doc is a distinct kind, not the whole API)
    one API version != all versions (a versioned endpoint records its version)
    /api/ substring != API surface  (GraphQL and versioned REST are APIs too)

These tests pin the deterministic classifier and its two integration points (katana tagging,
param-discovery prioritisation). A URL heuristic is a HINT -- these never assert reachability.
"""
from apps.api.scanner_engine.api_intel import (
    KIND_GRAPHQL,
    KIND_OPENAPI_DOC,
    KIND_REST,
    classify_api,
    is_api_url,
)
from apps.api.scanner_engine.tool_runners._web import param_discovery_targets
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput
from apps.api.scanner_engine.tool_runners.katana_runner import KatanaRunner


# --- the classifier ------------------------------------------------------------------------

def test_rest_api_segment_is_detected():
    c = classify_api("http://a/api/orders")
    assert c.is_api and c.kind == KIND_REST


def test_versioned_rest_without_api_segment_is_detected_with_version():
    """`/v2/users` is a versioned REST API even without an `/api/` segment -- previously
    invisible to the substring heuristic."""
    c = classify_api("http://a/v2/users")
    assert c.is_api and c.kind == KIND_REST and c.version == "v2"


def test_graphql_endpoint_is_detected_as_graphql():
    assert classify_api("http://a/graphql").kind == KIND_GRAPHQL
    assert classify_api("http://a/app/graphql").kind == KIND_GRAPHQL


def test_openapi_document_is_a_distinct_kind_not_a_plain_endpoint():
    """documentation != complete API: a swagger/openapi doc is `openapi_doc`, never `rest`."""
    for u in ("http://a/swagger.json", "http://a/openapi.yaml", "http://a/api-docs", "http://a/v3/api-docs"):
        assert classify_api(u).kind == KIND_OPENAPI_DOC, u


def test_version_is_captured_even_inside_an_api_path():
    c = classify_api("http://a/api/v3/orders")
    assert c.is_api and c.version == "v3"


def test_plain_pages_are_not_apis():
    for u in ("http://a/about", "http://a/software/download", "http://a/v1abc/x", "http://a/index.html"):
        assert not is_api_url(u), u


def test_classifier_never_raises_on_garbage():
    assert not classify_api("").is_api
    assert not classify_api("not a url").is_api


def test_as_metadata_is_empty_for_non_api():
    assert classify_api("http://a/about").as_metadata() == {}
    md = classify_api("http://a/v2/users").as_metadata()
    # The classification itself is unchanged; Prompt 26 adds an ADDITIVE `inferred_keys`
    # sidecar naming which of these keys were derived rather than observed.
    assert md == {
        "is_api": True, "api_kind": "rest", "api_version": "v2",
        "inferred_keys": ["api_kind", "api_version", "is_api"],
    }


# --- integration: katana tags API metadata onto the endpoint asset ------------------------

def test_katana_tags_api_endpoints():
    raw = RawToolOutput(
        "katana",
        stdout="http://a/graphql\nhttp://a/v2/users\nhttp://a/about\n",
        stderr="", exit_code=0,
    )
    by_val = {f.value: f.metadata for f in KatanaRunner().parse(raw)}
    assert by_val["http://a/graphql"]["api_kind"] == "graphql"
    assert by_val["http://a/v2/users"]["api_kind"] == "rest"
    assert by_val["http://a/v2/users"]["api_version"] == "v2"
    assert "is_api" not in by_val["http://a/about"]   # plain page carries no API tags


# --- integration: param discovery prioritises API surfaces robustly -----------------------

def test_param_discovery_hoists_graphql_and_versioned_apis_above_plain_pages():
    """GraphQL and versioned APIs must be prioritised for parameter/DAST testing, not just
    `/api/` paths. The old substring heuristic left them behind plain pages."""
    prior = [
        CommonFinding("url", "http://a/about", {}),
        CommonFinding("url", "http://a/graphql", {}),
        CommonFinding("url", "http://a/v2/users", {}),
        CommonFinding("url", "http://a/api/orders", {}),
    ]
    targets = param_discovery_targets(prior, max_targets=10)
    # all three API surfaces come before the plain page
    assert targets.index("http://a/about") == len(targets) - 1
    for api_url in ("http://a/graphql", "http://a/v2/users", "http://a/api/orders"):
        assert targets.index(api_url) < targets.index("http://a/about")


def test_openapi_doc_is_not_hoisted_above_real_endpoints():
    """A doc is API-related but not an injectable endpoint -- it must NOT crowd out a real
    endpoint from the (bounded) param-discovery budget."""
    prior = [
        CommonFinding("url", "http://a/api/orders", {}),
        CommonFinding("url", "http://a/swagger.json", {}),
    ]
    targets = param_discovery_targets(prior, max_targets=10)
    assert targets.index("http://a/api/orders") < targets.index("http://a/swagger.json")


def test_every_old_api_substring_url_still_classifies_as_api():
    """Strict-superset guarantee: nothing that matched `/api/` regresses to non-API."""
    for u in ("http://a/api/x", "http://a/x/api/y", "http://a/api/v1/z"):
        assert is_api_url(u), u
