"""Deterministic API-surface classification for discovered URL endpoints (Prompt 18).

WHAT THIS ADDS, and what it does NOT. Before this, the ONLY notion of "this endpoint is an
API" in the whole engine was a single substring test -- `"/api/" in url` in
_web.param_discovery_targets -- used to prioritise parameter discovery. That heuristic is
brittle in exactly the ways Prompt 18 calls out:

    /graphql            -> a GraphQL API, MISSED (no `/api/`)
    /v2/users           -> a versioned REST API, MISSED
    /swagger.json       -> an OpenAPI/Swagger document, MISSED
    /api/v3/orders      -> matched, but its VERSION was invisible

This module makes an API surface RECOGNISABLE and actionable: a pure, deterministic
classifier that tags a URL with whether it is an API, what KIND, and (where present) its
VERSION. It runs no tool, sends no request, and invents nothing -- every signal is derived
from the URL path itself. It is used to:

  * tag katana-discovered `url` assets with their API characteristics (so the coverage model
    and reports can reason about the API surface), and
  * prioritise parameter/DAST testing at the API surface ROBUSTLY (GraphQL and versioned
    APIs included), replacing the `/api/` substring.

DELIBERATE BOUNDARIES (Prompt 18's "attack assumptions"):
  * A URL heuristic is a HINT, never proof. is_api=True does not assert the endpoint is
    reachable, documented, or complete -- only that its shape matches an API surface. Nothing
    here reclassifies a finding or changes verification.
  * An OpenAPI/Swagger DOCUMENT (swagger.json / openapi.yaml / /api-docs) is flagged as
    `openapi_doc` -- it is documentation, and "documentation = complete API" is precisely the
    assumption Prompt 18 says to attack, so it is a DISTINCT kind, never treated as the whole
    API.
  * VERSION detection (v1, v2, ...) exists so "one API version = all versions" is visible: a
    discovered /v2/ endpoint records version="v2" so an untested /v1//v3 is a nameable gap,
    not an invisible one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# API "kinds" this classifier distinguishes. rest is the default when a path looks like an
# API surface but is not GraphQL or an OpenAPI document.
KIND_REST = "rest"
KIND_GRAPHQL = "graphql"
KIND_OPENAPI_DOC = "openapi_doc"

# A path segment like v1, v2, V3, v10 -- a version marker. Anchored to a full segment so
# `/software/` (contains no version) or `/v1abc/` (not a bare version) do not false-match.
_VERSION_SEG = re.compile(r"^v(\d+)$", re.IGNORECASE)

# Path (or trailing segment) shapes that denote an OpenAPI/Swagger DOCUMENT, not an endpoint.
_OPENAPI_DOC_MARKERS = (
    "swagger.json", "swagger.yaml", "swagger.yml",
    "openapi.json", "openapi.yaml", "openapi.yml",
    "/swagger-ui", "/api-docs", "/openapi", "/swagger",
)

# GraphQL endpoints conventionally live at one of these exact trailing paths.
_GRAPHQL_PATHS = ("/graphql", "/graphiql", "/gql")

# Segments that, as a WHOLE path segment, mark a REST API surface.
_REST_SEGMENTS = frozenset({"api", "rest", "graphql-api"})


@dataclass(frozen=True)
class ApiClassification:
    """The API characteristics of one URL, all derived from the path. `is_api` is a HINT."""

    is_api: bool
    kind: str | None = None       # rest | graphql | openapi_doc | None
    version: str | None = None    # e.g. "v2" when a version segment is present

    def as_metadata(self) -> dict:
        """The subset worth carrying onto an asset's metadata (only truthy fields, so a
        non-API URL adds nothing).

        PROVENANCE (Prompt 26). These keys are INFERRED -- derived from the URL path alone,
        with no request sent -- while they sit in the SAME flat metadata namespace as OBSERVED
        facts a tool actually measured (`status_code`, `tech`, `title`). Nothing distinguished
        the two, so a reader could not tell "nuclei saw a 403" from "this path looks like an
        API". The correlation rules require the distinction, so the inferred keys are NAMED in
        an additive sidecar rather than restructured: every existing consumer
        (adaptive.py's `md.get("is_api")`, coverage.py, attack_graph) keeps reading the same
        flat keys unchanged, and a reader that cares about the tier now has an explicit answer.

        This is a LABEL about how the value was derived. It asserts nothing about the
        endpoint, and an INFERRED classification can never become evidence or VERIFIED."""
        md: dict = {}
        if self.is_api:
            md["is_api"] = True
        if self.kind:
            md["api_kind"] = self.kind
        if self.version:
            md["api_version"] = self.version
        if md:
            md["inferred_keys"] = sorted(md)
        return md


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def classify_api(url: str) -> ApiClassification:
    """Classify a URL's API surface deterministically from its PATH. Never raises: a URL that
    does not parse is treated as non-API."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ApiClassification(is_api=False)
    path = (parts.path or "").lower()
    if not path:
        return ApiClassification(is_api=False)

    # OpenAPI/Swagger DOCUMENT -- documentation, a distinct kind (see module docstring).
    if any(marker in path for marker in _OPENAPI_DOC_MARKERS):
        version = _version_in(path)
        return ApiClassification(is_api=True, kind=KIND_OPENAPI_DOC, version=version)

    # GraphQL endpoint (exact trailing path).
    if any(path == g or path.endswith(g) for g in _GRAPHQL_PATHS):
        return ApiClassification(is_api=True, kind=KIND_GRAPHQL, version=_version_in(path))

    segs = _segments(path)
    version = _version_in(path)

    # A REST API surface: an `api`/`rest` segment, OR a version segment (a bare /v2/... is a
    # versioned API even without an explicit `api` segment).
    if _REST_SEGMENTS.intersection(segs) or version is not None:
        return ApiClassification(is_api=True, kind=KIND_REST, version=version)

    return ApiClassification(is_api=False)


def _version_in(path: str) -> str | None:
    """The first version segment (v1, v2, ...) in a path, normalised to lowercase, or None."""
    for seg in _segments(path):
        m = _VERSION_SEG.match(seg)
        if m:
            return f"v{m.group(1)}"
    return None


def is_api_url(url: str) -> bool:
    """Convenience: whether a URL's shape denotes an API surface (any kind)."""
    return classify_api(url).is_api
