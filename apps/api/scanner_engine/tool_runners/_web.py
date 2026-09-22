"""Shared web-target selection for the HTTP-layer tools (nuclei, katana,
nuclei-dast).

The recon pipeline confirms live HTTP services with httpx, but httpx only probes
default ports (80/443) on the bare target -- so a web app on a non-standard port
(e.g. :3300) yields no `http_service` finding. These helpers give the later
HTTP tools the *best available* set of URLs to work on, degrading gracefully:

    httpx-confirmed services  ->  discovered ports (naabu/nmap)  ->  bare host

Keeping this in one place means nuclei, the crawler, and the DAST runner all
target the exact same surface (no tool silently scanning a different thing)."""
import socket

from apps.api.scanner_engine import net_guard
from apps.api.scanner_engine.tool_runners._net import resolve_scan_host
from apps.api.scanner_engine.tool_runners.base import CommonFinding

# Each discovered open port becomes two candidate URLs (http + https); bound the
# fan-out so a wide top-ports sweep can't explode the target list.
DEFAULT_MAX_ENDPOINTS = 50


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    return [i for i in items if not (i in seen or seen.add(i))]


def _bare_host_dedupe_key(url: str) -> str:
    """Dedup key for a BARE-HOST http_service URL: collapses a lone trailing `/`.

    `https://host` and `https://host/` name the same resource (the site root) --
    httpx records both shapes depending on how it probed, and each one used to
    become its OWN katana process. Two of MBS.SC's most expensive targets
    (`cpanel`/`webmail`-style panels) were observed running TWICE this way, each
    copy independently timing out or hitting the per-process OOM ceiling -- pure
    duplicated cost with zero extra coverage, since both requests hit the same
    URL.

    NARROW ON PURPOSE: this strips at most one trailing `/`, and only when doing
    so leaves nothing else behind (no path, no query, no fragment) -- i.e. only
    for `scheme://host[:port]` and `scheme://host[:port]/`. It must NOT collapse
    `/api` and `/api/` (a trailing slash is meaningful on many servers -- a
    directory vs. a file, or a distinct route) or anything carrying a query
    string. This key is used ONLY by `http_service_urls()`; `_dedupe()` itself
    stays exact-match for every other caller (content-discovery, crawled-URL,
    param-discovery targets), where a trailing slash or a query string is part
    of the URL's identity.
    """
    if url.endswith("/") and url.count("/") == 3:
        # scheme://host/ -- exactly one trailing slash and nothing after the
        # host, e.g. "https://example.com/". Strip it so it dedupes against
        # "https://example.com".
        return url[:-1]
    return url


def _dedupe_bare_hosts(items: list[str]) -> list[str]:
    """Order-preserving dedupe of bare-host URLs, collapsing `host` == `host/`.

    First occurrence wins, exactly like `_dedupe()` -- so if httpx recorded the
    trailing-slash form first, THAT is the string handed to the tools; only the
    later duplicate is dropped."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = _bare_host_dedupe_key(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def http_service_urls(prior_findings: list[CommonFinding]) -> list[str]:
    """URLs of the HTTP services httpx confirmed (deduped; [] if none).

    Uses `_dedupe_bare_hosts()`, not the generic `_dedupe()`: httpx can record
    the same site root as both `https://host` and `https://host/`, and these
    are the SAME logical target for every downstream HTTP tool (katana,
    nuclei, nuclei-dast) -- see `_bare_host_dedupe_key()`."""
    return _dedupe_bare_hosts(
        [f.value for f in prior_findings if f.asset_type == "http_service" and f.value]
    )


def discovered_port_urls(
    prior_findings: list[CommonFinding], max_endpoints: int = DEFAULT_MAX_ENDPOINTS
) -> list[str]:
    """http+https URLs for each open port naabu (`port`) / nmap (`service`) found.

    We can't know the scheme without httpx, so both are emitted; the HTTP tools
    simply no-op on a port that doesn't speak (that) HTTP."""
    endpoints: list[str] = []
    seen: set[str] = set()
    for f in prior_findings:
        if f.asset_type not in ("service", "port"):
            continue
        host = f.metadata.get("ip") or f.metadata.get("host")
        port = f.metadata.get("port")
        if not host or port is None:
            continue
        ep = f"{host}:{port}"
        if ep not in seen:
            seen.add(ep)
            endpoints.append(ep)
    urls: list[str] = []
    for ep in endpoints[:max_endpoints]:
        urls.append(f"http://{ep}")
        urls.append(f"https://{ep}")
    return urls


def web_targets(
    target_value: str, prior_findings: list[CommonFinding], max_endpoints: int = DEFAULT_MAX_ENDPOINTS
) -> list[str]:
    """The best web URLs to point an HTTP tool at, in priority order:
    httpx-confirmed services, else discovered ports, else http(s) on the bare
    (SSRF-validated) target."""
    urls = http_service_urls(prior_findings)
    if urls:
        return urls
    urls = discovered_port_urls(prior_findings, max_endpoints)
    if urls:
        return urls
    # Validate (SSRF/DNS-rebinding) but build the URL from the ORIGINAL HOSTNAME, not the
    # resolved IP -- see httpx_runner.run()'s comment: an HTTP-layer tool needs the real
    # Host header/SNI or a CDN/shared-IP target answers with someone else's default site.
    # AUDIT-011: catch ONLY the expected resolver failures. This used to be a bare
    # `except Exception: pass`, which also swallowed net_guard.TargetNotAllowed -- so a target
    # the SSRF policy had just REJECTED fell straight through to the `return [http://host,
    # https://host]` below and was handed to nuclei/katana/ffuf anyway. A security denial must
    # never be downgraded to a silent success; it propagates to the orchestrator, which fails
    # the scan (see orchestrator.py's "safety failure, not a fail-soft tool error").
    # socket.gaierror (host does not resolve) and IndexError (resolver returned nothing) are
    # genuinely recoverable and stay best-effort, matching httpx_runner/naabu_runner.
    try:
        resolve_scan_host(target_value)
    except (socket.gaierror, IndexError):
        pass  # unresolvable now; the tool will fail cleanly on a host that isn't there
    host = net_guard._host_from_value(target_value) or target_value
    return [f"http://{host}", f"https://{host}"]


def _root_is_fuzzable(status_code) -> bool:
    """True if a host's ROOT status_code makes it a content-discovery target. Missing/None
    -> True (include, matching the pre-filter behavior). Non-numeric -> True too: never lose
    a real target to a parsing quirk. Only a parseable 4xx/5xx excludes."""
    if status_code is None:
        return True
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return True
    return code < 400


def content_discovery_targets(
    target_value: str, prior_findings: list[CommonFinding], max_endpoints: int = DEFAULT_MAX_ENDPOINTS
) -> list[str]:
    """web_targets() for content-discovery (ffuf), minus httpx-confirmed services whose ROOT
    returned 4xx/5xx.

    A host answering 4xx/5xx on `/` has no content tree to brute-force, and hammering it is
    exactly what makes ffuf bail with "Receiving spurious errors, exiting." (the real case: an
    Autodiscover/mail endpoint returning 400 to every path). The decision is behavior-based on
    httpx's own recorded status_code -- NO hostname rules. Only the httpx-service tier is
    filtered; the discovered-port and bare-host fallbacks are identical to web_targets() (they
    carry no status to judge), so nothing regresses when httpx found nothing."""
    usable = [
        f for f in prior_findings
        if f.asset_type == "http_service" and f.value and _root_is_fuzzable(f.metadata.get("status_code"))
    ]
    urls = _dedupe([f.value for f in usable])
    if urls:
        return urls
    urls = discovered_port_urls(prior_findings, max_endpoints)
    if urls:
        return urls
    # AUDIT-011: identical narrowing to web_targets() above -- TargetNotAllowed must reach the
    # caller rather than being converted into a fuzzable URL list for ffuf.
    try:
        resolve_scan_host(target_value)
    except (socket.gaierror, IndexError):
        pass  # unresolvable now; the tool will fail cleanly on a host that isn't there
    host = net_guard._host_from_value(target_value) or target_value
    return [f"http://{host}", f"https://{host}"]


def crawled_urls(prior_findings: list[CommonFinding]) -> list[str]:
    """URLs for the DAST fuzzer, best-first so a big crawl can't crowd the good
    targets out of the fuzz cap:
      1. arjun-confirmed parameters (highest value -- a real param to inject),
      2. other parameterised URLs (katana found a `?param=`),
      3. paramless URLs (little for -dast to fuzz)."""
    url_findings = [f for f in prior_findings if f.asset_type == "url" and f.value]
    arjun = _dedupe([f.value for f in url_findings if f.metadata.get("source") == "arjun"])
    with_params = _dedupe([f.value for f in url_findings if "?" in f.value and f.value not in arjun])
    paramless = _dedupe([f.value for f in url_findings if "?" not in f.value])
    return _dedupe(arjun + with_params + paramless)


# Static assets have no server-side parameters to discover -- skip them so param
# discovery (arjun) spends its (expensive) budget on real endpoints.
_STATIC_EXT = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".webp", ".pdf", ".mp4", ".mp3",
)


def param_discovery_targets(prior_findings: list[CommonFinding], max_targets: int = 10) -> list[str]:
    """The crawled endpoints worth running parameter discovery on: the base path
    of every non-static URL, API surfaces first (the JSON API is where the
    injectable params usually hide). We strip the query and dedupe by path --
    crucial because the crawler emits API endpoints WITH a trailing `?` (e.g.
    `/api/products?`), and those are exactly the paths whose real parameter names
    we need arjun to discover. Bounded because arjun is request-heavy per URL.

    Prompt 18 (API Intelligence): API detection now uses the deterministic classifier
    (api_intel.classify_api) instead of a `"/api/"` substring, so GraphQL (`/graphql`) and
    versioned REST (`/v2/users`) endpoints are recognised as API surfaces and prioritised too
    -- they were previously invisible to this ordering. Behaviour is a strict superset: every
    URL that matched `/api/` still classifies as an API surface. An OpenAPI/Swagger DOCUMENT
    is API-related but is documentation, not an injectable endpoint, so it is NOT hoisted
    above real endpoints (it stays in `rest`)."""
    from apps.api.scanner_engine.api_intel import KIND_OPENAPI_DOC, classify_api

    bases = _dedupe(
        [f.value.split("?", 1)[0] for f in prior_findings if f.asset_type == "url" and f.value]
    )
    candidates = [u for u in bases if not u.lower().endswith(_STATIC_EXT)]
    # An injectable API endpoint (not a doc) is highest priority.
    api = [u for u in candidates if (c := classify_api(u)).is_api and c.kind != KIND_OPENAPI_DOC]
    rest = [u for u in candidates if u not in api]
    return (api + rest)[:max_targets]
