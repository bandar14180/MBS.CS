"""Shared web-target selection for the HTTP-layer tools (nuclei, katana,
nuclei-dast).

The recon pipeline confirms live HTTP services with httpx, but httpx only probes
default ports (80/443) on the bare target -- so a web app on a non-standard port
(e.g. :3300) yields no `http_service` finding. These helpers give the later
HTTP tools the *best available* set of URLs to work on, degrading gracefully:

    httpx-confirmed services  ->  discovered ports (naabu/nmap)  ->  bare host

Keeping this in one place means nuclei, the crawler, and the DAST runner all
target the exact same surface (no tool silently scanning a different thing)."""
from apps.api.scanner_engine.tool_runners._net import resolve_scan_host
from apps.api.scanner_engine.tool_runners.base import CommonFinding

# Each discovered open port becomes two candidate URLs (http + https); bound the
# fan-out so a wide top-ports sweep can't explode the target list.
DEFAULT_MAX_ENDPOINTS = 50


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    return [i for i in items if not (i in seen or seen.add(i))]


def http_service_urls(prior_findings: list[CommonFinding]) -> list[str]:
    """URLs of the HTTP services httpx confirmed (deduped; [] if none)."""
    return _dedupe([f.value for f in prior_findings if f.asset_type == "http_service" and f.value])


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
    try:
        ip = resolve_scan_host(target_value)
    except Exception:
        ip = target_value
    return [f"http://{ip}", f"https://{ip}"]


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
    of every non-static URL, `/api/` paths first (the JSON API is where the
    injectable params usually hide). We strip the query and dedupe by path --
    crucial because the crawler emits API endpoints WITH a trailing `?` (e.g.
    `/api/products?`), and those are exactly the paths whose real parameter names
    we need arjun to discover. Bounded because arjun is request-heavy per URL."""
    bases = _dedupe(
        [f.value.split("?", 1)[0] for f in prior_findings if f.asset_type == "url" and f.value]
    )
    candidates = [u for u in bases if not u.lower().endswith(_STATIC_EXT)]
    api = [u for u in candidates if "/api/" in u]
    rest = [u for u in candidates if "/api/" not in u]
    return (api + rest)[:max_targets]
