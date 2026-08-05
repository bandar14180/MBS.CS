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
    """URLs a crawler (katana) discovered, parameterised ones first -- those are
    what DAST fuzzing actually has something to inject into."""
    urls = _dedupe([f.value for f in prior_findings if f.asset_type == "url" and f.value])
    with_params = [u for u in urls if "?" in u]
    return with_params + [u for u in urls if u not in with_params]
