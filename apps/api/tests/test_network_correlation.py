"""Network discovery correlation: domain -> IP -> port -> service -> technology (Prompt 27).

The seven network tools already emit a correlatable chain through the EXISTING asset model,
each carrying the relationship keys in metadata:

    subfinder/amass -> subdomain
    dnsx            -> subdomain + a_records   (subdomain -> IP)
    naabu           -> port     + host/ip/port (IP -> port)
    nmap            -> service  + ip/port/service/product/version
    httpx/whatweb   -> http_service + tech     (service -> web asset + technology)

THE GAP THIS CLOSES. httpx and whatweb BOTH emit `asset_type="http_service"` for the same
URL and both write `tech` -- httpx from its own fingerprinting, whatweb from its plugin set.
Because assets are keyed on (target_id, asset_type, value), those are the SAME row, and the
old wholesale `metadata=<incoming>` replacement meant whichever tool ran last destroyed the
other's technology list, its title, its webserver and its auth_state. `tech` feeds
attack_graph's service attributes, so the loss propagated beyond the asset itself.

What is pinned here is that correlation is non-destructive: relationship keys survive,
conflicting observations stay traceable, and nothing in discovery becomes vulnerability
evidence.
"""

from apps.api.modules.assets.service import OBSERVATIONS_KEY, merge_asset_metadata


def _obs(tool: str, run: str) -> dict:
    return {
        "discovered_by_tool": tool,
        "discovered_by_tool_version": "1.0.0",
        "discovered_in_tool_run": run,
        "in_scope": True,
    }


# --- A. The relationship chain survives correlation ---------------------------------------------

def test_dnsx_ip_mapping_survives_a_later_observation():
    """subdomain -> IP. The a_records link must not be erased by a later tool."""
    first = merge_asset_metadata(None, {**_obs("dnsx", "r1"), "a_records": ["93.184.216.34"]})
    merged = merge_asset_metadata(first, _obs("httpx", "r2"))
    assert merged["a_records"] == ["93.184.216.34"]


def test_naabu_port_mapping_survives_nmap_enrichment():
    """IP -> port, then nmap adds service/product/version for that same port."""
    naabu = merge_asset_metadata(
        None, {**_obs("naabu", "r1"), "host": "x.test", "ip": "10.0.0.1", "port": 8080,
               "protocol": "tcp"},
    )
    merged = merge_asset_metadata(
        naabu,
        {**_obs("nmap", "r2"), "ip": "10.0.0.1", "port": 8080, "service": "http",
         "product": "nginx", "version": "1.25.3"},
    )
    # The naabu-only key is preserved, and nmap's enrichment is present.
    assert merged["host"] == "x.test"
    assert merged["protocol"] == "tcp"
    assert merged["service"] == "http"
    assert merged["product"] == "nginx"
    assert [o["discovered_by_tool"] for o in merged[OBSERVATIONS_KEY]] == ["naabu", "nmap"]


def test_the_full_chain_is_reconstructable_after_repeated_correlation():
    md: dict = {}
    md = merge_asset_metadata(md, {**_obs("dnsx", "r1"), "a_records": ["10.0.0.1"]})
    md = merge_asset_metadata(md, {**_obs("naabu", "r2"), "ip": "10.0.0.1", "port": 443})
    md = merge_asset_metadata(md, {**_obs("nmap", "r3"), "service": "https"})
    md = merge_asset_metadata(md, {**_obs("whatweb", "r4"), "tech": ["nginx"]})
    assert md["a_records"] == ["10.0.0.1"]
    assert md["port"] == 443
    assert md["service"] == "https"
    assert md["tech"] == ["nginx"]
    assert len(md[OBSERVATIONS_KEY]) == 4


# --- B. Technology correlation (the httpx/whatweb collision) ------------------------------------

def test_two_tools_technology_observations_are_unioned_not_overwritten():
    """The concrete defect: whatweb used to wipe httpx's entire tech list on the same URL."""
    httpx = merge_asset_metadata(None, {**_obs("httpx", "r1"), "tech": ["nginx", "PHP"]})
    merged = merge_asset_metadata(httpx, {**_obs("whatweb", "r2"), "tech": ["WordPress"]})
    assert merged["tech"] == ["nginx", "PHP", "WordPress"]


def test_overlapping_technologies_are_not_duplicated():
    httpx = merge_asset_metadata(None, {**_obs("httpx", "r1"), "tech": ["nginx"]})
    merged = merge_asset_metadata(httpx, {**_obs("whatweb", "r2"), "tech": ["nginx", "PHP"]})
    assert merged["tech"] == ["nginx", "PHP"]


def test_httpx_scalar_context_is_not_destroyed_by_whatweb():
    """title/webserver/auth_state are httpx-only keys whatweb never reports."""
    httpx = merge_asset_metadata(
        None,
        {**_obs("httpx", "r1"), "title": "Home", "webserver": "nginx",
         "auth_state": "unauthenticated_ok", "status_code": 200},
    )
    merged = merge_asset_metadata(
        httpx, {**_obs("whatweb", "r2"), "tech": ["WordPress"], "status_code": 200}
    )
    assert merged["title"] == "Home"
    assert merged["webserver"] == "nginx"
    assert merged["auth_state"] == "unauthenticated_ok"


def test_a_single_string_technology_is_handled():
    merged = merge_asset_metadata(
        {**_obs("httpx", "r1"), "tech": "nginx"}, {**_obs("whatweb", "r2"), "tech": ["PHP"]}
    )
    assert merged["tech"] == ["nginx", "PHP"]


def test_a_malformed_technology_value_does_not_raise_or_invent():
    merged = merge_asset_metadata(
        {**_obs("httpx", "r1"), "tech": {"bad": 1}}, {**_obs("whatweb", "r2"), "tech": ["PHP"]}
    )
    assert merged["tech"] == ["PHP"]


def test_a_null_technology_list_does_not_erase_the_other_tools():
    """httpx writes `tech: None` when it fingerprinted nothing -- that must not wipe whatweb."""
    first = merge_asset_metadata(None, {**_obs("whatweb", "r1"), "tech": ["WordPress"]})
    merged = merge_asset_metadata(first, {**_obs("httpx", "r2"), "tech": None})
    assert merged["tech"] == ["WordPress"]


def test_only_tech_is_unioned_not_point_in_time_scalars():
    """A status_code is a point-in-time reading, not a set: unioning it would invent a state
    the service was never in. The newest supersedes, and the old stays in observations."""
    first = merge_asset_metadata(None, {**_obs("httpx", "r1"), "status_code": 200})
    merged = merge_asset_metadata(first, {**_obs("httpx", "r2"), "status_code": 500})
    assert merged["status_code"] == 500
    assert len(merged[OBSERVATIONS_KEY]) == 2


# --- C. Conflicting network observations stay traceable -------------------------------------------

def test_a_changed_ip_supersedes_but_both_runs_remain_traceable():
    """DNS legitimately changes between scans -- the conflict must be visible, not silent."""
    first = merge_asset_metadata(None, {**_obs("dnsx", "r1"), "a_records": ["10.0.0.1"]})
    merged = merge_asset_metadata(first, {**_obs("dnsx", "r2"), "a_records": ["10.0.0.2"]})
    assert merged["a_records"] == ["10.0.0.2"]
    assert [o["discovered_in_tool_run"] for o in merged[OBSERVATIONS_KEY]] == ["r1", "r2"]


def test_subfinder_provider_provenance_is_not_lost_to_a_later_tool():
    """subfinder's `source` is the upstream OSINT provider, a different concept from the
    discovering tool -- a later dnsx observation must not overwrite it."""
    first = merge_asset_metadata(None, {**_obs("subfinder", "r1"), "source": "crtsh"})
    merged = merge_asset_metadata(first, _obs("dnsx", "r2"))
    assert merged["source"] == "crtsh"
    assert merged["discovered_by_tool"] == "dnsx"


def test_amass_and_subfinder_both_finding_one_subdomain_are_two_observations():
    first = merge_asset_metadata(None, {**_obs("subfinder", "r1"), "source": "crtsh"})
    merged = merge_asset_metadata(first, {**_obs("amass", "r2"), "source": "amass"})
    assert [o["discovered_by_tool"] for o in merged[OBSERVATIONS_KEY]] == ["subfinder", "amass"]


# --- D. Discovery is never vulnerability evidence --------------------------------------------------

def test_network_correlation_produces_no_verification_or_severity():
    """A port being open, a service being fingerprinted and a technology being observed are
    OBSERVED facts. None of them is a vulnerability, and correlation must not invent one."""
    md: dict = {}
    md = merge_asset_metadata(md, {**_obs("naabu", "r1"), "port": 22})
    md = merge_asset_metadata(md, {**_obs("nmap", "r2"), "service": "ssh", "product": "OpenSSH"})
    md = merge_asset_metadata(md, {**_obs("whatweb", "r3"), "tech": ["OpenSSH"]})
    for banned in ("verified", "verification_status", "severity", "cve", "cwe",
                   "vulnerability", "exploit", "confidence"):
        assert banned not in md
        for observation in md[OBSERVATIONS_KEY]:
            assert banned not in observation


def test_an_out_of_scope_network_observation_is_recorded_not_silently_dropped():
    merged = merge_asset_metadata(
        None, {**_obs("naabu", "r1"), "in_scope": False, "port": 8080}
    )
    assert merged[OBSERVATIONS_KEY][0]["in_scope"] is False
