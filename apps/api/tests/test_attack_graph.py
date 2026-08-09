"""Pure unit tests for the evidence-driven attack graph (M4.3). No DB/network.

The graph is built ONLY from validated evidence; nothing is invented. These cover
node/edge creation, provenance + confidence, incremental/dedup behavior, and safe
handling of malformed evidence."""
from apps.api.scanner_engine.attack_graph import (
    AccessEvidence,
    AssetEvidence,
    FindingEvidence,
    build_graph,
    update_graph,
)
from apps.api.scanner_engine.state_projection import summarize_attack_graph

NOW = "2026-08-05T00:00:00+00:00"
LATER = "2026-08-05T01:00:00+00:00"

# ATT&CK catalog tuple shape: (tactic_id, technique_id, technique_name, kill_chain_phase)
_T1595 = ("TA0043", "T1595", "Active Scanning", "reconnaissance")
_T1190 = ("TA0001", "T1190", "Exploit Public-Facing Application", "exploitation")


def _nodes_by_type(graph, ntype):
    return [n for n in graph["nodes"] if n["type"] == ntype]


def _edge(graph, rel):
    return [e for e in graph["edges"] if e["rel"] == rel]


# 1. Asset node creation from valid evidence.
def test_host_asset_from_subdomain():
    g = build_graph([AssetEvidence("subdomain", "api.example.com", tool="subfinder")], now=NOW)
    assets = _nodes_by_type(g, "asset")
    assert len(assets) == 1
    assert assets[0]["id"] == "asset:api.example.com"
    assert assets[0]["attributes"]["kind"] == "subdomain"


def test_service_and_derived_host_from_http_service():
    g = build_graph(
        [AssetEvidence("http_service", "http://10.0.0.1:3000", tool="httpx", metadata={"host": "10.0.0.1", "port": 3000})],
        now=NOW,
    )
    services = _nodes_by_type(g, "service")
    hosts = _nodes_by_type(g, "asset")
    assert services and services[0]["id"] == "service:http://10.0.0.1:3000"
    assert hosts and hosts[0]["id"] == "asset:10.0.0.1"  # host derived from the service


# 2. Service relationships (host --exposes--> service).
def test_host_exposes_service_edge():
    g = build_graph([AssetEvidence("service", "10.0.0.1:22", tool="nmap", metadata={"ip": "10.0.0.1"})], now=NOW)
    exposes = _edge(g, "exposes")
    assert len(exposes) == 1
    assert exposes[0]["source"] == "asset:10.0.0.1" and exposes[0]["target"] == "service:10.0.0.1:22"


# 3. Vulnerability/finding relationships (service --has_finding--> finding).
def test_service_has_finding_edge():
    assets = [AssetEvidence("http_service", "http://10.0.0.1:3000", tool="httpx", metadata={"host": "10.0.0.1"})]
    findings = [FindingEvidence("fp1", "Missing security headers", "low", service_value="http://10.0.0.1:3000")]
    g = build_graph(assets, findings, now=NOW)
    hf = _edge(g, "has_finding")
    assert len(hf) == 1
    assert hf[0]["source"] == "service:http://10.0.0.1:3000" and hf[0]["target"] == "finding:fp1"


def test_finding_falls_back_to_host_when_no_service_node():
    # No service node for the exact value, but the host is known -> link to the host,
    # never to a node that doesn't exist.
    assets = [AssetEvidence("service", "10.0.0.1:80", tool="nmap", metadata={"ip": "10.0.0.1"})]
    findings = [FindingEvidence("fp2", "Info leak", "medium", service_value="10.0.0.1:9999")]
    g = build_graph(assets, findings, now=NOW)
    hf = _edge(g, "has_finding")
    assert len(hf) == 1 and hf[0]["source"] == "asset:10.0.0.1"


# 4. MITRE technique relationships (finding --maps_to--> technique).
def test_finding_maps_to_techniques():
    findings = [FindingEvidence("fp3", "SQLi", "high", techniques=[_T1190], service_value=None)]
    g = build_graph([], findings, now=NOW)
    techs = _nodes_by_type(g, "technique")
    maps = _edge(g, "maps_to")
    assert techs and techs[0]["id"] == "technique:T1190"
    assert techs[0]["attributes"]["tactic_id"] == "TA0001"
    assert len(maps) == 1 and maps[0]["target"] == "technique:T1190"


# 5. Provenance and confidence.
def test_provenance_and_confidence():
    g = build_graph(
        [AssetEvidence("http_service", "http://h:80", tool="httpx", metadata={"host": "h"})],
        [FindingEvidence("fp4", "x", "low", techniques=[_T1595])],
        now=NOW,
    )
    svc = _nodes_by_type(g, "service")[0]
    assert svc["provenance"]["tool"] == "httpx"
    assert svc["provenance"]["source"] == "recon"
    assert svc["provenance"]["first_seen"] == NOW and svc["provenance"]["last_seen"] == NOW
    assert svc["provenance"]["confidence"] == 0.9
    tech = _nodes_by_type(g, "technique")[0]
    assert tech["provenance"]["confidence"] == 0.7  # curated mapping is approximate
    assert tech["provenance"]["source"] == "mitre_catalog"


# 6. Incremental updates + first-seen preservation.
def test_incremental_update_adds_nodes_and_preserves_first_seen():
    g1 = update_graph(None, assets=[AssetEvidence("subdomain", "a.example.com", tool="subfinder")], now=NOW)
    g2 = update_graph(
        g1,
        assets=[
            AssetEvidence("subdomain", "a.example.com", tool="subfinder"),  # unchanged
            AssetEvidence("http_service", "http://a.example.com:443", tool="httpx", metadata={"host": "a.example.com"}),
        ],
        now=LATER,
    )
    ids = {n["id"] for n in g2["nodes"]}
    assert "asset:a.example.com" in ids and "service:http://a.example.com:443" in ids
    a = next(n for n in g2["nodes"] if n["id"] == "asset:a.example.com")
    assert a["provenance"]["first_seen"] == NOW   # preserved from the first update
    assert a["provenance"]["last_seen"] == LATER  # refreshed


# 7. Duplicate-node/edge handling.
def test_duplicate_evidence_does_not_duplicate():
    dup = [
        AssetEvidence("service", "h:22", tool="nmap", metadata={"ip": "h"}),
        AssetEvidence("service", "h:22", tool="nmap", metadata={"ip": "h"}),
    ]
    g = build_graph(dup, now=NOW)
    assert len(_nodes_by_type(g, "service")) == 1
    assert len(_edge(g, "exposes")) == 1


# 8 & 11. No invented nodes / malformed evidence is skipped.
def test_url_assets_and_empty_values_are_not_nodes():
    g = build_graph(
        [
            AssetEvidence("url", "http://h/login", tool="katana"),   # url type -> not modeled
            AssetEvidence("service", "", tool="nmap"),               # empty value -> skipped
        ],
        now=NOW,
    )
    assert g["nodes"] == []


def test_malformed_finding_and_technique_are_skipped():
    g = build_graph(
        [],
        [
            FindingEvidence("", "no fingerprint", "low"),                          # skipped
            FindingEvidence("fp5", "bad techniques", "low", techniques=[("only", "three")]),  # bad tuple skipped
        ],
        now=NOW,
    )
    findings = _nodes_by_type(g, "finding")
    assert len(findings) == 1 and findings[0]["id"] == "finding:fp5"
    assert _nodes_by_type(g, "technique") == []  # malformed tuple produced no technique


def test_finding_with_unknown_service_and_no_host_has_no_edge():
    g = build_graph([], [FindingEvidence("fp6", "orphan", "low", service_value=None)], now=NOW)
    assert _nodes_by_type(g, "finding")  # the node still exists...
    assert _edge(g, "has_finding") == []  # ...but no invented relationship


# Access nodes (gated exploitation) link to the host, never invented.
def test_access_node_links_to_host():
    assets = [AssetEvidence("service", "10.0.0.1:3000", tool="nmap", metadata={"ip": "10.0.0.1"})]
    access = [AccessEvidence(target="10.0.0.1", access_type="valid_credentials", module="default_credentials", proof="ref")]
    g = build_graph(assets, [], access, now=NOW)
    acc = _nodes_by_type(g, "access")
    granted = _edge(g, "granted")
    assert acc and acc[0]["type"] == "access"
    assert granted and granted[0]["source"] == "asset:10.0.0.1"
    # M4.4.4: evidence-backed access_state derived from access_type; access_type kept.
    assert acc[0]["attributes"]["access_state"] == "access_obtained"
    assert acc[0]["attributes"]["access_type"] == "valid_credentials"
    assert acc[0]["provenance"]["source"] == "exploitation"


def test_access_state_derived_from_access_type_only():
    # Each state comes ONLY from the actual ExploitResult.access_type -- never invented.
    cases = {
        "rce_proof": "access_obtained",
        "valid_credentials": "access_obtained",
        "info_access": "info_access",
        None: "access_obtained",           # unknown/None -> generic access, not priv-esc/lateral
        "weird_unknown": "access_obtained",
    }
    for access_type, expected_state in cases.items():
        g = build_graph([], [], [AccessEvidence(target="h", access_type=access_type, module="m", proof="p")], now=NOW)
        acc = _nodes_by_type(g, "access")[0]
        assert acc["attributes"]["access_state"] == expected_state
    # Crucially, current evidence NEVER yields a privilege_escalation / lateral_movement
    # state (no module produces that evidence) -- the graph does not fabricate it.
    produced_states = set()
    for at in ("rce_proof", "valid_credentials", "info_access", None):
        g = build_graph([], [], [AccessEvidence(target="h", access_type=at, module="m", proof="p")], now=NOW)
        produced_states.add(_nodes_by_type(g, "access")[0]["attributes"]["access_state"])
    assert "privilege_escalation" not in produced_states and "lateral_movement" not in produced_states


def test_confirmed_access_key_preserved_across_update():
    existing = {"nodes": [], "edges": [], "confirmed_access": [{"target": "h", "access_type": "x"}]}
    g = update_graph(existing, assets=[AssetEvidence("subdomain", "h", tool="subfinder")], now=NOW)
    assert g["confirmed_access"] == [{"target": "h", "access_type": "x"}]  # non-graph key kept


# 9. Graph summary generation.
def test_summary_empty():
    assert summarize_attack_graph({}) == "(empty)"
    assert summarize_attack_graph({"nodes": []}) == "(empty)"


def test_summary_includes_counts_paths_and_access():
    assets = [AssetEvidence("http_service", "http://h:3000", tool="httpx", metadata={"host": "h"})]
    findings = [FindingEvidence("fp7", "Missing headers", "high", techniques=[_T1595], service_value="http://h:3000")]
    access = [AccessEvidence(target="h", access_type="info_access", module="known_cve", proof="p")]
    g = build_graph(assets, findings, access, now=NOW)
    s = summarize_attack_graph(g)
    assert "finding" in s and "technique" in s
    assert "http://h:3000 -> Missing headers -> T1595" in s
    assert "Confirmed access: info_access" in s
