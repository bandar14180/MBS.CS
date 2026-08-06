"""Evidence-driven incremental attack/security graph (M4.3).

Deterministic construction ONLY. Every node and edge is DERIVED from validated
evidence -- recon assets (the tool findings), ingested vulnerabilities, the
deterministic ATT&CK catalog mappings, and confirmed access from the gated
exploitation phase. The LLM never writes to the graph; it only reasons over a
compact summary of it (fed into StateProjection). This preserves every existing
control -- the AI cannot invent hosts, findings, or reachability through the graph.

The graph models the chain the assessment actually evidences:

    Asset (host) --exposes--> Service --has_finding--> Finding --maps_to--> Technique
                                                          Asset --granted--> Access

Relationships are added ONLY when the evidence supports them (e.g. a Finding is
linked to the Service it was observed at, via the vulnerability's resolved asset).
Nothing is added merely because it is theoretically possible. Every node/edge
carries provenance: source, originating tool where known, first/last-seen
timestamps, a deterministic confidence, and the MITRE technique where applicable.

Persisted in EngagementState.attack_graph (JSONB) -- no migration. `update_graph`
is idempotent and incremental: re-running with the full accumulated evidence unions
by stable node/edge id, preserving each node's first-seen timestamp.

NOTE (scope): discovered `url`/parameter assets (katana/arjun) are intentionally NOT
modeled as nodes -- they can number in the hundreds and would bloat the graph without
changing the asset/service/finding/technique/access reasoning. This is a deliberate
limitation, not an oversight.
"""
from dataclasses import dataclass, field

NODE_ASSET = "asset"
NODE_SERVICE = "service"
NODE_FINDING = "finding"
NODE_TECHNIQUE = "technique"
NODE_ACCESS = "access"

# Asset types that represent a network service vs a host (from the tool runners).
_SERVICE_ASSET_TYPES = frozenset({"http_service", "service", "port"})
_HOST_ASSET_TYPES = frozenset({"subdomain", "host", "domain", "ip"})
# Bounded set of service attributes worth carrying onto the node (avoid raw blobs).
_SERVICE_ATTR_KEYS = ("port", "service", "product", "version", "scheme", "status_code", "webserver", "tech")

# Evidence-backed access-state classification (M4.4.4). Derived ONLY from a real
# ExploitResult.access_type -- never invented. The platform's curated modules confirm
# access/info exposure; privilege-escalation and lateral-movement states exist in this
# map but are emitted ONLY if a module ever produces that evidence (none do today), so
# the graph never fabricates a priv-esc/lateral claim.
_ACCESS_STATE = {
    "valid_credentials": "access_obtained",
    "rce_proof": "access_obtained",
    "info_access": "info_access",
    "privilege_escalation": "privilege_escalation",
    "lateral_movement": "lateral_movement",
}


def _access_state(access_type: str | None) -> str:
    return _ACCESS_STATE.get((access_type or "").strip().lower(), "access_obtained")


# Deterministic provenance confidences. These are NOT AI outputs and NOT a hardcoded
# attack path -- they reflect how directly the evidence supports the node/edge:
# directly observed facts are high; the curated ATT&CK mapping is approximate.
_CONF_ASSET = 0.9
_CONF_SERVICE = 0.9
_CONF_FINDING = 0.85
_CONF_TECHNIQUE = 0.7
_CONF_ACCESS = 0.95


@dataclass
class AssetEvidence:
    """A discovered asset (a tool CommonFinding), tagged with the tool that found it."""

    asset_type: str
    value: str
    tool: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class FindingEvidence:
    """An ingested vulnerability + its deterministic ATT&CK techniques. `service_value`
    is the value of the asset the finding was resolved to (vuln.asset_id -> asset),
    used to link Finding -> Service without inventing a location."""

    fingerprint: str
    title: str
    severity: str
    techniques: list[tuple] = field(default_factory=list)  # (tactic_id, technique_id, name, phase)
    service_value: str | None = None
    category: str | None = None
    tool: str | None = None


@dataclass
class AccessEvidence:
    """A confirmed access from the gated, deterministic exploitation phase."""

    target: str
    access_type: str | None
    module: str
    proof: str = ""


def _host_from_value(value: str | None) -> str | None:
    """Best-effort host from an asset value like 'http://h:3000/p', 'h:3000', 'h'."""
    if not value:
        return None
    v = str(value).strip()
    for scheme in ("http://", "https://"):
        if v.startswith(scheme):
            v = v[len(scheme):]
    v = v.split("/")[0]  # drop any path
    if ":" in v:
        head, _, tail = v.rpartition(":")
        if head and tail.isdigit():  # strip a numeric port, keep the host
            v = head
    return v or None


def _host_of(asset: AssetEvidence) -> str | None:
    md = asset.metadata or {}
    host = md.get("host") or md.get("ip")
    return str(host) if host else _host_from_value(asset.value)


def _service_attrs(metadata: dict | None) -> dict:
    md = metadata or {}
    return {k: md[k] for k in _SERVICE_ATTR_KEYS if md.get(k) is not None}


def _counts(nodes: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for n in nodes:
        out[n["type"]] = out.get(n["type"], 0) + 1
    return out


def build_graph(
    assets: list[AssetEvidence],
    findings: list[FindingEvidence] | None = None,
    access: list[AccessEvidence] | None = None,
    *,
    now: str,
) -> dict:
    """Construct a full graph from the given evidence (deterministic, pure). Malformed
    or incomplete evidence (empty value/fingerprint, bad technique tuple) is skipped,
    never guessed. Edges are only created between nodes that both exist."""
    findings = findings or []
    access = access or []
    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}

    def _node(node_id, ntype, label, *, source, confidence, tool=None, attributes=None):
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "type": ntype,
                "label": str(label)[:160],
                "provenance": {
                    "source": source,
                    "tool": tool,
                    "confidence": confidence,
                    "first_seen": now,
                    "last_seen": now,
                },
                "attributes": attributes or {},
            }
        return nodes[node_id]

    def _edge(src, tgt, rel, *, confidence):
        key = (src, tgt, rel)
        if key not in edges and src in nodes and tgt in nodes:
            edges[key] = {"source": src, "target": tgt, "rel": rel, "confidence": confidence, "first_seen": now}

    # 1) Services + the host assets they are exposed on.
    for a in assets:
        if not a.value:
            continue
        if a.asset_type in _SERVICE_ASSET_TYPES:
            sid = f"service:{a.value}"
            _node(
                sid, NODE_SERVICE, a.value, source="recon", confidence=_CONF_SERVICE, tool=a.tool,
                attributes={"asset_type": a.asset_type, **_service_attrs(a.metadata)},
            )
            host = _host_of(a)
            if host:
                hid = f"asset:{host}"
                _node(hid, NODE_ASSET, host, source="derived", confidence=_CONF_ASSET, tool=a.tool,
                      attributes={"kind": "host"})
                _edge(hid, sid, "exposes", confidence=_CONF_SERVICE)
        elif a.asset_type in _HOST_ASSET_TYPES:
            _node(f"asset:{a.value}", NODE_ASSET, a.value, source="recon", confidence=_CONF_ASSET, tool=a.tool,
                  attributes={"kind": a.asset_type})
        # url / unknown asset types are intentionally not modeled (see module docstring).

    # 2) Findings + their ATT&CK techniques.
    for f in findings:
        if not f.fingerprint:
            continue
        fid = f"finding:{f.fingerprint}"
        _node(fid, NODE_FINDING, f.title or f.fingerprint, source="detection", confidence=_CONF_FINDING,
              tool=f.tool, attributes={"severity": f.severity, "category": f.category})
        # Link to the exact service it was observed at, else the host asset -- never
        # to a node that doesn't exist (no invented reachability).
        if f.service_value:
            sid = f"service:{f.service_value}"
            if sid in nodes:
                _edge(sid, fid, "has_finding", confidence=_CONF_FINDING)
            else:
                host = _host_from_value(f.service_value)
                hid = f"asset:{host}" if host else None
                if hid and hid in nodes:
                    _edge(hid, fid, "has_finding", confidence=_CONF_FINDING)
        for tup in f.techniques:
            if not isinstance(tup, (list, tuple)) or len(tup) != 4:
                continue
            tactic_id, technique_id, technique_name, phase = tup
            if not technique_id:
                continue
            tid = f"technique:{technique_id}"
            _node(tid, NODE_TECHNIQUE, technique_name or technique_id, source="mitre_catalog",
                  confidence=_CONF_TECHNIQUE,
                  attributes={"technique_id": technique_id, "tactic_id": tactic_id, "kill_chain_phase": phase})
            _edge(fid, tid, "maps_to", confidence=_CONF_TECHNIQUE)

    # 3) Confirmed access (gated exploitation) -> the host it was granted on.
    for ac in access:
        if not ac.target:
            continue
        aid = f"access:{ac.target}:{ac.access_type or 'access'}"
        _node(aid, NODE_ACCESS, ac.access_type or "access", source="exploitation", confidence=_CONF_ACCESS,
              attributes={
                  "module": ac.module,
                  "proof": str(ac.proof)[:200],
                  "access_type": ac.access_type,
                  # Evidence-backed state (M4.4.4) -- derived from access_type, not invented.
                  "access_state": _access_state(ac.access_type),
              })
        host = _host_from_value(ac.target)
        hid = f"asset:{host}" if host else None
        if hid and hid in nodes:
            _edge(hid, aid, "granted", confidence=_CONF_ACCESS)

    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def merge_graph(existing: dict | None, fresh: dict, *, now: str) -> dict:
    """Union `fresh` into `existing` by stable id, preserving each node/edge's original
    first-seen timestamp and refreshing last-seen. Any non-graph keys already on
    `existing` (e.g. the M2 `confirmed_access` list) are preserved untouched."""
    existing = existing or {}
    prev_nodes = {n["id"]: n for n in existing.get("nodes", [])}
    for n in fresh["nodes"]:
        prev = prev_nodes.get(n["id"])
        if prev:
            n["provenance"]["first_seen"] = prev.get("provenance", {}).get("first_seen", n["provenance"]["first_seen"])
        n["provenance"]["last_seen"] = now

    prev_edges = {(e["source"], e["target"], e["rel"]): e for e in existing.get("edges", [])}
    for e in fresh["edges"]:
        prev = prev_edges.get((e["source"], e["target"], e["rel"]))
        if prev:
            e["first_seen"] = prev.get("first_seen", e["first_seen"])

    result = {
        "nodes": fresh["nodes"],
        "edges": fresh["edges"],
        "counts": _counts(fresh["nodes"]),
        "updated_at": now,
    }
    for k, v in existing.items():
        if k not in ("nodes", "edges", "counts", "updated_at"):
            result[k] = v
    return result


def update_graph(
    existing: dict | None,
    *,
    assets: list[AssetEvidence],
    findings: list[FindingEvidence] | None = None,
    access: list[AccessEvidence] | None = None,
    now: str,
) -> dict:
    """Incremental update: rebuild from the full accumulated evidence and merge onto
    the existing graph (idempotent; dedups by id, preserves first-seen)."""
    return merge_graph(existing, build_graph(assets, findings, access, now=now), now=now)
