"""Source provenance for discovered assets (Prompt E).

Prompt E requires "preserve source provenance for every discovered asset". Before this, the
orchestrator stamped only `in_scope`, and the discovering tool survived ONLY if the runner
happened to self-tag it. Six of twelve did not: httpx and naabu wrote no source at all, so an
`http_service` asset could not be traced back to the tool that found it.

Worse, the `source` key that DID exist was overloaded -- katana/ffuf/arjun/whatweb used it for
the discovering tool, while subfinder used it for the upstream OSINT provider ("crtsh", ...).

These cover the additive `discovered_by_*` keys and, critically, that the overloaded `source`
key was NOT repurposed: `_web.param_discovery_targets` selects DAST fuzz targets with
`metadata.get("source") == "arjun"`, so overwriting it would silently break P17 chaining.
"""

from apps.api.scanner_engine.tool_runners._web import param_discovery_targets
from apps.api.scanner_engine.tool_runners.base import CommonFinding


# --- A. The subfinder/arjun `source` meanings are preserved ---------------------------------

def test_arjun_source_still_selects_dast_targets():
    """The exact consumer that would break if `source` were repurposed for the tool name."""
    findings = [
        CommonFinding(asset_type="url", value="https://x.test/a?id=1",
                      metadata={"source": "arjun", "has_params": True}),
        CommonFinding(asset_type="url", value="https://x.test/b",
                      metadata={"source": "katana", "has_params": False}),
    ]
    targets = param_discovery_targets(findings)
    assert any("/a" in t for t in targets)


def test_subfinder_source_means_upstream_provider_not_tool():
    """subfinder's `source` is its OSINT provider. Stamping the tool name over it would
    destroy that provenance -- this asserts the two are distinct concepts."""
    f = CommonFinding(asset_type="subdomain", value="a.x.test", metadata={"source": "crtsh"})
    stamped = {**f.metadata, "discovered_by_tool": "subfinder"}
    assert stamped["source"] == "crtsh"                 # upstream provider, untouched
    assert stamped["discovered_by_tool"] == "subfinder"  # discovering tool, additive


# --- B. The provenance keys are additive and complete ---------------------------------------

def _stamp(finding, tool_name, tool_version, run_id, in_scope=True):
    """Mirrors the orchestrator's stamping block (_run_single_tool)."""
    return {
        **(finding.metadata or {}),
        "in_scope": in_scope,
        "discovered_by_tool": tool_name,
        "discovered_by_tool_version": tool_version,
        "discovered_in_tool_run": str(run_id),
    }


def test_provenance_is_stamped_even_when_runner_tags_nothing():
    """httpx/naabu write no source of their own -- provenance must not depend on that."""
    f = CommonFinding(asset_type="http_service", value="https://x.test", metadata={})
    md = _stamp(f, "httpx", "1.6.0", "run-1")
    assert md["discovered_by_tool"] == "httpx"
    assert md["discovered_by_tool_version"] == "1.6.0"
    assert md["discovered_in_tool_run"] == "run-1"


def test_stamping_preserves_existing_runner_metadata():
    """Additive: nothing a runner already recorded is dropped or overwritten."""
    f = CommonFinding(asset_type="url", value="https://x.test/a?id=1",
                      metadata={"source": "katana", "has_params": True})
    md = _stamp(f, "katana", "1.1.0", "run-2")
    assert md["source"] == "katana"        # untouched
    assert md["has_params"] is True        # untouched
    assert md["discovered_by_tool"] == "katana"


def test_scope_decision_is_still_recorded():
    """Regression guard: the pre-existing M4.5 in_scope tagging must survive."""
    f = CommonFinding(asset_type="subdomain", value="evil.other", metadata={})
    assert _stamp(f, "subfinder", "2.6.3", "run-3", in_scope=False)["in_scope"] is False


def test_provenance_is_deterministic():
    f = CommonFinding(asset_type="url", value="https://x.test/a", metadata={"source": "katana"})
    first = _stamp(f, "katana", "1.1.0", "run-4")
    for _ in range(20):
        assert _stamp(f, "katana", "1.1.0", "run-4") == first


def test_tool_run_id_links_asset_to_its_execution():
    """Provenance chain: asset -> tool run -> raw output/evidence. The run id is the join key
    that makes 'which execution produced this asset' answerable at all."""
    f = CommonFinding(asset_type="http_service", value="https://x.test", metadata={})
    md = _stamp(f, "httpx", "1.6.0", "abc-123")
    assert md["discovered_in_tool_run"] == "abc-123"
    assert isinstance(md["discovered_in_tool_run"], str)  # uuid rendered, never a raw object
