"""Prompt 21 -- Adaptive Detection Engine (deterministic, evidence-driven next-step selection).

Pure/deterministic tests of select_adaptive_candidates. These attack the Prompt 21 invariants
directly: determinism, provenance, deduplication, coverage/auth/API/parameter awareness,
endpoint canonicalization, the candidate!=finding separation, scope, failed-upstream, and
bounded execution. False-positive cases A-G (§7) each have a dedicated test.
"""
from apps.api.scanner_engine.adaptive import (
    AdaptiveCandidate,
    select_adaptive_candidates,
)
from apps.api.scanner_engine.coverage import ToolRunOutcome
from apps.api.scanner_engine.tool_runners.base import CommonFinding

TT = "domain"
TV = "ex.com"


def _f(asset_type, value, **md):
    md.setdefault("in_scope", True)
    md.setdefault("host", "ex.com")
    return CommonFinding(asset_type=asset_type, value=value, metadata=md)


def _select(findings, outcomes=None, **kw):
    kw.setdefault("active_testing_allowed", True)
    kw.setdefault("max_tier", "active_safe")
    return select_adaptive_candidates(
        findings, outcomes or [], target_type=TT, target_value=TV, **kw
    )


# --- core evidence -> candidate rules -----------------------------------------------------

def test_param_endpoint_yields_dast_candidate_with_reasons():
    cands = _select([_f("url", "http://ex.com/s?q=1", source="katana", params=["q"])])
    assert len(cands) == 1
    c = cands[0]
    assert c.capability == "dast_fuzzing" and c.tool == "nuclei-dast"
    assert "discovered_parameter" in c.reasons


def test_paramless_endpoint_yields_parameter_discovery_candidate():
    cands = _select([_f("url", "http://ex.com/about", source="katana")])
    assert cands[0].capability == "parameter_discovery" and cands[0].tool == "arjun"


def test_http_service_yields_web_crawling_candidate():
    cands = _select([_f("http_service", "http://ex.com/", source="httpx")])
    assert cands[0].capability == "web_crawling" and cands[0].tool == "katana"


def test_subdomain_and_port_do_not_produce_adaptive_candidates():
    """The adaptive layer focuses on app-layer surfaces; early-pipeline asset types produce
    no fabricated candidate."""
    cands = _select([_f("subdomain", "a.ex.com"), _f("port", "ex.com:22", port=22)])
    assert cands == []


# --- INVARIANT 10: determinism -------------------------------------------------------------

def test_identical_state_yields_identical_ordered_candidates():
    findings = [
        _f("url", "http://ex.com/b?x=1", source="katana", params=["x"]),
        _f("http_service", "http://ex.com/", source="httpx"),
        _f("url", "http://ex.com/a", source="katana"),
    ]
    a = _select(findings)
    b = _select(findings)
    assert [(c.capability, c.target) for c in a] == [(c.capability, c.target) for c in b]
    # ordered by pipeline phase: web_crawling(45) < parameter_discovery(48) < dast_fuzzing(55)
    assert [c.capability for c in a] == ["web_crawling", "parameter_discovery", "dast_fuzzing"]


def test_ordering_is_stable_regardless_of_input_order():
    f1 = _f("url", "http://ex.com/z?p=1", source="katana", params=["p"])
    f2 = _f("http_service", "http://ex.com/", source="httpx")
    assert [c.capability for c in _select([f1, f2])] == [c.capability for c in _select([f2, f1])]


# --- INVARIANT 8: provenance ---------------------------------------------------------------

def test_every_candidate_carries_provenance():
    cands = _select([_f("url", "http://ex.com/api?id=1", source="katana", params=["id"],
                        is_api=True, raw_url="http://EX.com:80/api?id=1")])
    p = cands[0].provenance
    assert p["source"] == "katana" and p["asset_type"] == "url"
    assert p["raw_url"] == "http://EX.com:80/api?id=1"   # P16 provenance preserved
    assert p["params"] == ["id"]                          # P17 provenance preserved


def test_reason_trace_is_machine_checkable_and_deterministic():
    c = _select([_f("url", "http://ex.com/s?q=1", source="katana", params=["q"], is_api=True)])[0]
    assert c.reason_trace() == "dast_fuzzing eligible for http://ex.com/s?q=1: discovered_parameter+api_surface+incomplete_coverage"


# --- INVARIANT 9 + §7 Case F: canonicalization / dedup ------------------------------------

def test_equivalent_canonical_targets_are_deduplicated():
    """Case F: the same canonical endpoint discovered twice yields ONE candidate. (Endpoints
    are already canonicalized upstream by katana; the selector dedups by (capability, target).)"""
    findings = [
        _f("url", "http://ex.com/api/x", source="katana", is_api=True),
        _f("url", "http://ex.com/api/x", source="katana", is_api=True),  # duplicate canonical
    ]
    cands = _select(findings)
    assert len([c for c in cands if c.target == "http://ex.com/api/x"]) == 1


# --- §7 Case A: API-looking but unreachable ------------------------------------------------

def test_api_classification_influences_but_does_not_assert_reachability():
    """Case A: an API-classified URL becomes a candidate (a SIGNAL), never a verified API or a
    finding. is_api only adds a reason code; it never sets a finding or a verified state."""
    c = _select([_f("url", "http://ex.com/api/v2/users", source="katana", is_api=True, api_kind="rest")])[0]
    assert "api_surface" in c.reasons
    # It is a candidate for a DETECTION capability, not a finding or a reachability claim.
    assert isinstance(c, AdaptiveCandidate)
    assert c.capability in ("parameter_discovery", "dast_fuzzing")


# --- §7 Case B / INVARIANT 4+5: failed / partial upstream ---------------------------------

def test_failed_upstream_crawl_keeps_service_as_a_candidate_not_clean():
    """Case B / Invariant 4: the crawl (web_crawling) FAILED, so the live service is NOT
    covered -- it stays an eligible candidate, with the failure named in the reasons."""
    cands = _select(
        [_f("http_service", "http://ex.com/", source="httpx")],
        [ToolRunOutcome("katana", "failed")],
    )
    assert cands and cands[0].capability == "web_crawling"
    assert "attempted_failed_upstream" in cands[0].reasons


def test_partial_upstream_keeps_candidate_and_names_partial():
    """Invariant 5: a partial crawl is not full coverage -- still a candidate, reason=partial."""
    cands = _select(
        [_f("http_service", "http://ex.com/", source="httpx")],
        [ToolRunOutcome("katana", "partial")],
    )
    assert cands and "partial_upstream" in cands[0].reasons


def test_completed_upstream_removes_the_candidate():
    """The positive control: once web_crawling COMPLETED, the service is covered and no longer
    an eligible candidate (bounded -- we don't re-run covered work)."""
    cands = _select(
        [_f("http_service", "http://ex.com/", source="httpx")],
        [ToolRunOutcome("katana", "completed")],
    )
    assert cands == []


# --- §7 Case C / INVARIANT 3+8: no fabricated parameter target ----------------------------

def test_no_parameter_is_fabricated_from_malformed_evidence():
    """Case C: a url with NO param evidence yields a parameter-DISCOVERY candidate (to find
    params), never a dast candidate carrying an invented parameter. The selector only reads
    existing params metadata; it never synthesises one."""
    c = _select([_f("url", "http://ex.com/thing", source="katana")])[0]
    assert c.capability == "parameter_discovery"
    assert "params" not in c.provenance      # nothing fabricated
    assert "discovered_parameter" not in c.reasons


# --- §7 Case D / INVARIANT 6: 401/403 protected -------------------------------------------

def test_protected_endpoint_is_not_a_candidate_and_not_clean():
    """Case D / Invariant 6: an endpoint tagged protected (401/403) is requires_auth in the
    coverage model, so it produces NO adaptive candidate -- it is not clean, and we never
    invent credentials to test it."""
    cands = _select([_f("http_service", "http://ex.com/admin", source="httpx", auth_state="protected")])
    assert cands == []


def test_login_redirect_endpoint_is_not_a_candidate():
    cands = _select([_f("http_service", "http://ex.com/app", source="httpx", auth_state="login_redirect")])
    assert cands == []


# --- §7 Case E / INVARIANT: JS reference is candidate intelligence, not browser evidence ---

def test_js_referenced_endpoint_is_a_candidate_not_browser_executed():
    """Case E: a JS-derived endpoint (source=katana) is candidate INTELLIGENCE for a detection
    tool -- never a claim that a browser executed it or that a finding exists. Its capability
    is a detection step, and its provenance names the crawler, not browser execution."""
    c = _select([_f("url", "http://ex.com/spa/api?token=1", source="katana", params=["token"], is_api=True)])[0]
    assert c.provenance["source"] == "katana"       # crawler intelligence, not browser exec
    assert c.capability == "dast_fuzzing"            # a detection candidate, not a finding


# --- §7 Case G is orchestrator-level (verification) -- covered in the DB/integration test --


# --- INVARIANT 1: scope -------------------------------------------------------------------

def test_out_of_scope_surface_produces_no_candidate():
    """Invariant 1: an out-of-scope asset (in_scope=False) is never an adaptive target."""
    cands = _select([_f("url", "http://evil.com/api?x=1", source="katana", params=["x"],
                        in_scope=False, host="evil.com")])
    assert cands == []


def test_scope_reenforced_even_if_in_scope_flag_lies_about_a_foreign_host():
    """Defense in depth: the selector re-runs the SAME scope_guard check the orchestrator uses.
    A foreign host is rejected on the authoritative check, not merely the metadata flag."""
    # host not under the target domain; scope_guard.finding_in_scope rejects it by name.
    cands = _select([_f("url", "http://notex.example/x?y=1", source="katana", params=["y"],
                        host="notex.example")])
    assert cands == []


# --- capability gating: active-testing + safety tier + already-run ------------------------

def test_dast_requires_active_testing():
    """A DAST candidate needs active testing; without it the registry resolves no tool and no
    candidate is emitted (the gate is the registry's, re-applied here)."""
    cands = _select([_f("url", "http://ex.com/s?q=1", source="katana", params=["q"])],
                    active_testing_allowed=False)
    assert cands == []


def test_already_run_capability_is_not_re_proposed():
    """Bounded execution: if the tool for a capability already ran, the registry excludes it
    and the selector proposes no duplicate work."""
    cands = _select([_f("url", "http://ex.com/a", source="katana")],
                    already_run=frozenset({"arjun"}))
    assert cands == []


# --- malformed evidence is skipped, never crashes -----------------------------------------

def test_malformed_findings_are_skipped():
    findings = [_f("url", ""), _f("", "http://ex.com/x"), _f("url", "http://ex.com/real?p=1", params=["p"])]
    cands = _select(findings)
    assert [c.target for c in cands] == ["http://ex.com/real?p=1"]
