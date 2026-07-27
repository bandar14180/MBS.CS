from apps.api.modules.compliance.catalog import controls_for_category
from apps.api.modules.risk.service import compute_risk


# --- Risk formula (pure) ---

def test_risk_weights_by_criticality() -> None:
    assert compute_risk(5.0, "low").final_risk_score == 2.5
    assert compute_risk(5.0, "medium").final_risk_score == 5.0
    assert compute_risk(5.0, "high").final_risk_score == 7.5
    assert compute_risk(5.0, "critical").final_risk_score == 10.0


def test_risk_caps_at_ten() -> None:
    r = compute_risk(7.5, "high")  # 7.5 * 1.5 = 11.25
    assert r.final_risk_score == 10.0
    assert "capped" in r.rationale


def test_risk_no_cvss_is_none() -> None:
    r = compute_risk(None, "high")
    assert r.final_risk_score is None
    assert r.business_impact_score is None
    assert r.asset_criticality_weight == 1.5


def test_risk_unknown_criticality_defaults_weight_one() -> None:
    r = compute_risk(6.0, "bogus")
    assert r.asset_criticality_weight == 1.0
    assert r.final_risk_score == 6.0


# --- Compliance catalog (pure) ---

def test_compliance_maps_known_cwe() -> None:
    controls = controls_for_category("cwe-693")
    frameworks = {f for f, _, _ in controls}
    assert "owasp" in frameworks
    assert ("owasp", "A05:2021", "Security Misconfiguration") in controls


def test_compliance_is_case_insensitive() -> None:
    assert controls_for_category("CWE-89") == controls_for_category("cwe-89")
    assert any(f == "owasp" and cid == "A03:2021" for f, cid, _ in controls_for_category("CWE-89"))


def test_compliance_unknown_or_missing_returns_empty() -> None:
    assert controls_for_category(None) == []
    assert controls_for_category("") == []
    assert controls_for_category("cwe-99999") == []
