from apps.api.modules.compliance.catalog import CWE_CONTROL_MAP, controls_for_category, framework_name
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


def test_compliance_covers_iso27001_and_pci_dss() -> None:
    # The landing page advertises OWASP + NIST + ISO 27001 + PCI DSS, so the
    # engine must actually map to all four. XSS is a good representative.
    frameworks = {f for f, _, _ in controls_for_category("cwe-79")}
    assert {"owasp", "nist", "iso27001", "pci_dss"}.issubset(frameworks)


def test_iso_and_pci_have_broad_coverage() -> None:
    # ISO 27001 and PCI DSS should not be token single-CWE mappings.
    iso = sum(1 for controls in CWE_CONTROL_MAP.values() for f, _, _ in controls if f == "iso27001")
    pci = sum(1 for controls in CWE_CONTROL_MAP.values() for f, _, _ in controls if f == "pci_dss")
    assert iso >= 10
    assert pci >= 10


def test_every_control_is_well_formed() -> None:
    # No blank framework/control id/description slipped into the curated table.
    for cwe, controls in CWE_CONTROL_MAP.items():
        for f, cid, desc in controls:
            assert f and cid and desc, f"blank control in {cwe}"


def test_framework_name_humanizes() -> None:
    assert framework_name("iso27001") == "ISO/IEC 27001"
    assert framework_name("pci_dss") == "PCI DSS"
    assert framework_name("unknown_x") == "unknown_x"  # falls back to the key
