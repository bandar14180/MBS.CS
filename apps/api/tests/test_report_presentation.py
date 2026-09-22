"""P2 -- report PRESENTATION hardening: Top Risks ordering, affected locations, evidence
linkage, and metadata.

Everything asserted here is presentation. The load-bearing tests are the INVARIANTS at the
bottom: none of these changes may move a CVSS, a final_risk_score, a security score, a
classification, or a verification/confidence value. If a presentation change ever leaks into
assessment, those fail.
"""

import uuid

from apps.api.modules.reports.data import VulnRow
from apps.api.modules.reports.render import (
    _evidence_type_label,
    _finding_groups,
    _group_locations_by_host,
    _location_host,
    _technical_metadata_rows,
    _top_risk_groups,
)
from apps.api.modules.reports.scoring import compute_security_score
from apps.api.modules.reports.verification import classify_verification_row


def _row(
    template_id="tpl-a",
    title="Finding A",
    severity="high",
    status="open",
    cvss=7.5,
    risk=7.5,
    matched_at="https://example.com/a",
    evidence=(),
    evidence_items=(),
    shots=(),
    category="cwe-79",
):
    return VulnRow(
        id=uuid.uuid4(),
        title=title,
        severity=severity,
        status=status,
        category=category,
        cvss_score=cvss,
        cvss_vector=None,
        final_risk_score=risk,
        risk_rationale=None,
        compliance=[],
        evidence_uris=list(evidence),
        evidence_items=list(evidence_items),
        screenshots=list(shots),
        template_id=template_id,
        matcher_name="m1",
        matched_at=matched_at,
    )


# ============================ P2-1: Top Risks ordering ====================================

def test_higher_risk_sorts_before_lower_risk() -> None:
    rows = [
        _row(template_id="low", title="Low", risk=2.0, cvss=2.0, severity="low"),
        _row(template_id="high", title="High", risk=9.5, cvss=9.5, severity="critical"),
        _row(template_id="mid", title="Mid", risk=5.0, cvss=5.0, severity="medium"),
    ]
    titles = [g["title"] for g in _top_risk_groups(rows)]
    assert titles == ["High", "Mid", "Low"]


def test_equal_risk_groups_have_deterministic_order() -> None:
    """Two DIFFERENT templates sharing every ranked value AND the same title. Before the
    issue_key tie-break these fell back on dict-insertion (i.e. DB row) order."""
    rows = [
        _row(template_id="tpl-z", title="Same Title", risk=5.0, cvss=5.0),
        _row(template_id="tpl-a", title="Same Title", risk=5.0, cvss=5.0),
    ]
    keys = [g["issue_key"] for g in _top_risk_groups(rows)]
    assert keys == ["template:tpl-a", "template:tpl-z"]  # by unique key, ascending


def test_repeated_rendering_is_identical() -> None:
    """Same input -> byte-identical ordering, every time."""
    rows = [
        _row(template_id=f"tpl-{i}", title="Tied", risk=5.0, cvss=5.0)
        for i in range(8)
    ]
    first = [g["issue_key"] for g in _top_risk_groups(rows)]
    for _ in range(5):
        assert [g["issue_key"] for g in _top_risk_groups(rows)] == first


def test_input_order_does_not_change_output_order() -> None:
    """Reversing the input must not reorder tied groups -- the proof the order is TOTAL."""
    rows = [_row(template_id=f"tpl-{i}", title="Tied", risk=5.0, cvss=5.0) for i in range(6)]
    forward = [g["issue_key"] for g in _top_risk_groups(rows)]
    backward = [g["issue_key"] for g in _top_risk_groups(list(reversed(rows)))]
    assert forward == backward


def test_unrelated_findings_do_not_reorder_existing_tied_entries() -> None:
    base = [_row(template_id=f"tie-{i}", title="Tied", risk=5.0, cvss=5.0) for i in range(4)]
    before = [g["issue_key"] for g in _top_risk_groups(base)]
    extra = base + [
        _row(template_id="unrelated-hi", title="Hi", risk=9.9, cvss=9.9, severity="critical"),
        _row(template_id="unrelated-lo", title="Lo", risk=0.5, cvss=0.5, severity="low"),
    ]
    after = [g["issue_key"] for g in _top_risk_groups(extra) if g["issue_key"].startswith("template:tie-")]
    assert after == before


def test_unscored_groups_rank_below_scored_but_still_appear() -> None:
    rows = [
        _row(template_id="unscored", title="Unscored", risk=None, cvss=None, severity="critical"),
        _row(template_id="scored", title="Scored", risk=1.0, cvss=1.0, severity="low"),
    ]
    groups = _top_risk_groups(rows)
    assert [g["title"] for g in groups] == ["Scored", "Unscored"]
    assert groups[1]["max_risk"] is None  # never coerced to 0.0


# ============================ P2-2: Affected locations ====================================

def test_duplicate_locations_are_deduplicated() -> None:
    rows = [_row(matched_at="https://example.com/same") for _ in range(4)]
    g = _finding_groups(rows)[0]
    assert g["matched_ats"] == ["https://example.com/same"]
    assert g["occurrence_count"] == 4  # breadth is not lost, only the repetition


def test_distinct_locations_remain_distinct() -> None:
    rows = [
        _row(matched_at="https://example.com/a"),
        _row(matched_at="https://example.com/b"),
        _row(matched_at="https://other.com/a"),
    ]
    g = _finding_groups(rows)[0]
    assert len(g["matched_ats"]) == 3


def test_location_ordering_is_deterministic() -> None:
    urls = ["https://c.com/3", "https://a.com/1", "https://b.com/2"]
    g1 = _finding_groups([_row(matched_at=u) for u in urls])[0]
    g2 = _finding_groups([_row(matched_at=u) for u in reversed(urls)])[0]
    assert g1["matched_ats"] == g2["matched_ats"] == sorted(urls)


def test_host_grouping_preserves_every_location_exactly_once() -> None:
    locs = ["https://a.com/x", "https://a.com/y", "https://b.com:8443/z"]
    grouped = _group_locations_by_host(locs)
    flattened = [loc for _, paths in grouped for loc in paths]
    assert sorted(flattened) == sorted(locs)  # nothing hidden, nothing duplicated
    assert len(flattened) == len(locs)


def test_host_grouping_keeps_port_distinction() -> None:
    """example.com:8443 is a different service from example.com:443 -- must not collapse."""
    grouped = dict(_group_locations_by_host(
        ["https://e.com:8443/a", "https://e.com:443/b", "https://e.com/c"]
    ))
    assert "e.com:8443" in grouped
    assert "e.com:443" in grouped
    assert "e.com" in grouped


def test_location_host_handles_malformed_and_empty_safely() -> None:
    assert _location_host("") == ""
    assert _location_host(None) == ""
    assert _location_host("not a url") == "not a url"
    assert _location_host("https://user:pw@h.com/p") == "h.com"
    assert _location_host("h.com/p?q=1#f") == "h.com"


def test_missing_locations_render_safely() -> None:
    g = _finding_groups([_row(matched_at=None)])[0]
    assert g["matched_ats"] == []
    assert g["unlocated_count"] == 1  # counted, not silently dropped


def test_grouping_does_not_mutate_input_rows() -> None:
    rows = [_row(matched_at="https://example.com/a"), _row(matched_at="https://example.com/b")]
    snapshot = [(r.matched_at, r.cvss_score, r.final_risk_score, r.severity) for r in rows]
    _finding_groups(rows)
    _top_risk_groups(rows)
    assert [(r.matched_at, r.cvss_score, r.final_risk_score, r.severity) for r in rows] == snapshot


# ============================ P2-3: Evidence presentation =================================

def test_log_evidence_is_typed_and_associated() -> None:
    g = _finding_groups([
        _row(evidence=["s3://e/raw.txt"], evidence_items=[("log_excerpt", "s3://e/raw.txt")])
    ])[0]
    assert g["evidence_items"] == [("log_excerpt", "s3://e/raw.txt")]
    assert _evidence_type_label("log_excerpt") == "Raw tool output"


def test_screenshot_evidence_remains_present_and_associated() -> None:
    g = _finding_groups([_row(shots=[("s3://e/shot.png", "abc123")])])[0]
    assert g["screenshots"] == [("s3://e/shot.png", "abc123")]


def test_multiple_evidence_types_render_distinctly() -> None:
    g = _finding_groups([
        _row(
            evidence=["s3://e/a.txt", "s3://e/b.har"],
            evidence_items=[("log_excerpt", "s3://e/a.txt"), ("http_response", "s3://e/b.har")],
            shots=[("s3://e/s.png", "cs1")],
        )
    ])[0]
    labels = {_evidence_type_label(t) for t, _ in g["evidence_items"]}
    assert labels == {"Raw tool output", "HTTP response"}
    assert len(g["screenshots"]) == 1


def test_evidence_uris_are_preserved_verbatim() -> None:
    uri = "s3://mbs-evidence/tool-runs/4aec2b77-dd8c-48f4-9b39-9101100685ec/raw-output.txt"
    g = _finding_groups([_row(evidence=[uri], evidence_items=[("log_excerpt", uri)])])[0]
    assert g["evidence_items"][0][1] == uri  # reference intact for retrieval


def test_evidence_is_deduplicated_but_distinct_artifacts_kept() -> None:
    g = _finding_groups([
        _row(matched_at="https://e.com/1", evidence_items=[("log_excerpt", "s3://e/same.txt")]),
        _row(matched_at="https://e.com/2", evidence_items=[("log_excerpt", "s3://e/same.txt")]),
        _row(matched_at="https://e.com/3", evidence_items=[("log_excerpt", "s3://e/other.txt")]),
    ])[0]
    assert len(g["evidence_items"]) == 2


def test_missing_evidence_renders_safely() -> None:
    g = _finding_groups([_row()])[0]
    assert g["evidence_items"] == []
    assert g["evidence_uris"] == []


def test_unknown_evidence_type_is_passed_through_not_invented() -> None:
    assert _evidence_type_label("some_new_type") == "Some new type"
    assert _evidence_type_label(None) == "Evidence"
    assert _evidence_type_label("") == "Evidence"


def test_rows_without_typed_evidence_still_expose_untyped_uris() -> None:
    """Backward compatibility: a legacy row/test double with only evidence_uris loses nothing."""
    g = _finding_groups([_row(evidence=["s3://e/legacy.txt"])])[0]
    assert g["evidence_items"] == []
    assert g["evidence_uris"] == ["s3://e/legacy.txt"]  # renderer falls back to this


# ============================ P2-4: Metadata ==============================================

def test_metadata_values_are_preserved_exactly() -> None:
    g = _finding_groups([_row(template_id="unix-command-injection", category="cwe-78")])[0]
    rows = dict(_technical_metadata_rows(g))
    assert rows["Template"] == "unix-command-injection"
    assert rows["Matcher"] == "m1"
    assert rows["Status"] == "open"
    assert rows["Category"] == "cwe-78"


def test_metadata_has_stable_labels_and_order() -> None:
    g = _finding_groups([_row()])[0]
    labels = [label for label, _ in _technical_metadata_rows(g)]
    assert labels[:4] == ["Tool", "Template", "Matcher", "Status"]


def test_missing_metadata_renders_na_and_never_crashes() -> None:
    g = _finding_groups([_row(template_id=None, category=None)])[0]
    rows = dict(_technical_metadata_rows(g))
    assert rows["Template"] == "N/A"
    assert rows["Tool"] == "N/A"
    assert "Category" not in rows  # optional field omitted, not padded


def test_cve_is_recovered_when_present_and_never_invented() -> None:
    with_cve = _finding_groups([_row(template_id="apache-CVE-2021-41773-path")])[0]
    assert dict(_technical_metadata_rows(with_cve))["CVE"] == "CVE-2021-41773"

    without = _finding_groups([_row(template_id="generic-detect", title="No identifier here")])[0]
    assert "CVE" not in dict(_technical_metadata_rows(without))


def test_executive_top_risks_stays_concise() -> None:
    """Executive rows carry only decision-useful fields -- no template/matcher/evidence detail."""
    g = _top_risk_groups([_row()])[0]
    assert set(g) == {"title", "issue_key", "endpoint_count", "max_risk", "max_cvss", "severity"}


def test_technical_group_retains_traceability_fields() -> None:
    g = _finding_groups([_row()])[0]
    for key in ("template_id", "matcher_names", "tools", "matched_ats", "evidence_items"):
        assert key in g


# ============================ INVARIANTS (the load-bearing tests) =========================

def _sample_rows():
    return [
        _row(template_id="a", matched_at="https://e.com/1", cvss=9.8, risk=10.0, severity="critical",
             evidence=["s3://e/a.txt"], evidence_items=[("log_excerpt", "s3://e/a.txt")]),
        _row(template_id="a", matched_at="https://e.com/2", cvss=9.8, risk=10.0, severity="critical"),
        _row(template_id="b", matched_at="https://f.com/1", cvss=5.5, risk=8.2, severity="medium"),
        _row(template_id="c", matched_at=None, cvss=None, risk=None, severity="low"),
    ]


def test_presentation_does_not_change_cvss_or_risk_values() -> None:
    rows = _sample_rows()
    before = [(r.cvss_score, r.final_risk_score, r.severity) for r in rows]
    _finding_groups(rows)
    _top_risk_groups(rows)
    assert [(r.cvss_score, r.final_risk_score, r.severity) for r in rows] == before


def test_presentation_does_not_change_security_score() -> None:
    rows = _sample_rows()
    before = compute_security_score(rows)
    _finding_groups(rows)
    _top_risk_groups(rows)
    assert compute_security_score(rows) == before


def test_security_score_ignores_evidence_presentation() -> None:
    """Identical findings differing ONLY in evidence metadata must score identically."""
    bare = [_row(template_id="x", cvss=7.5, risk=7.5)]
    rich = [_row(template_id="x", cvss=7.5, risk=7.5,
                 evidence=["s3://e/a.txt"],
                 evidence_items=[("log_excerpt", "s3://e/a.txt")],
                 shots=[("s3://e/s.png", "cs")])]
    assert compute_security_score(bare) == compute_security_score(rich)


def test_presentation_does_not_change_classification_or_verification() -> None:
    rows = _sample_rows()
    before_cls = [r.classification for r in rows]
    before_ver = [classify_verification_row(r) for r in rows]
    _finding_groups(rows)
    _top_risk_groups(rows)
    assert [r.classification for r in rows] == before_cls
    assert [classify_verification_row(r) for r in rows] == before_ver


def test_group_verification_still_reflects_evidence_after_p2_changes() -> None:
    """§5 semantics survive P2 unchanged.

    Note the GENERIC signal comes from the matcher here ("generic"), not from the template name:
    `unix-command-injection` on its own contains no generic marker. That is the §5 contract --
    a generic match with full evidence is corroborated, never proven.
    """
    rows = [
        VulnRow(
            id=uuid.uuid4(), title="Unix Command Injection - Generic Detection", severity="high",
            status="open", category="cwe-78", cvss_score=9.8, cvss_vector=None,
            final_risk_score=10.0, risk_rationale=None, compliance=[],
            evidence_uris=["s3://e/a.txt"], evidence_items=[("log_excerpt", "s3://e/a.txt")],
            screenshots=[("s3://e/s.png", "cs")], template_id="unix-command-injection",
            matcher_name="generic", matched_at="https://e.com/1",
        )
    ]
    g = _finding_groups(rows)[0]
    assert g["verification"] == "partially_verified"
    assert g["confidence"] == "medium"


def test_no_evidence_still_yields_unverified_after_p2_changes() -> None:
    """The §5 safe default is untouched by the evidence-presentation work."""
    g = _finding_groups([_row(template_id="unix-command-injection")])[0]
    assert g["verification"] == "unverified"
