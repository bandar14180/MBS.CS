"""Prompt 31 -- cross-cutting security regression for the behaviour Prompts 29-30 touched.

SCOPE, AND WHAT IS DELIBERATELY NOT HERE
-----------------------------------------
This does NOT rewrite the test architecture and does not duplicate suites that already pin a
property end to end. Tenant isolation, scope enforcement, worker isolation, execution fencing,
DAST provenance, state transitions, evidence integrity and the verification lifecycle each
already have a dedicated file (test_tenancy_isolation, test_scope_enforcement,
test_lease_orphan_recovery, test_discovery_provenance, test_evidence_integrity,
test_verification*, ...), and re-asserting them here would create a second, drifting copy.

What has NO home is the set of invariants that span the seams Prompts 29-30 cut across --
properties that hold only because two separate subsystems agree, and that a change to either
one alone would silently break. Each test below states the defect class it guards, with
positive and negative cases where the property has two directions.

THE DEFECT CLASSES GUARDED (the ones the batch names explicitly)
-----------------------------------------------------------------
  1. recorded-location vs unique-finding count confusion;
  2. provenance loss / destructive metadata replacement;
  3. verification-state contamination (report code moving a security fact);
  4. raw-vs-normalized evidence loss;
  5. inference / detection promoted to proof.
"""

import hashlib
import uuid

from apps.api.modules.reports.classification import classify_row
from apps.api.modules.reports.data import EvidenceRecord, ReportData, VulnRow
from apps.api.modules.reports.render import _finding_groups
from apps.api.modules.reports.scoring import compute_security_score, group_issues, issue_key
from apps.api.modules.reports.verification import (
    PARTIALLY_VERIFIED,
    UNVERIFIED,
    VERIFIED,
    ConfidenceProvenanceError,
    classify_verification_row,
    normalize_confidence,
)

SHOT = ("s3://mbs-evidence/vulnerabilities/v/screenshot-0011.png", "a" * 64)
LOG = "s3://mbs-evidence/tool-runs/t/raw-output.txt"


def _row(**kw) -> VulnRow:
    base = dict(
        id=uuid.uuid4(), title="SQL Injection", severity="high", status="open",
        category="cwe-89", cvss_score=8.6, cvss_vector=None, final_risk_score=7.9,
        risk_rationale=None, compliance=[], evidence_uris=[],
        template_id="sqli-error-based", matcher_name="word",
        matched_at="https://h/a?id=1",
    )
    base.update(kw)
    return VulnRow(**base)


def _data(rows) -> ReportData:
    return ReportData(
        project_name="P", security_score=0, severity_counts={},
        total_vulns=len(rows), active_vulns=len(rows), vulns=rows,
    )


# === 1. RECORDED LOCATIONS vs UNIQUE ISSUES ==================================================
# The defect: one issue observed at seven endpoints reported as "7 findings" above a single
# rendered block, so a reader could only conclude six findings had been dropped.

def test_one_issue_at_many_locations_is_one_issue_and_many_occurrences():
    """POSITIVE: both units are available and they disagree, correctly."""
    rows = [_row(matched_at=f"https://h/p{i}") for i in range(7)]
    data = _data(rows)
    assert data.total_issue_count() == 1          # unique issues
    assert data.total_vulns == 7                  # recorded locations
    assert len(_finding_groups(rows)) == 1        # rendered blocks reconcile with the issue unit


def test_distinct_issues_are_not_collapsed_by_the_issue_unit():
    """NEGATIVE: the issue unit must not over-merge -- different templates stay different."""
    rows = [
        _row(template_id="sqli-error-based", matched_at="https://h/a"),
        _row(template_id="xss-reflected", title="Reflected XSS", matched_at="https://h/a"),
    ]
    assert _data(rows).total_issue_count() == 2
    assert len({issue_key(r) for r in rows}) == 2


def test_breadth_is_weighted_within_one_issue_never_counted_as_many_issues():
    """The seam between scoring.py's unit and the report's count surfaces.

    Two DIFFERENT things are true here and the test pins both, because confusing them is
    exactly the count defect this batch guards:

      * breadth MATTERS -- one issue exposed at 20 locations is worse than at one, so
        `_location_factor` lowers the score. That is deliberate, not occurrence-counting.
      * breadth is NOT a second issue -- the 20 rows collapse to ONE ScoredIssue whose
        penalty is capped, so the diminishing-returns product multiplies one factor, not 20.

    If breadth ever leaked into the ISSUE count instead of the issue's penalty, the second
    assertion fails and the score would fall off a cliff for a single broad issue."""
    issues = group_issues([_row(matched_at=f"https://h/p{i}") for i in range(20)])
    assert len(issues) == 1                     # one ISSUE, whatever its breadth
    assert issues[0].location_count == 20       # breadth recorded on the issue itself
    assert issues[0].occurrence_count == 20

    broad = compute_security_score([_row(matched_at=f"https://h/p{i}") for i in range(20)])
    narrow = compute_security_score([_row(matched_at="https://h/a")])
    assert broad < narrow                       # breadth costs posture...
    # ...but as ONE capped issue, never as 20 stacked ones. Twenty genuinely DISTINCT issues
    # score far lower than one issue at twenty locations.
    twenty_distinct = compute_security_score(
        [_row(template_id=f"tpl-{i}", matched_at="https://h/a") for i in range(20)]
    )
    assert twenty_distinct < broad


# === 2. PROVENANCE LOSS / DESTRUCTIVE METADATA REPLACEMENT ===================================

def test_provenance_absence_is_represented_as_absence_not_as_a_value():
    """NEGATIVE case for fabricated provenance: nothing may invent a tool, version or digest."""
    row = _row()
    assert row.tool_version is None
    assert row.tool_name == "N/A"          # the explicit no-linkage sentinel, not a tool name
    groups = _finding_groups([row])
    assert groups[0]["tools"] == []        # "N/A" is filtered, never printed as a producer
    assert groups[0]["tool_versions"] == []


def test_recorded_provenance_survives_grouping():
    """POSITIVE: aggregation must not drop provenance that WAS recorded.

    Grouping is where provenance most easily disappears -- a representative row is chosen for
    the header, and anything read only from that representative is lost for every other
    member. Tools/versions are unioned across members, so they survive."""
    rows = [
        _row(matched_at="https://h/a", tool_name="nuclei", tool_version="3.2.9"),
        _row(matched_at="https://h/b", tool_name="zap", tool_version="1.4.2"),
    ]
    g = _finding_groups(rows)[0]
    assert g["tools"] == ["nuclei", "zap"]
    assert g["tool_versions"] == ["nuclei 3.2.9", "zap 1.4.2"]


def test_evidence_records_survive_grouping_with_their_digests():
    """Evidence is unioned across members, digests intact -- not reduced to the representative."""
    rec_a = EvidenceRecord(uuid.uuid4(), "log_excerpt", LOG + "a", "a" * 64, None)
    rec_b = EvidenceRecord(uuid.uuid4(), "log_excerpt", LOG + "b", "b" * 64, None)
    rows = [
        _row(matched_at="https://h/a", evidence_records=[rec_a]),
        _row(matched_at="https://h/b", evidence_records=[rec_b]),
    ]
    digests = {r.checksum for r in _finding_groups(rows)[0]["evidence_records"]}
    assert digests == {"a" * 64, "b" * 64}


# === 3. VERIFICATION-STATE CONTAMINATION =====================================================
# The report layer is a READ/VIEW layer. It must not be able to move a security fact.

def test_verification_never_alters_severity_cvss_or_score():
    """An UNVERIFIED critical is still a critical -- downgrading unproven findings hides risk."""
    unverified = _row(severity="critical", cvss_score=9.8)
    verified = _row(severity="critical", cvss_score=9.8,
                    evidence_uris=[LOG], screenshots=[SHOT])
    assert classify_verification_row(unverified)[0] == UNVERIFIED
    assert classify_verification_row(verified)[0] == VERIFIED
    # ...and the assessment facts are identical across that entire span.
    assert unverified.severity == verified.severity
    assert unverified.cvss_score == verified.cvss_score
    assert compute_security_score([unverified]) == compute_security_score([verified])


def test_ai_confidence_can_never_become_security_confidence():
    """NEGATIVE: the AI-bypass guard. A model self-rating must not acquire evidence authority.

    Both directions are asserted: a well-formed band from an AI source is refused BECAUSE of
    its source, and a raw float is refused because no sanctioned numeric->band mapping exists."""
    try:
        normalize_confidence("high", source="ai")
        raise AssertionError("an AI-sourced confidence must not be admitted")
    except ConfidenceProvenanceError:
        pass
    try:
        normalize_confidence(0.95)
        raise AssertionError("a numeric confidence must not be converted to a band")
    except ConfidenceProvenanceError:
        pass
    assert normalize_confidence("high") == "high"          # POSITIVE: evidence-sourced band


def test_rendering_a_report_does_not_mutate_the_finding_rows():
    """Rendering is a read. The rows handed in must come back byte-identical.

    Guards the whole class of "report code modified verification state": if any render path
    ever wrote back onto a row, this snapshot comparison fails."""
    rows = [_row(evidence_uris=[LOG], screenshots=[SHOT]), _row(matched_at="https://h/b")]
    before = [
        (r.severity, r.status, r.cvss_score, r.final_risk_score, r.verification, r.confidence,
         r.classification, r.tool_name, r.tool_version)
        for r in rows
    ]
    _finding_groups(rows)
    compute_security_score(rows)
    after = [
        (r.severity, r.status, r.cvss_score, r.final_risk_score, r.verification, r.confidence,
         r.classification, r.tool_name, r.tool_version)
        for r in rows
    ]
    assert before == after


# === 4. RAW vs NORMALIZED EVIDENCE ===========================================================

def test_the_recorded_digest_is_over_the_raw_artifact_not_a_display_form():
    """Differential verification depends on the raw artifact staying independently addressable.

    A normalized/redacted form hashes differently, so it can never be substituted for the
    authoritative one without detection."""
    raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=secret\r\n\r\nbody"
    normalized = raw.replace(b"secret", b"[REDACTED]")
    record = EvidenceRecord(uuid.uuid4(), "log_excerpt", LOG,
                            hashlib.sha256(raw).hexdigest(), None)
    assert record.has_checksum
    assert hashlib.sha256(raw).hexdigest() == record.checksum
    assert hashlib.sha256(normalized).hexdigest() != record.checksum


def test_report_evidence_carries_references_never_artifact_bytes():
    """A captured response routinely holds a cookie or key; the report must carry only pointers."""
    record = EvidenceRecord(uuid.uuid4(), "log_excerpt", LOG, "c" * 64, None)
    rendered = " ".join(str(v) for v in vars(record).values())
    assert "s3://" in rendered
    assert "Set-Cookie" not in rendered and "Bearer" not in rendered


# === 5. INFERENCE / DETECTION NEVER BECOME PROOF =============================================

def test_a_detection_is_never_verified_however_much_evidence_it_has():
    """NEGATIVE: artefacts corroborate, they do not convert an observation into an exploit.

    Both artefact kinds present -- the only route to VERIFIED for a real vulnerability -- and
    the detection still tops out at PARTIALLY_VERIFIED."""
    detection = _row(template_id="tech-detect", title="Technology Detection",
                     cvss_score=None, category=None,
                     evidence_uris=[LOG], screenshots=[SHOT])
    assert classify_row(detection) == "detection"
    assert classify_verification_row(detection)[0] == PARTIALLY_VERIFIED


def test_an_inference_based_match_is_never_verified():
    """Timing/blind inference is not observed output, so it cannot reach VERIFIED."""
    blind = _row(template_id="windows-command-injection", matcher_name="time-based",
                 evidence_uris=[LOG], screenshots=[SHOT])
    state, confidence = classify_verification_row(blind)
    assert state == PARTIALLY_VERIFIED
    assert confidence == "low"      # inference lowers CONFIDENCE, and only confidence


def test_a_detection_never_reduces_the_security_score():
    """A technology/WAF/version observation is not a weakness and must not cost posture."""
    detection = _row(template_id="tech-detect", title="Technology Detection",
                     cvss_score=None, category=None, severity="low")
    assert compute_security_score([detection]) == compute_security_score([])


def test_partial_evidence_does_not_reach_verified():
    """ONE artefact kind corroborates; VERIFIED requires two independent directions."""
    assert classify_verification_row(_row(evidence_uris=[LOG]))[0] == PARTIALLY_VERIFIED
    assert classify_verification_row(_row(screenshots=[SHOT]))[0] == PARTIALLY_VERIFIED
    # POSITIVE control: both kinds on a specific, non-generic match DO reach VERIFIED.
    assert classify_verification_row(
        _row(evidence_uris=[LOG], screenshots=[SHOT])
    )[0] == VERIFIED
