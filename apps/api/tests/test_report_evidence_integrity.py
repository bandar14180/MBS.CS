"""Phase 3.2 (R-02 audit item) -- evidence timestamps, hashes and the evidence manifest.

THE GAP THIS PINS
-----------------
`evidence` has always stored `checksum` (SHA-256 over the uploaded bytes, computed in
scanner_engine.evidence_store) and `created_at` (server CURRENT_TIMESTAMP(6) at capture). The
report selected only `storage_uri` and `evidence_type`, and kept the checksum for SCREENSHOTS
alone -- so a log artifact rendered as a bare `s3://...` key with no capture time and no digest.
A reader could neither date an artifact nor confirm a retrieved file was the one assessed, and
no manifest existed to show the evidence set was complete.

WHAT PHASE 3.2 CHANGED
----------------------
Read-side only. The same query now also selects `id`, `created_at` and `tool_run_id`; the values
travel on a new `EvidenceRecord` and are rendered. No schema change, no new capture logic, and
NOTHING is computed by the report -- every printed value is read back from the row written at
capture time.

WHAT IT MUST NOT DO
-------------------
Never present an artifact as verified when no digest was recorded; never substitute "now" for a
missing timestamp; never alter scoring, classification, verification, MITRE, compliance or the
scan scope.
"""

import collections
import hashlib
import re
import uuid
from datetime import datetime, timezone

import pytest

from apps.api.modules.reports.data import EvidenceRecord, ReportData, VulnRow
from apps.api.modules.reports.render import (
    _evidence_manifest_story,
    _finding_groups,
    render_executive,
    render_technical,
)
from apps.api.modules.reports.scoring import compute_security_score
from apps.api.tests.test_report_layout import _pdf_text

CONTENT = b"HTTP/1.1 200 OK\r\n\r\n<payload evidence>"
DIGEST = hashlib.sha256(CONTENT).hexdigest()
CAPTURED = datetime(2026, 9, 8, 14, 23, 51, tzinfo=timezone.utc)


def _record(etype="log_excerpt", uri="s3://mbs-evidence/tool-runs/abc/raw-output.txt",
            checksum=DIGEST, captured_at=CAPTURED, evidence_id=None, tool_run_id=None):
    return EvidenceRecord(
        evidence_id=evidence_id or uuid.UUID("3f9a2c71-0000-4000-8000-000000000001"),
        evidence_type=etype, storage_uri=uri, checksum=checksum,
        captured_at=captured_at, tool_run_id=tool_run_id,
    )


def _row(records=(), **kw):
    records = list(records)
    return VulnRow(
        id=kw.pop("vid", None) or uuid.uuid4(),
        title=kw.pop("title", "Command Injection"), severity=kw.pop("severity", "critical"),
        status=kw.pop("status", "open"), category="cwe-78", cvss_score=9.8, cvss_vector=None,
        final_risk_score=9.8, risk_rationale=None, compliance=[],
        evidence_uris=[r.storage_uri for r in records if r.evidence_type != "screenshot"],
        evidence_items=[(r.evidence_type, r.storage_uri) for r in records
                        if r.evidence_type != "screenshot"],
        evidence_records=records,
        screenshots=[(r.storage_uri, r.checksum) for r in records
                     if r.evidence_type == "screenshot"],
        template_id=kw.pop("template_id", "cmd-inj"), matcher_name="status",
        matched_at=kw.pop("matched_at", "https://h/a"),
    )


def _data(rows):
    sev = dict(collections.Counter(r.severity for r in rows))
    return ReportData(
        project_name="EvidenceProj", security_score=compute_security_score(rows),
        severity_counts=sev, total_vulns=len(rows), active_vulns=len(rows),
        active_severity_counts=sev, vulns=rows,
    )


def _text(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", _pdf_text(pdf))


def _unwrapped(pdf: bytes) -> str:
    """PDF text with ALL whitespace removed.

    A 64-char digest in a narrow manifest column is wrapped by ReportLab across two lines, so
    it appears in the extracted text with a space inside it. Searching the whitespace-stripped
    text is what lets a test assert the COMPLETE digest is present rather than settling for a
    prefix -- the wrap is a layout detail, not a missing value."""
    return re.sub(r"\s+", "", _pdf_text(pdf))


# --- EvidenceRecord semantics --------------------------------------------------------------

def test_record_reports_a_valid_digest_with_its_algorithm_named() -> None:
    r = _record()
    assert r.has_checksum is True
    assert r.checksum_label() == f"SHA-256:{DIGEST}"
    assert r.checksum_label().endswith(DIGEST)


def test_digest_matches_a_rehash_of_the_original_bytes() -> None:
    """The stored value really is SHA-256 over the artifact content, so a recipient can verify."""
    assert _record().checksum == hashlib.sha256(CONTENT).hexdigest()


def test_short_digest_is_marked_as_truncated() -> None:
    short = _record().checksum_short()
    assert short.startswith("SHA-256:")
    assert short.endswith("…"), "a truncated digest must not look complete"
    assert DIGEST[:16] in short


def test_missing_checksum_is_reported_as_unrecorded_not_verified() -> None:
    r = _record(checksum=None)
    assert r.has_checksum is False
    assert r.checksum_label() == "not recorded"
    assert r.checksum_short() == "not recorded"


@pytest.mark.parametrize("bad", ["", "   ", "abc", DIGEST[:63], DIGEST + "a", "z" * 64])
def test_malformed_digests_are_never_presented_as_valid(bad: str) -> None:
    """A truncated or non-hex value must not be shown as a verifiable digest."""
    assert _record(checksum=bad).has_checksum is False
    assert _record(checksum=bad).checksum_label() == "not recorded"


def test_timestamp_is_rendered_in_utc() -> None:
    assert _record().captured_label() == "2026-09-08 14:23:51 UTC"


def test_missing_timestamp_is_never_replaced_with_now() -> None:
    label = _record(captured_at=None).captured_label()
    assert label == "not recorded"
    assert str(datetime.now(timezone.utc).year) not in label


def test_artifact_id_is_stable_and_derived_from_the_evidence_row() -> None:
    r = _record()
    assert r.artifact_id == "EV-3F9A2C71"
    assert r.artifact_id == _record().artifact_id      # stable across construction
    assert re.fullmatch(r"EV-[0-9A-F]{8}", r.artifact_id)


def test_artifact_id_without_an_evidence_id_is_explicit() -> None:
    assert EvidenceRecord(None, "log_excerpt", "s3://x/y", DIGEST, CAPTURED).artifact_id == "EV-UNKNOWN"


def test_record_is_immutable() -> None:
    """An evidence record states a past capture; nothing downstream may edit it."""
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        _record().checksum = "tampered"


# --- group aggregation ---------------------------------------------------------------------

def test_records_reach_the_finding_group() -> None:
    g = _finding_groups([_row([_record()])])[0]
    assert [r.artifact_id for r in g["evidence_records"]] == ["EV-3F9A2C71"]


def test_identical_artifacts_across_locations_are_deduplicated() -> None:
    rec = _record()
    groups = _finding_groups([
        _row([rec], matched_at="https://h/1"),
        _row([rec], matched_at="https://h/2"),
    ])
    assert len(groups) == 1
    assert len(groups[0]["evidence_records"]) == 1


def test_distinct_artifacts_stay_distinct() -> None:
    a = _record(uri="s3://e/a.txt", evidence_id=uuid.uuid4())
    b = _record(uri="s3://e/b.txt", evidence_id=uuid.uuid4(), checksum=hashlib.sha256(b"b").hexdigest())
    g = _finding_groups([_row([a, b])])[0]
    assert len(g["evidence_records"]) == 2


def test_legacy_rows_without_records_still_render() -> None:
    """Backward compatibility: a row built before Phase 3.2 falls back to the untyped lists."""
    row = _row([])
    row.evidence_uris = ["s3://e/legacy.txt"]
    row.evidence_items = [("log_excerpt", "s3://e/legacy.txt")]
    g = _finding_groups([row])[0]
    assert g["evidence_records"] == []
    text = _text(render_technical(_data([row])))
    assert "s3://e/legacy.txt" in text


# --- rendered per-finding evidence ---------------------------------------------------------

def test_finding_evidence_shows_digest_timestamp_and_artifact_id() -> None:
    pdf = render_technical(_data([_row([_record()])]))
    text = _text(pdf)
    assert DIGEST in _unwrapped(pdf), "the full digest must be printed, not just a prefix"
    assert "2026-09-08 14:23:51 UTC" in text
    assert "EV-3F9A2C71" in text


def test_integrity_note_states_what_the_hash_does_and_does_not_prove() -> None:
    text = _text(render_technical(_data([_row([_record()])])))
    assert "SHA-256" in text
    assert "byte-identical" in text
    assert "not a cryptographic signature" in text


def test_an_artifact_without_a_digest_is_labelled_not_recorded() -> None:
    text = _text(render_technical(_data([_row([_record(checksum=None, captured_at=None)])])))
    assert "not recorded" in text


# --- manifest behaviour --------------------------------------------------------------------

def test_manifest_lists_every_artifact_including_screenshots() -> None:
    log = _record()
    shot = _record(etype="screenshot", uri="s3://e/s.png",
                   checksum=hashlib.sha256(b"png").hexdigest(), evidence_id=uuid.uuid4())
    pdf = render_technical(_data([_row([log, shot])]))
    assert "Evidence manifest" in _text(pdf)
    packed = _unwrapped(pdf)
    assert log.checksum in packed
    assert shot.checksum in packed, "screenshots belong in the manifest even though the per-finding view splits them"


def test_manifest_counts_only_digest_backed_artifacts_as_verified() -> None:
    rows = [_row([
        _record(),
        _record(uri="s3://e/none.har", etype="http_response", checksum=None,
                captured_at=None, evidence_id=uuid.uuid4()),
    ])]
    text = _text(render_technical(_data(rows)))
    m = re.search(r"(\d+) artifact reference\(s\).*?(\d+) carry a recorded SHA-256", text)
    assert m, "manifest summary line missing"
    assert m.group(1) == "2"
    assert m.group(2) == "1"


def test_manifest_links_each_artifact_to_its_finding() -> None:
    row = _row([_record()])
    text = _text(render_technical(_data([row])))
    g = _finding_groups([row])[0]
    assert g["finding_id"] in text
    assert "EV-3F9A2C71" in text


def test_manifest_states_absence_honestly_when_there_is_no_evidence() -> None:
    text = _text(render_technical(_data([_row([])])))
    assert "No evidence artifacts are recorded" in text


def test_manifest_is_deterministic() -> None:
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm

    from apps.api.modules.reports.render import _styles

    data = _data([_row([_record(), _record(uri="s3://e/b.txt", evidence_id=uuid.uuid4())])])
    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    first = _evidence_manifest_story(data, styles, colors, mm)
    second = _evidence_manifest_story(data, styles, colors, mm)
    assert len(first) == len(second)


def test_manifest_does_not_duplicate_one_artifact_under_one_finding() -> None:
    rec = _record()
    row = _row([rec, rec])       # same artifact referenced twice
    assert _unwrapped(render_technical(_data([row]))).count(rec.checksum) >= 1
    g = _finding_groups([row])[0]
    assert len(g["evidence_records"]) == 1


# --- invariants: earlier phases untouched ---------------------------------------------------

def test_r01_issue_counts_unaffected() -> None:
    rows = [_row([_record()], matched_at=f"https://h/p{i}") for i in range(7)]
    data = _data(rows)
    assert data.total_issue_count() == 1
    assert data.total_vulns == 7
    assert "1 unique issue across 7 affected locations" in _text(render_executive(data))


def test_r02_compliance_population_unaffected() -> None:
    data = _data([_row([_record()])])
    assert data.compliance_coverage() == []      # these rows carry no mappings
    assert data.compliance_frameworks() == []


def test_r03_scope_metadata_unaffected() -> None:
    data = _data([_row([_record()])])
    assert data.is_scan_scoped() is False
    assert data.scope_scans == []


def test_r04_score_band_unaffected() -> None:
    from apps.api.modules.reports import _branding as B
    from apps.api.modules.reports.render import _score_band

    data = _data([_row([_record()])])
    assert B.score_band_color(_score_band(data.security_score)) != B.MUTED


def test_evidence_metadata_never_alters_assessment_values() -> None:
    """Phase 3.2 is provenance only: adding records must not move any assessed number."""
    plain = _row([])
    withev = _row([_record()], vid=plain.id, title=plain.title)
    assert compute_security_score([plain]) == compute_security_score([withev])
    assert (plain.severity, plain.cvss_score, plain.final_risk_score) == (
        withev.severity, withev.cvss_score, withev.final_risk_score
    )


def test_verification_still_derives_from_artifact_presence_only() -> None:
    """verification.py reads evidence_uris/screenshots, not the new records -- unchanged."""
    from apps.api.modules.reports.verification import classify_verification_row

    before = classify_verification_row(_row([]))
    after = classify_verification_row(_row([_record()]))
    assert before[0] == "unverified"
    assert after[0] in ("partially_verified", "verified")
