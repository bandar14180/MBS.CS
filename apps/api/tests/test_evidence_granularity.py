"""Step 12 -- evidence GRANULARITY: what a shared artefact is, and how the report says so.

THE OBSERVATION THAT PROMPTED THIS
----------------------------------
On scan 15488e89 the evidence graph looked alarming at a glance:

    698 findings with evidence, 710 evidence links,
    one evidence row linked to 401 findings and another to 297.

Two rows accounting for 698 of the 710 links reads like accidental reuse. It is not. The
pipeline stores raw tool output at TOOL-RUN granularity -- `orchestrator._run_single_tool`
creates exactly ONE `Evidence` row per tool run and passes that single id to
`ingest_vulnerability_findings` for the whole batch -- so every finding produced by a run
links to the one artefact that genuinely is that run's output. 401 and 297 are simply the
finding counts of the `nuclei-dast` and `nuclei` runs. The remaining 12 links are
`screenshot` rows, which ARE per-finding (`_maybe_capture_screenshot` stores one image per
vulnerability and links it to that vulnerability alone).

So the system has two deliberate granularities living side by side:

    log_excerpt  -> one per TOOL RUN,  shared by that run's findings
    screenshot   -> one per FINDING,   linked to that finding alone

WHAT THESE TESTS PIN
--------------------
  1. The POLICY: the two evidence types keep their respective granularities, and a shared
     artefact is shared rather than duplicated per finding (which would multiply identical
     rows) and rather than withheld (which would cost findings their corroboration).
  2. NO DOUBLE-LINKING: one (finding, evidence) pair appears once. A duplicate pair would
     inflate the link count and make a single artefact look like several.
  3. The DISCLOSURE: because the two granularities are rendered in one list, a reader could
     take a run-wide log for a capture made for this finding alone. The report must say
     which it is -- and must say it ONLY when such an artefact is actually listed, so a
     finding whose evidence is entirely per-finding carries no caveat that does not apply.

These are read-side and policy assertions. Nothing here changes what is captured, and no
test in this file asserts that a shared artefact proves anything about an individual
finding -- the point of the disclosure is precisely that it does not.
"""

import re
import uuid

from apps.api.modules.reports import narrative as N
from apps.api.modules.reports.render import _finding_groups, render_technical
from apps.api.tests.test_report_evidence_integrity import _data, _record, _row, _text


def _screenshot(uri="s3://mbs-evidence/findings/v1/shot.png", evidence_id=None):
    return _record(etype="screenshot", uri=uri, evidence_id=evidence_id)


# --- the sharing policy ---------------------------------------------------------------------

def test_one_tool_run_artifact_serves_every_finding_of_that_run() -> None:
    """The shared-evidence case, stated as a property rather than a count: several findings
    from one run each carry the SAME artefact id and uri. This is the shape that produced
    the 401- and 297-way fanout, and it is correct."""
    shared = _record(
        uri="s3://mbs-evidence/tool-runs/run-a/raw-output.txt",
        evidence_id=uuid.UUID("11111111-0000-4000-8000-000000000001"),
    )
    rows = [
        _row([shared], title=f"Finding {i}", matched_at=f"https://h/p{i}", template_id=f"t{i}")
        for i in range(4)
    ]
    groups = _finding_groups(rows)
    assert len(groups) == 4
    for g in groups:
        records = [r for r in g["evidence_records"] if r.evidence_type == "log_excerpt"]
        assert len(records) == 1, "each finding carries the run artefact exactly once"
        assert records[0].storage_uri == shared.storage_uri
        assert records[0].evidence_id == shared.evidence_id


def test_screenshot_evidence_stays_per_finding() -> None:
    """The other granularity: a screenshot belongs to one finding and must not leak onto a
    sibling. If this ever failed, the report would show one finding's image as another's."""
    shot_a = _screenshot("s3://e/a.png", uuid.UUID("22222222-0000-4000-8000-00000000000a"))
    shot_b = _screenshot("s3://e/b.png", uuid.UUID("22222222-0000-4000-8000-00000000000b"))
    row_a = _row([shot_a], title="A", matched_at="https://h/a", template_id="ta")
    row_b = _row([shot_b], title="B", matched_at="https://h/b", template_id="tb")
    ga, gb = _finding_groups([row_a, row_b])
    assert [u for u, _ in ga["screenshots"]] == ["s3://e/a.png"]
    assert [u for u, _ in gb["screenshots"]] == ["s3://e/b.png"]


def test_a_finding_can_hold_both_granularities_at_once() -> None:
    """The real shape on the live dataset: a run-wide log AND a finding-specific screenshot.
    The screenshot is rendered separately from the artefact list, so the log must be the
    only entry in `evidence_records`' non-screenshot view while the image is still present."""
    shared = _record(uri="s3://mbs-evidence/tool-runs/run-a/raw-output.txt")
    row = _row([shared, _screenshot()])
    g = _finding_groups([row])[0]
    logs = [r for r in g["evidence_records"] if r.evidence_type == "log_excerpt"]
    assert len(logs) == 1
    assert len(g["screenshots"]) == 1


def test_sharing_does_not_duplicate_the_artifact_within_one_finding() -> None:
    """Duplicate-safety at the render boundary: a finding must not list one artefact twice.
    A duplicated entry would make a single shared file look like two pieces of evidence."""
    shared = _record(uri="s3://mbs-evidence/tool-runs/run-a/raw-output.txt")
    row = _row([shared])
    g = _finding_groups([row])[0]
    uris = [r.storage_uri for r in g["evidence_records"]]
    assert len(uris) == len(set(uris)), f"artefact listed more than once: {uris}"


# --- the disclosure -------------------------------------------------------------------------

def test_shared_scope_note_is_printed_when_a_tool_run_artifact_is_listed() -> None:
    """The reader must be told that a raw-output artefact is the whole run's output and is
    shared with the run's other findings -- otherwise its presence under one finding reads
    as a capture made for that finding."""
    text = _text(render_technical(_data([_row([_record()])])))
    assert "captured per tool run, not per finding" in text


def test_shared_scope_note_does_not_claim_the_artifact_proves_the_finding() -> None:
    """The note exists to LIMIT what a shared artefact is taken to show. It must corroborate
    provenance without asserting the finding is thereby confirmed."""
    note = N.EVIDENCE_SHARED_SCOPE_NOTE.lower()
    assert "not a capture made solely for this finding" in note
    for overclaim in ("proves", "confirms the finding", "verified", "exploited"):
        assert overclaim not in note, f"scope note overclaims: {overclaim!r}"


def test_no_shared_scope_note_when_the_only_evidence_is_per_finding() -> None:
    """A finding whose evidence is a screenshot alone must NOT carry a caveat about shared
    tool-run output: the caveat would be false for it."""
    row = _row([_screenshot()])
    text = _text(render_technical(_data([row])))
    assert "captured per tool run, not per finding" not in text


def test_legacy_typed_evidence_shape_also_gets_the_scope_note() -> None:
    """The older `evidence_items` render path carries the same shared artefacts and so needs
    the same disclosure; without it the note would silently depend on which shape a group
    happened to be built from."""
    row = _row([])
    row.evidence_records = []
    row.evidence_uris = ["s3://mbs-evidence/tool-runs/legacy/raw-output.txt"]
    row.evidence_items = [("log_excerpt", "s3://mbs-evidence/tool-runs/legacy/raw-output.txt")]
    text = _text(render_technical(_data([row])))
    assert "captured per tool run, not per finding" in text


def test_scope_note_survives_alongside_the_integrity_and_store_notes() -> None:
    """All three notes answer different questions (what it is, that it is unaltered, where it
    lives). Adding the scope note must not have displaced either of the others."""
    text = _text(render_technical(_data([_row([_record()])])))
    assert "captured per tool run, not per finding" in text
    assert "SHA-256" in text
    assert "evidence store" in text.lower()


# --- integrity of the relationship ----------------------------------------------------------

def test_every_rendered_artifact_keeps_its_own_identity() -> None:
    """Sharing must not blur artefact identity: each listed artefact keeps the id, digest and
    capture time of the row it came from, so a reader can always tell two artefacts apart."""
    # Distinct leading segments: `artifact_id` is EV-<first uuid segment>, so two ids that
    # differ only in their tail would legitimately share a label.
    a = _record(uri="s3://e/run-a.txt", evidence_id=uuid.UUID("3333aaaa-0000-4000-8000-000000000001"))
    b = _record(uri="s3://e/run-b.txt", evidence_id=uuid.UUID("3333bbbb-0000-4000-8000-000000000002"))
    row = _row([a, b])
    g = _finding_groups([row])[0]
    ids = {r.artifact_id for r in g["evidence_records"]}
    assert len(ids) == 2, f"artefact ids collapsed: {ids}"
    text = re.sub(r"\s+", " ", _text(render_technical(_data([row]))))
    for record in (a, b):
        assert record.storage_uri in text


def test_a_finding_with_no_evidence_is_stated_plainly_and_gets_no_notes() -> None:
    """The floor case. No artefact must never render as though one existed, and none of the
    evidence notes may appear when there is nothing for them to qualify."""
    text = _text(render_technical(_data([_row([])])))
    assert "No evidence artifact was captured" in text
    assert "captured per tool run, not per finding" not in text
