"""Prompt 33 -- metrics for verification outcomes and evidence processing.

THE GAP THESE CLOSE
-------------------
Two capabilities that FULLY EXIST emitted no metric at all:

  * verification state/confidence (modules/reports/verification.py) -- so a shift in the
    verification mix, e.g. `verified` collapsing to `unverified` after an evidence-store
    outage, was invisible to an operator unless somebody read a report;
  * evidence capture (scanner_engine/evidence_store.py) -- so the fail-soft
    `unavailable://evidence-storage-failed/...` path was a log line only, despite directly
    suppressing corroboration in every report that reads the resulting sentinel row (see
    test_failure_injection_evidence.py).

Extends the EXISTING prometheus_client registry and the existing `record_*` convention. No new
metrics system, and deliberately NO metrics for discovery/AUL/ASKG/session/TestPlan, whose
subsystems do not exist here -- emitting for them would mean inventing them.

THE PROPERTY THAT MATTERS MOST
------------------------------
Label cardinality is BOUNDED BY CONSTRUCTION, not by convention. `state`, `confidence`,
`kind`, `outcome` and `result` are clamped to closed vocabularies by `_bounded`, so a caller
passing a target, URL, workspace id or finding id cannot mint a time series -- it collapses to
"other". That is what keeps tenant data out of `/metrics` and keeps the series count finite.
"""

import pytest

from apps.api.core import observability as obs

pytestmark = pytest.mark.skipif(
    not obs._PROM, reason="prometheus_client not installed; metrics are no-ops"
)


def _c(counter, *labels):
    return (counter.labels(*labels) if labels else counter)._value.get()


# === emission ================================================================================

def test_verification_outcome_increments_for_each_state_and_band():
    before = {
        s: _c(obs.VERIFICATION_OUTCOMES, s, "high")
        for s in ("verified", "partially_verified", "unverified")
    }
    for s in before:
        obs.record_verification_outcome(s, "high")
    for s, was in before.items():
        assert _c(obs.VERIFICATION_OUTCOMES, s, "high") == was + 1


def test_evidence_processed_distinguishes_stored_from_storage_failed():
    """The two outcomes must be separate series -- that IS the operational signal."""
    ok0 = _c(obs.EVIDENCE_PROCESSED, "raw_output", "stored")
    bad0 = _c(obs.EVIDENCE_PROCESSED, "raw_output", "storage_failed")
    obs.record_evidence_processed("raw_output", "stored")
    obs.record_evidence_processed("raw_output", "storage_failed")
    assert _c(obs.EVIDENCE_PROCESSED, "raw_output", "stored") == ok0 + 1
    assert _c(obs.EVIDENCE_PROCESSED, "raw_output", "storage_failed") == bad0 + 1


def test_evidence_integrity_results_are_counted_separately():
    before = {r: _c(obs.EVIDENCE_INTEGRITY, r) for r in
              ("pass", "integrity_failure", "missing_object", "no_checksum")}
    for r in before:
        obs.record_evidence_integrity(r)
    for r, was in before.items():
        assert _c(obs.EVIDENCE_INTEGRITY, r) == was + 1


# === cardinality is bounded by construction ==================================================

def test_an_unknown_state_collapses_to_a_closed_vocabulary_value():
    """A value outside the closed set must NOT mint its own series."""
    before = _c(obs.VERIFICATION_OUTCOMES, "unverified", "medium")
    obs.record_verification_outcome("something-new", "also-new")
    # Falls back to the documented safe defaults, not to a new label pair.
    assert _c(obs.VERIFICATION_OUTCOMES, "unverified", "medium") == before + 1


def test_identifiers_passed_as_labels_cannot_create_series():
    """THE anti-leak case. Ids/URLs/hosts collapse to `other` instead of becoming labels.

    Each of these is exactly the kind of unbounded, tenant-identifying value that must never
    reach /metrics. Asserting on the `other` bucket proves the clamp fired rather than the
    value being silently accepted."""
    hostile = [
        "https://customer.internal/admin?token=abc",
        "0f9a2c71-0000-4000-8000-000000000001",
        "workspace-42",
        "mbsk_live_deadbeef",
    ]
    before = _c(obs.EVIDENCE_PROCESSED, "other", "other")
    for value in hostile:
        obs.record_evidence_processed(value, value)
    assert _c(obs.EVIDENCE_PROCESSED, "other", "other") == before + len(hostile)


def test_none_and_empty_values_are_handled_without_raising():
    obs.record_verification_outcome(None, None)
    obs.record_evidence_processed(None, "")
    obs.record_evidence_integrity("")


# === no sensitive data reaches the exposition format =========================================

def test_rendered_metrics_contain_no_secret_or_identifier_from_hostile_labels():
    """Render the ACTUAL exposition body and assert the hostile values are absent.

    Stronger than inspecting labels: this is the bytes an operator (or a scraper) receives."""
    secret_url = "https://customer.internal/admin?token=supersecret"
    obs.record_evidence_processed(secret_url, secret_url)
    obs.record_verification_outcome(secret_url, secret_url)

    body = obs.metrics_response_body().decode("utf-8", "replace")
    assert "supersecret" not in body
    assert "customer.internal" not in body
    # ...while the metrics themselves ARE exposed.
    assert "mbs_evidence_processed_total" in body
    assert "mbs_verification_outcomes_total" in body


def test_metric_names_follow_the_existing_prometheus_convention():
    """Same `mbs_*_total` counter convention as every existing counter in this module."""
    for metric in (obs.VERIFICATION_OUTCOMES, obs.EVIDENCE_PROCESSED, obs.EVIDENCE_INTEGRITY):
        assert metric._name.startswith("mbs_")
    body = obs.metrics_response_body().decode("utf-8", "replace")
    assert "mbs_evidence_integrity_checks_total" in body


def test_declared_labels_carry_no_identifying_dimension():
    """No workspace/project/target/finding/scan dimension on any metric added here."""
    forbidden = {"workspace", "workspace_id", "project", "project_id", "target", "url",
                 "host", "finding", "finding_id", "scan", "scan_id", "tenant", "user"}
    for metric in (obs.VERIFICATION_OUTCOMES, obs.EVIDENCE_PROCESSED, obs.EVIDENCE_INTEGRITY):
        assert not (set(metric._labelnames) & forbidden)


# === the recorder observes, it never decides =================================================

def test_recording_a_verification_outcome_returns_nothing_and_changes_no_state():
    """A metric recorder must be a pure side-effect on the registry.

    If it ever returned a value a caller could branch on, the metrics layer would have become
    part of the security decision it is supposed to be merely observing."""
    assert obs.record_verification_outcome("verified", "high") is None
    assert obs.record_evidence_processed("raw_output", "stored") is None
    assert obs.record_evidence_integrity("pass") is None
