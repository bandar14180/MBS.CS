"""Prompt 29 -- the Tool -> Tool Version link of the finding lineage chain.

THE DEFECT THIS PINS
--------------------
The required lineage chain runs Observation -> Execution -> Tool -> Tool Version -> Input ->
... -> Finding -> Report. `tool_runs.tool_version` is a NOT NULL column written by BOTH
execution planes -- the in-process orchestrator sets it from `runner.version`, and the remote
lease plane derives it from TOOL_REGISTRY rather than trusting the worker (result_sink.py) --
but `gather_report_data` selected only `tool_runs.tool_name` from the row it was already
joining, and dropped the version on the floor.

The consequence is a truthfulness one, not a cosmetic one: "nuclei found this" is not a
reproducible claim. The same template id can match under one tool release and not the next, so
a finding attributed to a tool WITHOUT its version cannot be re-run against the thing that
actually produced it. The chain was broken at the report boundary while the value sat in the
joined row.

WHAT THESE TESTS GUARANTEE
--------------------------
  1. the version is carried to the report layer, and is read from the SAME tool_runs row the
     name is read from (never paired across runs);
  2. a MISSING or blank version stays visibly missing -- it is never defaulted, substituted,
     or borrowed from a sibling finding that does have one;
  3. the rendered provenance is version-qualified where a version exists and degrades to the
     bare tool name where one does not;
  4. adding provenance changed NO assessment fact -- severity, CVSS, risk, classification,
     verification and confidence are byte-identical with and without a version.

(4) is the load-bearing one for this prompt: the report layer must remain a read/view layer
over trusted finding data, so a provenance field must be incapable of moving a security fact.
"""

import uuid

from apps.api.modules.reports.classification import classify_row
from apps.api.modules.reports.data import ReportData, VulnRow
from apps.api.modules.reports.render import _finding_groups, _technical_metadata_rows
from apps.api.modules.reports.verification import classify_verification_row


def _row(**kw) -> VulnRow:
    """A minimal VulnRow; every assessment field fixed so only provenance varies."""
    base = dict(
        id=uuid.uuid4(),
        title="SQL Injection",
        severity="high",
        status="open",
        category="cwe-89",
        cvss_score=8.6,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        final_risk_score=7.9,
        risk_rationale=None,
        compliance=[],
        evidence_uris=[],
        template_id="sqli-error-based",
        matcher_name="word",
        matched_at="https://h/a?id=1",
    )
    base.update(kw)
    return VulnRow(**base)


# --- 1. the version reaches the report, paired with its own tool -----------------------------

def test_vulnrow_carries_tool_version():
    row = _row(tool_name="nuclei", tool_version="3.2.9")
    assert row.tool_name == "nuclei"
    assert row.tool_version == "3.2.9"


def test_tool_version_defaults_to_none_not_a_placeholder():
    """Absent provenance must be None -- never "N/A", "unknown" or "" masquerading as a value.

    `tool_name` uses the string "N/A" for historical reasons and the renderer filters it out by
    name. A version must not repeat that: None is unambiguous and cannot be mistaken for a
    real version string by any downstream consumer."""
    assert _row().tool_version is None


def test_group_pairs_each_version_with_its_own_tool():
    """Two tools at two versions must not cross-pair.

    The group builds "tool version" from the (tool_name, tool_version) pair on ONE row. A
    naive implementation that sorted names and versions independently and zipped them would
    produce "nuclei 1.4.2" here -- attributing a version to a tool that never reported it."""
    key = dict(title="SQL Injection", template_id="sqli-error-based", category="cwe-89")
    groups = _finding_groups(([
        _row(tool_name="nuclei", tool_version="3.2.9", matched_at="https://h/a", **key),
        _row(tool_name="zap", tool_version="1.4.2", matched_at="https://h/b", **key),
    ]))
    assert len(groups) == 1
    assert groups[0]["tool_versions"] == ["nuclei 3.2.9", "zap 1.4.2"]


# --- 2. a missing version stays missing -------------------------------------------------------

def test_missing_version_renders_bare_tool_name_not_a_fabricated_one():
    groups = _finding_groups(([_row(tool_name="nuclei", tool_version=None)]))
    assert groups[0]["tool_versions"] == ["nuclei"]


def test_blank_version_is_treated_as_absent():
    """The remote plane stores "" (not NULL) when the registry has no version for a tool.

    An empty string must not render as a trailing-space "nuclei " that looks like a value."""
    groups = _finding_groups(([_row(tool_name="nuclei", tool_version="   ")]))
    assert groups[0]["tool_versions"] == ["nuclei"]


def test_a_versionless_row_does_not_borrow_a_siblings_version():
    """THE core anti-fabrication case for this field.

    Same tool, same issue, two occurrences -- one with a recorded version and one without. The
    versionless occurrence must NOT be presented as having run at 3.2.9; both facts are
    reported side by side instead."""
    key = dict(title="SQL Injection", template_id="sqli-error-based", category="cwe-89")
    groups = _finding_groups(([
        _row(tool_name="nuclei", tool_version="3.2.9", matched_at="https://h/a", **key),
        _row(tool_name="nuclei", tool_version=None, matched_at="https://h/b", **key),
    ]))
    assert groups[0]["tool_versions"] == ["nuclei", "nuclei 3.2.9"]


# --- 3. rendered provenance -------------------------------------------------------------------

def test_metadata_row_states_the_version():
    groups = _finding_groups(([_row(tool_name="nuclei", tool_version="3.2.9")]))
    rows = dict(_technical_metadata_rows(groups[0]))
    assert rows["Tool"] == "nuclei 3.2.9"


def test_metadata_row_falls_back_to_bare_tools_when_no_version_anywhere():
    groups = _finding_groups(([_row(tool_name="nuclei", tool_version=None)]))
    assert dict(_technical_metadata_rows(groups[0]))["Tool"] == "nuclei"


def test_metadata_row_is_na_when_there_is_no_tool_linkage_at_all():
    """No linkage must read "N/A" -- an explicit absence, never an invented tool."""
    groups = _finding_groups(([_row()]))
    assert dict(_technical_metadata_rows(groups[0]))["Tool"] == "N/A"


# --- 4. provenance cannot move an assessment fact ---------------------------------------------

def test_tool_version_changes_no_security_fact():
    """The report layer is a read/view layer: adding provenance must not touch an assessment.

    Classification, verification and confidence are recomputed for an otherwise-identical row
    with and without a version, and compared. If a future change ever let `tool_version` feed
    one of those classifiers, this fails."""
    without = _row(tool_name="nuclei", tool_version=None)
    with_ver = _row(id=without.id, tool_name="nuclei", tool_version="3.2.9")

    assert classify_row(without) == classify_row(with_ver)
    assert classify_verification_row(without) == classify_verification_row(with_ver)
    for attr in ("severity", "cvss_score", "cvss_vector", "final_risk_score", "status"):
        assert getattr(without, attr) == getattr(with_ver, attr)


def test_tool_version_does_not_change_issue_identity_or_grouping():
    """Two occurrences of one issue that ran at DIFFERENT tool versions are still ONE issue.

    Provenance must not fragment identity: if the version entered `issue_key`, a routine tool
    upgrade would silently double every issue count in the report."""
    key = dict(title="SQL Injection", template_id="sqli-error-based", category="cwe-89")
    data = _data([
        _row(tool_name="nuclei", tool_version="3.2.9", matched_at="https://h/a", **key),
        _row(tool_name="nuclei", tool_version="3.3.0", matched_at="https://h/b", **key),
    ])
    assert len(_finding_groups(data.vulns)) == 1
    assert data.total_issue_count() == 1


def _data(rows: list[VulnRow]) -> ReportData:
    return ReportData(
        project_name="p",
        security_score=0,
        severity_counts={},
        total_vulns=len(rows),
        active_vulns=len(rows),
        vulns=rows,
    )
