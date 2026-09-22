"""Canonical ATT&CK aggregation — the ONE definition of "how many issues hit a technique".

WHY THIS MODULE EXISTS
----------------------
The ATT&CK numbers were computed in three different places, by three different rules:

  * the PDF report (reports/data.gather_report_data) counted DISTINCT LOGICAL ISSUES,
    identified by `scoring.issue_key`, over the scorable population (`scoring.is_scorable`
    -- active status, not info severity, not a detection);
  * `attack.service.attack_matrix_for_scan` counted RAW `attack_mappings` ROWS, with no
    status filter and no classification filter;
  * `attack.service.kill_chain_steps` de-duplicated by finding TITLE.

So the same project could report a technique as hit once in the PDF and five times in the
API, because one vulnerability observed at five URLs is five `vulnerabilities` rows (the
dedup identity is `(project_id, fingerprint)`, and a fingerprint is
`template_id|matcher|matched_at` -- one LOCATION), each carrying its own `attack_mappings`
row. Measured on a five-location issue: API 5, PDF 1. A remediated or false-positive finding
also still counted toward the API's "current" ATT&CK coverage.

This module is that single source of truth. `attack.service` and `reports.data` both call
it, so the two surfaces cannot drift again.

WHAT "ONE ISSUE" MEANS
----------------------
`scoring.issue_key` -- `template:<template_id>` when the finding has one, else
`title:<title>`. Deliberately NOT the fingerprint and NOT `matched_at`: those identify one
occurrence at one location, which is exactly the over-counting this replaces. A single issue
mapped to several techniques counts once PER TECHNIQUE (each technique is its own row); two
distinct issues sharing a technique count as two.

WHICH FINDINGS COUNT
--------------------
`scoring.is_scorable` -- the SAME predicate the Security Score and the Executive report's
"currently affected" population use. That composes three independent exclusions: non-active
status (fixed / false_positive / accepted_risk), `info` severity, and a DETECTION
classification. Using it here means the ATT&CK matrix describes the same set of problems the
score does, rather than a historical record that includes findings the customer already
fixed.

STALE MAPPINGS
--------------
`attack_mappings` rows written BEFORE the detection guard landed in
`attack.catalog.techniques_for` may still exist for findings that are detections. Filtering
on `is_scorable` at READ time (rather than trusting what was written) means those stale rows
are excluded without needing a backfill migration.
"""


from apps.api.modules.reports.data import _parse_fingerprint
from apps.api.modules.reports.scoring import is_scorable, issue_key


class _FindingView:
    """The minimal shape `issue_key` / `is_scorable` need, built from a `Vulnerability` ORM
    row.

    Both predicates read plain attributes (`template_id`, `title`, `severity`, `status`,
    `cvss_score`, `category`) rather than requiring a report `VulnRow`, so this adapter lets
    the API path reuse them without constructing the full report data structure. `template_id`
    is recovered from the stored fingerprint with the SAME canonical parser the report uses,
    so both surfaces derive identity from identical inputs.
    """

    __slots__ = ("template_id", "title", "severity", "status", "cvss_score", "category")

    def __init__(self, vuln):
        template_id, _matcher, _matched_at = _parse_fingerprint(getattr(vuln, "fingerprint", None))
        self.template_id = template_id
        self.title = getattr(vuln, "title", None)
        self.severity = getattr(vuln, "severity", None)
        self.status = getattr(vuln, "status", None)
        self.cvss_score = getattr(vuln, "cvss_score", None)
        self.category = getattr(vuln, "category", None)


def scorable_issue_key(vuln) -> str | None:
    """The canonical issue identity for one `Vulnerability` row, or None if the finding must
    not be counted (inactive / informational / a detection). Fail-safe: a row that cannot be
    classified is simply not counted rather than counted wrongly."""
    view = _FindingView(vuln)
    if not is_scorable(view):
        return None
    return issue_key(view)


def count_issues_by_technique(mappings, vulns_by_id) -> dict[tuple[str, str, str, str], int]:
    """Canonical tally: (tactic_id, tactic_name, technique_id, technique_name) -> number of
    DISTINCT scorable issues hitting that technique.

    `mappings` is an iterable of `AttackMapping` rows; `vulns_by_id` maps
    vulnerability_id -> the `Vulnerability` row, so each mapping can be resolved back to the
    finding that produced it. A mapping whose vulnerability is missing or non-scorable
    contributes nothing.
    """
    keys_by_technique: dict[tuple[str, str, str, str], set[str]] = {}
    # Cache per vulnerability: one row usually carries several technique mappings, and
    # re-deriving its identity for each would re-parse the fingerprint every time.
    key_cache: dict[object, str | None] = {}

    for m in mappings:
        vuln_id = m.vulnerability_id
        if vuln_id not in key_cache:
            vuln = vulns_by_id.get(vuln_id)
            key_cache[vuln_id] = scorable_issue_key(vuln) if vuln is not None else None
        key = key_cache[vuln_id]
        if key is None:
            continue
        technique = (m.tactic_id, m.tactic_name, m.technique_id, m.technique_name)
        keys_by_technique.setdefault(technique, set()).add(key)

    return {t: len(keys) for t, keys in keys_by_technique.items()}


def scorable_vuln_ids(mappings, vulns_by_id) -> set:
    """The vulnerability ids among `mappings` whose findings actually count. Used by the
    kill-chain view, which lists evidencing findings per technique rather than a count."""
    out = set()
    for m in mappings:
        vuln = vulns_by_id.get(m.vulnerability_id)
        if vuln is not None and scorable_issue_key(vuln) is not None:
            out.add(m.vulnerability_id)
    return out
