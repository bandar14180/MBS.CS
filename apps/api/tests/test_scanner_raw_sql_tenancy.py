"""MBS.SC Phase 15 -- raw-SQL tenancy audit for the scanner/evidence persistence paths.

WHY THIS FILE EXISTS
--------------------
`apps.api.core.tenancy` filters ORM queries. It does NOT touch `session.execute(text(...))`
-- a raw statement goes to the database exactly as written. So every raw statement in a
scanner or evidence path is, by construction, outside the automatic protection, and each
one needs its own justification.

There are exactly three safe shapes, and this file asserts that every audited statement is
one of them:

  A. KEYED BY A TRUSTED INTERNAL ID. `WHERE id = :scan_id` where the id came from the
     platform (a Celery task argument the platform itself enqueued), never from a client.
     Reading one row by trusted primary key discloses nothing across tenants, and it is
     precisely how the worker BOOTSTRAPS the workspace it then binds.

  B. EXPLICITLY WORKSPACE-SCOPED. The statement carries its own workspace predicate.

  C. DELIBERATELY CROSS-TENANT SWEEPS that neither read nor move tenant data -- the orphan
     reaper (marks dead scans failed) and the queued-relay (re-dispatches stranded scans).
     These must iterate every workspace to do their job. They are safe because they change
     only lifecycle columns and disclose nothing to any tenant.

A NEW raw statement in these files that matches none of the above should fail the review
this test encodes, not slip through.
"""
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

# The files whose raw SQL touches scan / tool_run / evidence data.
AUDITED = [
    "apps/api/scanner_engine/orchestrator.py",
    "apps/api/celery_app/tasks/scan_tasks.py",
    "apps/api/celery_app/shutdown.py",
]

_SQL_VERB = re.compile(r"\b(SELECT|UPDATE|DELETE|INSERT)\b", re.IGNORECASE)
_TENANT_TABLES = re.compile(
    r"\bFROM\s+(tool_runs|evidence|vulnerabilities|findings|targets|projects|assets)\b"
    r"|\bUPDATE\s+(tool_runs|evidence|vulnerabilities|findings|targets|projects|assets)\b",
    re.IGNORECASE,
)


def _pydantic_model_fields(source: str, class_name: str) -> set:
    """Field names declared on a pydantic model, parsed from the AST.

    Parsed rather than string-sliced: an earlier version split the file on "class " and
    picked up unrelated endpoint code, which made the assertion pass/fail for the wrong
    reason. The AST asks the precise question -- what does THIS class declare?
    """
    import ast

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                stmt.target.id
                for stmt in node.body
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
            }
    raise AssertionError(f"{class_name} not found")


def _raw_sql_statements(path: Path):
    """Every `text("...")` literal in the file, joined across implicit concatenation."""
    source = path.read_text(encoding="utf-8")
    out = []
    for match in re.finditer(r"text\(\s*(.*?)\)\s*,?\s*\n", source, re.DOTALL):
        blob = match.group(1)
        parts = re.findall(r'"([^"]*)"', blob)
        if not parts:
            continue
        stmt = " ".join(parts)
        if _SQL_VERB.search(stmt):
            out.append(" ".join(stmt.split()))
    return out


@pytest.mark.parametrize("relpath", AUDITED)
def test_every_raw_statement_is_scoped_or_a_known_sweep(relpath):
    """Each audited statement must be keyed by a trusted id, carry a workspace predicate,
    or be one of the explicitly-justified cross-tenant lifecycle sweeps."""
    path = REPO_ROOT / relpath
    if not path.exists():
        pytest.skip(f"{relpath} not present")

    for stmt in _raw_sql_statements(path):
        upper = stmt.upper()

        # (A) keyed by a trusted internal id
        keyed = bool(re.search(r"WHERE\s+(\w+\.)?ID\s*=\s*:", upper)) or ":IDS" in upper
        # (B) explicit workspace scoping
        workspace_scoped = "WORKSPACE_ID" in upper or "JOIN WORKSPACES" in upper
        # (C) the justified lifecycle sweeps
        #
        # These are PLATFORM MAINTENANCE, not tenant queries: they repair rows whose owning
        # execution is provably gone, and they must run across every tenant precisely
        # because a dead worker is not scoped to one. Each is an atomic conditional UPDATE
        # whose source state ('running') is what makes it idempotent and race-free; none
        # reads or discloses tenant data, and none can be reached from a request.
        lifecycle_sweep = (
            upper.startswith("UPDATE SCANS SET STATUS = 'FAILED'")   # orphan reaper
            or upper.startswith("UPDATE SCANS SET STATUS = 'QUEUED'")  # shutdown requeue
            or upper.startswith("UPDATE SCANS SET CELERY_TASK_ID")     # relay stamp
            # TOOL-RUN orphan reconciliation (incident 615d0e0b). Repairs `tool_runs` left
            # 'running' under an ALREADY-TERMINAL scan -- a state nothing can leave
            # legitimately, because the scan that would have reported the result is over.
            # Cross-tenant for the same reason the scan reaper is: the rows are stranded by
            # worker/transaction failures, which respect no workspace boundary. The JOIN to
            # `scans` is a lifecycle predicate (parent must be terminal + past the grace
            # period), not a tenancy one, and the statement writes only status/completed_at/
            # error_message on rows that are already beyond any tenant's reach.
            or upper.startswith("UPDATE TOOL_RUNS TR JOIN SCANS S")
        )
        # Bare connectivity probes carry no table at all.
        trivial = upper.strip() in {"SELECT 1"}

        assert keyed or workspace_scoped or lifecycle_sweep or trivial, (
            f"{relpath}: raw SQL is neither id-keyed, workspace-scoped, nor a justified "
            f"sweep -- tenancy.py does NOT filter raw SQL:\n    {stmt}"
        )


@pytest.mark.parametrize("relpath", AUDITED)
def test_no_raw_statement_reads_a_tenant_table_without_scoping(relpath):
    """The strict rule for TENANT-OWNED tables (tool_runs/evidence/vulnerabilities/...):
    a raw statement touching one must name a workspace or be keyed by trusted ids.

    `scans` is excluded deliberately -- it is tenancy-EXEMPT precisely so the worker can
    bootstrap from a trusted scan_id, and its sweeps are covered by the test above."""
    path = REPO_ROOT / relpath
    if not path.exists():
        pytest.skip(f"{relpath} not present")

    for stmt in _raw_sql_statements(path):
        if not _TENANT_TABLES.search(stmt):
            continue
        upper = stmt.upper()
        assert "WORKSPACE_ID" in upper or ":IDS" in upper or re.search(r"=\s*:", upper), (
            f"{relpath}: raw SQL touches a tenant-owned table with no workspace scoping "
            f"and no bound key:\n    {stmt}"
        )


def test_evidence_is_never_written_by_raw_sql_in_the_scanner_paths():
    """Evidence must go through the validated sink (digest, size, type, tenancy), never a
    hand-written INSERT that would skip all four."""
    for relpath in AUDITED:
        path = REPO_ROOT / relpath
        if not path.exists():
            continue
        for stmt in _raw_sql_statements(path):
            upper = stmt.upper()
            assert not re.search(r"INSERT\s+INTO\s+EVIDENCE\b", upper), (
                f"{relpath} writes evidence via raw SQL, bypassing result_sink validation:"
                f"\n    {stmt}"
            )


def test_manager_evidence_path_binds_workspace_from_the_scan_row():
    """The evidence endpoint must derive the workspace from the SCAN row, never from the
    request -- otherwise a worker could file evidence under another tenant."""
    source = (REPO_ROOT / "apps/api/scanner_manager/app.py").read_text(encoding="utf-8")
    body = source.split("async def submit_evidence", 1)[1]
    assert "_authorize_scan_for_worker" in body, "evidence endpoint skips scan authorization"
    # workspace_scope(), not a bare bind_workspace(): in a request handler a bare bind
    # outlives the response and could leak this tenant's binding into the next request.
    assert "tenancy.workspace_scope(scan.workspace_id)" in body, (
        "evidence endpoint does not scope the workspace from the scan row"
    )
    # There must be no workspace_id field on the request model at all.
    fields = _pydantic_model_fields(source, "EvidenceIn")
    assert "workspace_id" not in fields, (
        f"EvidenceIn accepts a workspace_id -- a worker must never name its own tenant "
        f"(fields: {sorted(fields)})"
    )


def test_lease_endpoint_does_not_accept_a_tenant_or_site_from_the_worker():
    """Lease authorization must come from the worker's row, not its request body."""
    source = (REPO_ROOT / "apps/api/scanner_manager/app.py").read_text(encoding="utf-8")
    fields = _pydantic_model_fields(source, "LeaseIn")
    for forbidden in ("workspace_id", "site_id", "pool_id"):
        assert forbidden not in fields, (
            f"LeaseIn accepts {forbidden} -- a worker must not supply its own authorization"
        )
    # Only a batch-size hint is accepted, and it cannot widen authorization.
    assert fields == {"max_jobs"}, fields
