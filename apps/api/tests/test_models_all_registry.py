"""AUDIT-001 / AUDIT-009 -- the model registry must be COMPLETE, and it must match the migrations.

THE BUG (AUDIT-001)
-------------------
`apps/api/core/models_all.py` exists so that anything touching the ORM outside the FastAPI
router graph -- the Celery worker, and critically Alembic's env.py -- registers every mapped
class on `Base.metadata` first. `PlatformAuditEvent` lives in its own module
(`modules/audit/platform_models.py`) rather than in `modules/audit/models.py`, and was imported
only by `modules/audit/service.py`. models_all did not import it.

Consequence: `alembic revision --autogenerate` / `alembic check` diffed a metadata set that was
MISSING `platform_audit_events` against a database that HAD it, and therefore proposed

    op.drop_table('platform_audit_events')

That table is the NON-cascading record of tenant deletions -- it deliberately has no FK to
workspaces precisely so it outlives the tenant it describes. Autogenerating and applying that
diff would have destroyed the entire tenant-deletion audit trail: the one record that must
survive, deleted by a migration nobody would read closely because "autogenerate wrote it".

WHAT THESE TESTS LOCK
---------------------
1. models_all imports cleanly IN ISOLATION (no FastAPI app, no router side effects) -- that is
   the exact context Alembic and the worker use.
2. PlatformAuditEvent is on Base.metadata after that import alone.
3. The FULL expected table registry is present -- so the next model module added in its own
   file fails here instead of silently vanishing from a migration diff.
4. Every module under modules/*/ that defines a mapped class is reachable from models_all --
   a structural check that catches the NEXT platform_models, not just this one.
5. No table is registered twice (duplicate registration was the stated non-goal of the fix).
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

# Tables that must be on Base.metadata after importing models_all alone. Recorded explicitly
# rather than derived, so that LOSING one is a test failure instead of a silently smaller set.
EXPECTED_TABLES = {
    "agent_decisions", "agent_steps", "ai_plans", "ai_usage", "api_keys", "assets",
    "attack_mappings", "attack_narratives", "audit_events", "authorization_scopes",
    "compliance_mappings", "engagement_state", "evidence", "mfa_recovery_codes",
    "notifications", "permissions", "platform_audit_events", "projects", "refresh_tokens",
    "remediation_events", "remediation_evidence", "remediation_items", "remediations",
    "reports", "risk_acceptances", "risk_assessment_findings", "risk_assessments",
    "risk_scores", "role_permissions", "roles", "scan_schedules", "scans", "targets",
    "tool_runs", "users", "verification_requests", "vulnerabilities",
    "vulnerability_evidence", "workspace_members", "workspaces",
}


def test_models_all_imports_in_isolation_and_registers_platform_audit_event():
    """THE AUDIT-001 REGRESSION LOCK.

    Runs in a SEPARATE interpreter that imports ONLY models_all -- no conftest, no app, no
    router imports that would pull platform_models in transitively and mask the bug. This is
    precisely what db/migrations/env.py does.
    """
    code = (
        "import apps.api.core.models_all\n"
        "from apps.api.core.db import Base\n"
        "names = sorted(Base.metadata.tables)\n"
        "assert 'platform_audit_events' in names, 'MISSING platform_audit_events: ' + repr(names)\n"
        "print(len(names))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, (
        "importing models_all in isolation failed -- Alembic and the Celery worker do exactly "
        f"this.\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    )


def test_full_expected_table_registry_is_present():
    """The complete registry, not just the one table the finding named."""
    import apps.api.core.models_all  # noqa: F401
    from apps.api.core.db import Base

    registered = set(Base.metadata.tables)
    missing = EXPECTED_TABLES - registered
    assert not missing, (
        f"tables absent from Base.metadata: {sorted(missing)}. Alembic autogenerate would "
        "propose DROP TABLE for each of these."
    )


def test_tenant_deletion_audit_table_shape_survives_workspace_deletion():
    """`platform_audit_events` is only useful if it OUTLIVES the workspace. Its whole design is
    'no FK to workspaces' -- an ON DELETE CASCADE would take the deletion record with the
    tenant. Lock that, so a later 'add the missing FK for consistency' cleanup fails here."""
    import apps.api.core.models_all  # noqa: F401
    from apps.api.core.db import Base

    table = Base.metadata.tables["platform_audit_events"]
    ws = table.columns["workspace_id"]
    assert not ws.foreign_keys, (
        "platform_audit_events.workspace_id must have NO foreign key to workspaces -- the "
        "record must survive the tenant's hard deletion."
    )
    # NULLABLE since MBS.SC P8-G (migration e6f7a8b9c0d1): NULL means PLATFORM-SCOPED -- an
    # operator action with genuinely no workspace (the private-scanning emergency kill switch,
    # platform-wide by definition; an action on a SHARED PUBLIC worker, whose own
    # scanner_workers.workspace_id is already NULL). Requiring NOT NULL here would mean those
    # actions could not be audited AT ALL, which is a worse audit-provenance outcome than a
    # nullable column. The property this test actually protects -- that the record OUTLIVES
    # the tenant -- is carried by the no-FK assertions above and below, which still hold.
    assert ws.nullable, (
        "platform_audit_events.workspace_id is nullable BY DESIGN since P8-G: NULL == "
        "platform-scoped. See db/migrations/versions/e6f7a8b9c0d1_*.py and "
        "apps/api/modules/audit/platform_models.py."
    )
    # No FK anywhere on the table may point at workspaces.
    for col in table.columns:
        for fk in col.foreign_keys:
            assert not fk.target_fullname.startswith("workspaces."), (
                f"{col.name} introduces a cascade path back to workspaces: {fk.target_fullname}"
            )


def test_no_table_is_registered_twice():
    """The fix must not double-register a model. SQLAlchemy would normally raise on a duplicate
    __tablename__, but a module imported under two names can slip through; assert the mapped
    classes resolve to distinct tables."""
    import apps.api.core.models_all  # noqa: F401
    from apps.api.core.db import Base

    seen: dict[str, str] = {}
    for mapper in Base.registry.mappers:
        cls = mapper.class_
        tname = cls.__tablename__
        qualified = f"{cls.__module__}.{cls.__name__}"
        if tname in seen:
            assert seen[tname] == qualified, (
                f"table {tname!r} is mapped by two different classes: {seen[tname]} and {qualified}"
            )
        seen[tname] = qualified


def test_every_model_module_is_reachable_from_models_all():
    """STRUCTURAL guard -- catches the NEXT platform_models, not just this one.

    Walks apps/api for modules that define a `__tablename__`, and asserts models_all imports
    each one. A new model file in its own module is exactly how AUDIT-001 happened.
    """
    api_root = REPO_ROOT / "apps" / "api"
    if not api_root.is_dir():
        import pytest
        pytest.skip("application tree not bind-mounted")

    models_all_src = (api_root / "core" / "models_all.py").read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(models_all_src)):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imported.add(f"{node.module}.{alias.name}")

    defining: set[str] = set()
    for path in sorted(api_root.rglob("*.py")):
        parts = path.parts
        if "tests" in parts or "__pycache__" in parts:
            continue
        src = path.read_text(encoding="utf-8")
        if "__tablename__" not in src:
            continue
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        has_table = any(
            isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "__tablename__" for t in n.targets)
            for n in ast.walk(tree)
        )
        if has_table:
            defining.add(
                path.relative_to(REPO_ROOT).with_suffix("").as_posix().replace("/", ".")
            )

    unreachable = {m for m in defining if m not in imported}
    assert not unreachable, (
        "these modules define mapped tables but are NOT imported by core/models_all.py, so "
        "Alembic autogenerate would propose DROP TABLE for their tables: "
        f"{sorted(unreachable)}"
    )
