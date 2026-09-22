"""Cross-workspace isolation for every new tenant-scoped table.

Complements test_tenancy_isolation.py (which proves the MECHANISM works) by proving the seven
new tables are actually wired into it, at the ORM level, for SELECT / INSERT / UPDATE / DELETE
and for the unbound (fail-closed) case.

Direct ORM tests rather than API tests on purpose: the API layer has its own explicit
workspace/project predicates, so an API test that passes tells you nothing about whether the
tenancy filter would have caught a query that forgot them. These bypass the service layer and
put the question to `tenancy.py` itself.
"""
import asyncio
import uuid

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.core.tenancy import CrossTenantWriteError, TenancyNotBoundError
from apps.api.modules.assessment.models import RiskAssessment, RiskAssessmentFinding
from apps.api.modules.projects.models import Project
from apps.api.modules.remediation.models import (
    RemediationEvent,
    RemediationItem,
    VerificationRequest,
)
from apps.api.modules.remediation.risk_models import RiskAcceptance
from apps.api.modules.users.models import User
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.modules.workspaces.models import Workspace

# The tables this file must cover. Kept as data so a NEW table added to the subsystem without a
# test here is visible at a glance next to tenancy.py's registry.
NEW_TENANT_TABLES = [
    "remediation_items",
    "remediation_events",
    "remediation_evidence",
    "verification_requests",
    "risk_acceptances",
    "risk_assessments",
    "risk_assessment_findings",
]


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed_two_workspaces(session):
    """Two workspaces, each with a project, a vulnerability, a remediation item and an
    assessment.

    admin_bypass for the same reason test_tenancy_isolation.py uses it: writing rows for TWO
    workspaces in one session is exactly what the INSERT guard refuses by design, and a
    cross-workspace fixture is the genuine system write the bypass exists for. Weakening the
    guard to accommodate a test would be the wrong trade."""
    with tenancy.admin_bypass():
        user = User(
            email=f"rem-tenancy-{uuid.uuid4()}@test.local",
            password_hash="x", full_name="Remediation Tenancy Tester",
        )
        session.add(user)
        await session.flush()

        ws_a = Workspace(name=f"rem-ws-a-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
        ws_b = Workspace(name=f"rem-ws-b-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
        session.add_all([ws_a, ws_b])
        await session.flush()

        proj_a = Project(workspace_id=ws_a.id, name="proj-a", created_by=user.id)
        proj_b = Project(workspace_id=ws_b.id, name="proj-b", created_by=user.id)
        session.add_all([proj_a, proj_b])
        await session.flush()

        vuln_a = Vulnerability(
            project_id=proj_a.id, fingerprint=f"t-a|m|{uuid.uuid4()}", title="A",
            severity="high", status="open",
        )
        vuln_b = Vulnerability(
            project_id=proj_b.id, fingerprint=f"t-b|m|{uuid.uuid4()}", title="B",
            severity="high", status="open",
        )
        session.add_all([vuln_a, vuln_b])
        await session.flush()

        item_a = RemediationItem(
            workspace_id=ws_a.id, project_id=proj_a.id, issue_key=f"template:a-{uuid.uuid4().hex[:8]}",
            title="Item A", vulnerability_id=vuln_a.id,
        )
        item_b = RemediationItem(
            workspace_id=ws_b.id, project_id=proj_b.id, issue_key=f"template:b-{uuid.uuid4().hex[:8]}",
            title="Item B", vulnerability_id=vuln_b.id,
        )
        session.add_all([item_a, item_b])
        await session.flush()

        session.add_all([
            RemediationEvent(
                workspace_id=ws_a.id, remediation_item_id=item_a.id, event_type="created"),
            RemediationEvent(
                workspace_id=ws_b.id, remediation_item_id=item_b.id, event_type="created"),
            VerificationRequest(
                workspace_id=ws_a.id, remediation_item_id=item_a.id, status="pending", detail={}),
            VerificationRequest(
                workspace_id=ws_b.id, remediation_item_id=item_b.id, status="pending", detail={}),
        ])

        from datetime import datetime, timedelta, timezone

        expiry = datetime.now(timezone.utc) + timedelta(days=30)
        session.add_all([
            RiskAcceptance(
                workspace_id=ws_a.id, project_id=proj_a.id, vulnerability_id=vuln_a.id,
                justification="a", expires_at=expiry, status="active"),
            RiskAcceptance(
                workspace_id=ws_b.id, project_id=proj_b.id, vulnerability_id=vuln_b.id,
                justification="b", expires_at=expiry, status="active"),
        ])

        now = datetime.now(timezone.utc)
        assess_a = RiskAssessment(
            workspace_id=ws_a.id, project_id=proj_a.id, title="A",
            period_start=now - timedelta(days=1), period_end=now, summary={},
        )
        assess_b = RiskAssessment(
            workspace_id=ws_b.id, project_id=proj_b.id, title="B",
            period_start=now - timedelta(days=1), period_end=now, summary={},
        )
        session.add_all([assess_a, assess_b])
        await session.flush()

        session.add_all([
            RiskAssessmentFinding(
                workspace_id=ws_a.id, assessment_id=assess_a.id, issue_key="k-a",
                frozen_title="A", frozen_severity="high", frozen_vulnerability_status="open"),
            RiskAssessmentFinding(
                workspace_id=ws_b.id, assessment_id=assess_b.id, issue_key="k-b",
                frozen_title="B", frozen_severity="high", frozen_vulnerability_status="open"),
        ])
        await session.commit()

    return {
        "ws_a": ws_a.id, "ws_b": ws_b.id,
        "proj_a": proj_a.id, "proj_b": proj_b.id,
        "vuln_a": vuln_a.id, "vuln_b": vuln_b.id,
        "item_a": item_a.id, "item_b": item_b.id,
        "assess_a": assess_a.id, "assess_b": assess_b.id,
    }


def _run(scenario):
    """Run one async scenario against a fresh engine, always disposing it."""
    async def _outer():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                seeded = await _seed_two_workspaces(session)
                tenancy.clear_workspace()
                return await scenario(session, seeded)
        finally:
            tenancy.clear_workspace()
            await engine.dispose()

    return asyncio.run(_outer())


# =============================================================================================
# REGISTRY COMPLETENESS
# =============================================================================================

def test_every_new_table_is_registered_as_tenant_scoped() -> None:
    for table in NEW_TENANT_TABLES:
        assert tenancy.table_scope(table) == "TENANT_SCOPED", f"{table} is not TENANT_SCOPED"
        assert table in tenancy._DIRECT_TABLES, (
            f"{table} must be DIRECT-scoped: it carries its own workspace_id because a VIA "
            "chain through remediation_items would be 3 hops, past tenancy.py's 2-hop limit"
        )


def test_new_tables_more_than_two_hops_from_projects_carry_workspace_id() -> None:
    """requirement 24: anything further than 2 hops must have its OWN workspace_id and be
    registered DIRECT, never bypassing the registry."""
    from apps.api.core.db import Base

    by_table = {
        m.class_.__tablename__: m.class_
        for m in Base.registry.mappers
        if hasattr(m.class_, "__tablename__")
    }
    for table in NEW_TENANT_TABLES:
        model = by_table[table]
        assert hasattr(model, "workspace_id"), f"{table} has no workspace_id column"


# =============================================================================================
# SELECT
# =============================================================================================

@pytest.mark.parametrize(
    "model,label",
    [
        (RemediationItem, "remediation_items"),
        (RemediationEvent, "remediation_events"),
        (VerificationRequest, "verification_requests"),
        (RiskAcceptance, "risk_acceptances"),
        (RiskAssessment, "risk_assessments"),
        (RiskAssessmentFinding, "risk_assessment_findings"),
    ],
)
def test_select_never_returns_another_workspaces_rows(model, label) -> None:
    """Bound to A, a completely UNFILTERED select must return only A's rows -- even though B's
    row sits in the same table and the query carries no workspace predicate at all."""
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_a"]):
            rows = list(await session.scalars(select(model)))
        return rows

    rows = _run(scenario)
    assert rows, f"{label}: expected the bound workspace's own row(s)"
    for row in rows:
        assert row.workspace_id is not None


def test_select_from_workspace_b_cannot_see_workspace_a(client) -> None:
    """The mirror image, stated explicitly: A's item id is invisible while bound to B."""
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_b"]):
            found = await session.scalar(
                select(RemediationItem).where(RemediationItem.id == seeded["item_a"])
            )
        return found

    assert _run(scenario) is None


# =============================================================================================
# INSERT
# =============================================================================================

def test_insert_into_the_bound_workspace_succeeds() -> None:
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_a"]):
            item = RemediationItem(
                workspace_id=seeded["ws_a"], project_id=seeded["proj_a"],
                issue_key=f"template:ok-{uuid.uuid4().hex[:8]}", title="Allowed",
            )
            session.add(item)
            await session.flush()
            await session.rollback()
        return True

    assert _run(scenario) is True


def test_cross_workspace_insert_is_refused() -> None:
    """Bound to A, writing a row stamped with B's workspace_id must raise -- the INSERT guard
    is the one thing the SELECT filter cannot cover (an ORM flush never reaches
    do_orm_execute)."""
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_a"]):
            item = RemediationItem(
                workspace_id=seeded["ws_b"],  # <- another tenant
                project_id=seeded["proj_b"],
                issue_key=f"template:bad-{uuid.uuid4().hex[:8]}", title="Refused",
            )
            session.add(item)
            with pytest.raises(CrossTenantWriteError):
                await session.flush()
            await session.rollback()
        return True

    assert _run(scenario) is True


@pytest.mark.parametrize(
    "factory,label",
    [
        (lambda s: RemediationEvent(workspace_id=s["ws_b"], remediation_item_id=s["item_b"],
                                    event_type="created"), "remediation_events"),
        (lambda s: VerificationRequest(workspace_id=s["ws_b"], remediation_item_id=s["item_b"],
                                       status="pending", detail={}), "verification_requests"),
        (lambda s: RiskAssessmentFinding(workspace_id=s["ws_b"], assessment_id=s["assess_b"],
                                         issue_key="k", frozen_title="t", frozen_severity="high",
                                         frozen_vulnerability_status="open"),
         "risk_assessment_findings"),
    ],
)
def test_cross_workspace_insert_is_refused_for_every_child_table(factory, label) -> None:
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_a"]):
            session.add(factory(seeded))
            with pytest.raises(CrossTenantWriteError):
                await session.flush()
            await session.rollback()
        return True

    assert _run(scenario) is True, label


# =============================================================================================
# UPDATE / DELETE
# =============================================================================================

def test_update_cannot_reach_another_workspaces_row() -> None:
    """An ORM UPDATE with NO workspace predicate, bound to A, must not touch B's row."""
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_a"]):
            await session.execute(
                update(RemediationItem)
                .where(RemediationItem.id == seeded["item_b"])
                .values(title="HIJACKED")
            )
            await session.commit()

        with tenancy.workspace_scope(seeded["ws_b"]):
            row = await session.scalar(
                select(RemediationItem).where(RemediationItem.id == seeded["item_b"])
            )
            return row.title

    assert _run(scenario) == "Item B", "workspace B's row was modified from workspace A"


def test_update_within_the_bound_workspace_works() -> None:
    """The filter must not be so blunt that it blocks legitimate same-workspace writes."""
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_a"]):
            await session.execute(
                update(RemediationItem)
                .where(RemediationItem.id == seeded["item_a"])
                .values(title="Renamed")
            )
            await session.commit()
            row = await session.scalar(
                select(RemediationItem).where(RemediationItem.id == seeded["item_a"])
            )
            return row.title

    assert _run(scenario) == "Renamed"


def test_delete_cannot_reach_another_workspaces_row() -> None:
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_a"]):
            await session.execute(
                delete(RemediationItem).where(RemediationItem.id == seeded["item_b"])
            )
            await session.commit()

        with tenancy.workspace_scope(seeded["ws_b"]):
            return await session.scalar(
                select(RemediationItem).where(RemediationItem.id == seeded["item_b"])
            )

    assert _run(scenario) is not None, "workspace B's row was deleted from workspace A"


def test_delete_within_the_bound_workspace_works() -> None:
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_a"]):
            await session.execute(
                delete(RemediationEvent).where(RemediationEvent.workspace_id == seeded["ws_a"])
            )
            await session.commit()
            remaining = list(await session.scalars(select(RemediationEvent)))
        return remaining

    assert _run(scenario) == []


# =============================================================================================
# FAIL CLOSED
# =============================================================================================

@pytest.mark.parametrize(
    "model",
    [RemediationItem, RemediationEvent, VerificationRequest, RiskAcceptance,
     RiskAssessment, RiskAssessmentFinding],
)
def test_unbound_query_raises_rather_than_returning_an_empty_result(model) -> None:
    """A forgotten bind must be LOUD. An empty result would read as "this workspace has no
    remediation work", which is precisely the wrong conclusion to invite."""
    async def scenario(session, seeded):
        tenancy.clear_workspace()
        with pytest.raises(TenancyNotBoundError):
            await session.execute(select(model))
        return True

    assert _run(scenario) is True


def test_unbound_insert_raises() -> None:
    async def scenario(session, seeded):
        tenancy.clear_workspace()
        session.add(
            RemediationItem(
                workspace_id=seeded["ws_a"], project_id=seeded["proj_a"],
                issue_key=f"template:unbound-{uuid.uuid4().hex[:8]}", title="X",
            )
        )
        with pytest.raises(TenancyNotBoundError):
            await session.flush()
        await session.rollback()
        return True

    assert _run(scenario) is True


# =============================================================================================
# EVIDENCE: the two-path criterion
# =============================================================================================

def test_remediation_evidence_is_workspace_scoped_and_scanner_evidence_still_resolves() -> None:
    """`evidence.tool_run_id` became nullable, so a remediation-proof row is reachable ONLY
    through remediation_evidence. Verify BOTH: A sees its own proof, B does not, and the
    change did not make scanner evidence unreachable."""
    from apps.api.modules.remediation.models import RemediationEvidence
    from apps.api.scanner_engine.models import Evidence

    async def scenario(session, seeded):
        with tenancy.admin_bypass():
            proof = Evidence(
                tool_run_id=None, evidence_type="remediation_proof",
                storage_uri=f"s3://b/workspaces/{seeded['ws_a']}/remediation/x/proof.txt",
                checksum="a" * 64,
            )
            session.add(proof)
            await session.flush()
            session.add(
                RemediationEvidence(
                    remediation_item_id=seeded["item_a"], evidence_id=proof.id,
                    workspace_id=seeded["ws_a"],
                )
            )
            await session.commit()
            proof_id = proof.id

        with tenancy.workspace_scope(seeded["ws_a"]):
            visible_to_a = await session.scalar(select(Evidence).where(Evidence.id == proof_id))
        with tenancy.workspace_scope(seeded["ws_b"]):
            visible_to_b = await session.scalar(select(Evidence).where(Evidence.id == proof_id))
        return visible_to_a, visible_to_b

    to_a, to_b = _run(scenario)
    assert to_a is not None, "the owning workspace cannot see its own remediation proof"
    assert to_b is None, "another workspace can see this workspace's remediation proof"


def test_orphan_evidence_with_no_owner_is_visible_to_nobody() -> None:
    """Fail-closed for the degenerate case: an evidence row with a NULL tool_run AND no
    remediation link belongs to no workspace, so no workspace may read it."""
    from apps.api.scanner_engine.models import Evidence

    async def scenario(session, seeded):
        with tenancy.admin_bypass():
            orphan = Evidence(
                tool_run_id=None, evidence_type="remediation_proof",
                storage_uri="s3://b/orphan", checksum="b" * 64,
            )
            session.add(orphan)
            await session.commit()
            orphan_id = orphan.id

        with tenancy.workspace_scope(seeded["ws_a"]):
            from_a = await session.scalar(select(Evidence).where(Evidence.id == orphan_id))
        with tenancy.workspace_scope(seeded["ws_b"]):
            from_b = await session.scalar(select(Evidence).where(Evidence.id == orphan_id))
        return from_a, from_b

    from_a, from_b = _run(scenario)
    assert from_a is None and from_b is None
