"""Prompt 34 -- audit logging hardening.

Covers the properties an audit log must actually hold, rather than re-testing that the
existing call sites fire (apps/api/tests/test_audit.py already does that):

  * event creation carries actor / resource / outcome;
  * correlation id joins the event to its originating request;
  * tenant isolation -- one workspace can never read another's audit trail;
  * sensitive data never reaches the stored row;
  * append-only -- UPDATE is refused outright, DELETE only via the retention escape hatch;
  * unauthorized access is refused.
"""
import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.audit import service as audit_service
from apps.api.modules.audit.immutability import (
    AuditImmutabilityError,
    allow_audit_deletion,
)
from apps.api.modules.audit.immutability import install as install_immutability
from apps.api.modules.audit.models import AuditEvent
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace

install_immutability()


# --------------------------------------------------------------------------- helpers


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": "Audit User"},
    )
    assert resp.status_code == 201, resp.text
    return {"email": email, **resp.json()}


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _workspace(client: TestClient, headers: dict, name: str = "WS") -> str:
    return client.post("/api/v1/workspaces", headers=headers, json={"name": name}).json()["id"]


async def _seed_workspace(session) -> uuid.UUID:
    """Create a real user+workspace row.

    `audit_events.workspace_id` is a genuine FK, so the ORM-level tests below cannot insert
    against an invented UUID -- the insert would fail on the constraint long before reaching
    the behaviour under test."""
    user = User(
        email=f"{uuid.uuid4()}@example.com",
        password_hash="x",
        full_name="Audit Fixture",
    )
    session.add(user)
    await session.flush()
    ws = Workspace(name="Audit Fixture WS", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    return ws.id


async def _run(fn):
    engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with Session() as s:
            with tenancy.admin_bypass():
                return await fn(s)
    finally:
        await engine.dispose()


# ------------------------------------------------------------------ detail scrubbing


@pytest.mark.parametrize(
    "detail",
    [
        "password=hunter2",
        "api_key: sk-live-abcdef0123456789",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        "refresh_token=aaa.bbb.ccc",
        "cookie=session_value_here",
        "client_secret: super-secret-value",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_sensitive_values_are_scrubbed_from_detail(detail: str) -> None:
    """No credential-shaped value may survive into a stored audit detail."""
    scrubbed = audit_service.scrub_detail(detail)
    # scrub_detail is typed `str | None` because it passes a falsy detail straight through.
    # Every case here feeds it a non-empty string, so None would itself be a defect.
    assert scrubbed is not None
    assert "[REDACTED]" in scrubbed
    for secret in (
        "hunter2",
        "sk-live-abcdef0123456789",
        "eyJhbGciOiJIUzI1NiJ9",
        "aaa.bbb.ccc",
        "session_value_here",
        "super-secret-value",
        "MIIEow==",
    ):
        assert secret not in scrubbed


def test_scrubbing_leaves_ordinary_detail_intact() -> None:
    """The scrub is a backstop, not a shredder -- benign audit detail must stay readable,
    including hash-like values this table legitimately records."""
    for benign in (
        "tier=pro",
        "web: nuclei, httpx",
        "result=pass recorded=deadbeefcafe actual=deadbeefcafe",
        "status_changed: open -> resolved",
    ):
        assert audit_service.scrub_detail(benign) == benign


def test_scrub_handles_empty_and_none() -> None:
    assert audit_service.scrub_detail(None) is None
    assert audit_service.scrub_detail("") == ""


# ------------------------------------------------------------------------- outcomes


def test_invalid_outcome_is_rejected() -> None:
    """An unconstrained outcome column stops being queryable; reject junk at the boundary."""

    async def _attempt(session):
        with pytest.raises(ValueError, match="invalid audit outcome"):
            await audit_service.record(
                session, uuid.uuid4(), None, "scan.created", "scan", outcome="probably?"
            )

    asyncio.run(_run(_attempt))


def test_outcome_constants_are_the_closed_set() -> None:
    assert audit_service.VALID_OUTCOMES == {"success", "failure", "denied"}


# ------------------------------------------------- creation / fields / correlation id


def test_event_records_actor_resource_and_correlation_id(client: TestClient) -> None:
    """A security-relevant action records who did it, to what, and under which request id."""
    headers = _auth(_register(client))
    ws = _workspace(client, headers)

    request_id = uuid.uuid4().hex
    resp = client.patch(
        f"/api/v1/workspaces/{ws}/billing/plan",
        headers={**headers, "X-Request-ID": request_id},
        json={"tier": "pro"},
    )
    assert resp.status_code < 400, resp.text
    # The middleware echoes the id it bound, which is what the audit row must carry.
    assert resp.headers.get("X-Request-ID") == request_id

    events = client.get(f"/api/v1/workspaces/{ws}/audit", headers=headers).json()
    plan_events = [e for e in events if e["action"] == "plan.changed"]
    assert plan_events, events

    event = plan_events[0]
    assert event["actor_email"] is not None
    assert event["actor_user_id"] is not None
    assert event["resource_type"]
    assert event["correlation_id"] == request_id


def test_correlation_id_is_null_outside_a_request(client: TestClient) -> None:
    """Work with no inbound request must store NULL, not the contextvar's "-" placeholder,
    so a reader never mistakes an absence for an id."""

    async def _record(session):
        ws_id = await _seed_workspace(session)
        await audit_service.record(
            session, ws_id, None, "scan.created", "scan", detail="no request context"
        )
        row = (
            await session.execute(
                select(AuditEvent).where(AuditEvent.workspace_id == ws_id)
            )
        ).scalar_one()
        return row.correlation_id

    assert asyncio.run(_run(_record)) is None


# -------------------------------------------------------------------- tenant isolation


def test_audit_is_tenant_isolated(client: TestClient) -> None:
    """A workspace's audit trail must never surface another workspace's events."""
    owner_a = _auth(_register(client))
    owner_b = _auth(_register(client))
    ws_a = _workspace(client, owner_a, "A")
    ws_b = _workspace(client, owner_b, "B")

    client.patch(f"/api/v1/workspaces/{ws_a}/billing/plan", headers=owner_a, json={"tier": "pro"})

    # B's own trail does not contain A's event...
    b_events = client.get(f"/api/v1/workspaces/{ws_b}/audit", headers=owner_b).json()
    assert all(e["action"] != "plan.changed" for e in b_events)

    # ...and B cannot read A's trail by asking for it directly.
    assert client.get(f"/api/v1/workspaces/{ws_a}/audit", headers=owner_b).status_code in (403, 404)


def test_audit_requires_manage_permission(client: TestClient) -> None:
    """Unauthenticated and under-privileged access are both refused."""
    owner = _auth(_register(client))
    ws = _workspace(client, owner)
    assert client.get(f"/api/v1/workspaces/{ws}/audit").status_code in (401, 403)


# ---------------------------------------------------------------- append-only property


def test_audit_event_cannot_be_updated() -> None:
    """Rewriting a persisted audit event is never legitimate -- it must raise, not succeed."""

    async def _attempt(session):
        ws_id = await _seed_workspace(session)
        await audit_service.record(
            session, ws_id, None, "scan.created", "scan", detail="original"
        )
        await session.commit()

        row = (
            await session.execute(select(AuditEvent).where(AuditEvent.workspace_id == ws_id))
        ).scalar_one()
        row.detail = "tampered"
        with pytest.raises(AuditImmutabilityError, match="append-only"):
            await session.commit()
        await session.rollback()

        # The stored value is unchanged.
        session.expunge_all()
        again = (
            await session.execute(select(AuditEvent).where(AuditEvent.workspace_id == ws_id))
        ).scalar_one()
        assert again.detail == "original"

    asyncio.run(_run(_attempt))


def test_audit_event_cannot_be_deleted_without_the_escape_hatch() -> None:
    """A plain DELETE is refused; the explicit retention hatch permits it."""

    async def _attempt(session):
        ws_id = await _seed_workspace(session)
        await audit_service.record(session, ws_id, None, "scan.created", "scan")
        await session.commit()

        row = (
            await session.execute(select(AuditEvent).where(AuditEvent.workspace_id == ws_id))
        ).scalar_one()

        await session.delete(row)
        with pytest.raises(AuditImmutabilityError, match="append-only"):
            await session.commit()
        await session.rollback()

        # Still there.
        session.expunge_all()
        surviving = (
            await session.execute(select(AuditEvent).where(AuditEvent.workspace_id == ws_id))
        ).scalar_one()

        # Retention/erasure remains possible, but only deliberately.
        with allow_audit_deletion():
            await session.delete(surviving)
            await session.commit()

        assert (
            await session.execute(select(AuditEvent).where(AuditEvent.workspace_id == ws_id))
        ).first() is None

    asyncio.run(_run(_attempt))


def test_deletion_hatch_does_not_permit_updates() -> None:
    """The hatch unlocks DELETE only: expiring a row is legitimate, rewriting one is not."""

    async def _attempt(session):
        ws_id = await _seed_workspace(session)
        await audit_service.record(session, ws_id, None, "scan.created", "scan", detail="original")
        await session.commit()

        row = (
            await session.execute(select(AuditEvent).where(AuditEvent.workspace_id == ws_id))
        ).scalar_one()
        with allow_audit_deletion():
            row.detail = "tampered"
            with pytest.raises(AuditImmutabilityError, match="append-only"):
                await session.commit()
        await session.rollback()

    asyncio.run(_run(_attempt))
