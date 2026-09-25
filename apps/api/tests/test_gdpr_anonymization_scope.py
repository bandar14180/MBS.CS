"""AUDIT-008 -- the GDPR audit-actor anonymization UPDATE must run ONCE, and still be global.

THE BUG
-------
`_anonymize_audit_actor()` looked up every workspace the user was a member of and then, inside
that loop, executed:

    UPDATE audit_events SET actor_email = :anon
     WHERE actor_user_id = :uid AND actor_email IS NOT NULL

The statement carries NO workspace predicate. Under the old PostgreSQL design that was fine --
FORCE RLS plus a per-workspace GUC scoped it implicitly. After the MySQL cutover there is no
RLS and no GUC, and the surrounding `bind_workspace()` does not scope RAW SQL at all (the
tenancy filter hooks the ORM, which raw SQL never enters). So every iteration re-executed the
identical GLOBAL statement: the first pass anonymized everything, and passes 2..N matched
nothing thanks to `actor_email IS NOT NULL` while still costing a full round trip. A user in
50 workspaces paid 50 UPDATEs to do the work of one.

Removing the loop is not merely an optimisation -- it is more correct. Erasure now also reaches
events in workspaces whose membership row was already deleted, which the old
membership-driven loop silently MISSED.

WHAT THESE TESTS PIN
--------------------
1. One effective UPDATE (counted at the driver), not one per workspace.
2. Still global: an actor's events are anonymized in EVERY workspace, including one they are
   no longer a member of.
3. No collateral damage: other users' events, and other columns, are untouched.
"""
from __future__ import annotations

import asyncio
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.users.service import ANONYMIZED_ACTOR_EMAIL

_PW = "correct horse battery staple"


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": _PW, "full_name": "Multi WS"},
    )
    assert r.status_code == 201, r.text
    tokens = r.json()
    me = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200, me.text
    return {"email": email, "id": me.json()["id"], **tokens}


def _auth(t: dict) -> dict:
    return {"Authorization": f"Bearer {t['access_token']}"}


def _create_workspace(client: TestClient, headers: dict, name: str) -> str:
    r = client.post("/api/v1/workspaces", headers=headers, json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _insert_audit_event(workspace_id: str, user_id: str, email: str) -> str:
    eid = str(uuid.uuid4())
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    try:
        async with eng.begin() as c:
            tenancy.bind_workspace(workspace_id)
            await c.execute(
                text(
                    "INSERT INTO audit_events "
                    "(id, workspace_id, actor_user_id, actor_email, action, resource_type, created_at) "
                    "VALUES (:id, :wid, :uid, :email, 'test.action', 'test', now())"
                ),
                {"id": eid, "wid": workspace_id, "uid": user_id, "email": email},
            )
    finally:
        await eng.dispose()
    return eid


async def _emails_by_event(event_ids: list[str]) -> dict[str, str | None]:
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    try:
        async with eng.connect() as c:
            rows = (
                await c.execute(
                    text("SELECT id, actor_email FROM audit_events WHERE id IN :ids").bindparams(
                        __import__("sqlalchemy").bindparam("ids", expanding=True)
                    ),
                    {"ids": event_ids},
                )
            ).all()
            return {str(r[0]): r[1] for r in rows}
    finally:
        await eng.dispose()


def test_anonymization_is_global_and_runs_once(client: TestClient) -> None:
    """THE AUDIT-008 LOCK: multiple workspaces, matching actor in each, exactly ONE UPDATE,
    and every one of the actor's events anonymized regardless of workspace."""
    victim = _register(client)
    other = _register(client)

    # Three workspaces owned by the victim, plus audit events in each.
    ws_ids = [_create_workspace(client, _auth(victim), f"WS-{i}") for i in range(3)]
    victim_events = [
        asyncio.run(_insert_audit_event(ws, victim["id"], victim["email"])) for ws in ws_ids
    ]
    # An event by ANOTHER user, in one of the same workspaces -- must not be touched.
    other_event = asyncio.run(_insert_audit_event(ws_ids[0], other["id"], other["email"]))

    # Count the anonymization UPDATEs actually issued.
    from apps.api.modules.users import service as users_service

    executed: list[str] = []

    async def _run_anonymize():
        from sqlalchemy.ext.asyncio import async_sessionmaker

        eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(eng, expire_on_commit=False)
        try:
            async with maker() as session:
                orig = session.execute

                async def _counting_execute(stmt, *a, **kw):
                    sql = str(stmt)
                    if "UPDATE audit_events" in sql and "actor_email" in sql:
                        executed.append(sql)
                    return await orig(stmt, *a, **kw)

                session.execute = _counting_execute
                await users_service._anonymize_audit_actor(session, uuid.UUID(victim["id"]))
                await session.commit()
        finally:
            await eng.dispose()

    asyncio.run(_run_anonymize())

    assert len(executed) == 1, (
        f"the anonymization UPDATE ran {len(executed)} times for a user in {len(ws_ids)} "
        "workspaces -- it must be issued exactly once (AUDIT-008)"
    )

    emails = asyncio.run(_emails_by_event(victim_events + [other_event]))
    for eid in victim_events:
        assert emails[eid] == ANONYMIZED_ACTOR_EMAIL, (
            f"event {eid} was NOT anonymized -- erasure must span every workspace"
        )
    assert emails[other_event] == other["email"], (
        "another user's audit event was modified -- the UPDATE must match on actor_user_id only"
    )


def test_anonymization_reaches_workspaces_without_a_membership_row(client: TestClient) -> None:
    """Erasure must be COMPLETE. The old membership-driven loop could only reach workspaces the
    user was still a member of; an event in a workspace whose membership was already removed
    would have been left with the real email. The single global UPDATE reaches it."""
    victim = _register(client)
    owner = _register(client)

    # A workspace owned by someone ELSE, in which the victim nonetheless has an audit event
    # (and no membership row of their own).
    foreign_ws = _create_workspace(client, _auth(owner), "Foreign WS")
    orphan_event = asyncio.run(_insert_audit_event(foreign_ws, victim["id"], victim["email"]))

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from apps.api.modules.users import service as users_service

    async def _run():
        eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(eng, expire_on_commit=False)
        try:
            async with maker() as session:
                await users_service._anonymize_audit_actor(session, uuid.UUID(victim["id"]))
                await session.commit()
        finally:
            await eng.dispose()

    asyncio.run(_run())

    emails = asyncio.run(_emails_by_event([orphan_event]))
    assert emails[orphan_event] == ANONYMIZED_ACTOR_EMAIL, (
        "an audit event in a workspace the user has no membership row for was left "
        "un-anonymized -- GDPR erasure must be complete"
    )


def test_anonymization_preserves_actor_attribution(client: TestClient) -> None:
    """actor_user_id must survive: the audit trail stays attributable to the (now anonymized)
    user record. Only the denormalized email is scrubbed."""
    victim = _register(client)
    ws = _create_workspace(client, _auth(victim), "WS-attr")
    event_id = asyncio.run(_insert_audit_event(ws, victim["id"], victim["email"]))

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from apps.api.modules.users import service as users_service

    async def _run():
        eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(eng, expire_on_commit=False)
        try:
            async with maker() as session:
                await users_service._anonymize_audit_actor(session, uuid.UUID(victim["id"]))
                await session.commit()
            async with eng.connect() as c:
                return (
                    await c.execute(
                        text(
                            "SELECT actor_user_id, actor_email, action, resource_type "
                            "FROM audit_events WHERE id = :id"
                        ),
                        {"id": event_id},
                    )
                ).first()
        finally:
            await eng.dispose()

    row = asyncio.run(_run())
    assert row is not None, "the audit row itself must survive erasure"
    assert str(row[0]) == victim["id"], "actor_user_id must be preserved for trail integrity"
    assert row[1] == ANONYMIZED_ACTOR_EMAIL
    assert row[2] == "test.action" and row[3] == "test", "unrelated columns must be untouched"
