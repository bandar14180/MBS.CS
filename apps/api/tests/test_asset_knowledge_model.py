"""Asset / Application Knowledge Model -- relational integrity and provenance (Prompt 28).

WHAT THE MODEL ACTUALLY IS, after auditing what exists. The knowledge model is the EXISTING
`assets` table plus the derived, deterministic layers already built on it (api_intel's
endpoint classification, auth_state's authentication state, coverage, adaptive's candidates,
attack_graph). Its relational core is already correct and is NOT rebuilt here:

    assets.project_id -> projects.id   (ON DELETE CASCADE)
    assets.target_id  -> targets.id    (ON DELETE CASCADE)
    UNIQUE (target_id, asset_type, value_hash)   -- one row per asset, per target
    first_seen / last_seen                       -- history the architecture already keeps

Relationships between assets (subdomain -> IP -> port -> service -> web asset) are carried as
metadata on those rows and correlated non-destructively by `merge_asset_metadata`. No new
table, no second source of truth and no graph DB is introduced: the audit found no data flow
for identities, principals, sessions, workflows or object-ID candidates, because the platform
scans UNAUTHENTICATED by design (see scanner_engine/auth_state.py -- it classifies auth state
WITHOUT authenticating, and never holds a credential). Modelling those entities would be
inventing observations the system cannot make. That limitation is documented, not papered over.

WHAT IS PINNED HERE:
  * foreign-key integrity and cascade behaviour on the real DB
  * tenant isolation -- one workspace's assets are unreachable from another
  * no silent cross-asset merge: the unique grain keeps distinct assets distinct
  * provenance: OBSERVED vs INFERRED vs VERIFIED stay distinct
  * no inference-to-verification promotion -- the hard invariant
  * historical observations survive re-discovery
"""
import asyncio
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.assets.models import Asset
from apps.api.modules.assets.service import (
    OBSERVATIONS_KEY,
    PROVENANCE_INFERRED,
    PROVENANCE_OBSERVED,
    PROVENANCE_VERIFIED,
    merge_asset_metadata,
    upsert_asset,
)
from apps.api.tests.test_scans import _auth, _register


def _obs(tool: str, run: str) -> dict:
    return {
        "discovered_by_tool": tool,
        "discovered_by_tool_version": "1.0.0",
        "discovered_in_tool_run": run,
        "in_scope": True,
    }


def _make_target(client, headers, name="KM WS"):
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": name}).json()["id"]
    proj = client.post(
        f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": "P"}
    ).json()["id"]
    value = f"{uuid.uuid4()}.test"
    tgt = client.post(
        f"/api/v1/workspaces/{ws}/projects/{proj}/targets",
        headers=headers, json={"type": "domain", "value": value},
    ).json()["id"]
    return ws, proj, tgt, value


async def _with_session(ws, fn):
    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            tenancy.bind_workspace(ws)
            return await fn(s)
    finally:
        await engine.dispose()


# --- A. Provenance vocabulary is distinct ---------------------------------------------------

def test_the_three_provenance_tiers_are_distinct_values():
    assert len({PROVENANCE_OBSERVED, PROVENANCE_INFERRED, PROVENANCE_VERIFIED}) == 3


def test_a_discovered_asset_observation_is_observed():
    """A scanner SAW it. That is OBSERVED -- not inferred, and certainly not verified."""
    merged = merge_asset_metadata(None, _obs("katana", "r1"))
    assert merged[OBSERVATIONS_KEY][0]["provenance"] == PROVENANCE_OBSERVED


def test_discovery_never_writes_verified():
    """THE HARD INVARIANT. No discovery path may produce VERIFIED: verification belongs to
    the vulnerability verification pipeline and requires its own evidence."""
    md: dict = {}
    for tool, run in (("katana", "r1"), ("httpx", "r2"), ("whatweb", "r3")):
        md = merge_asset_metadata(md, _obs(tool, run))
    assert all(o["provenance"] == PROVENANCE_OBSERVED for o in md[OBSERVATIONS_KEY])
    assert PROVENANCE_VERIFIED not in str(md)


def test_a_caller_cannot_smuggle_verified_into_an_observation():
    """Even if an upstream metadata dict claims VERIFIED, the observation record is stamped
    by this module, not by its input -- inference/claim can never be promoted to verification."""
    hostile = {**_obs("katana", "r1"), "provenance": PROVENANCE_VERIFIED, "verified": True}
    merged = merge_asset_metadata(None, hostile)
    assert merged[OBSERVATIONS_KEY][0]["provenance"] == PROVENANCE_OBSERVED


def test_an_inferred_classification_is_not_recorded_as_an_observation():
    """api_intel's `is_api`/`api_kind` are DERIVED from a URL, not observed on the wire. They
    may travel in metadata, but they must not become observation provenance."""
    merged = merge_asset_metadata(
        None, {**_obs("katana", "r1"), "is_api": True, "api_kind": "rest"}
    )
    observation = merged[OBSERVATIONS_KEY][0]
    assert "is_api" not in observation and "api_kind" not in observation
    assert merged["is_api"] is True          # still available as derived metadata
    assert observation["provenance"] == PROVENANCE_OBSERVED


def test_relationships_alone_do_not_imply_a_vulnerability():
    """A subdomain resolving to an IP with an open port running a known product is a set of
    OBSERVED relationships -- not a finding."""
    md: dict = {}
    md = merge_asset_metadata(md, {**_obs("dnsx", "r1"), "a_records": ["10.0.0.1"]})
    md = merge_asset_metadata(md, {**_obs("naabu", "r2"), "port": 22})
    md = merge_asset_metadata(md, {**_obs("nmap", "r3"), "product": "OpenSSH", "version": "7.4"})
    for banned in ("severity", "cve", "cwe", "verified", "vulnerability", "exploit"):
        assert banned not in md


# --- B. History ------------------------------------------------------------------------------

def test_historical_observations_survive_re_discovery():
    md = merge_asset_metadata(None, _obs("katana", "r1"))
    md = merge_asset_metadata(md, _obs("katana", "r2"))
    md = merge_asset_metadata(md, _obs("katana", "r3"))
    assert [o["discovered_in_tool_run"] for o in md[OBSERVATIONS_KEY]] == ["r1", "r2", "r3"]


# --- C. Relational integrity + tenancy, against the REAL database -----------------------------

@pytest.mark.usefixtures("client")
def test_asset_rows_carry_their_project_and_target_foreign_keys(client):
    headers = _auth(_register(client, "Owner"))
    ws, proj, tgt, host = _make_target(client, headers)

    async def _go(s):
        await upsert_asset(
            s, project_id=uuid.UUID(proj), target_id=uuid.UUID(tgt),
            asset_type="url", value=f"http://{host}/a", metadata=_obs("katana", "r1"),
        )
        await s.commit()
        row = (await s.execute(select(Asset).where(Asset.target_id == uuid.UUID(tgt)))).scalar_one()
        return row

    row = asyncio.run(_with_session(ws, _go))
    assert str(row.project_id) == proj
    assert str(row.target_id) == tgt
    assert row.first_seen is not None and row.last_seen is not None


@pytest.mark.usefixtures("client")
def test_re_discovery_touches_one_row_and_preserves_both_observations(client):
    """The unique grain (target_id, asset_type, value) must correlate, not duplicate -- and
    must not lose the first tool's provenance."""
    headers = _auth(_register(client, "Owner"))
    ws, proj, tgt, host = _make_target(client, headers)
    url = f"http://{host}/shared"

    async def _go(s):
        await upsert_asset(s, project_id=uuid.UUID(proj), target_id=uuid.UUID(tgt),
                           asset_type="url", value=url, metadata=_obs("katana", "r1"))
        await s.commit()
        await upsert_asset(s, project_id=uuid.UUID(proj), target_id=uuid.UUID(tgt),
                           asset_type="url", value=url, metadata=_obs("arjun", "r2"))
        await s.commit()
        rows = (await s.execute(select(Asset).where(Asset.target_id == uuid.UUID(tgt)))).scalars().all()
        return rows

    rows = asyncio.run(_with_session(ws, _go))
    assert len(rows) == 1, "re-discovery must correlate into one row, not duplicate"
    tools = [o["discovered_by_tool"] for o in rows[0].metadata_[OBSERVATIONS_KEY]]
    assert tools == ["katana", "arjun"]


@pytest.mark.usefixtures("client")
def test_distinct_assets_are_never_silently_merged(client):
    """Different value, or same value under a different asset_type, are DIFFERENT assets."""
    headers = _auth(_register(client, "Owner"))
    ws, proj, tgt, host = _make_target(client, headers)

    async def _go(s):
        await upsert_asset(s, project_id=uuid.UUID(proj), target_id=uuid.UUID(tgt),
                           asset_type="url", value=f"http://{host}/a", metadata=_obs("katana", "r1"))
        await upsert_asset(s, project_id=uuid.UUID(proj), target_id=uuid.UUID(tgt),
                           asset_type="url", value=f"http://{host}/b", metadata=_obs("katana", "r1"))
        await upsert_asset(s, project_id=uuid.UUID(proj), target_id=uuid.UUID(tgt),
                           asset_type="http_service", value=f"http://{host}/a",
                           metadata=_obs("httpx", "r2"))
        await s.commit()
        rows = (await s.execute(select(Asset).where(Asset.target_id == uuid.UUID(tgt)))).scalars().all()
        return rows

    rows = asyncio.run(_with_session(ws, _go))
    assert len(rows) == 3


@pytest.mark.usefixtures("client")
def test_one_workspaces_assets_are_not_visible_to_another(client):
    """Tenant isolation at the knowledge-model layer."""
    h1 = _auth(_register(client, "Owner One"))
    ws1, proj1, tgt1, host1 = _make_target(client, h1, name="WS One")

    async def _seed(s):
        await upsert_asset(s, project_id=uuid.UUID(proj1), target_id=uuid.UUID(tgt1),
                           asset_type="url", value=f"http://{host1}/secret",
                           metadata=_obs("katana", "r1"))
        await s.commit()

    asyncio.run(_with_session(ws1, _seed))

    h2 = _auth(_register(client, "Owner Two"))
    r = client.get(f"/api/v1/workspaces/{ws1}/projects/{proj1}/assets", headers=h2)
    assert r.status_code in (403, 404), r.text


@pytest.mark.usefixtures("client")
def test_deleting_a_target_cascades_to_its_assets(client):
    """Referential integrity: an asset cannot outlive the target it belongs to."""
    headers = _auth(_register(client, "Owner"))
    ws, proj, tgt, host = _make_target(client, headers)

    async def _go(s):
        await upsert_asset(s, project_id=uuid.UUID(proj), target_id=uuid.UUID(tgt),
                           asset_type="url", value=f"http://{host}/x", metadata=_obs("katana", "r1"))
        await s.commit()
        await s.execute(text("DELETE FROM targets WHERE id = :t"), {"t": uuid.UUID(tgt).bytes})
        await s.commit()
        # Count in SQL rather than loading ORM objects: the raw DELETE cascades in the
        # DATABASE, which the Session's identity map knows nothing about, so a select() here
        # would hand back the stale in-memory Asset and assert the opposite of the truth.
        s.expunge_all()
        return (
            await s.execute(
                text("SELECT COUNT(*) FROM assets WHERE target_id = :t"),
                {"t": uuid.UUID(tgt).bytes},
            )
        ).scalar_one()

    assert asyncio.run(_with_session(ws, _go)) == 0
