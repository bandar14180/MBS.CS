"""MBS.SC P7-2 -- server-authoritative target execution context.

THE FINDING
-----------
`TargetCreate` exposed neither `network_zone` nor `site_id`, while `targets` carried both
columns and `scans.service` derived a scan's whole execution context from them. The model
comment even pointed at a validator (`validate_target_network_zone`) that was never
written. The practical effect was fail-CLOSED -- no API path could produce a private
target, so private scanning was unreachable through the product -- but the authorization
model for attaching a target to a site did not exist.

WHAT IS PROVEN HERE
-------------------
That closing the gap did NOT open a bypass. `site_id` is now accepted as an IDENTIFIER
REQUIRING AUTHORIZATION; `network_zone` is DERIVED server-side and is not an input at all.
The chain is:

    authenticated workspace -> project ownership -> site ownership -> zone -> CIDRs -> target

Both tenants below authorize the SAME CIDRs (10.0.0.0/16). Isolation therefore cannot come
from the addresses; it has to come from the site binding -- which is the point.
"""
import asyncio
import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.private_sites.models import PrivateSite
from apps.api.modules.projects import service as projects_service
from apps.api.modules.projects.models import Project
from apps.api.modules.projects.schemas import TargetCreate
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


@pytest.fixture
def private_scanning_enabled(monkeypatch):
    """The outer (global) safety boundary wide open, so anything still refused below is
    refused by PER-TENANT authorization rather than by the global ceiling."""
    s = get_settings()
    monkeypatch.setattr(s, "scan_allow_private_targets", True)
    monkeypatch.setattr(s, "scan_allowed_cidrs", ["10.0.0.0/8"])
    return s


async def _seed(session):
    """Two tenants, each with a project and an ACTIVE site authorizing the SAME CIDRs."""
    with tenancy.admin_bypass():
        made = []
        for label, pool in (("a", "private-a"), ("b", "private-b")):
            user = User(email=f"p72-{label}-{uuid.uuid4()}@test.local",
                        password_hash="x", full_name="P7-2")
            session.add(user)
            await session.flush()
            ws = Workspace(name=f"p72-{label}-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
            session.add(ws)
            await session.flush()
            project = Project(workspace_id=ws.id, name=f"p{label}", created_by=user.id)
            session.add(project)
            site = PrivateSite(
                id=uuid.uuid4(), workspace_id=ws.id, name="hq",
                authorized_cidrs=["10.0.0.0/16"], dns_servers=["10.0.0.53"],
                dns_search_domains=[], status="active", scanner_pool_id=pool,
            )
            session.add(site)
            await session.flush()
            made.append((ws.id, project, site, user.id))
        return made


def _run(coro_fn):
    """Run `coro_fn(session)` against a real session, always rolling back."""
    async def main():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            try:
                return await coro_fn(session)
            finally:
                await session.rollback()
                await engine.dispose()

    return asyncio.run(main())


# =======================================================================================
# THE SCHEMA CONTRACT -- what a client may and may not say
# =======================================================================================

def test_network_zone_is_not_a_client_input():
    """The single most important schema property: a client cannot declare its own
    execution context. `extra="forbid"` means the attempt FAILS rather than being
    silently dropped and believed."""
    assert "network_zone" not in TargetCreate.model_fields
    with pytest.raises(Exception):  # pydantic ValidationError
        TargetCreate.model_validate(
            {"type": "ip_range", "value": "10.0.0.5", "network_zone": "private"}
        )


def test_site_id_is_accepted_as_an_identifier():
    """P7-2's actual fix: site_id IS expressible -- it just is not proof of anything."""
    assert "site_id" in TargetCreate.model_fields
    parsed = TargetCreate.model_validate({"type": "ip_range", "value": "10.0.0.5"})
    assert parsed.site_id is None, "omitted site_id must mean 'public', not a default site"


@pytest.mark.parametrize("bad", ["not-a-uuid", "", "../../etc/passwd", 12345, {}])
def test_a_malformed_site_id_is_refused_by_validation(bad):
    with pytest.raises(Exception):
        TargetCreate.model_validate({"type": "ip_range", "value": "10.0.0.5", "site_id": bad})


def test_forged_authority_fields_are_refused_outright():
    """authorized_cidrs / pool_id / workspace_id are NOT inputs. Sending them is an error,
    not a silently-ignored no-op."""
    for forged in ({"authorized_cidrs": ["0.0.0.0/0"]}, {"pool_id": "private-b"},
                   {"workspace_id": str(uuid.uuid4())}, {"network_zone": "private"}):
        with pytest.raises(Exception):
            TargetCreate.model_validate(
                {"type": "ip_range", "value": "10.0.0.5", **forged}
            )


# =======================================================================================
# LEGITIMATE PATHS
# =======================================================================================

def test_a_public_target_needs_no_site_and_stays_public(private_scanning_enabled):
    async def body(session):
        (ws_a, proj_a, _site_a, user_a), _b = await _seed(session)
        with tenancy.admin_bypass():
            t = await projects_service.create_target(
                session, ws_a, proj_a.id, user_a, "domain", "example.com")
        assert t.network_zone == "public"
        assert t.site_id is None

    _run(body)


def test_a_private_target_on_its_own_site_is_authorized(private_scanning_enabled):
    """The legitimate private path, and the derivation: zone comes from the SITE."""
    async def body(session):
        (ws_a, proj_a, site_a, user_a), _b = await _seed(session)
        with tenancy.admin_bypass():
            t = await projects_service.create_target(
                session, ws_a, proj_a.id, user_a, "ip_range", "10.0.0.20",
                site_id=site_a.id)
        assert t.network_zone == "private", "zone was not derived from the site"
        assert t.site_id == site_a.id

    _run(body)


# =======================================================================================
# CROSS-TENANT / CROSS-SITE -- the attacks P7-2 must not enable
# =======================================================================================

def test_tenant_a_cannot_attach_a_target_to_tenant_bs_site(private_scanning_enabled):
    """THE CRITICAL NEGATIVE TEST (§12).

    Tenant A submits tenant B's site id with an attacker-chosen target. Both sites
    authorize the SAME CIDR, so the address itself is no defence -- only the site
    binding is.
    """
    from fastapi import HTTPException

    async def body(session):
        (ws_a, proj_a, _site_a, user_a), (_ws_b, _proj_b, site_b, _ub) = await _seed(session)
        with tenancy.admin_bypass():
            with pytest.raises(HTTPException) as exc:
                await projects_service.create_target(
                    session, ws_a, proj_a.id, user_a, "ip_range", "10.0.0.20",
                    site_id=site_b.id)
        assert exc.value.status_code == 403
        detail = str(exc.value.detail)
        assert "SITE_WRONG_WORKSPACE" in detail
        # Must not disclose WHICH workspace owns it.
        assert str(_ws_b) not in detail, "cross-tenant owner leaked in the error"

    _run(body)


def test_a_nonexistent_site_is_refused_without_disclosing_existence(private_scanning_enabled):
    from fastapi import HTTPException

    async def body(session):
        (ws_a, proj_a, _site_a, user_a), _b = await _seed(session)
        with tenancy.admin_bypass():
            with pytest.raises(HTTPException) as exc:
                await projects_service.create_target(
                    session, ws_a, proj_a.id, user_a, "ip_range", "10.0.0.20",
                    site_id=uuid.uuid4())
        assert exc.value.status_code == 403
        assert "SITE_NOT_FOUND" in str(exc.value.detail)

    _run(body)


def test_a_target_outside_the_sites_authorized_cidrs_is_refused(private_scanning_enabled):
    """Right site, wrong address: the site may not be used to authorize an address it
    never covered.

    Refused with 400 by the SSRF guard, which runs FIRST and is already policy-aware --
    the derived site policy narrows it to this site's CIDRs. The status differs from the
    403 of an ownership failure, and that distinction is correct: this is a bad target for
    a site the caller legitimately owns, not an authorization failure against the site.
    """
    from fastapi import HTTPException

    async def body(session):
        (ws_a, proj_a, site_a, user_a), _b = await _seed(session)
        with tenancy.admin_bypass():
            with pytest.raises(HTTPException) as exc:
                await projects_service.create_target(
                    session, ws_a, proj_a.id, user_a, "ip_range", "10.99.0.5",
                    site_id=site_a.id)
        assert exc.value.status_code == 400
        assert "not authorized for this scan" in str(exc.value.detail)

    _run(body)


def test_a_cidr_range_straddling_the_authorized_set_is_refused(private_scanning_enabled):
    """§14: forging breadth via the target VALUE rather than a field. 10.0.0.0/8 contains
    the authorized /16 but reaches far beyond it -- both edges must clear."""
    from fastapi import HTTPException

    async def body(session):
        (ws_a, proj_a, site_a, user_a), _b = await _seed(session)
        with tenancy.admin_bypass():
            with pytest.raises(HTTPException) as exc:
                await projects_service.create_target(
                    session, ws_a, proj_a.id, user_a, "ip_range", "10.0.0.0/8",
                    site_id=site_a.id)
        assert exc.value.status_code == 403
        assert "TARGET_OUTSIDE_AUTHORIZED_CIDRS" in str(exc.value.detail)

    _run(body)


@pytest.mark.parametrize("status_value,expected", [
    ("suspended", "SITE_SUSPENDED"),
    ("revoked", "SITE_REVOKED"),
    ("pending", "SITE_NOT_ACTIVE"),
])
def test_a_non_active_site_cannot_receive_a_target(private_scanning_enabled,
                                                   status_value, expected):
    """A target must not be attachable to a site that could not be scanned anyway --
    otherwise authorization would appear to succeed now and fail later."""
    from fastapi import HTTPException

    async def body(session):
        (ws_a, proj_a, site_a, user_a), _b = await _seed(session)
        with tenancy.admin_bypass():
            site_a.status = status_value
            await session.flush()
            with pytest.raises(HTTPException) as exc:
                await projects_service.create_target(
                    session, ws_a, proj_a.id, user_a, "ip_range", "10.0.0.20",
                    site_id=site_a.id)
        assert exc.value.status_code == 403
        assert expected in str(exc.value.detail)

    _run(body)


def test_a_project_in_another_workspace_is_refused_before_any_site_work(
        private_scanning_enabled):
    """§15 ordering: project ownership is proven BEFORE the site is even looked at, so a
    cross-workspace project cannot be used to probe site existence."""
    from fastapi import HTTPException

    async def body(session):
        (ws_a, _proj_a, site_a, user_a), (_ws_b, proj_b, _site_b, _ub) = await _seed(session)
        with tenancy.admin_bypass():
            with pytest.raises(HTTPException) as exc:
                await projects_service.create_target(
                    session, ws_a, proj_b.id, user_a, "ip_range", "10.0.0.20",
                    site_id=site_a.id)
        assert exc.value.status_code in (403, 404)

    _run(body)


def test_a_public_target_cannot_reach_a_private_address(private_scanning_enabled):
    """Omitting site_id must not be a way to get private reach: with no site there is no
    policy, so the ordinary SSRF guard refuses the address."""
    from fastapi import HTTPException

    async def body(session):
        (ws_a, proj_a, _site_a, user_a), _b = await _seed(session)
        with tenancy.admin_bypass():
            with pytest.raises(HTTPException) as exc:
                await projects_service.create_target(
                    session, ws_a, proj_a.id, user_a, "ip_range", "10.0.0.20")
        assert exc.value.status_code == 400

    _run(body)


def test_the_derived_context_is_what_a_scan_would_later_use(private_scanning_enabled):
    """The end of the chain: what was persisted is what `scans.service` reads back, so the
    target row -- not any client input -- remains the authority."""
    async def body(session):
        (ws_a, proj_a, site_a, user_a), _b = await _seed(session)
        with tenancy.admin_bypass():
            t = await projects_service.create_target(
                session, ws_a, proj_a.id, user_a, "ip_range", "10.0.0.20",
                site_id=site_a.id)
            from apps.api.modules.private_sites import service as sites_service

            policy = await sites_service.build_scan_network_policy(
                session, workspace_id=ws_a, scan_id=None,
                network_zone=t.network_zone, site_id=t.site_id)
        assert policy.is_private is True
        assert [str(c) for c in policy.authorized_cidrs] == ["10.0.0.0/16"]
        assert policy.site_id == site_a.id

    _run(body)
