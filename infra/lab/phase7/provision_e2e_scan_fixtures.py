"""MBS.SC PHASE 7 LAB -- disposable fixtures for ONE real private-scan E2E.

Creates the three rows the application path requires and that its own API cannot create:

  * a test PROJECT in the lab workspace;
  * a private TARGET (network_zone='private', site_id=<lab site>) valued inside the site's
    ONLY authorized CIDR, 10.90.0.0/24 -- `TargetCreate` exposes neither field, which is why
    this is done directly (see the P7-2 follow-up finding);
  * a VERIFIED authorization scope for that target, because scans.service.create_scan calls
    require_verified_target() and 403s without one.

ADDITIVE ONLY. Nothing existing is modified, overwritten or deleted; every row is new and
carries an obvious lab name so it can be identified and removed later. The scan itself is
then created through the REAL API, not here -- this only supplies the preconditions.

Idempotent: re-running reuses the rows it already created.

    python provision_e2e_scan_fixtures.py --workspace-id <ws> --site-id <site>
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

LAB_PROJECT_NAME = "Phase 7 E2E (lab)"
# Inside 10.90.0.0/24 -- the ONLY CIDR the lab site authorizes. This is the customer-a-target
# container, reachable exclusively through the WireGuard tunnel.
# An ip_range target carrying a BARE IP (no CIDR suffix).
#
# Why not the other two supported shapes:
#   * `domain` -- blocked by P7-3: private names resolve through scanner_engine/site_dns.py,
#     and NOTHING in production ever calls site_dns.set_backend(), so every private domain
#     lookup raises SiteDNSUnavailable. Reported as a follow-up finding; out of P7-1 scope.
#   * `10.90.0.20/32` -- accepted everywhere, but the runners pass the value through verbatim
#     and httpx-pd cannot probe a host with a CIDR suffix: it emits nothing and the tool
#     "succeeds" vacuously (observed: exit 0, findings 0, no request seen at the target).
#
# A bare IP is still type `ip_range` (the engine's supported network type) and is strictly
# inside the site's only authorized CIDR, 10.90.0.0/24.
LAB_TARGET_VALUE = "10.90.0.20"


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace-id", required=True)
    ap.add_argument("--site-id", required=True)
    args = ap.parse_args()

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from apps.api.core import models_all  # noqa: F401  -- resolve every FK before querying
    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.core.db import make_worker_engine
    from apps.api.modules.authorization_scope.models import AuthorizationScope
    from apps.api.modules.projects.models import Project, Target
    from apps.api.modules.users.models import User

    ws_id = uuid.UUID(args.workspace_id)
    site_id = uuid.UUID(args.site_id)

    engine = make_worker_engine(get_settings().database_url)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async with Session() as db:
        with tenancy.admin_bypass():
            # `projects.created_by` is NOT NULL -> reuse an existing user rather than
            # inventing a login-capable identity for a lab.
            user = await db.scalar(select(User).limit(1))
            if user is None:
                print("ERROR: no user exists to own the lab project", file=sys.stderr)
                return 2

            project = await db.scalar(
                select(Project).where(
                    Project.workspace_id == ws_id, Project.name == LAB_PROJECT_NAME
                )
            )
            if project is None:
                project = Project(
                    id=uuid.uuid4(), workspace_id=ws_id, name=LAB_PROJECT_NAME,
                    status="active", created_by=user.id,
                )
                db.add(project)
                await db.flush()

            target = await db.scalar(
                select(Target).where(
                    Target.project_id == project.id, Target.value == LAB_TARGET_VALUE
                )
            )
            if target is None:
                target = Target(id=uuid.uuid4(), project_id=project.id,
                                type="ip_range", value=LAB_TARGET_VALUE,
                                # NOT NULL on `targets`; same reused lab user as the project.
                                added_by=user.id)
                db.add(target)
            # THE PRIVATE BINDING. Set here because the API cannot express it.
            # `type` is refreshed on reuse too: an earlier lab run may have created this row
            # with a different (now-rejected) type, and only updating it on INSERT would
            # silently keep scanning the stale shape.
            target.type = "ip_range"
            target.network_zone = "private"
            target.site_id = site_id
            await db.flush()

            scope = await db.scalar(
                select(AuthorizationScope).where(AuthorizationScope.target_id == target.id)
            )
            if scope is None:
                scope = AuthorizationScope(id=uuid.uuid4(), target_id=target.id)
                db.add(scope)
            scope.proof_type = "manual"
            scope.proof_reference = "MBS.SC Phase 7 lab -- operator-owned disposable target"
            scope.verified = True
            scope.verified_by = user.id
            scope.verified_at = datetime.now(timezone.utc)
            # Passive httpx only for this run, but the scope must permit what we request.
            scope.active_testing_allowed = True
            scope.scope_notes = "Lab fixture. Target is a container owned by this assessment."
            await db.commit()

            print(f"PROJECT_ID={project.id}")
            print(f"TARGET_ID={target.id}")
            print(f"TARGET_VALUE={target.value}")
            print(f"NETWORK_ZONE={target.network_zone}")
            print(f"TARGET_SITE_ID={target.site_id}")
            print(f"SCOPE_VERIFIED={bool(scope.verified)}")
            print(f"USER_ID={user.id}")

    await engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
