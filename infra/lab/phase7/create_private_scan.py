"""MBS.SC PHASE 7 LAB -- create ONE real private scan through the application path.

Calls `scans.service.create_scan` -- the SAME function the HTTP router
(`POST /workspaces/{ws}/projects/{p}/scans`) invokes, with the same arguments. Nothing about
the authorization chain is bypassed:

  * require_verified_target() runs (403 without a verified scope);
  * active_testing_allowed is checked against the requested modules;
  * the NETWORK ZONE is read from the persisted target row, never from an argument here --
    a caller cannot declare a scan private;
  * build_scan_network_policy() validates workspace -> site -> CIDR ownership;
  * queue_for_scan() routes it to scans.private.<site-id>.

The API container is used deliberately (rather than a direct DB insert) so the scan is
created by the real control plane, with the real gates in the real process.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace-id", required=True)
    ap.add_argument("--project-id", required=True)
    ap.add_argument("--target-id", required=True)
    ap.add_argument("--user-id", required=True)
    # Passive only: local nuclei templates are absent, and httpx is enough to prove the
    # scanner executed against the private target through the tunnel.
    ap.add_argument("--modules", default="httpx")
    args = ap.parse_args()

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from apps.api.core import models_all  # noqa: F401
    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.core.db import make_worker_engine
    from apps.api.modules.scans import service as scans_service

    engine = make_worker_engine(get_settings().database_url)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    ws = uuid.UUID(args.workspace_id)
    async with Session() as db:
        # The workspace binding the API would have established from the caller's session.
        tenancy.bind_workspace(ws)
        scan = await scans_service.create_scan(
            db,
            workspace_id=ws,
            project_id=uuid.UUID(args.project_id),
            initiated_by=uuid.UUID(args.user_id),
            target_id=uuid.UUID(args.target_id),
            scan_type="custom",
            requested_modules=[m.strip() for m in args.modules.split(",") if m.strip()],
        )
        await db.commit()
        cfg = scan.config or {}
        print(f"SCAN_ID={scan.id}")
        print(f"STATUS={scan.status}")
        print(f"NETWORK_ZONE={cfg.get('network_zone')}")
        print(f"SITE_ID={cfg.get('site_id')}")
        print(f"QUEUE={cfg.get('queue') or cfg.get('scan_queue')}")
        print(f"MODULES={cfg.get('requested_modules') or cfg.get('modules')}")

    await engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
