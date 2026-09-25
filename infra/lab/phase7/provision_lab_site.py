"""MBS.SC PHASE 7 LAB -- provision the private site + private worker rows.

Creates exactly what the Phase 7 verification needs and nothing more:

  * one workspace                 (reused if the named lab workspace already exists)
  * one PrivateSite               authorized for 10.90.0.0/24 ONLY
  * one private ScannerWorker     bound to that site + workspace
  * one public ScannerWorker row is NOT touched -- the existing worker-public-1 stays as is

It uses the REAL models and the REAL token hashing (`scanner_workers.service`), so the rows
are byte-identical to what production provisioning would create. Nothing here bypasses an
authorization check: the checks all run at request time in the manager, against these rows.

The WireGuard PRIVATE key is never handled here -- only the worker's PUBLIC key is stored,
which is the Phase 7 key-custody rule. The private half is generated in, and stays in, the
worker container.

Idempotent: re-running updates the existing rows rather than creating duplicates.

    python infra/lab/phase7/provision_lab_site.py --worker-public-key <PUB> [--print-token]
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

LAB_WORKSPACE_NAME = "MBS.SC Phase 7 Lab"
LAB_SITE_NAME = "Customer A (Phase 7 Lab)"
LAB_WORKER_ID = "worker-site-lab-a"
LAB_POOL_ID = "private-lab-a"
# The ONLY authorized CIDR for this site. Customer B (10.91.0.0/24) is deliberately absent.
LAB_AUTHORIZED_CIDRS = ["10.90.0.0/24"]


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker-public-key", required=True,
                    help="the worker's WireGuard PUBLIC key (never the private half)")
    ap.add_argument("--peer-public-key", required=True,
                    help="the customer gateway's WireGuard public key")
    ap.add_argument("--endpoint-host", default="10.92.0.10")
    ap.add_argument("--endpoint-port", type=int, default=51820)
    ap.add_argument("--workspace-id", default=None,
                    help="anchor the lab site to this existing workspace (default: the first)")
    ap.add_argument("--print-token", action="store_true",
                    help="print the generated worker token so the lab can write it to a file")
    args = ap.parse_args()

    from sqlalchemy import select

    # Import the full model registry FIRST. Workspace has an FK to `users`, and SQLAlchemy
    # cannot resolve it unless every mapped class is imported -- otherwise the first query
    # raises NoReferencedTableError. `models_all` is the project's existing single import
    # point for that (the same one Alembic and the worker use).
    from apps.api.core import models_all  # noqa: F401
    from apps.api.core import tenancy
    from apps.api.core.db import make_worker_engine
    from apps.api.core.config import get_settings
    from apps.api.modules.private_sites.models import PrivateSite
    from apps.api.modules.scanner_workers import service as ws
    from apps.api.modules.scanner_workers.models import ScannerWorker
    from apps.api.modules.workspaces.models import Workspace
    from sqlalchemy.ext.asyncio import async_sessionmaker

    engine = make_worker_engine(get_settings().database_url)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    token = ws.generate_worker_token()
    async with Session() as db:
        # admin_bypass: this is a provisioning script running as an operator, creating the
        # very workspace the tenancy filter would scope to. Every row it writes is then
        # subject to the normal checks at request time.
        with tenancy.admin_bypass():
            # REUSE an existing workspace rather than creating one. `workspaces.owner_user_id`
            # requires a real user, and inventing a user for a lab would add a login-capable
            # identity to the live database -- more change than this verification needs. The
            # workspace is only a tenancy anchor here; what Phase 7 exercises is the SITE and
            # WORKER binding beneath it.
            if args.workspace_id:
                workspace = await db.get(Workspace, uuid.UUID(args.workspace_id))
                if workspace is None:
                    print(f"ERROR: no workspace {args.workspace_id}", file=sys.stderr)
                    return 2
            else:
                workspace = await db.scalar(select(Workspace).limit(1))
                if workspace is None:
                    print("ERROR: no workspace exists to anchor the lab site to",
                          file=sys.stderr)
                    return 2

            site = await db.scalar(
                select(PrivateSite).where(
                    PrivateSite.workspace_id == workspace.id,
                    PrivateSite.name == LAB_SITE_NAME,
                )
            )
            if site is None:
                site = PrivateSite(id=uuid.uuid4(), workspace_id=workspace.id,
                                   name=LAB_SITE_NAME)
                db.add(site)
            site.authorized_cidrs = list(LAB_AUTHORIZED_CIDRS)
            # The customer's OWN resolver, inside the authorized CIDR. Private names resolve
            # through it over the tunnel -- never a public resolver (site_dns.py).
            site.dns_servers = ["10.90.0.53"]
            site.dns_search_domains = ["customer-a.internal"]
            site.wg_endpoint_host = args.endpoint_host
            site.wg_endpoint_port = args.endpoint_port
            site.peer_public_key = args.peer_public_key
            site.worker_public_key = args.worker_public_key
            site.wg_persistent_keepalive = 25
            site.scanner_pool_id = LAB_POOL_ID
            site.status = "active"
            await db.flush()

            worker = await db.scalar(
                select(ScannerWorker).where(ScannerWorker.worker_id == LAB_WORKER_ID)
            )
            if worker is None:
                worker = ScannerWorker(id=uuid.uuid4(), worker_id=LAB_WORKER_ID)
                db.add(worker)
            worker.pool_id = LAB_POOL_ID
            worker.site_id = site.id
            worker.workspace_id = workspace.id
            worker.status = "active"
            worker.token_hash = ws.hash_worker_token(token)
            await db.commit()

            print(f"WORKSPACE_ID={workspace.id}")
            print(f"SITE_ID={site.id}")
            print(f"WORKER_ID={LAB_WORKER_ID}")
            print(f"POOL_ID={LAB_POOL_ID}")
            print(f"AUTHORIZED_CIDRS={site.authorized_cidrs}")
            if args.print_token:
                print(f"WORKER_TOKEN={token}")

    await engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
