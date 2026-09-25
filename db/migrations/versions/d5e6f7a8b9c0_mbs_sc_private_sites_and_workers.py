"""MBS.SC: private sites, scanner worker identity, target network zone

Adds the persisted authorization chain that private scanning is validated against:

    workspace -> private_site -> authorized_cidrs -> pool -> worker -> scan

Before this, "may we scan internal addresses" was answered by two PROCESS-WIDE settings
(`scan_allow_private_targets` / `scan_allowed_cidrs`), which cannot name a tenant. Enabling
them for one on-prem customer authorized every workspace in the deployment for every listed
range. These tables give that decision a per-tenant home so the check can be made against
persisted state instead of global configuration.

PURELY ADDITIVE. Two new tables plus two nullable columns on `targets`; no existing column,
index or constraint is modified or dropped, and no data is rewritten. `targets.network_zone`
defaults to 'public', so every existing row keeps exactly its present behaviour -- a target
is private only by an explicit later decision that also names its site.

NO PRIVATE KEY MATERIAL IS PERSISTED. `private_sites` holds the customer's public key and
the worker's PUBLIC key only. The WireGuard private key is generated inside the private
worker namespace and never leaves it, so a compromise of this database cannot yield the
ability to impersonate the scanner inside a customer's internal network. Likewise
`scanner_workers.token_hash` stores a HASH, never a usable credential.

UTCDateTime (not sa.DateTime) is used for every timestamp: MySQL's DATETIME is
timezone-blind and second-resolution by default -- see apps/api/core/db_types.py. That makes
these DATETIME(6), consistent with the rest of this schema.

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-09-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# Autogenerate emits fully-qualified apps.api.core.db_types.* below but does NOT emit this
# import; without it the generated file raises NameError on upgrade.
import apps.api.core.db_types


# revision identifiers, used by Alembic.
revision: str = 'd5e6f7a8b9c0'
down_revision: Union[str, None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'private_sites',
        sa.Column('id', apps.api.core.db_types.GUID(), nullable=False),
        # NOT NULL, no default: a site with no owner is precisely how cross-tenant access
        # would be reintroduced, so the schema refuses to represent one.
        sa.Column('workspace_id', apps.api.core.db_types.GUID(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        # JSON list of CIDR strings -- the authoritative private authorization.
        sa.Column('authorized_cidrs', apps.api.core.db_types.JSONType(), nullable=False),
        sa.Column('dns_servers', apps.api.core.db_types.JSONType(), nullable=False),
        sa.Column('dns_search_domains', apps.api.core.db_types.JSONType(), nullable=False),
        sa.Column('wg_endpoint_host', sa.String(length=255), nullable=True),
        sa.Column('wg_endpoint_port', sa.Integer(), nullable=True),
        # PUBLIC key material only (see the module docstring).
        sa.Column('peer_public_key', sa.String(length=64), nullable=True),
        sa.Column('worker_public_key', sa.String(length=64), nullable=True),
        sa.Column('wg_persistent_keepalive', sa.Integer(), nullable=True),
        sa.Column('scanner_pool_id', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False,
                  server_default=sa.text("'pending'")),
        sa.Column('status_reason', sa.Text(), nullable=True),
        sa.Column('last_handshake_at', apps.api.core.db_types.UTCDateTime(), nullable=True),
        sa.Column('last_verified_at', apps.api.core.db_types.UTCDateTime(), nullable=True),
        sa.Column('created_at', apps.api.core.db_types.UTCDateTime(),
                  server_default=sa.text('CURRENT_TIMESTAMP(6)'), nullable=False),
        sa.Column('updated_at', apps.api.core.db_types.UTCDateTime(), nullable=True),
        # CASCADE: deleting a workspace must not strand a site that grants access to a
        # customer's internal network.
        sa.ForeignKeyConstraint(['workspace_id'], ['workspaces.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_private_sites_workspace_id'), 'private_sites',
                    ['workspace_id'], unique=False)
    op.create_index(op.f('ix_private_sites_status'), 'private_sites', ['status'], unique=False)
    op.create_index(op.f('ix_private_sites_scanner_pool_id'), 'private_sites',
                    ['scanner_pool_id'], unique=False)
    # Unique per workspace, not globally: two different customers may each call a site "hq".
    op.create_index('ix_private_sites_workspace_name', 'private_sites',
                    ['workspace_id', 'name'], unique=True)

    op.create_table(
        'scanner_workers',
        sa.Column('id', apps.api.core.db_types.GUID(), nullable=False),
        sa.Column('worker_id', sa.String(length=128), nullable=False),
        sa.Column('pool_id', sa.String(length=64), nullable=False),
        # NULL for a shared public worker; set (and matching the site's workspace) for a
        # private one.
        sa.Column('site_id', apps.api.core.db_types.GUID(), nullable=True),
        sa.Column('workspace_id', apps.api.core.db_types.GUID(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False,
                  server_default=sa.text("'pending'")),
        # HASH only -- a database read must not yield a usable worker credential.
        sa.Column('token_hash', sa.String(length=128), nullable=True),
        sa.Column('cert_fingerprint', sa.String(length=128), nullable=True),
        sa.Column('cert_subject', sa.String(length=255), nullable=True),
        sa.Column('cert_not_after', apps.api.core.db_types.UTCDateTime(), nullable=True),
        sa.Column('last_seen_at', apps.api.core.db_types.UTCDateTime(), nullable=True),
        sa.Column('health_state', sa.String(length=32), nullable=False,
                  server_default=sa.text("'unknown'")),
        sa.Column('last_health_detail', sa.Text(), nullable=True),
        sa.Column('last_handshake_age_s', sa.Integer(), nullable=True),
        sa.Column('revoked_at', apps.api.core.db_types.UTCDateTime(), nullable=True),
        sa.Column('revoked_reason', sa.Text(), nullable=True),
        sa.Column('created_at', apps.api.core.db_types.UTCDateTime(),
                  server_default=sa.text('CURRENT_TIMESTAMP(6)'), nullable=False),
        sa.Column('updated_at', apps.api.core.db_types.UTCDateTime(), nullable=True),
        sa.ForeignKeyConstraint(['site_id'], ['private_sites.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspaces.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    # UNIQUE: worker_id is the authentication subject, so two rows sharing one would make
    # "which worker is this" ambiguous -- the database refuses to represent that.
    op.create_index(op.f('ix_scanner_workers_worker_id'), 'scanner_workers',
                    ['worker_id'], unique=True)
    op.create_index(op.f('ix_scanner_workers_pool_id'), 'scanner_workers', ['pool_id'], unique=False)
    op.create_index(op.f('ix_scanner_workers_site_id'), 'scanner_workers', ['site_id'], unique=False)
    op.create_index(op.f('ix_scanner_workers_workspace_id'), 'scanner_workers',
                    ['workspace_id'], unique=False)
    op.create_index(op.f('ix_scanner_workers_status'), 'scanner_workers', ['status'], unique=False)
    op.create_index(op.f('ix_scanner_workers_token_hash'), 'scanner_workers',
                    ['token_hash'], unique=False)
    op.create_index(op.f('ix_scanner_workers_cert_fingerprint'), 'scanner_workers',
                    ['cert_fingerprint'], unique=False)
    op.create_index(op.f('ix_scanner_workers_last_seen_at'), 'scanner_workers',
                    ['last_seen_at'], unique=False)
    op.create_index('ix_scanner_workers_pool_status', 'scanner_workers',
                    ['pool_id', 'status'], unique=False)

    # --- targets: network zone -------------------------------------------------------
    # server_default 'public' backfills every existing row to today's behaviour, so this
    # migration changes no scan's outcome.
    op.add_column('targets', sa.Column('network_zone', sa.String(length=16), nullable=False,
                                       server_default=sa.text("'public'")))
    op.add_column('targets', sa.Column('site_id', apps.api.core.db_types.GUID(), nullable=True))
    op.create_index(op.f('ix_targets_site_id'), 'targets', ['site_id'], unique=False)
    # RESTRICT, not CASCADE: deleting a site that targets still reference must FAIL loudly
    # rather than silently orphaning targets into an unauthorized state.
    op.create_foreign_key('fk_targets_site_id_private_sites', 'targets', 'private_sites',
                          ['site_id'], ['id'], ondelete='RESTRICT')


def downgrade() -> None:
    # MySQL has no transactional DDL: if a later statement in this function fails, the
    # earlier ones STAY APPLIED while alembic_version still reads the old revision --
    # leaving the schema and the stamp disagreeing (hit for real while developing this
    # migration). Each step is therefore made individually idempotent, so re-running a
    # partially-applied downgrade converges instead of erroring on the already-done half.
    bind = op.get_bind()

    def _fk_exists(table: str, name: str) -> bool:
        return bool(bind.execute(sa.text(
            "SELECT 1 FROM information_schema.table_constraints "
            "WHERE constraint_schema = DATABASE() AND table_name = :t "
            "AND constraint_name = :n AND constraint_type = 'FOREIGN KEY'"
        ), {"t": table, "n": name}).first())

    def _index_exists(table: str, name: str) -> bool:
        return bool(bind.execute(sa.text(
            "SELECT 1 FROM information_schema.statistics "
            "WHERE table_schema = DATABASE() AND table_name = :t AND index_name = :n"
        ), {"t": table, "n": name}).first())

    def _column_exists(table: str, name: str) -> bool:
        return bool(bind.execute(sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = :t AND column_name = :n"
        ), {"t": table, "n": name}).first())

    if _fk_exists('targets', 'fk_targets_site_id_private_sites'):
        op.drop_constraint('fk_targets_site_id_private_sites', 'targets', type_='foreignkey')
    if _index_exists('targets', 'ix_targets_site_id'):
        op.drop_index(op.f('ix_targets_site_id'), table_name='targets')
    if _column_exists('targets', 'site_id'):
        op.drop_column('targets', 'site_id')
    if _column_exists('targets', 'network_zone'):
        op.drop_column('targets', 'network_zone')

    # NOTE (MySQL/InnoDB): do NOT drop these tables' indexes individually before the
    # table. InnoDB REQUIRES an index on a foreign key column, so
    # `DROP INDEX ix_scanner_workers_workspace_id` fails with errno 1553
    # ("needed in a foreign key constraint") while the FK still exists -- verified
    # directly by running this downgrade against MySQL 8.0. `drop_table` removes the
    # table's own indexes and constraints together, which is both correct and simpler.
    op.execute("DROP TABLE IF EXISTS scanner_workers")
    # Dropped AFTER scanner_workers: scanner_workers.site_id references it.
    op.execute("DROP TABLE IF EXISTS private_sites")
