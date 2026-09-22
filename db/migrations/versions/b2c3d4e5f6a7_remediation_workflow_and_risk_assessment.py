"""remediation workflow, risk acceptance, client risk assessment

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-02 00:00:00.000000

ADDITIVE ONLY, with ONE compatibility change:

  * NEW tables: remediation_items, remediation_events, remediation_evidence,
    verification_requests, risk_acceptances, risk_assessments, risk_assessment_findings.
  * CHANGED: `evidence.tool_run_id` NOT NULL -> NULL, plus a new nullable `evidence.uploaded_by`.
    Widening a column to nullable is backward compatible for every existing row and every
    existing read -- no data is rewritten, no existing INSERT breaks (scanner evidence still
    supplies a tool_run_id). It is required because human-uploaded remediation proof has no
    tool run, and fabricating one would put a false claim into the evidence chain.
  * NEW permissions: remediation:read/manage, risk_assessment:read/manage, risk:accept, and the
    read-only `client_viewer` system role.

Follows the conventions of the existing seed migrations exactly: GUID column types on the
ad-hoc `table()` constructs (SQLAlchemy's generic sa.UUID binds `.hex`, which does NOT match
this schema's dashed CHAR(36) -- see 6a99a2128bba's comment for the full empirical account),
uuid.UUID(str(...)) normalization of raw role ids for PyMySQL, and backtick-quoted `key` in raw
SQL because it is a MySQL reserved word.
"""
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql
from sqlalchemy.sql import column, table

from apps.api.core.db_types import GUID, JSONType, UTCDateTime


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

permissions_table = table(
    "permissions",
    column("id", GUID()),
    column("key", sa.String()),
    column("description", sa.Text()),
)
roles_table = table(
    "roles",
    column("id", GUID()),
    column("workspace_id", GUID()),
    column("name", sa.String()),
    column("description", sa.Text()),
)
role_permissions_table = table(
    "role_permissions",
    column("role_id", GUID()),
    column("permission_id", GUID()),
)

NEW_PERMISSIONS: list[tuple[str, str]] = [
    ("remediation:read", "View remediation items, timelines, evidence and progress"),
    ("remediation:manage", "Create, assign, schedule and transition remediation work"),
    ("risk_assessment:read", "View client risk assessments and their findings"),
    ("risk_assessment:manage", "Create and issue client risk assessments"),
    ("risk:accept", "Formally accept the residual risk of a vulnerability"),
]

# WHO GETS WHAT, and why:
#   remediation:read / risk_assessment:read -- everyone including client_viewer: the whole
#     point of the client role is to SEE remediation progress and the assessment deliverable.
#   remediation:manage -- owner/admin/member. Members do the remediation work.
#   risk_assessment:manage -- owner/admin ONLY. Issuing freezes a client-facing document
#     permanently; that is a publishing decision, not day-to-day work.
#   risk:accept -- owner/admin ONLY. Deliberately NOT granted to member, and never to
#     client_viewer: accepting risk is a governance decision, and the requirement is explicit
#     that member -> DENY and client_viewer -> DENY.
ROLE_PERMISSION_NAMES: dict[str, list[str]] = {
    "remediation:read": ["owner", "admin", "member", "client_viewer"],
    "remediation:manage": ["owner", "admin", "member"],
    "risk_assessment:read": ["owner", "admin", "member", "client_viewer"],
    "risk_assessment:manage": ["owner", "admin"],
    "risk:accept": ["owner", "admin"],
}

CLIENT_VIEWER = "client_viewer"
CLIENT_VIEWER_DESCRIPTION = (
    "Read-only client access: can view projects, findings, remediation progress and risk "
    "assessments. Cannot change anything."
)

# The COMPLETE permission set for client_viewer. Strictly read-only: every key here is a
# `:read`/`:view`. The role is built by EXPLICIT ALLOWLIST rather than by copying `member` and
# subtracting -- a subtractive definition would silently grant any future permission added to
# member, which is exactly how a read-only role stops being read-only.
CLIENT_VIEWER_PERMISSIONS: list[str] = [
    "workspace:view",
    "project:read",
    "target:read",
    "scan:read",
    "asset:read",
    "vulnerability:read",
    "remediation:read",
    "risk_assessment:read",
    "report:read",
]


def upgrade() -> None:
    bind = op.get_bind()

    # --- 1) evidence: nullable tool_run_id + uploaded_by ------------------------------------
    # Widening to NULL only; existing rows and existing writes are unaffected. The column keeps
    # its FK and its index -- `existing_*` args are required by alembic's MySQL ALTER, which
    # rewrites the whole column definition rather than patching one attribute.
    op.alter_column(
        "evidence", "tool_run_id",
        existing_type=mysql.CHAR(36),
        nullable=True,
    )
    op.add_column("evidence", sa.Column("uploaded_by", GUID(), nullable=True))
    op.create_foreign_key(
        "fk_evidence_uploaded_by_users", "evidence", "users", ["uploaded_by"], ["id"],
        ondelete="SET NULL",
    )

    # --- 2) remediation_items ----------------------------------------------------------------
    op.create_table(
        "remediation_items",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("workspace_id", GUID(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", GUID(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("issue_key", sa.String(512), nullable=False),
        sa.Column("vulnerability_id", GUID(), sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True),
        sa.Column("remediation_id", GUID(), sa.ForeignKey("remediations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="proposed"),
        sa.Column("priority", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("assignee_user_id", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("due_date", UTCDateTime(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("notes_source", sa.String(16), nullable=True),
        sa.Column("source", sa.String(16), nullable=False, server_default="system"),
        sa.Column("resolved_at", UTCDateTime(), nullable=True),
        sa.Column("verified_at", UTCDateTime(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_by", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", UTCDateTime(), server_default=sa.text("CURRENT_TIMESTAMP(6)"), nullable=False),
        sa.Column(
            "updated_at", UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)"), nullable=False,
        ),
        # THE issue-level invariant, enforced by the database. 512 chars of utf8mb4 = 2048
        # bytes, well inside InnoDB's 3072-byte index key limit even combined with the 36-byte
        # project_id.
        sa.UniqueConstraint("project_id", "issue_key", name="uq_remediation_items_project_issue"),
    )
    op.create_index("ix_remediation_items_workspace_id", "remediation_items", ["workspace_id"])
    op.create_index("ix_remediation_items_project_id", "remediation_items", ["project_id"])
    op.create_index("ix_remediation_items_vulnerability_id", "remediation_items", ["vulnerability_id"])
    op.create_index("ix_remediation_items_assignee_user_id", "remediation_items", ["assignee_user_id"])
    op.create_index("ix_remediation_items_ws_status", "remediation_items", ["workspace_id", "status"])
    op.create_index("ix_remediation_items_due", "remediation_items", ["workspace_id", "due_date"])

    # --- 3) remediation_events (append-only) -------------------------------------------------
    op.create_table(
        "remediation_events",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("workspace_id", GUID(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "remediation_item_id", GUID(),
            sa.ForeignKey("remediation_items.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("event_type", sa.String(48), nullable=False),
        sa.Column("from_status", sa.String(32), nullable=True),
        sa.Column("to_status", sa.String(32), nullable=True),
        sa.Column("actor_user_id", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", UTCDateTime(), server_default=sa.text("CURRENT_TIMESTAMP(6)"), nullable=False),
    )
    op.create_index("ix_remediation_events_workspace_id", "remediation_events", ["workspace_id"])
    op.create_index("ix_remediation_events_remediation_item_id", "remediation_events", ["remediation_item_id"])
    op.create_index("ix_remediation_events_created_at", "remediation_events", ["created_at"])
    op.create_index(
        "ix_remediation_events_item_created", "remediation_events", ["remediation_item_id", "created_at"]
    )

    # --- 4) remediation_evidence (join table onto the ONE evidence store) --------------------
    op.create_table(
        "remediation_evidence",
        sa.Column(
            "remediation_item_id", GUID(),
            sa.ForeignKey("remediation_items.id", ondelete="CASCADE"), primary_key=True,
        ),
        sa.Column("evidence_id", GUID(), sa.ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("workspace_id", GUID(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("uploaded_by", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", UTCDateTime(), server_default=sa.text("CURRENT_TIMESTAMP(6)"), nullable=False),
    )
    op.create_index("ix_remediation_evidence_workspace_id", "remediation_evidence", ["workspace_id"])

    # --- 5) verification_requests -------------------------------------------------------------
    op.create_table(
        "verification_requests",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("workspace_id", GUID(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "remediation_item_id", GUID(),
            sa.ForeignKey("remediation_items.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("result", sa.String(16), nullable=True),
        sa.Column("scan_id", GUID(), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("requested_by", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("claimed_by_token", GUID(), nullable=True),
        sa.Column("claimed_at", UTCDateTime(), nullable=True),
        sa.Column("completed_at", UTCDateTime(), nullable=True),
        sa.Column("detail", JSONType(), nullable=False),
        sa.Column("created_at", UTCDateTime(), server_default=sa.text("CURRENT_TIMESTAMP(6)"), nullable=False),
    )
    op.create_index("ix_verification_requests_workspace_id", "verification_requests", ["workspace_id"])
    op.create_index(
        "ix_verification_requests_remediation_item_id", "verification_requests", ["remediation_item_id"]
    )
    op.create_index("ix_verification_requests_scan_id", "verification_requests", ["scan_id"])
    op.create_index("ix_verification_requests_ws_status", "verification_requests", ["workspace_id", "status"])

    # --- 6) risk_acceptances -------------------------------------------------------------------
    op.create_table(
        "risk_acceptances",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("workspace_id", GUID(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", GUID(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "vulnerability_id", GUID(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "remediation_item_id", GUID(),
            sa.ForeignKey("remediation_items.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("accepted_by", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("approved_by", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column("review_due_at", UTCDateTime(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("revoked_by", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("revoked_at", UTCDateTime(), nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=True),
        sa.Column("created_at", UTCDateTime(), server_default=sa.text("CURRENT_TIMESTAMP(6)"), nullable=False),
        sa.Column(
            "updated_at", UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)"), nullable=False,
        ),
    )
    op.create_index("ix_risk_acceptances_workspace_id", "risk_acceptances", ["workspace_id"])
    op.create_index("ix_risk_acceptances_project_id", "risk_acceptances", ["project_id"])
    op.create_index("ix_risk_acceptances_vulnerability_id", "risk_acceptances", ["vulnerability_id"])
    op.create_index("ix_risk_acceptances_remediation_item_id", "risk_acceptances", ["remediation_item_id"])
    op.create_index("ix_risk_acceptances_ws_status", "risk_acceptances", ["workspace_id", "status"])
    # Drives the expiry sweep's `status='active' AND expires_at <= now()` scan.
    op.create_index("ix_risk_acceptances_expiry", "risk_acceptances", ["status", "expires_at"])

    # --- 7) risk_assessments --------------------------------------------------------------------
    op.create_table(
        "risk_assessments",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("workspace_id", GUID(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        # NULLABLE: a workspace-wide assessment (no single project) is a legitimate scope.
        sa.Column("project_id", GUID(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("period_start", UTCDateTime(), nullable=False),
        sa.Column("period_end", UTCDateTime(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("security_score", sa.Integer(), nullable=True),
        sa.Column("score_band", sa.String(16), nullable=True),
        sa.Column("summary", JSONType(), nullable=False),
        sa.Column("narrative", sa.Text(), nullable=True),
        sa.Column("narrative_source", sa.String(16), nullable=True),
        sa.Column(
            "previous_assessment_id", GUID(),
            sa.ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("report_id", GUID(), sa.ForeignKey("reports.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_by", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("issued_by", GUID(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("issued_at", UTCDateTime(), nullable=True),
        sa.Column("created_at", UTCDateTime(), server_default=sa.text("CURRENT_TIMESTAMP(6)"), nullable=False),
        sa.Column(
            "updated_at", UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)"), nullable=False,
        ),
    )
    op.create_index("ix_risk_assessments_workspace_id", "risk_assessments", ["workspace_id"])
    op.create_index("ix_risk_assessments_project_id", "risk_assessments", ["project_id"])
    op.create_index(
        "ix_risk_assessments_ws_project_status", "risk_assessments", ["workspace_id", "project_id", "status"]
    )
    op.create_index("ix_risk_assessments_issued", "risk_assessments", ["workspace_id", "issued_at"])

    # --- 8) risk_assessment_findings (frozen) ----------------------------------------------------
    op.create_table(
        "risk_assessment_findings",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("workspace_id", GUID(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "assessment_id", GUID(),
            sa.ForeignKey("risk_assessments.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("issue_key", sa.String(512), nullable=False),
        sa.Column("vulnerability_id", GUID(), sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True),
        sa.Column("frozen_title", sa.String(512), nullable=False),
        sa.Column("frozen_severity", sa.String(16), nullable=False),
        sa.Column("frozen_cvss_score", sa.Float(), nullable=True),
        sa.Column("frozen_final_risk_score", sa.Float(), nullable=True),
        sa.Column("frozen_vulnerability_status", sa.String(24), nullable=False),
        sa.Column("frozen_remediation_status", sa.String(32), nullable=True),
        sa.Column("risk_accepted", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("location_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", UTCDateTime(), server_default=sa.text("CURRENT_TIMESTAMP(6)"), nullable=False),
    )
    # AUDIT-009: these two mirror `index=True` on the model's columns, so they MUST carry the
    # name SQLAlchemy derives there (ix_<table>_<column>) -- the repo-wide convention every
    # other migration follows via op.f(). Hand-shortening them to ix_raf_* made `alembic check`
    # report perpetual drift (drop ix_raf_*, add ix_risk_assessment_findings_*). The composite
    # index below is declared explicitly in __table_args__, so ITS short name is canonical and
    # stays as-is.
    op.create_index(
        op.f("ix_risk_assessment_findings_workspace_id"), "risk_assessment_findings", ["workspace_id"]
    )
    op.create_index(
        op.f("ix_risk_assessment_findings_assessment_id"), "risk_assessment_findings", ["assessment_id"]
    )
    op.create_index(
        "ix_raf_assessment_severity", "risk_assessment_findings", ["assessment_id", "frozen_severity"]
    )

    # --- 9) permissions + the client_viewer role -------------------------------------------------
    permission_ids = {key: uuid.uuid4() for key, _ in NEW_PERMISSIONS}
    op.bulk_insert(
        permissions_table,
        [{"id": permission_ids[key], "key": key, "description": desc} for key, desc in NEW_PERMISSIONS],
    )

    # Create the client_viewer SYSTEM role (workspace_id NULL, like owner/admin/member).
    client_viewer_id = uuid.uuid4()
    op.bulk_insert(
        roles_table,
        [{
            "id": client_viewer_id, "workspace_id": None,
            "name": CLIENT_VIEWER, "description": CLIENT_VIEWER_DESCRIPTION,
        }],
    )

    role_rows = bind.execute(sa.text("SELECT id, name FROM roles WHERE workspace_id IS NULL")).fetchall()
    # Same PyMySQL str -> uuid.UUID normalization as every other seed migration in this chain.
    role_ids = {name: uuid.UUID(str(role_id)) for role_id, name in role_rows}

    grants = [
        {"role_id": role_ids[role_name], "permission_id": permission_ids[perm_key]}
        for perm_key, role_names in ROLE_PERMISSION_NAMES.items()
        for role_name in role_names
        if role_name in role_ids
    ]

    # client_viewer's PRE-EXISTING read permissions (workspace:view, project:read, ... ) are
    # looked up by key rather than assumed: they were seeded by earlier migrations in this
    # chain, and resolving them here keeps the role's grant set complete in ONE place. A key
    # that does not exist is skipped rather than failing the migration -- the allowlist is
    # deliberately conservative and a missing optional permission must not block the upgrade.
    existing_perms = {
        key: uuid.UUID(str(pid))
        for pid, key in bind.execute(sa.text("SELECT id, `key` FROM permissions")).fetchall()
    }
    for key in CLIENT_VIEWER_PERMISSIONS:
        pid = existing_perms.get(key) or permission_ids.get(key)
        if pid is None:
            continue
        grant = {"role_id": client_viewer_id, "permission_id": pid}
        if grant not in grants:
            grants.append(grant)

    op.bulk_insert(role_permissions_table, grants)


def downgrade() -> None:
    keys = ", ".join(f"'{key}'" for key, _ in NEW_PERMISSIONS)
    # Drop client_viewer's grants first (its role_permissions reference permissions that other
    # roles also hold, so target the ROLE, then the new permission keys).
    op.execute(
        "DELETE FROM role_permissions WHERE role_id IN "
        f"(SELECT id FROM roles WHERE workspace_id IS NULL AND name = '{CLIENT_VIEWER}')"
    )
    op.execute(
        f"DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE `key` IN ({keys}))"
    )
    op.execute(f"DELETE FROM permissions WHERE `key` IN ({keys})")
    op.execute(f"DELETE FROM roles WHERE workspace_id IS NULL AND name = '{CLIENT_VIEWER}'")

    op.drop_table("risk_assessment_findings")
    op.drop_table("risk_assessments")
    op.drop_table("risk_acceptances")
    op.drop_table("verification_requests")
    op.drop_table("remediation_evidence")
    op.drop_table("remediation_events")
    op.drop_table("remediation_items")

    op.drop_constraint("fk_evidence_uploaded_by_users", "evidence", type_="foreignkey")
    op.drop_column("evidence", "uploaded_by")
    # Narrowing back to NOT NULL would FAIL if any remediation-proof row exists (its
    # tool_run_id is legitimately NULL). Those rows are removed above by the
    # remediation_evidence drop only in the join sense -- the evidence rows themselves remain --
    # so delete the orphaned proof rows first, which is the correct inverse of a migration that
    # created the ability to store them.
    op.execute("DELETE FROM evidence WHERE tool_run_id IS NULL")
    op.alter_column(
        "evidence", "tool_run_id",
        existing_type=mysql.CHAR(36),
        nullable=False,
    )
