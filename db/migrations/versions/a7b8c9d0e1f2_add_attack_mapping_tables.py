"""add attack_mappings and attack_narratives tables

MITRE ATT&CK technique + Cyber Kill Chain mapping (Phase 2). Two additive tables:

  * attack_mappings   -- per-vulnerability deterministic technique/phase rows
                         (analogue of compliance_mappings). RLS scopes through
                         vulnerabilities -> projects.workspace_id, exactly like
                         compliance_mappings/risk_scores (no own workspace column).
  * attack_narratives -- one AI-generated attack-path narrative per scan. Scans
                         are RLS-exempt, so this table carries its own
                         workspace_id and uses the ENABLE + FORCE RLS pattern
                         from ai_usage.

Revision ID: a7b8c9d0e1f2
Revises: f1a2b3c4d5e6
Create Date: 2026-07-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "a7b8c9d0e1f2"
down_revision: Union[str, None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attack_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vulnerability_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("tactic_id", sa.String(16), nullable=False),
        sa.Column("tactic_name", sa.String(64), nullable=False),
        sa.Column("technique_id", sa.String(16), nullable=False),
        sa.Column("technique_name", sa.String(128), nullable=False),
        sa.Column("kill_chain_phase", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("vulnerability_id", "technique_id", name="uq_attack_vuln_technique"),
    )
    op.create_index("ix_attack_mappings_vulnerability_id", "attack_mappings", ["vulnerability_id"])

    op.create_table(
        "attack_narratives",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "scan_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("steps", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("model_version", sa.String(128), nullable=True),
        sa.Column("prompt_version", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("scan_id", name="uq_attack_narrative_scan"),
    )
    op.create_index("ix_attack_narratives_workspace_id", "attack_narratives", ["workspace_id"])
    op.create_index("ix_attack_narratives_scan_id", "attack_narratives", ["scan_id"])

    # RLS: attack_mappings scopes through vulnerabilities -> projects.workspace_id
    # (identical to compliance_mappings). The worker sets app.current_workspace_id
    # before writing during a scan.
    op.execute("ALTER TABLE attack_mappings ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE attack_mappings FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY workspace_isolation ON attack_mappings USING ("
        "vulnerability_id IN (SELECT v.id FROM vulnerabilities v JOIN projects p ON p.id = v.project_id "
        "WHERE p.workspace_id = current_setting('app.current_workspace_id', true)::uuid))"
    )

    # RLS: attack_narratives has its own workspace_id (scans are RLS-exempt), same
    # ENABLE + FORCE pattern as ai_usage.
    op.execute("ALTER TABLE attack_narratives ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE attack_narratives FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY workspace_isolation ON attack_narratives USING ("
        "workspace_id = current_setting('app.current_workspace_id', true)::uuid)"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS workspace_isolation ON attack_narratives")
    op.drop_index("ix_attack_narratives_scan_id", table_name="attack_narratives")
    op.drop_index("ix_attack_narratives_workspace_id", table_name="attack_narratives")
    op.drop_table("attack_narratives")

    op.execute("DROP POLICY IF EXISTS workspace_isolation ON attack_mappings")
    op.drop_index("ix_attack_mappings_vulnerability_id", table_name="attack_mappings")
    op.drop_table("attack_mappings")
