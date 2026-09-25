"""tool_runs execution trace (Prompt 10)

Purely ADDITIVE: two nullable/defaulted columns on `tool_runs`, no data migration, no
change to any existing column, index, or constraint.

WHY: `tool_runs.command_hash` already recorded a SHA-256 digest of the exact command a
tool was invoked with, but a hash can only confirm a match against a value the caller
already possesses -- it cannot answer "what arguments actually ran" for an operator
investigating a scan after the fact. On the in-process orchestrator path the real command
text existed only inside the free-text evidence blob (`orchestrator._run_single_tool`'s
`f"$ {raw.command}\n\n=== STDOUT ==="`); on the remote/lease execution plane
(scanner_manager/app.py's `/v1/tool-started` and `/v1/tool-results`) `command_hash` was
never populated at all (hardcoded `""`), so that path recorded no reconstructible command
whatsoever. `effective_command` closes that gap directly on the row the rest of the trace
(status/exit_code/timestamps) already lives on.

Every tool runner also already computed whether ITS run hit its own wall-clock budget
(`base.run_with_timeout` returns `TimedRun.timed_out`), but that fact was discarded the
moment it was folded into a free-text "timed out" suffix on stderr plus a bare
`exit_code=-1` -- indistinguishable, without string-matching stderr, from a genuine tool
crash that also happens to exit -1. `timed_out` makes that a first-class, queryable fact.

Neither column can carry secrets: `scan.config` (the source of every effective argument)
carries only tuning knobs -- timeouts, port counts, rates, tags, wordlist paths -- and no
tool runner ever receives a credential/API key/token as a CLI argument (see
tool_runners/*.py). This is the same class of information `command_hash` already
digested; nothing new is exposed to any principal that could not already see the raw
evidence text this merely makes structured and queryable.

`timed_out` is NOT NULL with a server default of 0/false, so it is safe to add to a live
table without a data migration: every existing row reads as "did not time out", which is
the true historical fact for a row that predates this column (a scan that DID time out
already recorded that fact elsewhere -- in `error_message`/stderr -- unaffected by this).

Revision ID: a3b4c5d6e7f8
Revises: f7a8b9c0d1e2
Create Date: 2026-09-18 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a3b4c5d6e7f8"
down_revision: Union[str, None] = "f7a8b9c0d1e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("tool_runs", sa.Column("effective_command", sa.Text(), nullable=True))
    op.add_column(
        "tool_runs",
        sa.Column(
            "timed_out",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )


def downgrade() -> None:
    op.drop_column("tool_runs", "timed_out")
    op.drop_column("tool_runs", "effective_command")
