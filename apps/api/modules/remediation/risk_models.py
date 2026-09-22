"""Risk treatment: formal, expiring acceptance of a vulnerability's residual risk.

WHAT ACCEPTING RISK IS
----------------------
A TREATMENT DECISION, not a severity change. Accepting risk records that an authorized person
decided, with a written justification and an expiry date, to live with a finding. It therefore
must NOT (and, in the service layer, provably does not):

  * change `vulnerabilities.severity`   -- the scanner's technical severity;
  * change `vulnerabilities.cvss_score` / `cvss_vector`;
  * change `risk_scores.final_risk_score` -- the risk engine owns it;
  * delete the finding or touch its scanner evidence.

The ONLY way it can affect posture is through the EXISTING, approved vulnerability-status
semantics: an authorized actor may separately move the vulnerability to `accepted_risk` via
the ordinary status endpoint (scoring.ACTIVE_STATUSES already excludes that status). This
table records the DECISION and its lifecycle; it never reaches into the scoring model.

WHY IT IS ITS OWN TABLE AND PERMISSION
--------------------------------------
`vulnerabilities.status_justification` already carried a free-text reason, but it has no
approver, no expiry, no review date, and no revocation -- so an "accepted risk" was accepted
forever, silently, by anyone holding `vulnerability:manage`. Expiry is the substantive
addition: an acceptance that cannot lapse is indistinguishable from ignoring the finding.
Acceptance is gated on its own `risk:accept` permission, granted to owner/admin only and
explicitly withheld from `member` and `client_viewer`.
"""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base
from apps.api.core.db_types import GUID, UTCDateTime

STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"
STATUS_REVOKED = "revoked"
RISK_ACCEPTANCE_STATUSES = frozenset({STATUS_ACTIVE, STATUS_EXPIRED, STATUS_REVOKED})


class RiskAcceptance(Base):
    """One formal acceptance of one vulnerability's residual risk.

    Not unique per vulnerability: a lapsed or revoked acceptance stays on the record and a new
    one may be granted afterwards, which is the whole point of an audit trail. The service
    layer enforces AT MOST ONE `active` acceptance per vulnerability instead (a partial-unique
    index would be the structural equivalent, but MySQL has no filtered indexes, so the
    invariant is enforced in `accept_risk` under the row lock it already takes).
    """

    __tablename__ = "risk_acceptances"
    __table_args__ = (
        Index("ix_risk_acceptances_ws_status", "workspace_id", "status"),
        Index("ix_risk_acceptances_expiry", "status", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # The remediation item this acceptance closes out, when the acceptance was made through the
    # workflow. Nullable because a vulnerability may be accepted without a remediation item
    # having been created for its issue.
    remediation_item_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("remediation_items.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # REQUIRED, non-empty (enforced by the schema's min_length). An acceptance with no stated
    # reason is not an accepted risk, it is an ignored one.
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    accepted_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Separate approver, where the organisation requires four-eyes. Nullable: when the acceptor
    # is themselves the approving authority there is no second party to record, and inventing
    # one would misrepresent the decision.
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # REQUIRED. Enforced as a future timestamp at creation. The expiry sweep flips `active` ->
    # `expired` once passed, so an acceptance cannot outlive its stated window by inaction.
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    # When the decision should next be looked at. Optional and independent of expiry (a
    # 12-month acceptance may still warrant a 3-month review).
    review_due_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default=STATUS_ACTIVE)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), onupdate=text("CURRENT_TIMESTAMP(6)")
    )
