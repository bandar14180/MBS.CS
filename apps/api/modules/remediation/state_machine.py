"""The remediation lifecycle, as data.

Kept in its own module -- pure, importable with no database -- so the legal-transition table
is one auditable object rather than a chain of `if` statements spread through the service, and
so the transition tests can enumerate the whole graph directly instead of guessing at it.
"""

from apps.api.modules.remediation.models import (
    STATUS_ACCEPTED,
    STATUS_AWAITING_VERIFICATION,
    STATUS_CLOSED,
    STATUS_IN_PROGRESS,
    STATUS_PROPOSED,
    STATUS_REJECTED,
    STATUS_REOPENED,
    STATUS_RISK_ACCEPTED,
    STATUS_VERIFIED,
)

# The approved lifecycle. Anything not listed here is ILLEGAL and rejected with 409.
#
#   proposed -> accepted -> in_progress -> awaiting_verification -> verified -> closed
#
# plus the explicitly approved side paths. Each entry is a domain statement:
#
#   * risk_accepted is reachable from any state where work has NOT yet been proven done
#     (proposed / accepted / in_progress) -- deciding to live with a risk is a legitimate
#     alternative to fixing it, but not a way to retroactively re-label completed work.
#   * awaiting_verification -> in_progress is the "verification failed, back to the bench"
#     path, and is also what a FAILED verification result drives automatically.
#   * verified -> reopened and closed -> reopened exist because a regression is real: the
#     scanner re-detecting the issue must be able to revive the work item rather than
#     forcing a duplicate one (which the (project_id, issue_key) unique constraint forbids
#     anyway).
#   * reopened behaves like a fresh proposed item.
#   * rejected and risk_accepted are deliberately NOT dead ends -- a rejected item can be
#     re-proposed and an expired/revoked acceptance must be able to return to work, which is
#     what makes acceptance expiry meaningful rather than cosmetic.
LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    STATUS_PROPOSED: frozenset({STATUS_ACCEPTED, STATUS_RISK_ACCEPTED, STATUS_REJECTED}),
    STATUS_ACCEPTED: frozenset({STATUS_IN_PROGRESS, STATUS_RISK_ACCEPTED, STATUS_REJECTED}),
    STATUS_IN_PROGRESS: frozenset({STATUS_AWAITING_VERIFICATION, STATUS_RISK_ACCEPTED}),
    STATUS_AWAITING_VERIFICATION: frozenset({STATUS_VERIFIED, STATUS_IN_PROGRESS}),
    STATUS_VERIFIED: frozenset({STATUS_CLOSED, STATUS_REOPENED}),
    STATUS_CLOSED: frozenset({STATUS_REOPENED}),
    STATUS_REOPENED: frozenset({STATUS_ACCEPTED, STATUS_IN_PROGRESS, STATUS_RISK_ACCEPTED}),
    STATUS_RISK_ACCEPTED: frozenset({STATUS_REOPENED, STATUS_IN_PROGRESS}),
    STATUS_REJECTED: frozenset({STATUS_PROPOSED}),
}

# Transitions a HUMAN may not drive directly through the generic transition endpoint, because
# reaching them requires evidence the endpoint cannot supply:
#   * verified          -- only complete_verification() sets this, from a real retest result.
#   * risk_accepted     -- only accept_risk() sets this, and only with `risk:accept`,
#                          a justification and an expiry.
# Listing them here (rather than omitting them from LEGAL_TRANSITIONS) keeps the graph honest:
# they ARE legal transitions, they just have a specific authorized entry point.
GUARDED_TARGETS = frozenset({STATUS_VERIFIED, STATUS_RISK_ACCEPTED})


def is_legal(from_status: str, to_status: str) -> bool:
    """Is this transition in the approved graph at all? A self-transition (X -> X) is NOT
    legal: it would append a misleading event and bump the version for a change that did not
    happen."""
    return to_status in LEGAL_TRANSITIONS.get(from_status, frozenset())


def allowed_targets(from_status: str) -> frozenset[str]:
    return LEGAL_TRANSITIONS.get(from_status, frozenset())
