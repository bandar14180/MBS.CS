import re
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.audit.models import AuditEvent
from apps.api.modules.audit.platform_models import PlatformAuditEvent

# Prompt 34: audit outcomes. An audit row states what HAPPENED, so "attempted" is not an
# outcome -- an action that was tried and refused is `denied`, one that errored is `failure`.
OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_DENIED = "denied"
VALID_OUTCOMES = frozenset({OUTCOME_SUCCESS, OUTCOME_FAILURE, OUTCOME_DENIED})

# Prompt 34: defence-in-depth scrub for the free-text `detail` field.
#
# This is a BACKSTOP, not the control. The control is that callers pass only non-sensitive
# summaries; every current call site does. But `detail` is the one free-text field in the
# audit record, and an audit log is exactly the wrong place to discover a leaked token
# later, so a caller mistake redacts here instead of persisting a live credential.
#
# Deliberately pattern-based on the SECRET-BEARING shapes (key=value pairs, Bearer headers,
# PEM blocks, JWTs) rather than attempting to detect secrets by entropy -- entropy scoring
# produces false positives on hashes and ids, which this table legitimately stores.
_SENSITIVE_KEY = (
    r"password|passwd|secret|token|api[_-]?key|apikey|authorization|cookie|session|"
    r"credential|private[_-]?key|refresh[_-]?token|access[_-]?token|client[_-]?secret"
)
_REDACTED = "[REDACTED]"
_SCRUBBERS: tuple[tuple[re.Pattern[str], str], ...] = (
    # key=value / key: value / "key": "value" -- keeps the KEY (not sensitive, and it tells
    # the reader WHAT was redacted) and replaces only the value.
    (
        re.compile(r"""(?i)\b(""" + _SENSITIVE_KEY + r""")\b["']?\s*[=:]\s*["']?[^\s,;&"'}]+"""),
        r"\1=" + _REDACTED,
    ),
    # Authorization: Bearer <token> / Basic <b64>
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + _REDACTED),
    # Bare JWTs anywhere in the string.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), _REDACTED),
    # PEM private key blocks.
    (re.compile(r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"), _REDACTED),
)


def scrub_detail(detail: str | None) -> str | None:
    """Redact credential-shaped substrings from an audit `detail` before persistence.

    Returns the value unchanged when nothing matches, so ordinary details (ids, statuses,
    counts, tool names) are stored verbatim and stay useful."""
    if not detail:
        return detail
    for pattern, replacement in _SCRUBBERS:
        detail = pattern.sub(replacement, detail)
    return detail


def _current_correlation_id() -> str | None:
    """The request/task correlation id, or None outside a correlated context.

    `get_correlation_id()` returns the contextvar default "-" when nothing set it; that is an
    absence, not an id, so it is normalized to NULL rather than stored literally."""
    from apps.api.core.observability import get_correlation_id

    value = get_correlation_id()
    return value if value and value != "-" else None


async def record_platform_event(
    db: AsyncSession,
    workspace_id: uuid.UUID | None,
    actor_user_id: uuid.UUID | None,
    event: str,
    *,
    detail: str | None = None,
) -> None:
    """Append a DURABLE, non-cascading platform audit record (platform_audit_events -- no FK to
    workspaces, so it survives the workspace hard deletion) and flush it. Used for destructive
    tenant operations (tenant.delete.*) and, since P8-G, for Phase 8 scanner/VPN operator
    actions. Secret-free: only ids / event name / non-sensitive detail are stored.

    `workspace_id` may be None for a PLATFORM-SCOPED event -- one with no workspace at all,
    such as the private-scanning emergency kill switch or an action on a shared public
    scanner worker. See the column comment on PlatformAuditEvent for why NULL rather than a
    sentinel UUID."""
    db.add(
        PlatformAuditEvent(
            workspace_id=workspace_id,
            actor_user_id=actor_user_id,
            event=event,
            detail=scrub_detail(detail),
            correlation_id=_current_correlation_id(),
        )
    )
    await db.flush()


async def record(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    *,
    resource_id: uuid.UUID | None = None,
    detail: str | None = None,
    outcome: str | None = None,
) -> None:
    """Append an audit event. Flushes (does NOT commit) so the event is atomic
    with the action's own transaction. Denormalizes the actor email so the record
    survives the user being deleted later.

    `outcome` is one of OUTCOME_SUCCESS / OUTCOME_FAILURE / OUTCOME_DENIED, or None when the
    caller has no outcome to state. An unrecognized value is rejected rather than stored, so
    the column stays queryable. `detail` is scrubbed (see `scrub_detail`) and the current
    correlation id is attached automatically."""
    if outcome is not None and outcome not in VALID_OUTCOMES:
        raise ValueError(f"invalid audit outcome {outcome!r}; expected one of {sorted(VALID_OUTCOMES)}")

    actor_email = None
    if actor_user_id is not None:
        from apps.api.modules.users.models import User

        user = await db.get(User, actor_user_id)
        actor_email = user.email if user else None

    db.add(
        AuditEvent(
            workspace_id=workspace_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=scrub_detail(detail),
            outcome=outcome,
            correlation_id=_current_correlation_id(),
        )
    )
    await db.flush()


async def list_events(
    db: AsyncSession, workspace_id: uuid.UUID, action: str | None = None, page: Pagination | None = None
) -> tuple[list[AuditEvent], int]:
    query = select(AuditEvent).where(AuditEvent.workspace_id == workspace_id)
    if action:
        query = query.where(AuditEvent.action == action)
    query = query.order_by(AuditEvent.created_at.desc(), AuditEvent.id)
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))
