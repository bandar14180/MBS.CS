"""Prompt 34: enforce the APPEND-ONLY property both audit tables already claim.

`AuditEvent` and `PlatformAuditEvent` are documented as immutable/append-only, and every
current call site only ever INSERTs. Until now nothing enforced that: an ORM `UPDATE` or
`DELETE` against either table would have been accepted silently, which is precisely the
manipulation an audit log exists to make impossible. An audit trail that can be edited in
place is not evidence of anything.

WHY A `before_flush` HOOK, and why here:
  * The tenancy filter's `do_orm_execute` hook does not fire for flush-time INSERT/UPDATE/
    DELETE (documented empirically in apps/api/core/tenancy.py) -- `before_flush` does.
  * This lives in the audit module rather than core/tenancy.py because it is an audit
    invariant, not a tenancy one, and tenancy.py's hook has a different purpose.

SCOPE AND HONEST LIMITS:
  * This guards the ORM path. It is NOT a database-level control: raw SQL (`text()`), a
    direct MySQL client, or a DBA with UPDATE/DELETE grants all bypass it. True
    tamper-evidence at the storage layer requires either a restricted grant (no UPDATE/
    DELETE on these tables for the application user) or hash-chaining, neither of which is
    in place. See the batch report for this limitation.
  * Retention/erasure paths that must legitimately remove audit rows are covered by the
    explicit `allow_audit_deletion()` escape hatch below, so a GDPR/retention job stays
    possible without leaving the table generally writable.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

from sqlalchemy import event
from sqlalchemy.orm import Session

from apps.api.modules.audit.models import AuditEvent
from apps.api.modules.audit.platform_models import PlatformAuditEvent

_AUDIT_MODELS = (AuditEvent, PlatformAuditEvent)

# Set only inside `allow_audit_deletion()`. A ContextVar (not a module global) so a
# concurrent request/task cannot observe another one's escape hatch.
_deletion_allowed: ContextVar[bool] = ContextVar("mbs_audit_deletion_allowed", default=False)


class AuditImmutabilityError(RuntimeError):
    """Raised when code attempts to modify or delete a persisted audit event."""


@contextmanager
def allow_audit_deletion() -> Iterator[None]:
    """Permit audit-row DELETE for the duration of the block.

    Deliberately narrow: it unlocks DELETE only -- an UPDATE to an audit row is never
    legitimate, because rewriting history is not the same as expiring it. Intended for
    retention/erasure jobs and tenant hard-deletion, which remove whole rows by policy."""
    token = _deletion_allowed.set(True)
    try:
        yield
    finally:
        _deletion_allowed.reset(token)


def _is_audit(obj: object) -> bool:
    return isinstance(obj, _AUDIT_MODELS)


def install() -> None:
    """Register the append-only guard. Idempotent."""
    if getattr(install, "_installed", False):
        return

    @event.listens_for(Session, "before_flush")
    def _guard_audit_mutation(session: Session, flush_context, instances) -> None:
        for obj in session.dirty:
            # `dirty` is optimistic -- it includes objects touched but not actually
            # changed, so confirm a real column modification before refusing.
            if _is_audit(obj) and session.is_modified(obj, include_collections=False):
                raise AuditImmutabilityError(
                    f"{type(obj).__name__} is append-only: UPDATE of a persisted audit event "
                    "is never permitted."
                )
        if not _deletion_allowed.get():
            for obj in session.deleted:
                if _is_audit(obj):
                    raise AuditImmutabilityError(
                        f"{type(obj).__name__} is append-only: DELETE requires the explicit "
                        "allow_audit_deletion() retention escape hatch."
                    )

    install._installed = True  # type: ignore[attr-defined]
