"""Prompt 36 -- readiness boundary for FUTURE Hydra-style authentication testing.

WHAT THIS IS
============
A SAFETY CONTRACT and a statement of the missing boundaries. It defines the preconditions
any future credential-testing capability must satisfy BEFORE a single authentication attempt
could be made, expressed against the controls this platform already has.

WHAT THIS IS NOT
================
  * Not a brute-force engine, password sprayer, or credential-stuffing subsystem.
  * Not a customer-facing runner: nothing here subclasses BaseToolRunner, registers a
    capability, or appears in the tool registry, so the orchestrator CANNOT schedule it.
  * Not an executor: this module never spawns a process, opens a socket, or touches a
    target. It is pure, synchronous policy evaluation.

No credential attack can be performed through this module. It only ever ANSWERS "would this
be permitted, and what is still missing?" -- and the honest answer today is that it is not
permitted, because the platform is missing the pieces documented under MISSING BOUNDARIES.

REUSED ARCHITECTURE (audited, Prompt 36)
========================================
Nothing new is invented where a control already exists:

  authorization      -> modules/authorization_scope: `require_verified_target()` already
                        refuses to test a target whose ownership is not verified.
  target policy/scope -> scanner_engine/scope_guard.host_in_scope() + net_policy/egress_guard.
  safety gating      -> scanner_engine/safety.assert_action_allowed(). Credential testing is
                        INTRUSIVE (see TIER below), so it inherits the existing double gate:
                        engagement ceiling AND deployment-wide exploitation_enabled.
  tenant isolation   -> the existing workspace filter (core/tenancy.py). Unchanged.
  audit              -> modules/audit (Prompt 34), including the append-only guard.
  emergency stop     -> modules/scans.cancel_scan + the private-scanning emergency kill
                        switch (audit/scanner_ops.record_emergency_transition).
  worker isolation   -> the existing lease/execution-token fencing and heartbeat handling.
  encryption at rest -> core/mfa.py's Fernet pattern is the precedent a credential vault
                        would follow; it is NOT reused directly (that key is MFA's).

THE TIER DECISION
=================
Credential testing is classified INTRUSIVE, not ACTIVE_SAFE. Submitting real credentials to
a live authentication endpoint is state-changing by nature: it writes to auth logs, moves
lockout counters toward a threshold, can trip alerting, and can deny service to real users.
Calling it "active but non-intrusive" would be false, and would let it run under a ceiling
that was never chosen for it.

MISSING BOUNDARIES -- DOCUMENTED, NOT IMPLEMENTED
=================================================
Per this prompt, where the architecture is not ready the exact gap is stated instead of
building something unsafe. These are the gaps; `readiness_report()` returns them
machine-readably.

  1. NO TARGET-CREDENTIAL STORE. The platform holds credentials for ITS OWN users (password
     hashes, MFA secrets) but has NO model, table or vault for credentials belonging to a
     CUSTOMER'S target system. There is therefore nowhere for a credential list to live, and
     no encryption, ownership, retention or deletion policy governing one. This is the
     single largest gap and is a deliberate design decision to keep, not an oversight.
  2. NO LOCKOUT-SAFETY SIGNAL. Nothing in the platform can observe or model a target's
     account-lockout threshold. Without it, any attempt budget is a guess, and a wrong guess
     locks out real users -- a denial of service committed against the customer.
  3. NO PER-TARGET ATTEMPT RATE LIMITER. The existing limiter (core/middleware.py) governs
     INBOUND API traffic to this platform. There is no OUTBOUND per-target, per-account
     attempt governor, which is the control credential testing actually requires.
  4. NO CREDENTIAL-SAFE EVIDENCE PATH. Evidence is stored verbatim (raw tool output). A
     credential tool's output contains the credentials it tried. Storing that would put live
     secrets into the evidence store and the report pipeline. A redacting evidence path
     would have to exist first.

Until all four are closed, `evaluate_readiness()` refuses. It is written to fail closed: an
unknown or unrepresentable condition denies rather than permits.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from apps.api.scanner_engine.safety import SafetyTier

# Credential testing is INTRUSIVE. See THE TIER DECISION above.
CREDENTIAL_TESTING_TIER = SafetyTier.INTRUSIVE

# The four gaps from MISSING BOUNDARIES, as stable machine-readable ids.
GAP_NO_CREDENTIAL_STORE = "no_target_credential_store"
GAP_NO_LOCKOUT_SIGNAL = "no_lockout_safety_signal"
GAP_NO_ATTEMPT_RATE_LIMITER = "no_per_target_attempt_rate_limiter"
GAP_NO_REDACTING_EVIDENCE = "no_credential_safe_evidence_path"

BLOCKING_GAPS: tuple[str, ...] = (
    GAP_NO_CREDENTIAL_STORE,
    GAP_NO_LOCKOUT_SIGNAL,
    GAP_NO_ATTEMPT_RATE_LIMITER,
    GAP_NO_REDACTING_EVIDENCE,
)

# Protocols a future capability could constrain itself to. Presence here is NOT permission --
# every entry is still blocked by BLOCKING_GAPS. The list is an allow-list because a
# deny-list of protocols would silently permit anything newly invented.
CONSIDERED_PROTOCOLS: frozenset[str] = frozenset({"http-form", "http-basic", "ssh", "ftp", "smtp", "imap"})

# Protocols that must NEVER be targeted even once the gaps close: authenticating against
# these is disproportionately likely to lock out or disrupt the customer's core identity
# infrastructure, where a single mistake is an outage rather than a finding.
PERMANENTLY_EXCLUDED_PROTOCOLS: frozenset[str] = frozenset({"ldap", "kerberos", "smb", "rdp", "mssql", "mysql"})


class CredentialTestingNotReady(RuntimeError):
    """Raised when credential testing is requested but the platform is not ready for it.

    This is the fail-closed path and is the ONLY outcome available today."""


@dataclass(frozen=True)
class CredentialTestingRequest:
    """A hypothetical request, used only to evaluate policy. Deliberately carries NO
    credentials: there is no field for a password, a wordlist, or a credential-store handle,
    so this type cannot transport a secret even by accident."""

    target_host: str
    protocol: str
    authorized: bool = False          # from authorization_scope.require_verified_target
    in_scope: bool = False            # from scope_guard.host_in_scope
    exploitation_enabled: bool = False  # from RulesOfEngagement
    operator_approved: bool = False   # explicit human approval, per-engagement


@dataclass(frozen=True)
class ReadinessDecision:
    """The result of evaluating a request. `permitted` is False in every path today."""

    permitted: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)
    gaps: tuple[str, ...] = field(default_factory=tuple)


def readiness_report() -> dict:
    """Machine-readable statement of what is missing. Pure; safe to call anywhere."""
    return {
        "capability": "credential_testing",
        "ready": False,
        "tier": CREDENTIAL_TESTING_TIER,
        "blocking_gaps": list(BLOCKING_GAPS),
        "executes_anything": False,
        "customer_facing_runner": False,
        "considered_protocols": sorted(CONSIDERED_PROTOCOLS),
        "permanently_excluded_protocols": sorted(PERMANENTLY_EXCLUDED_PROTOCOLS),
    }


def evaluate_readiness(request: CredentialTestingRequest) -> ReadinessDecision:
    """Evaluate whether credential testing could proceed. ALWAYS denies today.

    Order matters: the authorization/scope/safety preconditions are checked FIRST, so that a
    request which is also unauthorized is reported as unauthorized rather than being excused
    by the platform-readiness gaps. Every failing condition is accumulated -- a caller sees
    everything wrong at once, not just the first thing."""
    reasons: list[str] = []

    if not str(request.target_host or "").strip():
        reasons.append("no target host supplied")
    protocol = str(request.protocol or "").strip().lower()
    if protocol in PERMANENTLY_EXCLUDED_PROTOCOLS:
        reasons.append(f"protocol '{protocol}' is permanently excluded from credential testing")
    elif protocol not in CONSIDERED_PROTOCOLS:
        # Fail closed: an unrecognized protocol is denied, never assumed benign.
        reasons.append(f"protocol '{protocol or '(none)'}' is not an allowed credential-testing protocol")
    if not request.authorized:
        reasons.append("target ownership is not verified (authorization_scope)")
    if not request.in_scope:
        reasons.append("target host is out of engagement scope (scope_guard)")
    if not request.exploitation_enabled:
        reasons.append("credential testing is INTRUSIVE and exploitation is not enabled for this engagement")
    if not request.operator_approved:
        reasons.append("explicit operator approval is required and was not given")

    # The platform-level gaps deny regardless of how well-formed the request is.
    reasons.extend(f"platform gap: {gap}" for gap in BLOCKING_GAPS)

    return ReadinessDecision(permitted=False, reasons=tuple(reasons), gaps=BLOCKING_GAPS)


def assert_credential_testing_allowed(request: CredentialTestingRequest) -> None:
    """Fail-closed entry point. Raises today, unconditionally, and by construction.

    A future implementation MUST call this before any attempt. It raises rather than
    returning a boolean so a caller cannot proceed by ignoring a return value."""
    decision = evaluate_readiness(request)
    if not decision.permitted:
        raise CredentialTestingNotReady(
            "credential testing is not available: " + "; ".join(decision.reasons)
        )


def assert_no_credentials_in(payload: object, *, context: str = "") -> None:
    """Guard for the rule that credentials must never reach logs, reports, metrics or
    ordinary evidence.

    Reuses the audit scrubber (Prompt 34) as the single definition of "credential-shaped"
    rather than introducing a second, drifting one. Raises if scrubbing would have changed
    the text -- i.e. if something secret-shaped is present."""
    from apps.api.modules.audit.service import scrub_detail

    text = payload if isinstance(payload, str) else repr(payload)
    if scrub_detail(text) != text:
        raise CredentialTestingNotReady(
            f"refusing to emit credential-shaped content{' in ' + context if context else ''}"
        )
