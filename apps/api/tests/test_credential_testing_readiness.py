"""Prompt 36 -- Hydra/credential-testing readiness and safety.

Every test here is validated WITHOUT executing a credential attack: the module under test
cannot execute one. These assert the fail-closed policy and the no-credential-leak rule.
"""
import inspect

import pytest

from apps.api.scanner_engine import credential_testing_readiness as ctr
from apps.api.scanner_engine.credential_testing_readiness import (
    BLOCKING_GAPS,
    CREDENTIAL_TESTING_TIER,
    CredentialTestingNotReady,
    CredentialTestingRequest,
    assert_credential_testing_allowed,
    assert_no_credentials_in,
    evaluate_readiness,
    readiness_report,
)
from apps.api.scanner_engine.safety import SafetyTier


def _fully_permitted_request(**kw) -> CredentialTestingRequest:
    """The most permissive request that could ever be constructed -- every precondition
    satisfied. It must STILL be denied, because the platform gaps are unconditional."""
    base = dict(
        target_host="app.example.com",
        protocol="http-form",
        authorized=True,
        in_scope=True,
        exploitation_enabled=True,
        operator_approved=True,
    )
    base.update(kw)
    return CredentialTestingRequest(**base)


# ------------------------------------------------------------------- it cannot execute


def test_module_executes_nothing() -> None:
    """Readiness must not be able to run a process or open a socket.

    Checked against the module's actual IMPORTS rather than its source text, so the prose
    in the docstrings (which legitimately discusses sockets and subprocesses in order to
    rule them out) cannot trip the assertion."""
    import ast

    tree = ast.parse(inspect.getsource(ctr))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    for forbidden in ("subprocess", "socket", "requests", "httpx", "asyncio", "paramiko", "telnetlib"):
        assert forbidden not in imported, f"readiness module must not import {forbidden}"


def test_no_hydra_runner_is_registered() -> None:
    """Readiness must NOT make credential testing a customer-facing scanner."""
    from apps.api.scanner_engine import tool_registry

    registry = getattr(tool_registry, "TOOL_RUNNERS", None) or getattr(tool_registry, "RUNNERS", None)
    if isinstance(registry, dict):
        assert not any("hydra" in str(k).lower() for k in registry)


def test_request_type_cannot_carry_a_credential() -> None:
    """The policy type has no field capable of transporting a secret."""
    fields = set(CredentialTestingRequest.__dataclass_fields__)
    for leaky in ("password", "passwords", "credentials", "wordlist", "username", "secret", "token"):
        assert leaky not in fields


# --------------------------------------------------------------------- fails closed


def test_credential_testing_is_never_permitted_today() -> None:
    assert evaluate_readiness(_fully_permitted_request()).permitted is False


def test_even_a_perfect_request_is_refused_on_platform_gaps() -> None:
    """Authorization, scope, exploitation and approval all satisfied -- still denied."""
    decision = evaluate_readiness(_fully_permitted_request())
    for gap in BLOCKING_GAPS:
        assert any(gap in r for r in decision.reasons), gap
    assert decision.gaps == BLOCKING_GAPS


def test_assert_raises_rather_than_returning_a_boolean() -> None:
    """A caller must not be able to proceed by ignoring a return value."""
    with pytest.raises(CredentialTestingNotReady, match="not available"):
        assert_credential_testing_allowed(_fully_permitted_request())


@pytest.mark.parametrize(
    "kw,expected",
    [
        ({"authorized": False}, "ownership is not verified"),
        ({"in_scope": False}, "out of engagement scope"),
        ({"exploitation_enabled": False}, "exploitation is not enabled"),
        ({"operator_approved": False}, "operator approval"),
        ({"target_host": ""}, "no target host"),
    ],
)
def test_each_precondition_is_reported_independently(kw, expected) -> None:
    """A request that is also unauthorized must be reported as unauthorized, not merely
    excused by the platform gaps."""
    reasons = " ".join(evaluate_readiness(_fully_permitted_request(**kw)).reasons)
    assert expected in reasons


# ------------------------------------------------------------------ protocol policy


@pytest.mark.parametrize("protocol", sorted(ctr.PERMANENTLY_EXCLUDED_PROTOCOLS))
def test_identity_infrastructure_protocols_are_permanently_excluded(protocol) -> None:
    """Locking out a customer's core identity infrastructure is an outage, not a finding."""
    reasons = " ".join(evaluate_readiness(_fully_permitted_request(protocol=protocol)).reasons)
    assert "permanently excluded" in reasons


@pytest.mark.parametrize("protocol", ["", "telnet", "made-up-protocol", "HTTP-FORM-X"])
def test_unknown_protocol_is_denied_not_assumed_benign(protocol) -> None:
    """Fail closed: an allow-list, so anything newly invented is refused by default."""
    reasons = " ".join(evaluate_readiness(_fully_permitted_request(protocol=protocol)).reasons)
    assert "not an allowed credential-testing protocol" in reasons


def test_excluded_and_considered_protocols_do_not_overlap() -> None:
    assert not (ctr.CONSIDERED_PROTOCOLS & ctr.PERMANENTLY_EXCLUDED_PROTOCOLS)


# ---------------------------------------------------------------------- tier decision


def test_credential_testing_is_classified_intrusive() -> None:
    """Submitting real credentials is state-changing: auth logs, lockout counters, alerting.
    Classifying it ACTIVE_SAFE would let it run under a ceiling never chosen for it."""
    assert CREDENTIAL_TESTING_TIER == SafetyTier.INTRUSIVE
    assert CREDENTIAL_TESTING_TIER != SafetyTier.ACTIVE_SAFE


def test_intrusive_tier_is_gated_by_the_existing_safety_control() -> None:
    """Reuse, not reinvention: the existing gate already refuses INTRUSIVE without the flag."""
    from apps.api.scanner_engine.safety import (
        RulesOfEngagement,
        SafetyViolation,
        assert_action_allowed,
    )

    roe = RulesOfEngagement(max_tier=SafetyTier.INTRUSIVE, exploitation_enabled=False)
    with pytest.raises(SafetyViolation, match="exploitation is not enabled"):
        assert_action_allowed(safety_tier=CREDENTIAL_TESTING_TIER, roe=roe)


# ------------------------------------------------------- credentials never leak outward


@pytest.mark.parametrize(
    "payload",
    [
        "password=hunter2",
        "trying admin / Summer2024!  token=abc.def.ghi",
        {"authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig"},
        "api_key: sk-live-0123456789abcdef",
    ],
)
def test_credential_shaped_output_is_refused(payload) -> None:
    """Credentials must never reach logs, reports, metrics or ordinary evidence."""
    with pytest.raises(CredentialTestingNotReady, match="credential-shaped"):
        assert_no_credentials_in(payload, context="evidence")


@pytest.mark.parametrize(
    "payload",
    ["3 attempts against app.example.com", "protocol=http-form outcome=denied", {"attempts": 3}],
)
def test_non_credential_output_is_allowed(payload) -> None:
    """The guard must not block ordinary, credential-free operational detail."""
    assert_no_credentials_in(payload, context="evidence")


def test_leak_guard_reuses_the_audit_scrubber() -> None:
    """One definition of 'credential-shaped', not two that drift apart."""
    assert "scrub_detail" in inspect.getsource(ctr.assert_no_credentials_in)


# ----------------------------------------------------------------------- the report


def test_readiness_report_states_not_ready_and_names_every_gap() -> None:
    report = readiness_report()
    assert report["ready"] is False
    assert report["executes_anything"] is False
    assert report["customer_facing_runner"] is False
    assert report["tier"] == SafetyTier.INTRUSIVE
    assert set(report["blocking_gaps"]) == set(BLOCKING_GAPS)


def test_report_is_pure_and_repeatable() -> None:
    assert readiness_report() == readiness_report()
