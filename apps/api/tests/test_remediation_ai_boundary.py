"""AI proposes, humans dispose (requirement 28) -- verified structurally, not by inspection.

The invariant: AI may PROPOSE remediation guidance, but it can never itself transition a
remediation item, transition a vulnerability, accept risk, or decide a verification result.

These are STRUCTURAL tests (import graph, function signatures, the OpenAPI surface) rather
than behavioural ones, deliberately. A behavioural test can only prove that the AI paths that
exist today do not mutate state; a structural test proves that no AI module can even reach the
code that would let it, so a future change that crossed the line fails here.
"""
import ast
import pathlib

import pytest

_API = pathlib.Path(__file__).resolve().parents[1]

# Modules that call an AI provider, or exist to serve AI features.
AI_MODULES = [
    _API / "ai_agent",
    _API / "modules" / "vulnerabilities" / "ai_service.py",
    _API / "modules" / "assistant",
    _API / "modules" / "agent",
]

# The functions that CHANGE security state. If an AI module can import one of these, the
# invariant is only a convention.
STATE_CHANGING = {
    "transition",
    "_apply_transition",
    "accept_risk",
    "revoke_risk_acceptance",
    "complete_verification",
    "claim_verification",
    "set_status",
    "reopen_for_regression",
}


def _python_files(target: pathlib.Path):
    if target.is_file():
        return [target]
    return [p for p in target.rglob("*.py") if "__pycache__" not in p.parts]


def _imports(path: pathlib.Path) -> set[str]:
    """Every module path and imported name in one file, including function-local imports (this
    codebase uses those heavily to break cycles, so a module-level-only scan would miss them)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            for alias in node.names:
                found.add(f"{node.module}.{alias.name}")
                found.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
    return found


def test_no_ai_module_imports_a_state_changing_function() -> None:
    """The import graph is the enforcement. An AI module that cannot import
    `transition`/`accept_risk`/`complete_verification` cannot call them."""
    offenders = []
    for target in AI_MODULES:
        if not target.exists():
            continue
        for path in _python_files(target):
            names = _imports(path)
            if "apps.api.modules.remediation.service" in names:
                offenders.append(f"{path.name} imports the remediation service")
            if "apps.api.modules.remediation.risk_service" in names:
                offenders.append(f"{path.name} imports the risk-acceptance service")
            if "apps.api.modules.remediation.verification" in names:
                offenders.append(f"{path.name} imports the verification service")
            for func in STATE_CHANGING & names:
                offenders.append(f"{path.name} imports the state-changing '{func}'")
    assert not offenders, "AI code can reach security-state mutation: " + "; ".join(offenders)


def test_no_ai_module_writes_a_protected_column() -> None:
    """Belt and braces on the import check: no assignment to a protected attribute anywhere in
    the AI modules. Catches a mutation reached through an object rather than an import."""
    protected = {"severity", "cvss_score", "cvss_vector", "final_risk_score"}
    offenders = []
    for target in AI_MODULES:
        if not target.exists():
            continue
        for path in _python_files(target):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                for t in node.targets:
                    if isinstance(t, ast.Attribute) and t.attr in protected:
                        offenders.append(f"{path.name}:{node.lineno} writes .{t.attr}")
    assert not offenders, "AI code writes a scanner/risk-engine-owned field: " + "; ".join(offenders)


def test_verification_outcome_cannot_be_supplied_by_any_caller() -> None:
    """No parameter -- on the service function OR on the HTTP endpoint -- through which an
    outcome could be asserted. This is what makes "an AI response cannot mark something
    verified" a property of the design rather than a promise."""
    import inspect

    from apps.api.main import create_app
    from apps.api.modules.remediation.verification import complete_verification

    params = set(inspect.signature(complete_verification).parameters)
    assert not (params & {"passed", "result", "outcome", "verified", "success"})

    spec = create_app().openapi()
    path = next(p for p in spec["paths"] if p.endswith("/verification/{request_id}/complete"))
    assert "requestBody" not in spec["paths"][path]["post"]


def test_ai_generated_remediation_guidance_is_labelled_ai() -> None:
    """AI guidance is stored in the EXISTING `remediations` table with generated_by='ai'. The
    remediation ITEM's own notes are a separate field with separate provenance, so AI text can
    never be surfaced as human-authored."""
    from apps.api.modules.remediation.models import RemediationItem
    from apps.api.modules.vulnerabilities.remediation_models import Remediation

    # Two distinct provenance fields on two distinct tables -- not one shared column that
    # whichever writer touched last would define.
    assert hasattr(Remediation, "generated_by")
    assert hasattr(RemediationItem, "notes_source")
    assert Remediation.__tablename__ != RemediationItem.__tablename__


def test_remediation_item_notes_are_never_written_by_the_ai_guidance_path() -> None:
    """The guidance generator writes `remediations`, never `remediation_items.notes`."""
    source = (_API / "modules" / "vulnerabilities" / "ai_service.py").read_text(encoding="utf-8")
    assert "RemediationItem" not in source
    assert "notes_source" not in source


@pytest.mark.parametrize("guarded", ["verified", "risk_accepted"])
def test_guarded_statuses_are_absent_from_the_public_transition_schema(guarded) -> None:
    """Even with `remediation:manage`, the transition endpoint cannot reach the two states that
    require evidence. The schema itself refuses them, so no client -- human or machine -- can
    ask for them through that route."""
    from apps.api.modules.remediation.schemas import TransitionTarget

    assert guarded not in set(TransitionTarget.__args__)


def test_ai_cannot_set_a_vulnerability_status_either() -> None:
    """The vulnerability lifecycle is equally protected: `set_status` requires an authenticated
    actor id and `vulnerability:manage`, and no AI module imports it."""
    import inspect

    from apps.api.modules.vulnerabilities.service import set_status

    params = inspect.signature(set_status).parameters
    # A human actor is a REQUIRED positional argument -- there is no anonymous/system caller
    # path through which an AI response could drive a status change.
    assert "changed_by" in params
    assert params["changed_by"].default is inspect.Parameter.empty
