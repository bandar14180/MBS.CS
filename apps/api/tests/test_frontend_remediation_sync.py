"""Guard: the frontend's remediation/assessment contract may not drift from the backend.

WHY THIS IS A PYTHON TEST AND NOT A JEST/tsc RUN: this repository has no node toolchain in
its test or CI pipeline (there is no frontend job in .github/workflows/ci.yml, and
`apps/web/node_modules` is empty on a fresh checkout). The existing
test_frontend_pipeline_sync.py established exactly this pattern for the same reason -- and it
exists because a real drift bug shipped: four scanner tools were registered server-side but
missing from three hardcoded frontend lists, so they were silently unusable.

The same class of bug is possible here, and worse: a status list that drifts from the backend
lifecycle produces a control that always 4xxs (which is precisely defect #1 -- the frontend
offering `remediated`, a status the backend never had). So these assertions check the frontend
source text against the backend's own constants.

Every check below is against a fact the backend OWNS, so a change on either side that is not
mirrored fails here.
"""
import json
import re
from pathlib import Path

import pytest

_WEB = Path(__file__).resolve().parents[3] / "apps" / "web"
_API_TS = _WEB / "lib" / "api.ts"
_REMEDIATION_TAB = _WEB / "components" / "project" / "RemediationTab.tsx"
_ASSESSMENTS_TAB = _WEB / "components" / "project" / "AssessmentsTab.tsx"
_VULNS_TAB = _WEB / "components" / "project" / "VulnerabilitiesTab.tsx"
_LAYOUT = _WEB / "app" / "(dashboard)" / "projects" / "[id]" / "layout.tsx"
_UI = _WEB / "components" / "ui.tsx"
_LOCALES = _WEB / "locales"

# The API/worker images copy only `apps/api`, so apps/web genuinely does not exist there.
# Skip rather than report a false drift, exactly as test_frontend_pipeline_sync.py does.
pytestmark = pytest.mark.skipif(
    not _API_TS.exists(), reason="apps/web is not present in this environment (API/worker image)"
)


def _ts_string_array(source: str, name: str) -> list[str]:
    """Pull the string literals out of a `NAME ... = [ "a", "b" ]` declaration.

    Anchored on the `= [` that FOLLOWS the name, then read to the matching `]`. Splitting on
    the bare name and taking everything up to the first `]` (the obvious first attempt) picks
    up whatever punctuation happens to precede the array and yields separator artifacts like
    `", "` as if they were entries."""
    after = source.split(name, 1)[1]
    # Anchor on `= [`, not on the first `[`: these declarations carry a type annotation whose
    # own `[]` (e.g. `: RemediationStatus[] = [...]`) would otherwise be read as the array.
    start = after.index("= [") + 2
    block = after[start + 1 : after.index("]", start)]
    return re.findall(r'"([^"]*)"', block)


# =============================================================================================
# VULNERABILITY STATUS (requirement 1 -- the `remediated` defect)
# =============================================================================================

def test_frontend_vulnerability_statuses_match_the_backend_lifecycle() -> None:
    """The filter list and the settable list must both come from the real lifecycle. Before
    the fix, both contained `remediated` -- a value the backend has never accepted -- so the
    filter matched nothing and the "mark as remediated" control was rejected every time."""
    from apps.api.modules.vulnerabilities.service import SETTABLE_STATUSES

    src = _VULNS_TAB.read_text(encoding="utf-8")

    filters = [s for s in _ts_string_array(src, "const STATUSES") if s]
    settable = _ts_string_array(src, "const STATUS_CHOICES")

    assert "remediated" not in filters and "remediated" not in settable
    # Every offered filter is a real backend status (including engine-set `reopened`).
    known = set(SETTABLE_STATUSES) | {"reopened"}
    assert set(filters) <= known, f"unknown status(es) offered as filters: {set(filters) - known}"
    # Every settable choice is one the backend will actually accept.
    assert set(settable) <= set(SETTABLE_STATUSES), (
        f"frontend offers unsettable status(es): {set(settable) - set(SETTABLE_STATUSES)}"
    )
    assert "fixed" in settable, "the frontend must offer the real `fixed` status"
    # `reopened` is ENGINE-set on re-detection and must not be offered as a manual choice.
    assert "reopened" not in settable


# =============================================================================================
# REMEDIATION LIFECYCLE + PRIORITY
# =============================================================================================

def test_frontend_transition_targets_match_the_backend_exactly() -> None:
    """The generic transition control must offer EVERY human-settable target and NOTHING more.
    `verified` and `risk_accepted` are guarded server-side (they need a real retest / an
    approved acceptance), so offering them would build a control that always fails."""
    from apps.api.modules.remediation.schemas import TransitionTarget

    backend_targets = set(TransitionTarget.__args__)
    src = _API_TS.read_text(encoding="utf-8")
    frontend_targets = set(_ts_string_array(src, "REMEDIATION_TRANSITION_TARGETS"))

    assert frontend_targets == backend_targets, (
        f"drift: frontend-only {frontend_targets - backend_targets}, "
        f"backend-only {backend_targets - frontend_targets}"
    )
    assert "verified" not in frontend_targets
    assert "risk_accepted" not in frontend_targets


def test_frontend_priorities_match_the_backend() -> None:
    from apps.api.modules.remediation.models import REMEDIATION_PRIORITIES

    src = _API_TS.read_text(encoding="utf-8")
    frontend = set(_ts_string_array(src, "REMEDIATION_PRIORITIES"))
    assert frontend == set(REMEDIATION_PRIORITIES)


def test_frontend_status_filter_list_covers_every_backend_status() -> None:
    """The filter dropdown must be able to reach every state an item can actually be in --
    otherwise a whole class of work is invisible in the UI."""
    from apps.api.modules.remediation.models import REMEDIATION_STATUSES

    src = _REMEDIATION_TAB.read_text(encoding="utf-8")
    filters = {s for s in _ts_string_array(src, "const STATUS_FILTERS") if s}
    assert filters == set(REMEDIATION_STATUSES), (
        f"filter drift: missing {set(REMEDIATION_STATUSES) - filters}, extra {filters - set(REMEDIATION_STATUSES)}"
    )


def test_every_remediation_status_has_a_badge_style() -> None:
    """An unstyled status silently falls back to the neutral grey, so `in_progress` would look
    identical to `risk_accepted` -- visually erasing the difference between work in flight and
    a decision not to fix."""
    from apps.api.modules.assessment.models import ASSESSMENT_STATUSES
    from apps.api.modules.remediation.models import REMEDIATION_STATUSES
    from apps.api.modules.remediation.risk_models import RISK_ACCEPTANCE_STATUSES

    src = _UI.read_text(encoding="utf-8")
    styled = set(re.findall(r"^\s{2}([a-z_]+):\s*\"bg-", src, re.MULTILINE))

    for status in REMEDIATION_STATUSES | RISK_ACCEPTANCE_STATUSES | ASSESSMENT_STATUSES:
        assert status in styled, f"status '{status}' has no Badge style in ui.tsx"


# =============================================================================================
# API SURFACE
# =============================================================================================

def test_frontend_calls_only_routes_the_backend_actually_serves() -> None:
    """Every remediation/assessment path the client builds must exist in the OpenAPI schema.
    Catches a typo'd or renamed route at test time instead of at runtime."""
    from apps.api.main import create_app

    spec = create_app().openapi()
    # Normalize the server's templated paths to a comparable shape.
    served = {
        re.sub(r"\{[^}]+\}", "{}", path.replace("/api/v1/workspaces/{workspace_id}", ""))
        for path in spec["paths"]
    }

    src = _API_TS.read_text(encoding="utf-8")
    # Template literals inside ws(...) -- e.g. `/projects/${pid}/remediation/${id}/events`.
    called = set()
    for raw in re.findall(r"ws\(`([^`]+)`\)", src):
        if "/remediation" not in raw and "/risk-assessments" not in raw:
            continue
        # Collapse ${...} interpolations into the {} placeholder FIRST, then strip any query
        # string. Order matters: a trailing `${q}` holding an optional query string looks like
        # a path segment until it is normalized, and splitting on "?" first would miss it.
        path = re.sub(r"\$\{[^}]+\}", "{}", raw).split("?")[0]
        # An interpolated query suffix normalizes to a trailing "{}" that is not a segment.
        path = re.sub(r"\{\}$", "", path).rstrip("/")
        called.add(path)

    unknown = sorted(p for p in called if p not in served)
    assert not unknown, f"frontend calls route(s) the backend does not serve: {unknown}"


def test_frontend_never_sends_a_protected_field() -> None:
    """The remediation client must not construct a body containing severity / CVSS / risk. The
    server rejects those with a 422, but a client that tries is a bug worth catching here."""
    src = _API_TS.read_text(encoding="utf-8")
    block = src.split("export const remediationApi", 1)[1].split("export const assessmentApi", 1)[0]
    for forbidden in ("severity", "cvss_score", "cvss_vector", "final_risk_score", "workspace_id"):
        assert forbidden not in block, (
            f"the remediation API client references the protected field '{forbidden}'"
        )


def test_verification_completion_sends_no_body() -> None:
    """Structural mirror of the backend guarantee: no field through which a client could
    assert a verification outcome."""
    src = _API_TS.read_text(encoding="utf-8")
    call = src.split("completeVerification:", 1)[1].split("},", 1)[0]
    assert "body" not in call, "the verification-completion call must not send a body"


# =============================================================================================
# i18n (requirement 32)
# =============================================================================================

def _locale(name: str) -> dict:
    return json.loads((_LOCALES / f"{name}.json").read_text(encoding="utf-8"))


def test_every_locale_has_every_new_string() -> None:
    """No English-only strings: each supported locale must define the full `remediation` and
    `assessment` sections plus the two new project tab labels."""
    english = _locale("en")
    locales = [p.stem for p in _LOCALES.glob("*.json")]
    assert set(locales) >= {"en", "ar", "ms", "fr", "pt", "it", "es"}

    for name in locales:
        data = _locale(name)
        for section in ("remediation", "assessment"):
            assert section in data, f"{name}.json is missing the '{section}' section"
            missing = sorted(set(english[section]) - set(data[section]))
            assert not missing, f"{name}.json is missing {section} key(s): {missing}"
        for key in ("tabRemediation", "tabAssessments"):
            assert key in data["project"], f"{name}.json is missing project.{key}"


def test_no_locale_string_is_left_as_untranslated_english() -> None:
    """A locale that merely COPIES the English string is not translated. Checked on a sample of
    distinctive multi-word strings -- short shared tokens (e.g. "CVSS", "Total") legitimately
    coincide across languages, so comparing every key would be noise rather than signal."""
    english = _locale("en")
    sampled = ["empty", "syncHint", "verificationHint", "riskHint"]

    for name in ("ar", "ms", "fr", "pt", "it", "es"):
        data = _locale(name)
        for key in sampled:
            assert data["remediation"][key] != english["remediation"][key], (
                f"{name}.json remediation.{key} is still the English string"
            )


def test_new_ui_uses_translation_keys_not_hardcoded_english() -> None:
    """Every user-facing string in the new components must come from t(). Checked by requiring
    each component to reference the sections it renders, and by spot-checking that no obvious
    English label was inlined into JSX text."""
    for path in (_REMEDIATION_TAB, _ASSESSMENTS_TAB):
        src = path.read_text(encoding="utf-8")
        assert "useTranslation" in src
        # A JSX text node that is a bare English sentence would look like `>Some Text<`.
        stray = re.findall(r">([A-Z][a-z]+(?: [a-z]+){2,})<", src)
        assert not stray, f"{path.name} has hardcoded user-facing text: {stray}"


def test_project_tabs_are_registered_for_the_new_routes() -> None:
    src = _LAYOUT.read_text(encoding="utf-8")
    assert '{ segment: "remediation", key: "project.tabRemediation" }' in src
    assert '{ segment: "risk-assessments", key: "project.tabAssessments" }' in src

    for segment in ("remediation", "risk-assessments"):
        page = _WEB / "app" / "(dashboard)" / "projects" / "[id]" / segment / "page.tsx"
        assert page.exists(), f"tab '{segment}' is registered but its route page is missing"


def _flatten(data: dict, prefix: str = "") -> dict:
    """Locale files are nested one level deep today, but flattening keeps this test correct if a
    future section nests further."""
    out: dict = {}
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            out.update(_flatten(value, path))
        else:
            out[path] = value
    return out


def test_every_locale_has_full_key_parity_with_english() -> None:
    """FE-7: total key parity, not just the remediation/assessment sections.

    `test_every_locale_has_every_new_string` above only guards the keys added by the
    remediation work. That let unrelated keys (assets.*, scans.stage*, project.tabAssets) be
    added to en.json alone, where they silently fell through to the English fallback in every
    other language. This asserts the whole surface so the gap cannot reopen: any key added to
    en.json without a translation fails here.
    """
    english = _flatten(_locale("en"))
    for name in sorted(p.stem for p in _LOCALES.glob("*.json")):
        if name == "en":
            continue
        data = _flatten(_locale(name))
        missing = sorted(set(english) - set(data))
        extra = sorted(set(data) - set(english))
        assert not missing, f"{name}.json is missing key(s): {missing}"
        assert not extra, f"{name}.json has key(s) absent from en.json: {extra}"


def test_locale_placeholders_survive_translation() -> None:
    """A translated string that drops or renames a `{var}` placeholder renders the raw token to
    the user, so every locale must carry exactly the placeholders English declares."""
    english = _flatten(_locale("en"))
    placeholder = re.compile(r"\{(\w+)\}")

    for name in ("ar", "ms", "fr", "pt", "it", "es"):
        data = _flatten(_locale(name))
        for key, en_value in english.items():
            if not isinstance(en_value, str):
                continue
            expected = set(placeholder.findall(en_value))
            if not expected:
                continue
            actual = set(placeholder.findall(str(data.get(key, ""))))
            assert actual == expected, (
                f"{name}.json {key} has placeholders {sorted(actual)}, expected {sorted(expected)}"
            )
