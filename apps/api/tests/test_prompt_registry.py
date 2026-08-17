"""AI-2.3 -- prompt-governance drift guard.

Fails if any AI prompt's content diverges from the pinned registry, forcing a version bump +
PROMPTS_CHANGELOG entry + re-pin whenever a prompt changes. This locks the prompt supply chain
(including the AI-1 injection-defense wording) as a change-controlled, reproducible artifact.
"""
from pathlib import Path

import pytest

from apps.api.ai_agent.prompts.registry import PROMPTS, REGISTERED

REPO_ROOT = Path(__file__).resolve().parents[3]
CHANGELOG = REPO_ROOT / "docs" / "ai" / "PROMPTS_CHANGELOG.md"


def test_registry_covers_every_prompt():
    assert set(PROMPTS) == set(REGISTERED), (
        "PROMPTS and REGISTERED must list the same prompts. Add every prompt to the registry."
    )


def test_no_prompt_drift():
    """The live prompt content must match the pinned governance record."""
    for name, spec in PROMPTS.items():
        exp_version, exp_hash = REGISTERED[name]
        if spec.hash != exp_hash:
            # The content changed. That's only allowed alongside a version bump + changelog + re-pin.
            assert spec.version != exp_version, (
                f"{name}: prompt CONTENT changed but {name.upper()}_PROMPT_VERSION is still "
                f"'{spec.version}'. Bump the version, add a docs/ai/PROMPTS_CHANGELOG.md entry, and "
                f"update REGISTERED['{name}'] in prompts/registry.py."
            )
            pytest.fail(
                f"{name}: prompt changed to '{spec.version}' -- update REGISTERED['{name}'] hash to "
                f"'{spec.hash}' and add a PROMPTS_CHANGELOG.md entry."
            )
        # Content unchanged -> the pinned version must match too (no silent version edits).
        assert spec.version == exp_version, (
            f"{name}: version is '{spec.version}' but REGISTERED pins '{exp_version}' with the same "
            "content. Reconcile prompts/registry.py."
        )


def test_prompt_versions_are_unique_and_well_formed():
    versions = [v for v, _ in REGISTERED.values()]
    assert len(versions) == len(set(versions)), "duplicate prompt versions in REGISTERED"
    for name, (version, _h) in REGISTERED.items():
        assert version.startswith(f"{name}/"), f"{name}: version '{version}' should be '{name}/vN'"


def test_changelog_records_every_registered_version():
    if not CHANGELOG.is_file():
        pytest.skip("PROMPTS_CHANGELOG.md not present in this environment")
    text = CHANGELOG.read_text(encoding="utf-8")
    for name, (version, _h) in REGISTERED.items():
        assert version in text, f"PROMPTS_CHANGELOG.md is missing an entry for '{version}'"
