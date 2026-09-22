"""AUDIT-005 -- container images and GitHub Actions must be referenced IMMUTABLY.

WHY A TAG IS NOT A PIN
----------------------
A tag is a mutable pointer. `mysql:8.0`, `nginx:alpine` and especially `:latest` can be
repointed at new content by the publisher at any time, so a tag-referenced stack is not
provably the stack that was tested and vulnerability-scanned. The same is true of a workflow
that says `uses: actions/checkout@v4`: the tag's owner can move it to any commit, and that
commit then runs with this repository's secrets and full checkout -- the tj-actions
compromise pattern.

This is not theoretical here. When the pins were taken, three tags had ALREADY drifted:
`redis:7-alpine`, `nginx:alpine` and `python:3.12-slim` resolved to different digests on the
deployment host than the same tags resolved to in the registry that day.

WHAT IS ASSERTED
----------------
1. No `:latest` (or any bare tag) anywhere in the infra tree.
2. Every image in the MERGED PRODUCTION compose configuration is a digest reference.
3. Every Dockerfile base image is a digest reference.
4. Every GitHub Actions `uses:` is a 40-character commit SHA.
5. The human-readable tag survives alongside each pin, so the pins stay maintainable.

The merged-config assertion is the one that actually matters: production is deployed as
`-f docker-compose.yml -f docker-compose.prod.yml`, so a pin in one file proves nothing about
the effective result. This test reads the same merge Docker itself computes where the docker
CLI is available, and falls back to a static parse of both files otherwise.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
INFRA = REPO_ROOT / "infra"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}\b")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _require(path: Path):
    if not path.exists():
        pytest.skip(f"{path} not present (repo root not bind-mounted)")
    return path


def _image_lines(text: str) -> list[str]:
    """`image:` values, ignoring commented-out lines."""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = re.match(r"image:\s*(\S+)", stripped)
        if m:
            out.append(m.group(1))
    return out


def _from_lines(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = re.match(r"FROM\s+(\S+)", stripped)
        if m and m.group(1) != "scratch":
            out.append(m.group(1))
    return out


# --------------------------------------------------------------------------------------------
# Compose
# --------------------------------------------------------------------------------------------

def test_no_latest_tag_anywhere_in_infra():
    """`:latest` is the most mutable reference there is. minio and ollama both used it."""
    _require(INFRA)
    offenders = []
    for path in sorted(INFRA.rglob("*")):
        if not path.is_file() or path.suffix not in {".yml", ".yaml"} and "Dockerfile" not in path.name:
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r"(image:\s*\S+:latest|^FROM\s+\S+:latest)", stripped):
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{n}: {stripped}")
    assert not offenders, "mutable `:latest` references remain:\n" + "\n".join(offenders)


@pytest.mark.parametrize("compose", ["docker-compose.yml", "docker-compose.prod.yml"])
def test_every_compose_image_is_digest_pinned(compose):
    path = _require(INFRA / compose)
    unpinned = [img for img in _image_lines(path.read_text(encoding="utf-8"))
                if not DIGEST_RE.search(img)]
    assert not unpinned, f"{compose} has non-digest image references: {unpinned}"


def test_merged_production_config_contains_only_digest_references():
    """THE ONE THAT COUNTS: production deploys the MERGE of both files, so only the merged
    result proves anything."""
    base = _require(INFRA / "docker-compose.yml")
    prod = _require(INFRA / "docker-compose.prod.yml")

    if shutil.which("docker"):
        proc = subprocess.run(
            ["docker", "compose", "-f", str(base), "-f", str(prod), "config"],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            images = _image_lines(proc.stdout)
            assert images, "the merged config declared no images at all -- parse failure?"
            unpinned = [i for i in images if not DIGEST_RE.search(i)]
            assert not unpinned, f"merged production config has mutable images: {unpinned}"
            return

    # Fallback: docker unavailable (or refused) -- assert over both source files instead.
    images = _image_lines(base.read_text(encoding="utf-8")) + _image_lines(
        prod.read_text(encoding="utf-8")
    )
    assert images
    unpinned = [i for i in images if not DIGEST_RE.search(i)]
    assert not unpinned, f"compose sources have mutable images: {unpinned}"


def test_pinned_images_keep_their_human_readable_tag_in_a_comment():
    """A bare digest is unmaintainable -- nobody can tell `mysql@sha256:7dcd...` is 8.0.
    Every pinned image must have its tag recorded nearby."""
    for compose in ("docker-compose.yml", "docker-compose.prod.yml"):
        path = _require(INFRA / compose)
        lines = path.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines):
            if not re.match(r"\s*image:\s*\S+@sha256:", line):
                continue
            # the preceding non-blank line should be a comment naming the tag
            preceding = [ln.strip() for ln in lines[max(0, n - 4):n] if ln.strip()]
            assert any(p.startswith("#") for p in preceding), (
                f"{compose}:{n + 1} pins a digest with no tag comment above it: {line.strip()}"
            )


# --------------------------------------------------------------------------------------------
# Dockerfiles
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("dockerfile", ["Dockerfile.api", "Dockerfile.worker", "Dockerfile.web"])
def test_dockerfile_base_images_are_digest_pinned(dockerfile):
    """A rebuild months later must reproduce the base that was tested and scanned."""
    path = _require(INFRA / "docker" / dockerfile)
    unpinned = [f for f in _from_lines(path.read_text(encoding="utf-8"))
                if not DIGEST_RE.search(f)]
    assert not unpinned, f"{dockerfile} has non-digest FROM references: {unpinned}"


# --------------------------------------------------------------------------------------------
# GitHub Actions
# --------------------------------------------------------------------------------------------

def test_every_github_action_is_pinned_to_a_commit_sha():
    """A tag-referenced action runs whatever its owner points the tag at, with this repo's
    secrets. Pin to the commit."""
    _require(WORKFLOWS)
    offenders: list[str] = []
    for wf in sorted(WORKFLOWS.glob("*.y*ml")):
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = re.search(r"uses:\s*([^\s#]+)", stripped)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith("./") or ref.startswith("docker://"):
                continue  # local composite action / explicit docker ref
            if "@" not in ref:
                offenders.append(f"{wf.name}:{n}: {ref} (no ref at all)")
                continue
            pinned = ref.rsplit("@", 1)[1]
            if not SHA_RE.match(pinned):
                offenders.append(f"{wf.name}:{n}: {ref} (mutable tag, not a commit SHA)")
    assert not offenders, "unpinned GitHub Actions:\n" + "\n".join(offenders)


def test_pinned_actions_keep_their_version_tag_in_a_trailing_comment():
    """Same maintainability requirement as the images: the SHA is the pin, the comment is how
    a human knows which version it is."""
    _require(WORKFLOWS)
    missing: list[str] = []
    for wf in sorted(WORKFLOWS.glob("*.y*ml")):
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or "uses:" not in stripped:
                continue
            if re.search(r"uses:\s*\S+@[0-9a-f]{40}", stripped) and "#" not in stripped:
                missing.append(f"{wf.name}:{n}: {stripped}")
    assert not missing, "pinned actions with no version comment:\n" + "\n".join(missing)


def test_workflows_still_parse_as_yaml():
    """The pinning edits must not have broken the workflow files."""
    yaml = pytest.importorskip("yaml")
    _require(WORKFLOWS)
    for wf in sorted(WORKFLOWS.glob("*.y*ml")):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        assert isinstance(doc, dict) and "jobs" in doc, f"{wf.name} is not a valid workflow"
