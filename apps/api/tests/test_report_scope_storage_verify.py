"""Phase 3.1 storage-backed verification (review follow-up).

Runs only where object storage is reachable. Proves the FULL round trip that the data-layer
tests could not: POST /reports with a scan scope -> PDF persisted to the object store ->
downloaded back -> its TEXT contains only the scoped scan's findings.

This asserts on the bytes actually served by GET /reports/{id}/download, so a scoping bug that
survived into the stored artifact would fail here even though every in-memory test passed.
"""

import re
import uuid

import pytest
from fastapi.testclient import TestClient

from apps.api.tests.test_remediation import _auth, _register, _seed_findings, _workspace_project
from apps.api.tests.test_report_layout import _pdf_text
from apps.api.tests.test_report_scan_scope import (
    _finding,
    _link_findings_to_scan,
    _reports_url,
    _seed_scan,
    requires_storage,
)

pytestmark = requires_storage


def _download_text(client: TestClient, wid: str, pid: str, report_id: str) -> str:
    resp = client.get(f"{_reports_url(wid, pid)}/{report_id}/download", headers=_HEADERS[wid])
    assert resp.status_code == 200, resp.text
    assert resp.content[:4] == b"%PDF", "downloaded artifact is not a PDF"
    return re.sub(r"\s+", " ", _pdf_text(resp.content))


_HEADERS: dict[str, dict] = {}


@pytest.fixture()
def scoped_project(client: TestClient):
    """Scan A -> CRITICAL 'alpha-only-template'. Scan B -> LOW 'beta-only-template'.

    The titles are deliberately unique strings so their presence/absence in the rendered PDF
    text is unambiguous evidence."""
    headers = _auth(_register(client, "StorageVerify"))
    wid, pid = _workspace_project(client, headers)
    _HEADERS[wid] = headers

    scan_a = _seed_scan(wid, pid)
    scan_b = _seed_scan(wid, pid)
    ids_a = _seed_findings(wid, pid, [
        _finding("alpha-only-template|param|https://alpha.test/x", "critical", 9.8),
    ])
    ids_b = _seed_findings(wid, pid, [
        _finding("beta-only-template|param|https://beta.test/y", "low", 2.1),
    ])
    _link_findings_to_scan(wid, ids_a, scan_a)
    _link_findings_to_scan(wid, ids_b, scan_b)
    return {"headers": headers, "wid": wid, "pid": pid, "scan_a": scan_a, "scan_b": scan_b}


def _create(client, ctx, scan_ids, rtype="technical"):
    body = {"type": rtype}
    if scan_ids is not None:
        body["scan_ids"] = [str(s) for s in scan_ids]
    resp = client.post(_reports_url(ctx["wid"], ctx["pid"]), headers=ctx["headers"], json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- (1) persists successfully, (2)+(3) content is scoped ----------------------------------

def test_single_scan_report_persists_and_contains_only_that_scan(client, scoped_project) -> None:
    ctx = scoped_project
    report = _create(client, ctx, [ctx["scan_a"]])

    # (1) persisted
    assert report["storage_uri"], "no storage_uri recorded"
    assert report["storage_uri"].startswith("s3://")
    assert [str(s) for s in report["scan_ids"]] == [str(ctx["scan_a"])]

    # (2)+(3) the DOWNLOADED bytes carry only scan A's finding
    text = _download_text(client, ctx["wid"], ctx["pid"], report["id"])
    assert "alpha-only-template" in text
    assert "beta-only-template" not in text
    assert "beta.test" not in text
    assert "1 selected scan(s)" in text


def test_the_other_single_scan_is_symmetric(client, scoped_project) -> None:
    ctx = scoped_project
    report = _create(client, ctx, [ctx["scan_b"]])
    text = _download_text(client, ctx["wid"], ctx["pid"], report["id"])
    assert "beta-only-template" in text
    assert "alpha-only-template" not in text
    assert "alpha.test" not in text


# --- (4) multi-scan --------------------------------------------------------------------

def test_multi_scan_report_contains_both(client, scoped_project) -> None:
    ctx = scoped_project
    report = _create(client, ctx, [ctx["scan_a"], ctx["scan_b"]])

    assert len(report["scan_ids"]) == 2
    text = _download_text(client, ctx["wid"], ctx["pid"], report["id"])
    assert "alpha-only-template" in text
    assert "beta-only-template" in text
    assert "2 selected scan(s)" in text


# --- (5) no regression: unscoped and executive still behave --------------------------------

def test_unscoped_report_still_covers_the_whole_project(client, scoped_project) -> None:
    ctx = scoped_project
    report = _create(client, ctx, None)

    assert report["scan_ids"] == []
    text = _download_text(client, ctx["wid"], ctx["pid"], report["id"])
    assert "alpha-only-template" in text
    assert "beta-only-template" in text
    assert "all findings recorded for this project" in text


def test_executive_report_is_scoped_too(client, scoped_project) -> None:
    ctx = scoped_project
    report = _create(client, ctx, [ctx["scan_a"]], rtype="executive")
    text = _download_text(client, ctx["wid"], ctx["pid"], report["id"])
    assert "beta-only-template" not in text
    assert "1 selected scan(s)" in text


def test_scoped_score_differs_from_project_wide_in_the_persisted_pdf(client, scoped_project) -> None:
    """Scan A holds the CRITICAL, so its stored report must show a worse score than the
    project-wide one -- proving the scope reached scoring, not just the text."""
    ctx = scoped_project
    scoped = _download_text(client, ctx["wid"], ctx["pid"],
                            _create(client, ctx, [ctx["scan_b"]])["id"])
    whole = _download_text(client, ctx["wid"], ctx["pid"], _create(client, ctx, None)["id"])

    def score(text: str) -> int:
        m = re.search(r"Security [Ss]core:?\s*(\d+)/100", text)
        assert m, f"no score in: {text[:200]}"
        return int(m.group(1))

    assert score(scoped) > score(whole)


def test_rejected_scope_persists_no_report(client, scoped_project) -> None:
    """A 404'd request must not leave a stored artifact behind."""
    ctx = scoped_project
    before = client.get(_reports_url(ctx["wid"], ctx["pid"]), headers=ctx["headers"]).json()
    resp = client.post(
        _reports_url(ctx["wid"], ctx["pid"]), headers=ctx["headers"],
        json={"type": "technical", "scan_ids": [str(uuid.uuid4())]},
    )
    assert resp.status_code == 404
    after = client.get(_reports_url(ctx["wid"], ctx["pid"]), headers=ctx["headers"]).json()
    assert len(after) == len(before)
