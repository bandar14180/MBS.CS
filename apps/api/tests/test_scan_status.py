from apps.api.scanner_engine.orchestrator import _resolve_scan_status


def test_all_tools_failed_is_failed() -> None:
    # Regression: a scan where every executed tool failed must NOT report success.
    assert _resolve_scan_status(executed=3, failed=3) == "failed"


def test_some_tools_failed_is_completed_with_errors() -> None:
    assert _resolve_scan_status(executed=4, failed=1) == "completed_with_errors"


def test_no_failures_is_completed() -> None:
    assert _resolve_scan_status(executed=4, failed=0) == "completed"


def test_nothing_executed_is_completed() -> None:
    # e.g. all requested tools were skipped (not applicable / unauthorized).
    assert _resolve_scan_status(executed=0, failed=0) == "completed"
