"""Web/API discovery correlation: multi-tool observations of one asset (Prompt 26).

THE GAP THIS CLOSES. Assets are keyed on (target_id, asset_type, value) so they outlive
individual scans -- but that same grain means several tools legitimately discover the SAME
row: katana crawls a URL, arjun then confirms its parameters, httpx probes the service
whatweb fingerprints. `upsert_asset` ended with
`on_duplicate_key_update(metadata=<incoming>)`, replacing the entire JSON document, so the
stored asset claimed it was discovered by whichever tool ran LAST and every earlier tool's
provenance was silently lost.

That is a destructive merge: the correlation rules require multiple observations, source/tool
provenance and conflicting observations to all remain traceable.

WHAT IS PINNED HERE is `merge_asset_metadata` -- the pure function that decides what survives
a re-discovery. Complements test_discovery_provenance (which covers the orchestrator's
STAMPING of provenance onto findings); this covers what happens to that provenance once two
tools stamp the same asset.

Nothing here promotes an observation to evidence: an observation records that a tool SAW
something, never that anything was verified.
"""

import pytest

from apps.api.modules.assets.service import (
    MAX_OBSERVATIONS,
    OBSERVATIONS_KEY,
    merge_asset_metadata,
)


def _obs(tool: str, run: str, version: str = "1.0.0", in_scope: bool = True) -> dict:
    """Metadata as the orchestrator stamps it for one tool run."""
    return {
        "discovered_by_tool": tool,
        "discovered_by_tool_version": version,
        "discovered_in_tool_run": run,
        "in_scope": in_scope,
    }


def _recorded(tool: str, run: str, version: str = "1.0.0", in_scope: bool = True) -> dict:
    """The same observation as it is STORED -- the merge stamps its provenance tier."""
    return {**_obs(tool, run, version, in_scope), "provenance": "OBSERVED"}


# --- A. Multiple observations survive ---------------------------------------------------------

def test_a_first_observation_is_recorded():
    merged = merge_asset_metadata(None, _obs("katana", "run-1"))
    assert merged[OBSERVATIONS_KEY] == [_recorded("katana", "run-1")]
    assert merged["discovered_by_tool"] == "katana"


def test_a_second_tool_does_not_erase_the_first():
    """The exact defect: arjun re-discovering katana's URL used to overwrite it wholesale."""
    first = merge_asset_metadata(None, _obs("katana", "run-1"))
    merged = merge_asset_metadata(first, _obs("arjun", "run-2"))
    tools = [o["discovered_by_tool"] for o in merged[OBSERVATIONS_KEY]]
    assert tools == ["katana", "arjun"]


def test_three_tools_observing_one_url_are_all_traceable():
    md: dict = {}
    for tool, run in (("katana", "r1"), ("arjun", "r2"), ("httpx", "r3")):
        md = merge_asset_metadata(md, _obs(tool, run))
    assert [o["discovered_by_tool"] for o in md[OBSERVATIONS_KEY]] == ["katana", "arjun", "httpx"]


def test_each_observation_keeps_its_own_tool_version_and_run():
    first = merge_asset_metadata(None, _obs("katana", "run-1", version="1.7.0"))
    merged = merge_asset_metadata(first, _obs("arjun", "run-2", version="2.2.7"))
    by_tool = {o["discovered_by_tool"]: o for o in merged[OBSERVATIONS_KEY]}
    assert by_tool["katana"]["discovered_by_tool_version"] == "1.7.0"
    assert by_tool["katana"]["discovered_in_tool_run"] == "run-1"
    assert by_tool["arjun"]["discovered_by_tool_version"] == "2.2.7"


# --- B. Duplicate vs genuinely new observations ------------------------------------------------

def test_the_same_tool_run_does_not_duplicate_an_observation():
    """Two findings from ONE run touching the same asset is one observation, not two."""
    first = merge_asset_metadata(None, _obs("katana", "run-1"))
    merged = merge_asset_metadata(first, _obs("katana", "run-1"))
    assert len(merged[OBSERVATIONS_KEY]) == 1


def test_the_same_tool_in_a_later_run_is_a_new_observation():
    """A re-scan genuinely observed the asset again -- that is real history, not a duplicate."""
    first = merge_asset_metadata(None, _obs("katana", "run-1"))
    merged = merge_asset_metadata(first, _obs("katana", "run-2"))
    runs = [o["discovered_in_tool_run"] for o in merged[OBSERVATIONS_KEY]]
    assert runs == ["run-1", "run-2"]


# --- C. Conflicting observations stay traceable ------------------------------------------------

def test_a_conflicting_scalar_is_superseded_but_the_prior_observation_remains():
    """httpx recording 200 and a later run recording 403 is a real conflict. The current
    value is the newest, but the superseded observation must not vanish."""
    first = merge_asset_metadata(None, {**_obs("httpx", "run-1"), "status_code": 200})
    merged = merge_asset_metadata(first, {**_obs("httpx", "run-2"), "status_code": 403})
    assert merged["status_code"] == 403                      # newest is current truth
    assert len(merged[OBSERVATIONS_KEY]) == 2                # both runs still traceable


def test_a_tool_that_reports_fewer_keys_does_not_erase_the_others():
    """arjun reporting has_params must not delete katana's status_code."""
    first = merge_asset_metadata(None, {**_obs("katana", "run-1"), "status_code": 200})
    merged = merge_asset_metadata(first, {**_obs("arjun", "run-2"), "has_params": True})
    assert merged["status_code"] == 200
    assert merged["has_params"] is True


def test_the_overloaded_source_key_is_preserved():
    """`source` means the upstream OSINT provider for subfinder and the tool for others;
    _web.param_discovery_targets selects DAST targets on it. It must survive a merge."""
    first = merge_asset_metadata(None, {**_obs("arjun", "run-1"), "source": "arjun"})
    merged = merge_asset_metadata(first, _obs("httpx", "run-2"))
    assert merged["source"] == "arjun"


# --- D. Scope decisions -------------------------------------------------------------------------

def test_an_out_of_scope_observation_is_recorded_as_such():
    merged = merge_asset_metadata(None, _obs("katana", "run-1", in_scope=False))
    assert merged[OBSERVATIONS_KEY][0]["in_scope"] is False


def test_scope_decisions_of_separate_observations_do_not_overwrite_each_other():
    first = merge_asset_metadata(None, _obs("katana", "run-1", in_scope=True))
    merged = merge_asset_metadata(first, _obs("httpx", "run-2", in_scope=False))
    assert [o["in_scope"] for o in merged[OBSERVATIONS_KEY]] == [True, False]


# --- E. Bounds and robustness --------------------------------------------------------------------

def test_the_observation_log_is_bounded():
    """A long-lived asset re-discovered on every scan cannot grow the JSON column forever."""
    md: dict = {}
    for i in range(MAX_OBSERVATIONS + 10):
        md = merge_asset_metadata(md, _obs("katana", f"run-{i}"))
    assert len(md[OBSERVATIONS_KEY]) == MAX_OBSERVATIONS


def test_truncation_drops_the_oldest_and_always_keeps_the_newest():
    md: dict = {}
    for i in range(MAX_OBSERVATIONS + 5):
        md = merge_asset_metadata(md, _obs("katana", f"run-{i}"))
    runs = [o["discovered_in_tool_run"] for o in md[OBSERVATIONS_KEY]]
    assert runs[-1] == f"run-{MAX_OBSERVATIONS + 4}"
    assert "run-0" not in runs


def test_metadata_without_provenance_does_not_create_an_empty_observation():
    """A finding carrying no provenance keys contributes no observation rather than a blank."""
    merged = merge_asset_metadata(None, {"status_code": 200})
    assert OBSERVATIONS_KEY not in merged
    assert merged["status_code"] == 200


@pytest.mark.parametrize("bad", [None, "not-a-dict", 42, ["a"]], ids=["none", "str", "int", "list"])
def test_an_unreadable_existing_document_does_not_lose_the_asset(bad):
    """Malformed stored metadata is treated as absent -- losing the row would be worse."""
    merged = merge_asset_metadata(bad, _obs("katana", "run-1"))
    assert merged[OBSERVATIONS_KEY] == [_recorded("katana", "run-1")]


def test_a_malformed_observation_list_is_repaired_not_propagated():
    existing = {OBSERVATIONS_KEY: ["junk", 5, {"discovered_in_tool_run": "run-1"}]}
    merged = merge_asset_metadata(existing, _obs("katana", "run-2"))
    assert all(isinstance(o, dict) for o in merged[OBSERVATIONS_KEY])


def test_a_non_list_observation_value_is_replaced_safely():
    merged = merge_asset_metadata({OBSERVATIONS_KEY: "corrupt"}, _obs("katana", "run-1"))
    assert merged[OBSERVATIONS_KEY] == [_recorded("katana", "run-1")]


def test_the_merge_is_deterministic():
    a = merge_asset_metadata({**_obs("katana", "r1")}, _obs("arjun", "r2"))
    b = merge_asset_metadata({**_obs("katana", "r1")}, _obs("arjun", "r2"))
    assert a == b


def test_the_merge_does_not_mutate_its_inputs():
    existing = merge_asset_metadata(None, _obs("katana", "run-1"))
    snapshot = {**existing, OBSERVATIONS_KEY: list(existing[OBSERVATIONS_KEY])}
    merge_asset_metadata(existing, _obs("arjun", "run-2"))
    assert existing[OBSERVATIONS_KEY] == snapshot[OBSERVATIONS_KEY]


# --- F. Observations are not evidence -------------------------------------------------------------

def test_an_observation_carries_no_verification_claim():
    """Discovery correlation must never manufacture a security conclusion. An observation
    records that a tool SAW the asset -- nothing is verified, and no severity is implied."""
    merged = merge_asset_metadata(None, _obs("katana", "run-1"))
    observation = merged[OBSERVATIONS_KEY][0]
    assert set(observation) <= {
        "discovered_by_tool", "discovered_by_tool_version", "discovered_in_tool_run",
        "in_scope", "provenance",
    }
    # The tier is explicit and is OBSERVED -- never VERIFIED, never INFERRED.
    assert observation["provenance"] == "OBSERVED"
    for banned in ("verified", "verification_status", "severity", "vulnerability", "confidence"):
        assert banned not in observation
        assert banned not in merged


# --- G. OBSERVED vs INFERRED are distinguishable on the document (Prompt 26) ------------------
#
# THE GAP THIS CLOSES. `api_intel.classify_api` (is_api / api_kind / api_version) and
# `auth_state.auth_metadata` (auth_state) are INFERRED -- derived from a URL path and a status
# code, with no extra request sent. They were written into the SAME flat metadata namespace as
# OBSERVED facts a tool actually measured (`status_code`, `tech`, `title`), with nothing
# marking which was which. A reader could not tell "httpx measured a 403" from "this path
# looks like a REST API", which is precisely the distinction the correlation rules require.
#
# The fix is an ADDITIVE `inferred_keys` sidecar: every existing consumer keeps reading the
# same flat keys (adaptive.py's `md.get("is_api")`, coverage.py's auth_state check), and the
# tier is now answerable. It is a label about DERIVATION, never a security claim.

def test_inferred_classifications_are_marked_as_inferred():
    from apps.api.scanner_engine.api_intel import classify_api

    md = classify_api("https://x.test/api/v2/users").as_metadata()
    assert md["is_api"] is True
    assert set(md["inferred_keys"]) == {"is_api", "api_kind", "api_version"}


def test_auth_state_is_marked_as_inferred():
    from apps.api.scanner_engine.auth_state import auth_metadata

    md = auth_metadata(403)
    assert md["auth_state"] == "protected"
    assert md["inferred_keys"] == ["auth_state"]


def test_a_signal_less_classification_marks_nothing():
    """No inference made => no provenance claim. The marker must not appear on an empty dict."""
    from apps.api.scanner_engine.api_intel import classify_api
    from apps.api.scanner_engine.auth_state import auth_metadata

    assert classify_api("https://x.test/about").as_metadata() == {}
    assert auth_metadata(None) == {}


def test_observed_facts_are_not_marked_inferred():
    """The other half of the distinction: a measured value must never be labelled inferred."""
    merged = merge_asset_metadata(None, {**_obs("httpx", "run-1"), "status_code": 200,
                                         "tech": ["nginx"]})
    assert "inferred_keys" not in merged


def test_two_tools_inferring_different_keys_both_keep_their_marks():
    """katana tags the API classification, httpx the auth state -- on the SAME asset row.
    Last-writer-wins would let one marker erase the other, leaving `is_api` on the document
    with nothing recording that it was inferred: an inference silently promoted to an
    observation. Unioned for the same reason `tech` is."""
    katana = {**_obs("katana", "run-1"), "is_api": True, "api_kind": "rest",
              "inferred_keys": ["api_kind", "is_api"]}
    httpx = {**_obs("httpx", "run-2"), "auth_state": "protected", "status_code": 403,
             "inferred_keys": ["auth_state"]}

    merged = merge_asset_metadata(katana, httpx)
    assert set(merged["inferred_keys"]) == {"is_api", "api_kind", "auth_state"}
    assert merged["is_api"] is True            # katana's inference survives httpx's write
    assert merged["status_code"] == 403        # and httpx's OBSERVED fact is not marked


def test_a_mark_never_outlives_the_key_it_describes():
    """A dangling provenance claim would assert something about a key that is not there."""
    existing = {**_obs("katana", "run-1"), "is_api": True, "inferred_keys": ["is_api", "gone"]}
    merged = merge_asset_metadata(existing, _obs("httpx", "run-2"))
    assert merged["inferred_keys"] == ["is_api"]


def test_an_inferred_mark_never_becomes_verification():
    """THE hard invariant: inference is never evidence. No amount of correlation may put a
    VERIFIED tier on a discovery document."""
    from apps.api.modules.assets.service import PROVENANCE_VERIFIED

    katana = {**_obs("katana", "run-1"), "is_api": True, "inferred_keys": ["is_api"]}
    merged = merge_asset_metadata(katana, {**_obs("httpx", "run-2"), "auth_state": "protected",
                                           "inferred_keys": ["auth_state"]})
    assert PROVENANCE_VERIFIED not in str(merged)
    assert "provenance" not in merged          # stripped from the document itself
    for observation in merged[OBSERVATIONS_KEY]:
        assert observation["provenance"] == "OBSERVED"
