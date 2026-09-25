"""Nuclei parser robustness against hostile/anomalous scanner output (Prompt 24, Req. E/F/I).

WHAT THE AUDIT FOUND, AND WHY THESE TESTS EXIST
------------------------------------------------
`parse_vulnerabilities` already skipped lines that failed `json.loads` (test_nuclei_detection
_boundary covers that). But `json.loads` succeeding only proves the line was valid JSON -- NOT
that it was a JSON *object* carrying the fields the parser then reaches for. Nine distinct
shape anomalies (null `info`, a list `classification`, a non-string `severity`, a top-level
list/scalar, a list `request`, ...) raised AttributeError/TypeError out of the whole method.

That is caught one level up (orchestrator.py `except Exception: vuln_findings = []`), so it
never crashed a scan -- which is exactly what made it dangerous. The consequence was a SILENT
FALSE NEGATIVE, measured before the fix:

    line 1: a critical RCE, perfectly well-formed
    line 2: one record with `"info": null`
    result: zero findings ingested, exit code 0, run classified `completed`

A clean "nothing found" report while a critical RCE sat in the captured evidence. Prompt 24's
rule is that malformed or incomplete scanner output must never silently become VERIFIED; this
is the same defect pointed the other way -- it silently became CLEAN.

THE RULE THESE TESTS PIN
------------------------
One anomalous line is skipped like a malformed one. It never poisons the batch, and it is
never reconstructed into a finding by defaulting its missing parts (which would fabricate a
severity/title nuclei did not state). Identity fields must be real strings or the record is
dropped -- no identity, no fingerprint, no traceability.
"""

import json

import pytest

from apps.api.scanner_engine.tool_runners.base import RawToolOutput, classify_run
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner

GOOD = json.dumps({
    "template-id": "acme-rce",
    "matched-at": "https://x.test/a",
    "matcher-name": "body",
    "info": {"name": "RCE", "severity": "critical",
             "classification": {"cwe-id": "cwe-78", "cve-id": "CVE-2021-44228"}},
})


def _parse(*lines: str):
    raw = RawToolOutput(command="nuclei", stdout="\n".join(lines), stderr="", exit_code=0)
    return NucleiRunner().parse_vulnerabilities(raw)


# --- 1/2. valid JSONL, single and multiple findings -----------------------------------------

def test_valid_jsonl_single_finding():
    findings = _parse(GOOD)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "RCE"
    assert f.severity == "critical"
    assert f.category == "cwe-78"                      # canonical, via Prompt 23 taxonomy
    assert f.metadata["cve"] == "CVE-2021-44228"
    assert f.matched_at == "https://x.test/a"          # raw string preserved for evidence


def test_multiple_distinct_findings_are_all_kept():
    second = json.dumps({"template-id": "acme-xss", "matched-at": "https://x.test/b",
                         "info": {"name": "XSS", "severity": "medium"}})
    assert len(_parse(GOOD, second)) == 2


# --- 3/4/5. malformed, mixed, truncated ------------------------------------------------------

def test_malformed_json_line_is_skipped():
    assert _parse("{not json at all") == []


def test_malformed_mixed_with_valid_keeps_the_valid_ones():
    assert len(_parse("{broken", GOOD, "also broken}")) == 1


def test_truncated_final_line_does_not_lose_earlier_findings():
    """A killed/timed-out nuclei leaves a half-written last line. It is unparseable, so it is
    skipped -- but everything already flushed before it must survive."""
    assert len(_parse(GOOD, GOOD[:40])) == 1


# --- THE REGRESSION: a shape anomaly must not poison the batch -------------------------------

# Every shape that used to raise AttributeError/TypeError out of the whole method. Each is
# valid JSON, so each passes the JSONDecodeError guard and reaches a field access below it.
#
# Split by what the record can still honestly yield, because the two outcomes are different
# guarantees and collapsing them would hide a real regression in either direction:
#
#   _UNREADABLE -- the record's IDENTITY or its whole `info` block is unusable, so there is no
#                  finding to report. Dropped, never reconstructed from defaults.
#   _DEGRADED   -- identity and `info` are readable; one OPTIONAL sub-field is not. The finding
#                  IS reported, minus the field that could not be read. Dropping the whole
#                  record here would lose a real detection over a cosmetic anomaly.
_UNREADABLE = {
    "info is a scalar": {"template-id": "t", "matched-at": "https://x.test/b", "info": "high"},
    "info is a list": {"template-id": "t", "matched-at": "https://x.test/b", "info": ["high"]},
    "matched-at is a number": {"template-id": "t", "matched-at": 8080, "info": {}},
    "template-id is a list": {"template-id": ["t"], "matched-at": "https://x.test/b",
                              "info": {}},
    "top-level is a list": [{"template-id": "t"}],
    "top-level is a scalar": "some nuclei error text",
}
_DEGRADED = {
    "classification is a list": {"template-id": "d1", "matched-at": "https://x.test/b",
                                 "info": {"severity": "high", "classification": ["cwe-79"]}},
    "severity is a list": {"template-id": "d2", "matched-at": "https://x.test/b",
                           "info": {"severity": ["high"]}},
    "request is a list": {"template-id": "d3", "matched-at": "https://x.test/b",
                          "info": {"severity": "high"}, "request": ["GET / HTTP/1.1"]},
}


@pytest.mark.parametrize("name", sorted({**_UNREADABLE, **_DEGRADED}))
def test_one_shape_anomalous_line_does_not_discard_the_whole_run(name):
    """THE measured false negative, one case per shape.

    Each of these used to raise out of `parse_vulnerabilities`, and the orchestrator's
    `except Exception: vuln_findings = []` then discarded EVERY finding in the run -- so the
    critical RCE beside it was lost and, with exit 0, the run still classified `completed`.
    A bad line must cost at most itself."""
    poison = json.dumps({**_UNREADABLE, **_DEGRADED}[name])
    findings = _parse(GOOD, poison, GOOD.replace("acme-rce", "acme-rce-2"))
    rces = [f for f in findings if f.title == "RCE"]
    assert len(rces) == 2                                  # both real findings survive
    assert all(f.severity == "critical" for f in rces)


@pytest.mark.parametrize("name", sorted(_UNREADABLE))
def test_unreadable_records_are_dropped_not_reconstructed(name):
    """No identity, or no readable `info` at all => no finding. Defaulting the missing parts
    would manufacture an 'info'-severity finding titled after its template id."""
    assert _parse(json.dumps(_UNREADABLE[name])) == []


@pytest.mark.parametrize("name", sorted(_DEGRADED))
def test_degraded_records_keep_what_was_readable(name):
    """One unreadable OPTIONAL field must not cost the whole detection."""
    findings = _parse(json.dumps(_DEGRADED[name]))
    assert len(findings) == 1
    assert findings[0].category is None or isinstance(findings[0].category, str)


def test_a_run_of_only_unreadable_lines_yields_nothing_without_raising():
    """The other half of the property: unreadable lines produce no findings, and the parser
    RETURNS rather than raising -- which is what lets a real finding beside them survive."""
    r = NucleiRunner()
    raw = RawToolOutput(
        command="nuclei",
        stdout="\n".join(json.dumps(o) for o in _UNREADABLE.values()),
        stderr="", exit_code=0,
    )
    assert r.parse_vulnerabilities(raw) == []
    assert classify_run(r, raw, False) == "completed"


def test_absent_info_block_is_still_parsed():
    """ABSENT `info` is normal in nuclei output and must keep degrading gracefully -- it is
    NOT the malformed case. Guarding it as one would have silently dropped real findings,
    which is the very failure mode this file exists to prevent."""
    line = json.dumps({"template-id": "acme-t", "matched-at": "https://x.test/a"})
    f = _parse(line)[0]
    assert f.title == "acme-t"     # falls back to the template id
    assert f.severity == "info"    # nuclei's own default; nothing invented
    assert f.category is None


# --- 6/7. missing and null fields ------------------------------------------------------------

def test_record_missing_identity_fields_is_dropped_not_guessed():
    no_tid = json.dumps({"matched-at": "https://x.test/", "info": {"severity": "high"}})
    no_loc = json.dumps({"template-id": "t", "info": {"severity": "high"}})
    assert _parse(no_tid, no_loc) == []


def test_null_optional_fields_do_not_raise_and_do_not_fabricate():
    """JSON `null` means "no value", so it degrades exactly like an absent key -- never into
    an invented title, severity or CWE."""
    line = json.dumps({
        "template-id": "t", "matched-at": "https://x.test/a", "matcher-name": None,
        "info": {"name": None, "severity": None, "description": None,
                 "classification": None, "tags": None},
    })
    findings = _parse(line)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "t"              # falls back to template_id, not an invented name
    assert f.severity == "info"        # nuclei's own default; not upgraded
    assert f.description is None       # absent stays absent
    assert f.category is None          # no CWE reported => none invented
    assert f.cvss_score is None


def test_absent_description_key_parses_as_none_and_is_not_fabricated():
    """FORENSIC LOCK. Most real nuclei templates emit no `info.description` at all -- the key
    is ABSENT, not null (the null case is covered above). The parser must yield
    `description is None` so `vulnerabilities.description` is stored NULL.

    This is load-bearing for report provenance: "Scanning engine description:" is emitted in
    the report if and only if this field is populated. If the parser ever defaulted this to
    "" or to a synthesised string, MBS-authored text would start appearing under the scanning
    engine's attribution. The report layer supplies its own prose on a separate parameter with
    a separate label (finding_descriptions.py); it never writes back to this field."""
    line = json.dumps({
        "template-id": "no-desc-template",
        "matched-at": "https://x.test/a",
        "matcher-name": "body",
        # `info` carries the usual metadata but, as is typical, NO "description" key.
        "info": {"name": "No description template", "severity": "medium",
                 "classification": {"cwe-id": "cwe-79"}},
    })
    findings = _parse(line)
    assert len(findings) == 1
    f = findings[0]
    assert "description" not in json.loads(line)["info"], "fixture must omit the key entirely"
    assert f.description is None, "absent description must stay NULL, never defaulted"
    # The rest of the record still parses: absence of a description is not a parse failure.
    assert f.title == "No description template"
    assert f.severity == "medium"


def test_non_string_identity_fields_are_dropped():
    """A non-string template-id/matched-at cannot form a stable, traceable fingerprint."""
    bad_tid = json.dumps({"template-id": ["t"], "matched-at": "https://x.test/a", "info": {}})
    bad_loc = json.dumps({"template-id": "t", "matched-at": 8080, "info": {}})
    assert _parse(bad_tid, bad_loc) == []


def test_top_level_non_object_lines_are_skipped():
    """A JSONL line that is a list/string/number is not a finding record."""
    assert _parse(json.dumps([{"template-id": "t"}]), json.dumps("hello"), json.dumps(42)) == []


def test_non_object_info_and_classification_are_skipped_or_emptied():
    """`info` must be an object to be read at all (skipped); a non-object `classification`
    inside a valid `info` just means no CWE/CVE was reported."""
    bad_info = json.dumps({"template-id": "t", "matched-at": "https://x.test/a", "info": "high"})
    assert _parse(bad_info) == []

    bad_class = json.dumps({"template-id": "t", "matched-at": "https://x.test/a",
                            "info": {"severity": "high", "classification": ["cwe-79"]}})
    findings = _parse(bad_class)
    assert len(findings) == 1
    assert findings[0].severity == "high"   # the readable part is still honoured
    assert findings[0].category is None     # the unreadable part is absent, not guessed


# --- 8. list vs scalar CWE/CVE normalisation (Prompt 23 reuse) -------------------------------

def test_cwe_and_cve_accept_list_and_scalar_forms():
    scalar = json.dumps({"template-id": "a", "matched-at": "https://x.test/1", "info": {
        "severity": "high", "classification": {"cwe-id": "CWE-89", "cve-id": "cve-2021-1234"}}})
    listed = json.dumps({"template-id": "b", "matched-at": "https://x.test/2", "info": {
        "severity": "high",
        "classification": {"cwe-id": ["cwe_79", "cwe-80"], "cve-id": ["CVE-2020-5678"]}}})
    a, b = _parse(scalar, listed)
    assert a.category == "cwe-89" and a.metadata["cve"] == "CVE-2021-1234"
    assert b.category == "cwe-79"                      # first entry is the primary
    assert b.metadata["cve"] == "CVE-2020-5678"


def test_malformed_cwe_cve_are_absent_not_fabricated():
    """The non-fabrication rule: an unparseable identifier is absence of information."""
    line = json.dumps({"template-id": "t", "matched-at": "https://x.test/a", "info": {
        "severity": "critical", "classification": {"cwe-id": "not-a-cwe", "cve-id": "CVE-99-1"}}})
    f = _parse(line)[0]
    assert f.category is None
    assert f.metadata["cve"] is None
    # ...and nothing derived one from the other, or either from the severity.
    assert f.severity == "critical"


def test_empty_cwe_list_does_not_raise_or_invent():
    line = json.dumps({"template-id": "t", "matched-at": "https://x.test/a",
                       "info": {"severity": "low", "classification": {"cwe-id": []}}})
    assert _parse(line)[0].category is None


def test_scanner_native_identifier_is_preserved_when_canonicalisation_changed_it():
    """Provenance: normalising must never be lossy -- what nuclei actually said is kept."""
    line = json.dumps({"template-id": "t", "matched-at": "https://x.test/a", "info": {
        "severity": "high", "classification": {"cwe-id": "CWE 89"}}})
    f = _parse(line)[0]
    assert f.category == "cwe-89"
    assert f.metadata["cwe_reported"] == "CWE 89"


# --- 9. severity normalisation ---------------------------------------------------------------

def test_severity_is_lowercased_and_unknown_words_pass_through_to_the_ingest_boundary():
    """The runner lower-cases; the AUTHORITATIVE normalisation is taxonomy.normalize_severity
    at ingest. The runner must not pre-empt it by inventing a vocabulary of its own."""
    upper = json.dumps({"template-id": "a", "matched-at": "https://x.test/1",
                        "info": {"severity": "CRITICAL"}})
    weird = json.dumps({"template-id": "b", "matched-at": "https://x.test/2",
                        "info": {"severity": "catastrophic"}})
    a, b = _parse(upper, weird)
    assert a.severity == "critical"
    assert b.severity == "catastrophic"   # preserved verbatim for the boundary to rule on


def test_non_string_severity_does_not_raise():
    for value in ([" high"], 5, {"level": "high"}, True):
        line = json.dumps({"template-id": "t", "matched-at": "https://x.test/a",
                           "info": {"severity": value}})
        assert _parse(line)[0].severity == "info"   # unreadable => nuclei's default, not guessed


# --- cvss score typing ------------------------------------------------------------------------

def test_cvss_score_accepts_numeric_and_numeric_string_and_rejects_junk():
    """`cvss_score` is typed float|None and reaches a NUMERIC column."""
    def score(value):
        line = json.dumps({"template-id": "t", "matched-at": "https://x.test/a", "info": {
            "severity": "high", "classification": {"cvss-score": value}}})
        return _parse(line)[0].cvss_score

    assert score(9.8) == 9.8
    assert score(10) == 10.0
    assert score("9.8") == 9.8
    assert score("not-a-score") is None
    assert score(True) is None          # bool is an int in Python; it is not a CVSS score
    assert score(None) is None


# --- 17. scanner-native metadata / provenance preservation -----------------------------------

def test_scanner_native_metadata_is_preserved():
    line = json.dumps({
        "template-id": "acme-rce", "matched-at": "https://x.test/a?id=1",
        "matcher-name": "status-code", "type": "http",
        "info": {"name": "RCE", "severity": "high", "tags": ["cve", "rce"]},
        "request": "GET /a?id=1 HTTP/1.1\r\nX-Forwarded-For: 1.2.3.4\r\n",
    })
    f = _parse(line)[0]
    assert f.metadata["template_id"] == "acme-rce"
    assert f.metadata["matcher_name"] == "status-code"
    assert f.metadata["type"] == "http"
    assert f.metadata["tags"] == ["cve", "rce"]
    # Prompt 13 DAST context, still merged into the same flat namespace.
    assert f.metadata["http_method"] == "GET"
    assert f.metadata["parameter_names"] == ["id"]
    assert f.metadata["notable_header_names"] == ["x-forwarded-for"]


def test_non_string_request_does_not_raise():
    """`request` is free text; a list one used to raise on .splitlines() out of the batch."""
    line = json.dumps({"template-id": "t", "matched-at": "https://x.test/a",
                       "info": {"severity": "high"}, "request": ["GET / HTTP/1.1"]})
    f = _parse(line)[0]
    assert "http_method" not in f.metadata      # no basis => key omitted, not defaulted


def test_sensitive_header_values_are_never_persisted():
    line = json.dumps({
        "template-id": "t", "matched-at": "https://x.test/a", "info": {"severity": "high"},
        "request": "GET /a HTTP/1.1\r\nAuthorization: Bearer SECRET-TOKEN\r\n"
                   "Cookie: session=SECRET\r\nX-Forwarded-For: 1.2.3.4\r\n",
    })
    f = _parse(line)[0]
    blob = json.dumps(f.metadata)
    assert "SECRET-TOKEN" not in blob and "SECRET" not in blob
    assert "authorization" not in f.metadata.get("notable_header_names", [])


# --- 16. duplicate / fingerprint behaviour ---------------------------------------------------

def test_equivalent_observations_dedupe_within_a_run():
    assert len(_parse(GOOD, GOOD, GOOD)) == 1


def test_locations_differing_only_cosmetically_are_one_finding():
    """normalize_location feeds the fingerprint's identity input, so a default port and a
    case-different host are the SAME observation -- they must not become two findings."""
    a = json.dumps({"template-id": "t", "matched-at": "https://x.test/a",
                    "matcher-name": "m", "info": {"severity": "high"}})
    b = json.dumps({"template-id": "t", "matched-at": "HTTPS://X.test:443/a",
                    "matcher-name": "m", "info": {"severity": "high"}})
    assert len(_parse(a, b)) == 1


def test_distinct_observations_stay_distinguishable():
    """Dedup must not over-collapse: a different template, matcher or location is a different
    observation and keeps its own fingerprint."""
    base = {"template-id": "t", "matched-at": "https://x.test/a", "matcher-name": "m",
            "info": {"severity": "high"}}
    other_template = dict(base, **{"template-id": "t2"})
    other_matcher = dict(base, **{"matcher-name": "m2"})
    other_location = dict(base, **{"matched-at": "https://x.test/b"})
    findings = _parse(*(json.dumps(o) for o in
                        (base, other_template, other_matcher, other_location)))
    assert len({f.fingerprint for f in findings}) == 4


# --- 10. non-zero exit with usable output ----------------------------------------------------

def test_non_zero_exit_with_usable_output_keeps_the_findings_as_partial():
    """Do not discard useful partial results merely because the process exited non-zero."""
    r = NucleiRunner()
    raw = RawToolOutput(command="nuclei", stdout=GOOD, stderr="some error", exit_code=2)
    findings = r.parse_vulnerabilities(raw)
    assert len(findings) == 1
    assert classify_run(r, raw, bool(findings)) == "partial"


def test_non_zero_exit_with_malformed_output_is_failed():
    r = NucleiRunner()
    raw = RawToolOutput(command="nuclei", stdout="{broken", stderr="boom", exit_code=2)
    assert r.parse_vulnerabilities(raw) == []
    # stdout is non-empty, so the run is `partial` -- output was produced, none of it usable.
    # The point is that nothing was fabricated to fill the gap.
    assert classify_run(r, raw, False) == "partial"


# --- 15. detection never becomes verification -------------------------------------------------

def test_parsed_findings_carry_no_verification_claim():
    """A nuclei finding is an observation. The parser must not emit any field that asserts
    exploitation -- verification is decided later, from captured artefacts, by
    reports.verification (which fails toward UNVERIFIED)."""
    f = _parse(GOOD)[0]
    blob = json.dumps(f.metadata).lower()
    for claim in ("verified", "confirmed", "exploited", "proof"):
        assert claim not in blob
    assert not hasattr(f, "verification")
    assert not hasattr(f, "verified")


def test_a_detection_with_artefacts_is_never_verified_by_the_report_layer():
    """End-to-end on the boundary: even WITH both artefact kinds, a nuclei detection template
    tops out at partially_verified -- VERIFIED is unreachable from a detection."""
    from apps.api.modules.reports.verification import PARTIALLY_VERIFIED, classify_verification

    state, _confidence = classify_verification(
        template_id="acme-detect", matcher_name="body",
        evidence_uris=["s3://log"], screenshots=["s3://shot"],
    )
    assert state == PARTIALLY_VERIFIED
