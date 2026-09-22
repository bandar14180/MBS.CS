"""The MBS-authored finding description catalogue.

WHAT THESE PIN
--------------
  1. The catalogue's CONTENTS are an explicit, reviewed list. A new entry cannot be added
     without updating the approved-IDs test here, which is the review gate: MBS prose is
     attributed to MBS in the report, so what is in this catalogue is an editorial decision,
     not an implementation detail.
  2. Lookup is EXACT after normalisation. There is no fuzzy match, no prefix match and no
     generic fallback -- an unreviewed template returns None so the report carries no MBS
     analyst description for it, rather than borrowing prose written for another template.
  3. Every stored key is already in normal form, so no entry can be made unreachable by a
     typo in its key.
  4. The prose does not claim exploitation, and does not present itself as scanner output.

Nothing here touches the scanner, the parser, ingestion or the database; this module is pure.
"""

import pytest

from apps.api.modules.reports import finding_descriptions as FD


# The approved initial catalogue. Adding an ID here is the review gate described above.
APPROVED_IDS = {"reflected-xss", "blind-ssrf"}


# --- catalogue contents -------------------------------------------------------------------

def test_catalogue_contains_exactly_the_approved_ids():
    """Fails deliberately when an entry is added: MBS-attributed prose needs review."""
    assert set(FD.catalogue_template_ids()) == APPROVED_IDS


def test_every_key_is_lowercase_stripped_and_non_empty():
    """A key not in normal form would be unreachable, since lookup normalises its argument."""
    for key in FD.catalogue_template_ids():
        assert key == key.strip(), key
        assert key == key.lower(), key
        assert key, "empty key"


@pytest.mark.parametrize("template_id", sorted(APPROVED_IDS))
def test_every_value_is_a_non_empty_string_and_not_a_placeholder(template_id):
    text = FD.curated_description(template_id)
    assert isinstance(text, str)
    assert text.strip()
    # Substantive prose, not a stub someone meant to come back to.
    assert len(text) > 200, "suspiciously short for a reviewed description"
    lowered = text.lower()
    for placeholder in ("todo", "tbd", "fixme", "xxx", "lorem ipsum", "placeholder"):
        assert placeholder not in lowered, f"{template_id} still contains {placeholder!r}"


@pytest.mark.parametrize("template_id", sorted(APPROVED_IDS))
def test_curated_prose_does_not_assert_that_exploitation_occurred(template_id):
    """The catalogue is written without sight of any finding, so it cannot report an
    observation. Per-finding claims come from evidence, via narrative.py."""
    lowered = FD.curated_description(template_id).lower()
    for claim in (
        "we exploited",
        "was exploited",
        "successfully exploited",
        "we confirmed",
        "was confirmed",
        "we observed",
        "was observed",
        "the response contained",
    ):
        assert claim not in lowered, f"{template_id} asserts an observation: {claim!r}"


# --- lookup contract ----------------------------------------------------------------------

@pytest.mark.parametrize("template_id", sorted(APPROVED_IDS))
def test_exact_lookup_returns_the_catalogued_text(template_id):
    assert FD.curated_description(template_id) is not None


@pytest.mark.parametrize(
    "supplied",
    ["Reflected-XSS", "REFLECTED-XSS", "  reflected-xss  ", "\treflected-xss\n", "Reflected-Xss"],
)
def test_lookup_normalises_case_and_surrounding_whitespace(supplied):
    assert FD.curated_description(supplied) == FD.curated_description("reflected-xss")


@pytest.mark.parametrize(
    "supplied",
    [
        "apache-path-traversal",     # a real template, simply not reviewed yet
        "unix-command-injection",
        "stored-xss",                # near neighbour: must NOT borrow reflected-xss prose
        "ssrf-detect",               # near neighbour: must NOT borrow blind-ssrf prose
        "reflected-xss-extra",       # prefix of a catalogued id: no prefix matching
        "xss",                       # substring of a catalogued id: no fuzzy matching
        "something-opaque",
    ],
)
def test_unknown_template_returns_none_with_no_fallback(supplied):
    assert FD.curated_description(supplied) is None


def test_none_input_returns_none():
    assert FD.curated_description(None) is None


@pytest.mark.parametrize("supplied", ["", "   ", "\t", "\n"])
def test_empty_or_whitespace_input_returns_none(supplied):
    assert FD.curated_description(supplied) is None


# --- purity -------------------------------------------------------------------------------

def test_module_is_pure_and_does_not_import_the_reports_package():
    """No DB, no scanner, no report imports: the catalogue must stay a leaf module."""
    import inspect

    source = inspect.getsource(FD)
    for forbidden in ("import sqlalchemy", "from sqlalchemy", "from .data", "from .render",
                      "from .narrative", "from apps.api.modules.reports"):
        assert forbidden not in source, f"catalogue imports {forbidden!r}"
