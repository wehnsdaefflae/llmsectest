"""The packaged suite accounts for all 10 OWASP categories on every run: the
implemented ones run real probes, the rest are reported "not yet implemented"
(skipped with a reason) — never silently absent.

These guards fail if the not-implemented map drifts from what actually ships, so
a newly-implemented category can't be left mislabeled.
"""

from llmsectest.probes import covered_categories
from llmsectest.reporting.owasp_metadata import OWASP_LLM_CATEGORIES
from llmsectest.suite.test_owasp_coverage import NOT_IMPLEMENTED


def test_not_implemented_map_matches_reality():
    uncovered = set(OWASP_LLM_CATEGORIES) - set(covered_categories())
    assert set(NOT_IMPLEMENTED) == uncovered


def test_every_category_is_accounted_for():
    accounted = set(covered_categories()) | set(NOT_IMPLEMENTED)
    assert accounted == set(OWASP_LLM_CATEGORIES)
    assert len(accounted) == 10


def test_not_implemented_reasons_say_so():
    for marker, reason in NOT_IMPLEMENTED.items():
        assert "not yet implemented" in reason.lower(), marker
