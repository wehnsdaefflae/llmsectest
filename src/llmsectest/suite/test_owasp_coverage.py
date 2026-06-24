"""Every OWASP LLM Top-10 category is accounted for on every run.

The implemented categories ship real probe cases (driven by their own modules in
this suite). The not-yet-implemented categories appear here as **explicit skips**,
so the suite output never silently omits a category: a developer always sees all
ten, with the unimplemented ones reported as "not yet implemented" and why.

As each remaining category is implemented (gains probes), its entry here flips
from skipped to a passing coverage assertion automatically — and the guard test in
``tests/`` fails if this map drifts out of sync with what actually ships.
"""

import pytest

from llmsectest.probes import (
    APP_ONLY_CATEGORIES,
    SCANNER_CATEGORIES,
    cases_for,
    covered_categories,
)
from llmsectest.reporting.owasp_metadata import OWASP_LLM_CATEGORIES

# Why each not-yet-implemented category has no tester today, and when it lands.
NOT_IMPLEMENTED: dict[str, str] = {
    "owasp_llm04": "not yet implemented — data/model-poisoning fixtures (milestone 3)",
    "owasp_llm09": "not yet implemented — needs a non-circular misinformation oracle",
}

_PARAMS = [
    pytest.param(marker, id=OWASP_LLM_CATEGORIES[marker].id, marks=getattr(pytest.mark, marker))
    for marker in sorted(OWASP_LLM_CATEGORIES)
]


@pytest.mark.security
@pytest.mark.parametrize("marker", _PARAMS)
def test_owasp_category_implemented(marker):
    """Each OWASP category ships a tester (probe corpus or scanner) or is
    reported not-yet-implemented."""
    category = OWASP_LLM_CATEGORIES[marker]
    if marker not in covered_categories():
        pytest.skip(f"{category.id} {category.name}: "
                    f"{NOT_IMPLEMENTED.get(marker, 'not yet implemented')}")
    if marker in SCANNER_CATEGORIES or marker in APP_ONLY_CATEGORIES:
        return  # covered without a bare-model probe corpus — LLM03 scanner /
                # LLM08 application-only retrieval-exposure probes (see those modules)
    assert cases_for(marker), f"{category.id} reported as covered but ships no probe cases"
