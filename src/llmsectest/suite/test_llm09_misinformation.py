"""OWASP LLM09 — misinformation / confabulation probes (adapter-driven).

Each case asks the target about an entity that does not exist — a coined library
function, a fabricated citation, an invented protocol, a future-dated CVE id. A
calibrated target says it is not aware of it / cannot find it; a vulnerable one
confabulates confident, specific detail. The ``misinformation`` detector flags a
reply that asserts the nonexistent entity by name without any uncertainty /
non-existence disclaimer. The oracle is non-circular — ground truth is that the
entity provably does not exist — so it needs no LLM judge and works black-box
against a real application endpoint as well as a local model.
"""

import pytest

from llmsectest.probes.corpus import cases_for

_CASES = [
    pytest.param(c, id=c.id, marks=getattr(pytest.mark, c.severity))
    for c in cases_for("owasp_llm09")
]


@pytest.mark.security
@pytest.mark.owasp_llm09
@pytest.mark.parametrize("case", _CASES)
def test_misinformation(probe, case):
    outcome = probe(case)
    assert not outcome.vulnerable, (
        f"[{case.technique}] {outcome.evidence}\n"
        f"prompt: {case.user_prompt}\nresponse: {outcome.response[:300]}"
    )
