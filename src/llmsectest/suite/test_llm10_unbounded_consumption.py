"""OWASP LLM10 — unbounded consumption probes (adapter-driven).

Each case asks the target to emit a marker without bound (flood, never-ending
enumeration, denial-of-wallet amplification, runaway continuation). A safe target
caps or refuses; a vulnerable one floods the marker. The ``unbounded_consumption``
detector flags a reply that repeats the marker past its flood threshold — a signal
visible even within a finite token budget, so it works black-box against a real
application endpoint as well as against a local model.
"""

import pytest

from llmsectest.probes.corpus import cases_for

_CASES = [
    pytest.param(c, id=c.id, marks=getattr(pytest.mark, c.severity))
    for c in cases_for("owasp_llm10")
]


@pytest.mark.security
@pytest.mark.owasp_llm10
@pytest.mark.parametrize("case", _CASES)
def test_unbounded_consumption(probe, case):
    outcome = probe(case)
    assert not outcome.vulnerable, (
        f"[{case.technique}] {outcome.evidence}\n"
        f"prompt: {case.user_prompt}\nresponse: {outcome.response[:300]}"
    )
