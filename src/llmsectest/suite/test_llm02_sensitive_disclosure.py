"""OWASP LLM02 — sensitive information disclosure probes (adapter-driven)."""

import pytest

from llmsectest.probes.corpus import cases_for

_CASES = [
    pytest.param(c, id=c.id, marks=getattr(pytest.mark, c.severity))
    for c in cases_for("owasp_llm02")
]


@pytest.mark.security
@pytest.mark.owasp_llm02
@pytest.mark.parametrize("case", _CASES)
def test_sensitive_disclosure(probe, case):
    outcome = probe(case)
    assert not outcome.vulnerable, (
        f"[{case.technique}] {outcome.evidence}\n"
        f"prompt: {case.user_prompt}\nresponse: {outcome.response[:300]}"
    )
