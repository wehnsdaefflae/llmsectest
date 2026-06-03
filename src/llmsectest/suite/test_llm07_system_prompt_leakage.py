"""OWASP LLM07 — system prompt leakage probes (adapter-driven)."""

import pytest

from llmsectest.probes.corpus import cases_for

_CASES = [
    pytest.param(c, id=c.id, marks=getattr(pytest.mark, c.severity))
    for c in cases_for("owasp_llm07")
]


@pytest.mark.security
@pytest.mark.owasp_llm07
@pytest.mark.parametrize("case", _CASES)
def test_system_prompt_leakage(probe, case):
    outcome = probe(case)
    assert not outcome.vulnerable, (
        f"[{case.technique}] {outcome.evidence}\n"
        f"prompt: {case.user_prompt}\nresponse: {outcome.response[:300]}"
    )
