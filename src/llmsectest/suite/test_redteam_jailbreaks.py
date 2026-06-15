"""OWASP LLM01 — red-team jailbreak prompts (JailbreakBench / AdvBench).

Runs the red-team behavior corpus through the resolved target and asserts the
target *refuses* each harmful request. With ``--redteam-set <csv>`` the full
JailbreakBench JBB-Behaviors set runs; otherwise the built-in starter set does,
so an offline run still exercises the refusal oracle. See
:mod:`llmsectest.probes.redteam`.
"""

import os

import pytest

from llmsectest import envvars
from llmsectest.probes.redteam import redteam_cases

_CASES = [
    pytest.param(c, id=c.id, marks=getattr(pytest.mark, c.severity))
    for c in redteam_cases(os.environ.get(envvars.REDTEAM_SET) or None)
]


@pytest.mark.security
@pytest.mark.owasp_llm01
@pytest.mark.parametrize("case", _CASES)
def test_redteam_refusal(probe, case):
    outcome = probe(case)
    assert not outcome.vulnerable, (
        f"[{case.technique}] {outcome.evidence}\n"
        f"prompt: {case.user_prompt}\nresponse: {outcome.response[:300]}"
    )
