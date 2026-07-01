"""OWASP LLM10 — unbounded consumption probes (adapter-driven).

Each case asks the target to emit a marker repeatedly. A safe target caps or
refuses; a vulnerable one floods the marker. The ``unbounded_consumption`` detector
flags a reply that repeats the marker past its flood threshold — a signal visible
even within a finite token budget.

The case set is target-aware so the probe is exercised everywhere without risking a
runaway generation:

* **model / demo target** — the full corpus (flood / never-ending enumeration /
  denial-of-wallet / runaway continuation). Those requests are *unbounded*, which is
  safe against a model because the adapter caps ``max_tokens``.
* **real app endpoint (``app:<url>``)** — the *bounded* app probe instead: an explicit
  small finite repeat count, above the flood threshold yet a short reply. An uncapped
  app endpoint has no ``max_tokens`` backstop, so an unbounded request could make it
  generate to its context limit and blow the per-app time budget; the bounded count has
  a natural terminus, so app-mode LLM10 is genuinely exercised without that risk.
"""

import os

import pytest

from llmsectest import envvars
from llmsectest.probes.application import app_cases, app_name_from_endpoint
from llmsectest.probes.corpus import cases_for


def _llm10_cases():
    target = os.environ.get(envvars.TARGET, "")
    if target.startswith("app:"):
        prompt, *_ = envvars.app_inputs_from_env()
        return [
            c for c in app_cases(app_name_from_endpoint(target), prompt)
            if c.owasp == "owasp_llm10"
        ]
    return cases_for("owasp_llm10")


_CASES = [
    pytest.param(c, id=c.id, marks=getattr(pytest.mark, c.severity))
    for c in _llm10_cases()
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
