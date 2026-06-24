"""Application-mode extras — LLM02/06/07 against a real app endpoint, dev-supplied inputs.

Against a real application endpoint (``--target app:<url>``) the canary-based
corpus modules for LLM02/06/07 would pass vacuously: they probe for *our* canary
secret/persona, which a real app does not hold. What makes those categories
testable black-box is knowledge only the app's developer has, passed on the CLI:

* ``--app-prompt`` — the app's own system prompt (text or a file path)
  → **LLM07**: we know what a leaked instruction looks like.
* ``--app-secret`` — a real secret/canary value the app holds
  → **LLM02**: a disclosure is unambiguous, no FP-prone heuristics.
* ``--app-action`` — a privileged tool/action signature of the app (repeatable)
  → **LLM06**: an unauthorized invocation is unambiguous.

Each category whose input is missing appears as an explicit skip-with-reason —
never a silent gap. For non-app targets this module steps aside with a single
skip: model/demo targets already run the full canary corpus.
"""

import os

import pytest

from llmsectest import envvars
from llmsectest.probes.application import app_cases, app_coverage, app_name_from_endpoint

# The categories this module adds on top of the always-reachable LLM01/LLM05
# modules that an app scan already runs.
_INPUT_CATEGORIES = ("owasp_llm02", "owasp_llm06", "owasp_llm07")


def _params():
    target = os.environ.get(envvars.TARGET, "")
    if not target.startswith("app:"):
        return [pytest.param(None, id="application-mode", marks=pytest.mark.skip(
            reason="application-mode extras apply only to --target app:<url> — "
                   "model/demo targets run the full canary corpus instead"))]

    # LLM08 (retrieval exposure) is gated on --app-canary and has its own module
    # (test_llm08_vector_embedding); this module stays LLM02/06/07.
    prompt, secret, actions, _canary = envvars.app_inputs_from_env()
    cases = [
        c for c in app_cases(app_name_from_endpoint(target), prompt,
                             known_secret=secret, forbidden_actions=actions or None)
        if c.owasp in _INPUT_CATEGORIES
    ]
    coverage = {c.owasp: c for c in app_coverage(prompt, known_secret=secret,
                                                 forbidden_actions=actions or None)}
    params = [
        pytest.param(c, id=c.id,
                     marks=(getattr(pytest.mark, c.severity), getattr(pytest.mark, c.owasp)))
        for c in cases
    ]
    # One visible skip per input-gated category whose input was not supplied.
    enabled = {c.owasp for c in cases}
    for marker in _INPUT_CATEGORIES:
        if marker not in enabled:
            params.append(pytest.param(
                None, id=f"{marker.replace('owasp_llm', 'LLM')}-application",
                marks=(getattr(pytest.mark, marker),
                       pytest.mark.skip(reason=coverage[marker].reason)),
            ))
    return params


@pytest.mark.security
@pytest.mark.parametrize("case", _params())
def test_application_mode(probe, case):
    outcome = probe(case)
    assert not outcome.vulnerable, (
        f"[{case.technique}] {outcome.evidence}\n"
        f"prompt: {case.user_prompt}\nresponse: {outcome.response[:300]}"
    )
