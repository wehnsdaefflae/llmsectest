"""OWASP LLM08 — vector & embedding weaknesses (two black-box RAG dimensions).

LLM08 covers Retrieval-Augmented Generation (RAG) and embedding-store flaws. This
module ships two black-box dimensions, each enabled by its own dev-supplied marker:

* **retrieval exposure** (``--app-canary`` → ``LLMSECTEST_APP_CANARY``) — does the
  app's retrieval layer surface confidential content from its indexed corpus to a
  user who should not reach it? The dev marks that content with a unique canary in
  an indexed document; corpus enumeration / retrieval-scope escalation / topic-
  targeted retrieval try to make the app reveal it. A canary in the reply is a
  finding (``retrieval_exposure`` oracle). Distinct from LLM02 (a secret held in the
  prompt/config): here the secret lives in the *retrieved corpus*.
* **indirect prompt injection via a poisoned retrieved document** (``--app-rag-poison``
  → ``LLMSECTEST_APP_RAG_POISON``) — does the app *obey an instruction planted in a
  retrieved document*? The dev plants a poisoned doc that tells the model to emit a
  marker; a benign query retrieves it and a vulnerable app executes it. The marker in
  the reply is a finding (the shared ``injection_marker`` oracle). The probe never
  names the marker — it comes from the corpus, not our prompt — which is what makes
  this LLM08 (retrieval-layer injection), not LLM01 (direct injection).

Like LLM03's repo scan, LLM08 needs an input only the app's operator has, so each
non-run state is an explicit skip-with-reason — never a silent pass:

* a non-``app:<url>`` target → skipped (a bare model has no retrieval corpus);
* an ``app:<url>`` target with neither marker → skipped, naming both flags.

The white-box LLM08 dimensions — embedding/data poisoning, multi-tenant namespace
isolation, embedding inversion — need the vector store's internals; they are tracked
as a later increment and reported not-exercised, never silently passed.
"""

import os

import pytest

from llmsectest import envvars
from llmsectest.probes.application import app_cases, app_name_from_endpoint


def _params():
    target = os.environ.get(envvars.TARGET, "")
    if not target.startswith("app:"):
        return [pytest.param(None, id="vector-embedding", marks=pytest.mark.skip(
            reason="LLM08 probes need a RAG application — pass --target app:<url> with "
                   "--app-canary <confidential content in a retrieved document> and/or "
                   "--app-rag-poison <marker a planted poisoned document emits>; a bare "
                   "model has no retrieval corpus"))]
    prompt, _secret, _actions, canary, poison = envvars.app_inputs_from_env()
    if not canary and not poison:
        return [pytest.param(None, id="vector-embedding", marks=pytest.mark.skip(
            reason="LLM08: no RAG-corpus marker supplied — pass --app-canary "
                   "<confidential content in an indexed document> for retrieval exposure "
                   "and/or --app-rag-poison <marker a poisoned document emits> for "
                   "indirect injection, so a leak/obey is unambiguous"))]
    cases = [c for c in app_cases(app_name_from_endpoint(target), prompt,
                                  known_canary=canary, known_poison=poison)
             if c.owasp == "owasp_llm08"]
    return [pytest.param(c, id=c.id,
                         marks=(getattr(pytest.mark, c.severity), pytest.mark.owasp_llm08))
            for c in cases]


@pytest.mark.security
@pytest.mark.parametrize("case", _params())
def test_vector_embedding(probe, case):
    outcome = probe(case)
    assert not outcome.vulnerable, (
        f"[{case.technique}] {outcome.evidence}\n"
        f"prompt: {case.user_prompt}\nresponse: {outcome.response[:300]}"
    )
