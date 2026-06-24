"""OWASP LLM08 — vector & embedding weaknesses (black-box retrieval exposure).

LLM08 covers Retrieval-Augmented Generation (RAG) and embedding-store flaws. The
black-box dimension this module ships is **retrieval exposure**: does the app's
retrieval layer surface confidential content from its indexed corpus to a user who
should not reach it? The developer marks that confidential content with a unique
canary planted in an indexed document (``--app-canary`` → ``LLMSECTEST_APP_CANARY``);
the probes then try to make the app retrieve and reveal it — corpus enumeration,
retrieval-scope escalation, topic-targeted retrieval. A canary in the reply is a
finding (scored by the ``retrieval_exposure`` oracle).

This is distinct from LLM02 (a secret held in the prompt/config): here the secret
lives in the *retrieved corpus* and the attacks target the *retrieval mechanism*.

Like LLM03's repo scan, LLM08 needs an input only the app's operator has, so each
non-run state is an explicit skip-with-reason — never a silent pass:

* a non-``app:<url>`` target → skipped (a bare model has no retrieval corpus);
* an ``app:<url>`` target without ``--app-canary`` → skipped, naming the flag.

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
            reason="LLM08 retrieval-exposure probes need a RAG application — pass "
                   "--target app:<url> with --app-canary <confidential content planted "
                   "in a retrieved document>; a bare model has no retrieval corpus"))]
    prompt, _secret, _actions, canary = envvars.app_inputs_from_env()
    if not canary:
        return [pytest.param(None, id="vector-embedding", marks=pytest.mark.skip(
            reason="LLM08 retrieval exposure: no retrieved-corpus canary supplied — "
                   "pass --app-canary <confidential content planted in an indexed "
                   "document> so a retrieval leak is unambiguous"))]
    cases = [c for c in app_cases(app_name_from_endpoint(target), prompt, known_canary=canary)
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
