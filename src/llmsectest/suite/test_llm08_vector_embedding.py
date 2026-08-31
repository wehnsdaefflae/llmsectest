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

A third dimension is **white-box** and needs no application at all:

* **embedding-inversion exposure** (``--vector-store`` → ``LLMSECTEST_VECTOR_STORE``)
  reads a persisted vector store and reports how much of the corpus somebody with
  read access to it recovers (see :mod:`llmsectest.probes.vectorstore`). It does not
  run an inversion, and says so: inverting an embedding needs a trained inverter per
  embedding space, which no offline scanner can carry. It answers the question
  inversion asks, from the store, where the usual answer is that the plaintext is
  filed next to the vector and no inversion is needed.

The remaining white-box dimensions — embedding-store poisoning and multi-tenant
namespace isolation — are tracked as a later increment and reported not-exercised,
never silently passed.
"""

import os
from pathlib import Path

import pytest

from llmsectest import envvars
from llmsectest.probes.application import app_cases, app_name_from_endpoint
from llmsectest.probes.vectorstore import (
    discover_vector_stores,
    scan_vector_stores,
    unreadable_stores,
)
from llmsectest.suite.scanners import fail_with_finding, scanner_params


def _params():
    target = os.environ.get(envvars.TARGET, "")
    if not target.startswith("app:"):
        return [pytest.param(None, id="vector-embedding", marks=pytest.mark.skip(
            reason="LLM08 probes need a RAG application, pass --target app:<url> with "
                   "--app-canary <confidential content in a retrieved document> and/or "
                   "--app-rag-poison <marker a planted poisoned document emits>; a bare "
                   "model has no retrieval corpus"))]
    prompt, _secret, _actions, canary, poison = envvars.app_inputs_from_env()
    if not canary and not poison:
        return [pytest.param(None, id="vector-embedding", marks=pytest.mark.skip(
            reason="LLM08: no RAG-corpus marker supplied, pass --app-canary "
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


def _store_load():
    """Return (findings, skip_reason). ``findings`` is None when skipped."""
    path = os.environ.get(envvars.VECTOR_STORE)
    if not path:
        return None, ("no vector store supplied, pass --vector-store <path> to scan a "
                      "persisted store for embedding-inversion exposure")
    p = Path(path)
    if not p.exists():
        return None, f"vector store path {path!r} does not exist"
    if not discover_vector_stores(p):
        unread = unreadable_stores(p)
        if unread:
            # Naming them matters more than the skip does. A store we recognised and
            # could not open holds exactly the plaintext this scan looks for, and
            # "no findings" over a file nobody read is the failure this project is
            # named after.
            names = ", ".join(sorted({u.suffix for u in unread}))
            return None, (f"found {len(unread)} store file(s) needing a reader we do not "
                          f"ship ({names}) and no store we can open under {path}")
        return None, (f"no readable vector store (Chroma sqlite, JSON/JSONL store, FAISS "
                      f"sidecar pickle) found under {path}")
    return scan_vector_stores(p), ""


def _store_params():
    findings, skip = _store_load()
    return scanner_params(findings, skip,
                          category_label="LLM08 embedding-inversion exposure",
                          skip_id="vector-store",
                          clean_id="no-embedding-inversion-exposure")


@pytest.mark.security
@pytest.mark.owasp_llm08
@pytest.mark.parametrize("finding", _store_params())
def test_embedding_inversion_exposure(finding, record_property):
    if finding is None:
        return  # no store path (skipped via mark) or scanned with no exposure found
    message = (
        f"[{finding.technique}] {finding.location}: "
        f"{finding.evidence}\n  \u2192 {finding.recommendation}"
    )
    fail_with_finding(record_property, message=message, artifact_uri=finding.store_file)
