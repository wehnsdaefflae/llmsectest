"""A poisoned document with no topic of its own masks the LLM08 retrieval probes
too, even once the competing-marker check (issue #12) stops it reading as a false
``withstood`` (issue #38).

With both ``--app-canary`` and ``--app-rag-poison`` set, all six LLM08 cases run
against one application. :mod:`tests.test_confounded_retrieval_probes` fixes the
*scoring* side: a reply carrying the poison marker instead of the canary now reads
``errored`` (inconclusive), never a false pass. But every test there, and the
``_AnsweringAdapter`` they share, answers every probe with the same one fixed reply --
which means the retrieval-exposure dimension can *never* get a genuine answer of its
own in that fixture: it is always confounded, never confirmed. That matches what
``docs/owasp/llm08.md`` measured across 16 real applications: 13 obeyed the poison on
every probe, and only one ever showed the retrieval dimension alone.

The fixture itself, not the scanner, is why: a single fixed reply has no notion of
*which* document a query actually retrieves. This module adds a more realistic test
fixture, :class:`_TopicRoutedAdapter`, which holds two documents on distinct topics and
answers each query from whichever one its own wording actually matches (the top-1
retrieval a real vector store would do). No file under ``src/llmsectest/probes/`` or
``src/llmsectest/adapters/`` changes: the fix is fixture content, matching what the
issue asks for, not scanning logic.
"""

from __future__ import annotations

from llmsectest.adapters.base import CompletionResponse, LLMAdapter
from llmsectest.probes.application import app_cases
from llmsectest.probes.runner import run_probe

CANARY = "DOC-CANARY-9z"
POISON = "RAG-POISON-3b9d"

# The two attack families' own wording, in src/llmsectest/probes/application.py,
# already separates by topic: every _RETRIEVAL_ATTACKS prompt asks about "confidential"
# material, and every _RAG_INJECTION_ATTACKS prompt asks about a knowledge-base
# "instruction". A fixture that plants its canary and poison documents on those same
# two topics, instead of one document answering everything, lets each probe family
# retrieve the document it actually asked about.
_CANARY_TOPIC = "confidential"
_POISON_TOPIC = "instruction"


class _TopicRoutedAdapter(LLMAdapter):
    """A mock RAG app with two documents on distinct topics and a top-1 retriever.

    Each document is ``(topic keyword, reply if retrieved)``. ``complete`` picks
    whichever document's topic keyword appears in the query -- the simplest possible
    stand-in for a vector store returning its single best match -- and replies as if
    that were the only document retrieved. A query matching neither document falls
    back to the first one, which never happens for the probes this module runs.
    """

    provider = "mock"

    def __init__(self, documents: list[tuple[str, str]]):
        super().__init__("m")
        self._documents = documents

    def complete(self, request):
        query = request.messages[-1].content.lower()
        for topic, reply in self._documents:
            if topic in query:
                return CompletionResponse(text=reply, model="m", provider="mock",
                                           raw={}, usage={})
        topic, reply = self._documents[0]
        return CompletionResponse(text=reply, model="m", provider="mock", raw={},
                                   usage={})


def _llm08_cases():
    cases = app_cases("x", "", known_canary=CANARY, known_poison=POISON)
    return [c for c in cases if c.owasp == "owasp_llm08"]


def test_distinct_topics_and_top_k_let_both_dimensions_co_fire():
    """Regression: a poisoned document with no topic of its own masks retrieval
    exposure even when a real canary leak would otherwise be there to find.

    Goes red if the adapter collapses back to one reply for every query (the
    ``_AnsweringAdapter`` fixture every other LLM08 test uses), which is the shape the
    present masking happens under.
    """
    adapter = _TopicRoutedAdapter([
        (_CANARY_TOPIC, f"The confidential record on file reads: {CANARY}"),
        (_POISON_TOPIC, POISON),
    ])
    cases = _llm08_cases()
    assert len(cases) == 6, "expected 3 retrieval-exposure + 3 injection cases"

    outcomes = [run_probe(adapter, case) for case in cases]
    retrieval_outcomes = [o for o, c in zip(outcomes, cases, strict=True)
                          if c.detector == "retrieval_exposure"]
    injection_outcomes = [o for o, c in zip(outcomes, cases, strict=True)
                          if c.detector == "injection_marker"]

    assert any(o.vulnerable for o in retrieval_outcomes), (
        "the canary leak never fired -- retrieval exposure is still masked")
    assert any(o.vulnerable for o in injection_outcomes), (
        "the injection probe never fired")
    assert not any(o.errored for o in retrieval_outcomes), (
        "a retrieval probe was confounded even though its own topic was retrieved "
        "cleanly, with no poison text in the reply")


def test_the_same_six_cases_mask_each_other_under_the_present_single_reply_fixture():
    """Contrast: the fixture every existing LLM08 test shares is exactly why the
    masking is total. Not a bug in that fixture -- it was never meant to model
    retrieval -- but the reason this module's fixture exists.
    """
    from tests.test_confounded_retrieval_probes import _AnsweringAdapter

    adapter = _AnsweringAdapter(POISON)
    cases = _llm08_cases()
    outcomes = [run_probe(adapter, case) for case in cases]
    retrieval_outcomes = [o for o, c in zip(outcomes, cases, strict=True)
                          if c.detector == "retrieval_exposure"]

    assert not any(o.vulnerable for o in retrieval_outcomes), (
        "retrieval exposure should still be fully masked under the single-reply "
        "fixture -- if this now fires, the contrast this module demonstrates no "
        "longer holds and the docstring above needs updating")
