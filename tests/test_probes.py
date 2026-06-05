"""Unit tests for the adapter-driven probe library (deterministic, offline).

These prove the probe machinery itself: detectors flag vulnerable replies and
clear safe ones, and the curated corpus is well-formed. They run against the
offline ScriptedAdapter demo targets — no network, no API key — so they are
safe to keep in the default CI collection.
"""

from __future__ import annotations

from llmsectest.adapters.mock import ScriptedAdapter
from llmsectest.probes import (
    cases_for,
    covered_categories,
    defended_demo_adapter,
    get_corpus,
    get_detector,
    resolve_target,
    run_probe,
    vulnerable_demo_adapter,
)
from llmsectest.probes.models import SEVERITIES

EXPECTED_CATEGORIES = {"owasp_llm01", "owasp_llm02", "owasp_llm05", "owasp_llm07"}


def test_corpus_covers_implemented_categories():
    assert set(covered_categories()) == EXPECTED_CATEGORIES
    for cat in EXPECTED_CATEGORIES:
        assert cases_for(cat), f"no cases for {cat}"


def test_corpus_cases_are_well_formed():
    seen_ids = set()
    for case in get_corpus():
        assert case.id not in seen_ids, f"duplicate case id {case.id}"
        seen_ids.add(case.id)
        assert case.severity in SEVERITIES
        assert case.forbidden, f"{case.id} has no forbidden tokens"
        assert case.user_prompt and case.system_prompt
        # detector must be registered
        get_detector(case.detector)


def test_detectors_flag_present_tokens():
    for case in get_corpus():
        detector = get_detector(case.detector)
        leaked = f"here you go: {case.forbidden[0]} -- anything else?"
        vulnerable, evidence = detector(leaked, case)
        assert vulnerable, f"{case.id}: detector missed a planted token"
        assert case.forbidden[0] in evidence


def test_detectors_pass_clean_responses():
    safe = "I can only help with ACME product questions and won't share that."
    for case in get_corpus():
        vulnerable, _ = get_detector(case.detector)(safe, case)
        assert not vulnerable, f"{case.id}: false positive on a safe reply"


def test_vulnerable_demo_target_is_flagged_for_every_case():
    adapter = vulnerable_demo_adapter()
    for case in get_corpus():
        outcome = run_probe(adapter, case)
        assert outcome.vulnerable, f"{case.id} not caught: {outcome.response!r}"
        assert outcome.case is case


def test_defended_demo_target_passes_every_case():
    adapter = defended_demo_adapter()
    for case in get_corpus():
        outcome = run_probe(adapter, case)
        assert not outcome.vulnerable, f"{case.id} false positive: {outcome.evidence}"


def test_resolve_target_demo_keywords():
    assert resolve_target("demo-vulnerable").model == "demo-vulnerable"
    assert resolve_target("demo-defended").model == "demo-defended"
    assert resolve_target("").model == "demo-vulnerable"


def test_resolve_target_provider_spec_is_lazy():
    # "mock" must resolve without importing any vendor SDK.
    adapter = resolve_target("mock")
    assert adapter.provider == "mock"


def test_unsafe_output_detector_ignores_escaped_payload():
    """LLM05: only raw/executable output is a finding — escaping it must not be."""
    case = cases_for("owasp_llm05")[0]  # the <script> XSS case
    raw = case.forbidden[0]
    escaped = raw.replace("<", "&lt;").replace(">", "&gt;")
    detector = get_detector(case.detector)
    assert detector(raw, case)[0] is True, "raw active payload should be flagged"
    assert detector(escaped, case)[0] is False, "escaped payload is a false positive"


def test_runner_uses_case_system_prompt():
    # The runner must pass the case's system prompt through to the adapter.
    seen = {}

    def responder(request):
        seen["system"] = request.messages[0].content
        return "ok"

    case = cases_for("owasp_llm07")[0]
    run_probe(ScriptedAdapter(responder), case)
    assert seen["system"] == case.system_prompt
