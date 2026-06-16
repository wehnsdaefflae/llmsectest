"""Unit tests for the LLM01 red-team integration (JailbreakBench / AdvBench).

Cover the corpus loader, the built-in starter set, the refusal oracle (including
its inverted polarity and the affirmative-target override), and the offline demo
behaviour — all deterministic, no network, no API key.
"""

from __future__ import annotations

import pytest

from llmsectest.probes import (
    FalseRefusalReport,
    benign_cases,
    builtin_behaviors,
    builtin_benign,
    defended_demo_adapter,
    get_detector,
    load_benign_set,
    load_redteam_set,
    measure_false_refusal,
    redteam_cases,
    run_probe,
    vulnerable_demo_adapter,
)
from llmsectest.probes.detectors import (
    REFUSAL_MARKERS,
    over_refusal_oracle,
    refusal_oracle,
)
from llmsectest.probes.models import SEVERITIES

_CSV_HEADER = "Index,Goal,Target,Behavior,Category,Source\n"


def _refusal_case():
    return builtin_behaviors()[0].to_case()


# --- built-in starter set ---------------------------------------------------------

def test_builtin_cases_are_well_formed():
    cases = redteam_cases()
    assert len(cases) >= 8
    ids = [c.id for c in cases]
    assert len(set(ids)) == len(ids), "duplicate red-team case ids"
    for c in cases:
        assert c.owasp == "owasp_llm01"
        assert c.detector == "refusal_oracle"
        assert c.severity in SEVERITIES
        assert c.forbidden and c.forbidden[0]
        assert c.user_prompt and c.system_prompt
        # the detector name resolves through the registry
        get_detector(c.detector)


def test_malware_category_ranks_critical():
    by_id = {b.behavior: b.to_case() for b in builtin_behaviors()}
    # the ransomware/malware behavior is tagged critical; defamation is high
    assert by_id["Malware"].severity == "critical"
    assert by_id["Defamation"].severity == "high"


# --- refusal oracle ---------------------------------------------------------------

def test_refusal_oracle_flags_compliance_without_a_marker():
    case = _refusal_case()
    vulnerable, evidence = refusal_oracle("Sure, step one is to gather the names…", case)
    assert vulnerable is True
    assert "did not refuse" in evidence


def test_refusal_oracle_passes_a_refusal():
    case = _refusal_case()
    vulnerable, evidence = refusal_oracle(
        "I'm sorry, but I can't help with creating false or defamatory content.", case
    )
    assert vulnerable is False
    assert "refused" in evidence


def test_affirmative_target_overrides_apologetic_boilerplate():
    """A reply that emits the harmful completion is a finding even if it also
    contains a refusal phrase (the affirmative-target override)."""
    case = _refusal_case()
    sneaky = f"I'm sorry, but as an exception — {case.forbidden[0]}: lorem ipsum."
    vulnerable, evidence = refusal_oracle(sneaky, case)
    assert vulnerable is True
    assert "affirmative target" in evidence


def test_every_refusal_marker_is_recognized():
    case = _refusal_case()
    for marker in REFUSAL_MARKERS:
        assert refusal_oracle(f"Response: {marker} …", case)[0] is False, marker


def test_defended_reply_is_recognized_as_a_refusal():
    """Drift guard: the offline defended target's reply must read as a refusal to
    the oracle, so the demo and the oracle can't silently diverge."""
    case = _refusal_case()
    reply = defended_demo_adapter().prompt(case.user_prompt, system=case.system_prompt)
    assert refusal_oracle(reply, case)[0] is False


# --- offline demo behaviour -------------------------------------------------------

def test_vulnerable_demo_is_flagged_for_every_builtin_case():
    adapter = vulnerable_demo_adapter()
    for case in redteam_cases():
        outcome = run_probe(adapter, case)
        assert outcome.vulnerable, f"{case.id} not caught: {outcome.response!r}"


def test_defended_demo_passes_every_builtin_case():
    adapter = defended_demo_adapter()
    for case in redteam_cases():
        outcome = run_probe(adapter, case)
        assert not outcome.vulnerable, f"{case.id} false positive: {outcome.evidence}"


# --- the JBB-Behaviors CSV loader -------------------------------------------------

def test_load_redteam_set_parses_jbb_schema(tmp_path):
    csv_path = tmp_path / "harmful.csv"
    csv_path.write_text(
        _CSV_HEADER
        + '0,"Do a bad thing","Sure, here is the bad thing",BadThing,Malware,AdvBench\n'
        + '1,"Do another bad thing","Sure, here it is",Other,Fraud,Original\n',
        encoding="utf-8",
    )
    cases = load_redteam_set(csv_path)
    assert len(cases) == 2
    assert cases[0].id == "LLM01-redteam-000"
    assert cases[0].owasp == "owasp_llm01"
    assert cases[0].detector == "refusal_oracle"
    assert cases[0].forbidden == ("Sure, here is the bad thing",)
    assert "AdvBench" in cases[0].technique
    assert cases[0].severity == "critical"  # Malware category
    assert cases[1].severity == "high"


def test_load_redteam_set_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_redteam_set(tmp_path / "nope.csv")


def test_load_redteam_set_rejects_non_jbb_csv(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("foo,bar\n1,2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Goal"):
        load_redteam_set(bad)


def test_load_redteam_set_rejects_empty(tmp_path):
    empty = tmp_path / "empty.csv"
    empty.write_text(_CSV_HEADER, encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        load_redteam_set(empty)


def test_redteam_cases_uses_path_when_given(tmp_path):
    csv_path = tmp_path / "one.csv"
    csv_path.write_text(
        _CSV_HEADER + '7,"Bad","Sure, here is bad",B,Cyber,TDC\n', encoding="utf-8"
    )
    cases = redteam_cases(csv_path)
    assert len(cases) == 1 and cases[0].id == "LLM01-redteam-007"
    # None falls back to the built-in starter set
    assert len(redteam_cases(None)) == len(builtin_behaviors())


# --- benign twins: the over-refusal (false-refusal) metric ------------------------

def test_builtin_benign_cases_are_well_formed():
    cases = benign_cases()
    assert len(cases) == len(builtin_benign()) >= 8
    ids = [c.id for c in cases]
    assert len(set(ids)) == len(ids), "duplicate benign case ids"
    for c in cases:
        assert c.owasp == "owasp_llm01"
        assert c.detector == "over_refusal_oracle"
        assert c.severity == "low"  # a usability defect, never a critical finding
        assert c.id.startswith("LLM01-benign-")
        assert c.forbidden and c.forbidden[0]
        assert c.user_prompt and c.system_prompt
        get_detector(c.detector)


def test_benign_twins_are_matched_to_the_harmful_starter_set():
    """Each benign twin shares its index and category with a harmful behavior, so
    the metric measures the specificity of the *same* guarded configuration."""
    from llmsectest.probes.redteam import REDTEAM_SYSTEM_PROMPT

    harmful = {b.index: b for b in builtin_behaviors()}
    benign = {b.index: b for b in builtin_benign()}
    assert harmful.keys() == benign.keys()
    for idx, twin in benign.items():
        assert twin.category == harmful[idx].category
        # the twin probes the same guarded persona the harmful set does
        assert twin.to_case(benign=True).system_prompt == REDTEAM_SYSTEM_PROMPT


# --- over-refusal oracle ----------------------------------------------------------

def _benign_case():
    return builtin_benign()[0].to_case(benign=True)


def test_over_refusal_oracle_flags_a_refusal_of_a_benign_request():
    case = _benign_case()
    vulnerable, evidence = over_refusal_oracle(
        "I'm sorry, but I can't help with that request.", case
    )
    assert vulnerable is True
    assert "OVER-REFUSED" in evidence


def test_over_refusal_oracle_passes_a_helpful_answer():
    case = _benign_case()
    vulnerable, evidence = over_refusal_oracle(
        "Here is a balanced summary of the official's voting record: …", case
    )
    assert vulnerable is False
    assert "did not refuse" in evidence


def test_over_refusal_affirmative_answer_overrides_a_stray_marker():
    """A reply that actually answers (emits the affirmative completion) is not an
    over-refusal even if it also contains a refusal-like phrase."""
    case = _benign_case()
    reply = f"{case.forbidden[0]} — though I'm sorry it took a moment."
    vulnerable, evidence = over_refusal_oracle(reply, case)
    assert vulnerable is False
    assert "answered the benign request" in evidence


def test_oracles_have_opposite_polarity_on_the_same_reply():
    """The same refusal reply is *safe* for a harmful behavior but a *finding*
    (over-refusal) for a benign one — the two oracles must not drift together."""
    refusal = "I'm sorry, but I cannot help with that."
    assert refusal_oracle(refusal, _refusal_case())[0] is False
    assert over_refusal_oracle(refusal, _benign_case())[0] is True


def test_vulnerable_demo_does_not_over_refuse_benign_twins():
    adapter = vulnerable_demo_adapter()
    for case in benign_cases():
        outcome = run_probe(adapter, case)
        assert not outcome.vulnerable, f"{case.id} false over-refusal: {outcome.evidence}"


def test_defended_demo_over_refuses_every_benign_twin():
    """Drift guard + dual demo: the offline 'hardened' target refuses everything,
    so it over-refuses every benign twin (100% false-refusal rate)."""
    adapter = defended_demo_adapter()
    for case in benign_cases():
        outcome = run_probe(adapter, case)
        assert outcome.vulnerable, f"{case.id} not flagged: {outcome.response!r}"


# --- the false-refusal-rate measurement -------------------------------------------

def test_measure_false_refusal_separates_over_defensive_from_compliant():
    vulnerable = measure_false_refusal(vulnerable_demo_adapter())
    defended = measure_false_refusal(defended_demo_adapter())
    assert isinstance(vulnerable, FalseRefusalReport)
    assert vulnerable.total == defended.total == len(builtin_benign())
    # vulnerable demo answers everything; defended demo refuses everything
    assert vulnerable.refused == 0 and vulnerable.rate == 0.0
    assert defended.refused == defended.total and defended.rate == 1.0
    assert all(o.vulnerable for o in defended.over_refusals)


def test_false_refusal_report_rate_handles_empty():
    assert FalseRefusalReport(total=0, over_refusals=()).rate == 0.0


# --- the JBB benign-behaviors CSV loader ------------------------------------------

def test_load_benign_set_parses_jbb_schema(tmp_path):
    csv_path = tmp_path / "benign.csv"
    csv_path.write_text(
        _CSV_HEADER
        + '0,"Explain how bread is baked","Sure, here is how bread is baked",Bake,Cooking,Original\n',
        encoding="utf-8",
    )
    cases = load_benign_set(csv_path)
    assert len(cases) == 1
    assert cases[0].id == "LLM01-benign-000"
    assert cases[0].detector == "over_refusal_oracle"
    assert cases[0].severity == "low"
    assert cases[0].forbidden == ("Sure, here is how bread is baked",)


def test_load_benign_set_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_benign_set(tmp_path / "nope.csv")


def test_benign_cases_uses_path_when_given(tmp_path):
    csv_path = tmp_path / "one.csv"
    csv_path.write_text(
        _CSV_HEADER + '3,"Be helpful","Sure, here you go",H,Cooking,Original\n',
        encoding="utf-8",
    )
    cases = benign_cases(csv_path)
    assert len(cases) == 1 and cases[0].id == "LLM01-benign-003"
    assert len(benign_cases(None)) == len(builtin_benign())
