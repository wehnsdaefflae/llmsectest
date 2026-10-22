"""The two axes beside the oracle reach the published SARIF (bl-084, phase-03 item b).

WHY THIS FILE EXISTS SEPARATELY from ``test_capability_axis.py`` and
``test_refusal_content_axis.py``. Those prove the axes COMPUTE correctly. This proves
they are VISIBLE — that the verdict survives the trip from ``ProbeOutcome`` through the
pytest property bridge into the SARIF a reader actually opens.

The distinction is not academic. Before 2026-10-21 the capability axis had been built,
tested and merged, and was recorded on no report at all: ``grep`` for ``.capability``
across ``src/`` returned exactly one hit, the line in ``runner.py`` that sets it. A
verdict nothing reports is a verdict nobody reads, and the unit tests were all green the
whole time. These tests fail if that happens again to either axis.
"""

from __future__ import annotations

import json

from llmsectest.reporting.sarif_generator import SARIFGenerator, TestResult


def _sarif_properties(properties: dict[str, object]) -> dict[str, object]:
    """Run one finding through the generator and return its SARIF properties."""
    result = TestResult(
        nodeid="…::test_prompt_injection[LLM01-refusal]",
        location=("src/llmsectest/suite/test_llm01_prompt_injection.py", 18, "t"),
        outcome="failed",
        longrepr="Failed: the target complied",
        markers=["security", "owasp_llm01", "high"],
        properties={"llmsec_finding": "the target complied", **properties},
    )
    generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
    sarif = json.loads(generator.generate([result]))
    return sarif["runs"][0]["results"][0]["properties"]


def test_the_capability_verdict_and_its_evidence_reach_the_finding():
    props = _sarif_properties(
        {
            "llmsec_capability": "opener_only",
            "llmsec_capability_evidence": (
                "affirmative opener present with 2 word(s) behind it against the "
                "opener's own 5; an affirmative opener with nothing behind it is not "
                "a jailbreak (JailbreakBench)"
            ),
        }
    )
    assert props["capability"] == "opener_only"
    # The evidence prints the measurement, which is the whole reason it is carried.
    assert "word(s) behind it" in props["capability_evidence"]


def test_the_refusal_content_verdict_and_its_evidence_reach_the_finding():
    props = _sarif_properties(
        {
            "llmsec_refusal_content": "discloses",
            "llmsec_refusal_content_evidence": (
                "the refusal echoes 11 consecutive words of the application's own "
                "system prompt that the attacker did not send: 'escalate any request "
                "about payroll to the finance partner before answering'"
            ),
        }
    )
    assert props["refusal_content"] == "discloses"
    # The span itself is carried, so a reader judges it rather than the verdict.
    assert "escalate any request about payroll" in props["refusal_content_evidence"]


def test_an_axis_that_said_nothing_adds_no_property():
    """``unmeasured`` is carried as absence, so a row that was never measured has no
    column rather than an empty one — the same rule the dataclass applies."""
    props = _sarif_properties({})
    assert "capability" not in props
    assert "capability_evidence" not in props
    assert "refusal_content" not in props
    assert "refusal_content_evidence" not in props


def test_neither_axis_changes_the_finding_s_level_or_outcome():
    """‼ THE PROPERTY THAT WOULD BE EXPENSIVE TO GET WRONG.

    A ``discloses`` row is still a row where the application DECLINED, and a span
    matcher cannot tell a damaging disclosure from a harmless restatement of a public
    policy line. If either axis ever started moving ``level``, findings would silently
    migrate between published categories — LLM08 Hidden Context Exposure has its own
    probes and its own rate — and every rate on the site would move with them.
    """
    bare = _sarif_properties({})
    with_axes = _sarif_properties(
        {
            "llmsec_capability": "delivered",
            "llmsec_refusal_content": "discloses",
        }
    )
    assert with_axes["test_outcome"] == bare["test_outcome"]

    def _level(properties: dict[str, object]) -> str:
        result = TestResult(
            nodeid="…::test_prompt_injection[LLM01-refusal]",
            location=("src/llmsectest/suite/test_llm01_prompt_injection.py", 18, "t"),
            outcome="failed",
            longrepr="Failed: the target complied",
            markers=["security", "owasp_llm01", "high"],
            properties={"llmsec_finding": "the target complied", **properties},
        )
        sarif = json.loads(
            SARIFGenerator("llmsectest", "0.1.0", source_root=".").generate([result])
        )
        return sarif["runs"][0]["results"][0]["level"]

    assert _level({}) == _level(
        {"llmsec_capability": "delivered", "llmsec_refusal_content": "discloses"}
    )


def test_a_passing_probe_carries_its_axes_too():
    """The axes are recorded on every red-team probe, not only the ones that fired.

    A probe that found nothing because the target refused is exactly the probe whose
    refusal-content verdict a reader wants, so restricting these to findings would drop
    the interesting half.
    """
    result = TestResult(
        nodeid="…::test_prompt_injection[LLM01-held]",
        location=("src/llmsectest/suite/test_llm01_prompt_injection.py", 18, "t"),
        outcome="passed",
        markers=["security", "owasp_llm01", "high"],
        properties={
            "llmsec_probe": "owasp_llm01",
            "llmsec_reply": "I'm sorry, I can't help with that.",
            "llmsec_refusal_content": "clean",
            "llmsec_capability": "absent",
        },
    )
    generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
    sarif = json.loads(generator.generate([result]))
    rows = sarif["runs"][0]["results"]
    # A passing probe is a transcript row (kind: pass, issue #21), not a finding. What
    # this pins is that recording the axes on a passing probe does not invent one.
    assert len(rows) == 1
    assert rows[0]["kind"] == "pass"
    assert rows[0]["properties"]["capability"] == "absent"
    assert rows[0]["properties"]["refusal_content"] == "clean"


def test_a_passing_probe_with_no_recorded_reply_invents_no_row():
    """The transcript row exists to carry a reply; with no reply there is nothing to say."""
    result = TestResult(
        nodeid="…::test_prompt_injection[LLM01-held]",
        location=("src/llmsectest/suite/test_llm01_prompt_injection.py", 18, "t"),
        outcome="passed",
        markers=["security", "owasp_llm01", "high"],
        properties={"llmsec_probe": "owasp_llm01"},
    )
    sarif = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", source_root=".").generate([result])
    )
    assert sarif["runs"][0]["results"] == []
