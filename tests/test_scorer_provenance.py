"""Independent PR #46 review: name the scorer that actually made a finding.

These tests deliberately exercise the two shipped LLM10 fallback paths omitted by
PR #46's LLM01/LLM07 demo regression. They live outside the product checkout.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import llmsectest
from llmsectest.adapters.base import AdapterTimeoutError, CompletionResponse
from llmsectest.probes.application import _llm10_app_cases
from llmsectest.probes.corpus import cases_for
from llmsectest.probes.detectors import detector_description, get_detector
from llmsectest.probes.runner import TargetResponsiveness
from llmsectest.reporting.models import TestResult
from llmsectest.reporting.sarif_generator import SARIFGenerator

ROOT = Path(llmsectest.__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("pr46_packaged_conftest", ROOT / "suite/conftest.py")
assert SPEC and SPEC.loader
CONFTEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFTEST)


class TimeoutAdapter:
    def complete(self, request):
        raise AdapterTimeoutError("no reply within budget", timeout=90)


class TokenCeilingAdapter:
    def complete(self, request):
        return CompletionResponse(text="hello", model="review-stub", provider="offline",
                                  usage={"completion_tokens": request.max_tokens})


def _finding(adapter, case, responsiveness):
    properties = {}
    probe = CONFTEST.probe.__wrapped__(
        target_adapter=adapter,
        target_responsiveness=responsiveness,
        configured_secret=None,
        configured_actions=(),
        configured_prompt="",
        configured_canary=None,
        configured_poison=None,
        configured_policy=None,
        configured_tool_schema=None,
        record_property=properties.__setitem__,
    )
    outcome = probe(case)
    assert outcome.vulnerable and not outcome.errored, outcome
    result = TestResult(
        nodeid=f"suite/test_llm10.py::test_consumption[{case.id}]",
        location=("suite/test_llm10.py", 1, f"test_consumption[{case.id}]"),
        outcome="failed",
        markers=["security", case.owasp, case.severity],
        properties=properties,
    )
    sarif = json.loads(SARIFGenerator("llmsectest", "0.4.1", source_root=".").generate([result]))
    finding = sarif["runs"][0]["results"][0]
    print(json.dumps({
        "case": case.id,
        "package": str(ROOT),
        "evidence": outcome.evidence,
        "published_detector": finding["properties"].get("detector"),
        "published_description": finding["properties"].get("detector_description"),
        "level": finding["level"],
        "severity_scope": finding["properties"].get("severity_scope"),
    }, sort_keys=True))
    return outcome, finding


def test_timeout_finding_must_not_name_an_oracle_that_never_ran():
    case = _llm10_app_cases("pr46-review", "")[0]
    responsiveness = TargetResponsiveness(completions=[2.0] * 5)
    with patch("llmsectest.probes.runner.get_detector", wraps=get_detector) as lookup:
        outcome, finding = _finding(TimeoutAdapter(), case, responsiveness)
    assert outcome.timed_out
    lookup.assert_not_called()
    assert outcome.scorer == "differential_timeout"
    assert finding["properties"]["detector"] == "differential_timeout"
    assert finding["properties"]["detector_description"] == (
        "Score a per-request timeout: an LLM10 finding when the differential supports it."
    )
    assert finding["level"] == "error"
    assert finding["properties"]["severity_scope"] == {
        "level": "probe", "cvss_base_severity": "category"
    }


def test_token_ceiling_finding_must_not_name_the_oracle_that_found_no_violation():
    case = next(c for c in cases_for("owasp_llm10") if c.id == "LLM10-output-ceiling")
    assert not get_detector(case.detector)("hello", case)[0]
    outcome, finding = _finding(TokenCeilingAdapter(), case, TargetResponsiveness())
    assert "output-token ceiling" in outcome.evidence
    assert outcome.scorer == "output_ceiling_reached"
    assert finding["properties"]["detector"] == "output_ceiling_reached"
    assert finding["properties"]["detector_description"] == (
        "LLM10 — the reply reached the output-token ceiling on an unbounded request."
    )
    assert finding["level"] == "warning"
    assert finding["properties"]["severity_scope"] == {
        "level": "probe", "cvss_base_severity": "category"
    }


class MarkerAdapter:
    def complete(self, request):
        return CompletionResponse(text="PWNED-LLM01-OVERRIDE", model="test", provider="offline")


def test_ordinary_finding_keeps_the_response_detector_that_fired():
    case = next(c for c in cases_for("owasp_llm01") if c.id == "LLM01-direct-override")
    outcome, finding = _finding(MarkerAdapter(), case, TargetResponsiveness())
    assert outcome.scorer == case.detector
    assert finding["properties"]["detector"] == case.detector
    assert finding["properties"]["detector_description"] == detector_description(case.detector)
