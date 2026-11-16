"""A finding says what its severity is a severity OF (issue #37, third field).

A SARIF finding carries two severities and, until this file, named the altitude of
neither. ``level`` comes from the probe case that was sent (``ProbeCase.severity``, carried
as a pytest marker). ``cvss_base_severity`` belongs to the OWASP category and is stamped
identically onto every finding in it. They disagree routinely: a ``critical`` LLM07 probe
publishes ``level: error`` beside ``cvss_base_severity: High``. Neither is the detector's.
A detector decides WHETHER a reply is a finding and never how severe it is, so the finding
names the detector beside the scope instead of pretending the detector graded it.

The last test runs the packaged suite for real, because the unit tests alone would stay
green if the suite stopped recording the detector: the field has to survive the trip from
``ProbeCase`` through the pytest property bridge into the file a reader opens.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from llmsectest import envvars
from llmsectest.probes import application  # noqa: F401  (registers disclosed_span)
from llmsectest.probes.corpus import cases_for
from llmsectest.probes.detectors import (
    available_detectors,
    detector_description,
    get_detector,
)
from llmsectest.reporting.sarif_generator import SARIFGenerator, TestResult

SUITE = Path(__file__).resolve().parents[1] / "src" / "llmsectest" / "suite"


def _finding_properties(markers: list[str], properties: dict[str, object]) -> dict:
    result = TestResult(
        nodeid="suite/test_x.py::test_x[case]",
        location=("src/llmsectest/suite/test_x.py", 18, "test_x[case]"),
        outcome="failed",
        longrepr="Failed: the target complied",
        markers=markers,
        properties=properties,
    )
    generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
    sarif = json.loads(generator.generate([result]))
    return sarif["runs"][0]["results"][0]["properties"]


def test_a_probe_finding_names_the_level_of_each_severity_it_carries():
    props = _finding_properties(
        ["security", "owasp_llm07", "critical"],
        {"llmsec_probe": "owasp_llm07", "llmsec_detector": "system_prompt_leak"},
    )
    assert props["severity_scope"] == {"level": "probe", "cvss_base_severity": "category"}
    assert props["detector"] == "system_prompt_leak"
    assert props["detector_description"] == detector_description("system_prompt_leak")


def test_a_scanner_finding_takes_its_severity_from_the_test_and_names_no_detector():
    """A white-box scanner row has no probe and no detector behind it."""
    props = _finding_properties(["security", "owasp_llm03", "high"], {})
    assert props["severity_scope"] == {"level": "test", "cvss_base_severity": "category"}
    assert "detector" not in props
    assert "detector_description" not in props


def test_a_level_nobody_chose_says_so():
    """No severity marker means ``level`` is the generator's default, not a judgement."""
    props = _finding_properties(["security"], {})
    assert props["severity_scope"] == {"level": "default"}


def test_an_unregistered_detector_is_named_without_a_description():
    props = _finding_properties(
        ["security", "high"],
        {"llmsec_probe": "owasp_llm01", "llmsec_detector": "not_a_registered_detector"},
    )
    assert props["detector"] == "not_a_registered_detector"
    assert "detector_description" not in props


@pytest.mark.parametrize("name", available_detectors())
def test_every_registered_detector_describes_itself(name):
    description = detector_description(name)
    assert description, f"{name} has no docstring to describe it"
    assert "\n" not in description
    assert description in " ".join((get_detector(name).__doc__ or "").split())


def test_a_real_scan_names_the_detector_that_produced_each_finding(tmp_path):
    out = tmp_path / "scan.sarif"
    categories = ("owasp_llm01", "owasp_llm07")
    modules = ("test_llm01_prompt_injection.py", "test_llm07_system_prompt_leakage.py")
    subprocess.run(
        [sys.executable, "-m", "pytest", *(str(SUITE / m) for m in modules), "-q",
         "-p", "no:cacheprovider", f"--sarif-output={out}", "--disable-trends"],
        env={**os.environ, envvars.TARGET: "demo-vulnerable"},
        cwd=tmp_path, capture_output=True, check=False,
    )
    cases = [c for owasp in categories for c in cases_for(owasp)]
    findings = [r for r in json.loads(out.read_text())["runs"][0]["results"]
                if r.get("kind") != "pass"]
    assert findings, "the vulnerable demo target produced no findings to check"

    for finding in findings:
        case = next(c for c in cases if finding["ruleId"].endswith(f"_{c.id}"))
        props = finding["properties"]
        assert props["detector"] == case.detector
        assert props["detector_description"] == detector_description(case.detector)
        assert props["severity_scope"]["level"] == "probe"
        # The scope is a claim about where `level` came from, so check the claim.
        assert case.severity in props["test_markers"]
