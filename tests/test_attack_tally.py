"""Unit tests for the run-level "attacks withstood" tally.

A scan that finds nothing has always produced an empty report, which is the same
report a scan that attacked nothing produces. That is the gap this tally closes: it
records what was actually *delivered* to the target and how much of it held, so a
defender who hardened an app can see the hardening work, and so a regression in a
defense is legible as a number going down.

The tests pin the three things that make the number trustworthy rather than
flattering: only real probes are counted (a coverage assertion or a static scanner
never inflates it), an unanswered attack is never counted as one the target
resisted, and the figure travels all the way to the surfaces a reader looks at (the
SARIF run properties, the rendered HTML page, the console summary).
"""

from __future__ import annotations

import json

from llmsectest.reporting.console_summary import generate_console_summary
from llmsectest.reporting.models import TestResult
from llmsectest.reporting.sarif_generator import SARIFGenerator
from llmsectest.reporting.sarif_html import render_sarif_html
from llmsectest.reporting.statistics import attack_tally


def _probe(name, outcome, marker, *, inconclusive=None):
    """A probe result as the suite records it: marked with ``llmsec_probe``."""
    properties = {"llmsec_probe": marker}
    if inconclusive is not None:
        properties["llmsec_inconclusive"] = inconclusive
    return TestResult(
        nodeid=f"suite/test_probe.py::{name}",
        location=("suite/test_probe.py", 12, name),
        outcome=outcome,
        markers=[marker, "high"],
        properties=properties,
    )


def _non_probe(name, outcome, marker):
    """A result that carries an OWASP marker but delivered no attack.

    The coverage-footer assertions and the static scanners look exactly like this.
    """
    return TestResult(
        nodeid=f"suite/test_owasp_coverage.py::{name}",
        location=("suite/test_owasp_coverage.py", 5, name),
        outcome=outcome,
        markers=[marker, "security"],
        properties={},
    )


def test_counts_passes_as_withstood_and_failures_as_findings():
    tally = attack_tally([
        _probe("injection", "passed", "owasp_llm01"),
        _probe("leak", "passed", "owasp_llm02"),
        _probe("poisoned_doc", "failed", "owasp_llm08"),
    ])
    assert tally["attempted"] == 3
    assert tally["withstood"] == 2
    assert tally["findings"] == 1
    assert tally["inconclusive"] == 0
    assert tally["by_category"]["LLM08"]["findings"] == 1
    assert tally["by_category"]["LLM01"]["withstood"] == 1


def test_an_unanswered_attack_is_not_counted_as_withstood():
    """A timed-out probe is evidence of nothing and must not flatter the target."""
    tally = attack_tally([
        _probe("injection", "passed", "owasp_llm01"),
        _probe("flood", "passed", "owasp_llm10",
               inconclusive="target exceeded the 90s per-request budget"),
    ])
    assert tally["attempted"] == 2
    assert tally["withstood"] == 1
    assert tally["inconclusive"] == 1
    assert tally["by_category"]["LLM10"]["withstood"] == 0


def test_coverage_assertions_and_scanners_never_inflate_the_count():
    """Only results the probe path marked at delivery are attacks."""
    tally = attack_tally([
        _probe("injection", "passed", "owasp_llm01"),
        _non_probe("test_owasp_category_implemented[LLM03]", "passed", "owasp_llm03"),
        _non_probe("test_owasp_category_implemented[LLM04]", "skipped", "owasp_llm04"),
    ])
    assert tally["attempted"] == 1
    assert set(tally["by_category"]) == {"LLM01"}


def test_a_run_with_no_delivered_attack_reports_nothing_rather_than_zero():
    """All-zero would read as "nothing held"; the honest answer is "not measured"."""
    assert attack_tally([
        _non_probe("test_owasp_category_implemented[LLM03]", "passed", "owasp_llm03"),
    ]) is None
    assert attack_tally([]) is None


def test_by_category_is_ordered_and_carries_the_category_name():
    """The SARIF renderer reads the file, not our metadata tables, so the name ships."""
    tally = attack_tally([
        _probe("flood", "passed", "owasp_llm10"),
        _probe("injection", "passed", "owasp_llm01"),
    ])
    assert list(tally["by_category"]) == ["LLM01", "LLM10"]
    assert tally["by_category"]["LLM01"]["name"]


def test_sarif_carries_the_tally_as_a_run_level_property(tmp_path):
    sarif = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", tmp_path).generate([
            _probe("injection", "passed", "owasp_llm01"),
            _probe("poisoned_doc", "failed", "owasp_llm08"),
        ])
    )
    props = sarif["runs"][0]["properties"]["attacks_withstood"]
    assert props["attempted"] == 2
    assert props["withstood"] == 1
    assert props["by_category"]["LLM08"]["findings"] == 1


def test_a_static_only_scan_omits_the_property_entirely(tmp_path):
    """No probe delivered → no claim made. An absent key beats a misleading zero."""
    sarif = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", tmp_path).generate([
            _non_probe("test_owasp_category_implemented[LLM03]", "passed", "owasp_llm03"),
        ])
    )
    assert "attacks_withstood" not in sarif["runs"][0].get("properties", {})


def test_clean_report_html_states_what_was_withstood(tmp_path):
    """The empty-report page must be evidence, not silence."""
    doc = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", tmp_path).generate([
            _probe("injection", "passed", "owasp_llm01"),
            _probe("poisoned_doc", "passed", "owasp_llm08"),
        ])
    )
    page = render_sarif_html(doc, source_name="defended-app")
    assert "2/2 attacks withstood" in page
    assert "withstood 2 of 2 delivered attacks" in page
    assert "LLM08" in page  # the per-category breakdown, not just a total


def test_html_of_a_third_party_report_without_the_tally_still_renders():
    """Any other tool's SARIF has no such property; the section simply disappears."""
    page = render_sarif_html({"runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": []}]})
    assert "attacks withstood" not in page
    assert "the scan was clean" in page


def test_console_summary_reports_delivered_attacks_separately_from_tests():
    text = generate_console_summary(
        [
            _probe("injection", "passed", "owasp_llm01"),
            _probe("flood", "passed", "owasp_llm10", inconclusive="timed out"),
            _non_probe("test_owasp_category_implemented[LLM03]", "passed", "owasp_llm03"),
        ],
        show_colors=False,
    )
    assert "Attacks Delivered:" in text
    assert "Total:     2" in text  # the coverage assertion is not an attack
    assert "Withstood: 1" in text
    assert "Inconclusive: 1" in text
