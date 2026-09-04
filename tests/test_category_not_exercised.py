"""A category nothing was put to must not render as a category that passed.

The defect, found 2026-09-04 while capturing a real scan for the quickstart page. Every
run collects ``suite/test_owasp_coverage.py``, which emits one test per OWASP category
asserting that *the tool* ships a tester for it. That test wears the category's own OWASP
marker so the map stays visible per category, and it passes on every run, including one
that never reached the application. Three surfaces read those results as results about
the target:

* the console table printed ``LLM02  Sensitive Information Disclosure  1  1  0`` on an
  app scan where no LLM02 probe had been sent, one test and one pass and no failures;
* ``get_coverage_gaps`` could not return anything but 100%, because every category always
  had at least one result, so one console run printed *OWASP Coverage: 100% (10/10)*
  above a footer saying four of ten were exercised, while ``--min-coverage`` gated on a
  number that was structurally constant;
* the HTML card took the green border and the markdown table the ✅.

This is the project's own recurring defect, "the unexamined treated as the fine", in the
report layer: the difference between *we did not ask* and *we asked and nothing got
through* had no representation at all. The third state exists now and is loud.

Both directions are pinned below, because a fix that hides the category instead of
labelling it trades a false pass for a silent gap.
"""

from __future__ import annotations

from llmsectest.reporting.console_summary import generate_console_summary
from llmsectest.reporting.html_generator import HTMLReportGenerator
from llmsectest.reporting.markdown_generator import MarkdownReportGenerator
from llmsectest.reporting.models import TestResult
from llmsectest.reporting.statistics import (
    COVERAGE_MAP_MARKER,
    calculate_statistics,
    exercised_categories,
    get_coverage_gaps,
)


def _coverage_map_result(marker: str) -> TestResult:
    """What ``test_owasp_category_implemented`` contributes for one category."""
    return TestResult(
        nodeid=f"suite/test_owasp_coverage.py::test_owasp_category_implemented[{marker}]",
        location=("suite/test_owasp_coverage.py", 1, "test_owasp_category_implemented"),
        outcome="passed",
        markers=["security", COVERAGE_MAP_MARKER, marker],
    )


def _probe_result(marker: str, outcome: str = "passed") -> TestResult:
    return TestResult(
        nodeid=f"suite/test_x.py::test_probe[{marker}]",
        location=("suite/test_x.py", 1, "test_probe"),
        outcome=outcome,
        markers=["security", marker],
        properties={"llmsec_probe": marker},
    )


def _skipped_result(marker: str) -> TestResult:
    return TestResult(
        nodeid=f"suite/test_x.py::test_probe[{marker}]",
        location=("suite/test_x.py", 1, "test_probe"),
        outcome="skipped",
        markers=["security", marker],
    )


ALL_MARKERS = [f"owasp_llm{n:02d}" for n in range(1, 11)]

TOOL, VERSION = "llmsectest", "0.0.0-test"


def _one_probed_category() -> list[TestResult]:
    """A realistic app scan: the full coverage map, probes for LLM01 only, LLM02 skipped."""
    results = [_coverage_map_result(m) for m in ALL_MARKERS]
    results.append(_probe_result("owasp_llm01"))
    results.append(_probe_result("owasp_llm01", outcome="failed"))
    results.append(_skipped_result("owasp_llm02"))
    return results


# --- the measurement -------------------------------------------------------------

def test_coverage_map_assertion_is_not_coverage():
    exercised = exercised_categories(_one_probed_category())
    assert exercised == {"owasp_llm01"}


def test_a_skip_is_not_coverage():
    """A category reporting the flag it needs has not been exercised by saying so."""
    assert exercised_categories([_skipped_result("owasp_llm02")]) == set()


def test_coverage_gaps_report_the_run_rather_than_the_tool():
    gaps = get_coverage_gaps(_one_probed_category())
    assert gaps["categories_tested"] == 1
    assert gaps["categories_untested"] == 9
    assert gaps["coverage_percent"] == 10.0
    assert {g["id"] for g in gaps["untested"]} >= {"LLM02", "LLM03"}


def test_coverage_of_a_run_that_exercised_everything_is_still_reachable():
    """The other direction: the honest 100% must remain expressible."""
    results = [_coverage_map_result(m) for m in ALL_MARKERS]
    results += [_probe_result(m) for m in ALL_MARKERS]
    gaps = get_coverage_gaps(results)
    assert gaps["categories_untested"] == 0
    assert gaps["coverage_percent"] == 100.0


def test_category_counts_exclude_the_coverage_assertion():
    stats = calculate_statistics(_one_probed_category())
    llm01 = stats["owasp_categories"]["LLM01"]
    assert (llm01["total"], llm01["passed"], llm01["failed"]) == (2, 1, 1)
    assert llm01["exercised"] is True

    llm02 = stats["owasp_categories"]["LLM02"]
    assert llm02["exercised"] is False
    assert llm02["passed"] == 0


# --- the three surfaces ----------------------------------------------------------

def test_console_says_not_exercised_and_keeps_the_row():
    out = generate_console_summary(_one_probed_category())
    llm02_line = next(line for line in out.splitlines() if "LLM02" in line)
    assert "not exercised" in llm02_line
    # The row is still there, so nothing goes missing.
    assert "Sensitive Information Disclosure" in llm02_line
    assert "Coverage this run: 1/10" in out


def test_console_never_claims_a_coverage_percent_the_run_did_not_earn():
    out = generate_console_summary(_one_probed_category())
    assert "100%" not in out


def test_markdown_marks_the_row_rather_than_ticking_it():
    md = MarkdownReportGenerator(TOOL, VERSION).generate(_one_probed_category())
    llm02_row = next(line for line in md.splitlines() if line.startswith("| LLM02 "))
    assert "Not exercised" in llm02_row
    assert "✅" not in llm02_row
    llm01_row = next(line for line in md.splitlines() if line.startswith("| LLM01 "))
    assert "❌ Fail" in llm01_row


def test_html_card_is_neither_green_nor_a_pass():
    html = HTMLReportGenerator(TOOL, VERSION).generate(_one_probed_category())
    assert "owasp-not-exercised" in html
    assert "not exercised this run" in html


def test_the_compliance_claim_counts_only_what_the_run_exercised():
    """The worst instance of the same defect, because this one is a compliance claim.

    `frameworks_covered` and `owasp_mapped` were built from every OWASP marker in the result
    set, which the coverage-map assertion makes all ten on every run. A scan that exercised
    four categories published six named frameworks and `owasp_mapped: 10` into its SARIF,
    which is the one figure in that file somebody might paste into an audit.
    """
    import json

    from llmsectest.reporting.sarif_generator import SARIFGenerator

    sarif = json.loads(SARIFGenerator(TOOL, VERSION, source_root=".").generate(_one_probed_category()))
    props = sarif["runs"][0]["properties"]["compliance_frameworks"]
    mapped = {v["owasp_mapped"] for v in props["framework_summary"].values()}
    assert mapped == {1}, props


def test_a_run_that_exercised_nothing_claims_no_framework_coverage():
    """The other direction, and the one that matters: a scan that reached nothing must not
    publish a compliance block at all."""
    import json

    from llmsectest.reporting.sarif_generator import SARIFGenerator

    only_the_map = [_coverage_map_result(m) for m in ALL_MARKERS]
    sarif = json.loads(SARIFGenerator(TOOL, VERSION, source_root=".").generate(only_the_map))
    assert "compliance_frameworks" not in sarif["runs"][0].get("properties", {})


def test_the_severity_block_does_not_count_the_coverage_assertions():
    """Found by the fresh-context pass, 2026-09-04, in the transcript of the fix itself.

    The coverage-map assertions carry no severity marker, so `get_test_severity` defaults
    them to medium, and ten of the fourteen Medium rows in the captured app scan were the
    tool asserting things about itself. A severity distribution is read as a property of
    the target.
    """
    stats = calculate_statistics(_one_probed_category())
    assert sum(stats["severity_distribution"].values()) == 3  # two probes plus one skip


def test_the_json_summary_says_whether_a_category_was_exercised():
    """A consumer reading `passed: 0, failed: 0` cannot tell the two states apart."""
    import json as _json

    from llmsectest.reporting.json_summary_generator import JSONSummaryGenerator
    out = _json.loads(JSONSummaryGenerator(TOOL, VERSION).generate(_one_probed_category()))
    cov = out["owasp_coverage"]
    assert cov["LLM01"]["exercised"] is True
    assert cov["LLM02"]["exercised"] is False


def test_a_voided_probe_is_not_a_pass_in_the_category_row():
    """Found 2026-09-04 while scanning an application through the new shape flags. The
    attacks block said `Voided: 4` with its reason, and the per-category table said
    `LLM02  4  4  0`. Two accounts of the same four probes in one report, and the one a
    reader meets first was the flattering one."""
    results = [_coverage_map_result(m) for m in ALL_MARKERS]
    for _ in range(4):
        r = _probe_result("owasp_llm02")
        r.properties["llmsec_secret_configured"] = "x"
        results.append(r)
    leak = _probe_result("owasp_llm07")
    leak.properties["llmsec_secret_exposed"] = "the reply carried the value"
    results.append(leak)

    stats = calculate_statistics(results)
    llm02 = stats["owasp_categories"]["LLM02"]
    assert llm02["voided"] == 4, stats["owasp_categories"]

    out = generate_console_summary(results)
    row = next(line for line in out.splitlines() if "LLM02" in line and "Sensitive" in line)
    assert "4 voided" in row, row
    assert "voided: survived a run that lost the secret" in out
