"""Unit tests for the HTML, Markdown and JSON-summary report formats.

These three formats ship in the wheel and are advertised alongside SARIF, but until
the first coverage measurement (2026-07-29) none of them had a single test: HTML sat
at 13% line coverage, Markdown at 14%, the JSON summary at 22%, and `ReportManager`
— the component that drives all four formats — at 19%.

That mattered more than the numbers suggest, because ``ReportManager.generate_reports``
deliberately wraps every format in its own ``except Exception`` so one broken generator
cannot abort a scan. The isolation is correct, but it also means a regression in the
HTML generator produces *no HTML file and no error* — a silent hole. The tests below
therefore check the two things the blind except can hide: that each requested format is
really written, and that a failure in one format still leaves the others intact.

Assertions target the report's *content contract* (the numbers a reader acts on, the
OWASP category attribution, escaping of attacker-controlled text) rather than exact
markup, so cosmetic template edits do not produce false failures.
"""

import json

import pytest

from llmsectest.reporting.html_generator import HTMLReportGenerator
from llmsectest.reporting.json_summary_generator import JSONSummaryGenerator
from llmsectest.reporting.markdown_generator import MarkdownReportGenerator
from llmsectest.reporting.models import TestResult
from llmsectest.reporting.report_manager import ReportManager

TOOL = "llmsectest"
VERSION = "0.1.0"


def _result(name, outcome, markers=None, longrepr=None, duration=0.1):
    """A TestResult shaped the way the pytest plugin builds them."""
    return TestResult(
        nodeid=f"suite/test_probe.py::{name}",
        location=("suite/test_probe.py", 12, name),
        outcome=outcome,
        longrepr=longrepr,
        duration=duration,
        markers=markers or [],
    )


@pytest.fixture
def results():
    """A mixed run: one failure per severity band, a pass, and a skip.

    Marker names mirror the real suite (an ``owasp_llmNN`` marker plus a severity),
    so the OWASP attribution in each format is exercised rather than stubbed out.
    """
    return [
        _result("test_prompt_injection", "failed",
                ["owasp_llm01", "critical"], "AssertionError: marker leaked"),
        _result("test_secret_disclosure", "failed",
                ["owasp_llm02", "high"], "AssertionError: canary in reply"),
        _result("test_output_handling", "passed", ["owasp_llm05", "medium"]),
        _result("test_supply_chain", "skipped", ["owasp_llm03", "low"]),
    ]


class TestHTMLReport:
    """The HTML report a developer opens after a scan."""

    def test_renders_a_complete_document(self, results):
        html = HTMLReportGenerator(TOOL, VERSION).generate(results)
        assert html.startswith("<!DOCTYPE html>")
        assert html.rstrip().endswith("</html>")
        assert html.count("<body>") == 1
        assert f"{TOOL} v{VERSION}" in html

    def test_reports_the_counts_a_reader_acts_on(self, results):
        html = HTMLReportGenerator(TOOL, VERSION).generate(results)
        # 4 tests, 2 failed, 1 passed, 1 skipped — the headline numbers must appear.
        assert ">4<" in html, "total test count missing"
        assert ">2<" in html, "failure count missing"

    def test_names_the_owasp_categories_that_failed(self, results):
        html = HTMLReportGenerator(TOOL, VERSION).generate(results)
        assert "LLM01" in html
        assert "LLM02" in html

    def test_escapes_model_output_in_failure_text(self):
        """Failure text is attacker-influenced: it quotes what the model replied.

        An LLM05 probe deliberately asks a target to emit a script tag, so the reply
        embedded in the report is exactly the payload we must not let the report
        execute. This is the one place a security report could itself become the
        vulnerability it reports.
        """
        payload = "<script>alert('xss')</script>"
        html = HTMLReportGenerator(TOOL, VERSION).generate(
            [_result("test_xss", "failed", ["owasp_llm05", "high"],
                     f"AssertionError: model returned {payload}")]
        )
        assert payload not in html, "raw script tag reached the report unescaped"
        assert "&lt;script&gt;" in html

    def test_optional_sections_are_absent_when_not_supplied(self, results):
        """Trend/risk/policy sections are optional inputs, not always-on chrome."""
        html = HTMLReportGenerator(TOOL, VERSION).generate(results)
        assert "Risk Score" not in html
        # ...and a trend payload without history stays suppressed too
        html_no_history = HTMLReportGenerator(TOOL, VERSION).generate(
            results, trend_analytics={"has_history": False}
        )
        assert html_no_history.count("<body>") == 1

    def test_empty_run_still_produces_a_valid_document(self):
        """A scan that collected nothing must not emit a broken page or divide by zero."""
        html = HTMLReportGenerator(TOOL, VERSION).generate([])
        assert html.startswith("<!DOCTYPE html>")
        assert html.rstrip().endswith("</html>")


class TestMarkdownReport:
    """The Markdown report, used for CI job summaries and PR comments."""

    def test_has_a_single_title_and_tool_attribution(self, results):
        md = MarkdownReportGenerator(TOOL, VERSION).generate(results)
        assert md.lstrip().startswith("# Security Test Report")
        assert md.count("\n# ") == 0, "only one H1 belongs in a Markdown report"
        assert f"{TOOL} v{VERSION}" in md

    def test_reports_counts_and_categories(self, results):
        md = MarkdownReportGenerator(TOOL, VERSION).generate(results)
        assert "LLM01" in md
        assert "LLM02" in md
        assert "4" in md and "2" in md

    def test_failure_section_names_the_failing_tests(self, results):
        md = MarkdownReportGenerator(TOOL, VERSION).generate(results)
        assert "test_prompt_injection" in md
        assert "test_secret_disclosure" in md
        # a passing test is not a failure and must not be listed as one
        failures = md.split("Failure")[-1] if "Failure" in md else ""
        assert "test_output_handling" not in failures

    def test_empty_run_still_produces_a_report(self):
        md = MarkdownReportGenerator(TOOL, VERSION).generate([])
        assert md.lstrip().startswith("# Security Test Report")


class TestJSONSummary:
    """The JSON summary — the format another tool parses, so its shape is a contract."""

    def test_is_valid_json_with_the_documented_envelope(self, results):
        data = json.loads(JSONSummaryGenerator(TOOL, VERSION).generate(results))
        assert data["metadata"]["tool"] == TOOL
        assert data["metadata"]["version"] == VERSION
        assert data["metadata"]["report_format"] == "json-summary-v2.0"

    def test_summary_counts_match_the_results(self, results):
        data = json.loads(JSONSummaryGenerator(TOOL, VERSION).generate(results))
        summary = data["summary"]
        assert summary["total_tests"] == 4
        assert summary["failed"] == 2
        assert summary["passed"] == 1
        assert summary["skipped"] == 1
        assert summary["pass_rate"] == 25.0

    def test_generated_at_is_timezone_aware(self, results):
        """Report timestamps went UTC on 2026-07-27; a naive stamp is a regression."""
        data = json.loads(JSONSummaryGenerator(TOOL, VERSION).generate(results))
        stamp = data["metadata"]["generated_at"]
        assert stamp.endswith(("+00:00", "Z")), stamp

    def test_owasp_coverage_attributes_failures_to_categories(self, results):
        data = json.loads(JSONSummaryGenerator(TOOL, VERSION).generate(results))
        coverage = json.dumps(data["owasp_coverage"])
        assert "LLM01" in coverage
        assert "LLM02" in coverage

    def test_empty_run_is_still_parseable(self):
        data = json.loads(JSONSummaryGenerator(TOOL, VERSION).generate([]))
        assert data["summary"]["total_tests"] == 0
        assert data["summary"]["pass_rate"] == 0


class TestReportManager:
    """The component that drives all four formats and isolates their failures."""

    def test_writes_every_requested_format(self, results, tmp_path):
        manager = ReportManager(TOOL, VERSION, tmp_path, output_dir=tmp_path / "out")
        generated = manager.generate_reports(results)

        assert set(generated) == {"sarif", "html", "json", "markdown"}
        for fmt, path in generated.items():
            assert path.is_file(), f"{fmt} reported as generated but no file exists"
            assert path.stat().st_size > 0, f"{fmt} report is empty"

    def test_generates_only_the_formats_asked_for(self, results, tmp_path):
        manager = ReportManager(TOOL, VERSION, tmp_path, output_dir=tmp_path / "out")
        generated = manager.generate_reports(results, formats=["json"])

        assert set(generated) == {"json"}
        assert not (tmp_path / "out" / "pytest-results.html").exists()

    def test_custom_paths_are_honored(self, results, tmp_path):
        target = tmp_path / "nested" / "custom-name.sarif"
        manager = ReportManager(TOOL, VERSION, tmp_path, output_dir=tmp_path / "out")
        generated = manager.generate_reports(
            results, formats=["sarif"], custom_paths={"sarif": target}
        )

        assert generated["sarif"] == target
        assert target.is_file(), "custom path did not create missing parent dirs"

    def test_one_broken_format_does_not_suppress_the_others(self, results, tmp_path,
                                                            monkeypatch):
        """The deliberate per-format ``except Exception`` is the point of this test.

        It keeps a scan alive when one generator breaks — but it also means the
        failure is silent, so the contract worth pinning is: the survivors are still
        written, and the broken format is reported as *not* generated rather than as
        a file that does not exist.
        """
        manager = ReportManager(TOOL, VERSION, tmp_path, output_dir=tmp_path / "out")

        def explode(*args, **kwargs):
            raise RuntimeError("template blew up")

        monkeypatch.setattr(manager.html_generator, "generate", explode)
        generated = manager.generate_reports(results)

        assert "html" not in generated, "a format that raised was reported as generated"
        assert set(generated) == {"sarif", "json", "markdown"}
        for path in generated.values():
            assert path.is_file()

    def test_creates_the_output_directory(self, results, tmp_path):
        out = tmp_path / "does" / "not" / "exist"
        ReportManager(TOOL, VERSION, tmp_path, output_dir=out).generate_reports(
            results, formats=["markdown"]
        )
        assert out.is_dir()
