"""Unit tests for core plugin modules.

Tests the foundational components: models, statistics, constants, and SARIF output.
These tests validate the plugin's internal logic independent of pytest hooks.
"""

import json
import pytest
from llmsectest.reporting.models import TestResult
from llmsectest.reporting.statistics import (
    calculate_statistics,
    get_test_severity,
    get_owasp_markers,
    get_coverage_gaps,
)
from llmsectest.reporting.constants import (
    SEVERITY_ORDER,
    SARIF_SEVERITY_MAP,
    SEVERITY_SCORES,
    SEVERITY_EMOJI,
    SEVERITY_COLORS_HEX,
    SEVERITY_BADGE_COLORS,
    RISK_LEVEL_EMOJI,
)
from llmsectest.reporting.sarif_generator import SARIFGenerator
from llmsectest.reporting.console_summary import generate_console_summary
from llmsectest.reporting.risk_scorer import RiskScoringEngine
from llmsectest.reporting.baseline_manager import BaselineManager, BaselineSnapshot, RegressionAnalysis
from llmsectest.reporting.policy_config import PolicyValidator, SecurityPolicy, CategoryPolicy


# =============================================================================
# TestResult Model Tests
# =============================================================================

class TestTestResultModel:
    """Tests for the TestResult dataclass."""

    def test_basic_creation(self):
        """Test creating a basic TestResult."""
        result = TestResult(
            nodeid="tests/test_example.py::test_function",
            location=("tests/test_example.py", 10, "test_function"),
            outcome="passed",
        )
        assert result.nodeid == "tests/test_example.py::test_function"
        assert result.outcome == "passed"
        assert result.file_path == "tests/test_example.py"
        assert result.line_number == 10
        assert result.test_name == "test_function"

    def test_failed_result_with_longrepr(self):
        """Test failed result includes error representation."""
        result = TestResult(
            nodeid="tests/test_example.py::test_failure",
            location=("tests/test_example.py", 20, "test_failure"),
            outcome="failed",
            longrepr="AssertionError: Expected True but got False",
        )
        assert result.outcome == "failed"
        assert "AssertionError" in result.longrepr

    def test_result_with_markers(self):
        """Test result with security markers."""
        result = TestResult(
            nodeid="tests/test_security.py::test_injection",
            location=("tests/test_security.py", 15, "test_injection"),
            outcome="passed",
            markers=["security", "owasp_llm01", "critical"],
        )
        assert "security" in result.markers
        assert "owasp_llm01" in result.markers
        assert "critical" in result.markers

    def test_result_with_docstring(self):
        """Test result with docstring in properties."""
        result = TestResult(
            nodeid="tests/test_example.py::test_documented",
            location=("tests/test_example.py", 30, "test_documented"),
            outcome="passed",
            properties={"docstring": "This test validates input sanitization."},
        )
        assert result.docstring == "This test validates input sanitization."

    def test_result_without_docstring(self):
        """Test result without docstring returns None."""
        result = TestResult(
            nodeid="tests/test_example.py::test_undocumented",
            location=("tests/test_example.py", 40, "test_undocumented"),
            outcome="passed",
        )
        assert result.docstring is None

    def test_result_duration(self):
        """Test result captures duration."""
        result = TestResult(
            nodeid="tests/test_example.py::test_slow",
            location=("tests/test_example.py", 50, "test_slow"),
            outcome="passed",
            duration=2.5,
        )
        assert result.duration == 2.5


# =============================================================================
# Statistics Module Tests
# =============================================================================

class TestGetTestSeverity:
    """Tests for severity extraction from markers."""

    def test_critical_severity(self):
        """Test critical severity extraction."""
        result = TestResult(
            nodeid="test::test_critical",
            location=("test.py", 1, "test_critical"),
            outcome="failed",
            markers=["security", "critical"],
        )
        assert get_test_severity(result) == "critical"

    def test_high_severity(self):
        """Test high severity extraction."""
        result = TestResult(
            nodeid="test::test_high",
            location=("test.py", 1, "test_high"),
            outcome="failed",
            markers=["security", "high"],
        )
        assert get_test_severity(result) == "high"

    def test_medium_severity(self):
        """Test medium severity extraction."""
        result = TestResult(
            nodeid="test::test_medium",
            location=("test.py", 1, "test_medium"),
            outcome="failed",
            markers=["security", "medium"],
        )
        assert get_test_severity(result) == "medium"

    def test_low_severity(self):
        """Test low severity extraction."""
        result = TestResult(
            nodeid="test::test_low",
            location=("test.py", 1, "test_low"),
            outcome="failed",
            markers=["security", "low"],
        )
        assert get_test_severity(result) == "low"

    def test_info_severity(self):
        """Test info severity extraction."""
        result = TestResult(
            nodeid="test::test_info",
            location=("test.py", 1, "test_info"),
            outcome="failed",
            markers=["security", "info"],
        )
        assert get_test_severity(result) == "info"

    def test_default_severity(self):
        """Test default medium severity when no marker present."""
        result = TestResult(
            nodeid="test::test_default",
            location=("test.py", 1, "test_default"),
            outcome="failed",
            markers=["security"],
        )
        assert get_test_severity(result) == "medium"

    def test_highest_severity_wins(self):
        """Test that highest severity marker is selected."""
        result = TestResult(
            nodeid="test::test_multiple",
            location=("test.py", 1, "test_multiple"),
            outcome="failed",
            markers=["low", "critical", "medium"],
        )
        # Critical comes first in SEVERITY_ORDER, so it wins
        assert get_test_severity(result) == "critical"


class TestCalculateStatistics:
    """Tests for statistics calculation."""

    @pytest.fixture
    def sample_results(self):
        """Create sample test results for statistics testing."""
        return [
            TestResult(
                nodeid="test::test_pass1",
                location=("test.py", 1, "test_pass1"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
                duration=0.1,
            ),
            TestResult(
                nodeid="test::test_pass2",
                location=("test.py", 10, "test_pass2"),
                outcome="passed",
                markers=["owasp_llm01", "high"],
                duration=0.2,
            ),
            TestResult(
                nodeid="test::test_fail1",
                location=("test.py", 20, "test_fail1"),
                outcome="failed",
                markers=["owasp_llm02", "critical"],
                duration=0.15,
            ),
            TestResult(
                nodeid="test::test_skip1",
                location=("test.py", 30, "test_skip1"),
                outcome="skipped",
                markers=["owasp_llm03", "low"],
                duration=0.0,
            ),
        ]

    def test_basic_counts(self, sample_results):
        """Test basic pass/fail/skip counts."""
        stats = calculate_statistics(sample_results)
        assert stats["total"] == 4
        assert stats["passed"] == 2
        assert stats["failed"] == 1
        assert stats["skipped"] == 1

    def test_pass_rate(self, sample_results):
        """Test pass rate calculation."""
        stats = calculate_statistics(sample_results)
        assert stats["pass_rate"] == 50.0  # 2 passed out of 4

    def test_fail_rate(self, sample_results):
        """Test fail rate calculation."""
        stats = calculate_statistics(sample_results)
        assert stats["fail_rate"] == 25.0  # 1 failed out of 4

    def test_total_duration(self, sample_results):
        """Test total duration calculation."""
        stats = calculate_statistics(sample_results)
        assert stats["total_duration"] == 0.45  # 0.1 + 0.2 + 0.15 + 0.0

    def test_severity_distribution(self, sample_results):
        """Test severity distribution counts."""
        stats = calculate_statistics(sample_results)
        assert stats["severity_distribution"]["critical"] == 2
        assert stats["severity_distribution"]["high"] == 1
        assert stats["severity_distribution"]["low"] == 1

    def test_owasp_categories(self, sample_results):
        """Test OWASP category tracking."""
        stats = calculate_statistics(sample_results)
        assert "LLM01" in stats["owasp_categories"]
        assert stats["owasp_categories"]["LLM01"]["total"] == 2
        assert stats["owasp_categories"]["LLM01"]["passed"] == 2
        assert stats["owasp_categories"]["LLM01"]["failed"] == 0

    def test_empty_results(self):
        """Test handling of empty results."""
        stats = calculate_statistics([])
        assert stats["total"] == 0
        assert stats["passed"] == 0
        assert stats["pass_rate"] == 0

    def test_all_passed(self):
        """Test statistics when all tests pass."""
        results = [
            TestResult(
                nodeid=f"test::test_pass{i}",
                location=("test.py", i, f"test_pass{i}"),
                outcome="passed",
                markers=["medium"],
            )
            for i in range(5)
        ]
        stats = calculate_statistics(results)
        assert stats["pass_rate"] == 100.0
        assert stats["failed"] == 0

    def test_all_failed(self):
        """Test statistics when all tests fail."""
        results = [
            TestResult(
                nodeid=f"test::test_fail{i}",
                location=("test.py", i, f"test_fail{i}"),
                outcome="failed",
                markers=["critical"],
            )
            for i in range(3)
        ]
        stats = calculate_statistics(results)
        assert stats["pass_rate"] == 0.0
        assert stats["failed"] == 3


class TestGetOwaspMarkers:
    """Tests for OWASP marker extraction."""

    def test_extract_owasp_markers(self):
        """Test extracting OWASP markers from results."""
        results = [
            TestResult(
                nodeid="test::test1",
                location=("test.py", 1, "test1"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
            ),
            TestResult(
                nodeid="test::test2",
                location=("test.py", 10, "test2"),
                outcome="passed",
                markers=["owasp_llm02", "high"],
            ),
            TestResult(
                nodeid="test::test3",
                location=("test.py", 20, "test3"),
                outcome="passed",
                markers=["owasp_llm01", "medium"],  # Duplicate category
            ),
        ]
        markers = get_owasp_markers(results)
        assert "owasp_llm01" in markers
        assert "owasp_llm02" in markers
        assert len(markers) == 2  # Deduplicated

    def test_no_owasp_markers(self):
        """Test results without OWASP markers."""
        results = [
            TestResult(
                nodeid="test::test1",
                location=("test.py", 1, "test1"),
                outcome="passed",
                markers=["security", "unit"],
            ),
        ]
        markers = get_owasp_markers(results)
        assert len(markers) == 0


class TestGetCoverageGaps:
    """Tests for coverage gap analysis."""

    def test_partial_coverage(self):
        """Test identifying untested OWASP categories."""
        results = [
            TestResult(
                nodeid="test::test1",
                location=("test.py", 1, "test1"),
                outcome="passed",
                markers=["owasp_llm01"],
            ),
            TestResult(
                nodeid="test::test2",
                location=("test.py", 10, "test2"),
                outcome="passed",
                markers=["owasp_llm02"],
            ),
        ]
        gaps = get_coverage_gaps(results)
        assert gaps["categories_tested"] == 2
        assert gaps["categories_untested"] == 8  # 10 total - 2 tested
        assert gaps["total_categories"] == 10

    def test_coverage_percent(self):
        """Test coverage percentage calculation."""
        results = [
            TestResult(
                nodeid=f"test::test{i}",
                location=("test.py", i, f"test{i}"),
                outcome="passed",
                markers=[f"owasp_llm{str(i).zfill(2)}"],
            )
            for i in range(1, 6)  # Test 5 categories
        ]
        gaps = get_coverage_gaps(results)
        assert gaps["coverage_percent"] == 50.0  # 5 out of 10


# =============================================================================
# Constants Module Tests
# =============================================================================

class TestConstants:
    """Tests for shared constants."""

    def test_severity_order_completeness(self):
        """Test all severity levels are defined."""
        expected = {"critical", "high", "medium", "low", "info"}
        assert set(SEVERITY_ORDER) == expected
        assert len(SEVERITY_ORDER) == 5

    def test_severity_order_precedence(self):
        """Test severity order from highest to lowest."""
        assert SEVERITY_ORDER[0] == "critical"
        assert SEVERITY_ORDER[-1] == "info"

    def test_sarif_severity_map_completeness(self):
        """Test SARIF severity mapping covers all levels."""
        for severity in SEVERITY_ORDER:
            assert severity in SARIF_SEVERITY_MAP

    def test_sarif_severity_map_values(self):
        """Test SARIF severity values are valid."""
        valid_levels = {"error", "warning", "note", "none"}
        for level in SARIF_SEVERITY_MAP.values():
            assert level in valid_levels

    def test_severity_scores_are_numeric(self):
        """Test severity scores can be parsed as floats."""
        for score in SEVERITY_SCORES.values():
            assert float(score) >= 0.0
            assert float(score) <= 10.0

    def test_severity_emoji_completeness(self):
        """Test all severities have emoji mappings."""
        for severity in SEVERITY_ORDER:
            assert severity in SEVERITY_EMOJI
            assert len(SEVERITY_EMOJI[severity]) > 0

    def test_hex_colors_are_valid(self):
        """Test hex colors are properly formatted."""
        import re
        hex_pattern = re.compile(r"^#[0-9a-fA-F]{6}$")
        for color in SEVERITY_COLORS_HEX.values():
            assert hex_pattern.match(color), f"Invalid hex color: {color}"

    def test_badge_colors_are_strings(self):
        """Test badge colors are non-empty strings."""
        for color in SEVERITY_BADGE_COLORS.values():
            assert isinstance(color, str)
            assert len(color) > 0

    def test_risk_level_emoji_completeness(self):
        """Test risk levels have emoji mappings."""
        expected_levels = {"critical", "high", "medium", "low", "minimal"}
        assert set(RISK_LEVEL_EMOJI.keys()) == expected_levels


# =============================================================================
# SARIF Output Validation Tests
# =============================================================================

class TestSARIFGeneration:
    """Tests for SARIF v2.1.0 output compliance."""

    @pytest.fixture
    def sample_results(self):
        """Create sample test results for SARIF generation."""
        return [
            TestResult(
                nodeid="tests/test_injection.py::test_basic_injection",
                location=("tests/test_injection.py", 10, "test_basic_injection"),
                outcome="failed",
                longrepr="AssertionError: LLM responded to injection",
                markers=["security", "owasp_llm01", "critical"],
                duration=0.1,
                properties={"docstring": "Test basic prompt injection defense."},
            ),
            TestResult(
                nodeid="tests/test_injection.py::test_delimiter_injection",
                location=("tests/test_injection.py", 25, "test_delimiter_injection"),
                outcome="passed",
                markers=["security", "owasp_llm01", "high"],
                duration=0.05,
            ),
            TestResult(
                nodeid="tests/test_data_leakage.py::test_pii_filter",
                location=("tests/test_data_leakage.py", 15, "test_pii_filter"),
                outcome="passed",
                markers=["security", "owasp_llm02", "critical"],
                duration=0.08,
            ),
        ]

    def test_finding_location_defaults_to_the_test_node(self, sample_results):
        """A behavioural finding (no tested-project artifact) points at the test file."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "tests/test_injection.py"
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert loc["region"]["startLine"] == 10

    def test_supply_chain_finding_points_at_the_tested_manifest(self):
        """An LLM03 finding records the tested project's manifest as an artifact uri;
        the SARIF location points there, not at the test file inside this tool."""
        result = TestResult(
            nodeid="…::test_supply_chain[LLM03-unpinned-requests]",
            location=("src/llmsectest/suite/test_llm03_supply_chain.py", 84, "test_supply_chain"),
            outcome="failed",
            longrepr="Failed: [unpinned dependency] requests (requirements.txt): ...",
            markers=["security", "owasp_llm03", "high"],
            properties={"llmsec_artifact_uri": "requirements.txt"},
        )
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate([result]))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "requirements.txt"
        # the manifest lives in the scanned repo, not under this tool's %SRCROOT%
        assert "uriBaseId" not in loc["artifactLocation"]

    def test_sarif_version(self, sample_results):
        """Verify SARIF output uses version 2.1.0."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif_json = generator.generate(sample_results)
        sarif = json.loads(sarif_json)
        assert sarif["version"] == "2.1.0"

    def test_sarif_schema_reference(self, sample_results):
        """Verify SARIF output references the official schema."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_sarif_has_single_run(self, sample_results):
        """Verify SARIF output contains exactly one run."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        assert len(sarif["runs"]) == 1

    def test_sarif_tool_info(self, sample_results):
        """Verify SARIF run contains correct tool information."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "llmsectest"
        assert tool["version"] == "0.1.0"

    def test_sarif_results_only_failures(self, sample_results):
        """Verify SARIF results only include failed tests."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        results = sarif["runs"][0]["results"]
        assert len(results) == 1  # Only the failed test
        assert results[0]["ruleId"] == "test_basic_injection"

    def test_sarif_rules_include_all_tests(self, sample_results):
        """Verify SARIF rules cover all unique tests."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "test_basic_injection" in rule_ids
        assert "test_delimiter_injection" in rule_ids
        assert "test_pii_filter" in rule_ids

    def test_sarif_severity_mapping(self, sample_results):
        """Verify severity levels map correctly to SARIF levels."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"  # critical maps to error

    def test_sarif_owasp_properties(self, sample_results):
        """Verify OWASP metadata is included in SARIF properties."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["owasp_category"] == "LLM01"

    def test_sarif_security_severity_is_cvss_base_score(self, sample_results):
        """security-severity uses the OWASP category's real CVSS v4.0 base score,
        not the flat marker-based placeholder."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        rule = rules["test_basic_injection"]  # owasp_llm01
        assert rule["properties"]["security-severity"] == "9.2"
        assert rule["properties"]["cvss_version"] == "4.0"
        assert rule["properties"]["cvss_base_severity"] == "Critical"
        assert rule["properties"]["cvss_vector"].startswith("CVSS:4.0/")

    def test_sarif_result_carries_cvss(self, sample_results):
        """Each finding carries the CVSS base score/severity/vector."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["cvss_base_score"] == 9.2
        assert result["properties"]["cvss_base_severity"] == "Critical"

    def test_sarif_compliance_frameworks(self, sample_results):
        """Verify compliance framework data is included in run properties."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        run_props = sarif["runs"][0].get("properties", {})
        assert "compliance_frameworks" in run_props
        assert run_props["compliance_frameworks"]["framework_count"] > 0

    def test_sarif_artifacts(self, sample_results):
        """Verify SARIF artifacts list test files."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        artifacts = sarif["runs"][0]["artifacts"]
        artifact_uris = {a["location"]["uri"] for a in artifacts}
        assert "tests/test_injection.py" in artifact_uris
        assert "tests/test_data_leakage.py" in artifact_uris

    def test_sarif_remediation_fixes(self, sample_results):
        """Verify failed OWASP tests include remediation steps as SARIF fixes."""
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif = json.loads(generator.generate(sample_results))
        result = sarif["runs"][0]["results"][0]
        assert "fixes" in result
        assert len(result["fixes"]) > 0


# =============================================================================
# Console Summary Tests
# =============================================================================

class TestConsoleSummary:
    """Tests for the consolidated console summary output."""

    @pytest.fixture
    def sample_results(self):
        """Create sample results for console summary testing."""
        return [
            TestResult(
                nodeid="test::test_pass",
                location=("test.py", 1, "test_pass"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
            ),
            TestResult(
                nodeid="test::test_fail",
                location=("test.py", 10, "test_fail"),
                outcome="failed",
                markers=["owasp_llm02", "high"],
                longrepr="AssertionError",
            ),
        ]

    def test_summary_contains_status(self, sample_results):
        """Test console summary includes security status."""
        output = generate_console_summary(sample_results, show_colors=False)
        assert "Security Status" in output

    def test_summary_contains_test_counts(self, sample_results):
        """Test console summary includes test counts."""
        output = generate_console_summary(sample_results, show_colors=False)
        assert "Total:   2" in output
        assert "Passed:  1" in output
        assert "Failed:  1" in output

    def test_summary_contains_owasp_categories(self, sample_results):
        """Test console summary includes OWASP category table."""
        output = generate_console_summary(sample_results, show_colors=False)
        assert "OWASP LLM Categories" in output
        assert "LLM01" in output
        assert "LLM02" in output

    def test_summary_no_colors_when_disabled(self, sample_results):
        """Test ANSI codes are absent when colors disabled."""
        output = generate_console_summary(sample_results, show_colors=False)
        assert "\033[" not in output

    def test_summary_includes_sarif_path(self, sample_results):
        """Test console summary includes SARIF path when provided."""
        output = generate_console_summary(sample_results, show_colors=False, sarif_path="results/test.sarif")
        assert "results/test.sarif" in output


# =============================================================================
# Risk Scoring Engine Tests
# =============================================================================

class TestRiskScoringEngine:
    """Tests for the risk scoring engine."""

    @pytest.fixture
    def engine(self):
        return RiskScoringEngine()

    @pytest.fixture
    def all_passing_results(self):
        return [
            TestResult(
                nodeid=f"test::test_pass{i}",
                location=("test.py", i, f"test_pass{i}"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
                duration=0.1,
            )
            for i in range(10)
        ]

    @pytest.fixture
    def mixed_results(self):
        results = []
        for i in range(5):
            results.append(TestResult(
                nodeid=f"test::test_pass{i}",
                location=("test.py", i, f"test_pass{i}"),
                outcome="passed",
                markers=["owasp_llm01", "medium"],
                duration=0.1,
            ))
        for i in range(5):
            results.append(TestResult(
                nodeid=f"test::test_fail{i}",
                location=("test.py", 10 + i, f"test_fail{i}"),
                outcome="failed",
                markers=["owasp_llm02", "critical"],
                duration=0.1,
            ))
        return results

    def test_minimal_risk_all_passing(self, engine, all_passing_results):
        """All-passing results produce minimal risk."""
        stats = calculate_statistics(all_passing_results)
        score = engine.calculate_risk(all_passing_results, stats)
        assert score.risk_level == "minimal"
        assert score.overall_score < 20

    def test_high_risk_many_failures(self, engine, mixed_results):
        """50% critical failures produce elevated risk."""
        stats = calculate_statistics(mixed_results)
        score = engine.calculate_risk(mixed_results, stats)
        assert score.overall_score > 20
        assert score.risk_level in ("medium", "high", "critical")

    def test_risk_level_thresholds(self, engine):
        """Risk level boundaries are correct."""
        assert engine._determine_risk_level(85) == "critical"
        assert engine._determine_risk_level(65) == "high"
        assert engine._determine_risk_level(45) == "medium"
        assert engine._determine_risk_level(25) == "low"
        assert engine._determine_risk_level(10) == "minimal"

    def test_confidence_increases_with_data(self, engine):
        """Confidence is higher with more data sources."""
        low = engine._calculate_confidence(5, False, False)
        high = engine._calculate_confidence(50, True, True)
        assert high > low

    def test_recommendations_generated(self, engine, mixed_results):
        """Recommendations are non-empty."""
        stats = calculate_statistics(mixed_results)
        score = engine.calculate_risk(mixed_results, stats)
        assert len(score.recommendations) > 0

    def test_category_scores_populated(self, engine, mixed_results):
        """Category scores are calculated for tested categories."""
        stats = calculate_statistics(mixed_results)
        score = engine.calculate_risk(mixed_results, stats)
        assert len(score.category_scores) > 0


# =============================================================================
# Coverage Gap Tests
# =============================================================================

class TestCoverageGaps:
    """Tests for OWASP coverage gap analysis used by --min-coverage gate."""

    def test_full_coverage(self):
        """Test 100% coverage when all 10 categories are tested."""
        results = [
            TestResult(
                nodeid=f"test::test_{i}",
                location=("test.py", i, f"test_{i}"),
                outcome="passed",
                markers=[f"owasp_llm{str(i).zfill(2)}"],
            )
            for i in range(1, 11)
        ]
        gaps = get_coverage_gaps(results)
        assert gaps["coverage_percent"] == 100.0
        assert gaps["categories_untested"] == 0

    def test_no_coverage(self):
        """Test 0% coverage when no OWASP categories are tested."""
        results = [
            TestResult(
                nodeid="test::test_plain",
                location=("test.py", 1, "test_plain"),
                outcome="passed",
                markers=["security"],
            )
        ]
        gaps = get_coverage_gaps(results)
        assert gaps["coverage_percent"] == 0.0
        assert gaps["categories_untested"] == 10

    def test_untested_categories_have_metadata(self):
        """Test that untested categories include name and ID for CI output."""
        results = [
            TestResult(
                nodeid="test::test_1",
                location=("test.py", 1, "test_1"),
                outcome="passed",
                markers=["owasp_llm01"],
            )
        ]
        gaps = get_coverage_gaps(results)
        untested = gaps["untested"]
        assert len(untested) == 9
        # Each untested entry should have metadata for display
        for entry in untested:
            assert "id" in entry
            assert "name" in entry
            assert "marker" in entry


# =============================================================================
# Baseline Manager Tests
# =============================================================================

class TestBaselineSnapshot:
    """Tests for baseline snapshot creation and serialization."""

    @pytest.fixture
    def sample_results(self):
        return [
            TestResult(
                nodeid="tests/test_a.py::test_pass",
                location=("tests/test_a.py", 1, "test_pass"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
            ),
            TestResult(
                nodeid="tests/test_a.py::test_fail",
                location=("tests/test_a.py", 10, "test_fail"),
                outcome="failed",
                markers=["owasp_llm02", "high"],
            ),
        ]

    def test_snapshot_from_results(self, sample_results):
        """Test creating snapshot from test results."""
        snapshot = BaselineSnapshot.from_results(sample_results)
        assert snapshot.total_tests == 2
        assert snapshot.passed_tests == 1
        assert snapshot.failed_tests == 1

    def test_snapshot_tracks_outcomes(self, sample_results):
        """Test snapshot records per-test outcomes."""
        snapshot = BaselineSnapshot.from_results(sample_results)
        assert snapshot.test_outcomes["tests/test_a.py::test_pass"] == "passed"
        assert snapshot.test_outcomes["tests/test_a.py::test_fail"] == "failed"

    def test_snapshot_tracks_severities(self, sample_results):
        """Test snapshot records per-test severities."""
        snapshot = BaselineSnapshot.from_results(sample_results)
        assert snapshot.test_severities["tests/test_a.py::test_pass"] == "critical"
        assert snapshot.test_severities["tests/test_a.py::test_fail"] == "high"

    def test_snapshot_roundtrip(self, sample_results):
        """Test snapshot survives serialization roundtrip."""
        snapshot = BaselineSnapshot.from_results(sample_results)
        data = snapshot.to_dict()
        restored = BaselineSnapshot.from_dict(data)
        assert restored.total_tests == snapshot.total_tests
        assert restored.test_outcomes == snapshot.test_outcomes


class TestBaselineManager:
    """Tests for baseline save/load/compare workflow."""

    @pytest.fixture
    def baseline_path(self, tmp_path):
        return tmp_path / "baseline.json"

    @pytest.fixture
    def baseline_results(self):
        return [
            TestResult(
                nodeid="test::test_a",
                location=("test.py", 1, "test_a"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
            ),
            TestResult(
                nodeid="test::test_b",
                location=("test.py", 10, "test_b"),
                outcome="passed",
                markers=["owasp_llm02", "high"],
            ),
            TestResult(
                nodeid="test::test_c",
                location=("test.py", 20, "test_c"),
                outcome="failed",
                markers=["owasp_llm03", "medium"],
            ),
        ]

    def test_save_and_load(self, baseline_path, baseline_results):
        """Test saving and loading baseline."""
        manager = BaselineManager(baseline_path)
        manager.save_baseline(baseline_results)
        loaded = manager.load_baseline()
        assert loaded is not None
        assert loaded.total_tests == 3

    def test_load_nonexistent(self, baseline_path):
        """Test loading when no baseline exists."""
        manager = BaselineManager(baseline_path)
        assert manager.load_baseline() is None

    def test_detect_regression(self, baseline_path, baseline_results):
        """Test detecting regressions when a passing test starts failing."""
        manager = BaselineManager(baseline_path)
        manager.save_baseline(baseline_results)

        # test_b regresses from passed to failed
        current = [
            TestResult(
                nodeid="test::test_a",
                location=("test.py", 1, "test_a"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
            ),
            TestResult(
                nodeid="test::test_b",
                location=("test.py", 10, "test_b"),
                outcome="failed",
                markers=["owasp_llm02", "high"],
            ),
            TestResult(
                nodeid="test::test_c",
                location=("test.py", 20, "test_c"),
                outcome="failed",
                markers=["owasp_llm03", "medium"],
            ),
        ]

        analysis = manager.compare_with_baseline(current)
        assert analysis is not None
        assert analysis.has_regressions
        assert analysis.regression_count == 1
        assert "test::test_b" in analysis.regressed_tests

    def test_detect_improvement(self, baseline_path, baseline_results):
        """Test detecting improvements when a failing test starts passing."""
        manager = BaselineManager(baseline_path)
        manager.save_baseline(baseline_results)

        # test_c improves from failed to passed
        current = [
            TestResult(
                nodeid="test::test_a",
                location=("test.py", 1, "test_a"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
            ),
            TestResult(
                nodeid="test::test_b",
                location=("test.py", 10, "test_b"),
                outcome="passed",
                markers=["owasp_llm02", "high"],
            ),
            TestResult(
                nodeid="test::test_c",
                location=("test.py", 20, "test_c"),
                outcome="passed",
                markers=["owasp_llm03", "medium"],
            ),
        ]

        analysis = manager.compare_with_baseline(current)
        assert analysis.has_improvements
        assert analysis.improvement_count == 1
        assert "test::test_c" in analysis.fixed_tests

    def test_detect_added_tests(self, baseline_path, baseline_results):
        """Test detecting newly added tests."""
        manager = BaselineManager(baseline_path)
        manager.save_baseline(baseline_results)

        current = baseline_results + [
            TestResult(
                nodeid="test::test_new",
                location=("test.py", 30, "test_new"),
                outcome="passed",
                markers=["owasp_llm04", "low"],
            ),
        ]

        analysis = manager.compare_with_baseline(current)
        assert "test::test_new" in analysis.added_tests

    def test_regression_severity_impact(self, baseline_path, baseline_results):
        """Test that regression severity is tracked."""
        manager = BaselineManager(baseline_path)
        manager.save_baseline(baseline_results)

        # Regress test_a (critical) and test_b (high)
        current = [
            TestResult(
                nodeid="test::test_a",
                location=("test.py", 1, "test_a"),
                outcome="failed",
                markers=["owasp_llm01", "critical"],
            ),
            TestResult(
                nodeid="test::test_b",
                location=("test.py", 10, "test_b"),
                outcome="failed",
                markers=["owasp_llm02", "high"],
            ),
            TestResult(
                nodeid="test::test_c",
                location=("test.py", 20, "test_c"),
                outcome="failed",
                markers=["owasp_llm03", "medium"],
            ),
        ]

        analysis = manager.compare_with_baseline(current)
        assert analysis.regression_severity == "critical"
        assert "critical" in analysis.severity_impact


class TestRegressionAnalysis:
    """Tests for RegressionAnalysis severity classification."""

    def test_regression_severity_critical(self):
        """Critical regressions produce critical severity."""
        analysis = RegressionAnalysis(severity_impact={"critical": 1})
        assert analysis.regression_severity == "critical"

    def test_regression_severity_none(self):
        """No regressions produce none severity."""
        analysis = RegressionAnalysis()
        assert analysis.regression_severity == "none"

    def test_to_dict(self):
        """RegressionAnalysis serializes to dict."""
        analysis = RegressionAnalysis(
            regressed_tests=["test::a"],
            regression_count=1,
            has_regressions=True,
        )
        d = analysis.to_dict()
        assert d["regression_count"] == 1
        assert d["has_regressions"] is True


# =============================================================================
# Policy Validator Tests
# =============================================================================

class TestPolicyValidator:
    """Tests for security policy validation."""

    @pytest.fixture
    def strict_policy(self):
        return SecurityPolicy(
            name="strict",
            description="Strict security policy",
            max_critical_failures=0,
            max_high_failures=0,
            max_total_failures=2,
            max_risk_score=30.0,
            category_policies={
                "owasp_llm01": CategoryPolicy("owasp_llm01", "critical", max_failures=0),
            },
        )

    @pytest.fixture
    def lenient_policy(self):
        return SecurityPolicy(
            name="lenient",
            description="Lenient security policy",
            max_critical_failures=5,
            max_high_failures=10,
            max_total_failures=50,
        )

    def test_all_passing_is_compliant(self, strict_policy):
        """All-passing results comply with any policy."""
        results = [
            TestResult(
                nodeid=f"test::test_{i}",
                location=("test.py", i, f"test_{i}"),
                outcome="passed",
                markers=["owasp_llm01", "critical"],
            )
            for i in range(5)
        ]
        stats = calculate_statistics(results)
        validator = PolicyValidator(strict_policy)
        assert validator.validate(results, stats) is True
        assert len(validator.violations) == 0

    def test_critical_failure_violates_strict(self, strict_policy):
        """Critical failures violate strict policy."""
        results = [
            TestResult(
                nodeid="test::test_fail",
                location=("test.py", 1, "test_fail"),
                outcome="failed",
                markers=["owasp_llm01", "critical"],
            ),
        ]
        stats = calculate_statistics(results)
        validator = PolicyValidator(strict_policy)
        assert validator.validate(results, stats) is False
        assert len(validator.violations) > 0

    def test_critical_failure_passes_lenient(self, lenient_policy):
        """A few critical failures pass lenient policy."""
        results = [
            TestResult(
                nodeid="test::test_fail",
                location=("test.py", 1, "test_fail"),
                outcome="failed",
                markers=["critical"],
            ),
        ]
        stats = calculate_statistics(results)
        validator = PolicyValidator(lenient_policy)
        assert validator.validate(results, stats) is True

    def test_category_policy_violation(self, strict_policy):
        """Category-specific failure limits are enforced."""
        results = [
            TestResult(
                nodeid="test::test_fail",
                location=("test.py", 1, "test_fail"),
                outcome="failed",
                markers=["owasp_llm01", "medium"],
            ),
        ]
        stats = calculate_statistics(results)
        validator = PolicyValidator(strict_policy)
        validator.validate(results, stats)
        category_violations = [v for v in validator.violations if v.category == "owasp_llm01"]
        assert len(category_violations) > 0

    def test_total_failure_threshold(self):
        """Total failure count threshold is enforced."""
        policy = SecurityPolicy(
            name="test",
            description="Test policy",
            max_critical_failures=100,
            max_high_failures=100,
            max_total_failures=2,
        )
        results = [
            TestResult(
                nodeid=f"test::test_fail_{i}",
                location=("test.py", i, f"test_fail_{i}"),
                outcome="failed",
                markers=["low"],
            )
            for i in range(5)
        ]
        stats = calculate_statistics(results)
        validator = PolicyValidator(policy)
        assert validator.validate(results, stats) is False
        total_violations = [v for v in validator.violations if "Total failures" in v.message]
        assert len(total_violations) == 1

    def test_risk_score_threshold(self):
        """Risk score threshold is checked when present in stats."""
        policy = SecurityPolicy(
            name="test",
            description="Test policy",
            max_risk_score=10.0,
        )
        results = [
            TestResult(
                nodeid="test::test_pass",
                location=("test.py", 1, "test_pass"),
                outcome="passed",
                markers=["medium"],
            ),
        ]
        stats = calculate_statistics(results)
        stats["risk_score"] = 50.0  # Above threshold
        validator = PolicyValidator(policy)
        assert validator.validate(results, stats) is False
        risk_violations = [v for v in validator.violations if "risk score" in v.message]
        assert len(risk_violations) == 1


# =============================================================================
# SARIF Validation Utility Tests
# =============================================================================

class TestSARIFValidation:
    """Tests for the SARIF file validation utility."""

    def test_valid_sarif_file(self, tmp_path):
        """Test validation passes for correctly generated SARIF."""
        from llmsectest.reporting import validate_sarif
        results = [
            TestResult(
                nodeid="tests/test_a.py::test_pass",
                location=("tests/test_a.py", 10, "test_pass"),
                outcome="passed",
                markers=["security", "owasp_llm01", "critical"],
            ),
        ]
        generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
        sarif_file = tmp_path / "test.sarif"
        sarif_file.write_text(generator.generate(results))
        assert validate_sarif(str(sarif_file)) is True

    def test_invalid_json(self, tmp_path):
        """Test validation rejects invalid JSON."""
        from llmsectest.reporting import validate_sarif
        bad_file = tmp_path / "bad.sarif"
        bad_file.write_text("not json")
        assert validate_sarif(str(bad_file)) is False

    def test_wrong_version(self, tmp_path):
        """Test validation rejects wrong SARIF version."""
        from llmsectest.reporting import validate_sarif
        sarif_file = tmp_path / "wrong.sarif"
        sarif_file.write_text('{"version": "1.0", "runs": []}')
        assert validate_sarif(str(sarif_file)) is False

    def test_missing_runs(self, tmp_path):
        """Test validation rejects SARIF with no runs."""
        from llmsectest.reporting import validate_sarif
        sarif_file = tmp_path / "empty.sarif"
        sarif_file.write_text('{"version": "2.1.0", "runs": []}')
        assert validate_sarif(str(sarif_file)) is False

    def test_nonexistent_file(self):
        """Test validation handles missing files gracefully."""
        from llmsectest.reporting import validate_sarif
        assert validate_sarif("/nonexistent/path.sarif") is False
