"""Unit tests for test suite functionality."""

import pytest
from typing import List

from llmsectest.core.base import (
    LLMAdapter,
    LLMMessage,
    LLMResponse,
    OWASPCategory,
    SecurityTest,
    Severity,
    TestResult,
)
from llmsectest.core.suite import SecurityTestSuite, TestSuiteResult


class MockAdapter(LLMAdapter):
    """Mock LLM adapter for testing."""

    async def send_message(
        self,
        message: str,
        system_prompt: str | None = None,
        conversation_history: List[LLMMessage] | None = None,
    ) -> LLMResponse:
        """Mock send message."""
        return LLMResponse(
            content="Mock response",
            model="mock-model",
            provider="mock",
        )

    def get_provider_name(self) -> str:
        """Get provider name."""
        return "mock"

    def get_model_name(self) -> str:
        """Get model name."""
        return "mock-model"


class MockSecurityTest(SecurityTest):
    """Mock security test for testing."""

    def __init__(self, adapter: LLMAdapter, should_pass: bool = True) -> None:
        """Initialize mock test."""
        super().__init__(adapter)
        self.should_pass = should_pass

    async def run(self) -> List[TestResult]:
        """Run mock test."""
        return [
            TestResult(
                test_name="Mock Test",
                owasp_category=OWASPCategory.LLM01,
                severity=Severity.INFO,
                passed=self.should_pass,
                message="Mock test result",
            )
        ]

    def get_owasp_category(self) -> OWASPCategory:
        """Get category."""
        return OWASPCategory.LLM01

    def get_test_name(self) -> str:
        """Get test name."""
        return "Mock Test"

    def get_description(self) -> str:
        """Get description."""
        return "A mock test"


class TestTestSuiteResult:
    """Tests for TestSuiteResult class."""

    def test_empty_results(self) -> None:
        """Test suite result with no tests."""
        result = TestSuiteResult([])
        assert result.total_tests == 0
        assert result.passed_tests == 0
        assert result.failed_tests == 0
        assert result.vulnerabilities_found == 0

    def test_with_results(self) -> None:
        """Test suite result with mixed results."""
        results = [
            TestResult(
                test_name="Test 1",
                owasp_category=OWASPCategory.LLM01,
                severity=Severity.HIGH,
                passed=False,
                message="Failed",
                vulnerability_found=True,
            ),
            TestResult(
                test_name="Test 2",
                owasp_category=OWASPCategory.LLM02,
                severity=Severity.INFO,
                passed=True,
                message="Passed",
            ),
        ]
        suite_result = TestSuiteResult(results)
        assert suite_result.total_tests == 2
        assert suite_result.passed_tests == 1
        assert suite_result.failed_tests == 1
        assert suite_result.vulnerabilities_found == 1

    def test_get_results_by_category(self) -> None:
        """Test filtering results by category."""
        results = [
            TestResult(
                test_name="Test 1",
                owasp_category=OWASPCategory.LLM01,
                severity=Severity.HIGH,
                passed=True,
                message="Test",
            ),
            TestResult(
                test_name="Test 2",
                owasp_category=OWASPCategory.LLM02,
                severity=Severity.HIGH,
                passed=True,
                message="Test",
            ),
            TestResult(
                test_name="Test 3",
                owasp_category=OWASPCategory.LLM01,
                severity=Severity.HIGH,
                passed=True,
                message="Test",
            ),
        ]
        suite_result = TestSuiteResult(results)
        llm01_results = suite_result.get_results_by_category(OWASPCategory.LLM01)
        assert len(llm01_results) == 2

    def test_to_dict(self) -> None:
        """Test converting suite result to dictionary."""
        results = [
            TestResult(
                test_name="Test 1",
                owasp_category=OWASPCategory.LLM01,
                severity=Severity.HIGH,
                passed=True,
                message="Test",
            )
        ]
        suite_result = TestSuiteResult(results)
        result_dict = suite_result.to_dict()
        assert "summary" in result_dict
        assert "results" in result_dict
        assert result_dict["summary"]["total_tests"] == 1


class TestSecurityTestSuite:
    """Tests for SecurityTestSuite class."""

    @pytest.mark.asyncio
    async def test_add_and_run_test(self) -> None:
        """Test adding and running a test."""
        adapter = MockAdapter()
        suite = SecurityTestSuite(adapter)
        test = MockSecurityTest(adapter)
        suite.add_test(test)

        results = await suite.run_all_tests()
        assert results.total_tests == 1
        assert results.passed_tests == 1

    @pytest.mark.asyncio
    async def test_run_with_category_filter(self) -> None:
        """Test running tests with category filter."""
        adapter = MockAdapter()
        suite = SecurityTestSuite(adapter)
        suite.add_test(MockSecurityTest(adapter))

        results = await suite.run_all_tests(categories=[OWASPCategory.LLM01])
        assert results.total_tests == 1

        results = await suite.run_all_tests(categories=[OWASPCategory.LLM02])
        assert results.total_tests == 0
