"""Test suite for running multiple security tests."""

import asyncio
from typing import Dict, List, Optional

from llmsectest.core.base import LLMAdapter, OWASPCategory, SecurityTest, TestResult


class TestSuiteResult:
    """Results from running a test suite."""

    def __init__(self, results: List[TestResult]) -> None:
        """
        Initialize test suite result.

        Args:
            results: List of individual test results
        """
        self.results = results

    @property
    def total_tests(self) -> int:
        """Total number of tests run."""
        return len(self.results)

    @property
    def passed_tests(self) -> int:
        """Number of tests that passed."""
        return sum(1 for r in self.results if r.passed)

    @property
    def failed_tests(self) -> int:
        """Number of tests that failed."""
        return sum(1 for r in self.results if not r.passed)

    @property
    def vulnerabilities_found(self) -> int:
        """Number of vulnerabilities found."""
        return sum(1 for r in self.results if r.vulnerability_found)

    def get_results_by_category(self, category: OWASPCategory) -> List[TestResult]:
        """Get results filtered by OWASP category."""
        return [r for r in self.results if r.owasp_category == category]

    def to_dict(self) -> Dict:
        """Convert results to dictionary."""
        return {
            "summary": {
                "total_tests": self.total_tests,
                "passed_tests": self.passed_tests,
                "failed_tests": self.failed_tests,
                "vulnerabilities_found": self.vulnerabilities_found,
            },
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self) -> str:
        """Convert results to JSON string."""
        import json

        return json.dumps(self.to_dict(), indent=2)

    def to_html(self, output_path: str) -> None:
        """Generate HTML report."""
        # Placeholder for future implementation
        raise NotImplementedError("HTML reporting not yet implemented")


class SecurityTestSuite:
    """Suite for running multiple security tests."""

    def __init__(self, adapter: LLMAdapter) -> None:
        """
        Initialize security test suite.

        Args:
            adapter: LLM adapter to test
        """
        self.adapter = adapter
        self.tests: List[SecurityTest] = []

    def add_test(self, test: SecurityTest) -> None:
        """Add a test to the suite."""
        self.tests.append(test)

    def add_tests(self, tests: List[SecurityTest]) -> None:
        """Add multiple tests to the suite."""
        self.tests.extend(tests)

    async def run_all_tests(
        self, categories: Optional[List[OWASPCategory]] = None
    ) -> TestSuiteResult:
        """
        Run all tests in the suite.

        Args:
            categories: Optional list of OWASP categories to filter

        Returns:
            TestSuiteResult containing all test results
        """
        tests_to_run = self.tests
        if categories:
            tests_to_run = [
                t for t in self.tests if t.get_owasp_category() in categories
            ]

        all_results: List[TestResult] = []
        for test in tests_to_run:
            results = await test.run()
            all_results.extend(results)

        return TestSuiteResult(all_results)

    async def run_parallel(
        self, categories: Optional[List[OWASPCategory]] = None
    ) -> TestSuiteResult:
        """
        Run tests in parallel.

        Args:
            categories: Optional list of OWASP categories to filter

        Returns:
            TestSuiteResult containing all test results
        """
        tests_to_run = self.tests
        if categories:
            tests_to_run = [
                t for t in self.tests if t.get_owasp_category() in categories
            ]

        # Run all tests concurrently
        test_results = await asyncio.gather(*[test.run() for test in tests_to_run])

        # Flatten results
        all_results: List[TestResult] = []
        for results in test_results:
            all_results.extend(results)

        return TestSuiteResult(all_results)
