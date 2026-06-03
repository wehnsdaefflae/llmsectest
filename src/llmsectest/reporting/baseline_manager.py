"""Baseline comparison and regression detection for security tests."""

import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from dataclasses import dataclass, field, asdict

from .models import TestResult
from .owasp_metadata import get_owasp_markers_from_test
from .statistics import get_test_severity


@dataclass
class BaselineSnapshot:
    """Snapshot of test results for baseline comparison."""

    timestamp: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    test_outcomes: Dict[str, str]  # nodeid -> outcome
    test_severities: Dict[str, str]  # nodeid -> severity
    test_owasp_categories: Dict[str, List[str]]  # nodeid -> OWASP categories
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'BaselineSnapshot':
        """Create from dictionary."""
        return cls(**data)

    @classmethod
    def from_results(cls, results: List[TestResult], metadata: Optional[Dict[str, str]] = None) -> 'BaselineSnapshot':
        """Create baseline snapshot from test results."""
        test_outcomes = {}
        test_severities = {}
        test_owasp_categories = {}

        passed = 0
        failed = 0

        for result in results:
            test_outcomes[result.nodeid] = result.outcome

            # Extract severity using centralized function
            test_severities[result.nodeid] = get_test_severity(result)

            # Extract OWASP categories
            owasp_markers = get_owasp_markers_from_test(result.markers)
            if owasp_markers:
                test_owasp_categories[result.nodeid] = owasp_markers

            if result.outcome == "passed":
                passed += 1
            elif result.outcome == "failed":
                failed += 1

        return cls(
            timestamp=datetime.now().isoformat(),
            total_tests=len(results),
            passed_tests=passed,
            failed_tests=failed,
            test_outcomes=test_outcomes,
            test_severities=test_severities,
            test_owasp_categories=test_owasp_categories,
            metadata=metadata or {}
        )


@dataclass
class RegressionAnalysis:
    """Analysis of test regressions and improvements."""

    fixed_tests: List[str] = field(default_factory=list)   # Previously failing, now passing
    regressed_tests: List[str] = field(default_factory=list)  # Previously passing, now failing
    removed_tests: List[str] = field(default_factory=list)  # Tests in baseline but not current
    added_tests: List[str] = field(default_factory=list)    # Tests in current but not baseline

    severity_impact: Dict[str, int] = field(default_factory=dict)  # severity -> regression count
    owasp_impact: Dict[str, int] = field(default_factory=dict)     # OWASP category -> regression count

    baseline_pass_rate: float = 0.0
    current_pass_rate: float = 0.0
    pass_rate_change: float = 0.0

    regression_count: int = 0
    improvement_count: int = 0

    has_regressions: bool = False
    has_improvements: bool = False

    @property
    def regression_severity(self) -> str:
        """Overall severity of regressions."""
        if "critical" in self.severity_impact and self.severity_impact["critical"] > 0:
            return "critical"
        elif "high" in self.severity_impact and self.severity_impact["high"] > 0:
            return "high"
        elif "medium" in self.severity_impact and self.severity_impact["medium"] > 0:
            return "medium"
        elif "low" in self.severity_impact and self.severity_impact["low"] > 0:
            return "low"
        return "none"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class BaselineManager:
    """Manages baseline snapshots and regression detection."""

    def __init__(self, baseline_file: Path):
        """Initialize baseline manager.

        Args:
            baseline_file: Path to baseline JSON file
        """
        self.baseline_file = Path(baseline_file)
        self._baseline: Optional[BaselineSnapshot] = None

    def save_baseline(self, results: List[TestResult], metadata: Optional[Dict[str, str]] = None) -> Path:
        """Save current test results as baseline.

        Args:
            results: List of test results
            metadata: Optional metadata to include in baseline

        Returns:
            Path to saved baseline file
        """
        snapshot = BaselineSnapshot.from_results(results, metadata)

        # Ensure directory exists
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)

        # Write baseline
        with open(self.baseline_file, 'w', encoding='utf-8') as f:
            json.dump(snapshot.to_dict(), f, indent=2)

        self._baseline = snapshot
        return self.baseline_file

    def load_baseline(self) -> Optional[BaselineSnapshot]:
        """Load baseline snapshot from file.

        Returns:
            Baseline snapshot if exists, None otherwise
        """
        if not self.baseline_file.exists():
            return None

        try:
            with open(self.baseline_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._baseline = BaselineSnapshot.from_dict(data)
            return self._baseline
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def compare_with_baseline(self, current_results: List[TestResult]) -> Optional[RegressionAnalysis]:
        """Compare current results with baseline.

        Args:
            current_results: Current test results

        Returns:
            Regression analysis if baseline exists, None otherwise
        """
        baseline = self.load_baseline()
        if not baseline:
            return None

        # Create snapshot of current results
        current = BaselineSnapshot.from_results(current_results)

        # Identify test changes
        baseline_tests = set(baseline.test_outcomes.keys())
        current_tests = set(current.test_outcomes.keys())

        removed_tests = list(baseline_tests - current_tests)
        added_tests = list(current_tests - baseline_tests)
        common_tests = baseline_tests & current_tests

        # Analyze regressions and improvements
        regressed_tests = []
        fixed_tests = []

        severity_impact: Dict[str, int] = {}
        owasp_impact: Dict[str, int] = {}

        for test_id in common_tests:
            baseline_outcome = baseline.test_outcomes[test_id]
            current_outcome = current.test_outcomes[test_id]

            # Regression: was passing, now failing
            if baseline_outcome == "passed" and current_outcome == "failed":
                regressed_tests.append(test_id)

                # Track severity impact
                severity = current.test_severities.get(test_id, "unknown")
                severity_impact[severity] = severity_impact.get(severity, 0) + 1

                # Track OWASP category impact
                owasp_cats = current.test_owasp_categories.get(test_id, [])
                for cat in owasp_cats:
                    owasp_impact[cat] = owasp_impact.get(cat, 0) + 1

            # Improvement: was failing, now passing
            elif baseline_outcome == "failed" and current_outcome == "passed":
                fixed_tests.append(test_id)

        # Calculate pass rates
        baseline_pass_rate = (baseline.passed_tests / baseline.total_tests * 100) if baseline.total_tests > 0 else 0
        current_pass_rate = (current.passed_tests / current.total_tests * 100) if current.total_tests > 0 else 0
        pass_rate_change = current_pass_rate - baseline_pass_rate

        regression_count = len(regressed_tests)
        improvement_count = len(fixed_tests)

        return RegressionAnalysis(
            fixed_tests=fixed_tests,
            regressed_tests=regressed_tests,
            removed_tests=removed_tests,
            added_tests=added_tests,
            severity_impact=severity_impact,
            owasp_impact=owasp_impact,
            baseline_pass_rate=baseline_pass_rate,
            current_pass_rate=current_pass_rate,
            pass_rate_change=pass_rate_change,
            regression_count=regression_count,
            improvement_count=improvement_count,
            has_regressions=regression_count > 0,
            has_improvements=improvement_count > 0
        )


