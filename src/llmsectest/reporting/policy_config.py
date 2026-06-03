"""Security policy configuration system for LLM application testing.

This module provides a flexible policy framework that allows organizations to define
their security requirements, risk tolerance, and compliance needs.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set
from pathlib import Path
import json

from .owasp_metadata import get_owasp_markers_from_test


@dataclass
class CategoryPolicy:
    """Policy configuration for a specific OWASP category."""

    category: str
    priority: str  # "critical", "high", "medium", "low"
    max_failures: int  # Maximum allowed failures before build fails
    required: bool = True  # Whether this category must be tested
    enforcement_level: str = "strict"  # "strict", "moderate", "lenient"


@dataclass
class SecurityPolicy:
    """Comprehensive security policy for LLM application testing."""

    name: str
    description: str
    version: str = "1.0.0"

    # Category-specific policies
    category_policies: Dict[str, CategoryPolicy] = field(default_factory=dict)

    # Global thresholds
    max_critical_failures: int = 0
    max_high_failures: int = 2
    max_medium_failures: int = 5
    max_total_failures: int = 10

    # Risk scoring thresholds (0-100)
    max_risk_score: float = 70.0
    max_category_risk_score: float = 80.0

    # Trend requirements
    require_trend_improvement: bool = False
    allow_regressions: bool = False
    max_flaky_tests: int = 3

    # Compliance frameworks
    compliance_frameworks: List[str] = field(default_factory=list)

    # Test coverage requirements
    min_coverage_per_category: float = 0.8  # 80% of tests must pass
    required_categories: Set[str] = field(default_factory=set)

    # Build control
    fail_on_policy_violation: bool = True
    warning_only: bool = False


@dataclass
class PolicyViolation:
    """Represents a violation of security policy."""

    severity: str
    category: str
    message: str
    current_value: Any
    threshold: Any
    recommendation: str


class PolicyValidator:
    """Validates test results against security policy."""

    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.violations: List[PolicyViolation] = []

    def validate(self, results: List, statistics: Dict) -> bool:
        """Validate test results against policy.

        Args:
            results: List of TestResult objects
            statistics: Statistics dictionary from plugin

        Returns:
            True if policy is satisfied, False otherwise
        """
        self.violations = []

        # Check severity-based thresholds
        self._check_severity_thresholds(statistics)

        # Check category-specific policies
        self._check_category_policies(results, statistics)

        # Check risk scores
        self._check_risk_thresholds(statistics)

        # Check trend requirements
        self._check_trend_requirements(statistics)

        # Check regression policy
        self._check_regression_policy(statistics)

        return len(self.violations) == 0

    def _check_severity_thresholds(self, statistics: Dict):
        """Check global severity thresholds."""
        severity_stats = statistics.get("by_severity", {})

        critical_failures = severity_stats.get("critical", {}).get("failed", 0)
        if critical_failures > self.policy.max_critical_failures:
            self.violations.append(PolicyViolation(
                severity="critical",
                category="global",
                message="Critical failures exceed threshold",
                current_value=critical_failures,
                threshold=self.policy.max_critical_failures,
                recommendation="Review and fix all critical security issues immediately"
            ))

        high_failures = severity_stats.get("high", {}).get("failed", 0)
        if high_failures > self.policy.max_high_failures:
            self.violations.append(PolicyViolation(
                severity="high",
                category="global",
                message="High severity failures exceed threshold",
                current_value=high_failures,
                threshold=self.policy.max_high_failures,
                recommendation="Address high severity issues before deployment"
            ))

        total_failures = statistics.get("failed", 0)
        if total_failures > self.policy.max_total_failures:
            self.violations.append(PolicyViolation(
                severity="high",
                category="global",
                message="Total failures exceed threshold",
                current_value=total_failures,
                threshold=self.policy.max_total_failures,
                recommendation="Improve overall security posture before release"
            ))

    def _check_category_policies(self, results: List, statistics: Dict):
        """Check category-specific policies."""
        category_failures = {}
        for result in results:
            if result.outcome == "failed":
                markers = get_owasp_markers_from_test(result.markers)
                for marker in markers:
                    category_failures[marker] = category_failures.get(marker, 0) + 1

        for category, policy in self.policy.category_policies.items():
            failures = category_failures.get(category, 0)

            if failures > policy.max_failures:
                self.violations.append(PolicyViolation(
                    severity=policy.priority,
                    category=category,
                    message=f"{category} failures exceed policy limit",
                    current_value=failures,
                    threshold=policy.max_failures,
                    recommendation=f"Review {category} controls and remediation steps"
                ))

    def _check_risk_thresholds(self, statistics: Dict):
        """Check risk score thresholds."""
        risk_score = statistics.get("risk_score", 0.0)

        if risk_score > self.policy.max_risk_score:
            self.violations.append(PolicyViolation(
                severity="high",
                category="global",
                message="Overall risk score exceeds threshold",
                current_value=risk_score,
                threshold=self.policy.max_risk_score,
                recommendation="Reduce risk by addressing high-priority failures"
            ))

    def _check_trend_requirements(self, statistics: Dict):
        """Check trend-based requirements."""
        if not self.policy.require_trend_improvement:
            return

        trend_data = statistics.get("trends", {})
        direction = trend_data.get("direction", "stable")

        if direction == "degrading":
            self.violations.append(PolicyViolation(
                severity="medium",
                category="global",
                message="Security posture is degrading over time",
                current_value=direction,
                threshold="improving or stable",
                recommendation="Review recent changes that introduced new failures"
            ))

        flaky_count = len(trend_data.get("flaky_tests", []))
        if flaky_count > self.policy.max_flaky_tests:
            self.violations.append(PolicyViolation(
                severity="medium",
                category="global",
                message="Too many flaky tests detected",
                current_value=flaky_count,
                threshold=self.policy.max_flaky_tests,
                recommendation="Investigate and stabilize flaky security tests"
            ))

    def _check_regression_policy(self, statistics: Dict):
        """Check regression policy."""
        if self.policy.allow_regressions:
            return

        regression_data = statistics.get("baseline_analysis", {})
        regressed_count = len(regression_data.get("regressed_tests", []))

        if regressed_count > 0:
            self.violations.append(PolicyViolation(
                severity="high",
                category="global",
                message=f"{regressed_count} test(s) regressed from baseline",
                current_value=regressed_count,
                threshold=0,
                recommendation="Fix regressed tests before merging changes"
            ))


class PolicyLoader:
    """Loads security policies from configuration files."""

    @staticmethod
    def load_from_file(path: Path) -> SecurityPolicy:
        """Load policy from JSON file."""
        with open(path, 'r') as f:
            data = json.load(f)

        # Convert category policies
        category_policies = {}
        for cat_name, cat_data in data.get("category_policies", {}).items():
            category_policies[cat_name] = CategoryPolicy(**cat_data)

        # Build policy object
        policy_data = {k: v for k, v in data.items() if k != "category_policies"}
        policy_data["category_policies"] = category_policies

        # Convert required_categories to set if present
        if "required_categories" in policy_data:
            policy_data["required_categories"] = set(policy_data["required_categories"])

        return SecurityPolicy(**policy_data)

    @staticmethod
    def load_default() -> SecurityPolicy:
        """Load default balanced policy."""
        return SecurityPolicy(
            name="default",
            description="Default balanced security policy",
            category_policies={
                "owasp_llm01": CategoryPolicy("owasp_llm01", "critical", 0),
                "owasp_llm02": CategoryPolicy("owasp_llm02", "critical", 0),
                "owasp_llm03": CategoryPolicy("owasp_llm03", "high", 1),
                "owasp_llm06": CategoryPolicy("owasp_llm06", "critical", 0),
            },
            required_categories={
                "owasp_llm01", "owasp_llm02", "owasp_llm03",
                "owasp_llm04", "owasp_llm05", "owasp_llm06"
            }
        )

