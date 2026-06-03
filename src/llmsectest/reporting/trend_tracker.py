"""Historical trend tracking for pytest security test results."""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict

from .models import TestResult
from .statistics import calculate_statistics


class TrendTracker:
    """Tracks test result trends over time and provides analytics."""

    def __init__(self, history_file: Path):
        """
        Initialize trend tracker.

        Args:
            history_file: Path to the JSON file storing historical test data
        """
        self.history_file = history_file
        self.history_file.parent.mkdir(parents=True, exist_ok=True)

    def save_test_run(self, results: List[TestResult], metadata: Dict[str, Any] = None) -> None:
        """
        Save current test run results to history.

        Args:
            results: List of test results from current run
            metadata: Optional metadata about the test run
        """
        history = self._load_history()

        run_data = {
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {},
            "summary": self._generate_run_summary(results),
            "tests": [self._serialize_test_result(r) for r in results]
        }

        history["runs"].append(run_data)

        # Keep only last 100 runs to prevent unbounded growth
        if len(history["runs"]) > 100:
            history["runs"] = history["runs"][-100:]

        self._save_history(history)

    def get_trend_analytics(self, results: List[TestResult]) -> Dict[str, Any]:
        """
        Generate trend analytics comparing current run with historical data.

        Args:
            results: Current test results

        Returns:
            Dictionary containing trend analytics and comparisons
        """
        history = self._load_history()

        if not history["runs"]:
            return {
                "has_history": False,
                "message": "No historical data available"
            }

        current_summary = self._generate_run_summary(results)
        previous_runs = history["runs"][-10:]  # Last 10 runs for trend analysis

        analytics = {
            "has_history": True,
            "total_runs": len(history["runs"]),
            "current_run": current_summary,
            "comparison": self._compare_with_previous(current_summary, previous_runs[-1]["summary"]),
            "trends": self._calculate_trends(previous_runs),
            "flakiness": self._detect_flaky_tests(previous_runs),
            "improvement_rate": self._calculate_improvement_rate(previous_runs),
            "owasp_category_trends": self._calculate_owasp_trends(previous_runs)
        }

        return analytics

    def _load_history(self) -> Dict[str, Any]:
        """Load historical test data from file."""
        if not self.history_file.exists():
            return {"runs": [], "version": "1.0"}

        try:
            with open(self.history_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"runs": [], "version": "1.0"}

    def _save_history(self, history: Dict[str, Any]) -> None:
        """Save historical test data to file."""
        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=2)

    def _generate_run_summary(self, results: List[TestResult]) -> Dict[str, Any]:
        """Generate summary statistics for a test run using centralized statistics."""
        stats = calculate_statistics(results)

        return {
            "total_tests": stats["total"],
            "passed": stats["passed"],
            "failed": stats["failed"],
            "skipped": stats["skipped"],
            "pass_rate": stats["pass_rate"],
            "total_duration": stats["total_duration"],
            "severity_distribution": dict(stats["severity_distribution"]),
            "owasp_categories": {k: dict(v) for k, v in stats["owasp_categories"].items()}
        }

    def _serialize_test_result(self, result: TestResult) -> Dict[str, Any]:
        """Serialize a test result for storage."""
        return {
            "name": result.test_name,
            "file": result.file_path,
            "outcome": result.outcome,
            "duration": round(result.duration, 3),
            "markers": result.markers
        }

    def _compare_with_previous(self, current: Dict, previous: Dict) -> Dict[str, Any]:
        """Compare current run with previous run."""
        return {
            "pass_rate_change": round(current["pass_rate"] - previous["pass_rate"], 2),
            "failed_tests_change": current["failed"] - previous["failed"],
            "total_tests_change": current["total_tests"] - previous["total_tests"],
            "duration_change": round(current["total_duration"] - previous["total_duration"], 3),
            "trend": self._determine_trend_direction(current["pass_rate"], previous["pass_rate"])
        }

    def _determine_trend_direction(self, current_rate: float, previous_rate: float) -> str:
        """Determine if trend is improving, degrading, or stable."""
        diff = current_rate - previous_rate
        if diff > 2:
            return "improving"
        elif diff < -2:
            return "degrading"
        else:
            return "stable"

    def _calculate_trends(self, runs: List[Dict]) -> Dict[str, Any]:
        """Calculate trends over multiple runs."""
        if len(runs) < 2:
            return {"status": "insufficient_data"}

        pass_rates = [run["summary"]["pass_rate"] for run in runs]
        fail_counts = [run["summary"]["failed"] for run in runs]

        return {
            "pass_rate_trend": {
                "current": pass_rates[-1],
                "average": round(sum(pass_rates) / len(pass_rates), 2),
                "min": min(pass_rates),
                "max": max(pass_rates),
                "direction": self._calculate_linear_trend(pass_rates)
            },
            "failure_trend": {
                "current": fail_counts[-1],
                "average": round(sum(fail_counts) / len(fail_counts), 2),
                "min": min(fail_counts),
                "max": max(fail_counts)
            }
        }

    def _calculate_linear_trend(self, values: List[float]) -> str:
        """Calculate linear trend direction (simple slope-based)."""
        if len(values) < 2:
            return "stable"

        # Simple slope calculation: compare first half with second half
        mid = len(values) // 2
        first_half_avg = sum(values[:mid]) / mid if mid > 0 else 0
        second_half_avg = sum(values[mid:]) / (len(values) - mid)

        diff = second_half_avg - first_half_avg
        if diff > 5:
            return "improving"
        elif diff < -5:
            return "degrading"
        else:
            return "stable"

    def _detect_flaky_tests(self, runs: List[Dict]) -> Dict[str, Any]:
        """Detect potentially flaky tests (tests that alternate between pass/fail)."""
        if len(runs) < 3:
            return {"flaky_tests": [], "message": "Need at least 3 runs to detect flakiness"}

        # Track test outcomes across runs
        test_outcomes = defaultdict(list)

        for run in runs[-10:]:  # Last 10 runs
            for test in run["tests"]:
                test_key = f"{test['file']}::{test['name']}"
                test_outcomes[test_key].append(test["outcome"])

        # Detect flakiness: test that has both passed and failed in recent runs
        flaky_tests = []
        for test_key, outcomes in test_outcomes.items():
            if len(outcomes) >= 3:
                unique_outcomes = set(outcomes)
                if "passed" in unique_outcomes and "failed" in unique_outcomes:
                    fail_count = outcomes.count("failed")
                    total = len(outcomes)
                    flaky_tests.append({
                        "test": test_key,
                        "fail_rate": round((fail_count / total * 100), 2),
                        "recent_outcomes": outcomes[-5:]  # Last 5 outcomes
                    })

        return {
            "flaky_tests": sorted(flaky_tests, key=lambda x: x["fail_rate"], reverse=True),
            "count": len(flaky_tests)
        }


    def _calculate_improvement_rate(self, runs: List[Dict]) -> Optional[Dict[str, Any]]:
        """Calculate the rate of improvement over recent runs."""
        if len(runs) < 2:
            return None

        # Compare latest 5 runs with previous 5 runs (if available)
        recent_runs = runs[-5:]
        older_runs = runs[-10:-5] if len(runs) >= 10 else runs[:-5]

        if not older_runs:
            return None

        recent_avg_pass_rate = sum(run["summary"]["pass_rate"] for run in recent_runs) / len(recent_runs)
        older_avg_pass_rate = sum(run["summary"]["pass_rate"] for run in older_runs) / len(older_runs)

        improvement = recent_avg_pass_rate - older_avg_pass_rate

        return {
            "recent_average_pass_rate": round(recent_avg_pass_rate, 2),
            "older_average_pass_rate": round(older_avg_pass_rate, 2),
            "improvement": round(improvement, 2),
            "status": "improving" if improvement > 2 else ("degrading" if improvement < -2 else "stable")
        }

    def _calculate_owasp_trends(self, runs: List[Dict]) -> Dict[str, Any]:
        """Calculate trends for each OWASP category."""
        if len(runs) < 2:
            return {}

        # Track OWASP category pass rates over time
        owasp_trends = defaultdict(list)

        for run in runs:
            owasp_cats = run["summary"].get("owasp_categories", {})
            for cat_id, stats in owasp_cats.items():
                total = stats["total"]
                if total > 0:
                    pass_rate = round((stats["passed"] / total * 100), 2)
                    owasp_trends[cat_id].append(pass_rate)

        # Calculate trend for each category
        category_trends = {}
        for cat_id, pass_rates in owasp_trends.items():
            if len(pass_rates) >= 2:
                category_trends[cat_id] = {
                    "current": pass_rates[-1],
                    "average": round(sum(pass_rates) / len(pass_rates), 2),
                    "trend": self._calculate_linear_trend(pass_rates)
                }

        return category_trends
