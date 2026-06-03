"""Centralized statistics calculation for test results."""

from typing import List, Dict, Set
from collections import defaultdict
from .models import TestResult
from .owasp_metadata import get_owasp_category, get_owasp_markers_from_test, OWASP_LLM_CATEGORIES


def get_test_severity(result: TestResult) -> str:
    """Extract severity level from test markers."""
    for severity in ["critical", "high", "medium", "low", "info"]:
        if severity in result.markers:
            return severity
    return "medium"


def calculate_statistics(results: List[TestResult]) -> Dict:
    """Calculate comprehensive statistics from test results.

    Returns a unified statistics dictionary used by all report generators.
    This is the single source of truth for all statistics - generators should
    use this directly without recalculating.
    """
    total = len(results)
    passed = sum(1 for r in results if r.outcome == "passed")
    failed = sum(1 for r in results if r.outcome == "failed")
    skipped = sum(1 for r in results if r.outcome == "skipped")
    total_duration = sum(r.duration for r in results)

    stats = {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "pass_rate": round((passed / total * 100), 2) if total > 0 else 0,
        "fail_rate": round((failed / total * 100), 2) if total > 0 else 0,
        "total_duration": round(total_duration, 3),
        "owasp_categories": defaultdict(lambda: {"total": 0, "failed": 0, "passed": 0, "skipped": 0}),
        "severity_distribution": defaultdict(int),
        "by_severity": defaultdict(lambda: {"total": 0, "failed": 0, "passed": 0}),
    }

    for result in results:
        # Track OWASP category statistics
        owasp_markers = get_owasp_markers_from_test(result.markers)
        for marker in owasp_markers:
            category = get_owasp_category(marker)
            if category:
                stats["owasp_categories"][category.id]["total"] += 1
                if result.outcome == "failed":
                    stats["owasp_categories"][category.id]["failed"] += 1
                elif result.outcome == "passed":
                    stats["owasp_categories"][category.id]["passed"] += 1
                elif result.outcome == "skipped":
                    stats["owasp_categories"][category.id]["skipped"] += 1

        # Track severity distribution
        severity = get_test_severity(result)
        stats["severity_distribution"][severity] += 1
        stats["by_severity"][severity]["total"] += 1
        if result.outcome == "failed":
            stats["by_severity"][severity]["failed"] += 1
        elif result.outcome == "passed":
            stats["by_severity"][severity]["passed"] += 1

    return stats


def get_owasp_markers(results: List[TestResult]) -> Set[str]:
    """Extract all unique OWASP markers from test results.

    Useful for compliance mapping and coverage analysis.
    """
    all_markers = set()
    for result in results:
        markers = get_owasp_markers_from_test(result.markers)
        all_markers.update(markers)
    return all_markers


def get_coverage_gaps(results: List[TestResult]) -> Dict:
    """Identify OWASP LLM Top 10 categories not covered by tests.

    Returns a dictionary with tested categories, untested categories,
    and coverage percentage. Essential for identifying blind spots in
    security test suites.
    """
    tested_markers = get_owasp_markers(results)
    all_markers = set(OWASP_LLM_CATEGORIES.keys())

    untested_markers = all_markers - tested_markers
    untested = []
    for marker in sorted(untested_markers):
        cat = OWASP_LLM_CATEGORIES[marker]
        untested.append({
            "marker": marker,
            "id": cat.id,
            "name": cat.name,
            "description": cat.description,
        })

    tested = []
    for marker in sorted(tested_markers):
        cat = OWASP_LLM_CATEGORIES.get(marker)
        if cat:
            tested.append({"marker": marker, "id": cat.id, "name": cat.name})

    total = len(all_markers)
    covered = len(tested_markers & all_markers)

    return {
        "total_categories": total,
        "categories_tested": covered,
        "categories_untested": total - covered,
        "coverage_percent": round((covered / total * 100), 1) if total > 0 else 0,
        "tested": tested,
        "untested": untested,
    }
