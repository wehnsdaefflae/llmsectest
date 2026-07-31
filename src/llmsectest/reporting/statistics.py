"""Centralized statistics calculation for test results."""

from collections import defaultdict

from .models import TestResult
from .owasp_metadata import OWASP_LLM_CATEGORIES, get_owasp_category, get_owasp_markers_from_test


def get_test_severity(result: TestResult) -> str:
    """Extract severity level from test markers."""
    for severity in ["critical", "high", "medium", "low", "info"]:
        if severity in result.markers:
            return severity
    return "medium"


def attack_tally(results: list[TestResult]) -> dict | None:
    """Tally the attacks actually delivered to the target: withstood / found / open.

    The positive half of a scan. Without it an empty findings list is silence — the
    report of a well-defended target is byte-for-byte as empty as the report of a
    scan that attacked nothing — so a defender hardening an app cannot tell that the
    hardening worked, and a *regression* in a defense ("18 withstood" becoming "14")
    is invisible.

    Counted only over real probes, which mark themselves with ``llmsec_probe`` at
    delivery, so a coverage assertion or a static scanner is never miscounted as an
    attack the target survived. An inconclusive probe (the target exceeded
    ``--app-timeout``) is neither withstood nor a finding and gets its own column:
    counting an attack the target never answered as one it resisted is the
    flattering error, and this tool does not make it.

    Returns ``None`` when no probe was delivered (a pure static scan, or every
    category skipped) — an all-zero block would read as "nothing held" rather than
    "nothing was attacked". ``by_category`` is keyed by OWASP id and carries the
    category name, so a consumer that has no access to our metadata tables (the
    SARIF renderer reads the file, not our code) can still label the rows.
    """
    by_category: dict[str, dict] = {}
    for result in results:
        marker = result.properties.get("llmsec_probe")
        if not marker:
            continue  # not a delivered attack (coverage assertion, scanner, ...)
        category = get_owasp_category(str(marker))
        key = category.id if category else "other"
        tally = by_category.setdefault(
            key,
            {"name": category.name if category else "",
             "attempted": 0, "withstood": 0, "findings": 0, "inconclusive": 0},
        )
        tally["attempted"] += 1
        if result.outcome == "failed":
            tally["findings"] += 1
        elif result.properties.get("llmsec_inconclusive") is not None:
            tally["inconclusive"] += 1
        else:
            tally["withstood"] += 1
    if not by_category:
        return None
    totals = {
        field: sum(t[field] for t in by_category.values())
        for field in ("attempted", "withstood", "findings", "inconclusive")
    }
    return {**totals, "by_category": dict(sorted(by_category.items()))}


def calculate_statistics(results: list[TestResult]) -> dict:
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


def get_owasp_markers(results: list[TestResult]) -> set[str]:
    """Extract all unique OWASP markers from test results.

    Useful for compliance mapping and coverage analysis.
    """
    all_markers = set()
    for result in results:
        markers = get_owasp_markers_from_test(result.markers)
        all_markers.update(markers)
    return all_markers


def get_coverage_gaps(results: list[TestResult]) -> dict:
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
