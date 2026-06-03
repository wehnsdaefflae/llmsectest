"""Console summary generator for CI/CD pipeline integration.

Provides clean, actionable terminal output suitable for CI/CD pipelines,
GitHub Actions, and automated security gates.
"""

from typing import Any, Dict, List, Optional

from .models import TestResult
from .statistics import calculate_statistics, get_test_severity, get_coverage_gaps
from .owasp_metadata import get_owasp_category
from .constants import SEVERITY_ORDER


# ANSI color codes for terminal output
class Colors:
    """ANSI escape codes for colored terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def _assess_security_posture(stats: Dict) -> str:
    """Assess overall security posture based on test results."""
    if stats["failed"] == 0:
        return "strong"
    critical_failed = stats["by_severity"].get("critical", {}).get("failed", 0)
    high_failed = stats["by_severity"].get("high", {}).get("failed", 0)
    if critical_failed > 0:
        return "critical"
    elif high_failed > 0:
        return "needs_attention"
    elif stats["pass_rate"] >= 80:
        return "moderate"
    return "weak"


def generate_console_summary(
    results: List[TestResult],
    risk_score: Optional[Any] = None,
    show_colors: bool = True,
    verbose: bool = False,
    trend_analytics: Optional[Dict] = None,
    baseline_analysis: Optional[Any] = None,
    policy_violations: Optional[List] = None,
    sarif_path: Optional[str] = None,
) -> str:
    """Generate a comprehensive console summary with all analytics.

    Args:
        results: List of test results
        risk_score: Optional risk score from RiskScoringEngine
        show_colors: Whether to include ANSI colors (disable for log files)
        verbose: Whether to show detailed failure information
        trend_analytics: Optional trend analytics data
        baseline_analysis: Optional baseline regression analysis
        policy_violations: Optional list of policy violations
        sarif_path: Optional path to generated SARIF file

    Returns:
        Formatted string for console output
    """
    stats = calculate_statistics(results)

    critical_high_failures = (
        stats["by_severity"].get("critical", {}).get("failed", 0) +
        stats["by_severity"].get("high", {}).get("failed", 0)
    )
    security_posture = _assess_security_posture(stats)

    # Color helpers
    c = Colors if show_colors else type('NoColor', (), {k: '' for k in dir(Colors) if not k.startswith('_')})()

    lines = []

    # Header
    lines.append("")
    lines.append(f"{c.BOLD}{'='*70}{c.RESET}")
    lines.append(f"{c.BOLD}  OWASP LLM Security Test Summary{c.RESET}")
    lines.append(f"{c.BOLD}{'='*70}{c.RESET}")
    lines.append("")

    # Quick status indicator
    if stats["failed"] == 0:
        status = f"{c.GREEN}{c.BOLD}PASSED{c.RESET}"
        status_icon = f"{c.GREEN}[OK]{c.RESET}"
    elif critical_high_failures > 0:
        status = f"{c.RED}{c.BOLD}CRITICAL{c.RESET}"
        status_icon = f"{c.RED}[!!]{c.RESET}"
    else:
        status = f"{c.YELLOW}{c.BOLD}FAILED{c.RESET}"
        status_icon = f"{c.YELLOW}[!]{c.RESET}"

    lines.append(f"  {status_icon} Security Status: {status}")
    lines.append("")

    # Summary stats
    lines.append(f"  {c.CYAN}Test Summary:{c.RESET}")
    lines.append(f"    Total:   {stats['total']}")
    lines.append(f"    Passed:  {c.GREEN}{stats['passed']}{c.RESET}")
    lines.append(f"    Failed:  {c.RED if stats['failed'] > 0 else ''}{stats['failed']}{c.RESET}")
    lines.append(f"    Skipped: {stats['skipped']}")
    lines.append(f"    Rate:    {stats['pass_rate']:.1f}%")
    lines.append("")

    # Baseline comparison
    if baseline_analysis:
        lines.append(f"  {c.CYAN}Baseline Comparison:{c.RESET}")
        lines.append(f"    Pass Rate: {baseline_analysis.baseline_pass_rate:.1f}% -> {baseline_analysis.current_pass_rate:.1f}% ({baseline_analysis.pass_rate_change:+.1f}%)")
        if baseline_analysis.has_regressions:
            lines.append(f"    {c.RED}Regressions: {baseline_analysis.regression_count} test(s) now failing{c.RESET}")
            if baseline_analysis.severity_impact:
                impacts = [f"{count} {sev}" for sev, count in sorted(baseline_analysis.severity_impact.items())]
                lines.append(f"    Impact:    {', '.join(impacts)}")
        if baseline_analysis.has_improvements:
            lines.append(f"    {c.GREEN}Fixed: {baseline_analysis.improvement_count} test(s) now passing{c.RESET}")
        if baseline_analysis.added_tests:
            lines.append(f"    New Tests: {len(baseline_analysis.added_tests)}")
        if baseline_analysis.removed_tests:
            lines.append(f"    Removed:   {len(baseline_analysis.removed_tests)}")
        lines.append("")

    # Trend analytics
    if trend_analytics and trend_analytics.get("has_history"):
        comparison = trend_analytics.get("comparison", {})
        lines.append(f"  {c.CYAN}Trend Analysis:{c.RESET}")
        lines.append(f"    Total Runs: {trend_analytics['total_runs']}")
        lines.append(f"    Trend:      {comparison.get('trend', 'unknown').upper()}")
        lines.append(f"    Pass Rate:  {comparison.get('pass_rate_change', 0):+.2f}%")
        flakiness = trend_analytics.get("flakiness", {})
        if flakiness.get("count", 0) > 0:
            lines.append(f"    {c.YELLOW}Flaky: {flakiness['count']} test(s) detected{c.RESET}")
        lines.append("")

    # Risk assessment
    if risk_score:
        risk_colors = {
            "critical": c.RED, "high": c.MAGENTA, "medium": c.YELLOW,
            "low": c.GREEN, "minimal": c.GREEN,
        }
        risk_color = risk_colors.get(risk_score.risk_level, "")
        lines.append(f"  {c.CYAN}Risk Assessment:{c.RESET}")
        lines.append(f"    Score:      {risk_color}{risk_score.overall_score:.1f}/100 ({risk_score.risk_level.upper()}){c.RESET}")
        lines.append(f"    Confidence: {risk_score.confidence * 100:.0f}%")
        top_factors = sorted(risk_score.factors.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_factors:
            for factor, value in top_factors:
                if value > 10:
                    lines.append(f"    - {factor.replace('_', ' ').title()}: {value:.1f}/100")
        if risk_score.recommendations:
            lines.append("    Recommendations:")
            for rec in risk_score.recommendations[:2]:
                lines.append(f"      * {rec}")
        lines.append("")

    # Policy compliance
    if policy_violations is not None:
        if len(policy_violations) > 0:
            lines.append(f"  {c.RED}Policy Violations: {len(policy_violations)}{c.RESET}")
            lines.append(f"    Critical: {sum(1 for v in policy_violations if v.severity == 'critical')}")
            lines.append(f"    High:     {sum(1 for v in policy_violations if v.severity == 'high')}")
            lines.append(f"    Medium:   {sum(1 for v in policy_violations if v.severity == 'medium')}")
            critical_violations = [v for v in policy_violations if v.severity == "critical"]
            if critical_violations:
                for v in critical_violations[:3]:
                    lines.append(f"    * {v.message}: {v.current_value} > {v.threshold}")
        else:
            lines.append(f"  {c.GREEN}Security Policy: COMPLIANT{c.RESET}")
        lines.append("")

    # Severity breakdown
    severity_colors = {
        "critical": c.RED, "high": c.MAGENTA, "medium": c.YELLOW,
        "low": c.BLUE, "info": "",
    }
    if stats["failed"] > 0 and stats["severity_distribution"]:
        lines.append(f"  {c.CYAN}Severity Distribution:{c.RESET}")
        for sev in SEVERITY_ORDER:
            count = stats["severity_distribution"].get(sev, 0)
            if count > 0:
                failed_count = stats["by_severity"].get(sev, {}).get("failed", 0)
                color = severity_colors[sev]
                fail_info = f" ({color}{failed_count} failed{c.RESET})" if failed_count > 0 else ""
                lines.append(f"    {sev.capitalize():12s} {count:3d}{fail_info}")
        lines.append("")

    # OWASP categories
    if stats["owasp_categories"]:
        lines.append(f"  {c.CYAN}OWASP LLM Categories:{c.RESET}")
        lines.append(f"    {'Category':<8} {'Name':<35} {'Total':>5} {'Pass':>5} {'Fail':>5}")
        lines.append("    " + "-" * 65)
        for category_id in sorted(stats["owasp_categories"].keys()):
            cat_stats = stats["owasp_categories"][category_id]
            category = get_owasp_category(f"owasp_{category_id.lower()}")
            name = category.name if category else "Unknown"
            fail_color = c.RED if cat_stats["failed"] > 0 else ""
            lines.append(
                f"    {category_id:<8} {name:<35} "
                f"{cat_stats['total']:>5} {cat_stats['passed']:>5} "
                f"{fail_color}{cat_stats['failed']:>5}{c.RESET}"
            )
        lines.append("")

    # Coverage gap analysis
    coverage = get_coverage_gaps(results)
    if coverage["categories_untested"] > 0:
        lines.append(f"  {c.CYAN}Coverage Gaps ({coverage['coverage_percent']}% of OWASP LLM Top 10):{c.RESET}")
        for gap in coverage["untested"]:
            lines.append(f"    - {gap['id']}: {gap['name']}")
    else:
        lines.append(f"  {c.GREEN}OWASP Coverage: 100% ({coverage['total_categories']}/{coverage['total_categories']} categories){c.RESET}")
    lines.append("")

    # Verbose mode: show failed test details
    if verbose and stats["failed"] > 0:
        failed_results = [r for r in results if r.outcome == "failed"]
        lines.append(f"  {c.CYAN}Failed Tests:{c.RESET}")
        for result in failed_results[:10]:
            severity = get_test_severity(result)
            sev_color = severity_colors.get(severity, "")
            lines.append(f"    {sev_color}[{severity.upper()}]{c.RESET} {result.test_name}")
            lines.append(f"           {result.file_path}:{result.line_number}")
        if len(failed_results) > 10:
            lines.append(f"    ... and {len(failed_results) - 10} more")
        lines.append("")

    # Security posture assessment
    posture_messages = {
        "strong": f"{c.GREEN}Security posture is STRONG - all tests passing{c.RESET}",
        "critical": f"{c.RED}CRITICAL issues detected - immediate action required{c.RESET}",
        "needs_attention": f"{c.YELLOW}High severity issues detected - prioritize remediation{c.RESET}",
        "moderate": f"{c.YELLOW}Some issues detected but manageable{c.RESET}",
        "weak": f"{c.RED}Multiple security failures - comprehensive review needed{c.RESET}",
    }
    lines.append(f"  {posture_messages.get(security_posture, 'Unknown posture')}")

    # SARIF report path
    if sarif_path:
        lines.append(f"  SARIF Report: {sarif_path}")

    # Footer
    lines.append(f"{c.BOLD}{'='*70}{c.RESET}")
    if stats["failed"] > 0:
        lines.append(f"  {c.RED}Exit code: 1 (failures detected){c.RESET}")
    else:
        lines.append(f"  {c.GREEN}Exit code: 0 (all tests passed){c.RESET}")
    lines.append("")

    return "\n".join(lines)


