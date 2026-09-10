"""Console summary generator for CI/CD pipeline integration.

Provides clean, actionable terminal output suitable for CI/CD pipelines,
GitHub Actions, and automated security gates.
"""

from typing import Any

from .constants import SEVERITY_ORDER
from .models import TestResult
from .owasp_metadata import get_owasp_category
from .statistics import (
    attack_tally,
    calculate_statistics,
    get_coverage_gaps,
    get_test_severity,
)


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


def _assess_security_posture(stats: dict, unanswered: int = 0) -> str:
    """Assess overall security posture based on test results.

    ``unanswered`` is the number of probes that came back without an answer, a timeout
    as much as a transport failure. It can only ever *remove* the clean verdict, never
    add one: a run that lost probes has not shown the application is strong, it has
    failed to ask. Before 2026-08-26 this function saw only ``stats["failed"]``, so a
    scan where every probe timed out printed *posture is STRONG, all tests passing*
    directly above the banner saying the results do not describe the target.

    **That fix named the timeout case and counted a different one (found 2026-09-03).**
    The caller passed the *undelivered* count, which is the transport-failure subset, and
    a timeout does not set that property. So the exact scan the docstring describes, every
    probe timing out against a target that answers nothing, went on printing STRONG for
    another eight days. The parameter is the superset now, and it is named for what it
    measures rather than for the branch that first needed it.
    """
    if stats["failed"] == 0:
        return "incomplete" if unanswered else "strong"
    critical_failed = stats["by_severity"].get("critical", {}).get("failed", 0)
    high_failed = stats["by_severity"].get("high", {}).get("failed", 0)
    if critical_failed > 0:
        return "critical"
    elif high_failed > 0:
        return "needs_attention"
    elif stats["pass_rate"] >= 80:
        return "moderate"
    return "weak"


def _slowest_probe(results: list[TestResult]) -> tuple[float, str] | None:
    """The slowest *answered* probe of a run as ``(seconds, probe id)``, else ``None``.

    Reads the per-probe ``llmsec_elapsed``/``llmsec_case`` properties the probe fixture
    records, rather than the run-level ``latency`` SARIF property, so the console line is
    available before any report is written. Anything non-numeric is skipped for the same
    reason the generator skips it: these arrive from recorded properties and a summary
    that raises while printing is worse than one missing a line.

    A probe that was cut off at the ``--app-timeout`` deadline is skipped, and that is the
    whole point of the line. It would otherwise always be the maximum, so the peak would
    read as the budget on every run that lost a probe and tell you nothing about how much
    room the answered ones had. The count of those probes is already printed above, on the
    ``Inconclusive`` line.
    """
    timed = [
        (secs, str(r.properties.get("llmsec_case", "")))
        for r in results
        if isinstance(secs := r.properties.get("llmsec_elapsed"), (int, float))
        and not isinstance(secs, bool) and secs >= 0
        and r.properties.get("llmsec_inconclusive") is None
    ]
    return max(timed) if timed else None


def generate_console_summary(
    results: list[TestResult],
    risk_score: Any | None = None,
    show_colors: bool = True,
    verbose: bool = False,
    trend_analytics: dict | None = None,
    baseline_analysis: Any | None = None,
    policy_violations: list | None = None,
    sarif_path: str | None = None,
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
    # Probes that came back without an answer, and the transport-failure subset of them.
    # The headline, the posture and the closing line all read the superset: a timed-out
    # probe is exactly as unanswered as one that never left, and only the exit code
    # distinguishes them (see the footer below). The plugin already refuses to exit 0 on
    # the subset and prints a SCAN INCOMPLETE banner; this block used to contradict both,
    # three lines at a time, because it read only the failure count (2026-08-26).
    undelivered = sum(
        1 for r in results if r.properties.get("llmsec_undelivered") is not None
    )
    unanswered = sum(
        1 for r in results if r.properties.get("llmsec_inconclusive") is not None
    )
    # Whether *nothing* came back. The plugin fails a run on this (a scan of nothing is
    # not a pass, whatever lost the probes), so the closing line has to know about it too:
    # printing "Exit code: 0" beside a process that exits 1 is the same falsehood as the
    # one removed on 2026-08-26, and it is the only line in this output a reader can check
    # against reality without re-running the scan.
    probes = sum(1 for r in results if r.properties.get("llmsec_probe"))
    nothing_answered = bool(probes) and unanswered >= probes
    security_posture = _assess_security_posture(stats, unanswered)

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
    if stats["failed"] == 0 and unanswered:
        # Not PASSED and not FAILED: we did not get an answer, so we have no verdict to
        # give. The third state is the whole honesty guarantee, and the headline is where
        # a reader looks first.
        status = f"{c.YELLOW}{c.BOLD}INCOMPLETE{c.RESET}"
        status_icon = f"{c.YELLOW}[?]{c.RESET}"
    elif stats["failed"] == 0:
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

    # Attacks actually delivered to the target, as opposed to tests executed (which
    # also counts coverage assertions and static scanners). This is the line a
    # defender reads: a clean run says how much it withstood, not merely that
    # nothing was found.
    attacks = attack_tally(results)
    if attacks:
        lines.append(f"  {c.CYAN}Attacks Delivered:{c.RESET}")
        lines.append(f"    Total:     {attacks['attempted']}")
        lines.append(f"    Withstood: {c.GREEN}{attacks['withstood']}{c.RESET}")
        lines.append(f"    Findings:  {c.RED if attacks['findings'] else ''}{attacks['findings']}{c.RESET}")
        if attacks.get("voided"):
            # Printed with its reason, never as a bare number: a column of withstands
            # that turned into zeroes without explanation reads as a broken scan.
            lines.append(
                f"    {c.RED}Voided:    {attacks['voided']}{c.RESET} "
                f"({attacks.get('voided_reason', '')})"
            )
        for cat, reason in sorted((attacks.get("unconfirmed_markers") or {}).items()):
            # Printed per category and with the flag named, because the action a reader
            # can take is to go and check that one string. A bare "unconfirmed" would
            # only tell them to distrust the row.
            lines.append(f"    {c.YELLOW}Unconfirmed: {cat}, {reason}{c.RESET}")
        for cat, tally in sorted((attacks.get("by_category") or {}).items()):
            # The third state, printed because the reader's action differs from both
            # neighbours: nothing to check, and the row is a verdict rather than a doubt.
            # It cannot coexist with the Unconfirmed line above for the same category —
            # `attack_tally` writes one or the other — so this is not a second opinion.
            if tally.get("marker_recited"):
                lines.append(f"    {c.GREEN}Confirmed: {cat}, "
                             f"{tally['marker_recited']}{c.RESET}")
        if attacks["inconclusive"]:
            # Name the undelivered subset: "the target ran out of time" and "we never
            # reached the target" have different fixes, and only the second means the
            # whole report is about nothing.
            undelivered = attacks.get("undelivered", 0)
            detail = f" ({undelivered} never delivered)" if undelivered else ""
            lines.append(
                f"    {c.YELLOW}Inconclusive: {attacks['inconclusive']}{detail}{c.RESET}"
            )
        # The slowest answered probe of the run, printed whether or not anything timed
        # out. A scan that lost no probe still tells you how much room it had, which is
        # the only warning available before the next run loses one.
        slowest = _slowest_probe(results)
        if slowest:
            secs, probe_id = slowest
            lines.append(f"    Slowest answered: {secs:.1f}s ({probe_id})")
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
            if not cat_stats.get("exercised"):
                # The row stays so no category goes missing, and it carries words rather
                # than numbers, because a numeric row here reads as a verdict.
                lines.append(
                    f"    {category_id:<8} {name:<35} "
                    f"{c.YELLOW}{'not exercised this run':>17}{c.RESET}"
                )
                continue
            fail_color = c.RED if cat_stats["failed"] > 0 else ""
            voided = cat_stats.get("voided", 0)
            never = cat_stats.get("undelivered", 0)
            # Neither a voided nor an undelivered probe is a pass, and neither may sit in
            # the Pass column, where each told a reader the opposite of a line in the block
            # above (voided 2026-09-04, undelivered 2026-09-06).
            passed = cat_stats["passed"] - voided - never
            notes = ([f"{voided} voided"] if voided else []) + \
                    ([f"{never} never delivered"] if never else [])
            note = f"  {c.RED}{', '.join(notes)}{c.RESET}" if notes else ""
            lines.append(
                f"    {category_id:<8} {name:<35} "
                f"{cat_stats['total']:>5} {max(passed, 0):>5} "
                f"{fail_color}{cat_stats['failed']:>5}{c.RESET}{note}"
            )
        if any(r.get("voided") for r in stats["owasp_categories"].values()):
            lines.append(f"    {c.YELLOW}voided: survived a run that lost the secret to another "
                         f"probe, so it is not a pass{c.RESET}")
        if any(r.get("undelivered") for r in stats["owasp_categories"].values()):
            lines.append(f"    {c.YELLOW}never delivered: the probe got no answer to score, so "
                         f"it is not a pass either{c.RESET}")
        lines.append("")

    # Coverage gap analysis
    coverage = get_coverage_gaps(results)
    if coverage["categories_untested"] > 0:
        lines.append(
            f"  {c.CYAN}Coverage this run: {coverage['categories_tested']}/"
            f"{coverage['total_categories']} OWASP LLM Top 10 categories exercised. "
            f"Not exercised:{c.RESET}"
        )
        for gap in coverage["untested"]:
            lines.append(f"    - {gap['id']}: {gap['name']}")
    else:
        lines.append(
            f"  {c.GREEN}Coverage this run: all {coverage['total_categories']} OWASP LLM "
            f"Top 10 categories exercised{c.RESET}"
        )
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
        "incomplete": (f"{c.YELLOW}No posture to report - {unanswered} probe(s) came back "
                       f"without an answer"
                       + (f", {undelivered} of them never reaching the target"
                          if undelivered else "")
                       + f", so nothing here describes it{c.RESET}"),
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
    elif undelivered:
        # The process really does exit 1 here (the plugin sets it on the same condition).
        # This line said 0 until 2026-08-26, which made it the only line in the output that
        # a reader could check against reality and find false.
        lines.append(
            f"  {c.YELLOW}Exit code: 1 ({undelivered} probe(s) never delivered){c.RESET}")
    elif nothing_answered:
        lines.append(
            f"  {c.YELLOW}Exit code: 1 (none of the {probes} probe(s) were answered, so "
            f"this run says nothing about the target){c.RESET}")
    elif unanswered:
        # A timed-out probe does not fail the run, deliberately: ten cohort members lose
        # four or five probes to the per-probe budget every pass, and failing on that
        # would fail every pass. What it must not do is borrow the sentence "all tests
        # passed", which is the claim those probes are precisely unable to support.
        lines.append(
            f"  {c.YELLOW}Exit code: 0 ({unanswered} probe(s) inconclusive, so this run "
            f"does not say the target withstood them){c.RESET}")
    else:
        lines.append(f"  {c.GREEN}Exit code: 0 (all tests passed){c.RESET}")
    lines.append("")

    return "\n".join(lines)


