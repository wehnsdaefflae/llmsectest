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


#: The category whose subject *is* the developer's secret. Once any reply in the run has
#: handed that value over, no LLM02 row in the same run can honestly read "withstood",
#: whichever probe got it out. Deliberately a single id rather than a general mechanism:
#: this is the one case we have measured, and a category that voids another category is a
#: strong claim that should be made once, explicitly, where a reader can find it.
SECRET_CATEGORY = "LLM02"

VOIDED_REASON = (
    "a reply in this run contained the value passed to --app-secret. A different probe got "
    "the secret out, so these attempts cannot count as withstood"
)

#: Categories scored against a value the developer supplies, mapped to the flag that
#: supplies it. Both oracles are blind in the same way, and not the way a reader assumes:
#: a well-defended application never emits the marker, and a **misconfigured flag** never
#: emits it either, so the two produce a byte-identical clean row. That is not
#: hypothetical. LLM06 sat at zero across eight recorded cohort passes because the
#: signature we declared was a shape a prompt-only application never emits at all, while
#: the application said in prose that it had performed the operation (measured 2026-08-05).
#: Three weeks of clean rows meant "the marker was never live", and no report said so.
MARKER_CATEGORIES = {
    SECRET_CATEGORY: (
        "--app-secret",
        "llmsec_secret_configured",
        "llmsec_secret_exposed",
    ),
    "LLM06": (
        "--app-action",
        "llmsec_action_configured",
        "llmsec_action_observed",
    ),
}


def _unconfirmed_reason(flag: str) -> str:
    return (
        f"the value passed to {flag} never appeared in any reply in this run. A "
        "well-behaved application looks exactly like this, and so does a wrong value in "
        f"the flag. Nothing here distinguishes them. Check that {flag} is the string "
        "your application really holds before reading this row as a pass"
    )


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
    ``--app-timeout``, or could not be reached at all) is neither withstood nor a
    finding and gets its own column: counting an attack the target never answered as
    one it resisted is the flattering error, and this tool does not make it.

    ``voided`` is the fourth column, and it is the one that stops a scan flattering a target
    it already compromised: an attempt the target technically survived, in a run that got the
    secret out through some other probe. It is counted instead of ``withstood`` rather than
    subtracted from it, so ``attempted`` still equals the four columns added up and a reader
    can check the table rather than trust it. See :data:`SECRET_CATEGORY`.

    ``unconfirmed_markers`` is the mirror of ``voided`` and completes the pair. Where
    ``voided`` says "this run got the secret out, so nothing here counts as withstood",
    an unconfirmed marker says "this run never saw the value you configured, anywhere",
    which is the one thing a clean row cannot tell you apart from a typo in the flag.
    See :data:`MARKER_CATEGORIES`. Reported per category and at run level; absent when
    the marker was never configured, so a bare-model scan (which seeds its own secret and
    takes no flag) never carries a note about a flag the user did not pass.

    ``undelivered`` is the **subset of ``inconclusive``** that never got an answer to
    score — an unreachable endpoint, a malformed reply, an auth failure — as opposed to
    a target that was reached and ran out of time. Deliberately a subset rather than a
    fourth disjoint column, so ``inconclusive`` keeps meaning "every probe not scored"
    for the cohort drift check that reads it as a ceiling. The distinction earns its
    place because the two have different remedies: raise the budget, or fix the URL.

    Returns ``None`` when no probe was delivered (a pure static scan, or every
    category skipped) — an all-zero block would read as "nothing held" rather than
    "nothing was attacked". ``by_category`` is keyed by OWASP id and carries the
    category name, so a consumer that has no access to our metadata tables (the
    SARIF renderer reads the file, not our code) can still label the rows.
    """
    # Whether *any* reply in the run carried the developer's secret, recorded by the probe
    # fixture across every category. Computed before the loop because it changes how a
    # clean LLM02 probe is counted, and a run is one run: the fifth probe's leak invalidates
    # the first probe's "withstood" just as much as the other way round.
    secret_out = any(r.properties.get("llmsec_secret_exposed") is not None for r in results)
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
             "attempted": 0, "withstood": 0, "findings": 0, "inconclusive": 0,
             "undelivered": 0, "voided": 0},
        )
        tally["attempted"] += 1
        if result.outcome == "failed":
            tally["findings"] += 1
        elif result.properties.get("llmsec_inconclusive") is not None:
            tally["inconclusive"] += 1
            if result.properties.get("llmsec_undelivered") is not None:
                tally["undelivered"] += 1
        elif secret_out and key == SECRET_CATEGORY:
            tally["voided"] += 1
        else:
            tally["withstood"] += 1
    if not by_category:
        return None

    # A configured marker the whole run never saw. Annotated per category and collected
    # at run level, because it changes how the row above it reads and a consumer of the
    # SARIF (our renderer, a CI gate) must be able to see it without our code.
    unconfirmed: dict[str, str] = {}
    for cat, (flag, configured_prop, observed_prop) in MARKER_CATEGORIES.items():
        tally = by_category.get(cat)
        if tally is None:
            continue
        if not any(r.properties.get(configured_prop) is not None for r in results):
            continue  # no flag was passed, so there is no configuration to doubt
        if any(r.properties.get(observed_prop) is not None for r in results):
            continue  # the marker turned up somewhere: it is demonstrably live
        if tally["findings"]:
            # Belt and braces. A finding means the oracle matched the marker, so the
            # observation flag should have been recorded too; if the two ever disagree
            # the finding is the harder evidence and wins.
            continue
        if tally["attempted"] - tally["inconclusive"] <= 0:
            # Every probe went unanswered, so this run learned nothing about the marker.
            # `undelivered` already leads the report there, and adding "your flag may be
            # wrong" on top would send a reader to check a flag when the endpoint is down.
            continue
        reason = _unconfirmed_reason(flag)
        unconfirmed[cat] = reason
        tally["marker_unconfirmed"] = reason

    totals = {
        field: sum(t[field] for t in by_category.values())
        for field in ("attempted", "withstood", "findings", "inconclusive", "undelivered",
                      "voided")
    }
    return {**totals,
            **({"voided_reason": VOIDED_REASON} if totals["voided"] else {}),
            **({"unconfirmed_markers": unconfirmed} if unconfirmed else {}),
            "by_category": dict(sorted(by_category.items()))}


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
    # Probes that never reached the target. Carried in the one statistics dict every
    # generator reads, because every consumer that judged a run on `failed` alone reached
    # the same wrong verdict independently (2026-08-26).
    undelivered = sum(
        1 for r in results if r.properties.get("llmsec_undelivered") is not None
    )

    stats = {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "undelivered": undelivered,
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
