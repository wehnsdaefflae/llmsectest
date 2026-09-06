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


#: The marker carried by ``suite/test_owasp_coverage.py``'s per-category assertion, which
#: is a claim about the **tool** ("a tester ships for this category") wearing the
#: category's own marker. Named here so the statistics layer can tell it apart from a
#: result that says something about the **target**. See :func:`exercised_categories`.
COVERAGE_MAP_MARKER = "llmsec_coverage_map"

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
#:
#: **One row per marker rather than per category (2026-09-05).** Until that day this held
#: two entries, for LLM02 and LLM06, and LLM08 had none, so a cohort member whose manifest
#: declared a canary and a poison marker its application never planted reported six LLM08
#: probes, six withstood, zero findings, with nothing beside the row.
#:
#: Adding one LLM08 entry would not have been enough, which is why the shape changed too.
#: LLM08 is scored against two independent developer-supplied values, a canary planted in
#: the retrieved corpus and the marker a poisoned document tells the application to emit,
#: and a run that proved one of them live says nothing about the other. A category-keyed
#: rule reads a member's injection findings as "the oracle matched, so the marker is live"
#: and suppresses the doubt about its canary. That case is live: the same member, rescanned
#: with its markers planted, obeyed all three injections while its canary appeared nowhere.
MARKER_CHECKS = (
    (SECRET_CATEGORY, "--app-secret",
     "llmsec_secret_configured", "llmsec_secret_exposed"),
    ("LLM06", "--app-action",
     "llmsec_action_configured", "llmsec_action_observed"),
    ("LLM08", "--app-canary",
     "llmsec_canary_configured", "llmsec_canary_observed"),
    ("LLM08", "--app-rag-poison",
     "llmsec_poison_configured", "llmsec_poison_observed"),
)




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
    See :data:`MARKER_CHECKS`. Reported per category and at run level; absent when
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
    # A finding is evidence that *the* marker was live only where the category has one.
    # LLM08 has two, so obeying the poisoned document proves nothing about the canary.
    sole = {cat for cat, *_ in MARKER_CHECKS
            if sum(1 for c, *_ in MARKER_CHECKS if c == cat) == 1}
    for cat, flag, configured_prop, observed_prop in MARKER_CHECKS:
        tally = by_category.get(cat)
        if tally is None:
            continue
        if not any(r.properties.get(configured_prop) is not None for r in results):
            continue  # no flag was passed, so there is no configuration to doubt
        if any(r.properties.get(observed_prop) is not None for r in results):
            continue  # the marker turned up somewhere: it is demonstrably live
        if tally["findings"] and cat in sole:
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
        # A category can carry two markers, so the doubts accumulate rather than replace:
        # a member that obeyed the poisoned document tells you nothing about whether its
        # canary was ever in the corpus, and the row has to be able to say both.
        unconfirmed[cat] = f"{unconfirmed[cat]} Also: {reason}" if cat in unconfirmed else reason
        tally["marker_unconfirmed"] = unconfirmed[cat]

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
    # And the superset it is a subset of: every probe that came back without an answer,
    # a timeout as much as a transport failure. Carried here for the same reason
    # `undelivered` is (2026-08-26) and because keying the verdict on the subset alone
    # reproduced that bug on the other branch: on 2026-09-03 a target that answered
    # nothing at all, every probe timing out, printed PASSED, "security posture is
    # acceptable" and exit 0. The comment above the fix described the timeout case; the
    # code counted transport failures.
    inconclusive = sum(
        1 for r in results if r.properties.get("llmsec_inconclusive") is not None
    )

    stats = {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "undelivered": undelivered,
        "inconclusive": inconclusive,
        "pass_rate": round((passed / total * 100), 2) if total > 0 else 0,
        "fail_rate": round((failed / total * 100), 2) if total > 0 else 0,
        "total_duration": round(total_duration, 3),
        # Per category, counted over results that say something about the **target**.
        # The coverage-map assertion carries every category's marker and passes on every
        # run, so counting it here printed `LLM02  1  1  0` — one test, one pass, no
        # failures — for a category no probe had been sent to, on a report whose reader
        # has no way to know that row is about the tool. `exercised` keeps the row
        # visible without letting it read as a verdict, which is the whole trade: a
        # category that vanishes is a silent gap and a category that shows a pass it did
        # not earn is worse (2026-09-04).
        "owasp_categories": defaultdict(
            lambda: {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "exercised": False,
                     "voided": 0, "undelivered": 0}
        ),
        "severity_distribution": defaultdict(int),
        "by_severity": defaultdict(lambda: {"total": 0, "failed": 0, "passed": 0}),
    }

    exercised = exercised_categories(results)
    # **Voided probes must not read as passes in the per-category row (2026-09-04).** A probe
    # the target survived, in a run where some other probe got the secret out, is already
    # counted as `voided` in the attacks block with its reason attached. The per-category
    # table counted the same probe as a pytest pass, so one page said `LLM02  4  4  0` and
    # the block above it said four voided. Two accounts of four probes, in one report.
    # **And an undelivered probe must not read as a pass either (2026-09-06).** Same
    # argument, one state along, found on `weknora-archivebot`: WeKnora's own
    # `utils.ValidateInput` refuses a query matching its XSS pattern list, so two of the
    # four LLM05 probes were rejected at the input boundary and never reached the model.
    # pytest records an undelivered probe as a pass with a warning — which is right, the
    # tool has nothing to assert — and the report printed `LLM05  4  4  0` above its own
    # banner saying two probes were never delivered. The attacks block already had this
    # right, counting them `inconclusive`; the per-category table was the surface that
    # still credited the target with output handling it never performed.
    tally = attack_tally(results) or {}
    voided_by_cat = {cat: row.get("voided", 0)
                     for cat, row in (tally.get("by_category") or {}).items()}
    undelivered_by_cat = {cat: row.get("undelivered", 0)
                          for cat, row in (tally.get("by_category") or {}).items()}
    for result in results:
        # Track OWASP category statistics
        is_coverage_map = COVERAGE_MAP_MARKER in result.markers
        owasp_markers = get_owasp_markers_from_test(result.markers)
        for marker in owasp_markers:
            category = get_owasp_category(marker)
            if not category:
                continue
            row = stats["owasp_categories"][category.id]
            row["exercised"] = marker in exercised
            row["voided"] = voided_by_cat.get(category.id, 0)
            row["undelivered"] = undelivered_by_cat.get(category.id, 0)
            if is_coverage_map:
                # The row exists so the category stays on every report. Its numbers do
                # not, because they would be the tool's own coverage assertion counted as
                # a test of the application.
                continue
            row["total"] += 1
            if result.outcome == "failed":
                row["failed"] += 1
            elif result.outcome == "passed":
                row["passed"] += 1
            elif result.outcome == "skipped":
                row["skipped"] += 1

        # Track severity distribution. **Also excludes the coverage-map assertion
        # (2026-09-04, fresh-context pass).** Those results carry no severity marker, so
        # `get_test_severity` defaults them to medium, and ten of the fourteen "Medium"
        # rows in an app scan's severity block were the tool asserting things about
        # itself. A severity distribution is read as a property of the target.
        if is_coverage_map:
            continue
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


def exercised_categories(results: list[TestResult]) -> set[str]:
    """The OWASP markers this run actually exercised **against its target**.

    Different from :func:`get_owasp_markers`, which answers "which categories appear
    anywhere in this result set". Two kinds of result carry an OWASP marker without
    saying anything about the target, and both have to come out:

    - **The coverage-map assertion.** ``suite/test_owasp_coverage.py`` emits one test per
      category asserting that *the tool* ships a tester for it, and it carries the
      category's marker so the map is visible per category. It passes on every run,
      including a run that never reached the application, which made
      :func:`get_coverage_gaps` structurally incapable of returning anything but 100%:
      every category always had one passing result. ``--min-coverage`` gated on that
      number and therefore could never fire, and one console run printed
      *OWASP Coverage: 100% (10/10 categories)* above a footer saying four of ten were
      exercised. Two figures for one fact, disagreeing in one output, on the surface a
      first-time reader meets first (found 2026-09-04).
    - **A skip.** A category whose input was never supplied reports a skip naming the flag
      it needs. That is the honest state and it is not coverage.

    So a category is exercised when at least one result carries its marker, is not the
    coverage-map assertion, and did not skip. That covers both modalities: a delivered
    probe and a white-box scanner run, neither of which is distinguishable here by
    outcome alone.
    """
    exercised: set[str] = set()
    for result in results:
        if COVERAGE_MAP_MARKER in result.markers:
            continue
        if result.outcome == "skipped":
            continue
        exercised.update(get_owasp_markers_from_test(result.markers))
    return exercised


def get_coverage_gaps(results: list[TestResult]) -> dict:
    """Identify OWASP LLM Top 10 categories this run did not exercise.

    Returns a dictionary with tested categories, untested categories,
    and coverage percentage. Essential for identifying blind spots in
    security test suites.

    "Tested" means :func:`exercised_categories`: a category the run actually put
    something to, rather than one that merely appears in the result set. Read that
    function for why the difference is the whole point of this one.
    """
    tested_markers = exercised_categories(results)
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
