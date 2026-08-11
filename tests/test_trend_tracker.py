"""Tests for the historical trend tracker.

Written 2026-08-11 because a coverage run put this module at **14%** — 113 statements,
91 of them never executed by any test — while its output reaches two surfaces a user
reads: the console summary's TREND block and the HTML/JSON reports. A shipped feature
with no tests is the "advertised, always green" failure this project exists to catch, so
it does not get to sit in our own tree.

The emphasis is on the decisions that would rot silently rather than on shapes: the
thresholds that classify a trend, the minimum windows below which an analysis refuses to
answer, the file-level failure modes, and the ordering contract between saving a run and
analysing it.
"""

from __future__ import annotations

import json

from llmsectest.reporting.models import TestResult
from llmsectest.reporting.trend_tracker import TrendTracker


def _results(passed: int, failed: int = 0, *, marker: str = "owasp_llm01") -> list[TestResult]:
    """A run of `passed` passing and `failed` failing results, all in one category."""
    out = []
    for i in range(passed):
        out.append(TestResult(nodeid=f"t::pass{i}", location=("t.py", i, f"pass{i}"),
                              outcome="passed", duration=0.1, markers=[marker]))
    for i in range(failed):
        out.append(TestResult(nodeid=f"t::fail{i}", location=("t.py", 100 + i, f"fail{i}"),
                              outcome="failed", duration=0.1, markers=[marker]))
    return out


def _tracker(tmp_path):
    return TrendTracker(tmp_path / "history" / "trend.json")


# --- the empty and the broken cases, which are the ones a first run actually hits ---


def test_with_no_history_analytics_says_so_instead_of_inventing_a_baseline(tmp_path):
    analytics = _tracker(tmp_path).get_trend_analytics(_results(3))

    assert analytics["has_history"] is False
    assert "comparison" not in analytics, "there is nothing to compare against yet"


def test_a_corrupt_history_file_degrades_to_empty_rather_than_crashing_the_run(tmp_path):
    """Trend tracking is a reporting nicety; a truncated JSON file must not take the
    whole test session's reporting down with it."""
    tracker = _tracker(tmp_path)
    tracker.history_file.write_text("{not json at all", encoding="utf-8")

    assert tracker.get_trend_analytics(_results(3))["has_history"] is False
    tracker.save_test_run(_results(3))  # and it recovers by rewriting the file
    assert json.loads(tracker.history_file.read_text(encoding="utf-8"))["runs"]


def test_the_history_directory_is_created_on_construction(tmp_path):
    target = tmp_path / "deep" / "nested" / "trend.json"
    TrendTracker(target)

    assert target.parent.is_dir()


# --- the ordering contract the plugin depends on, pinned so a refactor cannot lose it ---


def test_analytics_must_be_taken_before_the_run_is_saved(tmp_path):
    """`plugin.pytest_sessionfinish` calls `get_trend_analytics` first and `save_test_run`
    afterwards, and that order is load-bearing rather than incidental: analytics compares
    the current run against the newest *stored* run. Save first and the newest stored run
    IS the current run, so every comparison reads a perfect zero and the trend is always
    "stable" — a check that cannot fail, which is the exact defect class this tool reports
    on other people's software.

    Both directions are asserted here, so the wrong order is a failing test rather than a
    quietly reassuring report.
    """
    tracker = _tracker(tmp_path)
    tracker.save_test_run(_results(5, 5))          # an older run: 50% pass rate
    current = _results(10, 0)                       # today: 100%

    right_way = tracker.get_trend_analytics(current)
    assert right_way["comparison"]["pass_rate_change"] == 50.0
    assert right_way["comparison"]["trend"] == "improving"

    tracker.save_test_run(current)                  # now do it in the wrong order
    wrong_way = tracker.get_trend_analytics(current)
    assert wrong_way["comparison"]["pass_rate_change"] == 0.0
    assert wrong_way["comparison"]["trend"] == "stable"


# --- the thresholds, at their boundaries ---


def test_trend_direction_thresholds(tmp_path):
    """A move of more than 2 points is improving or degrading; 2 exactly is stable. The
    boundary is asserted because "> 2" and ">= 2" read identically at a glance."""
    tracker = _tracker(tmp_path)
    tracker.save_test_run(_results(50, 50))         # 50.00%

    def change(passed, failed):
        return tracker.get_trend_analytics(_results(passed, failed))["comparison"]["trend"]

    assert change(52, 48) == "stable", "exactly +2 points is not yet a trend"
    assert change(53, 47) == "improving"
    assert change(48, 52) == "stable", "exactly -2 points is not yet a trend"
    assert change(47, 53) == "degrading"


def test_multi_run_trend_needs_two_runs_and_then_reports_the_spread(tmp_path):
    tracker = _tracker(tmp_path)
    tracker.save_test_run(_results(10))
    assert tracker.get_trend_analytics(_results(10))["trends"] == {"status": "insufficient_data"}

    tracker.save_test_run(_results(5, 5))
    trends = tracker.get_trend_analytics(_results(10))["trends"]
    assert trends["pass_rate_trend"]["min"] == 50.0
    assert trends["pass_rate_trend"]["max"] == 100.0
    assert trends["failure_trend"]["current"] == 5


# --- flakiness, where the interesting case is the test that is NOT flaky ---


def test_a_consistently_failing_test_is_not_flaky(tmp_path):
    """Flakiness means alternating, not failing. Reporting a genuinely broken test as
    flaky is how a real finding gets dismissed as noise."""
    tracker = _tracker(tmp_path)
    for _ in range(4):
        tracker.save_test_run(_results(3, 1))

    flakiness = tracker.get_trend_analytics(_results(3, 1))["flakiness"]
    assert flakiness["count"] == 0
    assert flakiness["flaky_tests"] == []


def test_a_test_that_alternates_is_flagged_with_its_failure_rate(tmp_path):
    tracker = _tracker(tmp_path)
    # Same test id every run; outcome alternates pass/fail/pass/fail.
    for i in range(4):
        r = TestResult(nodeid="t::wobbly", location=("t.py", 1, "wobbly"),
                       outcome="passed" if i % 2 == 0 else "failed", markers=["owasp_llm01"])
        tracker.save_test_run([r])

    flakiness = tracker.get_trend_analytics(_results(1))["flakiness"]
    assert flakiness["count"] == 1
    entry = flakiness["flaky_tests"][0]
    assert entry["test"] == "t.py::wobbly"
    assert entry["fail_rate"] == 50.0
    assert entry["recent_outcomes"] == ["passed", "failed", "passed", "failed"]


def test_flakiness_refuses_to_answer_below_three_runs(tmp_path):
    tracker = _tracker(tmp_path)
    tracker.save_test_run(_results(1))
    tracker.save_test_run(_results(0, 1))

    flakiness = tracker.get_trend_analytics(_results(1))["flakiness"]
    assert flakiness["flaky_tests"] == []
    assert "at least 3 runs" in flakiness["message"]


# --- growth bounds and per-category trends ---


def test_history_is_capped_at_one_hundred_runs(tmp_path):
    """Unbounded growth in a file written on every test session is a slow leak. The cap
    keeps the newest runs, which are the ones every analysis window reads."""
    tracker = _tracker(tmp_path)
    for i in range(105):
        tracker.save_test_run(_results(i % 3 + 1))

    stored = json.loads(tracker.history_file.read_text(encoding="utf-8"))["runs"]
    assert len(stored) == 100
    assert stored[-1]["summary"]["total_tests"] == (104 % 3) + 1, "the newest run survives"


def test_owasp_category_trends_are_reported_per_category(tmp_path):
    tracker = _tracker(tmp_path)
    tracker.save_test_run(_results(1, 1, marker="owasp_llm02"))     # 50%
    tracker.save_test_run(_results(2, 0, marker="owasp_llm02"))     # 100%

    trends = tracker.get_trend_analytics(_results(2, 0, marker="owasp_llm02"))
    assert "LLM02" in trends["owasp_category_trends"], trends["owasp_category_trends"]
    assert trends["owasp_category_trends"]["LLM02"]["current"] == 100.0


def test_improvement_rate_is_none_until_there_is_an_older_window_to_compare(tmp_path):
    """It compares the last five runs with the five before them. With five runs or fewer
    there is no "before", and the honest answer is None rather than a number derived from
    comparing a window with itself."""
    tracker = _tracker(tmp_path)
    for _ in range(5):
        tracker.save_test_run(_results(5, 5))
    assert tracker.get_trend_analytics(_results(5, 5))["improvement_rate"] is None

    tracker.save_test_run(_results(5, 5))
    rate = tracker.get_trend_analytics(_results(5, 5))["improvement_rate"]
    assert rate is not None and rate["status"] == "stable"
