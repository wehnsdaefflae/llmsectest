"""Unit tests for the run-level "attacks withstood" tally.

A scan that finds nothing has always produced an empty report, which is the same
report a scan that attacked nothing produces. That is the gap this tally closes: it
records what was actually *delivered* to the target and how much of it held, so a
defender who hardened an app can see the hardening work, and so a regression in a
defense is legible as a number going down.

The tests pin the three things that make the number trustworthy rather than
flattering: only real probes are counted (a coverage assertion or a static scanner
never inflates it), an unanswered attack is never counted as one the target
resisted, and the figure travels all the way to the surfaces a reader looks at (the
SARIF run properties, the rendered HTML page, the console summary).
"""

from __future__ import annotations

import json

import pytest

from llmsectest.reporting import statistics
from llmsectest.reporting.console_summary import generate_console_summary
from llmsectest.reporting.models import TestResult
from llmsectest.reporting.sarif_generator import SARIFGenerator
from llmsectest.reporting.sarif_html import render_sarif_html
from llmsectest.reporting.statistics import attack_tally


def _probe(name, outcome, marker, *, inconclusive=None):
    """A probe result as the suite records it: marked with ``llmsec_probe``."""
    properties = {"llmsec_probe": marker}
    if inconclusive is not None:
        properties["llmsec_inconclusive"] = inconclusive
    return TestResult(
        nodeid=f"suite/test_probe.py::{name}",
        location=("suite/test_probe.py", 12, name),
        outcome=outcome,
        markers=[marker, "high"],
        properties=properties,
    )


def _non_probe(name, outcome, marker):
    """A result that carries an OWASP marker but delivered no attack.

    The coverage-footer assertions and the static scanners look exactly like this.
    """
    return TestResult(
        nodeid=f"suite/test_owasp_coverage.py::{name}",
        location=("suite/test_owasp_coverage.py", 5, name),
        outcome=outcome,
        markers=[marker, "security"],
        properties={},
    )


def test_counts_passes_as_withstood_and_failures_as_findings():
    tally = attack_tally([
        _probe("injection", "passed", "owasp_llm01"),
        _probe("leak", "passed", "owasp_llm02"),
        _probe("poisoned_doc", "failed", "owasp_llm08"),
    ])
    assert tally["attempted"] == 3
    assert tally["withstood"] == 2
    assert tally["findings"] == 1
    assert tally["inconclusive"] == 0
    # 2026 numbering: the `owasp_llm08` marker publishes as LLM09 Vector and Embedding
    # Weaknesses. The marker keys never move; the published id is what the edition changes.
    assert tally["by_category"]["LLM09"]["findings"] == 1
    assert tally["by_category"]["LLM01"]["withstood"] == 1


def test_an_unanswered_attack_is_not_counted_as_withstood():
    """A timed-out probe is evidence of nothing and must not flatter the target."""
    tally = attack_tally([
        _probe("injection", "passed", "owasp_llm01"),
        _probe("flood", "passed", "owasp_llm10",
               inconclusive="target exceeded the 90s per-request budget"),
    ])
    assert tally["attempted"] == 2
    assert tally["withstood"] == 1
    assert tally["inconclusive"] == 1
    # 2026: `owasp_llm10` publishes as LLM06 Unbounded Consumption.
    assert tally["by_category"]["LLM06"]["withstood"] == 0


def test_coverage_assertions_and_scanners_never_inflate_the_count():
    """Only results the probe path marked at delivery are attacks."""
    tally = attack_tally([
        _probe("injection", "passed", "owasp_llm01"),
        _non_probe("test_owasp_category_implemented[LLM03]", "passed", "owasp_llm03"),
        _non_probe("test_owasp_category_implemented[LLM04]", "skipped", "owasp_llm04"),
    ])
    assert tally["attempted"] == 1
    assert set(tally["by_category"]) == {"LLM01"}


def test_a_run_with_no_delivered_attack_reports_nothing_rather_than_zero():
    """All-zero would read as "nothing held"; the honest answer is "not measured"."""
    assert attack_tally([
        _non_probe("test_owasp_category_implemented[LLM03]", "passed", "owasp_llm03"),
    ]) is None
    assert attack_tally([]) is None


def test_by_category_is_ordered_and_carries_the_category_name():
    """The SARIF renderer reads the file, not our metadata tables, so the name ships."""
    tally = attack_tally([
        _probe("flood", "passed", "owasp_llm10"),
        _probe("injection", "passed", "owasp_llm01"),
    ])
    # Ordered by PUBLISHED id, so the 2026 renumbering changes the order itself: the flood
    # probe's marker (`owasp_llm10`) publishes as LLM06 and now sorts before a 2025 LLM10.
    assert list(tally["by_category"]) == ["LLM01", "LLM06"]
    assert tally["by_category"]["LLM01"]["name"]


def test_sarif_carries_the_tally_as_a_run_level_property(tmp_path):
    sarif = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", tmp_path).generate([
            _probe("injection", "passed", "owasp_llm01"),
            _probe("poisoned_doc", "failed", "owasp_llm08"),
        ])
    )
    props = sarif["runs"][0]["properties"]["attacks_withstood"]
    assert props["attempted"] == 2
    assert props["withstood"] == 1
    assert props["by_category"]["LLM09"]["findings"] == 1


def test_every_finding_names_the_edition_it_was_scored_under(tmp_path):
    """A stored SARIF must be datable from the file.

    `owasp-category: LLM03` is Supply Chain under 2025 and Excessive Agency under 2026, so a
    number without an edition cannot be read years later. This project has 92 published
    reports carrying 2025 numbers and migrated to 2026 on 2026-10-20; the edition property is
    what keeps both readable instead of rewriting the old ones.
    """
    sarif = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", tmp_path).generate([
            _probe("injection", "failed", "owasp_llm01"),
        ])
    )
    props = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
    assert props["owasp-edition"] == "2026"
    assert props["owasp-category"] == "LLM01"


def test_a_renumbered_category_carries_its_2025_number_too(tmp_path):
    """Eight of the ten categories changed number, and a reader may hold an older report.

    Marker `owasp_llm08` published as LLM08 Vector and Embedding Weaknesses under 2025 and
    publishes as LLM09 under 2026, so both numbers belong on the finding. LLM01 did not move,
    and there the legacy key is absent rather than duplicating the live one.
    """
    sarif = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", tmp_path).generate([
            _probe("poisoned_doc", "failed", "owasp_llm08"),
            _probe("injection", "failed", "owasp_llm01"),
        ])
    )
    by_id = {
        r["properties"]["owasp-category"]: r["properties"]
        for r in sarif["runs"][0]["tool"]["driver"]["rules"]
    }
    assert by_id["LLM09"]["owasp-category-2025"] == "LLM08"
    assert "owasp-category-2025" not in by_id["LLM01"]


def test_a_static_only_scan_omits_the_property_entirely(tmp_path):
    """No probe delivered → no claim made. An absent key beats a misleading zero."""
    sarif = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", tmp_path).generate([
            _non_probe("test_owasp_category_implemented[LLM03]", "passed", "owasp_llm03"),
        ])
    )
    assert "attacks_withstood" not in sarif["runs"][0].get("properties", {})


def test_clean_report_html_states_what_was_withstood(tmp_path):
    """The empty-report page must be evidence, not silence."""
    doc = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", tmp_path).generate([
            _probe("injection", "passed", "owasp_llm01"),
            _probe("poisoned_doc", "passed", "owasp_llm08"),
        ])
    )
    page = render_sarif_html(doc, source_name="defended-app")
    assert "2/2 attacks withstood" in page
    assert "withstood 2 of 2 delivered attacks" in page
    assert "LLM09" in page  # the per-category breakdown, not just a total


def test_html_of_a_third_party_report_without_the_tally_still_renders():
    """Any other tool's SARIF has no such property; the section simply disappears."""
    page = render_sarif_html({"runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": []}]})
    assert "attacks withstood" not in page
    assert "the scan was clean" in page


def test_console_summary_reports_delivered_attacks_separately_from_tests():
    text = generate_console_summary(
        [
            _probe("injection", "passed", "owasp_llm01"),
            _probe("flood", "passed", "owasp_llm10", inconclusive="timed out"),
            _non_probe("test_owasp_category_implemented[LLM03]", "passed", "owasp_llm03"),
        ],
        show_colors=False,
    )
    assert "Attacks Delivered:" in text
    assert "Total:     2" in text  # the coverage assertion is not an attack
    assert "Withstood: 1" in text
    assert "Inconclusive: 1" in text


def test_by_category_states_corpus_cases_and_delivered():
    """Issue #28: a row must say how much its corpus holds and how much ran.

    LLM02 ships four authored cases; delivering two of them must read as two
    delivered of four corpus cases, not as a bare "2". LLM01 ships five authored
    cases plus the eight built in red team behaviours, so its corpus reads 13.
    """
    tally = attack_tally([
        _probe("leak", "passed", "owasp_llm02"),
        _probe("leak-variant", "failed", "owasp_llm02"),
        _probe("injection", "passed", "owasp_llm01"),
    ])
    llm02 = tally["by_category"]["LLM02"]
    assert llm02["corpus_cases"] == 4
    assert llm02["delivered"] == 2
    assert llm02["attempted"] == 2
    assert llm02["withstood"] == 1
    llm01 = tally["by_category"]["LLM01"]
    assert llm01["corpus_cases"] == 13
    assert llm01["delivered"] == 1


def test_category_without_a_shipped_corpus_carries_no_corpus_claim():
    """LLM08 app probes ship no bare model corpus, so no number is invented.

    The row still states what was delivered; only the corpus claim is absent,
    because a zero there would read as "this category has no cases".
    """
    tally = attack_tally([
        _probe("poisoned_doc", "passed", "owasp_llm08"),
    ])
    row = tally["by_category"]["LLM09"]
    assert "corpus_cases" not in row
    assert row["delivered"] == 1


def test_sarif_carries_corpus_and_delivered_per_category(tmp_path):
    """The new fields travel to the SARIF run properties, not just the tally."""
    sarif = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", tmp_path).generate([
            _probe("leak", "passed", "owasp_llm02"),
            _probe("leak-variant", "failed", "owasp_llm02"),
        ])
    )
    row = sarif["runs"][0]["properties"]["attacks_withstood"]["by_category"]["LLM02"]
    assert row["corpus_cases"] == 4
    assert row["delivered"] == 2


def _row_of(findings, withstood, *, inconclusive=0, secret_out=False, marker="owasp_llm01"):
    """The tally row for one category built from the given outcome counts."""
    results = [_probe(f"finding-{i}", "failed", marker) for i in range(findings)]
    results += [_probe(f"held-{i}", "passed", marker) for i in range(withstood)]
    results += [
        _probe(f"silent-{i}", "passed", marker, inconclusive="timed out")
        for i in range(inconclusive)
    ]
    if secret_out:
        results[0].properties["llmsec_secret_exposed"] = "the reply carried the value"
    return next(iter(attack_tally(results)["by_category"].values()))


def test_bootstrap_interval_is_pinned_for_a_fixed_seed():
    """Issue #36: the published example, 12 of 43, with the default seed.

    The numbers are pinned so a change to the method, the resample count or the seed
    shows up as a failing test rather than as a report that quietly moved.
    """
    assert statistics.bootstrap_interval(12, 43) == {
        "confidence": 0.95,
        "confidence_lower": 0.1628,
        "confidence_upper": 0.4186,
    }


def test_bootstrap_interval_refuses_a_sample_under_thirty():
    """A small sample says so. It does not get a bound that would read as knowledge."""
    interval = statistics.bootstrap_interval(10, 29)
    assert interval == {
        "confidence_note": "sample too small for a confidence interval: 29 scored, 30 needed"
    }
    assert "confidence_lower" in statistics.bootstrap_interval(10, 30)


def test_bootstrap_interval_rejects_counts_that_cannot_be_a_rate():
    with pytest.raises(ValueError):
        statistics.bootstrap_interval(5, 4)


@pytest.mark.parametrize(
    "settings",
    [{"resamples": 0}, {"confidence": 0}, {"confidence": 1}, {"confidence": -0.5}],
)
@pytest.mark.parametrize("samples", [10, 43])
def test_bootstrap_interval_rejects_settings_that_cannot_give_an_interval(settings, samples):
    """A bad resample count or confidence level is refused, whatever the sample size.

    Zero resamples used to surface as an IndexError, and a negative confidence came back
    as bounds in the wrong order. Both are a ValueError now, small sample or not.
    """
    with pytest.raises(ValueError):
        statistics.bootstrap_interval(3, samples, **settings)


def test_a_row_with_thirty_scored_probes_carries_its_rate_and_bounds():
    """The bounds sit beside the rate they bound, and the old fields still read the same."""
    row = _row_of(findings=12, withstood=31)
    assert row["attempted"] == 43
    assert row["findings"] == 12
    assert row["scored"] == 43
    assert row["finding_rate"] == 0.2791
    assert row["confidence"] == 0.95
    assert row["confidence_lower"] == 0.1628
    assert row["confidence_upper"] == 0.4186
    assert "confidence_note" not in row


def test_a_row_with_a_small_sample_says_so_and_carries_no_bounds():
    row = _row_of(findings=2, withstood=10)
    assert row["scored"] == 12
    assert row["finding_rate"] == 0.1667
    assert "30 needed" in row["confidence_note"]
    assert "confidence_lower" not in row
    assert "confidence_upper" not in row


def test_unanswered_probes_are_not_in_the_denominator():
    """40 delivered, 15 never answered: 25 scored, which is under the floor."""
    row = _row_of(findings=5, withstood=20, inconclusive=15)
    assert row["attempted"] == 40
    assert row["scored"] == 25
    assert row["finding_rate"] == 0.2
    assert "confidence_lower" not in row


def test_voided_probes_are_not_in_the_denominator():
    """A voided LLM02 probe was scored and then rejected, so the bound must not cover it.

    35 delivered, 5 findings, and the secret got out, so the other 30 are voided. Counting
    them as scored would give 5 of 35 and a bound. The row stands behind 5 of 5 only.
    """
    row = _row_of(findings=5, withstood=30, secret_out=True, marker="owasp_llm02")
    assert row["voided"] == 30
    assert row["scored"] == 5
    assert row["finding_rate"] == 1.0
    assert "confidence_lower" not in row


def test_a_row_with_nothing_scored_carries_no_rate():
    row = _row_of(findings=0, withstood=0, inconclusive=3)
    assert row["scored"] == 0
    assert "finding_rate" not in row
    assert "confidence_note" in row


def test_sarif_carries_the_rate_and_bounds_per_category(tmp_path):
    """The interval travels to the SARIF run properties, not just the tally."""
    results = [_probe(f"finding-{i}", "failed", "owasp_llm01") for i in range(12)]
    results += [_probe(f"held-{i}", "passed", "owasp_llm01") for i in range(31)]
    sarif = json.loads(SARIFGenerator("llmsectest", "0.1.0", tmp_path).generate(results))
    row = sarif["runs"][0]["properties"]["attacks_withstood"]["by_category"]["LLM01"]
    assert row["finding_rate"] == 0.2791
    assert row["confidence_lower"] == 0.1628
    assert row["confidence_upper"] == 0.4186
