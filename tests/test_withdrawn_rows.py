"""A withdrawn row must stop counting as a finding, on every surface (bl-204).

``scripts/rescore_sarif.py --apply`` withdraws a row the current oracles no longer
support: it prefixes ``[WITHDRAWN by re-scoring on <date>]`` onto the message and drops
``level`` to ``note``. That looked like enough and it was not. ``_severity_of`` resolves
severity from the **CVSS score first** and only falls back to the SARIF level, and a
withdrawn row keeps its CVSS property, so after a re-render the page still showed the
row in the headline total, in the severity bar, in its own ``CRITICAL`` badge and in the
category table. Measured 2026-10-30 on two real third-party cohort members, both of
them withheld; the members are named in the private cohort records, not here.

The check that fails to check is ``grep WITHDRAWN report.html``: the string is there
while every number still counts the row. So these tests assert the **counts**.

Why it matters now: ``ask-112`` commits the project to re-scoring all stored reports, so
withdrawn rows stop being two withheld members and become many published ones.
"""

from __future__ import annotations

import re
import zlib

from llmsectest.reporting.sarif_html import render_sarif_html
from llmsectest.reporting.sarif_pdf import render_sarif_pdf

WITHDRAWN_PREFIX = "[WITHDRAWN by re-scoring on 2026-11-02] "


def _doc(*results: dict) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "llmsectest", "version": "0.4.1", "rules": [{
                "id": "test_x_LLM01-prompt-injection",
                "name": "LLM01 Prompt Injection",
                "properties": {"owasp-category": "LLM01", "owasp-name": "Prompt Injection"},
            }]}},
            "results": list(results),
        }],
    }


def _result(text: str, *, level: str = "error") -> dict:
    return {
        "ruleId": "test_x_LLM01-prompt-injection",
        "level": level,
        "message": {"text": text},
        "properties": {
            "owasp_category": "LLM01",
            "owasp_name": "Prompt Injection",
            "cvss_base_score": 9.2,
            "cvss_base_severity": "critical",
            "security-severity": "9.2",
        },
    }


def _headline(page: str) -> int:
    """The number in the summary's big count."""
    m = re.search(r'<span class="big">(\d+)</span>', page)
    assert m, "the summary headline is missing from the page"
    return int(m.group(1))


def test_a_withdrawn_row_is_not_in_the_headline_total():
    live = render_sarif_html(_doc(_result("the target emitted the marker")))
    assert _headline(live) == 1

    withdrawn = render_sarif_html(_doc(
        _result(WITHDRAWN_PREFIX + "the current oracle does not support it.", level="note")
    ))
    assert _headline(withdrawn) == 0


def test_a_withdrawn_row_keeps_its_cvss_and_still_leaves_the_severity_bar_empty():
    page = render_sarif_html(_doc(
        _result(WITHDRAWN_PREFIX + "no refusal marker is not compliance.", level="note")
    ))
    # The row carries cvss_base_severity "critical" and _severity_of reads CVSS first,
    # which is exactly the trap: the bar must not pick it up anyway.
    assert 'title="critical: 1"' not in page
    assert "critical: 1" not in page


def test_a_withdrawn_row_is_not_in_the_category_table():
    page = render_sarif_html(_doc(
        _result(WITHDRAWN_PREFIX + "withdrawn.", level="note")
    ))
    # The category table prints "LLM01 Prompt Injection" beside a count. With the only
    # row withdrawn there is no category group at all.
    assert '<h2 class="cat">' not in page


def test_a_withdrawn_row_is_still_visible_on_the_page():
    """Withdrawing is not deleting. The row stays readable, with its evidence."""
    page = render_sarif_html(_doc(
        _result(WITHDRAWN_PREFIX + "no refusal marker is not compliance.", level="note")
    ))
    assert "WITHDRAWN" in page
    assert "no refusal marker is not compliance." in page


def test_a_live_row_beside_a_withdrawn_one_still_counts_once():
    page = render_sarif_html(_doc(
        _result("the target emitted the marker"),
        _result(WITHDRAWN_PREFIX + "withdrawn.", level="note"),
    ))
    assert _headline(page) == 1
    assert "WITHDRAWN" in page


def test_the_withstood_table_does_not_count_a_withdrawn_row_as_a_finding():
    """‼ THE FOURTH COUNTER, found by a fresh-context review AFTER three were fixed.

    `_withstood_section` prints the per-category tally STORED IN THE SARIF AT SCAN TIME
    rather than counting results, so a later withdrawal never reached it. On one real
    report that produced a page contradicting itself in print: headline **14 findings**,
    category table LLM01 -> 8, and this table's own findings column **9**.

    The lesson the other three tests cannot teach: fixing every counter you can find is
    not the same as fixing the concept, and the check that finds the next one is
    comparing two numbers ON THE SAME PAGE rather than checking each in isolation.
    """
    doc = _tally_doc(
        _result("the target emitted the marker"),
        _result(WITHDRAWN_PREFIX + "withdrawn.", level="note"),
    )
    doc["runs"][0]["properties"]["attacks_withstood"] = {
        "attempted": 3, "withstood": 1,
        "by_category": {"LLM01": {"name": "Prompt Injection", "attempted": 3,
                                  "withstood": 1, "findings": 2}},
    }
    page = render_sarif_html(doc)
    assert _headline(page) == 1
    # the stored tally said 2; one was withdrawn, so the table must say 1
    assert ">2</td>" not in page, "the withstood table still counts the withdrawn row"
    assert ">1</td>" in page


def test_a_non_numeric_stored_tally_passes_through_untouched():
    """This renderer displays any tool's SARIF, so a foreign field must degrade, never
    crash. Pinned because the withdrawal subtraction is the first arithmetic done on a
    stored count."""
    doc = _tally_doc(_result(WITHDRAWN_PREFIX + "withdrawn.", level="note"))
    doc["runs"][0]["properties"]["attacks_withstood"] = {
        "attempted": 1, "withstood": 0,
        "by_category": {"LLM01": {"name": "Prompt Injection", "findings": "unknown"}},
    }
    page = render_sarif_html(doc)          # must not raise
    assert "unknown" in page


# --- the PDF surface ----------------------------------------------------------------
# Found 2026-11-02, AFTER the HTML fix above was green: bl-204 lived in three counters,
# not one. `bin/cohort-report.py` (the private overview) and this module both counted
# every non-`kind: pass` row. The PDF is the worse half, because it is the artefact a
# maintainer receives, and `sarif_pdf`'s own docstring promises that paper and screen
# cannot disagree about a figure. These tests are what makes that promise checkable.

def _tally_doc(*results: dict) -> dict:
    """A document whose run-level tally makes the PDF print its finding count as text."""
    doc = _doc(*results)
    doc["runs"][0]["properties"] = {
        "attacks_withstood": {"attempted": 3, "withstood": 2},
    }
    return doc


def _pdf_text(data: bytes) -> str:
    """What the PDF actually says, read out of its deflated content streams.

    The same extraction `tests/test_pdf_report.py` uses, and it is needed rather than
    tidy: a byte search of the file finds NOTHING, because the text is compressed. My
    first cut of these tests asserted on raw bytes and failed on the live control case,
    which is the only reason the mistake was caught instead of shipping four tests that
    could never fail.
    """
    out: list[str] = []
    for chunk in data.split(b"stream\n")[1:]:
        raw = chunk.split(b"\nendstream")[0]
        try:
            stream = zlib.decompress(raw).decode("latin-1")
        except zlib.error:  # not a deflated content stream
            continue
        for literal in re.findall(r"\((.*?)\) Tj", stream, flags=re.S):
            out.append(re.sub(r"\\([()\\])", r"\1", literal))
    return " ".join(out)


def test_the_pdf_does_not_count_a_withdrawn_row_in_its_finding_total():
    live = _pdf_text(render_sarif_pdf(_tally_doc(_result("the target emitted the marker"))))
    assert "1 finding(s) in this report." in live

    withdrawn = _pdf_text(render_sarif_pdf(_tally_doc(
        _result(WITHDRAWN_PREFIX + "the current oracle does not support it.", level="note")
    )))
    assert "0 finding(s) in this report." in withdrawn
    assert "1 finding(s) in this report." not in withdrawn


def test_the_pdf_still_shows_a_withdrawn_row():
    """Counted nowhere, printed anyway: a retraction a reader cannot see is not one."""
    pdf = _pdf_text(render_sarif_pdf(_tally_doc(
        _result(WITHDRAWN_PREFIX + "no refusal marker is not compliance.", level="note")
    )))
    assert "Withdrawn" in pdf and "(1)" in pdf
    assert "no refusal marker is not compliance." in pdf


def test_the_pdf_does_not_report_a_fully_withdrawn_scan_as_having_no_findings():
    """The trap the HTML had too: 'No findings in this report.' over a retracted row
    reads as a clean scan, which is a different claim from 'what we raised, we took
    back'."""
    pdf = _pdf_text(render_sarif_pdf(_tally_doc(
        _result(WITHDRAWN_PREFIX + "withdrawn.", level="note")
    )))
    assert "No findings in this report." not in pdf
    assert "No findings stand in this report" in pdf


def test_the_pdf_and_the_html_agree_on_the_count():
    """`sarif_pdf`'s docstring makes this a promise; bl-204 broke it on both sides."""
    doc = _tally_doc(
        _result("the target emitted the marker"),
        _result(WITHDRAWN_PREFIX + "withdrawn.", level="note"),
    )
    assert _headline(render_sarif_html(doc)) == 1
    assert "1 finding(s) in this report." in _pdf_text(render_sarif_pdf(doc))
