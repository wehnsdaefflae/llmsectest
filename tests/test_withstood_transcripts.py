"""A withstood probe leaves a transcript in the SARIF, not only a tally (issue #21).

The report of a defended target used to carry one row per finding and nothing else, so
an application that withstood 27 of 32 probes produced five rows and a number. A reader
asking *what did it say when it refused* had nothing to read, and the refusal-content
axis could not be calibrated against our own reports.

The rule these tests pin is the one the issue states: N withstood probes produce N rows,
each carrying the reply it withstood. The rows must not be mistaken for findings — a
consumer that counts results as vulnerabilities would otherwise turn every defence into
a defect — so they are ``kind: pass`` / ``level: none`` and carry a marker property.
"""

from __future__ import annotations

import json

from llmsectest.reporting.models import TestResult
from llmsectest.reporting.sarif_generator import SARIFGenerator
from llmsectest.reporting.sarif_html import render_sarif_html


def _probe(name: str, outcome: str, marker: str, *, reply: str | None = None) -> TestResult:
    properties = {"llmsec_probe": marker}
    if reply is not None:
        properties["llmsec_reply"] = reply
    return TestResult(
        nodeid=f"suite/test_probe.py::{name}",
        location=("suite/test_probe.py", 12, name),
        outcome=outcome,
        markers=[marker, "high"],
        properties=properties,
    )


def test_n_withstood_probes_produce_n_transcript_rows():
    results = [
        _probe("held-1", "passed", "owasp_llm01", reply="I'm sorry, I can't help with that."),
        _probe("held-2", "passed", "owasp_llm01", reply="I won't reveal that."),
        _probe("held-3", "passed", "owasp_llm02", reply="No."),
        _probe("found", "failed", "owasp_llm01"),
    ]
    doc = json.loads(SARIFGenerator("llmsectest", "0.1.0", source_root=".").generate(results))
    rows = doc["runs"][0]["results"]

    transcripts = [r for r in rows if r["properties"].get("llmsec_withstood")]
    assert len(transcripts) == 3
    assert {r["properties"]["reply"] for r in transcripts} == {
        "I'm sorry, I can't help with that.",
        "I won't reveal that.",
        "No.",
    }
    # A withstood row is evidence of a defence, never a finding.
    assert all(r["kind"] == "pass" for r in transcripts)
    assert all(r["level"] == "none" for r in transcripts)
    assert all(r["properties"]["test_outcome"] == "passed" for r in transcripts)


def test_the_transcript_count_agrees_with_the_attacks_tally():
    results = [
        _probe("held", "passed", "owasp_llm01", reply="I can't help."),
        _probe("found", "failed", "owasp_llm01"),
        _probe("lost", "passed", "owasp_llm02", reply=""),
    ]
    results[2].properties["llmsec_inconclusive"] = "timed out"
    doc = json.loads(SARIFGenerator("llmsectest", "0.1.0", source_root=".").generate(results))
    run = doc["runs"][0]
    transcripts = [r for r in run["results"] if r["properties"].get("llmsec_withstood")]
    assert len(transcripts) == run["properties"]["attacks_withstood"]["withstood"] == 1


def test_a_long_reply_is_capped_and_the_cap_is_disclosed():
    from llmsectest.reporting.sarif_generator import WITHSTOOD_REPLY_LIMIT

    reply = "x" * (WITHSTOOD_REPLY_LIMIT + 50)
    doc = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", source_root=".").generate([
            _probe("held", "passed", "owasp_llm01", reply=reply),
        ])
    )
    row = doc["runs"][0]["results"][0]
    assert len(row["properties"]["reply"]) == WITHSTOOD_REPLY_LIMIT
    assert row["properties"]["reply_truncated"] is True
    assert row["properties"]["reply_characters"] == len(reply)


def test_the_html_does_not_count_withstood_transcripts_as_findings():
    doc = json.loads(
        SARIFGenerator("llmsectest", "0.1.0", source_root=".").generate([
            _probe("held", "passed", "owasp_llm01", reply="I cannot help with that."),
        ])
    )
    page = render_sarif_html(doc, source_name="defended-app")
    assert "No findings in this report" in page
    assert "I cannot help with that." in page
    assert "Withstood probe replies" in page
