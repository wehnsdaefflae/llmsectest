"""Unit tests for the SARIF -> standalone HTML renderer."""

from __future__ import annotations

import json

from llmsectest.reporting import render_sarif_file, render_sarif_html


def _doc(results, rules):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "llmsectest", "version": "0.1.0", "rules": rules}},
            "results": results,
        }],
    }


_RULE_LLM01 = {
    "id": "r1",
    "name": "test_prompt_injection[LLM01-x]",
    "fullDescription": {"text": "Prompt injection description."},
    "help": {"text": "Mitigate by validating input."},
    "properties": {
        "owasp-category": "LLM01", "owasp-name": "Prompt Injection",
        "cvss_base_score": 9.2, "cvss_base_severity": "Critical",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L", "security-severity": "9.2",
        "cwe": ["CWE-77"],
    },
}
_RESULT_LLM01 = {
    "ruleId": "r1", "level": "error",
    "message": {"text": "target obeyed the injected instruction: PWNED"},
    "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "suite/test_llm01.py"}, "region": {"startLine": 18}}}],
    "fixes": [{"description": {"text": "Validate and sanitize prompts"}}],
}


def test_renders_a_finding_with_its_metadata():
    html = render_sarif_html(_doc([_RESULT_LLM01], [_RULE_LLM01]), source_name="demo.sarif")
    assert html.startswith("<!DOCTYPE html>")
    assert html.rstrip().endswith("</html>")
    assert "LLM01 Prompt Injection" in html          # category grouping header
    assert "CVSS 9.2" in html                          # severity badge with score
    assert "sev-critical" in html                      # severity class
    assert "suite/test_llm01.py:18" in html            # location
    assert "Validate and sanitize prompts" in html     # remediation
    assert "demo.sarif" in html                        # source name in the meta line


def test_groups_by_owasp_and_counts_in_summary():
    rule2 = {**_RULE_LLM01, "id": "r2",
             "properties": {**_RULE_LLM01["properties"],
                            "owasp-category": "LLM10", "owasp-name": "Unbounded Consumption",
                            "cvss_base_score": 8.7, "cvss_base_severity": "High"}}
    res2 = {**_RESULT_LLM01, "ruleId": "r2", "message": {"text": "runaway output"}}
    html = render_sarif_html(_doc([_RESULT_LLM01, res2], [_RULE_LLM01, rule2]))
    assert html.count('class="cat"') == 2              # two category sections
    assert "LLM10 Unbounded Consumption" in html
    assert 'class="big">2</span>' in html and "findings" in html   # summary total


def test_clean_report_shows_empty_state():
    html = render_sarif_html(_doc([], [_RULE_LLM01]))
    assert "No findings" in html
    assert 'class="big">0</span>' in html


def test_escapes_html_in_messages():
    nasty = {**_RESULT_LLM01, "message": {"text": "<script>alert(1)</script>"}}
    html = render_sarif_html(_doc([nasty], [_RULE_LLM01]))
    assert "<script>alert(1)</script>" not in html      # raw payload must be escaped
    assert "&lt;script&gt;" in html


def test_third_party_sarif_without_owasp_props_degrades_gracefully():
    rule = {"id": "x", "name": "some-other-rule",
            "defaultConfiguration": {"level": "warning"}}
    result = {"ruleId": "x", "level": "warning", "message": {"text": "a generic finding"}}
    html = render_sarif_html(_doc([result], [rule]))
    assert "Other" in html                              # no OWASP category -> "Other"
    assert "sev-medium" in html                         # level=warning -> medium
    assert "a generic finding" in html


def test_renders_per_finding_output_token_cost():
    """A finding carrying an ``output_tokens`` cost shows it as a badge; the
    run-level denial-of-wallet total appears in the header meta line."""
    costly = dict(_RESULT_LLM01, properties={"output_tokens": 512})
    doc = _doc([costly], [_RULE_LLM01])
    doc["runs"][0]["properties"] = {
        "denial_of_wallet": {"probes_with_usage": 3, "total_output_tokens": 640,
                             "peak_output_tokens": 512, "mean_output_tokens": 213.3}
    }
    html = render_sarif_html(doc)
    assert "512 output tokens" in html                 # per-finding cost badge
    assert "640 output tokens (3 probes)" in html      # run-level total in the meta line


def test_render_sarif_file_writes_html(tmp_path):
    src = tmp_path / "scan.sarif"
    src.write_text(json.dumps(_doc([_RESULT_LLM01], [_RULE_LLM01])), encoding="utf-8")
    out = render_sarif_file(src)
    assert out == src.with_suffix(".html")
    assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

    explicit = render_sarif_file(src, tmp_path / "sub" / "report.html")
    assert explicit.exists()  # parent dir created
