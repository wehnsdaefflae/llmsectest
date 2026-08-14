"""Unit tests for the SARIF -> standalone HTML renderer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from llmsectest.reporting import render_sarif_file, render_sarif_html
from llmsectest.reporting.sarif_html import _title_of

_FIXTURES = Path(__file__).parent / "fixtures"


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


def test_renders_inconclusive_probe_count():
    """A run-level ``inconclusive`` tally (probes that exceeded --app-timeout) shows in the
    header meta line, so a clean-looking report never hides that some probes under-ran."""
    doc = _doc([_RESULT_LLM01], [_RULE_LLM01])
    doc["runs"][0]["properties"] = {
        "inconclusive": {"count": 5, "reasons": ["probe inconclusive — timeout"]}
    }
    html = render_sarif_html(doc)
    assert "5 probe(s) inconclusive" in html            # run-level inconclusive tally


def test_renders_the_slowest_probe_beside_the_inconclusive_count():
    """The peak latency belongs next to the timeout count: they are one measurement
    either side of the budget, and only the peak says how close a clean run came."""
    doc = _doc([_RESULT_LLM01], [_RULE_LLM01])
    doc["runs"][0]["properties"] = {
        "inconclusive": {"count": 1, "reasons": ["APP-x-LLM02-direct [direct]: timeout"]},
        "latency": {"probes_measured": 32, "total_seconds": 210.4, "peak_seconds": 88.0,
                    "peak_probe": "APP-x-LLM02-handover-summary", "mean_seconds": 6.6},
    }
    html = render_sarif_html(doc)
    assert "slowest probe 88s" in html


def test_a_malformed_latency_property_does_not_break_the_render():
    """Same contract as every other run property: a foreign or truncated file may put
    anything here, and losing the whole report over one meta field is the worse failure."""
    doc = _doc([_RESULT_LLM01], [_RULE_LLM01])
    doc["runs"][0]["properties"] = {"latency": "88s"}
    assert "slowest probe" not in render_sarif_html(doc)


# --- robustness on malformed / foreign SARIF ----------------------------------
# The renderer's contract is to display *any* tool's SARIF and let missing fields
# "degrade gracefully". A third-party (or hand-written / truncated) file can put
# the wrong JSON type where the spec wants an object/array; none of these may crash
# the whole render — the whole report would be lost for one malformed field.

def _run(results, *, rules=None, driver=None):
    d = driver if driver is not None else {"name": "some-scanner", "version": "9", "rules": rules or []}
    return {"runs": [{"tool": {"driver": d}, "results": results}]}


_MALFORMED_DOCS = {
    "doc-not-a-dict": "not-a-sarif-doc",
    "runs-not-a-list": {"runs": {"k": "v"}},
    "run-not-a-dict": {"runs": ["a bare string where a run object belongs"]},
    "tool-not-a-dict": {"runs": [{"tool": "x", "results": []}]},
    "results-null": _run(None),                       # clean report emitting null, not []
    "results-a-dict": _run({"0": "x"}),
    "result-item-not-a-dict": _run(["stringresult", 5, None]),
    "message-a-string": _run([{"ruleId": "r", "message": "flat string"}]),
    "locations-not-a-list": _run([{"ruleId": "r", "locations": "x", "message": {"text": "m"}}]),
    "location-item-not-a-dict": _run([{"ruleId": "r", "locations": ["x"], "message": {"text": "m"}}]),
    "fixes-not-a-list": _run([{"ruleId": "r", "message": {"text": "m"}, "fixes": "x"}]),
    "defaultConfiguration-a-string":
        _run([{"ruleId": "r", "message": {"text": "m"}}],
             rules=[{"id": "r", "defaultConfiguration": "warning"}]),
    "rule-fields-wrong-type":
        _run([{"ruleId": "r", "message": {"text": "m"}}],
             rules=[{"id": "r", "fullDescription": "s", "help": [], "shortDescription": 3}]),
}


@pytest.mark.parametrize("name,doc", list(_MALFORMED_DOCS.items()), ids=list(_MALFORMED_DOCS))
def test_malformed_sarif_shapes_render_without_crashing(name, doc):
    html = render_sarif_html(doc, source_name=f"{name}.sarif")
    assert html.startswith("<!DOCTYPE html>")          # a full, valid page …
    assert html.rstrip().endswith("</html>")            # … not a partial / traceback


def test_third_party_results_null_renders_clean_empty_state():
    """A scanner that emits ``"results": null`` for a clean run (instead of ``[]``)
    must render the clean empty state, not crash on iterating None."""
    html = render_sarif_html(_run(None))
    assert "No findings" in html
    assert 'class="big">0</span>' in html


def test_single_string_cwe_is_not_split_into_characters():
    """A bare-string ``cwe`` (some tools emit one CWE, not a list) renders intact,
    not iterated as 'C, W, E, -, 7, 7'."""
    rule = {"id": "r", "name": "rule", "properties": {"cwe": "CWE-77"}}
    html = render_sarif_html(_run([{"ruleId": "r", "message": {"text": "m"}}], rules=[rule]))
    assert "CWE-77" in html
    assert "C, W, E" not in html


def test_string_message_degrades_but_finding_still_renders():
    """A non-object ``message`` loses its text but the finding card still appears
    (titled by its ruleId), rather than taking down the render."""
    html = render_sarif_html(_run([{"ruleId": "flat-msg-rule", "message": "flat string"}]))
    assert "flat-msg-rule" in html                      # finding still rendered
    assert 'class="big">1</span>' in html               # counted as one finding


def test_non_dict_results_are_skipped_not_ghost_findings():
    """Only object results become findings; scalars/None in the results array are
    dropped, never rendered as empty ghost cards or double-counted."""
    doc = _run(["junk", 42, None, {"ruleId": "real", "message": {"text": "a real one"}}])
    html = render_sarif_html(doc)
    assert 'class="big">1</span>' in html               # exactly the one dict result
    assert "a real one" in html


# --- interop against a genuine external tool's SARIF --------------------------
# The malformed-shape tests above are synthetic. This one renders a *real* file
# emitted by an external tool (ruff 0.15.15; see tests/fixtures/README.md), proving
# the "render any tool's SARIF" claim against output whose shape we did not design:
# no OWASP category, no CVSS security-severity, and the human rule name under
# ``properties.name`` rather than the top-level ``name``.

def test_renders_real_ruff_sarif_end_to_end():
    doc = json.loads((_FIXTURES / "ruff-0.15.15.sarif").read_text(encoding="utf-8"))
    html = render_sarif_html(doc, source_name="ruff-0.15.15.sarif")

    # A full, valid page — not a partial render or a traceback.
    assert html.startswith("<!DOCTYPE html>")
    assert html.rstrip().endswith("</html>")

    # The foreign tool identity is surfaced in the meta line.
    assert "ruff" in html and "0.15.15" in html

    # All four findings counted; no OWASP metadata -> grouped under "Other".
    assert 'class="big">4</span>' in html
    assert "Other" in html
    assert "LLM0" not in html  # nothing miscategorised into an OWASP bucket

    # ruff carries no security-severity, so severity falls back to the SARIF level
    # (error -> high).
    assert "sev-high" in html

    # The human-readable rule name lives under properties.name for ruff; the renderer
    # must prefer it over the terse rule id in both the finding card and the glossary.
    assert "unused-import" in html      # F401 card title (not just "F401")
    assert "none-comparison" in html    # E711 glossary entry (not just "E711")

    # A real ruff fix description renders as remediation, and the normalized location
    # (relative, machine-path-free) shows through.
    assert "Remove unused import" in html
    assert "sample_module.py:2" in html

    # The committed fixture must never carry a local absolute path.
    assert "/home/" not in html and "file://" not in html


def test_render_sarif_file_on_real_ruff_fixture(tmp_path):
    """The file entry point renders the real third-party fixture to disk too."""
    out = render_sarif_file(_FIXTURES / "ruff-0.15.15.sarif", tmp_path / "ruff.html")
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert "ruff" in page and "unused-import" in page


# --- CWE from the GitHub tag convention --------------------------------------
# Security scanners commonly encode CWE not in an explicit ``properties.cwe`` (as
# we do) but as an ``external/cwe/cwe-NNN`` entry in ``properties.tags`` (the
# GitHub code-scanning convention). The renderer surfaces both.

def test_github_cwe_tag_convention_resolves():
    """A CWE encoded only as an ``external/cwe/cwe-NNN`` tag is surfaced as CWE-NNN."""
    rule = {"id": "r", "name": "sqli",
            "properties": {"tags": ["security", "external/cwe/cwe-89"]}}
    html = render_sarif_html(_run([{"ruleId": "r", "message": {"text": "m"}}], rules=[rule]))
    assert "CWE-89" in html
    # The raw tag string is not what shows up in the CWE line.
    assert "external/cwe" not in html


def test_non_cwe_tags_do_not_become_cwes():
    """A finding with an explicit CWE plus unrelated semantic tags (as our own
    reports carry) shows exactly that CWE — a tag like 'injection' is never
    mistaken for one, so our own output is unchanged."""
    rule = {"id": "r", "name": "rule", "properties": {
        "cwe": ["CWE-77"], "tags": ["owasp_llm01", "injection", "jailbreak"]}}
    html = render_sarif_html(_run([{"ruleId": "r", "message": {"text": "m"}}], rules=[rule]))
    cwe_span = html.split('class="cwe">', 1)[1].split("</span>", 1)[0]
    assert cwe_span == "CWE-77"


# --- interop against a second genuine external tool (a real *security* scanner) -
# ruff (above) is a linter with no CWE; Bandit is a security scanner whose SARIF
# attaches CWE via the tag convention, not an explicit field. See fixtures/README.

def test_renders_real_bandit_sarif_end_to_end():
    doc = json.loads((_FIXTURES / "bandit-1.9.4.sarif").read_text(encoding="utf-8"))
    html = render_sarif_html(doc, source_name="bandit-1.9.4.sarif")

    # A full, valid page for a foreign security scanner.
    assert html.startswith("<!DOCTYPE html>")
    assert html.rstrip().endswith("</html>")
    assert "Bandit" in html and "1.9.4" in html

    # All five findings; no OWASP metadata -> grouped under "Other".
    assert 'class="big">5</span>' in html
    assert "Other" in html

    # CWE resolved from the ``external/cwe/cwe-NNN`` tags Bandit emits, canonicalised.
    assert "CWE-78" in html    # subprocess shell=True / eval
    assert "CWE-259" in html   # hardcoded password
    assert "CWE-327" in html   # weak MD5 hash
    assert "external/cwe" not in html   # the raw tag never leaks into the page

    # Severity falls back to the SARIF level Bandit sets (error -> high).
    assert "sev-high" in html
    # Normalized, machine-path-free location shows through.
    assert "sample_vuln.py:10" in html
    assert "/home/" not in html and "file://" not in html


def test_render_sarif_file_on_real_bandit_fixture(tmp_path):
    """The file entry point renders the real Bandit fixture to disk with its CWEs."""
    out = render_sarif_file(_FIXTURES / "bandit-1.9.4.sarif", tmp_path / "bandit.html")
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert "Bandit" in page and "CWE-327" in page


def test_render_sarif_file_writes_html(tmp_path):
    src = tmp_path / "scan.sarif"
    src.write_text(json.dumps(_doc([_RESULT_LLM01], [_RULE_LLM01])), encoding="utf-8")
    out = render_sarif_file(src)
    assert out == src.with_suffix(".html")
    assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

    explicit = render_sarif_file(src, tmp_path / "sub" / "report.html")
    assert explicit.exists()  # parent dir created


# --- interop against a third genuine external tool, and the CWE convention it uses -
# ruff carries no CWE at all; Bandit uses the GitHub ``external/cwe/cwe-NNN`` tag.
# Semgrep is a third convention again: a *descriptive* tag whose text begins with the
# id, e.g. "CWE-95: Improper Neutralization of Directives ...". It also settles a
# question the backlog carried since 2026-07-24 — whether the SARIF
# ``run.taxonomies`` / ``result.taxa`` path is how scanners attach CWE in practice.
# Semgrep OSS 1.172.0 emits neither key, so that path stays unimplemented rather than
# written from the spec. See fixtures/README.md for the exact regeneration command.

def _semgrep_doc() -> dict:
    return json.loads((_FIXTURES / "semgrep-1.172.0.sarif").read_text(encoding="utf-8"))


def test_renders_real_semgrep_sarif_end_to_end():
    html = render_sarif_html(_semgrep_doc(), source_name="semgrep-1.172.0.sarif")

    assert html.startswith("<!DOCTYPE html>")
    assert html.rstrip().endswith("</html>")
    assert "Semgrep OSS" in html and "1.172.0" in html

    # Three findings, no OWASP metadata -> grouped under "Other".
    assert 'class="big">3</span>' in html
    assert "Other" in html

    # CWE read out of Semgrep's descriptive tag, canonicalised to the bare id.
    assert "CWE-78" in html    # subprocess shell=True
    assert "CWE-95" in html    # eval
    assert "CWE-798" in html and "CWE-259" in html  # both ids on one rule
    # The descriptive remainder of the tag is not smuggled into the CWE chip.
    assert "Improper Neutralization" not in html.split('class="cwe">', 1)[1][:200]

    # Severity from the SARIF level Semgrep sets (error -> high, warning -> medium).
    assert "sev-high" in html and "sev-medium" in html
    assert "semgrep_sample_vuln.py:" in html
    assert "/home/" not in html and "file://" not in html


def test_semgrep_fixture_carries_no_taxonomies():
    """Guards the claim above: if a future regeneration starts emitting taxa, this
    fails and the renderer owes that path an implementation."""
    run = _semgrep_doc()["runs"][0]
    assert "taxonomies" not in run
    assert all("taxa" not in r for r in run["results"])


def test_namespaced_rule_id_is_titled_by_its_last_segment():
    """Semgrep names a rule after its id, and the id is namespaced by the config it
    came from, so the raw heading read 'tests.fixtures.python-eval-of-request-data'."""
    html = render_sarif_html(_semgrep_doc())
    assert 'class="f-title">python-eval-of-request-data<' in html
    assert "tests.fixtures.python-eval" not in html


def test_a_rule_name_that_differs_from_the_id_is_never_shortened():
    """Only ids are shortened. A name the tool wrote for humans may contain a dot and
    must survive whole, or Bandit-style names would silently lose their first half."""
    assert _title_of({}, {"id": "R1", "name": "Use of eval. Avoid it."}) == "Use of eval. Avoid it."
    assert _title_of({}, {"id": "a.b.c", "name": "a.b.c"}) == "c"
    assert _title_of({"ruleId": "x.y"}, {}) == "y"
    assert _title_of({}, {}) == "finding"


def test_render_sarif_file_on_real_semgrep_fixture(tmp_path):
    """The file entry point renders the real Semgrep fixture to disk with its CWEs."""
    out = render_sarif_file(_FIXTURES / "semgrep-1.172.0.sarif", tmp_path / "semgrep.html")
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert "Semgrep OSS" in page and "CWE-95" in page
