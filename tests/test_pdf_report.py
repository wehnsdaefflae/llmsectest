"""The PDF report: a valid file, and an honest one in the order it puts things.

Two halves. The mechanical half is that we emit a PDF a reader can actually open, which
matters more here than usual because we write the bytes ourselves rather than handing the
job to a library. The half that carries the argument is **order**: a reader who stops
after page one must not come away with "no findings" from a run that never reached its
target, so the undelivered notice is asserted to precede the findings rather than merely
to exist.

Nothing here shells out to a PDF reader. The suite may not depend on poppler being
installed, so structure is asserted against the format itself and the content is read back
out of the deflated streams. A one-off check against poppler is recorded in the worklog
instead, which is the right place for a measurement taken once.
"""

from __future__ import annotations

import json
import re
import zlib
from pathlib import Path

import pytest

from llmsectest.reporting.pdf import PDFDocument, text_width, wrap
from llmsectest.reporting.sarif_pdf import render_sarif_pdf, render_sarif_pdf_file

FIXTURES = Path(__file__).parent / "fixtures"


def _streams(data: bytes) -> list[str]:
    """Every content stream in the file, inflated, in page order."""
    out = []
    for chunk in data.split(b"stream\n")[1:]:
        raw = chunk.split(b"\nendstream")[0]
        try:
            out.append(zlib.decompress(raw).decode("latin-1"))
        except zlib.error:  # not a deflated content stream
            continue
    return out


def _text(data: bytes) -> str:
    """What the page actually says, with the drawn lines joined back into prose.

    Each wrapped line is its own ``(...) Tj``, so searching the raw stream for a sentence
    finds nothing the moment it wraps. Joining the literals with a space is what a reader
    effectively does, and it keeps the assertions about content rather than about where
    the wrap happened to fall.
    """
    out = []
    for stream in _streams(data):
        for chunk in re.findall(r"\((.*?)\) Tj", stream, flags=re.S):
            out.append(re.sub(r"\\([()\\])", r"\1", chunk))
    return " ".join(out)


def _doc(**props) -> dict:
    return {
        "runs": [{
            "tool": {"driver": {"name": "llmsectest", "version": "0.2.0"}},
            "properties": props,
            "results": [],
        }]
    }


def _finding_doc(**props) -> dict:
    doc = _doc(**props)
    doc["runs"][0]["results"] = [{
        "ruleId": "LLM02-direct",
        "message": {"text": "The application returned the planted credential verbatim."},
        "properties": {"security-severity": "8.7"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "suite/test_llm02.py"}}}],
    }]
    return doc


# --- the file is a file -------------------------------------------------------------

def test_the_output_is_a_structurally_complete_pdf():
    data = render_sarif_pdf(_finding_doc(), source_name="x.sarif")
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip().endswith(b"%%EOF")
    assert b"/Type /Catalog" in data
    assert b"/Type /Pages" in data
    assert b"/Type /Page " in data
    # The cross-reference table has to declare exactly as many objects as exist, or a
    # reader rebuilds the file and some refuse it outright.
    body = data.split(b"xref\n")[1]
    declared = int(body.split(b"\n")[0].split()[1])
    assert data.count(b" 0 obj\n") == declared - 1


def test_a_long_report_paginates_rather_than_running_off_the_page():
    rules = [{"id": f"case-{i}", "name": f"Probe case {i}"} for i in range(60)]
    doc = _doc()
    doc["runs"][0]["tool"]["driver"]["rules"] = rules
    doc["runs"][0]["results"] = [
        {"ruleId": r["id"], "message": {"text": "A planted instruction was obeyed. " * 6},
         "properties": {"security-severity": "7.5"}}
        for r in rules
    ]
    data = render_sarif_pdf(doc)
    assert data.count(b"/Type /Page ") > 3


def test_every_page_declares_the_fonts_it_draws_with():
    """A page whose resources omit a font it uses renders blank in a strict reader."""
    data = render_sarif_pdf(_finding_doc())
    pages = data.count(b"/Type /Page ")
    assert pages >= 1
    assert data.count(b"/Helvetica-Bold") >= 1
    for used in (b"/Helvetica ", b"/Helvetica-Bold ", b"/Courier "):
        assert data.count(used) >= pages, used


# --- the order is the argument ------------------------------------------------------

def test_the_undelivered_notice_precedes_the_findings():
    """Order is a claim. A reader who stops early must not take this for a clean run."""
    doc = _finding_doc(undelivered={"count": 3, "reasons": ["endpoint unreachable"]})
    text = _text(render_sarif_pdf(doc))
    assert "did not reach its target" in text
    assert text.index("did not reach its target") < text.index("planted credential")


def test_no_findings_plus_undelivered_probes_does_not_read_as_a_pass():
    doc = _doc(undelivered={"count": 4, "reasons": ["429 rate limited"]})
    text = _text(render_sarif_pdf(doc))
    assert "did not reach its target" in text
    assert "see the undelivered notice above" in text
    # And the bare claim never appears on its own.
    assert "No findings in this report." not in text


def test_a_genuinely_clean_run_is_allowed_to_say_so():
    """The counterpart, so the rule above is a rule rather than a permanent warning."""
    text = _text(render_sarif_pdf(_doc(attacks_withstood={"attempted": 12, "withstood": 12})))
    assert "No findings in this report." in text
    assert "did not reach its target" not in text


def test_inconclusive_probes_are_carried_into_the_pdf():
    """They are errored, so they are in no findings list. Dropping them here would be
    the one defect this project publishes reports about, in a new file format."""
    text = _text(render_sarif_pdf(_finding_doc(inconclusive={"count": 36})))
    assert "36 probe(s) could not be concluded" in text


def test_a_secret_that_came_back_invalidates_the_clean_row_on_paper_too():
    text = _text(render_sarif_pdf(_finding_doc(secret_exposed={"count": 32})))
    assert "does not mean the secret was protected" in text


def test_the_load_verdicts_reach_the_pdf_with_their_bound():
    doc = _finding_doc(stress={"cases": 17, "verdicts": {"held": 12, "regressed": 1}})
    text = _text(render_sarif_pdf(doc))
    assert "held 12" in text and "regressed 1" in text
    assert "bounded by the concurrency the run actually reached" in text


# --- text measurement ---------------------------------------------------------------

def test_wrapping_uses_real_glyph_widths_rather_than_a_character_count():
    """`iiii` and `MMMM` are the same length and nothing like the same width."""
    assert text_width("MMMM", "Helvetica", 10) > text_width("iiii", "Helvetica", 10) * 3
    # Courier is monospaced, so there the character count *is* the width.
    assert text_width("MMMM", "Courier", 10) == pytest.approx(
        text_width("iiii", "Courier", 10))


def test_every_wrapped_line_fits_the_width_it_was_given():
    text = "The application disclosed a verbatim span of its system prompt " * 4
    for line in wrap(text, "Helvetica", 10, 200):
        assert text_width(line, "Helvetica", 10) <= 200


def test_an_unbreakable_token_is_broken_rather_than_lost_off_the_page():
    """A canary, a base64 blob or a URL is exactly what a reader needs in full."""
    canary = "CANARY-" + "a1b2c3d4" * 12
    lines = wrap(canary, "Courier", 9, 150)
    assert len(lines) > 1
    assert "".join(lines) == canary
    for line in lines:
        assert text_width(line, "Courier", 9) <= 150


def test_a_character_the_base_fonts_cannot_draw_is_visibly_replaced():
    """Silently drawing a different glyph in a security report is the worse failure."""
    doc = _finding_doc()
    doc["runs"][0]["results"][0]["message"]["text"] = "leaked 日本語 and a plain tail"
    text = _text(render_sarif_pdf(doc))
    assert "and a plain tail" in text
    assert "日本語" not in text


def test_a_parenthesis_in_a_finding_cannot_break_the_file():
    """An unescaped ( or \\ in a PDF literal corrupts every byte after it."""
    doc = _finding_doc()
    doc["runs"][0]["results"][0]["message"]["text"] = r"payload (unbalanced and a \ slash"
    data = render_sarif_pdf(doc)
    assert data.rstrip().endswith(b"%%EOF")
    # Escaped on the way in, so the literal cannot swallow the rest of the stream...
    assert r"\(unbalanced" in "\n".join(_streams(data))
    # ...and unescaped on the way back out, so nothing the reader needs was dropped.
    assert "(unbalanced and a \\ slash" in _text(data)


# --- third-party input and the file API ---------------------------------------------

@pytest.mark.parametrize("name", ["ruff-0.15.15", "bandit-1.9.4", "semgrep-1.172.0"])
def test_a_third_party_sarif_renders(name):
    """The same promise `--render-sarif` makes: any SARIF v2.1.0, ours or not."""
    doc = json.loads((FIXTURES / f"{name}.sarif").read_text(encoding="utf-8"))
    data = render_sarif_pdf(doc, source_name=f"{name}.sarif")
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip().endswith(b"%%EOF")


def test_a_malformed_run_is_skipped_rather_than_fatal():
    doc = {"runs": [{"tool": "not-an-object", "results": ["not-an-object", 7]}]}
    assert render_sarif_pdf(doc).startswith(b"%PDF-1.4")


def test_render_to_file_defaults_beside_the_input(tmp_path):
    src = tmp_path / "scan.sarif"
    src.write_text(json.dumps(_finding_doc()), encoding="utf-8")
    written = render_sarif_pdf_file(src)
    assert written == tmp_path / "scan.pdf"
    assert written.read_bytes().startswith(b"%PDF-1.4")


def test_an_empty_document_still_produces_a_page():
    """A reader opening a zero-page PDF sees an error, which reads as our bug."""
    data = PDFDocument(title="empty").build()
    assert data.count(b"/Type /Page ") == 1
