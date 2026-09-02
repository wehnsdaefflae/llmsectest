"""Render a SARIF report to PDF, from the same data the HTML reader uses.

The two renderers read one SARIF and share every extraction helper in
:mod:`~llmsectest.reporting.sarif_html`, so a figure cannot say one thing on screen and
another on paper. That sharing is the point rather than a convenience: this project has
twice published two independently-computed views of one fact that disagreed, and a second
report format is exactly the shape that defect takes next.

**Order is a claim here.** The undelivered banner, the inconclusive count and the
withstood tally are laid out **before** the findings, because a reader who stops after
page one must not come away with "no findings" from a run that never reached its target.
The HTML page makes that argument with a red banner at the top; paper has no colour
guarantee and no scrolling, so here it is made with pagination.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .pdf import PDFDocument
from .sarif_html import (
    _as_dict,
    _as_list,
    _location_of,
    _owasp_of,
    _props,
    _rule_index,
    _score_of,
    _severity_of,
    _title_of,
)

#: Ink for each severity, dark enough to stay legible printed in greyscale.
_SEVERITY_INK = {
    "critical": (0.55, 0.05, 0.10),
    "high": (0.70, 0.25, 0.02),
    "medium": (0.55, 0.42, 0.00),
    "low": (0.20, 0.35, 0.55),
    "info": (0.35, 0.35, 0.35),
}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_OWASP_ORDER = {f"LLM{n:02d}": n for n in range(1, 11)}
_GREY = (0.42, 0.42, 0.42)


def _fmt(value: object) -> str:
    return "" if value is None else str(value)


def render_sarif_pdf(doc: dict, *, source_name: str | None = None,
                     generated: str | None = None) -> bytes:
    """Render a parsed SARIF document into a PDF file (bytes)."""
    runs = _as_list(doc.get("runs")) if isinstance(doc, dict) else []
    first_run = _as_dict(runs[0]) if runs else {}
    driver = _as_dict(_as_dict(first_run.get("tool")).get("driver"))
    tool = f"{driver.get('name', 'unknown tool')} {driver.get('version', '')}".strip()

    findings: list[tuple[dict, dict]] = []
    for run in runs:
        run = _as_dict(run)
        rules = _rule_index(run)
        for result in _as_list(run.get("results")):
            if isinstance(result, dict):
                findings.append((result, rules.get(result.get("ruleId"), {})))

    generated = generated or datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    props = _props(first_run)
    pdf = PDFDocument(title=f"LLMSecTest report {source_name or ''}".strip(),
                      author="LLMSecTest")

    pdf.text("LLMSecTest", font="Helvetica-Bold", size=20)
    pdf.text("SARIF security report", font="Helvetica", size=12, color=_GREY)
    pdf.space(6)
    meta = " · ".join(b for b in (tool, source_name, generated) if b)
    pdf.paragraph(meta, size=8.5, color=_GREY)
    pdf.rule()
    pdf.space(6)

    # --- what may not be read as a pass, before anything that could be -------------
    undelivered = props.get("undelivered")
    if isinstance(undelivered, dict) and undelivered.get("count"):
        pdf.text("This scan did not reach its target.", font="Helvetica-Bold", size=13,
                 color=_SEVERITY_INK["critical"])
        pdf.paragraph(
            f"{undelivered['count']} probe(s) never got an answer to score, so nothing "
            "below describes what the target withstood. A report with no findings and "
            "undelivered probes is not a clean report.",
            size=10, color=_SEVERITY_INK["critical"],
        )
        for reason in _as_list(undelivered.get("reasons"))[:6]:
            pdf.paragraph(f"— {_fmt(reason)}", size=8.5, font="Courier", indent=10,
                          color=_GREY)
        pdf.space(6)

    exposed = props.get("secret_exposed")
    if isinstance(exposed, dict) and exposed.get("count"):
        pdf.text("The value passed to --app-secret came back in a reply.",
                 font="Helvetica-Bold", size=12, color=_SEVERITY_INK["critical"])
        pdf.paragraph(
            f"{exposed['count']} probe(s) returned it, whichever category asked. A clean "
            "LLM02 row in this run does not mean the secret was protected.",
            size=10,
        )
        pdf.space(6)

    tally = props.get("attacks_withstood")
    if isinstance(tally, dict) and tally.get("attempted"):
        pdf.text("Attacks delivered", font="Helvetica-Bold", size=13)
        pdf.paragraph(
            f"{tally.get('withstood', 0)} of {tally['attempted']} delivered attacks were "
            f"withstood. {len(findings)} finding(s) in this report.",
            size=10,
        )
        pdf.space(4)

    inconclusive = props.get("inconclusive")
    if isinstance(inconclusive, dict) and inconclusive.get("count"):
        pdf.paragraph(
            f"{inconclusive['count']} probe(s) could not be concluded. They are neither "
            "findings nor passes, and they are counted here so an empty findings list "
            "cannot stand in for a result.",
            size=10, color=_SEVERITY_INK["medium"],
        )
        pdf.space(4)

    stress = props.get("stress")
    if isinstance(stress, dict) and stress.get("cases"):
        verdicts = ", ".join(f"{k} {v}" for k, v in sorted(stress.get("verdicts", {}).items()))
        pdf.paragraph(
            f"Concurrent load: {stress['cases']} case(s) replayed under simultaneous "
            f"requests ({verdicts}). A held verdict is bounded by the concurrency the "
            "run actually reached.",
            size=10,
        )
        pdf.space(4)

    if not findings:
        pdf.space(4)
        pdf.paragraph(
            "No findings in this report."
            if not (isinstance(undelivered, dict) and undelivered.get("count"))
            else "No findings, and see the undelivered notice above before reading that "
                 "as a pass.",
            font="Helvetica-Bold", size=11,
        )

    # --- findings, by category then severity ---------------------------------------
    groups: dict[tuple[str, str], list[tuple[dict, dict]]] = {}
    for result, rule in findings:
        groups.setdefault(_owasp_of(result, rule), []).append((result, rule))

    for (cat, name), items in sorted(
        groups.items(), key=lambda kv: _OWASP_ORDER.get(kv[0][0], 99)
    ):
        items.sort(key=lambda rr: _SEVERITY_RANK.get(_severity_of(*rr), 0), reverse=True)
        pdf.space(8)
        pdf.rule()
        pdf.text(f"{cat} {name}".strip() + f"  ({len(items)})",
                 font="Helvetica-Bold", size=13)
        pdf.space(2)
        for result, rule in items:
            severity = _severity_of(result, rule)
            score = _score_of(result, rule)
            ink = _SEVERITY_INK.get(severity, _GREY)
            head = severity.upper() + (f"  CVSS {score:g}" if score is not None else "")
            pdf.space(4)
            pdf.text(head, font="Helvetica-Bold", size=8.5, color=ink)
            pdf.paragraph(_title_of(result, rule), font="Helvetica-Bold", size=10.5)
            location = _location_of(result)
            if location:
                pdf.paragraph(location, font="Courier", size=8, color=_GREY)
            message = _fmt(_as_dict(result.get("message")).get("text"))
            if message:
                pdf.paragraph(message, size=9.5, indent=8)

    pdf.space(10)
    pdf.rule()
    pdf.paragraph(
        "Generated by LLMSecTest from a SARIF v2.1.0 report. Findings map to the OWASP "
        "LLM Top 10 (2025). A category this run had no input for is reported as skipped "
        "rather than passed.",
        size=8, color=_GREY,
    )
    return pdf.build()


def render_sarif_pdf_file(in_path: str | Path, out_path: str | Path | None = None) -> Path:
    """Read a ``.sarif`` file, render it to PDF, and write it.

    ``out_path`` defaults to the input with a ``.pdf`` suffix, mirroring
    :func:`~llmsectest.reporting.sarif_html.render_sarif_file` so the two formats are
    produced the same way from the same input.
    """
    in_path = Path(in_path)
    doc = json.loads(in_path.read_text(encoding="utf-8"))
    data = render_sarif_pdf(doc, source_name=in_path.name)
    out = Path(out_path) if out_path else in_path.with_suffix(".pdf")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    return out
