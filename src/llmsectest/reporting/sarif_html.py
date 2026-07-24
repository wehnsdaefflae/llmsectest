"""Render any SARIF v2.1.0 file as a standalone, browsable HTML report.

Unlike :mod:`llmsectest.reporting.html_generator` (which renders the in-memory
pytest result model during a run), this reads a finished ``.sarif`` file — ours
*or* any other tool's — and produces a single self-contained HTML page (inline
CSS, no assets, no network) you can open or share. It is SARIF-native: it reads
the runs / rules / results contract directly, so a finding from a third-party
scanner renders too, just with whatever metadata that tool supplied.

For LLMSecTest's own reports it surfaces the rich per-finding metadata we emit —
OWASP LLM category, CVSS v4.0 score/severity, CWE, location and remediation — and
groups findings by OWASP category. Missing fields degrade gracefully.
"""

from __future__ import annotations

import html as _html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Matches a CWE id in any of the conventions a SARIF producer uses: our explicit
# ``CWE-77``; the GitHub tag convention ``external/cwe/cwe-77`` (Bandit, CodeQL,
# Semgrep, ...); a bare ``cwe_77``. The number is captured for canonicalisation.
_CWE_RE = re.compile(r"cwe[-_ ]?(\d+)", re.IGNORECASE)

# Severity → accent colour and rank (higher = more severe, sorts first).
_SEVERITY = {
    "critical": ("#b3123a", 4),
    "high": ("#c2410c", 3),
    "medium": ("#a16207", 2),
    "low": ("#15803d", 1),
    "none": ("#475569", 0),
}
# OWASP LLM Top 10 ordering for grouping; anything else sorts after under "Other".
_OWASP_ORDER = {f"LLM{n:02d}": n for n in range(1, 11)}


def _esc(text: Any) -> str:
    return _html.escape(str(text), quote=True)


# --- defensive coercions -------------------------------------------------------
# This renderer promises to display *any* tool's SARIF, and a third-party (or
# hand-written / truncated) file may put the wrong JSON type where the spec wants
# an object/array. These coerce the wrong type into a harmless empty default so a
# malformed field degrades gracefully instead of crashing the whole render.

def _as_dict(obj: Any) -> dict:
    return obj if isinstance(obj, dict) else {}


def _as_list(obj: Any) -> list:
    return obj if isinstance(obj, list) else []


def _as_str_list(obj: Any) -> list[str]:
    """Coerce a field that should be a list of strings (e.g. ``cwe``). A lone
    scalar — some tools emit a single CWE as a bare string — becomes a one-item
    list rather than being iterated character-by-character; a dict/None yields []."""
    if isinstance(obj, list):
        return [str(x) for x in obj if x not in (None, "")]
    if isinstance(obj, (str, int, float)) and not isinstance(obj, bool) and obj != "":
        return [str(obj)]
    return []


def _severity_from_score(score: float) -> str:
    """CVSS-band a numeric security-severity (GitHub code-scanning bands)."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def _props(obj: dict) -> dict:
    return obj.get("properties", {}) if isinstance(obj, dict) else {}


def _cwes_of(result: dict, rule: dict) -> list[str]:
    """Collect a finding's CWE ids across every SARIF convention a tool uses.

    Not every scanner records CWE the way we do. Ours puts it in the explicit
    ``properties.cwe`` / ``properties.cwe_ids`` field; many security scanners
    instead follow the GitHub code-scanning tag convention and encode it as an
    ``external/cwe/cwe-NNN`` entry in ``properties.tags`` (Bandit does exactly
    this — see ``tests/fixtures/bandit-1.9.4.sarif``). Both are surfaced here.

    Ids are canonicalised to ``CWE-NNN`` and de-duplicated, explicit ids first —
    so our own reports (which carry only ``properties.cwe``) render byte-for-byte
    as before, while a Bandit/CodeQL finding now shows its CWE instead of none.
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(canon: str, key: str) -> None:
        if key not in seen:
            seen.add(key)
            out.append(canon)

    # 1. Explicit CWE field (our own reports). A recognisable id is canonicalised;
    #    an unrecognisable token is kept verbatim so nothing a tool emitted is lost.
    for token in _as_str_list(_props(rule).get("cwe") or _props(result).get("cwe_ids")):
        m = _CWE_RE.search(token)
        if m:
            _add(f"CWE-{int(m.group(1))}", m.group(1))
        else:
            _add(token, token.lower())
    # 2. GitHub tag convention (``external/cwe/cwe-NNN``) on the rule or result.
    for token in _as_str_list(_props(rule).get("tags")) + _as_str_list(_props(result).get("tags")):
        m = _CWE_RE.search(token)
        if m:
            _add(f"CWE-{int(m.group(1))}", m.group(1))
    return out


def _score_of(result: dict, rule: dict) -> float | None:
    """Best-effort numeric severity from result/rule properties."""
    for src in (_props(result), _props(rule)):
        for key in ("security-severity", "cvss_base_score"):
            val = src.get(key)
            if val not in (None, ""):
                try:
                    return float(val)
                except (TypeError, ValueError):
                    pass
    return None


def _severity_of(result: dict, rule: dict) -> str:
    """Resolve a finding's severity bucket from CVSS, then the SARIF level."""
    sev = _props(result).get("cvss_base_severity") or _props(rule).get("cvss_base_severity")
    if isinstance(sev, str) and sev.lower() in _SEVERITY:
        return sev.lower()
    score = _score_of(result, rule)
    if score is not None:
        return _severity_from_score(score)
    # No CVSS — fall back to the SARIF level (error/warning/note).
    level = result.get("level") or _as_dict(rule.get("defaultConfiguration")).get("level", "")
    return {"error": "high", "warning": "medium", "note": "low"}.get(level, "none")


def _owasp_of(result: dict, rule: dict) -> tuple[str, str]:
    """Return (category id, name), e.g. ('LLM01', 'Prompt Injection'); ('Other','')."""
    rp, xp = _props(rule), _props(result)
    cat = rp.get("owasp-category") or xp.get("owasp_category") or ""
    name = rp.get("owasp-name") or xp.get("owasp_name") or ""
    return (cat or "Other", name)


def _location_of(result: dict) -> str:
    for loc in _as_list(result.get("locations")):
        phys = _as_dict(_as_dict(loc).get("physicalLocation"))
        uri = _as_dict(phys.get("artifactLocation")).get("uri")
        if uri:
            line = _as_dict(phys.get("region")).get("startLine")
            return f"{uri}:{line}" if line else uri
    return ""


def _fixes_of(result: dict) -> list[str]:
    out = []
    for fix in _as_list(result.get("fixes")):
        text = _as_dict(_as_dict(fix).get("description")).get("text")
        if text:
            out.append(text)
    return out


def _rule_index(run: dict) -> dict[str, dict]:
    driver = _as_dict(_as_dict(run.get("tool")).get("driver"))
    return {r.get("id"): r for r in _as_list(driver.get("rules")) if isinstance(r, dict)}


# --- HTML pieces ---------------------------------------------------------------

def _sev_badge(sev: str, score: float | None) -> str:
    colour, _ = _SEVERITY.get(sev, _SEVERITY["none"])
    label = sev.upper() if sev != "none" else "—"
    if score is not None:
        label = f"{label} · CVSS {score:g}"
    return f'<span class="badge" style="background:{colour}">{_esc(label)}</span>'


def _finding_card(result: dict, rule: dict) -> str:
    sev = _severity_of(result, rule)
    score = _score_of(result, rule)
    # Some tools (e.g. ruff) put the human-readable rule name under
    # ``properties.name`` rather than the top-level ``name``; prefer it over the
    # terse rule id ("unused-import" reads better than "F401") before falling back.
    title = (rule.get("name") or _props(rule).get("name") or result.get("ruleId") or "finding")
    loc = _location_of(result)
    msg = _as_dict(result.get("message")).get("text", "")
    fixes = _fixes_of(result)
    cwes = _cwes_of(result, rule)

    parts = [f'<article class="finding sev-{sev}">']
    parts.append('<div class="f-head">')
    parts.append(f'<span class="f-title">{_esc(title)}</span>')
    parts.append(_sev_badge(sev, score))
    parts.append("</div>")
    sub = []
    if loc:
        sub.append(f'<code class="loc">{_esc(loc)}</code>')
    if cwes:
        sub.append('<span class="cwe">' + ", ".join(_esc(c) for c in cwes) + "</span>")
    cost = _props(result).get("output_tokens")
    if isinstance(cost, (int, float)) and not isinstance(cost, bool):
        sub.append(f'<span class="cost">{int(cost)} output tokens</span>')
    if sub:
        parts.append('<div class="f-sub">' + " ".join(sub) + "</div>")
    if msg:
        parts.append(f'<pre class="f-msg">{_esc(msg)}</pre>')
    if fixes:
        items = "".join(f"<li>{_esc(f)}</li>" for f in fixes)
        parts.append(
            f'<details class="f-fixes"><summary>Remediation ({len(fixes)})</summary>'
            f"<ol>{items}</ol></details>"
        )
    parts.append("</article>")
    return "".join(parts)


def _summary(findings: list[tuple[dict, dict]]) -> str:
    by_sev: dict[str, int] = {}
    by_cat: dict[tuple[str, str], int] = {}
    for result, rule in findings:
        sev = _severity_of(result, rule)
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_cat[_owasp_of(result, rule)] = by_cat.get(_owasp_of(result, rule), 0) + 1

    total = len(findings)
    # Stacked severity bar.
    segs = ""
    for sev in ("critical", "high", "medium", "low", "none"):
        n = by_sev.get(sev, 0)
        if n:
            pct = 100 * n / total
            colour = _SEVERITY[sev][0]
            segs += (f'<span class="seg" style="width:{pct:.3f}%;background:{colour}" '
                     f'title="{sev}: {n}"></span>')
    bar = f'<div class="sevbar">{segs}</div>' if total else ""

    sev_cards = ""
    for sev in ("critical", "high", "medium", "low", "none"):
        n = by_sev.get(sev, 0)
        if not n:
            continue
        colour = _SEVERITY[sev][0]
        sev_cards += (f'<div class="card"><span class="dot" style="background:{colour}"></span>'
                      f'<span class="n">{n}</span><span class="k">{_esc(sev)}</span></div>')

    cat_rows = ""
    for (cat, name), n in sorted(by_cat.items(), key=lambda kv: _OWASP_ORDER.get(kv[0][0], 99)):
        label = f"{cat} {name}".strip()
        cat_rows += f'<tr><td>{_esc(label)}</td><td class="num">{n}</td></tr>'

    return (
        '<section class="summary">'
        f'<div class="total"><span class="big">{total}</span> '
        f'finding{"s" if total != 1 else ""}</div>'
        f"{bar}"
        f'<div class="cards">{sev_cards}</div>'
        f'<table class="cat-table"><thead><tr><th>OWASP category</th>'
        f'<th class="num">findings</th></tr></thead><tbody>{cat_rows}</tbody></table>'
        "</section>"
    )


def _rules_glossary(rules: dict[str, dict]) -> str:
    rows = ""
    seen = set()
    for rule in rules.values():
        rp = _props(rule)
        key = rp.get("owasp-category") or rule.get("id")
        if key in seen:
            continue
        seen.add(key)
        cat = rp.get("owasp-category", "")
        name = rp.get("owasp-name") or rule.get("name") or rp.get("name") or rule.get("id", "")
        cvss = rp.get("cvss_base_score")
        vector = rp.get("cvss_vector", "")
        desc = _as_dict(rule.get("fullDescription")).get("text") or \
            _as_dict(rule.get("shortDescription")).get("text", "")
        help_text = _as_dict(rule.get("help")).get("text", "")
        cvss_str = f"CVSS {cvss} ({rp.get('cvss_base_severity', '')})" if cvss else ""
        rows += (
            '<details class="rule"><summary>'
            f'<b>{_esc(cat)}</b> {_esc(name)} '
            f'<span class="rule-cvss">{_esc(cvss_str)}</span></summary>'
            f'<p>{_esc(desc)}</p>'
            + (f'<p class="vec"><code>{_esc(vector)}</code></p>' if vector else "")
            + (f'<p class="help">{_esc(help_text)}</p>' if help_text else "")
            + "</details>"
        )
    if not rows:
        return ""
    return ('<section class="glossary"><h2>Rule reference</h2>'
            f"{rows}</section>")


_CSS = """
:root { --bg:#f6f7f9; --fg:#1c2430; --muted:#5b6878; --line:#e2e6ec; --card:#fff; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
code, pre, .mono { font-family:"SF Mono",ui-monospace,"Cascadia Code",Menlo,Consolas,monospace; }
.topbar { background:#0f172a; color:#e6edf6; padding:18px 28px; display:flex;
  align-items:baseline; gap:18px; flex-wrap:wrap; border-bottom:3px solid #1f9d6b; }
.brand { font-weight:700; font-size:18px; letter-spacing:.3px; }
.brand span { color:#1f9d6b; font-weight:600; }
.topbar .meta { color:#9fb0c4; font-size:13px; }
main { max-width:1000px; margin:0 auto; padding:26px 22px 60px; }
.summary { background:var(--card); border:1px solid var(--line); border-radius:12px;
  padding:20px 22px; margin-bottom:26px; }
.total { font-size:15px; color:var(--muted); margin-bottom:12px; }
.total .big { font-size:30px; font-weight:800; color:var(--fg); }
.sevbar { display:flex; height:12px; border-radius:6px; overflow:hidden; background:var(--line);
  margin-bottom:16px; }
.sevbar .seg { display:block; height:100%; }
.cards { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:16px; }
.card { display:flex; align-items:center; gap:8px; background:#fafbfc; border:1px solid var(--line);
  border-radius:9px; padding:8px 13px; }
.card .dot { width:11px; height:11px; border-radius:50%; }
.card .n { font-weight:800; font-size:17px; }
.card .k { color:var(--muted); text-transform:capitalize; font-size:13px; }
.cat-table { width:100%; border-collapse:collapse; margin-top:6px; }
.cat-table th, .cat-table td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); }
.cat-table th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase;
  letter-spacing:.4px; }
.num { text-align:right; font-variant-numeric:tabular-nums; }
h2.cat { font-size:16px; margin:30px 0 12px; padding-bottom:6px; border-bottom:2px solid var(--line); }
h2.cat .cnt { color:var(--muted); font-weight:500; font-size:14px; }
.finding { background:var(--card); border:1px solid var(--line); border-left:4px solid #94a3b8;
  border-radius:10px; padding:14px 16px; margin-bottom:12px; }
.finding.sev-critical { border-left-color:#b3123a; }
.finding.sev-high { border-left-color:#c2410c; }
.finding.sev-medium { border-left-color:#a16207; }
.finding.sev-low { border-left-color:#15803d; }
.f-head { display:flex; align-items:center; justify-content:space-between; gap:12px; }
.f-title { font-weight:700; font-size:14px; word-break:break-word; }
.badge { color:#fff; font-size:11px; font-weight:700; letter-spacing:.4px; padding:3px 9px;
  border-radius:20px; white-space:nowrap; }
.f-sub { margin-top:7px; display:flex; gap:12px; flex-wrap:wrap; align-items:center; }
.f-sub .loc { background:#eef1f5; padding:2px 7px; border-radius:5px; font-size:12.5px; color:#33414f; }
.f-sub .cwe { color:var(--muted); font-size:12.5px; }
.f-sub .cost { background:#fdf3e3; color:#8a5a12; padding:2px 7px; border-radius:5px; font-size:12.5px; }
.f-msg { margin:11px 0 0; background:#0f172a; color:#dbe4f0; padding:12px 14px; border-radius:8px;
  font-size:12.5px; line-height:1.45; max-height:260px; overflow:auto; white-space:pre-wrap;
  word-break:break-word; }
.f-fixes { margin-top:11px; }
.f-fixes summary { cursor:pointer; color:#1f7a52; font-weight:600; font-size:13px; }
.f-fixes ol { margin:9px 0 2px; padding-left:22px; color:#33414f; font-size:13.5px; }
.f-fixes li { margin:3px 0; }
.glossary { margin-top:38px; }
.glossary h2 { font-size:16px; border-bottom:2px solid var(--line); padding-bottom:6px; }
.rule { background:var(--card); border:1px solid var(--line); border-radius:9px; padding:10px 14px;
  margin-bottom:8px; }
.rule summary { cursor:pointer; }
.rule-cvss { color:var(--muted); font-size:12.5px; font-weight:600; }
.rule p { color:#33414f; font-size:13.5px; }
.rule .vec code { background:#eef1f5; padding:2px 6px; border-radius:5px; font-size:12px; }
.empty { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:34px;
  text-align:center; color:#1f7a52; font-weight:600; }
footer { max-width:1000px; margin:0 auto; padding:0 22px 40px; color:var(--muted); font-size:12.5px; }
"""


def render_sarif_html(doc: dict, *, source_name: str | None = None,
                      generated: str | None = None) -> str:
    """Render a parsed SARIF document into a standalone HTML page (string)."""
    runs = _as_list(doc.get("runs")) if isinstance(doc, dict) else []
    # Tool identity from the first run.
    first_run = _as_dict(runs[0]) if runs else {}
    driver = _as_dict(_as_dict(first_run.get("tool")).get("driver"))
    tool = driver.get("name", "unknown tool")
    version = driver.get("version", "")
    tool_str = f"{tool} {version}".strip()

    # Collect (result, rule) across all runs. Every field access is type-guarded so
    # a malformed third-party run/result (wrong JSON type) is skipped, not fatal.
    findings: list[tuple[dict, dict]] = []
    all_rules: dict[str, dict] = {}
    for run in runs:
        run = _as_dict(run)
        rules = _rule_index(run)
        all_rules.update({k: v for k, v in rules.items() if k})
        for result in _as_list(run.get("results")):
            if not isinstance(result, dict):
                continue  # a non-object result carries no renderable finding
            findings.append((result, rules.get(result.get("ruleId"), {})))

    generated = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    # Run-level denial-of-wallet cost (real provider output-token spend), when present.
    dow = _props(first_run).get("denial_of_wallet")
    cost_bit = (
        f"{dow['total_output_tokens']} output tokens ({dow['probes_with_usage']} probes)"
        if isinstance(dow, dict) and "total_output_tokens" in dow
        else None
    )
    # Inconclusive probes (target exceeded --app-timeout) — surfaced so a clean-looking
    # report never hides that some probes could not be concluded (they are errored, not
    # findings, so they appear nowhere else in the report).
    inc = _props(first_run).get("inconclusive")
    inc_bit = (
        f"{inc['count']} probe(s) inconclusive"
        if isinstance(inc, dict) and inc.get("count")
        else None
    )
    meta_bits = [b for b in (tool_str, source_name, generated, cost_bit, inc_bit) if b]

    # Group findings by OWASP category, ordered LLM01..LLM10 then Other; within a
    # group, most severe first.
    groups: dict[tuple[str, str], list[tuple[dict, dict]]] = {}
    for result, rule in findings:
        groups.setdefault(_owasp_of(result, rule), []).append((result, rule))

    body = [_summary(findings)]
    if not findings:
        body.append('<div class="empty">✓ No findings in this report — the scan was clean.</div>')
    for (cat, name), items in sorted(groups.items(), key=lambda kv: _OWASP_ORDER.get(kv[0][0], 99)):
        items.sort(key=lambda rr: _SEVERITY.get(_severity_of(*rr), (None, 0))[1], reverse=True)
        label = f"{cat} {name}".strip()
        body.append(f'<h2 class="cat">{_esc(label)} '
                    f'<span class="cnt">· {len(items)}</span></h2>')
        body.extend(_finding_card(result, rule) for result, rule in items)
    body.append(_rules_glossary(all_rules))

    title = f"LLMSecTest SARIF report — {source_name}" if source_name else "LLMSecTest SARIF report"
    return (
        "<!DOCTYPE html>\n"
        f'<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_esc(title)}</title><style>{_CSS}</style></head><body>"
        '<header class="topbar"><div class="brand">LLMSecTest '
        "<span>SARIF report</span></div>"
        f'<div class="meta">{_esc(" · ".join(meta_bits))}</div></header>'
        f'<main>{"".join(body)}</main>'
        '<footer>Generated by LLMSecTest from a SARIF v2.1.0 report · '
        "findings map to the OWASP LLM Top 10 (2025).</footer>"
        "</body></html>"
    )


def render_sarif_file(in_path: str | Path, out_path: str | Path | None = None) -> Path:
    """Read a ``.sarif`` file, render it to HTML, and write the page.

    Returns the path written. ``out_path`` defaults to the input with a ``.html``
    suffix (``results/foo.sarif`` → ``results/foo.html``).
    """
    in_path = Path(in_path)
    doc = json.loads(in_path.read_text(encoding="utf-8"))
    page = render_sarif_html(doc, source_name=in_path.name)
    out = Path(out_path) if out_path else in_path.with_suffix(".html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8")
    return out
