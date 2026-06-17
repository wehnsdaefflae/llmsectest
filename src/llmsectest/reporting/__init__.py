"""Reporting layer: pytest result model, scoring, and report generators.

Turns captured test outcomes into SARIF v2.1.0 / HTML / JSON / Markdown
security reports with OWASP LLM Top-10 metadata, CVSS v4.0 base scoring, risk
scoring, baselines, and policy gating.
"""

import json

from .console_summary import generate_console_summary
from .cvss import CVSSScore, cvss_for_category, score_vector
from .models import TestResult
from .risk_scorer import RiskScore, RiskScoringEngine
from .sarif_html import render_sarif_file, render_sarif_html
from .statistics import calculate_statistics, get_coverage_gaps

__all__ = [
    "CVSSScore",
    "RiskScore",
    "RiskScoringEngine",
    "TestResult",
    "calculate_statistics",
    "cvss_for_category",
    "generate_console_summary",
    "get_coverage_gaps",
    "render_sarif_file",
    "render_sarif_html",
    "score_vector",
    "validate_sarif",
]


def validate_sarif(path: str) -> bool:
    """Validate a SARIF file for v2.1.0 compliance.

    Checks version, structure, and required fields. Useful in CI to verify
    report integrity before uploading to a SARIF consumer (e.g. the GitHub
    Security tab).
    """
    try:
        with open(path) as f:
            sarif = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, OSError) as e:
        print(f"Error: {e}")
        return False

    if sarif.get("version") != "2.1.0":
        print(f"Invalid SARIF version: {sarif.get('version')}")
        return False

    runs = sarif.get("runs", [])
    if len(runs) != 1:
        print(f"Expected 1 run, found {len(runs)}")
        return False

    run = runs[0]
    if "tool" not in run or "results" not in run:
        print("Missing required SARIF fields: tool, results")
        return False

    rules = run["tool"]["driver"].get("rules", [])
    print(f"SARIF valid: {len(run['results'])} findings, {len(rules)} rules")
    return True
