"""Shared building blocks for the white-box *scanner* suites.

The scanner categories — LLM03 (supply-chain dependency scan) and LLM04
(data/model-poisoning model-file scan) — inspect the target project's *artifacts*
rather than prompting a model, and both must report with **no silent gap**:

* a **skip-with-reason** when the scanner had no input (no ``--repo`` /
  ``--model-scan``) or found nothing to scan,
* a single **clean marker** when it ran and found no risk, and
* **one parametrized case per finding** otherwise (each its own SARIF result).

Centralising that param logic here keeps the scanner suites identical and stops a
future scanner category from quietly drifting into a silent pass.
"""

from __future__ import annotations

import pytest


def scanner_params(findings, skip_reason: str, *, category_label: str,
                   skip_id: str, clean_id: str) -> list:
    """Build the pytest params for one scanner category — no silent gaps.

    ``findings`` is ignored when ``skip_reason`` is set. Each finding must expose
    ``.id`` and ``.severity`` (used as the case id and the pytest severity mark).
    """
    if skip_reason:
        # one skipped test, with the reason, so the category is never silently absent
        return [pytest.param(None, id=skip_id,
                             marks=pytest.mark.skip(reason=f"{category_label}: {skip_reason}"))]
    if not findings:
        return [pytest.param(None, id=clean_id)]
    return [pytest.param(f, id=f.id, marks=getattr(pytest.mark, f.severity))
            for f in findings]


def fail_with_finding(record_property, *, message: str, artifact_uri: str = "") -> None:
    """Record a scanner finding's location + clean message, then fail the test.

    ``artifact_uri`` (the manifest / model file the risk lives in) points the SARIF
    location at the *tested* project rather than this test file; ``message`` is the
    clean, traceback-free finding text shown in the report.
    """
    if artifact_uri:
        record_property("llmsec_artifact_uri", artifact_uri)
    record_property("llmsec_finding", message)
    pytest.fail(message)
