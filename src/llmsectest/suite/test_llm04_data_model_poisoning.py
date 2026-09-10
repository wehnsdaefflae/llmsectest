"""OWASP LLM04 — data & model poisoning scan (white-box, model-file-driven).

Like LLM03, this category inspects the target *project's* artifacts rather than
prompting a model: it scans the serialized model files for the data/model-
poisoning vector where a tampered weights file executes attacker code on load
(see :mod:`llmsectest.probes.modelpoison`). The path to scan comes from
``LLMSECTEST_MODEL_SCAN`` (the ``llmsectest`` CLI sets it from ``--model-scan``).
With no path supplied the category is reported skipped-with-reason — never a
silent pass — so a developer always sees that LLM04 ran and what it needs to fire.
"""

import os
from pathlib import Path

import pytest

from llmsectest import envvars
from llmsectest.probes.modelpoison import (
    discover_model_files,
    discover_safe_model_files,
    scan_model_files,
)
from llmsectest.suite.scanners import fail_with_finding, scanner_params


def _load():
    """Return (findings, skip_reason). ``findings`` is None when skipped."""
    path = os.environ.get(envvars.MODEL_SCAN)
    if not path:
        return None, ("no model path supplied, pass --model-scan <path> to scan "
                      "model files for poisoning")
    p = Path(path)
    if not p.exists():
        return None, f"model path {path!r} does not exist"
    if not discover_model_files(p):
        # "nothing there" and "everything there is in a format that cannot carry the
        # attack" are opposite statements about a project, and the second one is the
        # remediation this category recommends. Reporting it as an absence read as a
        # gap in the scan on a deployment whose only model file is an ONNX embedder.
        safe = discover_safe_model_files(p)
        if safe:
            return None, (f"{len(safe)} model file(s) under {path}, all in code-free "
                          f"formats (.safetensors / .gguf / .onnx) that carry no pickle "
                          f"to execute on load — nothing for this scan to walk, which is "
                          f"the recommended state")
        return None, (f"no model files (.pkl / .pt / .pth / .ckpt / .bin / .npy / "
                      f".joblib / …) found under {path}")
    return scan_model_files(p), ""


def _params():
    findings, skip = _load()
    return scanner_params(findings, skip, category_label="LLM04 model poisoning",
                          skip_id="model-scan", clean_id="no-model-poisoning-risk")


@pytest.mark.security
@pytest.mark.owasp_llm04
@pytest.mark.parametrize("finding", _params())
def test_model_poisoning(finding, record_property):
    if finding is None:
        return  # no model path (skipped via mark) or scanned with no risk found
    message = (
        f"[{finding.technique}] {finding.location}: "
        f"{finding.evidence}\n  → {finding.recommendation}"
    )
    fail_with_finding(record_property, message=message, artifact_uri=finding.model_file)
