"""OWASP LLM03 — supply-chain dependency scan (white-box, repo-driven).

Unlike the adapter-driven categories, LLM03 inspects the target *project's*
dependency manifests rather than prompting a model. The repo to scan comes from
``LLMSECTEST_REPO`` (the ``llmsectest`` CLI sets it from ``--repo``). With no repo
supplied the category is reported as skipped-with-reason — never a silent pass —
so a developer always sees that LLM03 ran and what it needs to fire.
"""

import os
from pathlib import Path

import pytest

from llmsectest.probes.supplychain import discover_manifests, scan_dependencies


def _load():
    """Return (findings, skip_reason). ``findings`` is None when skipped."""
    repo = os.environ.get("LLMSECTEST_REPO")
    if not repo:
        return None, "no project repo supplied — pass --repo <path> to scan dependencies"
    path = Path(repo)
    if not path.exists():
        return None, f"repo path {repo!r} does not exist"
    if not discover_manifests(path):
        return None, (f"no dependency manifest (requirements*.txt / pyproject.toml / "
                      f"Pipfile) found under {repo}")
    return scan_dependencies(path), ""


def _params():
    findings, skip = _load()
    if skip:
        # one skipped test, with the reason, so the category is never silently absent
        return [pytest.param(None, id="supply-chain",
                             marks=pytest.mark.skip(reason=f"LLM03 supply chain: {skip}"))]
    if not findings:
        return [pytest.param(None, id="no-supply-chain-risk")]
    # one test per finding so each risky dependency is its own SARIF result
    return [pytest.param(f, id=f.id, marks=getattr(pytest.mark, f.severity)) for f in findings]


@pytest.mark.security
@pytest.mark.owasp_llm03
@pytest.mark.parametrize("finding", _params())
def test_supply_chain(finding):
    if finding is None:
        return  # no repo (skipped via mark) or manifests scanned with no risk found
    pytest.fail(
        f"[{finding.technique}] {finding.package} ({finding.manifest}): "
        f"{finding.evidence}\n  → {finding.recommendation}"
    )
