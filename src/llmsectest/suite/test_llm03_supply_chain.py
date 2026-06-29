"""OWASP LLM03 — supply-chain dependency scan (white-box, repo-driven).

Unlike the adapter-driven categories, LLM03 inspects the target *project's*
dependency manifests rather than prompting a model. The repo to scan comes from
``LLMSECTEST_REPO`` (the ``llmsectest`` CLI sets it from ``--repo``). With no repo
supplied the category is reported as skipped-with-reason — never a silent pass —
so a developer always sees that LLM03 ran and what it needs to fire.

Two layers, each surfaced separately:

* **structural** (offline, always with ``--repo``): malicious/typosquat names,
  unpinned/unbounded versions, direct VCS/URL installs, insecure indexes;
* **known CVEs** (networked, opt-in via ``--osv`` → ``LLMSECTEST_OSV``): OSV.dev
  advisories against exactly-pinned versions. Not requested, nothing queryable,
  or a failed lookup each shows as an explicit skip reason — never as "clean".
"""

import os
from pathlib import Path

import pytest

from llmsectest import envvars

from llmsectest.probes.osv import scan_known_vulnerabilities
from llmsectest.probes.supplychain import discover_manifests, scan_dependencies
from llmsectest.suite.scanners import fail_with_finding, scanner_params


def _load():
    """Return (findings, skip_reason). ``findings`` is None when skipped."""
    repo = os.environ.get(envvars.REPO)
    if not repo:
        return None, "no project repo supplied — pass --repo <path> to scan dependencies"
    path = Path(repo)
    if not path.exists():
        return None, f"repo path {repo!r} does not exist"
    if not discover_manifests(path):
        return None, (f"no dependency manifest (requirements*.txt / pyproject.toml / "
                      f"Pipfile) found under {repo}")
    return scan_dependencies(path), ""


def _osv_params(repo: str) -> list:
    """Params for the known-CVE layer — each non-run state is a visible skip."""
    if not os.environ.get(envvars.OSV):
        return [pytest.param(None, id="osv-cve-lookup", marks=pytest.mark.skip(
            reason="LLM03 known-CVE lookup not requested — pass --osv to query "
                   "OSV.dev for advisories against pinned versions (networked)"))]
    result = scan_known_vulnerabilities(repo)
    if result.error:
        return [pytest.param(None, id="osv-cve-lookup", marks=pytest.mark.skip(
            reason=f"LLM03 known-CVE lookup failed: {result.error}"))]
    if result.queried == 0:
        return [pytest.param(None, id="osv-cve-lookup", marks=pytest.mark.skip(
            reason="LLM03 known-CVE lookup: no exactly-pinned (==X.Y.Z) dependencies "
                   "to query — OSV can only attribute advisories to a concrete version"))]
    if not result.findings:
        return [pytest.param(None, id=f"no-known-cves-{result.queried}-pinned-queried")]
    return [pytest.param(f, id=f.id, marks=getattr(pytest.mark, f.severity))
            for f in result.findings]


def _params():
    findings, skip = _load()
    structural = scanner_params(findings, skip, category_label="LLM03 supply chain",
                                skip_id="supply-chain",
                                clean_id="no-structural-supply-chain-risk")
    if skip:
        return structural  # no repo → the OSV layer has nothing to query either
    return structural + _osv_params(os.environ[envvars.REPO])


@pytest.mark.security
@pytest.mark.owasp_llm03
@pytest.mark.parametrize("finding", _params())
def test_supply_chain(finding, record_property):
    if finding is None:
        return  # no repo (skipped via mark) or layer scanned with no risk found
    message = (
        f"[{finding.technique}] {finding.package} ({finding.manifest}): "
        f"{finding.evidence}\n  → {finding.recommendation}"
    )
    # The cause lives in the *tested* project's manifest, not this test file —
    # record it so the SARIF location points there (see SARIFGenerator).
    fail_with_finding(record_property, message=message,
                      artifact_uri=getattr(finding, "manifest", "") or "")
