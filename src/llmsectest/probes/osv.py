"""OWASP LLM03 — known-vulnerability lookup via OSV.dev (opt-in, networked).

The offline structural scan in :mod:`llmsectest.probes.supplychain` flags *risky
shapes* — malicious names, unpinned versions, direct URL installs. This module
adds the complementary depth check: are any **exactly pinned** dependency
versions affected by *known, published vulnerabilities*? It queries
`OSV.dev <https://osv.dev>`_ — the open, cross-ecosystem advisory database that
also backs pip-audit — through its free batch API (no key, no auth).

Opt-in by design: the lookup needs the network, so it runs only when the CLI is
given ``--osv``; the structural scan stays the deterministic, offline default.

Only exact pins (``==`` / ``===``, no wildcard) are queried. A range like
``>=1.0`` does not determine which version an installation will actually
receive, so a static manifest scan cannot honestly attribute a CVE to it —
resolving the live environment is pip-audit's job, not a manifest scanner's.
Deps without an exact pin are counted and surfaced, never silently dropped.

A failed lookup (no network, API error) is likewise *surfaced* — the result
carries the error and the packaged suite reports the check as skipped with that
reason — never as a clean "no known CVEs".
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# ``pinned_version`` lives with the ``Dependency`` it describes (supplychain);
# re-exported here because "which deps are queryable" is the OSV layer's own
# vocabulary and existing importers reference ``osv.pinned_version``.
from .supplychain import (
    Dependency,
    SupplyChainFinding,
    collect_dependencies,
    pinned_version,
)

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

# OSV accepts up to 1000 queries per batch request; stay well inside the limit.
_BATCH_SIZE = 500
_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class OsvScanResult:
    """Outcome of an OSV known-vulnerability scan over a repo's manifests.

    ``error`` is non-empty when the lookup itself failed (network/API); callers
    must surface that state instead of treating the empty ``findings`` as clean.
    ``unqueried`` counts deps that had no exact pin and so could not be checked.
    """

    findings: list[SupplyChainFinding] = field(default_factory=list)
    queried: int = 0
    unqueried: int = 0
    error: str = ""


def _post_json(url: str, payload: dict) -> dict:
    """POST ``payload`` as JSON and return the decoded JSON response."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
        return json.load(response)


def _advisory_finding(dep: Dependency, version: str, vuln_ids: list[str]) -> SupplyChainFinding:
    """One aggregated finding per vulnerable pinned package."""
    shown = ", ".join(vuln_ids[:6]) + (" …" if len(vuln_ids) > 6 else "")
    return SupplyChainFinding(
        # Severity note: OSV's batch endpoint returns advisory ids only (no
        # per-advisory severity); grading each advisory needs a details call per
        # id. Any published advisory against the exact installed version is
        # treated as high — the category-level CVSS vector scores the class.
        id=f"LLM03-osv-{dep.name}",
        severity="high",
        package=f"{dep.name}=={version}",
        manifest=dep.manifest,
        technique="pinned version has known published vulnerabilities (OSV)",
        evidence=f"'{dep.name}=={version}' is affected by {len(vuln_ids)} published "
                 f"advisories: {shown}.",
        recommendation=f"Upgrade '{dep.name}' to a patched release; details: "
                       f"https://osv.dev/vulnerability/{vuln_ids[0]}",
    )


def scan_known_vulnerabilities(repo: str | Path) -> OsvScanResult:
    """Query OSV.dev for every exactly-pinned dependency under ``repo``.

    Parses the same manifests as the structural scan, batch-queries OSV for the
    deps whose version is statically determined, and aggregates the advisories
    into one finding per vulnerable package. Network use is the caller's opt-in.
    """
    pinned: dict[tuple[str, str], Dependency] = {}
    unqueried = 0
    for dep in collect_dependencies(repo):
        version = pinned_version(dep)
        if version is None:
            unqueried += 1
            continue
        pinned.setdefault((dep.name, version), dep)  # dedupe across manifests

    ordered = sorted(pinned.items())
    results: list[dict] = []
    try:
        for start in range(0, len(ordered), _BATCH_SIZE):
            chunk = ordered[start:start + _BATCH_SIZE]
            payload = {
                "queries": [
                    {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
                    for (name, version), _ in chunk
                ]
            }
            response = _post_json(OSV_QUERYBATCH_URL, payload)
            results.extend(response.get("results") or [])
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return OsvScanResult(queried=len(ordered), unqueried=unqueried,
                             error=f"OSV.dev query failed: {exc}")

    findings = []
    for ((name, version), dep), result in zip(ordered, results):
        vuln_ids = [v["id"] for v in (result.get("vulns") or []) if v.get("id")]
        if vuln_ids:
            findings.append(_advisory_finding(dep, version, vuln_ids))
    findings.sort(key=lambda f: f.package)
    return OsvScanResult(findings=findings, queried=len(ordered), unqueried=unqueried)
