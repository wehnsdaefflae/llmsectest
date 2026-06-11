"""Adapter-driven OWASP security probes.

A probe sends an attacker prompt through the unified :class:`LLMAdapter` and a
detector scores the reply. The corpus currently covers OWASP LLM01 (prompt
injection), LLM02 (sensitive information disclosure), LLM05 (improper output
handling), LLM06 (excessive agency) and LLM07 (system prompt leakage); the
packaged pytest suite in :mod:`llmsectest.suite` runs them.
"""

from __future__ import annotations

from .corpus import (
    SCANNER_CATEGORIES,
    cases_for,
    covered_categories,
    get_corpus,
)
from .supplychain import (
    Dependency,
    SupplyChainFinding,
    collect_dependencies,
    discover_manifests,
    scan_dependencies,
)
from .osv import (
    OsvScanResult,
    pinned_version,
    scan_known_vulnerabilities,
)
from .detectors import (
    available_detectors,
    get_detector,
    register_detector,
)
from .demo import (
    defended_demo_adapter,
    resolve_target,
    vulnerable_demo_adapter,
)
from .application import (
    ALL_CATEGORIES,
    AppScanResult,
    CategoryCoverage,
    app_cases,
    app_coverage,
    run_app_scan,
)
from .models import ProbeCase, ProbeOutcome
from .runner import run_probe

__all__ = [
    "ALL_CATEGORIES",
    "SCANNER_CATEGORIES",
    "AppScanResult",
    "CategoryCoverage",
    "Dependency",
    "OsvScanResult",
    "ProbeCase",
    "ProbeOutcome",
    "SupplyChainFinding",
    "app_cases",
    "app_coverage",
    "available_detectors",
    "cases_for",
    "collect_dependencies",
    "covered_categories",
    "defended_demo_adapter",
    "discover_manifests",
    "get_corpus",
    "get_detector",
    "pinned_version",
    "register_detector",
    "resolve_target",
    "run_app_scan",
    "run_probe",
    "scan_dependencies",
    "scan_known_vulnerabilities",
    "vulnerable_demo_adapter",
]
