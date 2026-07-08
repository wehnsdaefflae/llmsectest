"""Adapter-driven OWASP security probes.

A probe sends an attacker prompt through the unified :class:`LLMAdapter` and a
detector scores the reply. The corpus currently covers OWASP LLM01 (prompt
injection), LLM02 (sensitive information disclosure), LLM05 (improper output
handling), LLM06 (excessive agency), LLM07 (system prompt leakage), LLM09
(misinformation) and LLM10 (unbounded consumption); the packaged pytest suite in
:mod:`llmsectest.suite` runs them.
"""

from __future__ import annotations

from .corpus import (
    APP_ONLY_CATEGORIES,
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
    pinned_version,
    scan_dependencies,
)
from .osv import (
    OsvScanResult,
    scan_known_vulnerabilities,
)
from .modelpoison import (
    ModelPoisonFinding,
    discover_model_files,
    scan_model_file,
    scan_model_files,
)
from .detectors import (
    available_detectors,
    get_detector,
    register_detector,
)
from .redteam import (
    REDTEAM_SYSTEM_PROMPT,
    FalseRefusalReport,
    RedTeamBehavior,
    benign_cases,
    builtin_behaviors,
    builtin_benign,
    load_benign_set,
    load_redteam_set,
    measure_false_refusal,
    redteam_cases,
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
    app_name_from_endpoint,
    run_app_scan,
)
from .models import ProbeCase, ProbeOutcome
from .runner import run_probe

__all__ = [
    "ALL_CATEGORIES",
    "APP_ONLY_CATEGORIES",
    "SCANNER_CATEGORIES",
    "AppScanResult",
    "CategoryCoverage",
    "Dependency",
    "FalseRefusalReport",
    "ModelPoisonFinding",
    "OsvScanResult",
    "ProbeCase",
    "ProbeOutcome",
    "REDTEAM_SYSTEM_PROMPT",
    "RedTeamBehavior",
    "SupplyChainFinding",
    "app_cases",
    "app_coverage",
    "app_name_from_endpoint",
    "available_detectors",
    "benign_cases",
    "builtin_behaviors",
    "builtin_benign",
    "cases_for",
    "collect_dependencies",
    "covered_categories",
    "defended_demo_adapter",
    "discover_manifests",
    "discover_model_files",
    "get_corpus",
    "get_detector",
    "load_benign_set",
    "load_redteam_set",
    "measure_false_refusal",
    "pinned_version",
    "redteam_cases",
    "register_detector",
    "resolve_target",
    "run_app_scan",
    "run_probe",
    "scan_dependencies",
    "scan_known_vulnerabilities",
    "scan_model_file",
    "scan_model_files",
    "vulnerable_demo_adapter",
]
