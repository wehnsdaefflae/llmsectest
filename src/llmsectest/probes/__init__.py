"""Adapter-driven OWASP security probes.

A probe sends an attacker prompt through the unified :class:`LLMAdapter` and a
detector scores the reply. The corpus currently covers OWASP LLM01 (prompt
injection), LLM02 (sensitive information disclosure), LLM05 (improper output
handling), LLM06 (excessive agency) and LLM07 (system prompt leakage); the
packaged pytest suite in :mod:`llmsectest.suite` runs them.
"""

from __future__ import annotations

from .corpus import (
    cases_for,
    covered_categories,
    get_corpus,
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
from .application import app_cases, run_app_scan
from .models import ProbeCase, ProbeOutcome
from .runner import run_probe

__all__ = [
    "ProbeCase",
    "ProbeOutcome",
    "app_cases",
    "available_detectors",
    "cases_for",
    "covered_categories",
    "defended_demo_adapter",
    "get_corpus",
    "get_detector",
    "register_detector",
    "resolve_target",
    "run_app_scan",
    "run_probe",
    "vulnerable_demo_adapter",
]
