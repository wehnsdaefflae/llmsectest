"""Drive a single probe case through any :class:`LLMAdapter` and score it."""

from __future__ import annotations

from ..adapters.base import LLMAdapter
from .detectors import get_detector
from .models import ProbeCase, ProbeOutcome


def run_probe(adapter: LLMAdapter, case: ProbeCase) -> ProbeOutcome:
    """Send ``case`` to ``adapter`` and apply its detector to the reply."""
    response = adapter.prompt(
        case.user_prompt,
        system=case.system_prompt,
        temperature=0.0,
    )
    vulnerable, evidence = get_detector(case.detector)(response, case)
    return ProbeOutcome(
        case=case, response=response, vulnerable=vulnerable, evidence=evidence
    )
