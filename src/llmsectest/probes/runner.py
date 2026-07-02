"""Drive a single probe case through any :class:`LLMAdapter` and score it."""

from __future__ import annotations

from ..adapters.base import CompletionRequest, LLMAdapter, Message
from .detectors import get_detector
from .models import ProbeCase, ProbeOutcome


def _output_tokens(usage: dict) -> int | None:
    """The provider-reported output-token count, across the two key spellings.

    OpenAI / Ollama / LM Studio report ``completion_tokens``; Anthropic reports
    ``output_tokens``. Returns ``None`` when neither is present (a black-box app
    endpoint, or the offline mock adapters, report no usage).
    """
    value = usage.get("completion_tokens", usage.get("output_tokens"))
    return int(value) if isinstance(value, (int, float)) else None


def run_probe(adapter: LLMAdapter, case: ProbeCase) -> ProbeOutcome:
    """Send ``case`` to ``adapter``, score the reply, and record its output cost.

    Drives the target through :meth:`~llmsectest.adapters.base.LLMAdapter.complete`
    (rather than the text-only ``prompt`` convenience) so the full response — including
    the provider's usage block — is available: the per-probe output-token count is
    captured on the outcome as the precise denial-of-wallet cost figure (``None`` for a
    black-box endpoint that reports no usage).
    """
    response = adapter.complete(
        CompletionRequest(
            messages=[
                Message.system(case.system_prompt),
                Message.user(case.user_prompt),
            ],
            temperature=0.0,
        )
    )
    vulnerable, evidence = get_detector(case.detector)(response.text, case)
    return ProbeOutcome(
        case=case,
        response=response.text,
        vulnerable=vulnerable,
        evidence=evidence,
        output_tokens=_output_tokens(response.usage),
    )
