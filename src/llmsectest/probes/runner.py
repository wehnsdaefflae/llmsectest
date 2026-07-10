"""Drive a single probe case through any :class:`LLMAdapter` and score it."""

from __future__ import annotations

from ..adapters.base import (
    AdapterTimeoutError,
    CompletionRequest,
    LLMAdapter,
    Message,
)
from .detectors import get_detector, output_ceiling_reached
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

    A case with :attr:`~llmsectest.probes.models.ProbeCase.cost_ceiling` set is *also*
    flagged (independently of its text detector) when the reply reached the request's
    ``max_tokens`` budget — the "would-have-continued" denial-of-wallet signal that the
    text oracles cannot see. The request's own ``max_tokens`` is the ceiling reference, so
    the two never drift.

    A target that does not respond within its per-request time budget raises
    :class:`~llmsectest.adapters.base.AdapterTimeoutError`; this is caught and recorded as
    an **inconclusive** outcome (``errored=True``) rather than allowed to abort the scan. A
    timeout is not scored as a finding (it is not proof of a vulnerability — the app may
    simply be slow) but neither is it a silent clean: the outcome carries the timeout as its
    evidence for the report. Every other adapter failure (unreachable endpoint, malformed
    reply, auth error) still propagates, so a genuine misconfiguration fails loudly.
    """
    request = CompletionRequest(
        messages=[
            Message.system(case.system_prompt),
            Message.user(case.user_prompt),
        ],
        temperature=0.0,
    )
    try:
        response = adapter.complete(request)
    except AdapterTimeoutError as exc:
        return ProbeOutcome(
            case=case,
            response="",
            vulnerable=False,
            evidence=f"probe inconclusive — {exc}",
            errored=True,
        )
    output_tokens = _output_tokens(response.usage)
    vulnerable, evidence = get_detector(case.detector)(response.text, case)
    if case.cost_ceiling and not vulnerable:
        vulnerable, evidence = output_ceiling_reached(output_tokens, request.max_tokens)
    return ProbeOutcome(
        case=case,
        response=response.text,
        vulnerable=vulnerable,
        evidence=evidence,
        output_tokens=output_tokens,
    )
