"""Data model for adapter-driven security probes.

A :class:`ProbeCase` is one red-team attack against a target model: an attacker
``user_prompt`` sent on top of the application-under-test ``system_prompt``. A
detector then inspects the model's reply for ``forbidden`` tokens (canaries,
planted secrets, or an injected marker) whose presence signals a vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True, repr=False)
class ProbeCase:
    """One OWASP attack case driven through the unified LLM adapter."""

    id: str
    owasp: str  # pytest marker name, e.g. "owasp_llm01"
    title: str
    severity: str  # one of SEVERITIES
    technique: str  # short label for the attack technique
    user_prompt: str  # the attacker-controlled turn
    system_prompt: str  # the application-under-test persona (may carry canaries)
    detector: str  # name of the registered detector that scores the reply
    forbidden: tuple[str, ...]  # tokens whose presence in a reply signals compromise
    #: True for a case scored by a *metric* (e.g. output volume) rather than a planted
    #: token — such a case legitimately carries no ``forbidden`` marker.
    tokenless: bool = False
    #: When True the case is *also* flagged if the reply reached the provider's output
    #: token ceiling (the request's ``max_tokens``) — a "would-have-continued" denial-of-
    #: wallet signal for an unbounded request. It catches a *non-repetitive* runaway (a
    #: long essay) and a hidden-reasoning runaway that the text detectors cannot see,
    #: since both manifest as the completion filling the whole token budget. Evaluated in
    #: :func:`~llmsectest.probes.runner.run_probe` from the reply's ``output_tokens``, so
    #: it only fires against a target that reports usage (a bare model, not a black-box
    #: app endpoint). See :func:`~llmsectest.probes.detectors.output_ceiling_reached`.
    cost_ceiling: bool = False

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"{self.id}: invalid severity {self.severity!r}")
        if not self.forbidden and not self.tokenless:
            raise ValueError(f"{self.id}: at least one forbidden token is required")

    def __repr__(self) -> str:
        return f"ProbeCase({self.id})"


@dataclass(frozen=True)
class ProbeOutcome:
    """The result of running one :class:`ProbeCase` against a target adapter."""

    case: ProbeCase
    response: str
    vulnerable: bool
    evidence: str
    #: The provider-reported output-token count for the reply, when the target
    #: returns one (local runtimes / OpenAI / Anthropic do; a black-box app
    #: endpoint does not) — the precise per-probe cost figure. ``None`` when the
    #: target reports no usage.
    output_tokens: int | None = None
    #: True when the probe could not be scored because the target did not respond
    #: within its per-request time budget. Recorded as *inconclusive* — neither a
    #: finding (a timeout is not proof of a vulnerability) nor a clean pass — so a
    #: single hung endpoint never takes down the rest of the scan. ``evidence``
    #: carries the timeout detail. See :func:`~llmsectest.probes.runner.run_probe`.
    errored: bool = False
