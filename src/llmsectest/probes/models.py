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
    #: When True a per-request **timeout** on this case is itself evidence, provided the
    #: target has demonstrably answered other probes inside the same budget. Set only on
    #: *bounded*, self-terminating requests (repeat a marker N times; enumerate 1..N),
    #: which a healthy app answers in one short reply — so exhausting the caller's whole
    #: budget on one is disproportionate work, i.e. unbounded consumption. Without the
    #: flag, and without that demonstrated responsiveness, a timeout stays *inconclusive*.
    #: See :func:`~llmsectest.probes.runner._timeout_outcome`.
    timeout_is_signal: bool = False

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
    #: True when the probe could not be scored: the target did not respond within its
    #: per-request time budget, or the adapter could not reach it at all (see
    #: :attr:`undelivered`). Recorded as *inconclusive* — neither a finding (failing to
    #: get an answer is not proof of a vulnerability) nor a clean pass — so a single
    #: hung or dead endpoint never takes down the rest of the scan. ``evidence``
    #: carries the detail. See :func:`~llmsectest.probes.runner.run_probe`.
    errored: bool = False
    #: True when the attack never reached the target, or reached it and came back
    #: unusable: an unreachable endpoint, a malformed reply, an auth failure. Always
    #: implies :attr:`errored`; the extra bit is *why*, and it matters because a
    #: timeout is the target refusing to finish while this is the scan never getting
    #: an answer to score. A run holding any of these exits non-zero (see
    #: :meth:`~llmsectest.plugin.SARIFPlugin.pytest_sessionfinish`), because
    #: "0 findings, 25 undelivered" is not a pass.
    undelivered: bool = False
    #: Wall-clock seconds the probe took, measured around the adapter call. Recorded
    #: for a timed-out probe too (there it is the budget that was exhausted), which is
    #: what lets one scan tell a target's ordinary latency apart from a request that
    #: provoked disproportionate work. ``None`` only when a caller builds an outcome
    #: without running one. See :class:`~llmsectest.probes.runner.TargetResponsiveness`.
    elapsed_seconds: float | None = None

    def inconclusive_reason(self) -> str:
        """This outcome's ``evidence``, prefixed with the probe that produced it.

        What the report says when a probe could not be scored. The evidence on its own
        describes the *failure* ("the app did not respond within 90s") and never the
        *probe*, so a run that lost four probes to the clock published four identical
        sentences and no way to tell which four. Measured on the 2026-08-13 cohort pass:
        nine members' reports each said "1 probe inconclusive" for LLM07 and three said
        "3 of 4" for LLM02, and answering *which* three of the four mechanisms went
        unanswered meant re-running the member, because the report did not carry it.

        Two facts go in front of the evidence, and both are actionable. The **case id**
        ends in the technique slug (``…-LLM02-handover-summary``), so a reader learns
        which mechanism was lost rather than only how many. The **elapsed time** says
        whether the probe spent the whole budget or died early, which separates a target
        that is slow from one that is gone. A probe built without being run carries no
        elapsed time and simply omits it rather than printing a zero it did not measure.
        """
        took = "" if self.elapsed_seconds is None else f" after {self.elapsed_seconds:.1f}s"
        return f"{self.case.id} [{self.case.technique}]{took}: {self.evidence}"
