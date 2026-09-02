"""Concurrent-load (stress) testing: does a guardrail that holds at one request hold at N?

The Antrag names *Stresstests* beside supply-chain testing, SBOM and embedding inversion
as the four capabilities of AP3, whose milestone is full coverage of the OWASP categories.
Everything else this package does sends **one** request and scores **one** reply, which
means every guardrail we report on has only ever been observed idle. This module is the
missing half: it puts the same probe under simultaneous load and asks whether the answer
changes.

**The finding is differential, and that is the whole design.** A case that already leaks
at concurrency 1 is an ordinary finding and the normal scan already reports it; repeating
it under load adds nothing. What is new information is a case the target **withstood**
when asked once and **failed** when asked N times at once: a filter with a shared buffer,
a rate limiter that fails open, a cache that serves another session's reply, a truncated
system prompt under memory pressure. Only that transition is reported here, and it is
reported as the transition rather than as a fresh leak.

**A "withstood under load" row is worthless if the load never arrived**, which is this
project's closed-world bias (:file:`STATE.md`) pointed at a stopwatch: the unexamined
read as the fine. So the arithmetic runs the other way round. Every run records what
*actually* happened, and the verdict is allowed to be "held" only when the wave it claims
to describe demonstrably formed. Three specific consequences:

* Workers meet at a :class:`threading.Barrier` before issuing their request, so the wave
  is simultaneous by construction rather than by luck. Without it, a target that answers
  faster than the pool dispatches would be reported as having survived a concurrency it
  never saw.
* :attr:`LoadReport.peak_outstanding` is named for what it measures, which is **our**
  side of the wire. We can count requests we have sent and not yet had back; we cannot see
  the target's own queue. Claiming "the app served N concurrently" from that number would
  be the same overreach as reading an unanswered probe as a withstood one.
* A request the target **refused with a rate limit** is not a request it served, so a
  throttled wave never counts as an arrived one. It leaves an inconclusive differential
  and a separate, positive observation: a defence fired. Both facts are true and the
  report carries both.

**A timeout under deliberate load is inconclusive here, always.** The ordinary scan is
allowed to read a timeout on a bounded LLM10 probe as a finding, because a target that
answers everything else comfortably has been made to do disproportionate work by that one
request (see :func:`~llmsectest.probes.runner._timeout_outcome`). Under load that argument
collapses: the target is slow because we made it busy, which was the point. Load requests
are therefore run with **no** :class:`~llmsectest.probes.runner.TargetResponsiveness`
record, which is what makes the timeout branch fall through to inconclusive, and it is
thread-safety for free, since nothing shared is mutated from the pool.
"""

from __future__ import annotations

import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from ..adapters.base import LLMAdapter
from .models import ProbeCase, ProbeOutcome
from .runner import TargetResponsiveness, run_probe

#: The verdicts a stress comparison can reach. Four rather than two, because the two
#: interesting failures of this kind of test are *not* "vulnerable" and "safe": they are
#: "the load never formed" and "there was nothing to compare against". Folding either into
#: a pass is the defect this whole module is written around.
STRESS_VERDICTS = ("regressed", "held", "inconclusive", "not-applicable")

#: How long a worker waits at the start barrier for its wave to assemble. Generous, since
#: it only has to cover thread start-up, and a wave that cannot form inside it is reported
#: as a broken wave rather than hanging the scan.
_BARRIER_TIMEOUT = 30.0


@dataclass(frozen=True)
class LoadReport:
    """What one wave of concurrent requests actually did, as opposed to what was asked for.

    Every field is a count of something observed. There is deliberately no field for the
    target's own concurrency: nothing on this side of the wire can measure it, and a name
    like ``server_concurrency`` would invite a claim the data does not support.
    """

    #: Concurrency the caller asked for.
    requested_concurrency: int
    #: How many waves of ``requested_concurrency`` requests were sent.
    waves: int
    #: Requests issued in total (``requested_concurrency * waves``).
    requests: int
    #: The largest number of requests that were simultaneously outstanding **from here**:
    #: sent and not yet answered. Our side of the wire, and named for it.
    peak_outstanding: int
    #: Requests the target answered with something scoreable.
    completed: int
    #: Requests that never came back usable (transport failure, malformed reply, auth).
    undelivered: int
    #: Requests the target refused with a rate limit. A subset of ``undelivered``, and the
    #: one subset that is *good* news about the target.
    throttled: int
    #: Requests that exhausted their per-request budget.
    timed_out: int
    #: Wall-clock seconds from the first request leaving to the last one returning.
    wall_seconds: float
    #: Per-request wall-clock seconds, completions only.
    latencies: tuple[float, ...] = ()
    #: True when a wave could not be assembled at all (a worker died before the barrier).
    broken_wave: bool = False

    @property
    def load_arrived(self) -> bool:
        """Whether this run may be described as a test at ``requested_concurrency``.

        Both halves are required and neither is redundant. The peak says the requests
        were outstanding together, which is the concurrency claim. The completion count
        says the target actually answered them, which is what stops a wave of refusals or
        dead connections from reading as a survived load test.
        """
        if self.broken_wave:
            return False
        return (
            self.peak_outstanding >= self.requested_concurrency
            and self.completed >= self.requests
        )

    @property
    def applied(self) -> bool:
        """Whether any load was actually sent.

        False for the placeholder report a no-load verdict carries. It exists because the
        alternative, summarising that placeholder, prints *"0 request(s) ... 0 answered"*,
        which reads as a measurement of zero load rather than as no measurement at all.
        That is the absence-versus-zero distinction this whole module is about, and it was
        being got wrong one layer above the code that argues for it: caught on 2026-09-02
        by reading the first SARIF that carried the property, where four `not-applicable`
        cases had each contributed a zero line.
        """
        return self.requests > 0

    @property
    def achieved_rps(self) -> float:
        """Completed requests per second of wall clock. ``0.0`` when nothing completed."""
        if self.wall_seconds <= 0 or not self.completed:
            return 0.0
        return self.completed / self.wall_seconds

    @property
    def median_latency(self) -> float | None:
        return statistics.median(self.latencies) if self.latencies else None

    @property
    def slowest_latency(self) -> float | None:
        return max(self.latencies) if self.latencies else None

    def summary(self) -> str:
        """One line of evidence, always carrying the numbers behind the verdict."""
        parts = [
            (f"{self.requests} request(s) in {self.waves} wave(s) of "
             f"{self.requested_concurrency}"),
            (f"peak {self.peak_outstanding} outstanding at once "
             "(measured here, not on the target)"),
            f"{self.completed} answered",
        ]
        if self.throttled:
            parts.append(f"{self.throttled} rate limited")
        if self.undelivered - self.throttled:
            parts.append(f"{self.undelivered - self.throttled} undelivered")
        if self.timed_out:
            parts.append(f"{self.timed_out} timed out")
        parts.append(f"{self.wall_seconds:.1f}s wall clock")
        if self.completed:
            parts.append(f"{self.achieved_rps:.2f} answered/s")
        # Guarded on the latencies rather than on ``completed``: a target can answer
        # without the caller having timed it (an outcome built by hand, a completion
        # recorded with no elapsed time), and a summary that crashed there would take
        # down the report of a run that had otherwise worked perfectly well.
        if self.latencies:
            parts.append(
                f"latency median {self.median_latency:.1f}s, slowest "
                f"{self.slowest_latency:.1f}s"
            )
        if self.broken_wave:
            parts.append("the wave did not assemble")
        return "; ".join(parts)


def _is_throttled(outcome: ProbeOutcome) -> bool:
    """Whether this outcome was a rate-limit refusal.

    Reads the structured flag rather than matching the evidence prose. The prose is
    written for a person and gets reworded; a report that counted throttles by looking
    for the words "rate limited" would silently start counting zero the first time
    somebody improved the sentence.
    """
    return outcome.throttled


def run_load(
    adapter: LLMAdapter,
    case: ProbeCase,
    *,
    concurrency: int,
    waves: int = 1,
) -> tuple[LoadReport, tuple[ProbeOutcome, ...]]:
    """Send ``case`` ``concurrency`` times at once, ``waves`` times over, and report both.

    Returns the measured :class:`LoadReport` and every outcome, in completion order. The
    outcomes are scored by the ordinary detectors, so a leak under load is recognised by
    exactly the oracle that would have recognised it when idle.

    Each wave is assembled at a barrier, so the requests genuinely overlap. Threads are
    the right instrument here rather than an async rewrite: every adapter call is one
    blocking HTTP round trip, and each worker builds its own request and its own outcome,
    sharing nothing but the adapter itself.
    """
    if concurrency < 1:
        raise ValueError(f"concurrency must be at least 1, got {concurrency}")
    if waves < 1:
        raise ValueError(f"waves must be at least 1, got {waves}")

    barrier = threading.Barrier(concurrency)
    lock = threading.Lock()
    outstanding = 0
    peak = 0
    broken = False

    def one_request(_: int) -> ProbeOutcome:
        nonlocal outstanding, peak, broken
        try:
            barrier.wait(timeout=_BARRIER_TIMEOUT)
        except threading.BrokenBarrierError:
            with lock:
                broken = True
        with lock:
            outstanding += 1
            peak = max(peak, outstanding)
        try:
            # No responsiveness record on purpose: under deliberate load a timeout is
            # saturation rather than evidence about the request, so it must stay
            # inconclusive. See this module's docstring.
            return run_probe(adapter, case, None)
        finally:
            with lock:
                outstanding -= 1

    outcomes: list[ProbeOutcome] = []
    started = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            for _ in range(waves):
                barrier.reset()
                outcomes.extend(pool.map(one_request, range(concurrency)))
    finally:
        wall = time.monotonic() - started

    completed = [o for o in outcomes if not o.errored]
    report = LoadReport(
        requested_concurrency=concurrency,
        waves=waves,
        requests=concurrency * waves,
        peak_outstanding=peak,
        completed=len(completed),
        undelivered=sum(1 for o in outcomes if o.undelivered),
        throttled=sum(1 for o in outcomes if _is_throttled(o)),
        timed_out=sum(1 for o in outcomes if o.errored and not o.undelivered),
        wall_seconds=wall,
        latencies=tuple(
            o.elapsed_seconds for o in completed if o.elapsed_seconds is not None
        ),
        broken_wave=broken,
    )
    return report, tuple(outcomes)


@dataclass(frozen=True)
class StressOutcome:
    """One case compared between an idle request and a concurrent wave of them."""

    case: ProbeCase
    baseline: ProbeOutcome
    load: LoadReport
    load_outcomes: tuple[ProbeOutcome, ...]
    verdict: str
    evidence: str

    def __post_init__(self) -> None:
        if self.verdict not in STRESS_VERDICTS:
            raise ValueError(f"{self.case.id}: unknown verdict {self.verdict!r}")

    @property
    def vulnerable(self) -> bool:
        """Only a genuine transition is a finding. See :data:`STRESS_VERDICTS`."""
        return self.verdict == "regressed"

    @property
    def regressions(self) -> tuple[ProbeOutcome, ...]:
        """The load outcomes the detector flagged."""
        return tuple(o for o in self.load_outcomes if o.vulnerable)


def stress_probe(
    adapter: LLMAdapter,
    case: ProbeCase,
    *,
    concurrency: int,
    waves: int = 1,
    baseline: ProbeOutcome | None = None,
    responsiveness: TargetResponsiveness | None = None,
) -> StressOutcome:
    """Run ``case`` once, then ``concurrency`` times at once, and compare the two.

    ``baseline`` lets a caller reuse an outcome the ordinary scan already produced rather
    than paying for it twice; when omitted one is measured here. The baseline **is** run
    with the shared ``responsiveness`` record, because at concurrency 1 the ordinary
    reading of a timeout still applies.

    The four verdicts, and why each exists rather than collapsing into a pass or a fail:

    ``not-applicable``
        The baseline was already a finding. Nothing about load is being learned, and
        reporting it again would double-count one leak.
    ``inconclusive``
        Either the baseline could not be scored at all, or the wave did not arrive. The
        second is the case this module exists to keep honest: refusals, timeouts and a
        peak below the requested concurrency all mean the target was never observed doing
        the work, so the guardrail was never observed holding.
    ``regressed``
        The baseline withstood, the wave arrived, and the same detector fired under it.
    ``held``
        The baseline withstood, the wave arrived, and nothing fired. Bounded to the
        concurrency actually reached, which the evidence names.
    """
    baseline = baseline if baseline is not None else run_probe(adapter, case, responsiveness)

    if baseline.errored:
        return StressOutcome(
            case=case, baseline=baseline,
            load=LoadReport(
                requested_concurrency=concurrency, waves=waves, requests=0,
                peak_outstanding=0, completed=0, undelivered=0, throttled=0,
                timed_out=0, wall_seconds=0.0,
            ),
            load_outcomes=(), verdict="inconclusive",
            evidence=(
                "no load was applied: the single-request baseline could not be scored, so "
                f"there is nothing to compare a loaded run against ({baseline.evidence})"
            ),
        )
    if baseline.vulnerable:
        return StressOutcome(
            case=case, baseline=baseline,
            load=LoadReport(
                requested_concurrency=concurrency, waves=waves, requests=0,
                peak_outstanding=0, completed=0, undelivered=0, throttled=0,
                timed_out=0, wall_seconds=0.0,
            ),
            load_outcomes=(), verdict="not-applicable",
            evidence=(
                "no load was applied: this case already fails at one request, so it is "
                "reported by the ordinary scan and a failure under load would be the same "
                f"finding counted twice ({baseline.evidence})"
            ),
        )

    load, outcomes = run_load(adapter, case, concurrency=concurrency, waves=waves)
    regressions = [o for o in outcomes if o.vulnerable]

    if regressions:
        return StressOutcome(
            case=case, baseline=baseline, load=load, load_outcomes=outcomes,
            verdict="regressed",
            evidence=(
                f"the guardrail held when asked once and failed under load: "
                f"{len(regressions)} of {load.requests} concurrent request(s) were "
                f"flagged by the same detector that passed the single request. "
                f"{load.summary()}. First regression: {regressions[0].evidence}"
            ),
        )
    if not load.load_arrived:
        return StressOutcome(
            case=case, baseline=baseline, load=load, load_outcomes=outcomes,
            verdict="inconclusive",
            evidence=(
                f"the requested load did not arrive, so this says nothing about the "
                f"guardrail at concurrency {concurrency}: {load.summary()}"
                + (
                    f". {load.throttled} request(s) were refused with a rate limit, which "
                    "is a defence working rather than a failure to test"
                    if load.throttled else ""
                )
            ),
        )
    return StressOutcome(
        case=case, baseline=baseline, load=load, load_outcomes=outcomes,
        verdict="held",
        evidence=(
            f"the guardrail held under concurrent load as well as at rest, at the "
            f"concurrency actually reached and no higher: {load.summary()}"
        ),
    )
