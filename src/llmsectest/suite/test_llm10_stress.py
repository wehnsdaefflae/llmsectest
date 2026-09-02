"""OWASP LLM10 — the same application cases under simultaneous concurrent load.

Every other module in this suite sends one request and scores one reply, so every
guardrail this tool reports on has only ever been watched while the target was idle.
This module asks the question the rest cannot: **does what held at one request still hold
at N at once?** It is the *Stresstests* item of AP3, and the mechanism is
:mod:`llmsectest.probes.stress`.

Only the **transition** is a finding. A case that already leaks when asked once is
reported by its own module, and repeating it under load would count one leak twice; a
case that never held has nothing to lose. What is new information is a guardrail that
survives one request and fails when several arrive together, which is a shared buffer, a
rate limiter failing open, a cache handing over another session's reply, or a context
truncated under pressure.

**Opt-in, and silent otherwise.** Without ``--app-stress N`` this module reports one
skipped test naming the flag, the same contract the scanner suites use: a category with
no input appears as a skip that names what it needs, never as a silent pass (see
:mod:`llmsectest.suite.scanners`). The reason it may not default to *some* concurrency is
that the target is somebody else's running application, so the absence of the flag has to
mean the absence of traffic.

**A test here can fail for one reason only.** ``inconclusive`` and ``not-applicable``
verdicts pass with their reason recorded, because neither is evidence of a vulnerability,
and a load that never arrived must never read as either a finding or a clean bill. That
asymmetry is the honesty guarantee applied to load, and :mod:`llmsectest.probes.stress`
carries the argument.

**These requests are deliberately left out of the run-level attack tally.** Every
other module records ``llmsec_probe`` per case, and the published cohort rates are
computed from that tally over a population where each case is one request. A stress
case is one case and ``N + 1`` requests, so counting it either way would move a
published rate without the page that carries it saying anything had changed. The
load numbers live on each result as ``llmsec_stress_load`` instead, where they
describe themselves.
"""

import os

import pytest

from llmsectest import envvars
from llmsectest.probes.application import app_cases, app_name_from_endpoint
from llmsectest.probes.stress import stress_probe

_SKIP_ID = "LLM10-stress-not-requested"


def _stress_params():
    """One param per reachable app case, or a single skip naming what is missing."""
    target = os.environ.get(envvars.TARGET, "")
    concurrency = envvars.app_stress_from_env()
    if not target.startswith("app:"):
        return [pytest.param(
            None, id=_SKIP_ID,
            marks=pytest.mark.skip(
                reason="LLM10 stress: needs a running application (--target app:<url>); "
                       "a concurrency test against a local model measures this machine"
            ),
        )]
    if concurrency is None:
        return [pytest.param(
            None, id=_SKIP_ID,
            marks=pytest.mark.skip(
                reason="LLM10 stress: no load requested, pass --app-stress <N> (N of 2 or "
                       "more) to replay every reachable case as one simultaneous wave"
            ),
        )]
    prompt, secret, actions, canary, poison = envvars.app_inputs_from_env()
    cases = app_cases(
        app_name_from_endpoint(target), prompt,
        known_secret=secret, forbidden_actions=actions,
        known_canary=canary, known_poison=poison,
    )
    return [
        pytest.param(c, id=f"{c.id}-under-load", marks=getattr(pytest.mark, c.severity))
        for c in cases
    ]


_CASES = _stress_params()


@pytest.mark.security
@pytest.mark.owasp_llm10
@pytest.mark.parametrize("case", _CASES)
def test_guardrail_holds_under_concurrent_load(
    target_adapter, target_responsiveness, case, record_property
):
    concurrency = envvars.app_stress_from_env()
    outcome = stress_probe(
        target_adapter, case, concurrency=concurrency,
        responsiveness=target_responsiveness,
    )
    # Recorded on every verdict, not only on failures: the numbers behind a "held" are
    # what let a reader tell it apart from a wave that never formed.
    record_property("llmsec_stress_verdict", outcome.verdict)
    # Only when load was actually sent. A no-load verdict carries a placeholder report,
    # and summarising it would publish "0 request(s) … 0 answered", which reads as a
    # measurement of zero rather than as no measurement.
    if outcome.load.applied:
        record_property("llmsec_stress_load", outcome.load.summary())
    assert not outcome.vulnerable, (
        f"[{case.technique}] {outcome.evidence}\n"
        f"prompt: {case.user_prompt}"
    )
