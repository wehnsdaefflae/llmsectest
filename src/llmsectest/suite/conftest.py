"""Target resolution for the packaged probe suite.

The target is chosen by the ``LLMSECTEST_TARGET`` environment variable (the
``llmsectest`` CLI sets it from ``--target``). With no target set, the suite
runs against the offline demo-vulnerable app so a zero-config run still
produces a meaningful report.
"""

import os
import warnings

import pytest

from llmsectest import envvars
from llmsectest.probes import resolve_target
from llmsectest.probes.detectors import action_signatures_emitted, secret_exposed
from llmsectest.probes.runner import TargetResponsiveness, run_probe


def _target_spec() -> str:
    return os.environ.get(envvars.TARGET, "demo-vulnerable")


@pytest.fixture(autouse=True)
def _locate_finding_at_target(record_property):
    """Locate every finding at the **tested target**, not at this suite's own files.

    A behavioural finding (prompt injection, output handling, prompt leakage, …) is
    about the *application under test* and has no source line in our code, so its
    SARIF location should reference the target — the app endpoint or the model —
    rather than the pytest node inside llmsectest. We record that as the default
    artifact for every test here; a category that knows a more specific artifact in
    the tested project (LLM03 records the offending dependency manifest) records it
    afterwards and overrides this (``dict(user_properties)`` keeps the last value).
    """
    target = _target_spec()
    # Strip the ``app:`` scheme so the location reads as the app's plain endpoint URL.
    artifact = target[len("app:"):] if target.startswith("app:") else target
    record_property("llmsec_artifact_uri", artifact)


@pytest.fixture(scope="session")
def target_adapter():
    return resolve_target(_target_spec(), app_timeout=envvars.app_timeout_from_env())


@pytest.fixture(scope="session")
def target_responsiveness():
    """One latency record shared by every probe of the scan against this target.

    A per-request timeout is ambiguous on its own; what disambiguates it is how the
    *same* target answered everything else. Session scope so one record spans every
    category of the scan rather than restarting per test.
    """
    return TargetResponsiveness()


@pytest.fixture(scope="session")
def configured_secret() -> str | None:
    """The value the developer passed to ``--app-secret``, or ``None``.

    Read once per session so every probe can be checked against it, not only the LLM02
    ones — see :func:`~llmsectest.probes.detectors.secret_exposed` for why that matters.
    """
    return envvars.app_inputs_from_env()[1]


@pytest.fixture(scope="session")
def configured_prompt() -> str:
    """The app's own system prompt as passed to ``--app-prompt`` (``""`` if unknown).

    Needed by the marker check to tell an invocation from the application quoting its
    own documented action grammar back at us.
    """
    return envvars.app_inputs_from_env()[0]


@pytest.fixture(scope="session")
def configured_actions() -> tuple[str, ...]:
    """The signatures the developer passed to ``--app-action``, or ``()``.

    Read once per session for the same reason as :func:`configured_secret`: the question
    "did this marker ever appear at all" is a question about the whole run, not about the
    probes of one category.
    """
    return envvars.app_inputs_from_env()[2]


@pytest.fixture
def probe(target_adapter, target_responsiveness, configured_secret, configured_actions,
          configured_prompt, record_property):
    """Return a callable that runs a probe case against the resolved target.

    When the case is a finding, record a **clean finding message** — the attack
    technique, the detector's evidence, the attack prompt and the app's response —
    so the SARIF/HTML report shows *what the tested app did wrong*, not pytest's
    assertion traceback through this suite's own code (see SARIFGenerator).
    """

    def _run(case):
        outcome = run_probe(target_adapter, case, target_responsiveness)
        # Mark this result as a real attack that was actually delivered to the target.
        # Only the probe path records it, so the run-level tally never counts a
        # coverage assertion or a static scanner as an attack the target withstood.
        record_property("llmsec_probe", case.owasp)
        # Record the provider's real per-probe output-token cost (the concrete
        # denial-of-wallet figure) on every probe that reports usage — pass or
        # fail — so the report carries the cost even when the probe found nothing
        # (a well-behaved but token-hungry model is a cost problem, not a finding).
        # The generator surfaces it per-finding and aggregates a run-level total.
        if outcome.output_tokens is not None:
            record_property("output_tokens", outcome.output_tokens)
        # How long the target took to answer this probe, on every probe. The timed-out
        # ones were already visible; the answered ones were not, and they are the half
        # that says whether a timeout was the target or the machine it ran on. The
        # generator aggregates these into a run-level `latency` property beside
        # `denial_of_wallet` — same shape, same reason: a cost the report should carry
        # whether or not it also carries a finding.
        if outcome.elapsed_seconds is not None:
            record_property("llmsec_elapsed", outcome.elapsed_seconds)
            record_property("llmsec_case", case.id)
        if outcome.errored:
            # A probe that timed out or never reached the target is inconclusive, not
            # clean: surface it as a warning (visible in the pytest summary the CLI
            # prints) and record it as a property so the run is never silently short a
            # probe. The reason names the probe (see ProbeOutcome.inconclusive_reason),
            # because a list of identical failure sentences cannot say which probes were
            # lost, and that is the question a reader of the report actually has.
            record_property("llmsec_inconclusive", outcome.inconclusive_reason())
            if outcome.undelivered:
                # A transport failure is the subset that also fails the whole run, so
                # a scan of a dead endpoint cannot exit 0. Recorded separately from
                # llmsec_inconclusive, which stays the superset the drift check reads.
                record_property("llmsec_undelivered", outcome.inconclusive_reason())
            warnings.warn(f"{case.id}: {outcome.evidence}", stacklevel=2)
        # The cross-probe secret check: every reply, not only the LLM02 ones. A scan that
        # printed the developer's secret must not report sensitive disclosure as withstood,
        # whichever probe provoked the reply that carried it.
        exposed, detail = secret_exposed(outcome.response, configured_secret,
                                         sent=case.user_prompt)
        if exposed:
            record_property("llmsec_secret_exposed", f"{case.id}: {detail}")
        # Was the marker ever *live* in this run? Recorded for the same reason and read
        # the other way round: a configured value that never turns up anywhere leaves a
        # clean row that a defended application and a mistyped flag both produce. The
        # "configured" flags say a doubt is possible at all; the "observed" ones resolve
        # it. See llmsectest.reporting.statistics.MARKER_CATEGORIES.
        if configured_secret:
            record_property("llmsec_secret_configured", configured_secret[:8] + "…")
        if configured_actions:
            record_property("llmsec_action_configured", len(configured_actions))
            # Discounting signatures the app merely recited out of its own documented
            # grammar: measured on 2026-08-10, that is the only place most members ever
            # produce one, and counting it would report the marker as live in a run where
            # nothing was invoked. See detectors.action_signatures_emitted.
            seen = action_signatures_emitted(outcome.response, configured_actions,
                                             configured_prompt)
            if seen:
                record_property("llmsec_action_observed", f"{case.id}: {', '.join(seen)}")
        if outcome.vulnerable:
            record_property(
                "llmsec_finding",
                f"[{case.technique}] {outcome.evidence}\n"
                f"attack prompt: {case.user_prompt}\n"
                f"app response: {outcome.response[:500]}",
            )
        return outcome

    return _run
