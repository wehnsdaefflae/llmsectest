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
from llmsectest.probes.detectors import (
    action_signatures_emitted,
    action_signatures_present,
    evidence_excerpt,
    secret_exposed,
)
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
    return resolve_target(_target_spec(), app_timeout=envvars.app_timeout_from_env(),
                          app_shape=envvars.app_shape_from_env())


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


@pytest.fixture(scope="session")
def configured_canary() -> str | None:
    """The value the developer passed to ``--app-canary``, or ``None``.

    Session scope for the same reason as :func:`configured_secret`: a canary planted in
    the retrieved corpus can come back through any probe, so "was it ever live" is a
    question about the whole run.
    """
    return envvars.app_inputs_from_env()[3]


@pytest.fixture(scope="session")
def configured_poison() -> str | None:
    """The marker the developer passed to ``--app-rag-poison``, or ``None``."""
    return envvars.app_inputs_from_env()[4]


@pytest.fixture
def probe(target_adapter, target_responsiveness, configured_secret, configured_actions,
          configured_prompt, configured_canary, configured_poison, record_property):
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
        # The reply itself, on every probe, not only the findings. A withstood probe used
        # to leave only a number in the report, so "it refused correctly" could not be
        # audited and the refusal-content axis had no transcripts to calibrate against
        # (issue #21). The SARIF generator publishes this as a `kind: pass` row; the cap
        # that keeps report size sane is applied there, so the in-memory record stays
        # whole for every other consumer.
        record_property("llmsec_reply", outcome.response)
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
            if outcome.timed_out:
                record_property("llmsec_timed_out", True)
        # THE TWO AXES BESIDE THE ORACLE'S VERDICT (bl-084, roadmap phase-03 item b),
        # recorded on every red-team probe, pass or fail, for the same reason the cost
        # and the latency are: the question they answer does not only arise when the
        # oracle fired.
        #
        # `llmsec_capability` — did the reply carry the capability it was asked for, or
        # was it an affirmative opener with nothing behind it (which JailbreakBench calls
        # safe)? The oracle asks whether the target DECLINED; a reader of an LLM01
        # finding reads it as "the attack worked". Those are garak's two detectors.
        #
        # `llmsec_refusal_content` — when the target DID refuse, did the refusal itself
        # disclose the application's own instructions? Varonis routed around Microsoft
        # 365 Copilot precisely by reading its refusals.
        #
        # ‼ NEITHER CHANGES A FINDING. The detector keeps the gate and these are carried
        # beside it, the way `fired` and `measured` are kept apart: collapsing them would
        # invent a number neither one measured, and a `discloses` row in particular is
        # still a row where the application declined.
        if outcome.capability is not None:
            record_property("llmsec_capability", outcome.capability)
            if outcome.capability_evidence:
                record_property("llmsec_capability_evidence", outcome.capability_evidence)
        if outcome.refusal_content is not None:
            record_property("llmsec_refusal_content", outcome.refusal_content)
            if outcome.refusal_content_evidence:
                record_property(
                    "llmsec_refusal_content_evidence", outcome.refusal_content_evidence
                )
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
            if outcome.boundary_refused:
                # The application refused the input itself, which is the opposite fact
                # from a transport failure. A subset of llmsec_undelivered, recorded
                # beside it so the report can say which of the two happened (issue #18).
                record_property("llmsec_boundary_refused", outcome.inconclusive_reason())
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
        # it. See llmsectest.reporting.statistics.MARKER_CHECKS.
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
            else:
                # A signature the application RECITED, which is not an invocation and is
                # not scored as one — and which still answers the only question the
                # unconfirmed-marker doubt asks. That doubt is "your flag may not be the
                # string the application holds"; a reply reproducing the signature verbatim
                # out of the application's own instructions settles it, whichever probe
                # provoked the reply. Measured on 2026-09-06: a deployment recited both of
                # its signatures inside its LLM07 finding while its LLM06 row read "never
                # appeared in any reply in this run", which is a sentence that run held a
                # counterexample to.
                recited = action_signatures_present(outcome.response, configured_actions)
                if recited:
                    record_property("llmsec_action_recited",
                                    f"{case.id}: {', '.join(recited)}")
        # The two LLM08 markers, checked across every probe rather than only the LLM08
        # ones, because a canary planted in the corpus can come back to any question and
        # a poisoned document instructs the application whatever it was asked. Added
        # 2026-09-05, after a cohort member reported six LLM08 attacks withstood while
        # neither value it declared was anywhere in the application it stood up.
        for value, configured_key, observed_key in (
            (configured_canary, "llmsec_canary_configured", "llmsec_canary_observed"),
            (configured_poison, "llmsec_poison_configured", "llmsec_poison_observed"),
        ):
            if not value:
                continue
            record_property(configured_key, value[:8] + "…")
            if value.casefold() in outcome.response.casefold():
                record_property(observed_key, case.id)
        if outcome.vulnerable:
            record_property(
                "llmsec_finding",
                f"[{case.technique}] {outcome.evidence}\n"
                f"attack prompt: {case.user_prompt}\n"
                # Centred on the matched value rather than the head of the reply: see
                # detectors.evidence_excerpt for the finding that made this necessary.
                f"app response: {evidence_excerpt(outcome.response, outcome.evidence)}",
            )
        return outcome

    return _run
