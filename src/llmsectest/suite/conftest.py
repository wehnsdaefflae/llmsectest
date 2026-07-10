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
from llmsectest.probes.runner import run_probe


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


@pytest.fixture
def probe(target_adapter, record_property):
    """Return a callable that runs a probe case against the resolved target.

    When the case is a finding, record a **clean finding message** — the attack
    technique, the detector's evidence, the attack prompt and the app's response —
    so the SARIF/HTML report shows *what the tested app did wrong*, not pytest's
    assertion traceback through this suite's own code (see SARIFGenerator).
    """

    def _run(case):
        outcome = run_probe(target_adapter, case)
        # Record the provider's real per-probe output-token cost (the concrete
        # denial-of-wallet figure) on every probe that reports usage — pass or
        # fail — so the report carries the cost even when the probe found nothing
        # (a well-behaved but token-hungry model is a cost problem, not a finding).
        # The generator surfaces it per-finding and aggregates a run-level total.
        if outcome.output_tokens is not None:
            record_property("output_tokens", outcome.output_tokens)
        if outcome.errored:
            # A timed-out probe is inconclusive, not clean: surface it as a warning
            # (visible in the pytest summary the CLI prints) and record it as a
            # property so the run is never silently short a probe.
            record_property("llmsec_inconclusive", outcome.evidence)
            warnings.warn(f"{case.id}: {outcome.evidence}", stacklevel=2)
        if outcome.vulnerable:
            record_property(
                "llmsec_finding",
                f"[{case.technique}] {outcome.evidence}\n"
                f"attack prompt: {case.user_prompt}\n"
                f"app response: {outcome.response[:500]}",
            )
        return outcome

    return _run
