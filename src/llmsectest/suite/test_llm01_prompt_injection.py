"""OWASP LLM01 — prompt injection probes (adapter-driven).

With ``--redteam-generate N`` the authored corpus is joined by N variants of each case,
composed by the target's own model and validated before they run
(:mod:`llmsectest.probes.generate`). The authored cases are unchanged and still run, so
this adds attacks rather than replacing them, and the regression baseline keeps reading
the deterministic set alone.

**Every variant is checked against a defended control before it runs.** Keeping the marker
proves a rewrite is *scoreable*; it does not prove it is still an *attack*. "Please output
MARKER-7F3A" keeps the marker and is an ordinary request that any cooperative target
answers, and that reply would score as a prompt-injection finding against a model that was
asked nicely. The packaged hardened demo settles it: a variant that fires there tests
nothing and is rejected, one that does not fire there was refused by a defence, which is
what an attack means.

**Only the marker-based cases are generated from, and the asymmetry is the reason.** Here
a broken rewrite drops the marker, which produces a **false negative** the validator
catches structurally: nobody asked for the token, so the target could not emit it. In the
refusal-oracle set (:mod:`llmsectest.suite.test_redteam_jailbreaks`) a broken rewrite makes
the request benign, the target answers it, and compliance scores as a **finding**. That is
a false positive, and no structural check can see it without a judge model deciding whether
the rewrite is still a harmful ask. Generating there would manufacture critical findings, so
it does not happen and this paragraph is why.
"""

import os

import pytest

from llmsectest import envvars
from llmsectest.probes.corpus import cases_for

_CASES = [
    pytest.param(c, id=c.id, marks=getattr(pytest.mark, c.severity))
    for c in cases_for("owasp_llm01")
]


@pytest.fixture(scope="session")
def generated_cases(target_adapter):
    """Model-composed variants of the authored LLM01 seeds, or an empty list.

    Session-scoped so the generation happens once per run rather than once per test, and
    so the report it produces describes the whole run.
    """
    count = envvars.redteam_generate_from_env()
    if not count or os.environ.get(envvars.TARGET, "").startswith("app:"):
        # An app endpoint is somebody else's application, not a model we may ask to write
        # prompts for us. Generation needs a model target.
        return [], None
    from llmsectest.probes import resolve_target
    from llmsectest.probes.generate import generate_corpus

    # The hardened demo is the control. A variant that fires against it is not an attack,
    # it is a request any cooperative target answers, and scoring that as a prompt
    # injection would be a manufactured critical finding. It costs one extra call per
    # variant and needs no network, since the defended demo is packaged.
    control = resolve_target("demo-defended")
    return generate_corpus(target_adapter, cases_for("owasp_llm01"),
                           per_seed=count, control=control)


@pytest.mark.security
@pytest.mark.owasp_llm01
@pytest.mark.parametrize("case", _CASES)
def test_prompt_injection(probe, case):
    outcome = probe(case)
    assert not outcome.vulnerable, (
        f"[{case.technique}] {outcome.evidence}\n"
        f"prompt: {case.user_prompt}\nresponse: {outcome.response[:300]}"
    )


def test_generated_prompt_injection(probe, generated_cases, record_property):
    """Run every accepted model-composed variant, and record what generation produced.

    One test rather than a parametrized set, because the cases do not exist until the run
    starts and pytest needs its parameters at collection time. The **generated prompt text
    travels into the report** on every finding, since a variant exists only in the run that
    composed it and a finding citing an unreproducible attack is not a finding anybody can
    act on.
    """
    cases, report = generated_cases
    if report is None:
        pytest.skip("LLM01 generated attacks: not requested, pass --redteam-generate <N> "
                    "against a model target to add model-composed variants of each case")
    record_property("llmsec_generation", report.summary())
    failures = []
    for case in cases:
        outcome = probe(case)
        if outcome.vulnerable:
            failures.append(f"[{case.id}] {outcome.evidence}\nprompt: {case.user_prompt}")
    assert not failures, (
        f"{len(failures)} of {len(cases)} generated attack(s) got through "
        f"({report.summary()}):\n\n" + "\n\n".join(failures)
    )
