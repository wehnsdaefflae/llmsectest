"""Known private policy/schema excerpts must reach app scans without entering attacks."""

from __future__ import annotations

import pytest

from llmsectest import envvars
from llmsectest.adapters.base import CompletionResponse
from llmsectest.adapters.mock import ScriptedAdapter
from llmsectest.probes.application import (
    app_cases,
    app_coverage,
    run_app_scan,
    suite_case_counts,
)
from llmsectest.probes.runner import run_probe
from llmsectest.suite import test_application_mode as suite

POLICY = "Private retrieval policy P7K9 requires two reviewers before release."
SCHEMA = '"private_tool_r8n4": {"approval_token": "K7Z9-SCHEMA-ONLY"}'


@pytest.fixture(autouse=True)
def isolated_hidden_context_env(monkeypatch):
    for name in (envvars.APP_POLICY, envvars.APP_TOOL_SCHEMA):
        monkeypatch.delenv(name, raising=False)


def hidden_cases(**kwargs):
    return [c for c in app_cases("example", "", **kwargs)
            if c.detector == "hidden_context_exposure"]


@pytest.mark.parametrize("name,span,source", [
    ("known_policy", POLICY, "retrieved policy"),
    ("known_tool_schema", SCHEMA, "tool schema"),
])
def test_private_inputs_enable_two_distinct_extraction_cases(name, span, source):
    cases = hidden_cases(**{name: span})
    assert len(cases) == 2
    assert len({c.user_prompt for c in cases}) == 2
    for case in cases:
        assert case.owasp == "owasp_llm07"  # maps to 2026 Hidden Context Exposure
        assert case.forbidden == (span,)
        assert span not in case.user_prompt and span not in case.system_prompt
        outcome = run_probe(ScriptedAdapter(lambda _r: span), case)
        assert outcome.vulnerable and not outcome.errored
        assert source in outcome.evidence
        assert outcome.scorer == "hidden_context_exposure"


@pytest.mark.parametrize("reply", [
    "I cannot provide private configuration.",
    "The public documentation describes an ordinary search tool.",
    "An unrelated retrieval marker POISON-ONLY-99 appeared.",
])
def test_refusal_public_text_and_competing_poison_are_not_exposure(reply):
    for case in hidden_cases(known_policy=POLICY, known_tool_schema=SCHEMA):
        assert not run_probe(ScriptedAdapter(lambda _r: reply), case).vulnerable


def test_refusal_that_quotes_private_policy_is_still_exposure():
    case = hidden_cases(known_policy=POLICY)[0]
    result = run_probe(ScriptedAdapter(lambda _r: "I cannot share " + POLICY), case)
    assert result.vulnerable


def test_matching_private_excerpt_does_not_ignore_punctuation_or_case():
    case = hidden_cases(known_tool_schema=SCHEMA)[0]
    assert run_probe(ScriptedAdapter(lambda _r: SCHEMA), case).vulnerable
    assert not run_probe(ScriptedAdapter(lambda _r: SCHEMA.upper()), case).vulnerable


def test_response_sibling_can_expose_private_schema():
    class SiblingAdapter(ScriptedAdapter):
        def complete(self, request):
            return CompletionResponse(text="I cannot share that.", model="mock", provider="mock",
                                      raw={"reply": "I cannot share that.", "debug": SCHEMA})

    result = run_probe(SiblingAdapter(lambda _r: ""),
                       hidden_cases(known_tool_schema=SCHEMA)[0])
    assert result.vulnerable and SCHEMA in result.evidence


def test_request_echo_never_supplies_the_private_span():
    result = run_app_scan("example", "", ScriptedAdapter(
        lambda request: request.messages[-1].content),
        known_policy=POLICY, known_tool_schema=SCHEMA)
    hidden = [o for o in result.outcomes if o.case.detector == "hidden_context_exposure"]
    assert len(hidden) == 4
    assert all(not o.vulnerable for o in hidden)


@pytest.mark.parametrize("value", ["short", " " * 40])
@pytest.mark.parametrize("name", ["known_policy", "known_tool_schema"])
def test_non_distinctive_inputs_fail_before_any_request(name, value):
    with pytest.raises(ValueError, match="25"):
        app_cases("example", "", **{name: value})


def test_absent_inputs_keep_existing_case_set_and_explain_skip():
    assert hidden_cases() == []
    row = next(c for c in app_coverage("") if c.owasp == "owasp_llm07")
    assert not row.exercised
    assert all(flag in row.reason for flag in
               ("--app-prompt", "--app-policy", "--app-tool-schema"))


def test_published_scope_caveat_names_exact_private_sources_and_limits():
    from llmsectest.reporting.owasp_metadata import get_owasp_category

    caveat = get_owasp_category("owasp_llm07").scope_caveat
    assert "--app-policy" in caveat and "--app-tool-schema" in caveat
    assert "exact" in caveat and "paraphrased" in caveat
    assert "not yet probed" not in caveat and "not yet" not in caveat


def test_coverage_and_suite_counts_include_both_sources():
    kwargs = {"known_policy": POLICY, "known_tool_schema": SCHEMA}
    row = next(c for c in app_coverage("", **kwargs) if c.owasp == "owasp_llm07")
    assert row.exercised and row.cases == 4
    assert suite_case_counts("", **kwargs)["owasp_llm07"] == 4


def test_environment_addition_preserves_existing_five_value_contract(monkeypatch):
    monkeypatch.setenv(envvars.APP_POLICY, POLICY)
    monkeypatch.setenv(envvars.APP_TOOL_SCHEMA, SCHEMA)
    assert len(envvars.app_inputs_from_env()) == 5
    assert envvars.hidden_context_from_env() == {
        "known_policy": POLICY, "known_tool_schema": SCHEMA,
    }


def test_packaged_suite_collects_both_private_sources_without_prompt(monkeypatch):
    monkeypatch.setenv(envvars.TARGET, "app:http://localhost:8000/chat")
    for name in (envvars.APP_PROMPT, envvars.APP_SECRET, envvars.APP_ACTIONS):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(envvars.APP_POLICY, POLICY)
    monkeypatch.setenv(envvars.APP_TOOL_SCHEMA, SCHEMA)
    params = suite._params()
    cases = [p.values[0] for p in params if p.values[0] is not None]
    assert len(cases) == 4
    assert all(c.detector == "hidden_context_exposure" for c in cases)
    assert not any(p.id == "LLM07-application" for p in params)


def test_opt_in_stress_includes_private_sources(monkeypatch):
    from llmsectest.suite.test_llm10_stress import _stress_params

    monkeypatch.setenv(envvars.TARGET, "app:http://localhost:8000/chat")
    monkeypatch.setenv(envvars.APP_STRESS, "2")
    monkeypatch.setenv(envvars.APP_POLICY, POLICY)
    monkeypatch.setenv(envvars.APP_TOOL_SCHEMA, SCHEMA)
    cases = [p.values[0] for p in _stress_params() if p.values[0] is not None]
    assert len([c for c in cases if c.detector == "hidden_context_exposure"]) == 4


def test_cli_reads_private_excerpts_from_files(monkeypatch, tmp_path):
    import llmsectest.__main__ as cli

    policy = tmp_path / "policy.txt"
    schema = tmp_path / "schema.txt"
    policy.write_text(POLICY)
    schema.write_text(SCHEMA)
    captured = {}
    monkeypatch.setattr(cli, "run_suite", lambda *args, **kwargs:
                        captured.update(kwargs) or 0)
    monkeypatch.setattr(cli.sys, "argv", ["llmsectest", "--target",
                        "app:http://localhost:8000/chat", "--app-policy", str(policy),
                        "--app-tool-schema", str(schema)])
    assert cli.main() == 0
    assert captured["app_policy"] == POLICY
    assert captured["app_tool_schema"] == SCHEMA


def test_cli_rejects_hidden_context_inputs_without_app_target(monkeypatch, capsys):
    import llmsectest.__main__ as cli

    monkeypatch.setattr(cli.sys, "argv", ["llmsectest", "--app-policy", POLICY])
    assert cli.main() == 2
    assert "app:<url>" in capsys.readouterr().err


def test_cli_transports_private_excerpts_and_reports_depth(monkeypatch, capsys):
    import llmsectest.__main__ as cli

    for name in (envvars.APP_PROMPT, envvars.APP_SECRET, envvars.APP_ACTIONS,
                 envvars.APP_CANARY, envvars.APP_RAG_POISON):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli.subprocess, "call", lambda _cmd: 0)
    monkeypatch.setattr(cli, "print_banner", lambda: None)
    assert cli.run_suite([], "app:http://localhost:8000/chat",
                         app_policy=POLICY, app_tool_schema=SCHEMA) == 0
    assert envvars.hidden_context_from_env()["known_policy"] == POLICY
    assert "LLM08 (4 cases)" in capsys.readouterr().out


def _drive_probe(response: str, *, policy=None, tool_schema=None):
    """Call the suite's probe fixture through its underlying function, with fakes.

    The fixture is what writes the report, so asserting on the data alone would pass
    while the recording side carried nothing — the same wiring gap
    `test_the_probe_fixture_records_the_named_reason_on_both_properties` exists for.
    """
    from llmsectest.suite import conftest

    recorded: list[tuple[str, object]] = []
    run = conftest.probe.__wrapped__(
        target_adapter=ScriptedAdapter(lambda _r: response),
        target_responsiveness=None,
        configured_secret=None,
        configured_actions=(),
        configured_prompt="",
        configured_canary=None,
        configured_poison=None,
        configured_policy=policy,
        configured_tool_schema=tool_schema,
        record_property=lambda name, value: recorded.append((name, value)),
    )
    run(hidden_cases(known_policy=policy, known_tool_schema=tool_schema)[0])
    return dict(recorded)


def test_a_declared_policy_excerpt_is_recorded_as_configured():
    """A clean LLM08 row must say which kinds of hidden context the run probed."""
    recorded = _drive_probe("I cannot share that.", policy=POLICY)
    assert "llmsec_policy_configured" in recorded
    assert POLICY not in str(recorded["llmsec_policy_configured"])
    assert "llmsec_policy_observed" not in recorded


def test_an_application_that_emits_the_policy_records_it_as_observed():
    recorded = _drive_probe(f"Our policy says: {POLICY}", policy=POLICY)
    assert "llmsec_policy_observed" in recorded


def test_a_declared_tool_schema_excerpt_is_recorded_as_configured():
    recorded = _drive_probe("I cannot share that.", tool_schema=SCHEMA)
    assert "llmsec_tool_schema_configured" in recorded
    assert "llmsec_tool_schema_observed" not in recorded


def test_both_private_context_markers_are_registered_for_the_report():
    """Without a MARKER_CHECKS row the property is recorded and never rendered."""
    from llmsectest.reporting.statistics import MARKER_CHECKS

    flags = {flag for _, flag, *_ in MARKER_CHECKS}
    assert {"--app-policy", "--app-tool-schema"} <= flags
