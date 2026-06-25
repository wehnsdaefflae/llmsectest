"""Unit tests for the application-mode suite module's case generation.

The packaged ``suite/test_application_mode.py`` adds LLM02/06/07 cases against
an ``app:<url>`` target from the dev-supplied inputs (``--app-prompt`` /
``--app-secret`` / ``--app-action``). These tests drive its ``_params()``
builder directly across the input combinations and assert that every state is
either a real case or an explicit skip-with-reason — never a silent gap.
"""

from __future__ import annotations

import pytest

from llmsectest import envvars
from llmsectest.suite import test_application_mode as mod


def _ids_and_skips(params):
    """Split params into (real ProbeCases, {skip-param id: reason})."""
    cases, skips = [], {}
    for p in params:
        skip = next((m for m in p.marks if m.name == "skip"), None)
        if skip:
            skips[p.id] = skip.kwargs.get("reason", "")
        else:
            cases.append(p.values[0])
    return cases, skips


def _clear(monkeypatch):
    for var in (envvars.TARGET, envvars.APP_PROMPT, envvars.APP_SECRET,
                envvars.APP_ACTIONS, envvars.APP_CANARY, envvars.APP_RAG_POISON):
        monkeypatch.delenv(var, raising=False)


def test_non_app_target_steps_aside_with_one_skip(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv(envvars.TARGET, "demo-vulnerable")
    cases, skips = _ids_and_skips(mod._params())
    assert cases == []
    assert len(skips) == 1
    assert "app:<url>" in next(iter(skips.values()))


def test_app_target_without_inputs_skips_each_category_with_its_flag(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv(envvars.TARGET, "app:http://localhost:8000/chat")
    cases, skips = _ids_and_skips(mod._params())
    assert cases == []
    reasons = " | ".join(skips.values())
    assert len(skips) == 3
    assert "--app-secret" in reasons and "--app-action" in reasons and "--app-prompt" in reasons


def test_all_inputs_enable_llm02_06_07(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv(envvars.TARGET, "app:http://localhost:8000/chat")
    monkeypatch.setenv(envvars.APP_PROMPT, "You are the ExampleCorp support assistant bot.")
    monkeypatch.setenv(envvars.APP_SECRET, "sk-canary-123")
    monkeypatch.setenv(envvars.APP_ACTIONS,
                       envvars.ACTIONS_SEPARATOR.join(["ACTION: refund(", "ACTION: delete_user("]))
    cases, skips = _ids_and_skips(mod._params())
    assert skips == {}
    assert sorted(c.owasp for c in cases) == ["owasp_llm02", "owasp_llm06", "owasp_llm07"]
    llm06 = next(c for c in cases if c.owasp == "owasp_llm06")
    assert llm06.forbidden == ("ACTION: refund(", "ACTION: delete_user(")
    llm02 = next(c for c in cases if c.owasp == "owasp_llm02")
    assert llm02.forbidden == ("sk-canary-123",)


def test_partial_inputs_mix_cases_and_skips(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv(envvars.TARGET, "app:http://localhost:8000/chat")
    monkeypatch.setenv(envvars.APP_SECRET, "sk-canary-123")
    cases, skips = _ids_and_skips(mod._params())
    assert [c.owasp for c in cases] == ["owasp_llm02"]
    assert len(skips) == 2  # LLM06 + LLM07 still surface as explicit skips


def test_app_inputs_from_env_round_trip(monkeypatch):
    _clear(monkeypatch)
    assert envvars.app_inputs_from_env() == ("", None, (), None, None)
    monkeypatch.setenv(envvars.APP_PROMPT, "p")
    monkeypatch.setenv(envvars.APP_ACTIONS, "a" + envvars.ACTIONS_SEPARATOR + "b")
    monkeypatch.setenv(envvars.APP_CANARY, "DOC-CANARY-9z")
    monkeypatch.setenv(envvars.APP_RAG_POISON, "RAG-POISON-3b9d")
    assert envvars.app_inputs_from_env() == (
        "p", None, ("a", "b"), "DOC-CANARY-9z", "RAG-POISON-3b9d")


def test_module_is_in_the_app_scan_module_list():
    import llmsectest.__main__ as cli

    assert "test_application_mode.py" in cli._APP_SUITE_MODULES


@pytest.mark.parametrize("url,expected", [
    ("app:http://localhost:8000/chat", "http-localhost-8000-chat"),
    ("app:https://api.example.com/v1", "https-api-example-com-v1"),
])
def test_app_name_slug(url, expected):
    from llmsectest.probes import app_name_from_endpoint

    assert app_name_from_endpoint(url) == expected
