"""Unit tests for the packaged LLM08 (vector & embedding weaknesses) suite module.

The black-box LLM08 dimension is retrieval exposure: against a RAG ``app:<url>``
target whose confidential retrieved-corpus content is marked with ``--app-canary``,
the module runs retrieval-exposure probes; every other state is an explicit
skip-with-reason (a bare model has no corpus; an app without a canary names the
flag). These tests drive the module's ``_params()`` builder directly.
"""

from __future__ import annotations

from llmsectest import envvars
from llmsectest.suite import test_llm08_vector_embedding as mod


def _ids_and_skips(params):
    cases, skips = [], {}
    for p in params:
        skip = next((m for m in p.marks if m.name == "skip"), None)
        if skip:
            skips[p.id] = skip.kwargs.get("reason", "")
        else:
            cases.append(p.values[0])
    return cases, skips


def _clear(monkeypatch):
    for var in (envvars.TARGET, envvars.APP_PROMPT, envvars.APP_CANARY):
        monkeypatch.delenv(var, raising=False)


def test_non_app_target_skips_with_reason(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv(envvars.TARGET, "demo-vulnerable")
    cases, skips = _ids_and_skips(mod._params())
    assert cases == []
    assert "RAG application" in next(iter(skips.values()))


def test_app_target_without_canary_skips_naming_the_flag(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv(envvars.TARGET, "app:http://localhost:8000/chat")
    cases, skips = _ids_and_skips(mod._params())
    assert cases == []
    assert "--app-canary" in next(iter(skips.values()))


def test_app_target_with_canary_runs_retrieval_exposure_cases(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv(envvars.TARGET, "app:http://localhost:8000/chat")
    monkeypatch.setenv(envvars.APP_CANARY, "DOC-CANARY-9z")
    cases, skips = _ids_and_skips(mod._params())
    assert skips == {}
    assert len(cases) == 3
    assert all(c.owasp == "owasp_llm08" for c in cases)
    assert all(c.forbidden == ("DOC-CANARY-9z",) for c in cases)


def test_module_is_in_the_app_scan_module_list():
    import llmsectest.__main__ as cli

    assert "test_llm08_vector_embedding.py" in cli._APP_SUITE_MODULES
