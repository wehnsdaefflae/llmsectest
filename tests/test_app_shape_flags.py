"""A real application's HTTP contract is describable from the CLI.

**The gap, 2026-09-04.** `AppEndpointAdapter` has carried `request_field`, `response_path`,
`headers` and `extra_body` since it was written, and none of them was reachable without
writing Python. So the README told users to point the scanner at their endpoint, and the
moment an endpoint was not shaped like the one we imagined they had to write a translation
shim. We wrote five of them: private-gpt speaks Anthropic `/v1/messages`, open-webui has its
own, Langflow wants `{input_value, output_type, input_type}` and answers with the reply five
levels down. Five real applications, five shims, none of it in the tool.

Measured on a deliberately Langflow-shaped endpoint before the flags existed: **23 probes
never delivered, `INCOMPLETE`, nothing learned about the application at all.** With the four
flags and no shim: 8 findings, 16 withstood, 6 of 10 categories exercised.
"""

from __future__ import annotations

import json

import pytest

import llmsectest.envvars as envvars
from llmsectest.adapters.app_endpoint import AppEndpointAdapter
from llmsectest.adapters.base import AdapterError
from llmsectest.probes.demo import resolve_target


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (envvars.APP_REQUEST_FIELD, envvars.APP_RESPONSE_PATH,
                 envvars.APP_HEADERS, envvars.APP_BODY):
        monkeypatch.delenv(name, raising=False)


def test_an_unset_shape_leaves_the_adapter_on_its_defaults():
    """The side that must not move: an application shaped like our default keeps working
    without a single flag."""
    assert envvars.app_shape_from_env() == {}
    a = resolve_target("app:http://x/chat")
    assert a.request_field == "message"
    assert a.response_path is None


def test_each_field_reaches_the_adapter(monkeypatch):
    monkeypatch.setenv(envvars.APP_REQUEST_FIELD, "input_value")
    monkeypatch.setenv(envvars.APP_RESPONSE_PATH, "outputs.0.results.message.text")
    monkeypatch.setenv(envvars.APP_HEADERS, json.dumps({"Authorization": "Bearer t"}))
    monkeypatch.setenv(envvars.APP_BODY, json.dumps({"output_type": "chat"}))
    a = resolve_target("app:http://x/run", app_shape=envvars.app_shape_from_env())
    assert a.request_field == "input_value"
    assert a.response_path == "outputs.0.results.message.text"
    assert a.headers["Authorization"] == "Bearer t"
    assert a.extra_body == {"output_type": "chat"}


def test_the_default_content_type_survives_custom_headers(monkeypatch):
    """A user adding an auth header must not lose the JSON content type with it."""
    monkeypatch.setenv(envvars.APP_HEADERS, json.dumps({"Authorization": "Bearer t"}))
    a = resolve_target("app:http://x/run", app_shape=envvars.app_shape_from_env())
    assert a.headers["Content-Type"] == "application/json"


@pytest.mark.parametrize("raw", ['{"a"', '"a string"', "[1,2]"])
def test_a_malformed_shape_fails_loudly(monkeypatch, raw):
    """Never a silent fallback to the default shape. A scan that talked to the wrong contract
    would record every probe as undelivered, and the honesty guarantee would then faithfully
    report a whole application as unreachable."""
    monkeypatch.setenv(envvars.APP_HEADERS, raw)
    with pytest.raises(SystemExit):
        envvars.app_shape_from_env()


def test_the_shape_is_ignored_for_a_non_app_target(monkeypatch):
    """These describe an HTTP contract, so a demo or provider target must not choke on them."""
    monkeypatch.setenv(envvars.APP_REQUEST_FIELD, "input_value")
    a = resolve_target("demo-defended", app_shape=envvars.app_shape_from_env())
    assert a is not None


# The `--help` check that lived here until 2026-09-05 read only flags matching
# `--app-[a-z-]+`, so it passed while `--redteam-generate`, `--html-output` and
# `--pdf-output` were undocumented: a check whose denominator excluded them.
# `tests/test_cli_help_and_coverage_map.py` asks the question over every option the
# CLI accepts, which is where it belongs.


# --- the prompt's own place in the body ---------------------------------------
#
# Added 2026-09-06, standing up OpenAgent (the-open-agent/openagent v2.90.1), whose only
# chat door is OpenAI-compatible: the prompt belongs at `messages.0.content`, inside a list
# the caller supplies in `--app-body`. A flat key could not reach it, so every such
# application needed a wrapper script — and a wrapper that sends a system message is exactly
# what makes a scan measure the model instead of the application.

def test_the_prompt_reaches_a_list_element_the_body_carries():
    """The OpenAI-compatible shape, described with no shim."""
    a = AppEndpointAdapter(
        endpoint="http://x/v1/chat/completions",
        request_field="messages.0.content",
        extra_body={"model": "m", "stream": False,
                    "messages": [{"role": "user", "content": ""}]},
    )
    assert a._body("attack") == {
        "model": "m", "stream": False,
        "messages": [{"role": "user", "content": "attack"}],
    }


def test_the_body_template_is_not_consumed_by_the_first_probe():
    """`extra_body` is one object shared by every probe, and the placement writes into it,
    so a shallow copy would leave probe 2 sending probe 1's text."""
    a = AppEndpointAdapter(
        endpoint="http://x/v1/chat/completions",
        request_field="messages.0.content",
        extra_body={"messages": [{"role": "user", "content": ""}]},
    )
    a._body("first")
    assert a._body("second")["messages"][0]["content"] == "second"
    assert a.extra_body["messages"][0]["content"] == ""


def test_the_prompt_wins_over_a_static_value_for_the_same_field():
    """The body used to be `{request_field: sent, **extra_body}`, so a body naming the same
    key silently replaced the attacker turn with a fixed sentence and the probe text never
    left this process. Every reply would then be the application answering something else,
    scored as if it had answered the attack."""
    a = AppEndpointAdapter(endpoint="http://x/chat", request_field="message",
                           extra_body={"message": "placeholder", "stream": False})
    assert a._body("attack") == {"message": "attack", "stream": False}


@pytest.mark.parametrize("path,body", [
    ("messages.0.content", {}),                       # no list at all
    ("messages.2.content", {"messages": [{}]}),       # past the end of the one there
    ("0", {"messages": [{}]}),                        # the body itself is not a list
])
def test_an_index_with_no_list_under_it_is_still_refused(path, body):
    """The original refusal was right about the case it was written for: a path cannot say
    how long a list the application never asked for should be."""
    a = AppEndpointAdapter(endpoint="http://x/chat", request_field=path, extra_body=body)
    with pytest.raises(AdapterError, match="named fields only"):
        a._body("attack")
