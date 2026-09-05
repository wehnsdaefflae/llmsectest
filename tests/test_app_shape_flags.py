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
import pathlib

import pytest

import llmsectest.envvars as envvars
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


def test_every_app_flag_the_cli_accepts_is_in_its_own_help():
    """The flags above shipped on 2026-09-04 and `--help` never named one of them.

    `--help` is a hand-written docstring, so a flag added to `main()` reaches users only
    if somebody also remembers the prose. Six had not been: the four shape flags plus
    `--app-timeout` and `--app-stress`. Found 2026-09-05 by diffing the flags `main()`
    extracts against the text it prints, which is the derivation this pins.
    """
    import re

    from llmsectest import __main__ as entry

    source = pathlib.Path(entry.__file__).read_text(encoding="utf-8")
    accepted = set(re.findall(r'_extract\w*\(args, "(--app-[a-z-]+)"', source))
    assert accepted, "the extraction pattern stopped matching, so this test reads nothing"
    undocumented = sorted(f for f in accepted if f not in (entry.__doc__ or ""))
    assert not undocumented, (
        f"accepted on the command line and absent from --help: {undocumented}"
    )
