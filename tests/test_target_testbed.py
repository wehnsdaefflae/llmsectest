"""`--target testbed` scans a target whose clean result can be checked (issue #15).

**The gap.** A clean report reads the same whether the application withstood the probe or
the probe never reached anything that could fail. `docs/guides/target-app.md` names a target
with known answers, Tom Kaltofen's `mloda-rag-testbed`, where Alice can see a document that
Bob cannot. Scanning it took a seven-flag command copied from that project's own docs, and one
mistyped marker makes every probe look withstood for the wrong reason.

**Measured on 2026-11-25** against a locally started testbed (`TESTBED_LLM=fake`,
`TESTBED_RETRIEVAL=all`, its commit 8879025): the long command below reached the application
and scored 43 probes. These tests check that the shortcut expands to that command. They make
no network call.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import llmsectest.__main__ as cli

GUIDE = Path(__file__).resolve().parent.parent / "docs" / "guides" / "target-app.md"

# The command that was run by hand, as (flag, value) pairs.
LONG_FORM = {
    "--app-body": '{"user": "bob"}',
    "--app-session-field": "conversation_id",
    "--app-secret": "SECRET-DEMO-7f2a",
    "--app-canary": "CANARY-EXAMPLEBANK-91ac",
    "--app-rag-poison": "POISON-EXAMPLEBANK-3b9d",
}
TESTBED_URL = "app:http://localhost:8000/chat"


def _pairs(args: list) -> dict:
    return {args[i]: args[i + 1] for i in range(0, len(args), 2)}


def test_testbed_expands_to_the_long_form():
    args, target = cli._expand_testbed_target([], "testbed")
    assert target == TESTBED_URL
    assert _pairs(args) == LONG_FORM


@pytest.mark.parametrize("target", [None, "demo-defended", "openai:gpt-4o-mini",
                                    "app:http://localhost:8000/chat", "testbed:x"])
def test_every_other_target_is_left_alone(target):
    """The side that must not move: only the exact word is a shortcut."""
    args, out = cli._expand_testbed_target(["--repo", "."], target)
    assert out == target
    assert args == ["--repo", "."]


@pytest.mark.parametrize("given", [
    ["--app-body", '{"user": "alice"}'],
    ['--app-body={"user": "alice"}'],
])
def test_a_flag_the_user_typed_wins(given):
    """Alice is the positive control: the same scan, where the canary can be reached. The
    user gets there by overriding one flag, so a default must never be added on top of it."""
    args, _ = cli._expand_testbed_target(list(given), "testbed")
    assert args[:len(given)] == given
    assert sum(a.split("=", 1)[0] == "--app-body" for a in args) == 1
    assert "--app-canary" in args


def _run_main(monkeypatch, argv: list) -> dict:
    captured: dict = {}

    def fake_run_suite(args, target, *rest, **kwargs):
        captured.update(kwargs, args=args, target=target)
        return 0

    monkeypatch.setattr(cli, "run_suite", fake_run_suite)
    monkeypatch.setattr(cli.sys, "argv", ["llmsectest", *argv])
    assert cli.main() == 0
    return captured


def test_main_scans_the_testbed_as_bob(monkeypatch, capsys):
    got = _run_main(monkeypatch, ["--target", "testbed"])
    assert got["target"] == TESTBED_URL
    assert json.loads(got["app_body"]) == {"user": "bob"}
    assert got["app_session_field"] == "conversation_id"
    assert got["app_secret"] == "SECRET-DEMO-7f2a"
    assert got["app_canary"] == "CANARY-EXAMPLEBANK-91ac"
    assert got["app_rag_poison"] == "POISON-EXAMPLEBANK-3b9d"
    # None of the defaults may leak through to pytest as a stray argument.
    assert got["args"] == []
    out = capsys.readouterr().out
    # The user has to learn from the run itself what was scanned and whose project it is.
    assert TESTBED_URL in out
    assert "mloda-rag-testbed" in out


def test_main_scans_the_testbed_as_alice_when_asked(monkeypatch):
    got = _run_main(monkeypatch, ["--target=testbed", "--app-body", '{"user": "alice"}'])
    assert json.loads(got["app_body"]) == {"user": "alice"}
    assert got["app_canary"] == "CANARY-EXAMPLEBANK-91ac"


def test_the_help_text_names_the_shortcut():
    assert "--target testbed" in cli.__doc__


def test_the_guide_documents_the_command_and_whose_project_it_is():
    """The guide is where a first-time user reads what a clean result means here, so it must
    carry the command, the long form it stands for, and the fact that the testbed is somebody
    else's project."""
    text = GUIDE.read_text(encoding="utf-8")
    section = text.split("## A target where you can check a clean result", 1)[1]
    section = section.split("\n## ", 1)[0]
    assert "llmsectest --target testbed" in section
    assert "Tom Kaltofen" in section
    for value in (TESTBED_URL, *LONG_FORM.values()):
        assert value in section, value
