"""Unit tests for the CLI's per-target report-path defaults.

These guard the footgun that scanning several targets back-to-back used to
overwrite a single ``results/pytest-results.sarif``; the CLI now derives a
per-target default path, and ``--validate`` resolves the same default.
"""

from __future__ import annotations

import llmsectest.__main__ as cli


def test_target_slug_for_provider_spec():
    assert cli.target_slug("openai:gpt-4o-mini") == "openai-gpt-4o-mini"
    assert cli.target_slug("anthropic:claude-3-5-haiku") == "anthropic-claude-3-5-haiku"


def test_target_slug_defaults_to_demo():
    assert cli.target_slug(None) == cli.DEFAULT_TARGET
    assert cli.target_slug("") == cli.DEFAULT_TARGET
    assert cli.target_slug("   ") == cli.DEFAULT_TARGET


def test_distinct_targets_get_distinct_paths():
    a = cli.default_sarif_path("demo-vulnerable")
    b = cli.default_sarif_path("demo-defended")
    assert a != b
    assert a == "results/demo-vulnerable.sarif"
    assert b == "results/demo-defended.sarif"


def test_extract_target_pulls_value_out_of_args():
    rest, target = cli._extract_target(["--target", "openai:gpt-4o-mini", "-q"])
    assert target == "openai:gpt-4o-mini"
    assert rest == ["-q"]
    rest, target = cli._extract_target(["--target=demo-defended"])
    assert target == "demo-defended"
    assert rest == []


def test_run_suite_injects_per_target_sarif_path(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: captured.setdefault("cmd", cmd) or 0)
    cli.run_suite([], "openai:gpt-4o-mini")
    assert "--sarif-output=results/openai-gpt-4o-mini.sarif" in captured["cmd"]


def test_run_suite_respects_explicit_sarif_output(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: captured.setdefault("cmd", cmd) or 0)
    cli.run_suite(["--sarif-output=custom/out.sarif"], "demo-defended")
    sarif_opts = [a for a in captured["cmd"] if a.startswith("--sarif-output")]
    assert sarif_opts == ["--sarif-output=custom/out.sarif"]
