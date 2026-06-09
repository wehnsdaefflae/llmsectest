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


# --- the --opt value footgun: an option's value must not be read as a test path ---

def test_has_explicit_path_empty():
    assert cli._has_explicit_path([]) is False


def test_has_explicit_path_real_positional():
    # `tests` exists relative to the repo root (pytest cwd) -> a real test path.
    assert cli._has_explicit_path(["tests"]) is True


def test_value_opt_value_is_not_a_path_even_if_it_exists():
    # `--report-dir tests` consumes `tests` as the option value; despite the dir
    # existing it must NOT be treated as a positional path (the documented footgun).
    assert cli._has_explicit_path(["--report-dir", "tests"]) is False
    assert cli._has_explicit_path(["--report-formats", "sarif,html"]) is False
    assert cli._has_explicit_path(["-k", "injection"]) is False


def test_unknown_value_is_not_a_path_when_it_does_not_exist():
    assert cli._has_explicit_path(["--report-dir", "no_such_dir_zzz"]) is False
    assert cli._has_explicit_path(["no_such_path_zzz"]) is False


def test_real_positional_after_a_value_opt_is_found():
    assert cli._has_explicit_path(["--report-dir", "tests", "tests"]) is True


def test_run_suite_keeps_packaged_suite_with_spaced_value_option(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: captured.setdefault("cmd", cmd) or 0)
    cli.run_suite(["--report-dir", "tests"], None)
    # The packaged suite must still be the test path (footgun fixed).
    assert str(cli.SUITE_DIR) in captured["cmd"]


def test_run_suite_uses_explicit_path_when_given(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: captured.setdefault("cmd", cmd) or 0)
    cli.run_suite(["tests"], None)
    assert str(cli.SUITE_DIR) not in captured["cmd"]


def test_run_suite_shows_skip_reasons(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: captured.setdefault("cmd", cmd) or 0)
    cli.run_suite([], None)
    assert "-rs" in captured["cmd"]  # skip reasons ("not yet implemented") always print


def test_app_target_scopes_modules_and_keeps_all_ten_coverage(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: captured.setdefault("cmd", cmd) or 0)
    cli.run_suite([], "app:http://localhost:8000/chat")
    cmd = captured["cmd"]
    # the all-10 coverage module runs, so unimplemented categories still surface
    assert any("test_owasp_coverage.py" in a for a in cmd)
    assert any("test_llm01_prompt_injection.py" in a for a in cmd)
    # canary-only modules are NOT run vacuously against a real app whose secrets we don't hold
    assert not any(("test_llm02" in a or "test_llm06" in a or "test_llm07" in a) for a in cmd)
