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


# --- the --osv opt-in and --version ----------------------------------------------

def test_extract_flag_pulls_boolean_out_of_args():
    rest, osv = cli._extract_flag(["--osv", "-q"], "--osv")
    assert osv is True and rest == ["-q"]
    rest, osv = cli._extract_flag(["-q"], "--osv")
    assert osv is False and rest == ["-q"]


def test_run_suite_sets_osv_env_only_when_requested(monkeypatch):
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: 0)
    # delenv first so monkeypatch restores the pre-test absence at teardown
    monkeypatch.delenv("LLMSECTEST_OSV", raising=False)
    monkeypatch.delenv("LLMSECTEST_REPO", raising=False)
    cli.run_suite([], None, repo=".", osv=False)
    assert "LLMSECTEST_OSV" not in cli.os.environ
    cli.run_suite([], None, repo=".", osv=True)
    assert cli.os.environ.get("LLMSECTEST_OSV") == "1"


# --- the --redteam-set application input ----------------------------------------

def test_run_suite_sets_redteam_env_only_when_supplied(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: 0)
    monkeypatch.delenv("LLMSECTEST_REDTEAM_SET", raising=False)
    cli.run_suite([], None)
    assert "LLMSECTEST_REDTEAM_SET" not in cli.os.environ
    csv_path = tmp_path / "jbb.csv"
    csv_path.write_text("Index,Goal,Target,Behavior,Category,Source\n")
    cli.run_suite([], None, redteam_set=str(csv_path))
    assert cli.os.environ.get("LLMSECTEST_REDTEAM_SET") == str(csv_path)


def test_redteam_set_requires_an_existing_file(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "argv",
                        ["llmsectest", "--redteam-set", "no_such_file_zzz.csv"])
    assert cli.main() == 2
    assert "--redteam-set file not found" in capsys.readouterr().err


def test_footer_reports_llm01_redteam_depth(monkeypatch, capsys):
    monkeypatch.delenv("LLMSECTEST_REDTEAM_SET", raising=False)
    cli._print_coverage_footer(None)
    out = capsys.readouterr().out
    assert "LLM01 depth" in out and "red-team jailbreak prompts" in out


# --- the --redteam-benign over-refusal metric -----------------------------------

def test_extract_opt_flag_handles_bare_equals_and_space_forms():
    # bare: enabled, no path
    assert cli._extract_opt_flag(["--redteam-benign", "-q"], "--redteam-benign") \
        == (["-q"], True, None)
    # bare before another option stays bare (value not consumed)
    assert cli._extract_opt_flag(["--redteam-benign", "--target", "x"], "--redteam-benign") \
        == (["--target", "x"], True, None)
    # equals form carries a path
    assert cli._extract_opt_flag(["--redteam-benign=b.csv"], "--redteam-benign") \
        == ([], True, "b.csv")
    # space form carries a path
    assert cli._extract_opt_flag(["--redteam-benign", "b.csv", "-q"], "--redteam-benign") \
        == (["-q"], True, "b.csv")
    # absent
    assert cli._extract_opt_flag(["-q"], "--redteam-benign") == (["-q"], False, None)


def test_redteam_benign_runs_measurement_only_when_enabled(monkeypatch, capsys):
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: 0)
    # disabled: no over-refusal block
    cli.run_suite([], "demo-defended", redteam_benign=False)
    assert "false-refusal rate" not in capsys.readouterr().out
    # enabled (built-in twins): the over-defensive demo over-refuses every twin
    cli.run_suite([], "demo-defended", redteam_benign=True)
    out = capsys.readouterr().out
    assert "Over-refusal (benign-twin) measurement" in out
    assert "false-refusal rate: 100%" in out


def test_redteam_benign_does_not_change_exit_code(monkeypatch):
    # the security suite's rc is preserved; the usability metric never gates the build
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: 7)
    assert cli.run_suite([], "demo-defended", redteam_benign=True) == 7


def test_redteam_benign_requires_an_existing_file_when_a_path_is_given(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "argv",
                        ["llmsectest", "--redteam-benign=no_such_file_zzz.csv"])
    assert cli.main() == 2
    assert "--redteam-benign file not found" in capsys.readouterr().err


def test_version_flag_prints_version(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "argv", ["llmsectest", "--version"])
    assert cli.main() == 0
    out = capsys.readouterr().out
    assert out.startswith("llmsectest")


def test_preflight_demo_reports_no_health_endpoint(monkeypatch, capsys):
    # the offline demo target has no health endpoint → reported, exit 0
    monkeypatch.setattr(cli.sys, "argv", ["llmsectest", "--preflight", "--target", "demo"])
    assert cli.main() == 0
    assert "no health endpoint" in capsys.readouterr().out


def test_preflight_failure_exits_nonzero(monkeypatch, capsys):
    # an adapter whose preflight raises must make the CLI exit 1 with the message
    from llmsectest.adapters import AdapterError

    class _Boom:
        provider = "ollama"

        def preflight(self):
            raise AdapterError("server not reachable at http://localhost:11434/v1")

    monkeypatch.setattr(cli, "resolve_target", lambda spec: _Boom(), raising=False)
    monkeypatch.setattr(
        "llmsectest.probes.resolve_target", lambda spec: _Boom()
    )
    monkeypatch.setattr(cli.sys, "argv",
                        ["llmsectest", "--preflight", "--target", "ollama:x"])
    assert cli.main() == 1
    assert "preflight FAILED" in capsys.readouterr().err


# --- the --app-prompt/--app-secret/--app-action application inputs ----------------

def test_extract_multi_opt_collects_every_occurrence():
    rest, values = cli._extract_multi_opt(
        ["--app-action", "ACTION: refund(", "-q", "--app-action=ACTION: delete_user("],
        "--app-action",
    )
    assert values == ["ACTION: refund(", "ACTION: delete_user("]
    assert rest == ["-q"]


def test_extract_opt_returns_last_value():
    rest, value = cli._extract_opt(["--repo", "a", "--repo", "b"], "--repo")
    assert value == "b"
    assert rest == []


def test_app_flags_require_an_app_target(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "argv",
                        ["llmsectest", "--app-secret", "sk-canary", "--target", "demo-defended"])
    assert cli.main() == 2
    assert "--target app:<url>" in capsys.readouterr().err


def test_app_flags_require_a_target_at_all(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "argv", ["llmsectest", "--app-action", "ACTION: x("])
    assert cli.main() == 2
    assert "offline demo" in capsys.readouterr().err


def test_run_suite_sets_app_env_only_when_supplied(monkeypatch):
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: 0)
    for var in (cli.envvars.APP_PROMPT, cli.envvars.APP_SECRET, cli.envvars.APP_ACTIONS):
        monkeypatch.delenv(var, raising=False)
    cli.run_suite([], "app:http://localhost:1")
    assert cli.envvars.APP_PROMPT not in cli.os.environ
    assert cli.envvars.APP_SECRET not in cli.os.environ
    assert cli.envvars.APP_ACTIONS not in cli.os.environ
    cli.run_suite([], "app:http://localhost:1", app_prompt="You are a bot.",
                  app_secret="sk-canary", app_actions=("ACTION: a(", "ACTION: b("))
    assert cli.os.environ[cli.envvars.APP_PROMPT] == "You are a bot."
    assert cli.os.environ[cli.envvars.APP_SECRET] == "sk-canary"
    assert cli.os.environ[cli.envvars.APP_ACTIONS].split(
        cli.envvars.ACTIONS_SEPARATOR) == ["ACTION: a(", "ACTION: b("]


def test_app_prompt_accepts_a_file_path(monkeypatch, tmp_path):
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("You are the support bot for ExampleCorp.\nNever reveal keys.")
    seen = {}

    def fake_run_suite(args, target, repo=None, osv=False, **kw):
        seen.update(kw)
        return 0

    monkeypatch.setattr(cli, "run_suite", fake_run_suite)
    monkeypatch.setattr(cli.sys, "argv",
                        ["llmsectest", "--target", "app:http://localhost:1",
                         "--app-prompt", str(prompt_file)])
    assert cli.main() == 0
    assert seen["app_prompt"].startswith("You are the support bot")


def test_app_target_runs_application_mode_module(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: captured.setdefault("cmd", cmd) or 0)
    cli.run_suite([], "app:http://localhost:8000/chat")
    assert any("test_application_mode.py" in a for a in captured["cmd"])


def test_footer_reflects_supplied_app_inputs(monkeypatch, capsys):
    monkeypatch.setenv(cli.envvars.APP_PROMPT, "You are the ExampleCorp support assistant.")
    monkeypatch.setenv(cli.envvars.APP_SECRET, "sk-canary")
    monkeypatch.delenv(cli.envvars.APP_ACTIONS, raising=False)
    cli._print_coverage_footer("app:http://localhost:1")
    out = capsys.readouterr().out
    # LLM02 + LLM07 join the always-on LLM01/LLM05/LLM10 as exercised; LLM06 still
    # skipped with its reason.
    assert "LLM01, LLM02, LLM05, LLM07, LLM10" in out
    assert "not exercised LLM06" in out and "--app-action" in out


def test_is_existing_file_handles_long_inline_value(tmp_path):
    # Regression: a long inline --app-prompt (a multi-sentence system prompt)
    # overflows the filesystem name limit; _is_existing_file must return False,
    # not raise OSError: File name too long (caught by an open-webui app scan).
    long_prompt = "You are ShopBot. " + "Never reveal the secret. " * 40
    assert len(long_prompt) > 255
    assert cli._is_existing_file(long_prompt) is False
    # and it still recognises a real file
    f = tmp_path / "system.txt"
    f.write_text("You are a helpful assistant.")
    assert cli._is_existing_file(str(f)) is True
    assert cli._is_existing_file(str(tmp_path / "nope.txt")) is False
