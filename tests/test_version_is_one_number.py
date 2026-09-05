"""The version this package reports is the version it was released as.

Found 2026-09-05 by fresh-eyes, reading the HTML report the tool renders as its audience
rather than as its author. The header said ``Tool: llmsectest v0.1.0`` on a tree whose
``pyproject.toml`` said ``0.3.0`` and whose release on PyPI was ``0.3.0``. The literal in
``llmsectest/__init__.py`` had not moved since the first tagged release on 2026-06-10, and
nothing read the two numbers against each other.

It is three surfaces, not one: ``llmsectest --version`` prints ``__version__``,
``plugin.py`` writes it into every SARIF as ``tool.driver.version``, and the HTML renderer
puts it in the report header. Every ``.sarif`` in ``qa/reports/`` therefore names a version
that never ran, which is a provenance claim about published evidence.

``pyproject.toml`` stays the source of truth because the release workflow already gates a
tag against it. This test is what makes the copy in the package follow it.
"""

from __future__ import annotations

import pathlib
import re
import tomllib

import llmsectest

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _declared() -> str:
    return tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def test_package_version_matches_pyproject() -> None:
    assert llmsectest.__version__ == _declared(), (
        f"llmsectest.__version__ is {llmsectest.__version__!r} and pyproject declares "
        f"{_declared()!r}. Every SARIF driver version, every HTML report header and "
        "`llmsectest --version` report the first one"
    )


def test_the_changelog_has_an_entry_for_this_version() -> None:
    """A version the changelog never announces is one a reader cannot look up."""
    changelog = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    released = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.M)
    assert released, "no released version heading found in CHANGELOG.md"
    assert _declared() in released, (
        f"pyproject declares {_declared()!r} and CHANGELOG.md announces {released[:3]}"
    )


def test_version_flag_reports_the_code_that_is_running(monkeypatch, capsys) -> None:
    """A stale editable install must not make ``--version`` report a version nothing ran."""
    import llmsectest.__main__ as cli

    monkeypatch.setattr("importlib.metadata.version", lambda _name: "0.0.1-stale")
    monkeypatch.setattr(cli.sys, "argv", ["llmsectest", "--version"])
    assert cli.main() == 0
    out = capsys.readouterr().out
    assert llmsectest.__version__ in out
    assert "0.0.1-stale" in out, "the disagreement is the one thing worth printing"
