"""Two surfaces that describe the CLI have to agree with the CLI.

Both defects these guard were found by the 2026-09-05 self-heal re-derivation, and
both are the same shape: a hand-written description of the code that the code had
moved past. Nothing read the description against the thing it described.

* ``--redteam-generate``, ``--html-output`` and ``--pdf-output`` were live options
  the module docstring never named, and that docstring is ``--help``. A user reading
  the only listing the tool offers could not learn the flag existed. Earlier the same
  day a check for exactly this went into ``test_app_shape_flags.py`` and passed, because
  its pattern was ``--app-[a-z-]+``: three flags outside that prefix were never in its
  denominator. That is the reason this sweep reads the parser calls themselves and
  asserts on how many it found.
* ``docs/owasp/index.md`` called LLM08 black-box in its own coverage table while
  ``--check`` called it ``black-box + white-box`` and named ``--vector-store``. The
  page says the authoritative map is ``llmsectest --check``, so it disagreed with
  the surface it defers to.

Written as tests rather than as repository gates because both are properties of
this package, checkable from its own source, and the checks belong where the thing
they check lives.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

import llmsectest.__main__ as cli

# The CLI parses argv by hand: every option reaches one of these three helpers as a
# string literal, so the source is the register of what the CLI accepts.
_PARSERS = {"_extract_opt", "_extract_flag", "_extract_opt_flag"}

# Relative to this test file, so an installed copy of the package cannot move it.
_DOCS = pathlib.Path(__file__).resolve().parents[1] / "docs" / "owasp"


def _accepted_long_options() -> set[str]:
    """Every ``--long-option`` the CLI's own source pulls out of argv."""
    source = pathlib.Path(cli.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None)
        if name not in _PARSERS:
            continue
        for arg in node.args:
            if (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                    and arg.value.startswith("--")):
                found.add(arg.value)
    # Options handled by an ``in args`` test rather than by a helper.
    found |= set(re.findall(r'"(--[a-z][a-z0-9-]+)" in args', source))
    # ``--help`` prints the listing, so it is not a line the listing owes.
    return found - {"--help"}


def test_every_option_the_cli_accepts_is_named_in_its_help():
    """``--help`` is the module docstring, and it is the only listing users get."""
    documented = set(re.findall(r"--[a-z][a-z0-9-]+", cli.__doc__ or ""))
    missing = sorted(_accepted_long_options() - documented)
    assert not missing, (
        "live CLI options absent from the --help docstring: " + ", ".join(missing)
    )


def test_the_sweep_that_finds_the_options_found_some():
    """A check that looked at nothing reads exactly like a check that found nothing."""
    accepted = _accepted_long_options()
    assert len(accepted) >= 15, f"only {len(accepted)} option(s) swept: {sorted(accepted)}"
    assert "--redteam-generate" in accepted, "the option that motivated this test"


@pytest.mark.parametrize("marker", sorted(cli._TESTABILITY))
def test_the_docs_coverage_map_agrees_with_check_about_white_box(marker):
    """The map's per-category row carries every modality ``--check`` prints for it."""
    index = (_DOCS / "index.md").read_text(encoding="utf-8")
    number = marker.removeprefix("owasp_llm")
    row = [ln for ln in index.splitlines()
           if ln.startswith(f"| [LLM{number} ")]
    assert len(row) == 1, f"no single coverage-table row for {marker}"
    modality = row[0].split("|")[2].lower()
    for word in cli._TESTABILITY[marker][0].split(" + "):
        assert word in modality, (
            f"{marker}: --check says {cli._TESTABILITY[marker][0]!r}, "
            f"the coverage table row says {modality.strip()!r}"
        )


@pytest.mark.parametrize("marker", sorted(cli._SCANNER_INPUT))
def test_a_white_box_scanner_names_its_input_flag_on_the_map(marker):
    """A scanner a user cannot discover the input for is a scanner they will not run."""
    index = (_DOCS / "index.md").read_text(encoding="utf-8")
    number = marker.removeprefix("owasp_llm")
    row = next(ln for ln in index.splitlines() if ln.startswith(f"| [LLM{number} "))
    _, hint = cli._SCANNER_INPUT[marker]
    option = re.search(r"--[a-z][a-z0-9-]+", hint).group(0)
    assert option in row, f"{marker}: coverage row never names {option}"
