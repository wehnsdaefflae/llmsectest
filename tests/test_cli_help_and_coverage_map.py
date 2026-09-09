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

# The CLI parses argv by hand: every option reaches one of these helpers as a string
# literal, so the source is the register of what the CLI accepts.
#
# `_extract_multi_opt` was missing until 2026-09-05, which is this file's own lesson turned
# on itself: it asserts a floor on how many options it found precisely because a narrow
# sweep reads like a clean one, and it then swept 30 of at least 33. The flag it could not
# see was `--app-action`, one of the five the day's work was about.
_PARSERS = {"_extract_opt", "_extract_multi_opt", "_extract_flag", "_extract_opt_flag"}

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
    # …and by an equals-or-space test, which is how ``--sarif-output`` is recognised.
    found |= set(re.findall(r'a == "(--[a-z][a-z0-9-]+)" or a\.startswith', source))
    # The pytest plugin's own options reach a user through the same `llmsectest` command,
    # so a listing that omits one is as wrong as if `__main__` had parsed it itself.
    found |= _plugin_options()
    # ``--help`` prints the listing, so it is not a line the listing owes.
    return found - {"--help"}


def _plugin_options() -> set[str]:
    """Every ``--long-option`` the pytest plugin registers with ``addoption``."""
    source = (pathlib.Path(cli.__file__).parent / "plugin.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    return {arg.value
            for node in ast.walk(tree) if isinstance(node, ast.Call)
            and getattr(node.func, "attr", None) == "addoption"
            for arg in node.args
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            and arg.value.startswith("--")}


def test_every_option_the_cli_accepts_is_named_in_its_help():
    """``--help`` is the module docstring, and it is the only listing users get."""
    documented = set(re.findall(r"--[a-z][a-z0-9-]+", cli.__doc__ or ""))
    missing = sorted(_accepted_long_options() - documented)
    assert not missing, (
        "live CLI options absent from the --help docstring: " + ", ".join(missing)
    )


def test_every_option_the_help_names_is_one_the_cli_accepts():
    """The other direction, which is what a reader actually hits. A listing promising a flag
    that errors is the wall this project measured in the wild on 2026-09-05: `llmsectest`
    0.2.0 answered `unrecognized arguments` to six flags its own documentation used."""
    documented = set(re.findall(r"--[a-z][a-z0-9-]+", cli.__doc__ or "")) - {"--help"}
    unknown = sorted(documented - _accepted_long_options())
    assert not unknown, (
        "--help names options the CLI does not accept: " + ", ".join(unknown)
    )


def test_the_sweep_that_finds_the_options_found_some():
    """A check that looked at nothing reads exactly like a check that found nothing."""
    accepted = _accepted_long_options()
    assert len(accepted) >= 40, f"only {len(accepted)} option(s) swept: {sorted(accepted)}"
    assert "--redteam-generate" in accepted, "the option that motivated this test"
    # One per parsing route, so a route dropping out of `_accepted_long_options` fails here
    # rather than quietly shrinking the denominator of the two tests above.
    for opt in ("--app-action", "--sarif-output", "--check"):
        assert opt in accepted, f"{opt} is live and the sweep no longer sees it"

def test_help_has_a_worked_example_for_custom_app_request_shapes():
    """The four flags are most useful together for a non-OpenAI-compatible endpoint."""
    examples = (cli.__doc__ or "").split("Application scans", maxsplit=1)[0]
    assert (
        "python -m llmsectest --target app:http://localhost:7860/api/v1/run/<flow-id>"
        in examples
    )
    for option in (
        "--app-request-field",
        "--app-response-path",
        "--app-headers",
        "--app-body",
    ):
        assert option in examples


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


# The third surface that describes the CLI, added 2026-09-09 with
# `docs/guides/adapter-prompt.md`. That page hands a user a prompt whose whole
# premise is that the flags it names are real, so a renamed flag turns the page
# into instructions for producing a command that does not run. The two tests above
# read `--help` and the coverage map; nothing read the guides.
_GUIDES = pathlib.Path(__file__).resolve().parents[1] / "docs" / "guides"

#: Options a guide may name without the CLI accepting them, each with its reason.
#: An exception is written down here rather than argued for at the assertion.
_NOT_THE_CLI: dict[str, str] = {
    "--cov": "pytest's, in the Development guide's own test command",
}


def _options_named_in(page: pathlib.Path) -> set[str]:
    """Every ``--long-option`` a guide names, code blocks included.

    Code blocks are the point: the flags live in the command a reader copies.
    """
    text = page.read_text(encoding="utf-8")
    # Two shapes in these pages look like options and are not. Prose writes the family
    # as `--app-*`, so a match may not be followed by a hyphen, a star or another word
    # character: trimming the trailing hyphen instead would produce a `--app` this test
    # then reports as an invented flag. And three of the guides open with the mkdocs
    # snippet line `--8<-- "_release.md"`, so an option has to start with a letter.
    return {m for m in re.findall(r"--[a-z][a-z0-9-]*[a-z0-9](?![\w*-])", text)
            if m not in _NOT_THE_CLI}


@pytest.mark.parametrize("page", sorted(_GUIDES.glob("*.md")), ids=lambda p: p.name)
def test_every_option_a_guide_names_is_one_the_cli_accepts(page):
    """A guide naming a flag the CLI dropped is a copy-paste command that fails."""
    accepted = _accepted_long_options()
    named = _options_named_in(page)
    unknown = sorted(o for o in named if o not in accepted)
    assert not unknown, (
        f"{page.name} names option(s) the CLI does not accept: {', '.join(unknown)}. "
        f"Either the flag was renamed and the guide is stale, or the guide invented it."
    )


def test_the_guide_sweep_reads_the_page_that_motivated_it():
    """A check that looked at nothing reads exactly like a check that found nothing.

    `adapter-prompt.md` is the reason this exists, and most of its flags sit inside a
    fenced block, so the denominator is asserted on that page specifically.
    """
    page = _GUIDES / "adapter-prompt.md"
    assert page.exists(), "the guide this test was written for is gone"
    named = _options_named_in(page)
    assert len(named) >= 10, f"only {len(named)} option(s) read off the page: {sorted(named)}"
    for option in ("--app-request-field", "--app-response-path", "--app-session-init",
                   "--app-rag-poison"):
        assert option in named, f"{option} is on the page and the sweep no longer sees it"
