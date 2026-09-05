"""``README.md`` is also the package page on PyPI, and a link that only works here is broken there.

Found on 2026-09-05 by the adoption phase, read off the rendered page in a real browser
rather than out of this file: seven links in the description on
``https://pypi.org/project/llmsectest/`` pointed at ``LICENSE``, ``CONTRIBUTING.md``,
``SECURITY.md``, ``CHANGELOG.md`` and ``examples/``. PyPI renders the long description with
``readme_renderer``, which sanitises the HTML and leaves every ``href`` exactly as written,
so each of those resolved against the project URL. All five answered 404. The package had
been up for fifteen days with 151 downloads in the trailing month, and the three files a
security tool most owes a visitor (how to contribute, how to report a vulnerability, what
changed) were the ones that did not open.

``pyproject.toml`` names this file as ``readme``, so its bytes are shipped as the long
description of every wheel and are what PyPI renders. Two properties follow, one for each
side of the fix:

* No relative link may survive here, because the same bytes are read at two roots.
* Every absolute link into this repository must name a path that exists, because
  rewriting a relative link into a ``blob/main`` URL trades a PyPI 404 for a repository
  404 unless something watches the path.

Both assert a floor on what they inspected. A sweep that silently matched nothing reads
exactly like a sweep that found nothing wrong, which is the defect
``test_cli_help_and_coverage_map.py`` was written about.
"""

from __future__ import annotations

import pathlib
import re
import tomllib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"

#: ``[text](target)``, with the target taken up to the first closing parenthesis. The label
#: admits one level of nesting because the badge row is written ``[![alt](img)](target)``,
#: and a label pattern of ``[^\]]*`` stops at the inner bracket: the first version of this
#: test reported five of the six broken links and read as a full sweep, missing the
#: ``LICENSE`` badge that sits in the README's fifth line. An autolink or a
#: reference-style link would need its own pattern, which is what the floor below reveals.
_LINK = re.compile(r"\[(?:[^\[\]]|\[[^\]]*\])*\]\(([^)\s]+)\)")

#: What the README carried when this test was written. A floor rather than an equality:
#: the file grows, and a test that has to be edited whenever a sentence is added stops
#: being read.
_MIN_LINKS = 20

_REPO_URL = "https://github.com/wehnsdaefflae/llmsectest"
_INTO_REPO = re.compile(re.escape(_REPO_URL) + r"/(?:blob|tree)/main/([^)#\s]+)")


def _readme() -> pathlib.Path:
    """The file ``pyproject.toml`` ships as the long description.

    Read from the metadata rather than hardcoded, so renaming the readme moves this test
    with it instead of leaving it checking a file nobody publishes.
    """
    declared = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["readme"]
    path = _ROOT / declared
    assert path.exists(), f"pyproject declares readme = {declared!r}, which does not exist"
    return path


def _targets() -> list[str]:
    found = _LINK.findall(_readme().read_text(encoding="utf-8"))
    assert len(found) >= _MIN_LINKS, (
        f"only {len(found)} links matched in the README, under the {_MIN_LINKS} it carried "
        "when this test was written: the pattern has stopped seeing the file, so a clean "
        "result here would mean nothing"
    )
    return found


def test_no_relative_links_in_the_packaged_readme() -> None:
    """A relative target resolves against the project URL on PyPI, where nothing is."""
    relative = sorted({
        t for t in _targets()
        if not t.startswith(("http://", "https://", "#", "mailto:"))
    })
    assert not relative, (
        "these README links resolve against https://pypi.org/project/llmsectest/ on the "
        f"package page and 404 there: {relative}. Write them against {_REPO_URL}/blob/main/ "
        "so the one file serves both readers"
    )


def test_links_into_this_repository_name_a_real_path() -> None:
    """The other half of the trade: an absolute path may not rot silently."""
    paths = sorted(set(_INTO_REPO.findall(_readme().read_text(encoding="utf-8"))))
    if not paths:
        pytest.skip("the README carries no blob/main or tree/main link to check")
    missing = [p for p in paths if not (_ROOT / p).exists()]
    assert not missing, (
        f"the README links to {missing} at {_REPO_URL}, and no such path is in this "
        "repository, so the link 404s for every reader on both surfaces"
    )
