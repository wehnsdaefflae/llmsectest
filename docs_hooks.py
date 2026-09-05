"""Build-time hooks for the documentation site.

`on_pre_build` writes `docs/_release.md`, the snippet every page that documents a flag
includes. It exists because the two halves a reader uses come from different places:
`docs.llmsec.dev` is deployed from `main` on every push, and `pip install llmsectest` gives
the last upload to PyPI. Between a release and the next one the site documents flags the
released tool refuses, which on 2026-09-05 was seven of them for fifteen days and cost a
release to close. Nothing on the page said which of the two a reader was looking at.

Generated rather than typed: the same page carried a hand-written `v0.2.0` badge for two
hours after 0.3.0 was on PyPI, and eight copies of it across the website went stale at once.
"""
from __future__ import annotations

import pathlib
import re

BANNER = """!!! info "These pages describe {version}"

    The site is built from `main`, so it can describe a version newer than the one
    `pip install llmsectest` gives you. Run `llmsectest --version` to see what you have.
    [The changelog](https://docs.llmsec.dev/changelog/) says what arrived when.
"""


def version() -> str:
    """The version this tree builds, read from the one file the packaging uses."""
    root = pathlib.Path(__file__).resolve().parent
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    return re.search(r'^version = "([^"]+)"', text, re.M).group(1)


def on_pre_build(config, **kwargs) -> None:  # noqa: ARG001  (mkdocs passes its config)
    target = pathlib.Path(__file__).resolve().parent / "docs" / "_release.md"
    target.write_text(BANNER.format(version=f"v{version()}"), encoding="utf-8")
