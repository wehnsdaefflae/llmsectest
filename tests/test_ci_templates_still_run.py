"""The published CI/CD templates name only flags the CLI still has.

WHY THIS FILE EXISTS. `docs/guides/ci.md` is a promise rather than prose: AP6 of the
grant ships GitHub Actions, GitLab CI and Jenkins templates, and an adopter copies the
block verbatim into their pipeline. Nothing tested those blocks, so a renamed or
removed flag would break every copied pipeline in the world while our own suite stayed
green -- the same defect class found on 2026-11-03 in `contract/playbooks/`, where three
pages told a reader to run `gu gmail`, a tool that does not exist.

WHAT IT ASSERTS, and why in this direction. The flags are read out of the templates and
held against the CLI's own `--help`, which is the primary source: a flag that stopped
existing disappears from help, so the test goes red at the rename rather than at the
first adopter's pipeline. It deliberately does NOT restate the flag list -- a hardcoded
list is a second copy that goes stale the same way the templates would.

It also pins that all three platforms keep a block. The grant promises three, and a
platform silently losing its template is a deliverable quietly shrinking.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI_GUIDE = ROOT / "docs" / "guides" / "ci.md"

# The three platforms AP6 promises. Each must keep a heading in the guide.
PROMISED_PLATFORMS = ("GitHub Actions", "GitLab CI", "Jenkins")


def _cli_help() -> str:
    proc = subprocess.run(
        [sys.executable, "-m", "llmsectest", "--help"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc.stdout + proc.stderr


def _invocation_flags(text: str) -> set:
    """Every ``--flag`` the guide tells a reader to pass to ``llmsectest``.

    An invocation is the line carrying the command plus every line a trailing
    backslash continues it onto, which is how all three templates are written.
    """
    lines = text.splitlines()
    flags = set()
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.search(r"(^|[/\s'\"])llmsectest\s+--", line):
            block = [line]
            while block[-1].rstrip().endswith("\\") and i + 1 < len(lines):
                i += 1
                block.append(lines[i])
            for part in block:
                for flag in re.findall(r"(--[a-z][a-z0-9-]+)", part):
                    flags.add(flag)
        i += 1
    return flags


def test_every_platform_the_grant_promises_still_has_a_template():
    text = CI_GUIDE.read_text(encoding="utf-8")
    missing = [p for p in PROMISED_PLATFORMS if f"## {p}" not in text]
    assert not missing, f"the CI guide no longer documents: {missing}"


def test_the_templates_name_flags_the_cli_still_accepts():
    text = CI_GUIDE.read_text(encoding="utf-8")
    flags = _invocation_flags(text)
    # The extractor itself is load-bearing: a regex that silently matches nothing
    # would make this test vacuously green, which is the failure mode the gate's
    # own rules call out.
    assert len(flags) >= 4, f"no llmsectest invocation found in {CI_GUIDE}: {flags}"
    help_text = _cli_help()
    unknown = sorted(f for f in flags if f not in help_text)
    assert not unknown, (
        f"{CI_GUIDE.name} tells adopters to pass {unknown}, which the CLI's own "
        f"--help no longer lists -- every copied pipeline would fail"
    )


def test_the_extractor_reads_a_continued_invocation_whole():
    """Two-sided: the parser must find flags on continuation lines, not just the first."""
    sample = (
        "    - |\n"
        "      llmsectest --target app:http://x/chat \\\n"
        "        --report-dir results \\\n"
        "        --app-timeout 60\n"
    )
    assert _invocation_flags(sample) == {"--target", "--report-dir", "--app-timeout"}


def test_the_extractor_ignores_prose_that_merely_mentions_a_flag():
    """A sentence about a flag is not an invocation, so it is not held against help."""
    sample = "Pass `--min-coverage` if you want a coverage gate.\n"
    assert _invocation_flags(sample) == set()
