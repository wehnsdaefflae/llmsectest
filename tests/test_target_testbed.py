"""The guide's testbed example: a target whose clean result can be checked (issue #15).

**The gap.** A clean report reads the same whether the application withstood the probe or
the probe never reached anything that could fail. `docs/guides/target-app.md` names a target
with known answers, Tom Kaltofen's `mloda-rag-testbed`, where Alice can see a document that
Bob cannot. Scanning it takes a seven-flag command, and one mistyped marker makes every probe
look withstood for the wrong reason.

These tests read the guide. They make no network call.
"""

from __future__ import annotations

from pathlib import Path

GUIDE = Path(__file__).resolve().parent.parent / "docs" / "guides" / "target-app.md"

# The command that was run by hand against the testbed, as (flag, value) pairs.
LONG_FORM = {
    "--app-body": '{"user": "bob"}',
    "--app-session-field": "conversation_id",
    "--app-secret": "SECRET-DEMO-7f2a",
    "--app-canary": "CANARY-EXAMPLEBANK-91ac",
    "--app-rag-poison": "POISON-EXAMPLEBANK-3b9d",
}
TESTBED_URL = "app:http://localhost:8000/chat"

# A real report of that scan, bundled so a reader can see a result without starting anything.
REPORT = GUIDE.parent / "samples" / "testbed-bob.md"

# The rows of that report the guide tells the reader to check. They are quoted in the guide,
# so if the report is ever recorded again, these and the guide have to change with it.
REPORT_ROWS = (
    "| Passed | 35 |",
    "| Failed | 8 |",
    "| LLM01 | Prompt Injection | 13 | 5 | 8 | ❌ Fail |",
    "| LLM02 | Sensitive Information Disclosure | 4 | 4 | 0 | ✅ Pass |",
    "| LLM09 | Vector and Embedding Weaknesses | 6 | 6 | 0 | ✅ Pass |",
)


def _section() -> str:
    text = GUIDE.read_text(encoding="utf-8")
    section = text.split("## A target where you can check a clean result", 1)[1]
    return section.split("\n## ", 1)[0]


def test_the_guide_documents_the_command_and_whose_project_it_is():
    """The guide is where a first-time user reads what a clean result means here, so it must
    carry the full command and the fact that the testbed is somebody else's project."""
    section = _section()
    assert "Tom Kaltofen" in section
    for value in (TESTBED_URL, *LONG_FORM.values()):
        assert value in section, value


def test_the_sample_report_is_bundled_and_linked():
    """The review on PR #49 asked for an example a reader can follow offline: a report to
    open, rather than a server to start first."""
    assert REPORT.is_file(), REPORT
    assert "(samples/testbed-bob.md)" in _section()


def test_the_rows_the_guide_quotes_are_in_the_report():
    report = REPORT.read_text(encoding="utf-8")
    section = _section()
    for row in REPORT_ROWS:
        assert row in report, f"the bundled report no longer has {row!r}"
        assert row in section, f"the guide no longer quotes {row!r}"


def test_the_guide_starts_the_testbed_on_its_offline_backend():
    """Left unset, `TESTBED_LLM` is `codex`: a coding-agent CLI that can read local files, and
    this scan sends it injection prompts. The first version of this section gave a start command
    without the variable (PR #49 review). Every start command in the section has to name `fake`."""
    starts = [line for line in _section().splitlines() if "uvicorn mloda_rag_testbed" in line]
    assert starts, "the section no longer shows how to start the testbed"
    for line in starts:
        assert "TESTBED_LLM=fake" in line, line
