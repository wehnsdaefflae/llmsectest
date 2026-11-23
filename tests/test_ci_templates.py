"""The shipped CI templates must parse, and must not drift from the guide.

`docs/guides/ci.md` documents three pipelines and `examples/ci/` ships them as files
a user copies. Two copies of one pipeline drift, and the drift is invisible: a stale
template still parses and still runs, it just stops matching what we tell people.
So the invariant under test is the one that matters, that the command the template
runs is the command the guide documents.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml  # declared in the dev extra; a plain import so CI cannot skip these

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "examples" / "ci"
GUIDE = ROOT / "docs" / "guides" / "ci.md"


def test_all_three_templates_ship():
    names = {p.name for p in TEMPLATES.iterdir() if p.is_file()}
    assert names == {"github-actions.yml", "gitlab-ci.yml", "Jenkinsfile"}


@pytest.mark.parametrize("name", ["github-actions.yml", "gitlab-ci.yml"])
def test_the_yaml_templates_parse(name):
    loaded = yaml.safe_load((TEMPLATES / name).read_text())
    assert isinstance(loaded, dict)


def test_the_github_template_keeps_the_scan_and_the_verdict_on_one_run():
    """`continue-on-error` plus `steps.scan.outcome` is the whole point of the shape."""
    loaded = yaml.safe_load((TEMPLATES / "github-actions.yml").read_text())
    steps = loaded["jobs"]["llmsectest"]["steps"]
    scan = next(s for s in steps if s.get("id") == "scan")
    assert scan["continue-on-error"] is True
    assert any("steps.scan.outcome" in str(s.get("if", "")) for s in steps)
    assert loaded["jobs"]["llmsectest"]["permissions"]["security-events"] == "write"


def test_the_gitlab_template_uploads_artifacts_from_a_failed_job():
    loaded = yaml.safe_load((TEMPLATES / "gitlab-ci.yml").read_text())
    artifacts = loaded["llmsectest"]["artifacts"]
    assert artifacts["when"] == "always"
    assert artifacts["reports"]["sarif"] == "results/llmsectest.sarif"


def test_the_jenkins_template_archives_the_report_whatever_the_stage_did():
    text = (TEMPLATES / "Jenkinsfile").read_text()
    assert "post {" in text and "always {" in text
    assert "recordIssues" in text
    assert "catchError(buildResult: 'UNSTABLE'" in text


@pytest.mark.parametrize("name", ["github-actions.yml", "gitlab-ci.yml", "Jenkinsfile"])
def test_each_template_runs_the_command_the_guide_documents(name):
    """A template whose scan command left the guide behind is the drift we fear."""
    guide = GUIDE.read_text()
    text = (TEMPLATES / name).read_text()
    for line in ("--target app:http://localhost:8000/chat",
                 "--sarif-output results/llmsectest.sarif",
                 "--app-timeout 60"):
        assert line in text, f"{name} dropped {line!r}"
        assert line in guide, f"the guide no longer documents {line!r}"


@pytest.mark.parametrize("name", ["github-actions.yml", "gitlab-ci.yml", "Jenkinsfile"])
def test_each_template_says_which_two_things_to_edit(name):
    text = (TEMPLATES / name).read_text()
    assert "EDIT" in text
    assert "docs.llmsec.dev/guides/ci" in text
