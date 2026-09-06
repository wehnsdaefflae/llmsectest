"""A white-box category that RAN must not read like one that never ran.

`attacks_withstood` counts probes delivered to a target. LLM03 and LLM04 read the
project's own dependency manifests and model files instead, so they can never appear in
that tally — and until 2026-09-06 nothing else in the SARIF said they had run either. A
consumer of the file therefore saw a category with findings and no tally row at all,
which is indistinguishable from a category no probe ever touched.

Measured on a real scan: it carried dozens of supply-chain
findings against a pinned checkout of the application's own upstream, and the report from
that same file rendered LLM03 as *not tested*. The console footer said it too, in the
line a reader trusts most: *"not exercised LLM03: pass --repo <path>"*, printed by a run
that had been given `--repo`.

Both surfaces are pinned here, because they failed independently and a fix to one would
have left the other saying the opposite.
"""

from __future__ import annotations

import json

import pytest

from llmsectest import envvars
from llmsectest.reporting.models import TestResult
from llmsectest.reporting.sarif_generator import SARIFGenerator

TOOL, VERSION = "llmsectest", "0.0.0-test"


def _scanner_finding(name: str, marker: str) -> TestResult:
    """A white-box scanner result: an OWASP marker, and no ``llmsec_probe``."""
    return TestResult(
        nodeid=f"suite/test_llm03_supply_chain.py::{name}",
        location=("suite/test_llm03_supply_chain.py", 12, name),
        outcome="failed",
        markers=[marker, "security", "high"],
        properties={},
    )


def _sarif(results):
    return json.loads(SARIFGenerator(TOOL, VERSION, source_root=".").generate(results))


def test_a_run_pointed_at_a_repo_records_that_it_was(monkeypatch, tmp_path):
    monkeypatch.setenv(envvars.REPO, str(tmp_path))
    props = _sarif([_scanner_finding("unpinned_dep", "owasp_llm03")])["runs"][0]["properties"]
    assert props["white_box_scanners"]["LLM03"] == {"input": "--repo", "path": str(tmp_path)}


def test_the_record_names_every_white_box_input_that_was_given(monkeypatch, tmp_path):
    monkeypatch.setenv(envvars.REPO, str(tmp_path))
    monkeypatch.setenv(envvars.MODEL_SCAN, str(tmp_path / "models"))
    monkeypatch.setenv(envvars.VECTOR_STORE, str(tmp_path / "store"))
    props = _sarif([_scanner_finding("unpinned_dep", "owasp_llm03")])["runs"][0]["properties"]
    assert sorted(props["white_box_scanners"]) == ["LLM03", "LLM04", "LLM08"]


def test_a_run_given_no_white_box_input_records_none(monkeypatch):
    """The other direction, and it is the one that keeps the record honest: an empty block
    would let a scan that pointed LLM03 at nothing look like one that pointed it at a repo
    and found it clean."""
    for name in (envvars.REPO, envvars.MODEL_SCAN, envvars.VECTOR_STORE):
        monkeypatch.delenv(name, raising=False)
    props = _sarif([_scanner_finding("unpinned_dep", "owasp_llm03")])["runs"][0]["properties"]
    assert "white_box_scanners" not in props


@pytest.mark.parametrize("variable, flag, category", [
    (envvars.REPO, "--repo", "LLM03"),
    (envvars.MODEL_SCAN, "--model-scan", "LLM04"),
])
def test_the_app_scan_footer_stops_asking_for_a_flag_it_was_given(
        monkeypatch, capsys, tmp_path, variable, flag, category):
    """The footer is the coverage map a reader trusts to say what went untested, so a
    footer that contradicts the scan printed above it is worse than no footer."""
    from llmsectest.__main__ import _print_coverage_footer

    # `run_suite` writes the scanner variables straight into `os.environ` and never
    # restores them, so a test that ran earlier in this process can leave one set. Cleared
    # explicitly, because the point of this test is which ONE input was supplied.
    for other in (envvars.REPO, envvars.MODEL_SCAN, envvars.VECTOR_STORE):
        monkeypatch.delenv(other, raising=False)
    monkeypatch.setenv(variable, str(tmp_path))
    monkeypatch.setenv(envvars.APP_PROMPT, "You are a bot. The token is SECRET-1.")
    monkeypatch.setenv(envvars.APP_SECRET, "SECRET-1")
    _print_coverage_footer("app:http://127.0.0.1:1/chat")
    out = capsys.readouterr().out
    exercised = out.split("exercised:")[1].split("\n")[0]
    assert category in exercised, out
    assert f"not exercised {category}" not in out, out
    assert flag not in out, out
