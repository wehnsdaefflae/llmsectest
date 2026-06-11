"""Unit tests for the OSV.dev known-CVE layer (LLM03, opt-in networked).

The OSV HTTP call is monkeypatched throughout — no test touches the network.
What's under test: which deps are queryable (exact pins only), batching,
deduplication, finding aggregation, and that a failed lookup is *surfaced*
(``error`` set) instead of read as "no known CVEs".
"""

from __future__ import annotations

import pytest

from llmsectest.probes import osv
from llmsectest.probes.osv import (
    OsvScanResult,
    pinned_version,
    scan_known_vulnerabilities,
)
from llmsectest.probes.supplychain import Dependency, collect_dependencies


def _dep(spec: str, name: str = "pkg") -> Dependency:
    return Dependency(name=name, raw=f"{name}{spec}", specifier=spec,
                      manifest="requirements.txt")


def _write(repo, name, body):
    p = repo / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


# --- which deps are statically queryable ----------------------------------------


def test_pinned_version_exact_pins():
    assert pinned_version(_dep("==2.19.1")) == "2.19.1"
    assert pinned_version(_dep("===1.0")) == "1.0"
    assert pinned_version(_dep("==1!2.0.post1")) == "1!2.0.post1"


def test_pinned_version_rejects_ranges_and_wildcards():
    assert pinned_version(_dep("")) is None            # unpinned
    assert pinned_version(_dep(">=1.0")) is None       # range
    assert pinned_version(_dep(">=1,<2")) is None      # bounded range
    assert pinned_version(_dep("~=1.4")) is None       # compatible release
    assert pinned_version(_dep("==1.2.*")) is None     # wildcard pin


# --- shared parse pass -----------------------------------------------------------


def test_collect_dependencies_across_manifest_types(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.19.1\nflask>=2\n")
    _write(tmp_path, "pyproject.toml",
           '[project]\nname = "x"\nversion = "0"\ndependencies = ["urllib3==1.22"]\n')
    deps = collect_dependencies(tmp_path)
    assert {(d.name, d.specifier) for d in deps} == {
        ("requests", "==2.19.1"), ("flask", ">=2"), ("urllib3", "==1.22"),
    }


# --- OSV scan (HTTP monkeypatched) ----------------------------------------------


def test_scan_aggregates_advisories_per_package(tmp_path, monkeypatch):
    _write(tmp_path, "requirements.txt", "requests==2.19.1\nsafe-pkg==9.9.9\nflask>=2\n")

    def fake_post(url, payload):
        # queries are sorted by (name, version): requests, safe-pkg
        assert [q["package"]["name"] for q in payload["queries"]] == ["requests", "safe-pkg"]
        assert all(q["package"]["ecosystem"] == "PyPI" for q in payload["queries"])
        return {"results": [
            {"vulns": [{"id": "GHSA-x84v-xcm2-53pg"}, {"id": "PYSEC-2018-28"}]},
            {},
        ]}

    monkeypatch.setattr(osv, "_post_json", fake_post)
    result = scan_known_vulnerabilities(tmp_path)

    assert result.error == ""
    assert result.queried == 2          # the two exact pins
    assert result.unqueried == 1        # flask>=2 is not statically determined
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.id == "LLM03-osv-requests"
    assert finding.package == "requests==2.19.1"
    assert finding.severity == "high"
    assert "GHSA-x84v-xcm2-53pg" in finding.evidence
    assert "osv.dev/vulnerability/GHSA-x84v-xcm2-53pg" in finding.recommendation


def test_scan_dedupes_same_pin_across_manifests(tmp_path, monkeypatch):
    _write(tmp_path, "requirements.txt", "requests==2.19.1\n")
    _write(tmp_path, "sub/requirements.txt", "requests==2.19.1\n")
    calls = []

    def fake_post(url, payload):
        calls.append(payload)
        return {"results": [{} for _ in payload["queries"]]}

    monkeypatch.setattr(osv, "_post_json", fake_post)
    result = scan_known_vulnerabilities(tmp_path)
    assert result.queried == 1
    assert len(calls) == 1 and len(calls[0]["queries"]) == 1


def test_scan_batches_large_query_sets(tmp_path, monkeypatch):
    lines = [f"pkg{i:04d}==1.0.0" for i in range(osv._BATCH_SIZE + 10)]
    _write(tmp_path, "requirements.txt", "\n".join(lines) + "\n")
    calls = []

    def fake_post(url, payload):
        calls.append(len(payload["queries"]))
        return {"results": [{} for _ in payload["queries"]]}

    monkeypatch.setattr(osv, "_post_json", fake_post)
    result = scan_known_vulnerabilities(tmp_path)
    assert result.queried == osv._BATCH_SIZE + 10
    assert calls == [osv._BATCH_SIZE, 10]


def test_scan_surfaces_network_failure_as_error(tmp_path, monkeypatch):
    _write(tmp_path, "requirements.txt", "requests==2.19.1\n")

    def fake_post(url, payload):
        raise OSError("network unreachable")

    monkeypatch.setattr(osv, "_post_json", fake_post)
    result = scan_known_vulnerabilities(tmp_path)
    assert result.findings == []
    assert "network unreachable" in result.error


def test_scan_with_no_exact_pins_queries_nothing(tmp_path, monkeypatch):
    _write(tmp_path, "requirements.txt", "flask>=2\npyyaml\n")

    def fake_post(url, payload):  # pragma: no cover - must not be reached
        raise AssertionError("no query should be sent without exact pins")

    monkeypatch.setattr(osv, "_post_json", fake_post)
    result = scan_known_vulnerabilities(tmp_path)
    assert result == OsvScanResult(findings=[], queried=0, unqueried=2)


def test_evidence_truncates_long_advisory_lists(tmp_path, monkeypatch):
    _write(tmp_path, "requirements.txt", "requests==2.19.1\n")

    def fake_post(url, payload):
        return {"results": [{"vulns": [{"id": f"PYSEC-2020-{i}"} for i in range(9)]}]}

    monkeypatch.setattr(osv, "_post_json", fake_post)
    finding = scan_known_vulnerabilities(tmp_path).findings[0]
    assert "9 published advisories" in finding.evidence
    assert finding.evidence.count("PYSEC-") == 6 and "…" in finding.evidence


# --- suite integration: every non-run state is a visible skip --------------------


def _osv_param_marks(tmp_path, monkeypatch, env_osv: str | None):
    from llmsectest.suite import test_llm03_supply_chain as suite_mod

    monkeypatch.setenv("LLMSECTEST_REPO", str(tmp_path))
    if env_osv is None:
        monkeypatch.delenv("LLMSECTEST_OSV", raising=False)
    else:
        monkeypatch.setenv("LLMSECTEST_OSV", env_osv)
    return suite_mod._osv_params(str(tmp_path))


def test_suite_skips_when_osv_not_requested(tmp_path, monkeypatch):
    _write(tmp_path, "requirements.txt", "requests==2.19.1\n")
    params = _osv_param_marks(tmp_path, monkeypatch, env_osv=None)
    assert len(params) == 1
    reason = params[0].marks[0].kwargs["reason"]
    assert "not requested" in reason and "--osv" in reason


def test_suite_skips_when_lookup_fails(tmp_path, monkeypatch):
    _write(tmp_path, "requirements.txt", "requests==2.19.1\n")
    monkeypatch.setattr(osv, "_post_json",
                        lambda url, payload: (_ for _ in ()).throw(OSError("boom")))
    params = _osv_param_marks(tmp_path, monkeypatch, env_osv="1")
    assert len(params) == 1
    assert "lookup failed" in params[0].marks[0].kwargs["reason"]


def test_suite_passes_visibly_when_no_cves(tmp_path, monkeypatch):
    _write(tmp_path, "requirements.txt", "requests==2.99.0\n")
    monkeypatch.setattr(osv, "_post_json", lambda url, payload: {"results": [{}]})
    params = _osv_param_marks(tmp_path, monkeypatch, env_osv="1")
    assert len(params) == 1
    assert params[0].id == "no-known-cves-1-pinned-queried"
    assert not params[0].marks


@pytest.mark.parametrize("body,expected_reason_part", [
    ("flask>=2\n", "no exactly-pinned"),
])
def test_suite_skips_when_nothing_queryable(tmp_path, monkeypatch, body, expected_reason_part):
    _write(tmp_path, "requirements.txt", body)
    monkeypatch.setattr(osv, "_post_json",
                        lambda url, payload: {"results": []})
    params = _osv_param_marks(tmp_path, monkeypatch, env_osv="1")
    assert len(params) == 1
    assert expected_reason_part in params[0].marks[0].kwargs["reason"]
