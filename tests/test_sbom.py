"""Unit tests for the CycloneDX SBOM export (LLM03 layer).

What's under test: the CycloneDX 1.6 document shape, that the pinned/unpinned
grading is carried into each component (version + PURL only for exact pins),
cross-manifest deduplication, bom-ref uniqueness, deterministic output with the
volatile fields injected, and the end-to-end parse -> build path.
"""

from __future__ import annotations

import json

from llmsectest.probes.supplychain import Dependency, collect_dependencies
from llmsectest.reporting import build_cyclonedx, render_sbom_json, write_sbom
from llmsectest.reporting.sbom import SPEC_VERSION

# volatile fields pinned so assertions are stable
_TS = "2026-07-08T09:00:00Z"
_SN = "urn:uuid:00000000-0000-0000-0000-000000000000"


def _dep(spec: str, name: str = "pkg", manifest: str = "requirements.txt",
         url: str = "") -> Dependency:
    return Dependency(name=name, raw=f"{name}{spec}", specifier=spec,
                      manifest=manifest, url=url)


def _by_name(bom: dict) -> dict[str, dict]:
    return {c["name"]: c for c in bom["components"]}


def _props(component: dict) -> dict[str, list[str]]:
    props: dict[str, list[str]] = {}
    for p in component.get("properties", []):
        props.setdefault(p["name"], []).append(p["value"])
    return props


# --- document envelope ----------------------------------------------------------

def test_document_envelope():
    bom = build_cyclonedx([_dep("==1.0")], subject="acme",
                          tool_version="9.9.9", timestamp=_TS, serial_number=_SN)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == SPEC_VERSION
    assert bom["version"] == 1  # the BOM revision, NOT the spec version
    assert bom["serialNumber"] == _SN
    assert bom["metadata"]["timestamp"] == _TS
    tools = bom["metadata"]["tools"]["components"]
    assert tools == [{"type": "application", "name": "llmsectest", "version": "9.9.9"}]
    assert bom["metadata"]["component"] == {
        "type": "application", "name": "acme", "bom-ref": "root:acme",
    }


def test_tool_version_omitted_when_unknown(monkeypatch):
    # simulate running from source (no installed dist): _tool_version() -> None
    monkeypatch.setattr("llmsectest.reporting.sbom._tool_version", lambda: None)
    bom = build_cyclonedx([_dep("==1.0")], timestamp=_TS, serial_number=_SN)
    assert bom["metadata"]["tools"]["components"] == [
        {"type": "application", "name": "llmsectest"}
    ]
    # no subject -> no root component
    assert "component" not in bom["metadata"]


# --- pinned vs unpinned carried into the component ------------------------------

def test_pinned_dependency_gets_version_and_purl():
    bom = build_cyclonedx([_dep("==2.31.0", name="requests")],
                          timestamp=_TS, serial_number=_SN)
    comp = _by_name(bom)["requests"]
    assert comp["type"] == "library"
    assert comp["version"] == "2.31.0"
    assert comp["purl"] == "pkg:pypi/requests@2.31.0"
    assert comp["bom-ref"] == "pkg:pypi/requests@2.31.0"
    assert _props(comp)["llmsectest:pinned"] == ["true"]
    assert "llmsectest:constraint" not in _props(comp)


def test_unpinned_dependency_omits_version_records_constraint():
    bom = build_cyclonedx([_dep(">=1.0", name="flask")],
                          timestamp=_TS, serial_number=_SN)
    comp = _by_name(bom)["flask"]
    assert "version" not in comp  # nothing is statically resolvable
    assert comp["purl"] == "pkg:pypi/flask"  # versionless PURL
    assert _props(comp)["llmsectest:pinned"] == ["false"]
    assert _props(comp)["llmsectest:constraint"] == [">=1.0"]


def test_wildcard_and_range_pins_are_not_versions():
    # mirrors pinned_version's contract: only a concrete exact pin resolves
    bom = build_cyclonedx([_dep("==1.2.*", name="a"), _dep(">=1,<2", name="b")],
                          timestamp=_TS, serial_number=_SN)
    comps = _by_name(bom)
    assert "version" not in comps["a"]
    assert "version" not in comps["b"]


def test_vcs_url_dependency_records_url_property():
    dep = _dep("", name="mypkg", url="git+https://example.com/mypkg.git")
    bom = build_cyclonedx([dep], timestamp=_TS, serial_number=_SN)
    comp = _by_name(bom)["mypkg"]
    assert _props(comp)["llmsectest:vcs-url"] == ["git+https://example.com/mypkg.git"]


# --- dedup + uniqueness ---------------------------------------------------------

def test_same_dep_across_manifests_merges_into_one_component():
    deps = [
        _dep("==1.0", name="shared", manifest="requirements.txt"),
        _dep("==1.0", name="shared", manifest="subdir/requirements.txt"),
    ]
    bom = build_cyclonedx(deps, timestamp=_TS, serial_number=_SN)
    shared = [c for c in bom["components"] if c["name"] == "shared"]
    assert len(shared) == 1
    assert _props(shared[0])["llmsectest:manifest"] == [
        "requirements.txt", "subdir/requirements.txt",  # sorted
    ]


def test_distinct_unpinned_constraints_get_unique_bom_refs():
    # two different unpinned constraints on the same name share a versionless PURL
    deps = [_dep(">=1.0", name="dup"), _dep("<2.0", name="dup")]
    bom = build_cyclonedx(deps, timestamp=_TS, serial_number=_SN)
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))  # unique
    assert "pkg:pypi/dup" in refs
    assert "pkg:pypi/dup#2" in refs


# --- determinism + serialization -----------------------------------------------

def test_output_is_deterministic_with_injected_volatiles():
    deps = [_dep("==3.0", name="zeta"), _dep(">=1", name="alpha")]
    a = render_sbom_json(deps, subject="p", tool_version="1.0",
                         timestamp=_TS, serial_number=_SN)
    b = render_sbom_json(deps, subject="p", tool_version="1.0",
                         timestamp=_TS, serial_number=_SN)
    assert a == b
    assert a.endswith("\n")
    doc = json.loads(a)
    # components sorted by name -> alpha before zeta
    assert [c["name"] for c in doc["components"]] == ["alpha", "zeta"]


def test_serial_and_timestamp_default_to_fresh_values():
    bom = build_cyclonedx([_dep("==1.0")])
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["timestamp"].endswith("Z")


def test_write_sbom_roundtrips(tmp_path):
    out = write_sbom([_dep("==1.0", name="requests")], tmp_path / "out" / "sbom.json",
                     subject="x", timestamp=_TS, serial_number=_SN)
    assert out.is_file()
    doc = json.loads(out.read_text())
    assert doc["bomFormat"] == "CycloneDX"
    assert _by_name(doc)["requests"]["purl"] == "pkg:pypi/requests@1.0"


# --- end-to-end: real manifest parse -> SBOM ------------------------------------

def test_end_to_end_from_collect_dependencies(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=1.0\n# a comment\n", encoding="utf-8")
    deps = collect_dependencies(tmp_path)
    bom = build_cyclonedx(deps, subject=tmp_path.name,
                          timestamp=_TS, serial_number=_SN)
    comps = _by_name(bom)
    assert comps["requests"]["version"] == "2.31.0"
    assert "version" not in comps["flask"]
    assert len(bom["components"]) == 2
