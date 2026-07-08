"""CycloneDX SBOM export from a repo's declared dependencies (LLM03 layer).

A Software Bill of Materials (SBOM) inventories exactly what a project pulls in —
the raw material for supply-chain risk assessment (LLM03). This module turns the
same normalised dependency list the supply-chain scanner already parses
(:func:`llmsectest.probes.supplychain.collect_dependencies`) into a **CycloneDX
1.6 JSON** BOM: one component per declared dependency, with a PURL identifier.

Built dependency-free from the stdlib (``json``/``uuid``/``datetime``).
CycloneDX JSON is a stable, well-specified schema, so a faithful emitter needs no
third-party library — matching the zero-dep-offline core philosophy elsewhere in
this tree (cf. the LLM03 structural scan vs the opt-in OSV layer, and the stdlib
LLM04 pickle scanner vs the optional ``modelscan`` engine). The richer
``cyclonedx-python-lib`` engine (XML/SPDX output, schema validation) is a
documented optional follow-up, never a hard dependency.

The **pinned/unpinned distinction is carried into the SBOM** exactly as the LLM03
scanner grades it, through the shared
:func:`~llmsectest.probes.supplychain.pinned_version`: an exactly-pinned
dependency (``==X.Y.Z``) becomes a component with a concrete ``version`` and a
fully-qualified PURL (``pkg:pypi/name@version``); a range/unpinned dependency has
no statically-resolvable version, so its component omits ``version`` and records
the raw constraint in a property. The SBOM is thus only ever as precise as the
manifests allow — it never asserts a version a manifest did not pin.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from ..probes.supplychain import Dependency, pinned_version

SPEC_VERSION = "1.6"
#: Prefix for every llmsectest-authored component property (namespaced per the
#: CycloneDX convention so a consumer can tell our annotations from a tool's).
PROP_NS = "llmsectest"


def _tool_version() -> str | None:
    """The installed llmsectest version, or ``None`` when running from source."""
    try:
        return version("llmsectest")
    except PackageNotFoundError:
        return None


def _now_iso() -> str:
    """UTC timestamp in the CycloneDX (RFC 3339) form, e.g. ``2026-07-08T09:00:00Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _purl(name: str, pinned: str | None) -> str:
    """The Package-URL for a PyPI dependency (canonical name; version if pinned).

    Names are already PEP 503-canonical (``[a-z0-9-]``), so no PURL percent-
    encoding is required. An unpinned dependency yields a versionless PURL.
    """
    base = f"pkg:pypi/{name}"
    return f"{base}@{pinned}" if pinned else base


def _component(name: str, specifier: str, url: str, deps: list[Dependency],
               taken_refs: set[str]) -> dict:
    """One CycloneDX ``component`` for a group of identical declarations."""
    pinned = pinned_version(deps[0])  # every dep in the group shares the specifier
    purl = _purl(name, pinned)

    # bom-ref must be unique across the BOM; two distinct unpinned constraints on
    # the same name share a versionless PURL, so disambiguate on collision.
    ref = purl
    n = 2
    while ref in taken_refs:
        ref = f"{purl}#{n}"
        n += 1
    taken_refs.add(ref)

    component: dict = {"type": "library", "bom-ref": ref, "name": name}
    if pinned:
        component["version"] = pinned
    component["purl"] = purl

    properties = [
        {"name": f"{PROP_NS}:manifest", "value": manifest}
        for manifest in sorted({d.manifest for d in deps})
    ]
    properties.append(
        {"name": f"{PROP_NS}:pinned", "value": "true" if pinned else "false"}
    )
    if not pinned and specifier:
        properties.append({"name": f"{PROP_NS}:constraint", "value": specifier})
    if url:
        properties.append({"name": f"{PROP_NS}:vcs-url", "value": url})
    component["properties"] = properties
    return component


def build_cyclonedx(dependencies: list[Dependency], *, subject: str | None = None,
                    tool_version: str | None = None, timestamp: str | None = None,
                    serial_number: str | None = None) -> dict:
    """Build a CycloneDX 1.6 BOM document from a parsed dependency list.

    Declarations of the same package with the same constraint are merged into one
    component listing every manifest it appears in. ``subject`` names the scanned
    project (recorded as the BOM's root ``metadata.component``). ``timestamp`` and
    ``serial_number`` are injectable so the volatile fields can be pinned in tests;
    left unset they default to now (UTC) and a fresh ``urn:uuid``.
    """
    if tool_version is None:
        tool_version = _tool_version()

    groups: dict[tuple[str, str, str], list[Dependency]] = {}
    for dep in dependencies:
        groups.setdefault((dep.name, dep.specifier, dep.url), []).append(dep)

    taken_refs: set[str] = set()
    components = [
        _component(name, specifier, url, groups[(name, specifier, url)], taken_refs)
        for (name, specifier, url) in sorted(groups)
    ]

    tool = {"type": "application", "name": "llmsectest"}
    if tool_version:
        tool["version"] = tool_version
    metadata: dict = {
        "timestamp": timestamp or _now_iso(),
        "tools": {"components": [tool]},
    }
    if subject:
        metadata["component"] = {
            "type": "application", "name": subject, "bom-ref": f"root:{subject}",
        }

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,  # the BOM's own revision number, not the CycloneDX spec version
        "metadata": metadata,
        "components": components,
    }


def render_sbom_json(dependencies: list[Dependency], **kwargs) -> str:
    """Render a dependency list as pretty-printed CycloneDX JSON text."""
    return json.dumps(build_cyclonedx(dependencies, **kwargs), indent=2) + "\n"


def write_sbom(dependencies: list[Dependency], out_path: str | Path, **kwargs) -> Path:
    """Write a CycloneDX SBOM for ``dependencies`` to ``out_path``; return the path."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_sbom_json(dependencies, **kwargs), encoding="utf-8")
    return out
