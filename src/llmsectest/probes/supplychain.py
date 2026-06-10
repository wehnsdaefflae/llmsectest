"""OWASP LLM03 — Supply-chain dependency scanning (white-box, offline).

LLM applications inherit the supply chain of every package they install: a
compromised, malicious or typosquatted dependency runs with the app's full
privileges, and an *unpinned* dependency silently pulls whatever the registry
serves next — including a release published by an attacker who took over the
package. This module reads a target project's dependency manifests and flags
those risks **statically and offline** — no network, no package-index queries,
so a scan is deterministic and safe to run in CI.

What it flags, per declared dependency:

* **known-malicious / typosquatted name** (``critical``) — the package name
  matches a curated list of names known to have carried malware on PyPI, or to
  squat a popular package / stdlib module. A hit is high-signal: these are
  documented malicious uploads, not heuristics.
* **direct VCS / URL install** (``high``) — the dependency is pulled from a git
  ref or an arbitrary URL (``git+https://…``, ``pkg @ https://…``) instead of the
  package index, bypassing the index's integrity and yanking guarantees.
* **unpinned dependency** (``high``) — no version constraint at all, so the build
  floats to *any* future version, including a compromised one.
* **no upper bound** (``medium``) — a lower bound only (``>=1.0``) still admits an
  unvetted future major release.
* **insecure / extra package index** (``high`` / ``medium``) — an index served over
  cleartext ``http://`` (MITM), or an extra index that widens the
  dependency-confusion surface.

Exact pins (``==`` / ``===``), compatible-release (``~=``) and fully bounded ranges
(``>=x,<y``) are treated as safe and produce no finding.

Manifests understood: ``requirements*.txt`` (incl. ``-e`` / index directives),
PEP 621 ``pyproject.toml`` (``[project]`` + optional-dependencies), Poetry
(``[tool.poetry.dependencies]``) and ``Pipfile``. A CVE/advisory lookup
(OSV / pip-audit) that needs the network is a planned optional extra; this core
is the offline, zero-dependency baseline.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .models import SEVERITIES

SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}

# Directories we never descend into when discovering manifests: virtualenvs,
# vendored/installed packages and VCS metadata are not the *project's* declared
# supply chain, and scanning them produces noise.
_PRUNE_DIRS = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "site-packages", "__pycache__", ".tox", ".nox", "build", "dist",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "tmp", ".eggs",
})

# Curated list of PyPI package names documented to have carried malware or to
# squat a popular package / stdlib module name. Stored as *canonical* names
# (see :func:`canonicalize_name`) so a hit is exact and high-signal — this is a
# pattern library of known-bad uploads, deliberately not a fuzzy typo heuristic
# (which would false-positive). Provenance: SK-CSIRT/“Nora” PyPI typosquat
# disclosure (2017); BleepingComputer/Medium reports (colourama 2018,
# python3-dateutil & jeIlyfish 2019); JFrog PyPI-malware disclosure (2021).
KNOWN_MALICIOUS_PACKAGES: dict[str, str] = {
    "acqusition": "typosquat of 'acquisition' (SK-CSIRT 2017)",
    "apidev-coop": "typosquat of 'apidev-coop_cms' (SK-CSIRT 2017)",
    "bzip": "squats the stdlib 'bz2' module name (SK-CSIRT 2017)",
    "crypt": "squats the stdlib 'crypt' module name (SK-CSIRT 2017)",
    "django-server": "django name-confusion squat (SK-CSIRT 2017)",
    "pwd": "squats the stdlib 'pwd' module name (SK-CSIRT 2017)",
    "setup-tools": "typosquat of 'setuptools' (SK-CSIRT 2017)",
    "telnet": "squats the stdlib 'telnetlib' module name (SK-CSIRT 2017)",
    "urlib3": "typosquat of 'urllib3' (SK-CSIRT 2017)",
    "urllib": "squats the stdlib 'urllib' module name (SK-CSIRT 2017)",
    "colourama": "typosquat of 'colorama' — crypto clipboard hijacker (2018)",
    "ssh-decorate": "malicious upload exfiltrating SSH credentials (2018)",
    "python3-dateutil": "typosquat of 'python-dateutil' — credential stealer (2019)",
    "jeilyfish": "typosquat of 'jellyfish' — SSH/GPG-key stealer (2019)",
    "pytagora": "malicious upload (JFrog disclosure, 2021)",
    "noblesse": "info-stealer malicious upload (JFrog disclosure, 2021)",
}

# Version-specifier operators that establish an upper bound (so a future,
# unvetted release cannot be pulled silently).
_HAS_UPPER = ("==", "===", "~=", "<", "<=")
_SPEC_RE = re.compile(r"(===|==|!=|~=|>=|<=|>|<)\s*[^,;\s]+")


def canonicalize_name(name: str) -> str:
    """PEP 503 name normalisation: lowercase, runs of ``-_.`` collapsed to ``-``."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


@dataclass(frozen=True)
class Dependency:
    """One declared dependency, normalised across manifest formats."""

    name: str  # canonical name
    raw: str  # the raw declaration as written
    specifier: str  # version constraint, e.g. "==1.2.3", ">=1.0", "" (unpinned)
    manifest: str  # repo-relative path of the manifest it came from
    url: str = ""  # set when the dep is a direct VCS/URL install


@dataclass(frozen=True, repr=False)
class SupplyChainFinding:
    """A supply-chain risk in a declared dependency or index directive."""

    id: str
    severity: str  # one of models.SEVERITIES
    package: str
    manifest: str
    technique: str
    evidence: str
    recommendation: str

    def __repr__(self) -> str:  # compact id-only repr keeps pytest/SARIF output clean
        return f"SupplyChainFinding({self.id})"


def _strip_comment(line: str) -> str:
    """Drop a requirements.txt inline comment (a ``#`` preceded by whitespace)."""
    return re.sub(r"(^|\s)#.*$", "", line).strip()


def _split_name_spec(text: str) -> tuple[str, str, str]:
    """Split a PEP 508 requirement into (name, specifier, url).

    Handles ``name[extras]==1.2``, ``name>=1,<2; python_version<'3.12'`` and the
    direct-reference form ``name @ https://…``. Returns canonical name plus the
    version specifier (empty if unpinned) and a URL (empty unless a direct ref).
    """
    text = text.strip()
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", text)
    if not m:
        return "", "", ""
    name = canonicalize_name(m.group(1))
    rest = text[m.end():].strip()
    # strip an extras group: name[extra1,extra2]
    if rest.startswith("["):
        rest = rest[rest.find("]") + 1:].strip() if "]" in rest else ""
    # direct reference: name @ url
    if rest.startswith("@"):
        return name, "", rest[1:].strip()
    # drop an environment marker (everything after ';')
    rest = rest.split(";", 1)[0].strip()
    specifier = ",".join(m.group(0) for m in _SPEC_RE.finditer(rest))
    return name, specifier, ""


def _is_url_install(text: str) -> str:
    """Return the URL if ``text`` is a bare VCS/URL install, else ""."""
    if re.match(r"^(git|hg|svn|bzr)\+", text) or re.match(r"^https?://|^file://", text):
        return text.strip()
    return ""


def _parse_requirements(path: Path, rel: str) -> tuple[list[Dependency], list[SupplyChainFinding]]:
    """Parse a ``requirements.txt``-style file into deps + index-directive findings."""
    deps: list[Dependency] = []
    findings: list[SupplyChainFinding] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    # join backslash line-continuations
    text = re.sub(r"\\\n", " ", text)
    for line in text.splitlines():
        line = _strip_comment(line)
        if not line:
            continue
        if line.startswith("-"):
            findings.extend(_index_directive_findings(line, rel))
            # -e / --editable <url> is a direct VCS/URL install
            edit = re.match(r"^(-e|--editable)\s+(.*)$", line)
            if edit:
                url = edit.group(2).strip()
                deps.append(Dependency(_url_pkg_name(url), url, "", rel, url=url))
            continue
        url = _is_url_install(line)
        if url:
            deps.append(Dependency(_url_pkg_name(url), line, "", rel, url=url))
            continue
        name, specifier, ref_url = _split_name_spec(line)
        if name:
            deps.append(Dependency(name, line, specifier, rel, url=ref_url))
    return deps, findings


def _url_pkg_name(url: str) -> str:
    """Best-effort package name from a VCS/URL install (``#egg=`` or the repo stem)."""
    egg = re.search(r"[#&]egg=([A-Za-z0-9._-]+)", url)
    if egg:
        return canonicalize_name(egg.group(1))
    stem = re.sub(r"\.git$", "", url.rstrip("/").split("/")[-1])
    return canonicalize_name(stem) or "<url>"


def _index_directive_findings(line: str, rel: str) -> list[SupplyChainFinding]:
    """Flag insecure (cleartext) or extra package indexes in a requirements line."""
    out: list[SupplyChainFinding] = []
    m = re.match(r"^(--index-url|-i|--extra-index-url|--find-links)[=\s]+(\S+)", line)
    if not m:
        return out
    opt, value = m.group(1), m.group(2)
    if value.startswith("http://"):
        out.append(SupplyChainFinding(
            id=f"LLM03-index-cleartext-{canonicalize_name(value)[:24]}",
            severity="high", package=value, manifest=rel,
            technique="package index over cleartext HTTP",
            evidence=f"{opt} points at an http:// index ({value}) — packages can be "
                     "swapped in transit (MITM).",
            recommendation="Use an https:// index URL; prefer the default PyPI index.",
        ))
    elif opt in ("--extra-index-url", "--find-links"):
        out.append(SupplyChainFinding(
            id=f"LLM03-extra-index-{canonicalize_name(value)[:24]}",
            severity="medium", package=value, manifest=rel,
            technique="additional package index broadens dependency-confusion surface",
            evidence=f"{opt} adds a non-default index ({value}); a public package of the "
                     "same name can shadow the intended private one.",
            recommendation="Pin the index per package, or use a single trusted index with "
                           "namespace ownership.",
        ))
    return out


def _parse_pyproject(path: Path, rel: str) -> list[Dependency]:
    """Parse PEP 621 and Poetry dependencies out of a ``pyproject.toml``."""
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
        return deps
    project = data.get("project", {})
    specs: list[str] = list(project.get("dependencies", []) or [])
    for group in (project.get("optional-dependencies", {}) or {}).values():
        specs.extend(group or [])
    for spec in specs:
        name, specifier, ref_url = _split_name_spec(spec)
        if name:
            deps.append(Dependency(name, spec, specifier, rel, url=ref_url))
    # Poetry-style dependencies
    poetry = data.get("tool", {}).get("poetry", {})
    for section in ("dependencies", "dev-dependencies"):
        for name, spec in (poetry.get(section, {}) or {}).items():
            if name.lower() == "python":
                continue
            deps.append(_poetry_dep(name, spec, rel))
    return deps


def _poetry_dep(name: str, spec, rel: str) -> Dependency:
    """Normalise a Poetry dependency value (string or table) to a Dependency."""
    cname = canonicalize_name(name)
    if isinstance(spec, dict):
        if any(k in spec for k in ("git", "url", "path")):
            url = spec.get("git") or spec.get("url") or spec.get("path") or ""
            return Dependency(cname, f"{name} = {spec}", "", rel, url=str(url))
        spec = spec.get("version", "*")
    text = str(spec).strip()
    # caret/tilde establish an upper bound; "*" or "" is unpinned
    if text in ("", "*"):
        specifier = ""
    elif text[0] in "^~":
        specifier = "~=" + text[1:]  # treat as bounded (has an upper bound)
    else:
        specifier = "".join(m.group(0) for m in _SPEC_RE.finditer(text)) or text
    return Dependency(cname, f"{name} = {spec!r}", specifier, rel)


def _parse_pipfile(path: Path, rel: str) -> list[Dependency]:
    """Parse ``[packages]`` / ``[dev-packages]`` out of a Pipfile (TOML)."""
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
        return deps
    for section in ("packages", "dev-packages"):
        for name, spec in (data.get(section, {}) or {}).items():
            deps.append(_poetry_dep(name, spec, rel))  # same value shape as Poetry
    return deps


_MANIFEST_GLOBS = ("requirements*.txt", "pyproject.toml", "Pipfile")


def discover_manifests(repo: Path) -> list[Path]:
    """Find dependency manifests anywhere under ``repo``, skipping vendored/venv dirs.

    Recurses so monorepos and nested projects are covered — a top-level-only scan
    would report a repo whose manifests live in subdirectories as "clean", which
    is a silent gap for a security tool. Vendored/installed trees (``.venv``,
    ``node_modules``, ``site-packages``, …) are pruned so only the project's own
    declared dependencies are scanned.
    """
    repo = Path(repo)
    found: set[Path] = set()
    for pattern in _MANIFEST_GLOBS:
        for path in repo.rglob(pattern):
            if any(part in _PRUNE_DIRS for part in path.relative_to(repo).parts[:-1]):
                continue
            if path.is_file():
                found.add(path)
    return sorted(found)


def _classify(dep: Dependency) -> SupplyChainFinding | None:
    """Return the highest-severity supply-chain risk for one dependency, or None."""
    if dep.name in KNOWN_MALICIOUS_PACKAGES:
        return SupplyChainFinding(
            id=f"LLM03-malicious-{dep.name}", severity="critical",
            package=dep.name, manifest=dep.manifest,
            technique="known-malicious / typosquatted package",
            evidence=f"'{dep.name}' is a known-bad package: "
                     f"{KNOWN_MALICIOUS_PACKAGES[dep.name]}.",
            recommendation=f"Remove '{dep.name}' immediately and audit for compromise; "
                           "install the legitimate package by its correct name.",
        )
    if dep.url:
        return SupplyChainFinding(
            id=f"LLM03-direct-url-{dep.name}", severity="high",
            package=dep.name, manifest=dep.manifest,
            technique="direct VCS/URL install bypasses the package index",
            evidence=f"'{dep.name}' is installed from {dep.url!r}, bypassing the package "
                     "index's integrity, signing and yank guarantees.",
            recommendation="Depend on a released, version-pinned package from a trusted "
                           "index; if a fork is required, pin it to an immutable commit hash.",
        )
    if not dep.specifier:
        return SupplyChainFinding(
            id=f"LLM03-unpinned-{dep.name}", severity="high",
            package=dep.name, manifest=dep.manifest,
            technique="unpinned dependency floats to any future version",
            evidence=f"'{dep.name}' has no version constraint, so the build pulls whatever "
                     "the index serves next — including a compromised release.",
            recommendation=f"Pin '{dep.name}' to a reviewed version (e.g. '{dep.name}==X.Y.Z') "
                           "or use a hash-locked requirements file.",
        )
    if not any(op in dep.specifier for op in _HAS_UPPER):
        return SupplyChainFinding(
            id=f"LLM03-no-upper-bound-{dep.name}", severity="medium",
            package=dep.name, manifest=dep.manifest,
            technique="version range has no upper bound",
            evidence=f"'{dep.name}' specifies '{dep.specifier}' with no upper bound, admitting "
                     "an unvetted future major release.",
            recommendation=f"Add an upper bound (e.g. '{dep.name}>=X,<Y') or pin exactly.",
        )
    return None


def scan_dependencies(repo: str | Path) -> list[SupplyChainFinding]:
    """Scan every dependency manifest under ``repo`` for supply-chain risks.

    Returns the findings sorted worst-first (by severity, then package). An empty
    list means no risky dependency or index directive was found in any manifest.
    """
    repo = Path(repo)
    findings: list[SupplyChainFinding] = []
    seen: set[tuple[str, str]] = set()  # (canonical name, technique-class) — dedupe across manifests
    for manifest in discover_manifests(repo):
        rel = str(manifest.relative_to(repo))
        if manifest.name == "pyproject.toml":
            deps, dir_findings = _parse_pyproject(manifest, rel), []
        elif manifest.name == "Pipfile":
            deps, dir_findings = _parse_pipfile(manifest, rel), []
        else:
            deps, dir_findings = _parse_requirements(manifest, rel)
        findings.extend(dir_findings)
        for dep in deps:
            finding = _classify(dep)
            if finding is None:
                continue
            key = (dep.name, finding.technique)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.package))
    return findings
