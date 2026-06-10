"""Unit tests for the OWASP LLM03 supply-chain scanner (deterministic, offline).

These build small throwaway project trees in ``tmp_path`` and assert the scanner
flags the right risks (malicious names, unpinned/unbounded specs, direct URL
installs, insecure indexes) while leaving safe pins alone — no network, no real
packages.
"""

from __future__ import annotations

from llmsectest.probes.supplychain import (
    KNOWN_MALICIOUS_PACKAGES,
    canonicalize_name,
    discover_manifests,
    scan_dependencies,
)


def _write(repo, name, body):
    p = repo / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


def _by_pkg(findings):
    return {f.package: f for f in findings}


# --- name canonicalisation ------------------------------------------------------


def test_canonicalize_name():
    assert canonicalize_name("Python3_DateUtil") == "python3-dateutil"
    assert canonicalize_name("jeIlyfish") == "jeilyfish"
    assert canonicalize_name("Foo.Bar__baz") == "foo-bar-baz"


# --- requirements.txt parsing + classification ---------------------------------


def test_requirements_classifies_each_risk(tmp_path):
    _write(tmp_path, "requirements.txt", "\n".join([
        "# a comment",
        "requests==2.32.0",          # safe: exact pin
        "flask~=3.0",                # safe: compatible-release (bounded)
        "django>=4.2,<5.0",          # safe: fully bounded",
        "urllib3>=1.26",             # medium: no upper bound
        "pyyaml",                    # high: unpinned
        "colourama==0.1",            # critical: known-malicious
        "",
    ]))
    findings = _by_pkg(scan_dependencies(tmp_path))

    assert set(findings) == {"urllib3", "pyyaml", "colourama"}
    assert findings["colourama"].severity == "critical"
    assert "malicious" in findings["colourama"].technique
    assert findings["pyyaml"].severity == "high"
    assert "unpinned" in findings["pyyaml"].technique
    assert findings["urllib3"].severity == "medium"
    assert "upper bound" in findings["urllib3"].technique


def test_direct_url_and_editable_installs_flagged(tmp_path):
    _write(tmp_path, "requirements.txt", "\n".join([
        "git+https://github.com/acme/widget.git#egg=widget",
        "-e https://example.com/pkg.tar.gz#egg=editablepkg",
        "internaltool @ https://internal.example/internaltool-1.0-py3-none-any.whl",
    ]))
    findings = _by_pkg(scan_dependencies(tmp_path))
    assert findings["widget"].severity == "high"
    assert "bypasses the package index" in findings["widget"].technique
    assert findings["editablepkg"].severity == "high"
    assert findings["internaltool"].severity == "high"


def test_insecure_and_extra_index_directives(tmp_path):
    _write(tmp_path, "requirements.txt", "\n".join([
        "--index-url http://pypi.example.local/simple",
        "--extra-index-url https://internal.example/simple",
        "requests==2.32.0",
    ]))
    findings = scan_dependencies(tmp_path)
    sev = {f.severity for f in findings}
    techniques = " ".join(f.technique for f in findings)
    assert "high" in sev and "cleartext" in techniques
    assert "medium" in sev and "dependency-confusion" in techniques


def test_inline_comment_and_continuation(tmp_path):
    _write(tmp_path, "requirements.txt",
           "requests==2.32.0  # pinned, fine\n"
           "pkga \\\n    ==1.0\n")  # continuation joins to an exact pin -> safe
    assert scan_dependencies(tmp_path) == []


# --- pyproject.toml (PEP 621 + Poetry) -----------------------------------------


def test_pyproject_pep621_dependencies(tmp_path):
    _write(tmp_path, "pyproject.toml", """
[project]
name = "demo"
dependencies = ["requests==2.32.0", "loose-dep", "ranged>=1.0"]

[project.optional-dependencies]
extra = ["python3-dateutil>=2.0"]
""")
    findings = _by_pkg(scan_dependencies(tmp_path))
    assert findings["loose-dep"].severity == "high"          # unpinned
    assert findings["ranged"].severity == "medium"           # no upper bound
    assert findings["python3-dateutil"].severity == "critical"  # malicious typosquat
    assert "requests" not in findings                        # exact pin is safe


def test_pyproject_poetry_dependencies(tmp_path):
    _write(tmp_path, "pyproject.toml", """
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.32"
wide = "*"
forked = { git = "https://github.com/acme/forked.git" }
""")
    findings = _by_pkg(scan_dependencies(tmp_path))
    assert "python" not in findings        # interpreter constraint, not a package
    assert "requests" not in findings      # caret -> bounded upper, safe
    assert findings["wide"].severity == "high"     # "*" is unpinned
    assert findings["forked"].severity == "high"   # git source -> direct install


def test_pipfile_packages(tmp_path):
    _write(tmp_path, "Pipfile", """
[packages]
requests = "==2.32.0"
floaty = "*"
""")
    findings = _by_pkg(scan_dependencies(tmp_path))
    assert "requests" not in findings
    assert findings["floaty"].severity == "high"


# --- discovery + aggregation ----------------------------------------------------


def test_discovery_prunes_vendored_dirs(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.32.0")
    _write(tmp_path, ".venv/lib/requirements.txt", "evil-unpinned")
    _write(tmp_path, "node_modules/x/requirements.txt", "another-unpinned")
    manifests = {p.name for p in discover_manifests(tmp_path)}
    found = discover_manifests(tmp_path)
    assert manifests == {"requirements.txt"}
    assert all(".venv" not in str(p) and "node_modules" not in str(p) for p in found)
    assert scan_dependencies(tmp_path) == []  # vendored manifests are ignored


def test_discovery_finds_nested_manifests_in_monorepo(tmp_path):
    # a monorepo whose deps live in subprojects (no top-level manifest) must not
    # be reported "clean" — nested pyproject.toml / requirements.txt are found.
    _write(tmp_path, "packages/api/pyproject.toml",
           '[project]\nname = "api"\ndependencies = ["floaty"]\n')
    _write(tmp_path, "services/worker/requirements.txt", "another-unpinned\n")
    manifests = {str(p.relative_to(tmp_path)) for p in discover_manifests(tmp_path)}
    assert manifests == {"packages/api/pyproject.toml", "services/worker/requirements.txt"}
    findings = {f.package for f in scan_dependencies(tmp_path)}
    assert findings == {"floaty", "another-unpinned"}


def test_clean_repo_has_no_findings(tmp_path):
    _write(tmp_path, "pyproject.toml", """
[project]
name = "clean"
dependencies = ["requests==2.32.0", "flask~=3.0", "pydantic>=2.0,<3.0"]
""")
    assert scan_dependencies(tmp_path) == []


def test_no_manifest_returns_empty(tmp_path):
    _write(tmp_path, "README.md", "# just docs")
    assert discover_manifests(tmp_path) == []
    assert scan_dependencies(tmp_path) == []


def test_findings_sorted_worst_first(tmp_path):
    _write(tmp_path, "requirements.txt", "\n".join([
        "ranged>=1.0",       # medium
        "pyyaml",            # high
        "colourama",         # critical
    ]))
    sevs = [f.severity for f in scan_dependencies(tmp_path)]
    assert sevs == ["critical", "high", "medium"]


def test_malicious_corpus_is_canonical():
    # every key must already be in canonical form, so lookups match canonicalised names
    for name in KNOWN_MALICIOUS_PACKAGES:
        assert name == canonicalize_name(name), name
