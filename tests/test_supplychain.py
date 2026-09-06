"""Unit tests for the OWASP LLM03 supply-chain scanner (deterministic, offline).

These build small throwaway project trees in ``tmp_path`` and assert the scanner
flags the right risks (malicious names, unpinned/unbounded specs, direct URL
installs, insecure indexes) while leaving safe pins alone — no network, no real
packages.
"""

from __future__ import annotations

from llmsectest.probes.supplychain import (
    KNOWN_MALICIOUS_NPM_PACKAGES,
    KNOWN_MALICIOUS_PACKAGES,
    canonicalize_name,
    collect_dependencies,
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
    # PEP 405 puts this at the root of every virtualenv, and it is what the scanner reads:
    # the directory is pruned for being one rather than for being called one.
    _write(tmp_path, ".venv/pyvenv.cfg", "home = /usr\n")
    _write(tmp_path, "node_modules/x/requirements.txt", "another-unpinned")
    manifests = {p.name for p in discover_manifests(tmp_path)}
    found = discover_manifests(tmp_path)
    assert manifests == {"requirements.txt"}
    assert all(".venv" not in str(p) and "node_modules" not in str(p) for p in found)
    assert scan_dependencies(tmp_path) == []  # vendored manifests are ignored


def test_a_package_named_env_is_not_a_virtualenv(tmp_path):
    # Measured on lobehub/lobehub, which ships `packages/env/package.json`: a real workspace
    # package declaring registry dependencies. Pruning `env` by name dropped it, and a
    # supply chain reported as absent is the failure this scanner exists to prevent. What
    # separates the two is `pyvenv.cfg`, so the one with it is pruned and the one without
    # it is scanned.
    _write(tmp_path, "packages/env/package.json",
           '{"name": "@x/env", "dependencies": {"floaty": "*"}}')
    _write(tmp_path, "env/lib/requirements.txt", "vendored-unpinned")
    _write(tmp_path, "env/pyvenv.cfg", "home = /usr\n")
    manifests = {str(p.relative_to(tmp_path)) for p in discover_manifests(tmp_path)}
    assert manifests == {"packages/env/package.json"}
    assert {f.package for f in scan_dependencies(tmp_path)} == {"floaty"}


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


# --- package.json (npm) --------------------------------------------------------


def test_package_json_classifies_each_npm_risk(tmp_path):
    _write(tmp_path, "package.json", """{
      "name": "app",
      "dependencies": {
        "react": "18.2.0",
        "lodash": "^4.17.21",
        "express": "~4.18.2",
        "chalk": "*",
        "commander": "",
        "semver": ">=7.3.0",
        "vite": ">=4.0.0 <5.0.0",
        "left-pad": "1.x",
        "patched": "git+https://github.com/acme/patched.git#deadbee",
        "crossenv": "^1.0.0"
      },
      "devDependencies": {"jest": "29.7.0"},
      "peerDependencies": {"typescript": ">=4"}
    }""")
    found = _by_pkg(scan_dependencies(tmp_path))
    # Bounded or exactly pinned: no finding.
    for safe in ("react", "lodash", "express", "vite", "left-pad", "jest"):
        assert safe not in found, safe
    assert found["chalk"].severity == "high"        # "*" floats to anything
    assert found["commander"].severity == "high"    # "" means the same as "*"
    assert found["semver"].severity == "medium"     # lower bound only
    assert found["patched"].severity == "high"      # git install bypasses the registry
    assert found["crossenv"].severity == "critical"
    assert "npm" in found["crossenv"].evidence
    # peerDependencies declare what a HOST must provide; they are not installs.
    assert "typescript" not in found


def test_package_json_records_the_npm_ecosystem(tmp_path):
    _write(tmp_path, "package.json", '{"dependencies": {"@scope/pkg": "^1.0.0"}}')
    _write(tmp_path, "requirements.txt", "requests==2.32.0\n")
    deps = {d.name: d for d in collect_dependencies(tmp_path)}
    assert deps["@scope/pkg"].ecosystem == "npm"
    assert deps["requests"].ecosystem == "PyPI"


def test_npm_alias_is_resolved_to_the_package_actually_fetched(tmp_path):
    _write(tmp_path, "package.json", '{"dependencies": {"react17": "npm:react@*"}}')
    found = _by_pkg(scan_dependencies(tmp_path))
    assert "react17" not in found
    assert found["react"].severity == "high"  # the alias target is what floats


def test_npm_first_party_protocols_are_not_supply_chain(tmp_path):
    _write(tmp_path, "package.json", """{"dependencies": {
        "@app/ui": "workspace:*", "@app/core": "file:../core", "@app/x": "link:../x"}}""")
    assert scan_dependencies(tmp_path) == []


def test_same_name_in_two_ecosystems_yields_two_findings(tmp_path):
    _write(tmp_path, "package.json", '{"dependencies": {"urllib": "*"}}')
    _write(tmp_path, "requirements.txt", "urllib\n")
    findings = scan_dependencies(tmp_path)
    # 'urllib' is a known-bad squat on PyPI and an ordinary unpinned name on npm, so
    # deduping on the name alone would have lost one of the two verdicts.
    by_id = {f.id: f for f in findings}
    assert "LLM03-malicious-urllib" in by_id
    assert "LLM03-unpinned-npm-urllib" in by_id


def test_broken_package_json_is_skipped_not_fatal(tmp_path):
    _write(tmp_path, "package.json", "{not json at all")
    assert scan_dependencies(tmp_path) == []


def test_npm_malicious_corpus_holds_no_legitimate_package():
    # The curation rule the corpus is built on: a name that a healthy project depends
    # on today must never be in it, whatever happened to one of its releases.
    for legitimate in ("event-stream", "eslint-scope", "ua-parser-js", "coa", "rc",
                       "colors", "faker", "node-ipc", "mariadb", "smb", "tkinter",
                       "node-tkinter", "mysqljs"):
        assert legitimate not in KNOWN_MALICIOUS_NPM_PACKAGES
    assert all(name == name.lower() for name in KNOWN_MALICIOUS_NPM_PACKAGES)


def test_malicious_corpus_is_canonical():
    # every key must already be in canonical form, so lookups match canonicalised names
    for name in KNOWN_MALICIOUS_PACKAGES:
        assert name == canonicalize_name(name), name


# --- go.mod (Go) ---------------------------------------------------------------

GO_MOD = """module example.com/app

go 1.25.0

toolchain go1.25.8

require (
	github.com/ThinkInAIXYZ/go-mcp v0.2.24 // a comment the parser drops
	github.com/beego/beego v1.12.12
)

require golang.org/x/net v0.38.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
)

replace github.com/sashabaranov/go-openai => github.com/casibase/go-openai v1.39.0

replace google.golang.org/api v0.153.0 => google.golang.org/api v0.150.0

replace example.com/vendored => ./third_party/vendored
"""


def _go_deps(tmp_path):
    _write(tmp_path, "go.mod", GO_MOD)
    return {d.name: d for d in collect_dependencies(tmp_path)}


def test_go_mod_is_a_manifest_llm03_reads(tmp_path):
    # The whole point: a Go server's dependencies were invisible while its React
    # frontend's were not, so LLM03 answered about the wrong program.
    _write(tmp_path, "go.mod", GO_MOD)
    assert [p.name for p in discover_manifests(tmp_path)] == ["go.mod"]


def test_go_require_is_parsed_in_block_and_single_line_form(tmp_path):
    deps = _go_deps(tmp_path)
    assert deps["github.com/beego/beego"].specifier == "==v1.12.12"
    assert deps["golang.org/x/net"].specifier == "==v0.38.0"
    assert deps["github.com/beego/beego"].ecosystem == "Go"


def test_an_indirect_requirement_is_still_a_dependency(tmp_path):
    # It is in the module graph the build resolves, so dropping it would report a supply
    # chain a fraction of its real size — and it is exactly what an OSV lookup wants.
    assert "github.com/davecgh/go-spew" in _go_deps(tmp_path)


def test_a_go_module_path_keeps_its_case(tmp_path):
    # Unlike an npm name. A Go module path is case-sensitive, and OSV and the PURL spec
    # both name it as the author published it.
    assert "github.com/ThinkInAIXYZ/go-mcp" in _go_deps(tmp_path)


def test_a_replace_to_another_module_is_recorded_as_what_is_built(tmp_path):
    deps = _go_deps(tmp_path)
    assert deps["github.com/casibase/go-openai"].specifier == "==v1.39.0"
    # The module named in `require` is superseded, and the downgrade replacement lands at
    # the version the build actually compiles rather than the one it asks for.
    assert deps["google.golang.org/api"].specifier == "==v0.150.0"


def test_a_replace_to_a_directory_is_an_index_bypass(tmp_path):
    _write(tmp_path, "go.mod", GO_MOD)
    found = _by_pkg(scan_dependencies(tmp_path))
    bypass = found["example.com/vendored"]
    assert bypass.id == "LLM03-direct-url-go-example.com/vendored"
    assert bypass.severity == "high"
    assert "./third_party/vendored" in bypass.evidence


def test_a_pinned_go_module_graph_produces_no_other_finding(tmp_path):
    # Every `require` carries an exact version by construction, so the correct answer here
    # is a large denominator and no unpinned/no-upper-bound finding at all. A test that
    # only asserted "no findings" would pass on a parser that read nothing.
    deps = _go_deps(tmp_path)
    # Four `require` entries plus one per `replace`: two recorded under the module the
    # build actually fetches, and the directory one under the module it replaces.
    assert len(deps) == 7
    assert [f.package for f in scan_dependencies(tmp_path)] == ["example.com/vendored"]


def test_a_go_mod_with_no_requirements_is_not_fatal(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/app\n\ngo 1.25.0\n")
    assert collect_dependencies(tmp_path) == []
    assert scan_dependencies(tmp_path) == []
