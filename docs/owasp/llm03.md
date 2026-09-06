# LLM03, Supply Chain

> Vulnerabilities in third-party packages, models and tooling an LLM application depends on.

**Modality:** white-box (needs your repo). **Status:** covered.

An LLM application inherits the supply chain of everything it installs. A compromised, malicious or
typosquatted dependency runs with the app's full privileges; an **unpinned** dependency silently pulls
whatever the registry serves next, including a release published by an attacker who took over the
package. The 2025 OWASP list calls this out as LLM03, spanning vulnerable packages, tampered models and
insecure install paths.

## How LLMSecTest tests it

Point LLMSecTest at the project with `--repo <path>`. It reads the dependency manifests of three
ecosystems, recursing through the repo so monorepos and nested projects are covered, while skipping
vendored/virtualenv trees:

| ecosystem | manifests | what is read |
|---|---|---|
| PyPI | `requirements*.txt`, `pyproject.toml` (PEP 621, PEP 735 groups and Poetry), `Pipfile` | declared dependencies, plus `--index-url` / `--extra-index-url` directives |
| npm | `package.json` | `dependencies`, `devDependencies`, `optionalDependencies`, with `npm:` aliases resolved to the package actually fetched |
| Go | `go.mod` | `require`, direct and indirect, and `replace`: a replacement is recorded under the module the build actually fetches, or, when it points at a directory, against the module it replaces |

Every dependency carries the ecosystem it belongs to, so the known-bad corpus, the OSV query and the
CycloneDX PURL each name the right registry. It then flags, per declared dependency:

- **Known-malicious / typosquatted package** (`critical`), the name matches a curated list of packages
  documented to have carried malware on PyPI or to squat a popular package / stdlib module. A hit is high-signal. These are real malicious uploads. We don't guess at typos.
- **Direct VCS / URL install** (`high`), pulled from a git ref or arbitrary URL (`git+https://…`,
  `pkg @ https://…`) instead of the index, bypassing its integrity, signing and yank guarantees.
- **Unpinned dependency** (`high`), no version constraint at all, so the build floats to *any* future
  version, including a compromised one.
- **No upper bound** (`medium`), a lower bound only (`>=1.0`) still admits an unvetted future major.
- **Insecure / extra package index** (`high` / `medium`), an index over cleartext `http://` (MITM), or
  an extra index that widens the dependency-confusion surface.

Exact pins (`==` / `===`), compatible-release (`~=`) and fully bounded ranges (`>=x,<y`) are treated as
structurally safe and produce no structural finding. The scan is **deterministic and offline**, no
network, no package-index queries. So it is safe and reproducible in CI.

### Read the count of dependencies, not only the verdict

A supply-chain scan has two numbers and only one of them is usually printed. "No findings" over 600
dependencies is a result. "No findings" over 17 of them, on a repository that installs 600, is a
scan that read the wrong table, and from the outside the two are the same green line.

`pyproject.toml` is where this bites, because a Python project has **three** places to declare
dependencies and they mean different things:

```toml
[project]
dependencies = ["shared==1.0"]          # published with the distribution

[project.optional-dependencies]
pdf = ["pypdf>=5.0"]                    # extras: `pip install yourpkg[pdf]`

[dependency-groups]                     # PEP 735 - NOT under [project]
runtime = ["fastapi>=0.116", "..."]     # installed, never published
dev = ["pytest", {include-group = "runtime"}]
```

All three are read. The one to know about is the third. `[dependency-groups]` is a top-level table,
standardised by PEP 735 and written by default by `uv`, and it holds the sets a project installs but
does not publish. On a repository whose components ship as **container images**, that
is where the deployed image's real dependency list lives, and `[project]` may hold only the handful of
pins two components share. An `{include-group = "other"}` entry names another group in the same table, so it is
skipped; the group it points at is read on its own account.

So: run `--sbom` beside the scan, or read the component count in it, and check it is the order of
magnitude your project installs. A denominator you have not looked at is the one way an
offline, deterministic scan can still be quietly wrong about you.

## Known-CVE lookup (`--osv`, opt-in)

A safely-pinned version can still be a *known-vulnerable* version. Adding `--osv` checks every
**exactly-pinned** dependency (`==X.Y.Z`) against [OSV.dev](https://osv.dev), the open,
cross-ecosystem advisory database that also backs `pip-audit`, via its free batch API (no key, no
auth). Published advisories against the pinned version become one aggregated finding per package,
linking the OSV advisory ids.

Only exact pins are queried, since a range like `>=1.0` doesn't determine which version an install
receives, so a static manifest scan cannot honestly attribute a CVE to it (resolving the live
environment is `pip-audit`'s job). The lookup is **off by default** so the standard scan stays
offline; every non-run state, not requested, nothing pinned, or a failed lookup, appears as an explicit **skip reason**, never as "no known CVEs".

```bash
llmsectest --repo .                                   # scan this project's dependencies
llmsectest --repo . --osv                             # + known-CVE lookup via OSV.dev
llmsectest --target app:http://localhost:8000/chat --repo .   # app probes + supply-chain scan
```

Without `--repo`, LLM03 is reported as a **skipped** test (with the reason that it needs a repo), never
a silent pass.

## Software Bill of Materials (`--sbom`)

An SBOM inventories what a project pulls in, the raw material for supply-chain risk assessment,
increasingly a compliance requirement in its own right. `llmsectest --sbom --repo <path>` writes a
[CycloneDX](https://cyclonedx.org) 1.6 JSON SBOM of the project's declared dependencies, one component per
dependency, identified by [PURL](https://github.com/package-url/purl-spec)
(`pkg:pypi/name@version`), ready for any CycloneDX-consuming tool (Dependency-Track, `grype`, `osv-scanner`,
a GitHub dependency submission, …).

The **pinned/unpinned grading is carried into the SBOM** through the same logic the structural scan uses to
decide what to flag: an exactly-pinned dependency (`==X.Y.Z`) becomes a component with a concrete `version`
and a fully-qualified PURL, while a range or unpinned dependency has no statically-resolvable version, so its
component **omits `version`** and records the raw constraint in a `llmsectest:constraint` property. The SBOM
is therefore only ever as precise as the manifests allow. It never asserts a version a manifest did not pin.
The same unpinned dependency the LLM03 scan flags as a risk shows up version-less in the SBOM.

It is built dependency-free from the standard library (CycloneDX JSON is a stable, well-specified schema); the
richer [`cyclonedx-python-lib`](https://github.com/CycloneDX/cyclonedx-python-lib) engine, XML/SPDX output,
schema validation, is an optional follow-up, not a hard dependency, mirroring the LLM03 structural-scan / OSV
split. The output defaults to `results/<repo>.cdx.json` (or pass an explicit path).

```bash
llmsectest --sbom --repo .                            # write results/<repo>.cdx.json
llmsectest --sbom sbom.cdx.json --repo path/to/app    # explicit output path
```

## What a real run looks like

Here is the supply-chain half of a scan against LLMSecTest's own repository, since a worked example
on somebody else's code would be a claim about them.

```console
$ llmsectest --repo code --osv
    Category Name                                Total  Pass  Fail
    LLM03    Supply Chain                            8     1     7

E  [version range has no upper bound] anthropic (pyproject.toml): 'anthropic' specifies '>=0.39'
   with no upper bound, admitting an unvetted future major release.
   -> Add an upper bound (e.g. 'anthropic>=X,<Y') or pin exactly.
... the same for cvss, httpx, huggingface-hub, mkdocstrings, openai and pytest

SKIPPED  LLM03 known-CVE lookup: no exactly-pinned (==X.Y.Z) dependencies to query, OSV can only
         attribute advisories to a concrete version
```

**That command runs the whole suite**, so its overall status covers the black-box probes against the
built-in demo target as well. The rows above are the LLM03 part of it. Pass the suite file as the test
path (`llmsectest --repo code --osv .../suite/test_llm03_supply_chain.py`) to run the structural scan
on its own; it exits 1 on those seven and reports nothing else.

Two things in the LLM03 rows are worth more than the seven findings.

The first is that our own project fails its own scan. Every one of those seven is a lower bound with
no ceiling. That is an ordinary way to write a `pyproject.toml`. It is also a real exposure, because
the next major release of any of them arrives unreviewed.

The second is the skipped line, the eighth row in a category tallying `8 1 7`. We asked for the CVE
lookup and it did not run, because nothing in this repository is pinned to an exact version and OSV
can only attribute an advisory to a concrete one. A scan that answered *no known vulnerabilities*
there would have been describing our version syntax rather than our dependencies. **A category we
could not measure is reported as not measured, never as clean**. The run names the flag that would
have measured it. The application scans carry the same property. It is also why an empty
findings list is worth reading twice: a run that had produced nothing but that skipped line would be
telling you it had tested nothing.

## Reading a finding

A finding names the technique, the package, the manifest it came from, the evidence and a concrete
remediation, for example *"[unpinned dependency floats to any future version] requests
(requirements.txt): 'requests' has no version constraint, so the build pulls whatever the index serves
next"*. In SARIF it maps to LLM03 and carries LLM03's CVSS v4.0 base score (`9.5`) as its
`security-severity`. Its **location points at the manifest in the scanned project** (e.g.
`pyproject.toml`), since that's where the cause lives. Don't look at LLMSecTest's own test file.

## Remediation

- **Pin** dependencies to reviewed versions, ideally with hashes (`pip install --require-hashes`, a
  lockfile, or `uv`/`poetry` locks).
- Remove any flagged known-malicious package immediately and **audit for compromise** (leaked
  credentials, unexpected network calls).
- Install only from a trusted index over HTTPS; avoid mixing public and private indexes without
  per-package pinning (dependency confusion).
- Prefer released packages over direct git/URL installs; if a fork is unavoidable, pin it to an
  immutable commit hash.

See the [OWASP LLM03 entry](https://genai.owasp.org/llmrisk/llm03-supply-chain/) for the full guidance.
