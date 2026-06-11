# LLM03 — Supply Chain

> Vulnerabilities in third-party packages, models and tooling an LLM application depends on.

**Modality:** white-box (needs your repo). **Status:** covered.

An LLM application inherits the supply chain of everything it installs. A compromised, malicious or
typosquatted dependency runs with the app's full privileges; an **unpinned** dependency silently pulls
whatever the registry serves next — including a release published by an attacker who took over the
package. The 2025 OWASP list calls this out as LLM03, spanning vulnerable packages, tampered models and
insecure install paths.

## How LLMSecTest tests it

Point LLMSecTest at the project with `--repo <path>`. It reads the dependency manifests
(`requirements*.txt`, `pyproject.toml` including Poetry, and `Pipfile`) — recursing through the repo so
monorepos and nested projects are covered, while skipping vendored/virtualenv trees — and flags, per
declared dependency:

- **Known-malicious / typosquatted package** (`critical`) — the name matches a curated list of packages
  documented to have carried malware on PyPI or to squat a popular package / stdlib module. A hit is
  high-signal: these are real malicious uploads, not a fuzzy typo heuristic.
- **Direct VCS / URL install** (`high`) — pulled from a git ref or arbitrary URL (`git+https://…`,
  `pkg @ https://…`) instead of the index, bypassing its integrity, signing and yank guarantees.
- **Unpinned dependency** (`high`) — no version constraint at all, so the build floats to *any* future
  version, including a compromised one.
- **No upper bound** (`medium`) — a lower bound only (`>=1.0`) still admits an unvetted future major.
- **Insecure / extra package index** (`high` / `medium`) — an index over cleartext `http://` (MITM), or
  an extra index that widens the dependency-confusion surface.

Exact pins (`==` / `===`), compatible-release (`~=`) and fully bounded ranges (`>=x,<y`) are treated as
structurally safe and produce no structural finding. The scan is **deterministic and offline** — no
network, no package-index queries — so it is safe and reproducible in CI.

## Known-CVE lookup (`--osv`, opt-in)

A safely-pinned version can still be a *known-vulnerable* version. Adding `--osv` checks every
**exactly-pinned** dependency (`==X.Y.Z`) against [OSV.dev](https://osv.dev) — the open,
cross-ecosystem advisory database that also backs `pip-audit` — via its free batch API (no key, no
auth). Published advisories against the pinned version become one aggregated finding per package,
linking the OSV advisory ids.

Only exact pins are queried: a range like `>=1.0` doesn't determine which version an install actually
receives, so a static manifest scan cannot honestly attribute a CVE to it (resolving the live
environment is `pip-audit`'s job). The lookup is **off by default** so the standard scan stays
offline; every non-run state — not requested, nothing exactly pinned, or a failed lookup — appears as
an explicit **skip reason**, never as "no known CVEs".

```bash
llmsectest --repo .                                   # scan this project's dependencies
llmsectest --repo . --osv                             # + known-CVE lookup via OSV.dev
llmsectest --target app:http://localhost:8000/chat --repo .   # app probes + supply-chain scan
```

Without `--repo`, LLM03 is reported as a **skipped** test (with the reason that it needs a repo) — never
a silent pass.

## Reading a finding

A finding names the technique, the package, the manifest it came from, the evidence and a concrete
remediation — for example *"[unpinned dependency floats to any future version] requests
(requirements.txt): 'requests' has no version constraint, so the build pulls whatever the index serves
next"*. In SARIF it maps to LLM03 and carries LLM03's CVSS v4.0 base score (`9.5`) as its
`security-severity`.

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
