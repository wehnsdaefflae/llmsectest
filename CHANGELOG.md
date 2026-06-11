# Changelog

All notable changes to LLMSecTest are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

LLMSecTest is pre-1.0 and built in the open. `0.1.0` is the first tagged GitHub release; it is **not
yet published to PyPI**. The forward-looking plan is the [roadmap](https://llmsec.dev/#roadmap).

## [Unreleased]

### Added
- **LLM03 known-CVE lookup via OSV.dev (`--osv`).** With `--repo`, the new opt-in `--osv` flag checks
  every exactly-pinned dependency (`==X.Y.Z`) against the free OSV.dev advisory API (no key) and turns
  published advisories into findings — one aggregated finding per vulnerable package, linking the OSV
  ids. The structural scan stays the offline default; "not requested", "nothing exactly pinned" and
  "lookup failed" each surface as an explicit skip reason, never as a clean result. (2026-06-11)
- **`--version` flag** prints the installed llmsectest version. (2026-06-11)
- **OWASP LLM03 (Supply Chain) scanning.** A white-box dependency scanner reads a project's
  manifests (`requirements*.txt`, `pyproject.toml` incl. Poetry, `Pipfile`) and flags
  known-malicious / typosquatted packages, unpinned or unbounded versions, direct VCS/URL installs
  and insecure/extra package indexes — deterministic and offline (no network). Enable it with the new
  `--repo <path>` flag; findings carry the LLM03 CVSS v4.0 base score (9.5) in SARIF. Coverage is now
  **6/10** OWASP categories. Without `--repo`, LLM03 reports itself skipped (needs a repo), never a
  silent pass. (2026-06-10)

## [0.1.0] - 2026-06-10

### Added
- **CVSS v4.0 scoring.** Each OWASP category carries a representative `CVSS:4.0` base vector; findings
  report its base score as the SARIF `security-severity`. The ten canonical scores ship in the
  dependency-free core; the optional `cvss` library (`pip install "llmsectest[cvss]"`) scores custom
  vectors. (2026-06-09)
- **Every scan covers all ten OWASP categories — no silent gaps.** Implemented categories run real
  probes; not-yet-implemented ones are reported as skipped tests marked *not yet implemented* (with what
  they need and when), and every run prints a coverage footer summarising what it exercised. (2026-06-09)
- **Black-box testing of a real application.** `--target app:<url>` drives your running app through its
  own HTTP endpoint (its real guardrails in the loop); a persona proxy (`run_app_scan`) tests an app's
  real system prompt against a local model. Application mode covers LLM01 and LLM05 out of the box, and
  LLM02 / LLM06 / LLM07 when you supply the app's secret / action signatures / system prompt. (2026-06-08–09)
- **Local and self-hosted models.** Ollama adapter and OpenAI-compatible `base_url`, so the suite can run
  against a local model with no API key and no paid calls. (2026-06-08)
- **OWASP probe suite.** Adapter-driven probes for LLM01 Prompt Injection, LLM02 Sensitive Information
  Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency and LLM07 System Prompt Leakage,
  with false-positive-resistant substring/canary detectors. (2026-06-03–08)
- **Reporting.** SARIF v2.1.0, HTML, JSON and Markdown reports carrying OWASP metadata, CWE tags,
  compliance-framework mapping, risk scoring, baselines and policy gates. Per-target SARIF paths so
  consecutive scans don't overwrite each other. (2026-06-03–04)
- **Unified LLM adapter.** OpenAI, Anthropic and Hugging Face behind one interface with lazy SDK imports,
  plus offline test doubles for deterministic, key-free tests. (2026-06-02)
- **Command-line interface.** The `llmsectest` console script: `--target`, `--check`, `--list-probes`,
  `--validate`, and report-format selection. (2026-06-03)
- **Documentation site** at <https://docs.llmsec.dev> (MkDocs Material), with the API reference
  auto-generated from docstrings. (2026-06-08)

### Changed
- Reconciled all OWASP metadata (names, numbering, CWEs) to the **OWASP LLM Top 10 (2025)** list.
  (2026-06-08)
- SARIF `security-severity` now carries the real CVSS v4.0 base score instead of a flat severity
  placeholder. (2026-06-09)

### Fixed
- CLI: a space-separated option value (e.g. `--report-dir tmp`) was mistaken for a positional test path
  and silently skipped the packaged suite. (2026-06-09)

[Unreleased]: https://github.com/wehnsdaefflae/llmsectest/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/wehnsdaefflae/llmsectest/releases/tag/v0.1.0
