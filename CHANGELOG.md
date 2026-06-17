# Changelog

All notable changes to LLMSecTest are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

LLMSecTest is pre-1.0 and built in the open. `0.1.0` is the first tagged GitHub release; it is **not
yet published to PyPI**. The forward-looking plan is the [roadmap](https://llmsec.dev/#roadmap).

## [Unreleased]

### Added
- **`--render-sarif <file.sarif>` — render any SARIF report as standalone HTML.** Turns a finished SARIF
  v2.1.0 file (ours or any other tool's) into a single self-contained HTML page (inline CSS, no assets,
  no network) — findings grouped by OWASP category, CVSS-scored and colour-coded by severity, each with
  its location, evidence and remediation, plus a rule-reference glossary; third-party SARIF without our
  OWASP/CVSS properties degrades gracefully. Writes `results/<target>.html` by default (or `-o <path>`).
  New `llmsectest.reporting.sarif_html` (`render_sarif_html` / `render_sarif_file`). Lets you review the
  reports from the real projects you scan in a browser, not just as raw JSON. (2026-06-17)
- **OWASP LLM10 (Unbounded Consumption) probes — coverage 6/10 → 7/10.** A new probe corpus and a
  deterministic `unbounded_consumption` detector flag a target that produces **runaway output** instead
  of bounding it: each case asks the target to emit a marker without bound (repetition flood,
  never-terminating enumeration, denial-of-wallet amplification, runaway continuation), and a reply that
  repeats the marker past a flood threshold is a finding — a denial-of-service / denial-of-wallet signal
  visible even within a finite token budget, so it works black-box against a real app endpoint as well as
  a local model. A safe target that caps or refuses passes; a short bounded sample is not a false positive.
  LLM10 is **always reachable** in application mode (it joins LLM01 + LLM05 as attack-side-marker
  categories that need no dev-supplied input). Findings carry the LLM10 CVSS v4.0 base score (8.7).
  (2026-06-17)
- **Over-refusal (false-refusal-rate) metric via the JailbreakBench benign twins.** `--redteam-benign`
  runs the JBB **benign twins** — harmless requests topic-matched to the harmful red-team behaviors —
  through a new **over-refusal oracle** (the mirror of the refusal oracle: a *refusal* of a harmless
  request is the finding) and reports the target's **false-refusal rate**. Bare `--redteam-benign` uses a
  built-in benign starter set; `--redteam-benign <csv>` runs the full JBB `benign-behaviors.csv`. It is a
  **usability** signal — over-refusing is a product-quality defect, not an OWASP vulnerability — so it is
  reported separately and never enters the SARIF security report or the exit code. This turns the
  detector's specificity control into a shipped metric (the offline demos show the split cleanly:
  `demo-vulnerable` 0% over-refusal but high attack success, `demo-defended` 0 findings but 100%
  over-refusal). Deepens LLM01; the 6/10 category count is unchanged. (2026-06-16)
- **Red-team jailbreak prompts (JailbreakBench / AdvBench) under LLM01.** A new red-team module scores
  a target with a **refusal oracle** — inverted from the canary detectors: a red-team behavior plants no
  token, so the target is a finding when it **complies** with a harmful request instead of refusing it.
  Point `--redteam-set <csv>` at the MIT-licensed [JailbreakBench JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors)
  set (100 behaviors; 18% from AdvBench, 27% from HarmBench/TDC) to run the full benchmark; without it a
  small built-in starter set ships so an offline run still exercises the oracle. The oracle errs toward
  "refused" (it under-reports rather than raising false findings); a classifier oracle (Llama-Guard /
  GLiGuard / garak's ModernBERT refusal detector) is the documented optional upgrade. This deepens LLM01;
  it does not change the 6/10 category count. (2026-06-15)
- **`--app-prompt` / `--app-secret` / `--app-action` CLI flags.** An application scan
  (`--target app:<url>`) always exercises LLM01 + LLM05 black-box; these new flags unlock the
  remaining black-box categories from the command line — the app's own system prompt (inline or a
  file path) enables **LLM07** leakage detection, a real secret the app holds enables **LLM02**, and
  its privileged tool/action signature(s) (repeatable flag) enable **LLM06**. Previously these inputs
  existed only on the `run_app_scan` Python API, so a CLI endpoint scan reached 2/10 categories; now
  it reaches up to 5/10, and every category whose input is missing is reported as a skip naming the
  flag that would enable it. The coverage footer reflects the supplied inputs. (2026-06-12)
- **CI workflow.** Every push and pull request now runs `ruff` + the unit suite on Python
  3.11/3.12/3.13, plus a smoke job that installs the package, scans the offline hardened demo and
  validates the emitted SARIF — so "it actually runs" is checked, not just the unit tests. README
  carries the badge. (2026-06-12)
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

### Fixed
- **LLM03 (supply chain) findings now point at the manifest in the *tested* project**, not at the
  scanner's own test file. Each supply-chain finding records the offending manifest's repo-relative path
  (`requirements.txt`, `pyproject.toml`, …) as an artifact location, so the SARIF/HTML location reads e.g.
  `pyproject.toml` in the scanned repo instead of `src/llmsectest/suite/test_llm03_supply_chain.py`.
  Behavioural findings (whose cause is a model response, with no project source line) still point at the
  test node. (Manifest line numbers are a follow-on; `tomllib` does not expose them for `pyproject.toml`.)
  (2026-06-17)

### Changed
- The offline demo target's persona branches (agent / red-team / resource-limit) now key on named
  trigger constants instead of inline magic strings, and a guard test pins each trigger to the matching
  corpus persona — so rewording a persona can no longer silently stop a demo branch from firing.
  (2026-06-17)
- The two red-team oracles (`refusal_oracle` and the new `over_refusal_oracle`) now share one
  `_refusal_signal` screening helper, and the harmful/benign CSV loaders share one `_load_behaviors`
  parser, so the harmful set and its benign twins cannot drift apart in how they read a reply or a file.
  (2026-06-16)
- The `LLMSECTEST_*` environment variables that carry CLI options to the packaged suite are now
  defined once in `llmsectest.envvars` (shared by the CLI, the suite and the coverage footer), so the
  two sides of that contract cannot drift. (2026-06-12)

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
