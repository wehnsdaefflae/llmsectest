# CLI reference

LLMSecTest installs a `llmsectest` console script (equivalently `python -m llmsectest`). It runs the
packaged OWASP probe suite against your chosen target and writes reports.

```bash
llmsectest [--target <spec>] [--report-formats=...] [pytest options]
llmsectest --check | --list-probes | --validate <file.sarif> | --render-sarif <file.sarif>
llmsectest --sbom [<out.json>] --repo <path>
```

## Wrapper commands

| Flag | Description |
|---|---|
| `--target <spec>` | What to test: `app:<url>`, `ollama:<model>`, `lmstudio:<model>`, `openai:<model>`, `anthropic:<model>`, `huggingface:<model>`, `mock`, `demo`, `demo-defended`. Omit it to scan the offline demo app. |
| `--repo <path>` | Add the white-box **LLM03 (supply chain)** scan of that project's dependency manifests (`requirements*.txt`, `pyproject.toml`, `Pipfile`). Combine with `--target` to test an app and its dependencies in one run. |
| `--osv` | With `--repo`: also query [OSV.dev](https://osv.dev) for **known CVEs** in every exactly-pinned (`==X.Y.Z`) dependency (networked, free, no API key). Off by default so the scan stays offline/deterministic; any non-run state (not requested, nothing pinned, lookup failed) appears as an explicit skip reason. |
| `--sbom [<out.json>]` | With `--repo`: write a **CycloneDX 1.6 JSON SBOM** of the project's declared dependencies (one PURL-identified component each) and exit. An exact pin (`==X.Y.Z`) is carried into the component `version` + a fully-qualified PURL (`pkg:pypi/name@version`); a range/unpinned dependency is left version-less with its raw constraint recorded as a property — so the SBOM is only ever as precise as the manifests allow, never asserting a version a manifest did not pin. Built dependency-free from the stdlib. Writes `results/<repo>.cdx.json` unless a path is given. |
| `--model-scan <path>` | Add the white-box **LLM04 (data and model poisoning)** scan of the serialized model files under that path. Walks each pickle's opcode stream (stdlib `pickletools`, never unpickling) and flags imports of code-execution primitives (`os.system`, `subprocess`, `builtins.eval`, nested `pickle`/`torch.load`, reflection gadgets) that would run on load — across raw pickles, PyTorch `.pt`/`.pth`/`.ckpt` zips and numpy object arrays. Offline and deterministic; a clean weights file does not false-positive. |
| `--redteam-set <csv>` | Run the **LLM01 red-team** module against the JailbreakBench [JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) CSV at this path (the 100-behaviour benchmark; columns `Index,Goal,Target,Behavior,Category,Source`). A target is a finding when it **complies** with a harmful request instead of refusing (refusal oracle). Without the flag, a built-in starter set runs so an offline scan still exercises the oracle. |
| `--redteam-benign [<csv>]` | Measure **over-refusal**: run the JBB **benign twins** (harmless requests matched to the harmful behaviours) through the over-refusal oracle and report the target's **false-refusal rate**. Bare uses a built-in benign set; pass JBB's `benign-behaviors.csv` for the full 100. A usability metric — over-refusing is a quality defect, not a vulnerability — so it is reported separately and never enters the SARIF findings or the exit code. |
| `--app-prompt <text-or-file>` | With `--target app:<url>`: the app's **own system prompt** (inline text, or a path to a file holding it) — unlocks **LLM07** leakage detection, since we then know what a leaked instruction looks like. |
| `--app-secret <value>` | With `--target app:<url>`: a **real secret/canary the app holds** — unlocks **LLM02**; a disclosure is then unambiguous (no FP-prone heuristics). |
| `--app-action <signature>` | With `--target app:<url>`: a **privileged tool/action signature** of the app (e.g. `"ACTION: refund("`). Repeatable — unlocks **LLM06**; an unauthorized invocation is then unambiguous. |
| `--app-canary <value>` | With `--target app:<url>`: **confidential content planted in the app's RAG / retrieved corpus** (a unique token in an indexed document) — unlocks the **LLM08** retrieval-exposure probes (corpus enumeration, retrieval-scope escalation, topic-targeted retrieval). A reply that reproduces the canary means the retrieval layer leaked confidential indexed content. Distinct from `--app-secret` (LLM02), where the secret lives in the *prompt/config*; here it lives in the *retrieved corpus*. |
| `--app-rag-poison <marker>` | With `--target app:<url>`: the **marker a poisoned document planted in the app's retrieved corpus instructs the model to emit** — unlocks the **LLM08** indirect-injection probes (kb-directive, follow-retrieved, apply-policy). Each is a benign query that never names the marker; if the app retrieves the poisoned doc and emits it, the app obeyed an injected instruction from retrieved content. Categorized LLM08 (not LLM01) because the injection vector is the retrieval layer — the LLM08↔LLM01 bridge. |
| `--check` | Print the OWASP LLM Top 10 coverage map, each category's test modality and its CVSS v4.0 base score, then exit. |
| `--list-probes` | List the probe corpus that ships today (incl. the built-in red-team set), then exit. |
| `--validate <file>` | Validate an existing SARIF file against the v2.1.0 schema, then exit. |
| `--render-sarif <file>` | Render a SARIF v2.1.0 file (ours or any other tool's) as a **standalone HTML report** and exit. Writes `<file>.html` next to it, or pass `-o`/`--html-output <path>`. Findings are grouped by OWASP category, CVSS-scored and colour-coded by severity, each with its location, evidence and remediation, plus a rule-reference glossary — no server or assets, just open the file. |
| `--preflight` | Health-check `--target` and exit. For a local OpenAI-compatible runtime (`ollama:` / `lmstudio:`) it hits the server's `GET /v1/models` (no key, no paid call) to confirm the server is **reachable** and the requested **model is loaded** — failing fast (exit 1) with a clear message instead of an opaque SDK error deep inside the first probe. A provider with no cheap health endpoint reports that and exits 0. Run it before a long local scan. |
| `--version` | Print the installed llmsectest version, then exit. |

## Reporting options (pytest plugin)

| Flag | Description |
|---|---|
| `--report-formats=sarif,html,json,markdown` | Which report formats to emit (default: sarif). |
| `--report-dir=<dir>` | Where to write reports (default: `results/`). |
| `--sarif-output=<path>` | Explicit SARIF path (otherwise `results/<target-slug>.sarif`). |

## Gating, baselines and policy

| Flag | Description |
|---|---|
| `--risk-threshold=<level>` | Fail only at/above a severity (e.g. `high`). |
| `--min-coverage=<n>` | Require at least *n* OWASP categories exercised. |
| `--save-baseline` / `--update-baseline` | Record current findings as an accepted baseline. |
| `--compare-baseline` | Fail only on findings **new** since the baseline. |
| `--enable-policy` / `--security-policy=<file>` | Enforce a YAML security policy. |
| `--enable-trends` / `--disable-trends` | Track findings over time. |

Any other `pytest` option (e.g. `-k`, `-v`, `-x`) is passed straight through.

## Coverage footer (no silent gaps)

All ten OWASP categories run on every invocation: the implemented ones execute real probes, and the
not-yet-implemented ones are reported as **skipped tests** that say `not yet implemented` (skip reasons
print by default). A run also ends with a footer listing **all ten** categories — which this run
exercised and which it did not, with the reason — so a category is never silently left untested. A model/demo target
exercises the implemented probe categories (LLM01/02/05/06/07/10); adding `--repo <path>` runs the white-box
**LLM03 (supply chain)** scan as well. LLM01 also runs a **red-team jailbreak** set (built-in starter set,
or the full JailbreakBench corpus with `--redteam-set <csv>`); the footer prints the LLM01 depth so the
red-team coverage is never a silent gap. Adding `--redteam-benign` prints, *below* the security report, the
target's **over-refusal (false-refusal) rate** over the benign twins — a usability metric kept out of the
findings and the exit code. A real app endpoint (`--target app:<url>`) is
black-box: LLM01, LLM05, LLM09 and LLM10 (a bounded repetition-flood probe) always run, and
**LLM07/LLM02/LLM06/LLM08 join them when you pass
`--app-prompt` / `--app-secret` / `--app-action` / `--app-canary` / `--app-rag-poison`** — each category
whose input is missing is reported as skipped with the flag that would enable it (LLM04 is white-box and
not yet implemented). LLM08 has two enabling markers: `--app-canary` (retrieval exposure) and
`--app-rag-poison` (indirect injection via a poisoned retrieved document). `llmsectest --check` prints the
same map with each category's CVSS score.

## Exit code

Non-zero when the target is vulnerable (findings present) — so the command fails your pipeline. Use
`--risk-threshold` or `--compare-baseline` to control exactly what fails.

## Examples

```bash
llmsectest --target app:http://localhost:8000/chat
llmsectest --target app:http://localhost:8000/chat --repo .   # app + its dependencies (LLM03)
llmsectest --target app:http://localhost:8000/chat \
    --app-prompt prompt.txt --app-secret "sk-canary" \
    --app-action "ACTION: refund(" --app-action "ACTION: delete_user(" \
    --app-canary "INTERNAL-DOC-CANARY-7f2a" \
    --app-rag-poison "RAG-POISON-3b9d"                                  # + LLM07/02/06/08
llmsectest --repo .                                            # supply-chain scan only
llmsectest --repo . --osv                                      # + known-CVE lookup (OSV.dev)
llmsectest --sbom --repo .                                     # CycloneDX SBOM of the deps (LLM03)
llmsectest --redteam-set jbb/harmful-behaviors.csv --target ollama:llama3  # 100 JailbreakBench prompts
llmsectest --redteam-benign --target ollama:llama3            # over-refusal (false-refusal) rate
llmsectest --target ollama:gemma4:e2b-it-q4_K_M --report-formats=sarif,html
llmsectest --target app:http://localhost:8000/chat --compare-baseline --risk-threshold=high
llmsectest --check
```
