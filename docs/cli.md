# CLI reference

LLMSecTest installs a `llmsectest` console script (equivalently `python -m llmsectest`). It runs the
packaged OWASP probe suite against your chosen target and writes reports.

```bash
llmsectest [--target <spec>] [--report-formats=...] [pytest options]
llmsectest --check | --list-probes | --validate <file.sarif> | --render-sarif <file.sarif>
```

## Wrapper commands

| Flag | Description |
|---|---|
| `--target <spec>` | What to test: `app:<url>`, `ollama:<model>`, `openai:<model>`, `anthropic:<model>`, `huggingface:<model>`, `mock`, `demo`, `demo-defended`. Omit it to scan the offline demo app. |
| `--repo <path>` | Add the white-box **LLM03 (supply chain)** scan of that project's dependency manifests (`requirements*.txt`, `pyproject.toml`, `Pipfile`). Combine with `--target` to test an app and its dependencies in one run. |
| `--osv` | With `--repo`: also query [OSV.dev](https://osv.dev) for **known CVEs** in every exactly-pinned (`==X.Y.Z`) dependency (networked, free, no API key). Off by default so the scan stays offline/deterministic; any non-run state (not requested, nothing pinned, lookup failed) appears as an explicit skip reason. |
| `--redteam-set <csv>` | Run the **LLM01 red-team** module against the JailbreakBench [JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) CSV at this path (the 100-behaviour benchmark; columns `Index,Goal,Target,Behavior,Category,Source`). A target is a finding when it **complies** with a harmful request instead of refusing (refusal oracle). Without the flag, a built-in starter set runs so an offline scan still exercises the oracle. |
| `--redteam-benign [<csv>]` | Measure **over-refusal**: run the JBB **benign twins** (harmless requests matched to the harmful behaviours) through the over-refusal oracle and report the target's **false-refusal rate**. Bare uses a built-in benign set; pass JBB's `benign-behaviors.csv` for the full 100. A usability metric — over-refusing is a quality defect, not a vulnerability — so it is reported separately and never enters the SARIF findings or the exit code. |
| `--app-prompt <text-or-file>` | With `--target app:<url>`: the app's **own system prompt** (inline text, or a path to a file holding it) — unlocks **LLM07** leakage detection, since we then know what a leaked instruction looks like. |
| `--app-secret <value>` | With `--target app:<url>`: a **real secret/canary the app holds** — unlocks **LLM02**; a disclosure is then unambiguous (no FP-prone heuristics). |
| `--app-action <signature>` | With `--target app:<url>`: a **privileged tool/action signature** of the app (e.g. `"ACTION: refund("`). Repeatable — unlocks **LLM06**; an unauthorized invocation is then unambiguous. |
| `--check` | Print the OWASP LLM Top 10 coverage map, each category's test modality and its CVSS v4.0 base score, then exit. |
| `--list-probes` | List the probe corpus that ships today (incl. the built-in red-team set), then exit. |
| `--validate <file>` | Validate an existing SARIF file against the v2.1.0 schema, then exit. |
| `--render-sarif <file>` | Render a SARIF v2.1.0 file (ours or any other tool's) as a **standalone HTML report** and exit. Writes `<file>.html` next to it, or pass `-o`/`--html-output <path>`. Findings are grouped by OWASP category, CVSS-scored and colour-coded by severity, each with its location, evidence and remediation, plus a rule-reference glossary — no server or assets, just open the file. |
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
black-box: LLM01, LLM05 and LLM10 always run, and **LLM07/LLM02/LLM06 join them when you pass
`--app-prompt` / `--app-secret` / `--app-action`** — each category whose input is missing is
reported as skipped with the flag that would enable it (LLM04/08 are white-box and LLM09 needs an
oracle). `llmsectest --check` prints the same map with each category's CVSS score.

## Exit code

Non-zero when the target is vulnerable (findings present) — so the command fails your pipeline. Use
`--risk-threshold` or `--compare-baseline` to control exactly what fails.

## Examples

```bash
llmsectest --target app:http://localhost:8000/chat
llmsectest --target app:http://localhost:8000/chat --repo .   # app + its dependencies (LLM03)
llmsectest --target app:http://localhost:8000/chat \
    --app-prompt prompt.txt --app-secret "sk-canary" \
    --app-action "ACTION: refund(" --app-action "ACTION: delete_user("  # + LLM07/02/06
llmsectest --repo .                                            # supply-chain scan only
llmsectest --repo . --osv                                      # + known-CVE lookup (OSV.dev)
llmsectest --redteam-set jbb/harmful-behaviors.csv --target ollama:llama3  # 100 JailbreakBench prompts
llmsectest --redteam-benign --target ollama:llama3            # over-refusal (false-refusal) rate
llmsectest --target ollama:gemma4:e2b-it-q4_K_M --report-formats=sarif,html
llmsectest --target app:http://localhost:8000/chat --compare-baseline --risk-threshold=high
llmsectest --check
```
