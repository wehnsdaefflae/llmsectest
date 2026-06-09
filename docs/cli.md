# CLI reference

LLMSecTest installs a `llmsectest` console script (equivalently `python -m llmsectest`). It runs the
packaged OWASP probe suite against your chosen target and writes reports.

```bash
llmsectest [--target <spec>] [--report-formats=...] [pytest options]
llmsectest --check | --list-probes | --validate <file.sarif>
```

## Wrapper commands

| Flag | Description |
|---|---|
| `--target <spec>` | What to test: `app:<url>`, `ollama:<model>`, `openai:<model>`, `anthropic:<model>`, `huggingface:<model>`, `mock`, `demo`, `demo-defended`. Omit it to scan the offline demo app. |
| `--check` | Print the OWASP LLM Top 10 coverage map, each category's test modality and its CVSS v4.0 base score, then exit. |
| `--list-probes` | List the red-team corpus that ships today, then exit. |
| `--validate <file>` | Validate an existing SARIF file against the v2.1.0 schema, then exit. |

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

## Exit code

Non-zero when the target is vulnerable (findings present) — so the command fails your pipeline. Use
`--risk-threshold` or `--compare-baseline` to control exactly what fails.

## Examples

```bash
llmsectest --target app:http://localhost:8000/chat
llmsectest --target ollama:gemma4:e2b-it-q4_K_M --report-formats=sarif,html
llmsectest --target app:http://localhost:8000/chat --compare-baseline --risk-threshold=high
llmsectest --check
```
