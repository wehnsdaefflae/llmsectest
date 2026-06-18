# Getting started

## Install

```bash
pip install llmsectest
```

LLMSecTest is a `pytest` plugin and a CLI. The core install is dependency-light (just `pytest`);
provider SDKs are optional extras you install only if you target them:

```bash
pip install "llmsectest[openai]"   # also: [anthropic], [huggingface], or [all]
```

A local model needs no extra and no API key — see [Test your running app](guides/target-app.md).

## Your first run (zero config)

With no target, LLMSecTest runs against a built-in **offline demo app** so you get a real report
immediately — no keys, no network:

```bash
llmsectest                 # scans the offline "vulnerable" demo app → shows findings
llmsectest --target demo-defended   # the hardened demo app → passes cleanly
```

This writes a SARIF report under `results/` and prints a summary. Because findings are pytest
failures, the process exits non-zero when the target is vulnerable — exactly what you want in CI.

## Targets

A **target** is what you point LLMSecTest at. Choose one with `--target`:

| Target | What it is |
|---|---|
| `app:<url>` | **Your running application's HTTP endpoint** — the faithful way to test an app (its own system prompt, guardrails, RAG and tools are in the loop). See [the guide](guides/target-app.md). |
| `ollama:<model>` | A **local** model via [Ollama](https://ollama.com) — no API key, no paid calls (e.g. `ollama:gemma4:e2b-it-q4_K_M`). |
| `lmstudio:<model>` | A **local** model via [LM Studio](https://lmstudio.ai)'s OpenAI-compatible server (default `localhost:1234`) — no API key, no paid calls. Set `LMSTUDIO_BASE_URL` to override the port. |
| `openai:<model>` / `anthropic:<model>` / `huggingface:<model>` | A hosted model (needs the matching extra + API key in the environment). |
| `demo` / `demo-defended` | Offline deterministic demo apps (no network). |

## See what's covered

```bash
llmsectest --check          # the OWASP coverage map + each category's test modality
llmsectest --list-probes    # the red-team corpus that ships today
```

`--check` is the source of truth for coverage — it shows which categories are black-box (testable
against your endpoint now) and which are white-box (need app internals and land per milestone).

## Next

- **[Test your running app](guides/target-app.md)** — the real workflow.
- **[Author your own tests](guides/authoring.md)** — write app-specific probes in plain pytest.
- **[CI/CD integration](guides/ci.md)** — wire SARIF into GitHub code-scanning.
