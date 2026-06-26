# LLMSecTest

**Pytest-native security testing for LLM _applications_ — mapped to the [OWASP LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/).**

LLMSecTest tests **applications that use an LLM** (a system prompt, guardrails, RAG, and tools around a
model) — not bare models — for the security risks in the OWASP Top 10 for LLM Applications, and emits
**SARIF / HTML / JSON / Markdown** reports that drop straight into CI/CD.

```bash
pip install llmsectest

# point it at your running app and test it black-box
llmsectest --target app:http://localhost:8000/chat
```

A failing probe is a **finding**, so a non-zero exit fails your pipeline when your app is vulnerable.

## Why

With LLMs in real products, users face new risks: in one study **86% of tested LLM applications were
vulnerable to prompt injection**. Developers in finance and healthcare lack an open, CI-ready way to
check their LLM apps against a recognized standard. LLMSecTest is that — MIT-licensed and fully
open-source, built on `pytest` so it fits the tools developers already use.

## What it tests

The OWASP LLM Top 10 spans two testing modalities. LLMSecTest is honest about which apply to a given
target — run `llmsectest --check` to see the live map.

| | Category | How it's tested |
|---|---|---|
| LLM01 | Prompt Injection | **black-box** — your app endpoint |
| LLM02 | Sensitive Information Disclosure | black-box (or white-box) |
| LLM03 | Supply Chain | white-box — your deps (`--repo`) |
| LLM04 | Data and Model Poisoning | white-box — model/data provenance |
| LLM05 | Improper Output Handling | black-box (or white-box) |
| LLM06 | Excessive Agency | black-box (or white-box) |
| LLM07 | System Prompt Leakage | **black-box** — prompt extraction |
| LLM08 | Vector and Embedding Weaknesses | white-box — your RAG/vector store |
| LLM09 | Misinformation | black-box — output verification |
| LLM10 | Unbounded Consumption | white-box — rate/resource limits |

→ **[Getting started](getting-started.md)** · **[Test your running app](guides/target-app.md)** ·
**[OWASP coverage](owasp/index.md)** · **[API reference](api.md)**

!!! note "Status"
    Pre-alpha (active grant development). Black-box categories **LLM01/02/05/06/07/09/10**, the white-box
    **LLM03 (supply chain)** scan (`--repo`) and the black-box **LLM08 (vector & embedding weaknesses)** RAG
    probes ship today — **9/10**; **LLM04** lands per milestone. Coverage claims here always match what the
    tool actually does — see `llmsectest --check`.
