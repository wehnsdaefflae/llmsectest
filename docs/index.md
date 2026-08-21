# LLMSecTest

**Pytest-native security testing for LLM _applications_, mapped to the [OWASP LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/).**

LLMSecTest tests **applications that use an LLM** (a system prompt, guardrails, RAG, and tools around a model) rather than bare models, for the security risks in the OWASP Top 10 for LLM Applications, and emits
**SARIF / HTML / JSON / Markdown** reports that drop straight into CI/CD.

```bash
pip install llmsectest

# point it at your running app and test it black-box
llmsectest --target app:http://localhost:8000/chat
```

A failing probe is a **finding**, so a non-zero exit fails your pipeline when your app is vulnerable.

## Why

With LLMs in real products, users face new risks, prompt injection, sensitive-data disclosure and
unsafe output handling are common, well-documented failure modes. Developers in finance and healthcare lack an open, CI-ready way to
check their LLM apps against a recognized standard. LLMSecTest is that, MIT-licensed and fully
open-source, built on `pytest` so it fits the tools developers already use.

## What it tests

The OWASP LLM Top 10 spans two testing modalities. LLMSecTest is honest about which apply to a given
target, run `llmsectest --check` to see the live map.

| | Category | How it's tested |
|---|---|---|
| LLM01 | Prompt Injection | **black-box**, your app endpoint |
| LLM02 | Sensitive Information Disclosure | black-box (or white-box) |
| LLM03 | Supply Chain | white-box, your deps (`--repo`) |
| LLM04 | Data and Model Poisoning | white-box, your model files (`--model-scan`) |
| LLM05 | Improper Output Handling | black-box (or white-box) |
| LLM06 | Excessive Agency | black-box (or white-box) |
| LLM07 | System Prompt Leakage | **black-box**, prompt extraction |
| LLM08 | Vector and Embedding Weaknesses | **black-box**, your RAG app (`--app-canary` / `--app-rag-poison`) |
| LLM09 | Misinformation | **black-box**, nonexistent-entity confabulation |
| LLM10 | Unbounded Consumption | **black-box**, flood / output amplification |

→ **[Getting started](getting-started.md)** · **[Test your running app](guides/target-app.md)** ·
**[Red-team your defense](guides/red-team-your-defense.md)** · **[OWASP coverage](owasp/index.md)** ·
**[API reference](api.md)**

!!! note "Status"
    Pre-alpha (active grant development). All **10/10** OWASP LLM Top 10 (2025) categories ship today:
    black-box probes for **LLM01/02/05/06/07/09/10**, white-box scanners for **LLM03 (supply chain)**
    (`--repo`) and **LLM04 (data and model poisoning)** (`--model-scan`), and black-box **LLM08 (vector &
    embedding weaknesses)** RAG probes. What remains is depth, not breadth. Coverage claims here always
    match what the tool does, see `llmsectest --check`.

!!! warning "Which edition, and why not the newer one"
    A **2026** edition of the list came out on 3 August 2026. This tool implements **2025** and says so
    on every surface. Read side by side, the two lists hold the same ten risks: nothing was added,
    dropped, merged or split. Eight categories change number, and LLM07 System Prompt Leakage becomes
    LLM08 Hidden Context Exposure with a wider remit that now covers retrieved policy text and tool
    schemas. Every report and baseline published here carries 2025 numbers, so a silent renumber would
    change what already-published records mean, and OWASP's own per-category pages still carry 2025.
    Both change before this does.

## Funding

LLMSecTest is funded by the **German Federal Ministry of Research, Technology and Space (BMFTR)**
through the **[Prototype Fund](https://prototypefund.de)**, funding code (Förderkennzeichen)
**16IS26S10**. The funding guideline is implemented by the Open Knowledge Foundation Deutschland; the
project agency is VDI/VDE-IT.

<p class="fund-logos">
  <img src="assets/bmftr-funded-by-en.png" class="logo-bmftr"
       alt="With funding from the Federal Ministry of Research, Technology and Space (BMFTR)">
  <img src="assets/prototype-fund-en.png" class="logo-ptf"
       alt="Supported by the Prototype Fund">
</p>
