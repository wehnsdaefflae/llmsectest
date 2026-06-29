# OWASP LLM Top 10 — coverage map

LLMSecTest maps directly to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/).
The ten risks split into two testing **modalities**, and LLMSecTest is explicit about which applies to
a given target — the live, authoritative map is `llmsectest --check`.

- **Black-box** — testable by sending inputs to your running app (`--target app:<url>`).
- **White-box** — needs your application's internals (dependencies, RAG/vector store, resource limits,
  model/data provenance) and is covered by dedicated modules.

Each category also carries a representative **CVSS v4.0 base score** (worst-case for the class),
reported as the SARIF `security-severity` of its findings.

| Category | Modality | CVSS v4.0 | Status today |
|---|---|---|---|
| [LLM01 Prompt Injection](llm01.md) | black-box | 9.2 Critical | ✅ probes |
| LLM02 Sensitive Information Disclosure | black-box / white-box | 9.2 Critical | ✅ probes |
| [LLM03 Supply Chain](llm03.md) | white-box — requires `--repo` | 9.5 Critical | ✅ scan |
| [LLM04 Data and Model Poisoning](llm04.md) | white-box — requires `--model-scan` | 7.1 High | ✅ scan |
| LLM05 Improper Output Handling | black-box / white-box | 9.9 Critical | ✅ probes |
| LLM06 Excessive Agency | black-box / white-box | 10.0 Critical | ✅ probes |
| LLM07 System Prompt Leakage | black-box | 8.7 High | ✅ probes |
| [LLM08 Vector and Embedding Weaknesses](llm08.md) | black-box — requires `--app-canary` and/or `--app-rag-poison` (RAG) | 7.1 High | ✅ probes |
| [LLM09 Misinformation](llm09.md) | black-box | 5.3 Medium | ✅ probes |
| [LLM10 Unbounded Consumption](llm10.md) | black-box | 8.7 High | ✅ probes |

!!! warning "No silent gaps"
    All ten categories run on every invocation. Each ships a real probe or scanner; a category that
    needs an input it wasn't given (a repo, a model path, an app marker) appears as a **skipped test that
    says exactly what it needs** — never silently absent. LLMSecTest will not claim coverage a target's
    modality didn't actually exercise. Run `llmsectest --check` for the current state.

With **LLM04**, LLMSecTest now covers the **complete** OWASP LLM Top 10 (2025) — **10/10**. The two
white-box categories run from a path you provide: **LLM03 (supply chain)** scans the project's dependency
manifests with `--repo <path>` (see the [LLM03 deep-dive](llm03.md)); **LLM04 (data and model poisoning)**
scans the project's serialized model files with `--model-scan <path>`, flagging load-time code-execution
in pickle/PyTorch artifacts (see the [LLM04 deep-dive](llm04.md)). **LLM08 (vector & embedding weaknesses)**
ships two black-box dimensions — retrieval exposure and indirect injection via a poisoned retrieved
document, for RAG apps (see the [LLM08 deep-dive](llm08.md)); **LLM09 (misinformation)** ships black-box
confabulation probes (see the [LLM09 deep-dive](llm09.md)). What remains is *depth* — LLM08's white-box
dimensions and a classifier refusal oracle — not breadth.

## Testing a real application (black-box)

When you point LLMSecTest at a running app (`--target app:<url>`, or the `run_app_scan` API on the app's
system prompt), it tests **only what black-box access can actually reach**, and reports the rest — never
a silent pass:

- **LLM01 (prompt injection)**, **LLM05 (improper output handling)** and **LLM09 (misinformation)**
  transfer with no setup: the attack-side marker (or, for LLM09, a guaranteed-nonexistent entity) lives in
  the attack, so the app needs to reveal nothing for a finding to be unambiguous. (LLM10 is exercised
  against a *model* target but reported not-exercised against an *app* endpoint until a bounded black-box
  probe lands — an uncapped app would generate to its context limit on the unbounded prompts.)
- **LLM07 (system-prompt leakage)**, **LLM02 (sensitive disclosure)**, **LLM06 (excessive agency)** and
  **LLM08 (vector & embedding weaknesses)** light up once you tell LLMSecTest what a leak looks like — the
  app's own system prompt, a known secret it holds, its privileged action signatures, or (for a RAG app)
  a confidential canary planted in its retrieved corpus (`--app-canary`) and/or the marker a poisoned
  retrieved document emits (`--app-rag-poison`). Without that, they are reported as *not exercised* with
  the reason, rather than passed vacuously.
- The white-box categories are likewise surfaced as not-exercised against an endpoint unless you supply
  their artifact path: **LLM03 (supply chain)** runs from the repo (add `--repo <path>` to scan the
  dependency manifests alongside the endpoint probes), and **LLM04 (data and model poisoning)** runs from
  the model files (add `--model-scan <path>`). LLM08's *white-box* dimensions (embedding poisoning,
  multi-tenant isolation, inversion) remain not-exercised — its two
  black-box dimensions (retrieval exposure + indirect injection via a poisoned retrieved document) ship
  now (see the [LLM08 deep-dive](llm08.md)).

Every scan prints a coverage footer accounting for **all ten** categories, so the report never overstates
what was tested.
