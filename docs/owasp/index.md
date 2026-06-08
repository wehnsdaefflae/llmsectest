# OWASP LLM Top 10 — coverage map

LLMSecTest maps directly to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/).
The ten risks split into two testing **modalities**, and LLMSecTest is explicit about which applies to
a given target — the live, authoritative map is `llmsectest --check`.

- **Black-box** — testable by sending inputs to your running app (`--target app:<url>`).
- **White-box** — needs your application's internals (dependencies, RAG/vector store, resource limits,
  model/data provenance) and is covered by dedicated modules.

| Category | Modality | Status today |
|---|---|---|
| [LLM01 Prompt Injection](llm01.md) | black-box | ✅ probes |
| LLM02 Sensitive Information Disclosure | black-box / white-box | ✅ probes |
| LLM03 Supply Chain | white-box — requires deps/SBOM | planned (per milestone) |
| LLM04 Data and Model Poisoning | white-box — requires model/data provenance | planned |
| LLM05 Improper Output Handling | black-box / white-box | ✅ probes |
| LLM06 Excessive Agency | black-box / white-box | ✅ probes |
| LLM07 System Prompt Leakage | black-box | ✅ probes |
| LLM08 Vector and Embedding Weaknesses | white-box — requires RAG/vector store | planned |
| LLM09 Misinformation | black-box — output verification | planned |
| LLM10 Unbounded Consumption | white-box — requires rate/resource limits | planned |

!!! warning "No silent gaps"
    A category not yet covered is reported as **planned** with what it needs — never silently skipped.
    LLMSecTest will not claim coverage a target's modality didn't actually exercise. Run
    `llmsectest --check` for the current state.

The white-box categories are sequenced across the project's milestones (supply-chain/SBOM, embedding
weaknesses and stress/consumption tests land together with their fixtures). Each consumes a concrete
input you provide — your `requirements`/lockfile, your vector store, or your rate/resource limits.
