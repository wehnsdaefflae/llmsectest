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
| LLM04 Data and Model Poisoning | white-box — requires model/data provenance | 7.1 High | planned |
| LLM05 Improper Output Handling | black-box / white-box | 9.9 Critical | ✅ probes |
| LLM06 Excessive Agency | black-box / white-box | 10.0 Critical | ✅ probes |
| LLM07 System Prompt Leakage | black-box | 8.7 High | ✅ probes |
| LLM08 Vector and Embedding Weaknesses | white-box — requires RAG/vector store | 7.1 High | planned |
| LLM09 Misinformation | black-box — output verification | 5.3 Medium | planned |
| [LLM10 Unbounded Consumption](llm10.md) | black-box | 8.7 High | ✅ probes |

!!! warning "No silent gaps"
    All ten categories run on every invocation. A category not yet implemented appears as a **skipped
    test reported `not yet implemented`** (with what it needs and when it lands) — never silently absent.
    LLMSecTest will not claim coverage a target's modality didn't actually exercise. Run
    `llmsectest --check` for the current state.

The first white-box category — **LLM03 (supply chain)** — ships now: pass `--repo <path>` to scan the
project's dependency manifests (see the [LLM03 deep-dive](llm03.md)). The remaining white-box categories
are sequenced across the project's milestones (embedding weaknesses and stress/consumption tests land
together with their fixtures). Each consumes a concrete input you provide — your `requirements`/lockfile,
your vector store, or your rate/resource limits.

## Testing a real application (black-box)

When you point LLMSecTest at a running app (`--target app:<url>`, or the `run_app_scan` API on the app's
system prompt), it tests **only what black-box access can actually reach**, and reports the rest — never
a silent pass:

- **LLM01 (prompt injection)**, **LLM05 (improper output handling)** and **LLM10 (unbounded
  consumption)** transfer with no setup: the marker lives in the attack, so the app needs to reveal
  nothing for a finding to be unambiguous.
- **LLM07 (system-prompt leakage)**, **LLM02 (sensitive disclosure)** and **LLM06 (excessive agency)**
  light up once you tell LLMSecTest what a leak looks like — the app's own system prompt, a known secret
  it holds, or its privileged action signatures. Without that, they are reported as *not exercised* with
  the reason, rather than passed vacuously.
- The white-box categories are likewise surfaced as not-exercised — except **LLM03 (supply chain)**,
  which runs from the repo: add `--repo <path>` and it scans the dependency manifests alongside the
  endpoint probes. LLM04/08 and LLM09 (oracle) remain not-exercised until their milestones.

Every scan prints a coverage footer accounting for **all ten** categories, so the report never overstates
what was tested.
