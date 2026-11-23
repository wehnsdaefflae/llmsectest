# OWASP LLM Top 10, coverage map

LLMSecTest maps directly to the [OWASP Top 10 for LLM Applications
(2026)](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), published 2026-08-03. The
numbering below is the 2026 edition's. Eight of the ten categories carry a different number than
they did in 2025 and one is renamed, so a report or an advisory of ours dated before 2026-10-20
uses the 2025 numbers. Every row below carries both numbers. Every finding a scan writes now names
the edition it was scored under.

!!! note "Why the page filenames still read `llm07.md`"
    The renumbering is a permutation: System Prompt Leakage moves 07 → 08 while Vector and
    Embedding Weaknesses moves 08 → 09. Renaming the deep-dive pages to match would break every
    link already published against them and would collide mid-rename. Each page states its own
    2026 id and its 2025 id. Treat a file path here as a permanent address for the page.
The ten risks split into two testing **modalities** and LLMSecTest is explicit about which applies to
a given target, the live, authoritative map is `llmsectest --check`.

- **Black-box**, testable by sending inputs to your running app (`--target app:<url>`).
- **White-box**, needs your application's internals (dependencies, RAG/vector store, resource limits,
  model/data provenance) and is covered by dedicated modules.

Each category also carries a representative **CVSS v4.0 base score** (worst-case for the class),
reported as the SARIF `security-severity` of its findings.

All ten categories ship a probe or scanner and **all ten now have a deep-dive page**, linked from the
table below. Each page says what the category's probes send, what its oracle matches, and, the
part a coverage table cannot carry, what a clean result does *not* tell you.

| Category (2026) | Was (2025) | Modality | CVSS v4.0 | Status today |
|---|---|---|---|---|
| [LLM01 Prompt Injection](llm01.md) | LLM01 | black-box | 9.2 Critical | ✅ probes |
| [LLM02 Sensitive Information Disclosure](llm02.md) | LLM02 | black-box / white-box | 9.2 Critical | ✅ probes |
| [LLM03 Excessive Agency](llm06.md) | LLM06 | black-box / white-box | 10.0 Critical | ✅ probes |
| [LLM04 Supply Chain](llm03.md) | LLM03 | white-box, requires `--repo` | 9.5 Critical | ✅ scan |
| [LLM05 Data and Model Poisoning](llm04.md) | LLM04 | white-box, requires `--model-scan` | 7.1 High | ✅ scan |
| [LLM06 Unbounded Consumption](llm10.md) | LLM10 | black-box | 8.7 High | ✅ probes |
| [LLM07 Misinformation](llm09.md) | LLM09 | black-box | 5.3 Medium | ✅ probes |
| [LLM08 Hidden Context Exposure](llm07.md) | LLM07 System Prompt Leakage | black-box; retrieved policy text and tool schemas require `--app-policy` and/or `--app-tool-schema` | 8.7 High | ✅ probes |
| [LLM09 Vector and Embedding Weaknesses](llm08.md) | LLM08 | black-box, requires `--app-canary` and/or `--app-rag-poison` (RAG); white-box, requires `--vector-store` | 7.1 High | ✅ probes + scan |
| [LLM10 Improper Output Handling](llm05.md) | LLM05 | black-box / white-box | 9.9 Critical | ✅ probes |

!!! warning "LLM08 Hidden Context Exposure needs two inputs from you"
    2025 scoped this risk to the system prompt and our probes ask the target to restate its
    instructions. 2026 scopes it to hidden context of any kind: the system prompt, developer
    instructions, retrieved policy text from a RAG store or a configuration service, and the
    schemas of the tools the application exposes to the model. We probe all of those. The last two
    need you to declare the private excerpt with `--app-policy` and `--app-tool-schema`, because
    only you know what your application holds privately. We never put that excerpt in the request,
    so a hit is your application producing it unprompted. A run without those two flags covers the
    system-prompt part alone. The report says on the row which kinds it probed.

!!! warning "No silent gaps"
    All ten categories run on every invocation. Each ships a real probe or scanner; a category that
    needs an input it wasn't given (a repo, a model path, an app marker) appears as a **skipped test that
    says exactly what it needs**, never silently absent. LLMSecTest will not claim coverage a target's
    modality didn't exercise. Run `llmsectest --check` for the current state.

LLMSecTest ships a probe or a scanner for all ten categories of the OWASP LLM Top 10 (2026),
**10/10**, with the LLM08 scope limit stated above. The two
white-box categories run from a path you provide: **LLM04 (supply chain)** scans the project's dependency
manifests with `--repo <path>` (see the [supply-chain deep-dive](llm03.md)); **LLM05 (data and model poisoning)**
scans the project's serialized model files with `--model-scan <path>`, flagging load-time code-execution
in pickle/PyTorch artifacts (see the [poisoning deep-dive](llm04.md)). **LLM09 (vector & embedding weaknesses)**
ships three dimensions for RAG apps: retrieval exposure and indirect injection via a poisoned
retrieved document, both black-box, plus the white-box embedding-inversion-exposure scan of a persisted
store with `--vector-store <path>` (see the [vector-store deep-dive](llm08.md)); **LLM07 (misinformation)** ships
black-box confabulation probes (see the [misinformation deep-dive](llm09.md)). What remains is *depth*: embedding
poisoning, inversion itself, plus a classifier refusal oracle. **Multi-tenant isolation ships as of
2026-09-29**, white-box off the persisted store.

## Testing a real application (black-box)

When you point LLMSecTest at a running app (`--target app:<url>`, or the `run_app_scan` API on the app's
system prompt), it tests **only what black-box access can reach**. It reports the rest, never
as a silent pass:

!!! note "The two entry points reach the same ten categories at different depth"
    With every developer input supplied, the `run_app_scan` API sends **23 cases**, of which LLM01 is
    **one** injection technique and LLM07 is **one** confabulation probe. The CLI runs the packaged
    pytest suite, where LLM01 arrives as the **five** authored injection techniques plus the **eight**
    built-in red-team behaviours and LLM07 as **four** confabulation probes, for **38** delivered
    attacks. Both paths print the same 10-category coverage map, so an exercised LLM01 or LLM07 row
    from the API path means the category was asked once. `AppScanResult.outcomes` carries the exact
    set a given run sent.

- **LLM01 (prompt injection)**, **LLM10 (improper output handling)**, **LLM07 (misinformation)** and
  **LLM06 (unbounded consumption)** transfer with no setup: the attack-side marker (or, for misinformation, a
  guaranteed-nonexistent entity) lives in the attack, so the app needs to reveal nothing for a finding to
  be unambiguous. (LLM06 uses a *bounded* repetition-flood probe against an app, an explicit finite repeat
  count, above the flood threshold yet a short reply. So a flooding app is flagged without the unbounded
  model-mode prompts ever risking a runaway generation against an uncapped endpoint.)
- **LLM08 (hidden context exposure)**, **LLM02 (sensitive disclosure)**, **LLM03 (excessive agency)** and
  **LLM09 (vector & embedding weaknesses)** light up once you tell LLMSecTest what a leak looks like, the
  app's own system prompt, a known secret it holds, its privileged action signatures, or (for a RAG app)
  a confidential canary planted in its retrieved corpus (`--app-canary`) and/or the marker a poisoned
  retrieved document emits (`--app-rag-poison`). Without that, they are reported as *not exercised* with
  the reason, rather than passed vacuously.
- The white-box categories are likewise surfaced as not-exercised against an endpoint unless you supply
  their artifact path: **LLM04 (supply chain)** runs from the repo (add `--repo <path>` to scan the
  dependency manifests alongside the endpoint probes) and **LLM05 (data and model poisoning)** runs from
  the model files (add `--model-scan <path>`). **LLM09** runs from the persisted store with
  `--vector-store <path>`, which measures how much of the corpus a reader of the store recovers with no
  inversion, alongside its two black-box dimensions, retrieval exposure and indirect injection via a
  poisoned retrieved document (see the [vector-store deep-dive](llm08.md)). The same `--vector-store` pass also
  reports **multi-tenant namespace isolation**, where the store's own per-vector metadata shows several
  tenants sharing one store, and **embedding-store poisoning**, where an indexed chunk carries an
  instruction addressed to the model rather than content. Running an inversion itself remains
  not-exercised, because that needs a trained inverter per embedding space.

Every scan prints a coverage footer accounting for **all ten** categories, so the report never overstates
what was tested.
