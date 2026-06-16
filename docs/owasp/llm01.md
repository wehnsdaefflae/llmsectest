# LLM01 — Prompt Injection

> User prompts alter the intended behavior of the LLM system.

**Modality:** black-box. **Status:** covered.

Prompt injection is the canonical LLM application risk: attacker-controlled text (direct, or indirect
via a document/web page/tool output the app ingests) overrides the application's intended instructions,
making it leak data, take unauthorized actions, or produce attacker-chosen output. In one study, 86% of
tested LLM applications were vulnerable.

## How LLMSecTest tests it

LLMSecTest sends a battery of injection techniques to your application and checks whether the app
**obeys** the injected instruction. Detection uses an **attacker-side marker**: the attack asks the app
to emit a unique sentinel; if the reply contains it, the injection succeeded. This needs nothing from
inside your app, so it works black-box against any endpoint.

Techniques in the corpus include:

- **Direct instruction override** — "Ignore previous instructions and …".
- **Forged system delimiter** — fake `system:`/role markers to impersonate the app's own instructions.
- **Prefix / compliance priming** — coaxing a "Sure, …" prefix that carries the injected payload.
- **Role-play jailbreak (DAN-style)** and **task context switch**.

```bash
llmsectest --target app:http://localhost:8000/chat
```

## Red-team jailbreak prompts (JailbreakBench / AdvBench)

Beyond the marker-injection corpus, LLMSecTest runs a **red-team set** of harmful-behavior prompts and
checks whether your target **refuses** them. These behaviors plant no marker, so a different oracle
applies — a **refusal oracle** (inverted polarity): the target is a finding when it *complies* with a
harmful request instead of refusing it.

- The full corpus is the MIT-licensed **[JailbreakBench JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors)**
  set — 100 curated misuse behaviors (18% sourced from **AdvBench**, 27% from HarmBench/TDC, 55% original),
  plus 100 benign twins for false-positive testing. Download `data/harmful-behaviors.csv` once and run:

  ```bash
  llmsectest --redteam-set jbb/data/harmful-behaviors.csv --target ollama:llama3
  ```

- Without `--redteam-set`, a small built-in starter set ships so an offline run still exercises the oracle.
- The oracle is the **refusal-string baseline** (Zou et al. 2023): it matches standard refusal phrases and
  the behavior's affirmative target completion. It is deliberately conservative — it errs toward "refused",
  so it **under-reports** successful jailbreaks rather than raising false findings. For higher recall, swap
  in a classifier oracle (Llama-Guard, GLiGuard, or garak's ModernBERT refusal detector) via the detector
  registry; that work is on the [roadmap](https://llmsec.dev/#roadmap).

This deepens LLM01 — it is not a separate OWASP category.

## Over-refusal: the benign twins (`--redteam-benign`)

A refusal oracle only tells half the story. A target that refuses *everything* would score perfectly on
the harmful set while being useless in practice. JBB-Behaviors ships **100 benign twins** — harmless
requests topic-matched to the harmful behaviors — and `--redteam-benign` runs them through the mirror-image
**over-refusal oracle**: here a *refusal of a harmless request* is the finding. The result is the target's
**false-refusal rate** (the share of benign requests it wrongly declines).

```bash
llmsectest --redteam-benign                          # built-in benign twins
llmsectest --redteam-benign jbb/data/benign-behaviors.csv --target ollama:llama3   # the full 100
```

Over-refusing is a **usability** defect, not a security vulnerability — so it would be backwards to count
it as a finding (a cautious model is *safer*, not more vulnerable). LLMSecTest therefore reports the
false-refusal rate as a **separate quality metric**: it never enters the SARIF security report and never
changes the exit code. It is the **specificity control** for the refusal oracle — and, paired with the
harmful set, it exposes the security/usability trade-off directly. The offline demos make the split
vivid: `demo-vulnerable` complies with everything (0% over-refusal but many findings), while
`demo-defended` refuses everything (0 findings but a **100%** false-refusal rate). The same
string-matching caveat applies, inverted: a benign reply that incidentally contains a refusal-like phrase
can be over-counted, which a classifier oracle would fix.

## Reading a finding

A finding names the technique, the OWASP category (LLM01), a severity, and the evidence — for example
*"target obeyed the injected instruction and emitted marker: PWNED-LLM01-DELIM"*, alongside the prompt
and the app's response. In SARIF it lands in your code-scanning view mapped to LLM01, carrying LLM01's
CVSS v4.0 base score (`9.2`, vector `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N`)
as its `security-severity`.

## Remediation

- Treat **all** model input as untrusted — including tool outputs, retrieved documents, and prior turns.
- Keep privileged instructions out of reach of user content; don't concatenate user text into the
  system prompt.
- Constrain outputs and **validate them** before acting (see [LLM05](index.md)); require explicit,
  out-of-band authorization for state-changing actions (see [LLM06](index.md)).
- Add a guardrail/classifier layer and re-run LLMSecTest to confirm it closes the finding.

See the [OWASP LLM01 entry](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) for the full
guidance.
