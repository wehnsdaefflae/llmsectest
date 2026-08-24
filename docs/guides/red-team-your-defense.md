# Red-team your defense

Most of this documentation is about finding out that something is broken. This page is about the
other direction: you have built a defense (a prompt-injection filter, a spotlighting layer in front of
your RAG context, an output guard) and you want to know whether it does anything.

Nothing new is needed to do that. Point `--target` at the **defended** endpoint and every probe becomes
a test of the defense: a finding means an attack got through it.

```bash
llmsectest --target app:http://localhost:8000/chat \
    --app-secret "sk-canary-123" \
    --app-canary "INTERNAL-DOC-CANARY-7f2a" \
    --app-rag-poison "RAG-POISON-3b9d"
```

## An empty report is not an answer

The catch used to be that a clean scan and a scan that attacked nothing produced the same report: no
findings, nothing else to read. So every run reports what was **delivered** and how much of it held.

```
  Attacks Delivered:
    Total:     21
    Withstood: 21
    Findings:  0
```

The same figures ride along in the SARIF as a run-level `attacks_withstood` property, broken down by
OWASP category. The rendered HTML page leads with them. Three rules make the number worth
trusting:

- **Only delivered attacks count.** Coverage assertions and the static scanners (LLM03, LLM04) are not
  attacks and never inflate the total, so it stays smaller than the test count and means something
  different.
- **An unanswered attack counts as neither.** A probe that exhausted `--app-timeout` is reported
  *inconclusive*, in its own column. A target that stops answering must never look like a target that
  resisted.
- **No probes delivered, no claim made.** A pure `--repo` supply-chain scan omits the property rather
  than reporting zero of zero.

## Use it as a regression test

The number is most useful over time. Wire the scan into CI (see [CI/CD
integration](ci.md)) and compare runs: `21 withstood` becoming `17 withstood` says a defense
regressed. It says so even when the finding count stayed inside whatever variance you tolerate
from a sampled model. That comparison is the reason the tally is per category: a defense usually
protects one surface. You want to see *that* surface, not a total.

## What "withstood" does and does not mean

It means: these attacks, against this deployment, on this run. It's evidence that a defense is doing work. It's no proof of immunity. A model's output is sampled, so a defense that holds 21 of 21 today may
leak once tomorrow; run it repeatedly and treat a single breach as real. And LLMSecTest attacks the
surface it can reach, so a defense that holds against these probes has not been proven against an
adversary who writes new ones.

Two habits make the evidence stronger:

- **Keep an undefended twin.** Run the same corpus and prompts with the defense off. If both report
  zero findings, the probes are not reaching the surface you think they are, and the defended result
  means nothing yet.
- **Watch for a defense that works by being useless.** An app that refuses everything withstands
  everything. `--redteam-benign` measures the opposite failure (refusals of harmless requests) and
  reports a false-refusal rate that we keep out of the findings and the exit code.

For a worked example of this on RAG indirect injection, including a defense that measurably fails,
see [LLM08, Vector and Embedding Weaknesses](../owasp/llm08.md).
