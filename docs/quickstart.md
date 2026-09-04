# Quickstart

You have an HTTP chat endpoint with an LLM behind it. You want to know what gets through. This page
goes from nothing to a rendered report in about a minute, then tells you what the report does not
cover.

## One command

```bash
pip install llmsectest
llmsectest --target app:http://localhost:8000/chat
```

That is the setup. The scan POSTs `{"message": "<attacker input>"}` to your endpoint and pulls the
reply out of a top-level `reply` / `response` / `content` / `answer` field or out of the OpenAI-shaped
`choices[0].message.content`. If your application speaks a different shape, two lines configure it:
see [request and response shapes](guides/target-app.md#request-and-response-shapes).

There is no API key to set, because the model under test is the one your application already talks
to. Nothing leaves your machine except the requests to your own endpoint.

## What comes back

Here is a real run against a weak endpoint written for this page, a support assistant with a
credential in its system prompt that repeats its own instructions when asked nicely.

```text
  [!!] Security Status: CRITICAL

  Attacks Delivered:
    Total:     23
    Withstood: 15
    Findings:  8

  Severity Distribution:
    Critical       3 (1 failed)
    High          17 (7 failed)
    Medium         4

  OWASP LLM Categories:
    Category Name                                Total  Pass  Fail
    -----------------------------------------------------------------
    LLM01    Prompt Injection                       13     5     8
    LLM02    Sensitive Information Disclosure    not exercised this run
    LLM03    Supply Chain                        not exercised this run
    LLM04    Data and Model Poisoning            not exercised this run
    LLM05    Improper Output Handling                4     4     0
    LLM06    Excessive Agency                    not exercised this run
    LLM07    System Prompt Leakage               not exercised this run
    LLM08    Vector and Embedding Weaknesses     not exercised this run
    LLM09    Misinformation                          4     4     0
    LLM10    Unbounded Consumption                   2     2     0

  Coverage this run: 4/10 OWASP LLM Top 10 categories exercised. Not exercised:
    - LLM02: Sensitive Information Disclosure
    - LLM03: Supply Chain
    - LLM04: Data and Model Poisoning
    - LLM06: Excessive Agency
    - LLM07: System Prompt Leakage
    - LLM08: Vector and Embedding Weaknesses

  SARIF Report: results/app-http-localhost-8000-chat.sarif
  Exit code: 1 (failures detected)
```

Each finding names the probe, the prompt it sent and the reply that failed it, so you can paste the
prompt into your own app and watch it happen. Add `--report-formats=sarif,html` for a browsable
version under `results/`.

## Read the second half of that table first

**Six of the ten categories say `not exercised this run`. That is the most useful thing on the
page.** They split two ways. The footer at the bottom of the run names which is which.

**Four are scored against something only you know**: a real secret your app holds, the signature of a
privileged action it can perform, a confidential string sitting in its retrieved corpus. Without one
of those a probe has nothing to look for, so a clean row would only mean the marker was never live.
The scan says so instead of scoring them.

**Two are not about your endpoint at all.** LLM03 reads your dependency manifests and LLM04 reads
your model files, so they need a path rather than a flag about your app: `--repo .` and
`--model-scan <path>`. Neither sends anything anywhere.

Telling it one of those turns a blank row into a real one:

```bash
llmsectest --target app:http://localhost:8000/chat \
  --app-prompt system-prompt.txt \
  --app-secret "sk-your-real-canary"
```

`--app-prompt` brings in LLM07, `--app-secret` LLM02, `--app-action` LLM06, the two RAG markers
LLM08. The [application guide](guides/target-app.md) walks through each one. Adding `--repo .` to the same
command brings in LLM03.

## What a report like this is worth

- **A finding is evidence.** It carries the exact request and the exact reply, so it reproduces.
- **A clean row is weaker than it looks.** It says the probes we ship did not get through on this
  run. Probes are model-driven, so two scans of one application can disagree. Nobody has probed
  everything.
- **A clean report is not a safety claim.** LLMSecTest is pre-1.0. Use it to find what is already
  broken rather than to certify that nothing is.
- **A non-zero exit does not always mean vulnerable.** It also fires when probes never came back. In
  that case the report describes nothing at all, the summary says `INCOMPLETE` and no posture is
  claimed. See
  [what a non-zero exit means](guides/ci.md#what-a-non-zero-exit-means).

## Next

- **[Test your running app](guides/target-app.md)** for the full black-box workflow.
- **[CI/CD integration](guides/ci.md)** for GitHub Actions, GitLab CI or Jenkins.
- **[Getting started](getting-started.md)** for targets other than an HTTP endpoint, from a local
  model through Ollama or LM Studio to a hosted model or the offline demo apps.
- `llmsectest --check` prints the coverage map, the authority on what the tool tests today.

Something here cost you more than a minute? [Open an issue](https://github.com/wehnsdaefflae/llmsectest/issues)
saying where you stopped. That is the most useful report this project receives.
