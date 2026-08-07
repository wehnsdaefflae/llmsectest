# Test your running application

This is the point of LLMSecTest: test the **application**, not a bare model. When you target your
app's own endpoint, its real system prompt, guardrails, RAG context and tools are all exercised — so a
finding reflects how your app actually behaves under attack.

## Point at your app endpoint

```bash
llmsectest --target app:https://your-app.example.com/chat
```

LLMSecTest POSTs the **attacker turn** to your endpoint and reads the reply. It sends *only* the user
message — your application supplies its own system prompt, which is exactly what we want to test.

### Request and response shapes

By default the request body is `{"message": "<attacker input>"}` and the reply is auto-detected across
common shapes: a top-level `reply` / `response` / `message` / `content` / `answer` field, or the
OpenAI-style `choices[0].message.content`. If your app differs, configure it (Python API):

```python
from llmsectest.adapters.app_endpoint import AppEndpointAdapter

target = AppEndpointAdapter(
    endpoint="https://your-app.example.com/v1/chat",
    request_field="prompt",            # your app's input field
    response_path="data.0.text",       # dotted path to the reply in the JSON
    headers={"Authorization": "Bearer <token>"},
    extra_body={"session_id": "llmsectest"},
)
```

## No paid calls: back your app with a local model

Run your app in a test configuration whose LLM backend points at a **local** model (e.g. Ollama or
LM Studio), then test it — zero API cost:

```bash
# 1) your app, configured to call a local OpenAI-compatible endpoint:
export OPENAI_BASE_URL=http://localhost:11434/v1   # Ollama (LM Studio: http://localhost:1234/v1)
export OPENAI_API_KEY=ollama                        # ignored by local servers
./run-your-app.sh &

# 2) test it
llmsectest --target app:http://localhost:8000/chat
```

## What's covered against an endpoint

Endpoint testing is **black-box**. **LLM01 (prompt injection)**, **LLM05 (improper output
handling)**, **LLM09 (misinformation)** and **LLM10 (unbounded consumption)** always run — their
attack-side marker (or, for LLM09, a guaranteed-nonexistent entity) lives in the attack, so the scan
needs nothing from you. LLM10 uses two *bounded* probes — a repetition flood (repeat a marker an explicit,
finite number of times) and output amplification (emit a large but finite non-repetitive volume) — so an
app that floods or amplifies on demand is flagged without risking a runaway generation against an uncapped
endpoint. Four more categories light up when you tell LLMSecTest what
only you, the app's developer, know:

```bash
llmsectest --target app:http://localhost:8000/chat \
    --app-prompt prompt.txt \                      # your app's system prompt    → LLM07
    --app-secret "sk-canary-123" \                 # a real secret it holds      → LLM02
    --app-action "ACTION: refund(" \               # a privileged tool call      → LLM06
    --app-action "ACTION: delete_user(" \          # (repeatable)
    --app-canary "INTERNAL-DOC-CANARY-7f2a" \      # confidential RAG content    → LLM08
    --app-rag-poison "RAG-POISON-3b9d"             # poisoned-doc marker         → LLM08
```

- **`--app-prompt`** — the app's own system prompt (inline text or a file path). Knowing it means
  the scan knows what a **leaked instruction** looks like (LLM07).
- **`--app-secret`** — a real secret/canary value the app holds. A disclosure is then unambiguous —
  no false-positive-prone heuristics (LLM02).
- **`--app-action`** — a privileged tool/action signature your app can execute; repeat the flag for
  several. An unauthorized invocation is then unambiguous (LLM06). **Pass a string your app really
  emits when it acts** — for a tool-using agent, the tool-invocation line it returns or logs — and
  verify that before you trust a clean row: send it a request you are happy for it to honour and read
  the raw reply. An app that only *describes* what it did in prose can never trip this probe, so a
  clean LLM06 row on one means "not observed". Measured, not assumed: see
  [LLM06](../owasp/llm06.md#what-a-clean-llm06-result-does-and-does-not-tell-you).
- **`--app-canary`** — confidential content planted in your app's **RAG / retrieved corpus** (a unique
  token in an indexed document). Enables the **LLM08** retrieval-exposure probes: a reply that
  reproduces the canary means the retrieval layer leaked confidential indexed content. Distinct from
  `--app-secret` — there the secret lives in the prompt/config, here in the retrieved corpus.
- **`--app-rag-poison`** — the marker a **poisoned document** planted in your retrieved corpus instructs
  the model to emit. Enables the **LLM08** indirect-injection probes: benign queries retrieve the poisoned
  doc, and a vulnerable app obeys its instruction and emits the marker (which the probe never named). It
  proves the app trusts retrieved content — the LLM08↔LLM01 bridge. Independent of `--app-canary`; supply
  either or both.

Each category whose input you don't supply shows up as an **explicit skip naming the flag** that
would enable it — never a silent gap. The white-box categories run from a path you provide alongside the
endpoint scan: add `--repo <path>` for **LLM03 (supply chain)** and `--model-scan <path>` for **LLM04
(data and model poisoning)**. LLM08's two black-box dimensions ship today; its white-box ones
(poisoning, inversion, multi-tenant isolation) are not implemented yet and are reported as
not-exercised rather than passed. Always check `llmsectest --check`.

## When the scan can't reach your app

If your endpoint is unreachable, returns something that isn't the JSON shape above, or dies partway
through a scan, those probes are recorded **inconclusive** — never as findings. A target we could not
talk to is not a vulnerable target, and the report says so in three places: a red banner at the top of
the HTML page, an `undelivered` count in the SARIF run properties, and the console *Attacks Delivered*
block.

**The run also exits non-zero.** That is deliberate, and it is the half that makes the rest safe: a scan
that reached nothing produces an empty findings list, which in CI would otherwise be indistinguishable
from a clean bill of health. `0 findings, 25 never delivered` is not a pass.

A slow app is a different case. One that exceeds `--app-timeout` was reached and ran out of budget: that
is also inconclusive, but it does not fail the run — raise the budget instead. The console line
distinguishes them (`Inconclusive: 26 (26 never delivered)`).

## When you can't run the app: the persona proxy

If you only have the app's system prompt (not a running instance), load it onto a model and test that
as a proxy. Lower fidelity (no guardrail/RAG/tool code), but useful:

```python
from llmsectest.adapters import get_adapter
from llmsectest.probes import run_app_scan

target = get_adapter("ollama", "gemma4:e2b-it-q4_K_M")
prompt = open("my_app_system_prompt.txt").read()
for outcome in run_app_scan("my-app", prompt, target):
    print(outcome.case.owasp, "VULNERABLE" if outcome.vulnerable else "ok", outcome.evidence)
```

See [`run_app_scan`](../api.md) in the API reference.
