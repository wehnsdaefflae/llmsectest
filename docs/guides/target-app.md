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

Run your app in a test configuration whose LLM backend points at a **local** model (e.g. Ollama),
then test it — zero API cost:

```bash
# 1) your app, configured to call a local OpenAI-compatible endpoint:
export OPENAI_BASE_URL=http://localhost:11434/v1   # Ollama
export OPENAI_API_KEY=ollama                        # ignored by Ollama
./run-your-app.sh &

# 2) test it
llmsectest --target app:http://localhost:8000/chat
```

## What's covered against an endpoint

Endpoint testing is **black-box**, so it covers the prompt-facing OWASP categories:
**LLM01 (prompt injection)**, **LLM05 (improper output handling)**, **LLM06 (excessive agency)**, and
— with a configured canary — **LLM02/LLM07** disclosure/leakage. The white-box categories
(LLM03/04/08/10) need your app's internals and are covered by their own modules per milestone. Always
check `llmsectest --check`.

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
