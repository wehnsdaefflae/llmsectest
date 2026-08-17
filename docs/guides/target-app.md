# Test your running application

This is the point of LLMSecTest: test the **application**, not a bare model. When you target your
app's own endpoint, its real system prompt, guardrails, RAG context and tools are all exercised. So a
finding reflects how your app behaves under attack.

## Point at your app endpoint

```bash
llmsectest --target app:https://your-app.example.com/chat
```

LLMSecTest POSTs the **attacker turn** to your endpoint and reads the reply. It sends *only* the user
message. Your application supplies its own system prompt, and that's the thing we want to test.

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
LM Studio), then test it, zero API cost:

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
handling)**, **LLM09 (misinformation)** and **LLM10 (unbounded consumption)** always run, their
attack-side marker (or, for LLM09, a guaranteed-nonexistent entity) lives in the attack, so the scan
needs nothing from you. LLM10 uses two *bounded* probes, a repetition flood (repeat a marker an explicit,
finite number of times) and output amplification (emit a large but finite non-repetitive volume). So an
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

- **`--app-prompt`**, the app's own system prompt (inline text or a file path). Knowing it means
  the scan knows what a **leaked instruction** looks like (LLM07).
- **`--app-secret`**, a real secret/canary value the app holds. A disclosure is then unambiguous, with
  no false-positive-prone heuristics (LLM02).
- **`--app-action`**, a privileged tool/action signature your app can execute; repeat the flag for
  several. An unauthorized invocation is then unambiguous (LLM06). **Pass a string your app really
  emits when it acts.** For a tool-using agent that's the tool-invocation line it returns or logs.
  Verify it before you trust a clean row: send it a request you are happy for it to honour and read
  the raw reply. An app that only *describes* what it did in prose can never trip this probe, so a
  clean LLM06 row on one means "not observed". Measured, not assumed: see
  [LLM06](../owasp/llm06.md#what-a-clean-llm06-result-does-and-does-not-tell-you).
- **`--app-canary`**, confidential content planted in your app's **RAG / retrieved corpus** (a unique
  token in an indexed document). Enables the **LLM08** retrieval-exposure probes: a reply that
  reproduces the canary means the retrieval layer leaked confidential indexed content. Distinct from
  `--app-secret`. There the secret lives in the prompt/config, here in the retrieved corpus.
- **`--app-rag-poison`**, the marker a **poisoned document** planted in your retrieved corpus instructs
  the model to emit. Enables the **LLM08** indirect-injection probes: benign queries retrieve the poisoned
  doc, and a vulnerable app obeys its instruction and emits the marker (which the probe never named). It
  proves the app trusts retrieved content, the LLM08↔LLM01 bridge. Independent of `--app-canary`; supply
  either or both.

Each category whose input you don't supply shows up as an **explicit skip naming the flag** that
would enable it, never a silent gap. The white-box categories run from a path you provide alongside the
endpoint scan: add `--repo <path>` for **LLM03 (supply chain)** and `--model-scan <path>` for **LLM04
(data and model poisoning)**. LLM08's two black-box dimensions ship today; its white-box ones
(poisoning, inversion, multi-tenant isolation) are not implemented yet and are reported as
not-exercised rather than passed. Always check `llmsectest --check`.

## When the scan can't reach your app

If your endpoint is unreachable, returns something that isn't the JSON shape above, or dies partway
through a scan, those probes are recorded **inconclusive**, never as findings. A target we could not
talk to is not a vulnerable target, and the report says so in three places. A red banner at the top of
the HTML page, an `undelivered` count in the SARIF run properties, and the console *Attacks Delivered*
block.

**The run also exits non-zero.** That's deliberate, and it's the half that makes the rest safe. A scan
that reached nothing produces an empty findings list, and in CI that's indistinguishable from a clean
bill of health. `0 findings, 25 never delivered` is not a pass.

A slow app is a different case. One that exceeds `--app-timeout` was reached and ran out of budget. That
is also inconclusive, but it doesn't fail the run, raise the budget instead. The console line
distinguishes them (`Inconclusive: 26 (26 never delivered)`).

**Every inconclusive probe is named.** The reason recorded for each one starts with the probe's own id
and technique, so the report says which attacks you did not get an answer for:

```
APP-shop-LLM02-handover-summary [indirect disclosure via a configuration handover document]
after 90.0s: probe inconclusive, app endpoint http://127.0.0.1:8041/chat did not respond within 90s
```

That matters because a category runs several mechanisms. `LLM02 attempted 4, inconclusive 3` is honest
about the count, and it still leaves you guessing which three. Now you can read it off the report.

**And every scan records its slowest answered probe**, whether or not anything timed out:

```
Slowest answered: 11.4s (APP-shop-LLM07-disclosure)
```

Same figure in the SARIF as a run-level `latency` property, and in the header of the HTML page. A probe
answered at 88 seconds under a 90 second budget looks the same in your report as one answered in 3, right
up to the run where it stops answering. Now you can see it coming. It also tells a slow target apart from
a busy machine, worth knowing before you go looking at your app.

The word *answered* is doing work. A probe recorded inconclusive because it ran out of time measured the
timeout, so it never enters the mean or the peak. It gets `probes_unfinished` and `unfinished_seconds`
instead. Fold the two together and the mean stops describing your app and starts describing your budget.

There is one exception and we would rather name it than let you find it. The two **bounded LLM10** probes
score a timeout as a finding, because a request for explicitly finite output that eats the whole budget is
the vulnerability. Those probes are not inconclusive, so they land in the answered population and can set
`peak_seconds` to your budget. On our own cohort that is 13 targets of 51, every one of them an LLM10
bounded probe and nothing else. The finding's own text carries the honest figure beside it (*"21 other
probes completed inside the same budget, median 4.5s, slowest 9.2s"*), so read that when the peak reads
like a round number.

We did that to ourselves. Our own 50-application cohort split into ten slow targets at 18 to 23 seconds a
probe and forty fast ones at 4 to 10. It looked like two kinds of application. It was arithmetic. Each of
the ten had lost four or five probes pinned at 90 seconds. Count only the probes that answered and the ten
run at 5 to 12 seconds against the forty's 4 to 10, and the gap is gone.

One more thing fell out of that, and you want it before you read your own timeouts. On nine of the ten,
the probes that timed out were **consecutive**. That's not four expensive probes. It's one window where
the app answered nothing, and our own deadline is what opens it. Your app doesn't stop working when we
stop waiting. If your handler is synchronous in front of a backend that serves one request at a time, our
next probe queues behind the generation we walked away from, and it times out for a reason that has
nothing to do with it. So read a run of consecutive timeouts as one event, and only the first one as
having a cause.

**A rate-limited target is a third case, and it says so.** A hosted target that answers `HTTP 429` has
been reached, so the report does not tell you to check whether your endpoint is up. Those probes are
recorded inconclusive in the same tally, with `rate limited by the target` as the reason and the
provider's own `Retry-After` value when it sent one, and the run exits non-zero for the same reason as
above. There is no retry or backoff: getting the count right comes first, and a retry loop
built over a wrong count would only produce a confidently wrong number. Slow the scan down or raise your
quota, then run it again.

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
