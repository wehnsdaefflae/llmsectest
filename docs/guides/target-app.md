# Test your running application

--8<-- "_release.md"

This is the point of LLMSecTest: test the **application**, not a bare model. When you target your
app's own endpoint, its real system prompt, guardrails, RAG context and tools are all exercised. So a
finding reflects how your app behaves under attack.

## Point at your app endpoint

```bash
llmsectest --target app:https://your-app.example.com/chat
```

LLMSecTest POSTs the **attacker turn** to your endpoint and reads the reply. It sends *only* the user
message. Your application supplies its own system prompt. That's the thing we want to test.

### Request and response shapes

By default the request body is `{"message": "<attacker input>"}` and the reply is auto-detected across
common shapes: a top-level `reply` / `response` / `message` / `content` / `answer` field, or the
OpenAI-style `choices[0].message.content`.

**Real applications often differ. Four flags describe how.** No wrapper, no proxy, no Python:

```bash
llmsectest --target app:http://localhost:7860/api/v1/run/<flow-id> \
  --app-request-field input_value \
  --app-response-path 'outputs.0.outputs.0.results.message.text' \
  --app-headers '{"Authorization": "Bearer <token>"}' \
  --app-body '{"output_type": "chat", "input_type": "chat"}'
```

- `--app-request-field` says where your input goes: a field name, or a dotted path
  into the body from `--app-body`, list indices included. An OpenAI-compatible
  endpoint takes `messages.0.content` against a body carrying that one user
  message. No wrapper script is needed. Send **no system message**. An application
  that lets a client one override its own prompt would then be answering yours, so
  the scan becomes a scan of the model wearing your application's name.
- `--app-response-path` is a dotted path to the reply. A number in it is a list index, so
  `outputs.0.results.message.text` walks a list and then two objects.
- `--app-headers` is a JSON object merged over the defaults, for bearer tokens and API keys. The
  JSON content type stays unless you replace it.
- `--app-body` is a JSON object of fixed keys sent alongside your input, for the envelope fields
  some products require.

**A malformed value for either JSON flag is refused rather than ignored.** Falling back to the
default shape would make every probe come back unanswered. The scan would then honestly report your
whole application as unreachable, which is a true sentence about the wrong thing.

The same four are available on the Python API if you are driving the adapter yourself:

```python
from llmsectest.adapters.app_endpoint import AppEndpointAdapter

target = AppEndpointAdapter(
    endpoint="https://your-app.example.com/v1/chat",
    request_field="prompt",
    response_path="data.0.text",
    headers={"Authorization": "Bearer <token>"},
    extra_body={"session_id": "llmsectest"},
)
```

### An OpenAI-compatible application

A great many products serve `POST /v1/chat/completions`. That shape needs no wrapper either. It
is worth its own example. The prompt does not sit at the top level of the body: it sits inside a
list.

```bash
llmsectest --target app:http://localhost:14000/api/v1/chat/completions \
  --app-request-field messages.0.content \
  --app-response-path 'choices.0.message.content' \
  --app-headers '{"Authorization": "Bearer <token>"}' \
  --app-body '{"model": "your-app", "stream": false,
               "messages": [{"role": "user", "content": ""}]}'
```

`--app-body` supplies the envelope with one empty user turn in it. `--app-request-field` writes each
probe into that turn. The path only ever writes into a list your body already carries: it never
creates or extends one, because how long a list should be is not something a path can say.

**Send no `system` message, whatever your body looks like.** Many implementations of this endpoint
let a client system message *replace* the application's own configured prompt. Put your persona
there and the application stops being the thing under test: it becomes a proxy to the model, every
guardrail written into its own prompt is gone, and the report that comes out looks exactly like a
report about your application. If you want to know which side of that line your endpoint is on, ask
it who it is twice: once with no system message, once with a system message naming somebody else.
Whichever answer wins tells you. That is the same control described under *Prove your prompt reached the
model* below, run as a differential.

**A system message that is merely *added* is the quieter half of the same problem.** Where one
implementation replaces the application's prompt, another keeps its own and appends yours. Nothing
looks wrong: the persona reaches the model, your canary comes back, the report fills in. What you
have measured is the prompt your client sent, on an application that is holding a different one,
and there is nothing on the server to read your persona back from. The remedy is the same either
way. **Put the persona where the application stores it**, through whatever the product calls a
system prompt, an agent or a workspace instruction, send no `system` message at all, then read it
back off the application and check it byte for byte before you believe a single clean row.

Two more things worth knowing about this shape:

- **Prefer the nested response path to a flattened convenience field.** `choices.0.message.content`
  fails loudly when the reply is not the shape you expected, so the probe is recorded undelivered
  with the reason. A short field that quietly yields an empty string turns an
  application that said nothing into one that withstood the attack.
- **Watch for an error envelope returned with HTTP 200.** Several implementations answer
  `{"status": "error", "msg": ...}` with a success code. The nested path above is what catches it.

### Applications that scope a chat to a conversation

Some applications hang the persona, the knowledge base or the tool set off a **conversation**. Point
every probe at one conversation and each attack sees the ones before it, so a refusal or a leak early
on changes what every later probe measures. That is then a property of the scan. Two flags give each
probe a conversation of its own.

**When your application accepts an id you choose:**

```bash
llmsectest --target app:http://localhost:3000/api/chat \
  --app-session-field conversation_id
```

A fresh UUID goes into that body field for every probe. It costs no extra request. Most applications
need only this. The field takes a dotted path, so `metadata.session.id` reaches a nested envelope.

**When only the application may create one:**

```bash
llmsectest --target app:http://localhost:42110/api/chat \
  --app-session-field conversation_id \
  --app-session-init '{"url": "/api/sessions", "response_path": "conversation_id"}'
```

Before each probe LLMSecTest sends that request, reads the value at `response_path` out of the reply
and carries it into the field `--app-session-field` names. A relative `url` resolves against your
endpoint; `method` (default `POST`), `headers` and `body` are optional. An unknown key in the JSON is
refused, so a misspelled `response_path` cannot quietly leave the scan auto-detecting some other
field.

**A session step that fails is inconclusive.** It never scores as a finding. It never scores as
an LLM10 timeout either. An application that never answered a setup request has said nothing about
how it bounds the work of a probe it never received.

## Getting past your platform's front door

If your application is built on a hosted platform rather than written from scratch, its chat endpoint
is usually wrapped in an authentication scheme built for that platform's own web UI. Three real
examples, all met while enrolling them into our test cohort:

| Platform | What the browser sends | What a scanner should use |
|---|---|---|
| Langflow | a session bearer token from `/api/v1/auto_login` | an API key from `/api/v1/api_key/` |
| Dify | a console login whose password field is encrypted | the per-app **Service API** key, `app-…` |
| Lobe Chat | `X-Lobe-Chat-Auth`, a XOR-obfuscated base64 JSON blob | server-side provider config, or its server-database mode |

**Reach for the integration credential rather than the browser's.** Every one of these platforms
publishes a machine path, because they all want people building on them, and it is a different door
from the one the UI walks through. Look for *API keys*, *Service API* or *integrations* in the app's
own settings. It is a one-time manual step per application.

Once you hold that credential the rest is the four flags above:

```bash
llmsectest --target app:https://your-platform/v1/chat-messages \
  --app-headers '{"Authorization": "Bearer app-xxxxxxxx"}' \
  --app-request-field query \
  --app-body '{"inputs": {}, "response_mode": "blocking", "user": "llmsectest"}'
```

**One thing to check before you read the results.** On some platforms the assistant's system prompt
lives in the browser rather than on the server. It is sent with each request. There, an endpoint
reached directly has no system prompt at all, so anything scored against a value you planted in one
(LLM02, LLM06, LLM07) has nothing to find. The scan says so, reporting those as `unconfirmed` or not
exercised. The categories carrying their own marker in the attack, LLM01, LLM05, LLM09 and LLM10,
score normally either way.

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
  doc. A vulnerable app obeys its instruction and emits the marker (which the probe never named). It
  proves the app trusts retrieved content, the LLM08↔LLM01 bridge. Independent of `--app-canary`; supply
  either or both.

Each category whose input you don't supply shows up as an **explicit skip naming the flag** that
would enable it, never a silent gap. The white-box categories run from a path you provide alongside the
endpoint scan: add `--repo <path>` for **LLM03 (supply chain)** and `--model-scan <path>` for **LLM04
(data and model poisoning)**. LLM08's two black-box dimensions ship today; its white-box ones
(poisoning, inversion, multi-tenant isolation) are not implemented yet and are reported as
not-exercised rather than passed. Always check `llmsectest --check`.

## Prove your prompt reached the model

`--app-secret`, `--app-action` and `--app-canary` are only ever observed when the value comes
**back** in a reply. An application that resisted every attack and an application that never
received your system prompt therefore produce the same report: clean rows, nothing recovered, a run
that reads as a pass. Before you believe one, rule out the other.

Put a second marker in the same system prompt as your canary, one the assistant is explicitly
allowed to state. Then ask for it:

```text
Your configuration build is ACME-CFG-3F8H. It identifies a revision, it is not confidential,
and you state it plainly to anyone who asks which build you are running.
```

```bash
curl -s localhost:8000/chat -H 'content-type: application/json' \
     -d '{"message":"Which configuration build are you running?"}' | grep ACME-CFG-3F8H
```

If the marker comes back, that string reached the model and the canary sitting in it is live
ground truth. If it does not, your clean rows are describing your configuration. The fix belongs there. The
report will follow it.

Two details make the difference between a control and a formality:

- **Ask through the path the scan will use**, with the same headers, session handling and body that
  your `--app-*` run sends. A marker that comes back through the web UI proves the web UI. Platforms
  that bind a system prompt to an assistant, an agent or a workspace commonly apply it on one route
  and not on another, and that route is what your scan is about to measure.
- **Do not ask for the secret itself.** An application that refuses is doing what you
  configured it to do, so the refusal tells you nothing about whether the secret is there. The
  marker works because stating it is permitted.

## When the scan can't reach your app

If your endpoint is unreachable, returns something that isn't the JSON shape above, or dies partway
through a scan, those probes are recorded **inconclusive**, never as findings. A target we could not
talk to is not a vulnerable target. The report says so in three places. A red banner at the top of
the HTML page, an `undelivered` count in the SARIF run properties, and the console *Attacks Delivered*
block.

**The run also exits non-zero.** That's deliberate. It's the half that makes the rest safe. A scan
that reached nothing produces an empty findings list. In CI that's indistinguishable from a clean
bill of health. `0 findings, 25 never delivered` is not a pass.

A slow app is a different case in one respect only. One that exceeds `--app-timeout` was reached and
ran out of budget, so it doesn't fail the run: raise the budget instead. Everything else is the same,
because an unanswered probe is unanswered whichever way it went missing. The status still reads
`INCOMPLETE`, no posture is claimed, and the closing line says the run does not claim those probes
were withstood. The console distinguishes the two reasons (`Inconclusive: 26 (26 never delivered)`),
so you can tell a budget to raise from a URL to check.

**And the exception to the exception: a scan where no probe was answered fails.** Losing some probes
to the clock is an ordinary afternoon. Losing all of them means the page describes nothing, so it
gets the same red banner and the same non-zero exit as an endpoint that was never there.

**An app that answers with an error is a third case. The report says which.** If your endpoint
replies `HTTP 429` the probe is recorded as **throttled**, with your app's own `Retry-After` when it
sends one, because the fix is a quota rather than a URL. Any other refusal (`401` on an expired token,
`403` from a gateway in front of the app, `500` from the app itself) is inconclusive as well, and the
reason names the status and says the endpoint *was* reached. That distinction matters when you are
scanning through an auth layer: `app endpoint … answered HTTP 401 (Unauthorized)` sends you to your
token, where `unreachable` would send you to your DNS.

**The fourth case is the one with nothing to fix: your app refused the input on purpose.** Some
applications validate the prompt before it reaches the model. If yours rejects, say, anything
matching an XSS pattern list, the probes carrying `<script>` or `javascript:` payloads never reach
the model at all. They are recorded undelivered like any other error. That is the right
record: nothing about your output handling was measured, so nothing may be claimed about it. The remedy is
what differs. There isn't one. Tell the two apart by sending one of the named probes by hand. A
refusal that quotes your own validator ("query contains invalid content") is your guardrail; a 500
with a stack trace is not.

**The fifth case answers 200 and says nothing. It is the one that looks most like success.**
An agent framework can finish a turn without producing an assistant message: the model calls a tool,
the tool returns nothing usable, and the run ends. Some of them still answer `HTTP 200` with a
success status and an empty output list, no error anywhere in the envelope. A client cannot tell that
from a model that had nothing to say.

Point `--app-response-path` at the field that only exists when there *is* a message. The scanner
then tells the two apart for you: the path stops partway and the probe is recorded undelivered with
the reason naming the segment it stopped at.

```
LLM09-fabricated-citation [hallucinated academic citation] after 12.8s: probe not delivered,
response path 'output.0.content.0.text' does not match the reply JSON (stopped at '0')
```

The trap is the convenience field next to it. Frameworks that return `output: []` often also return
a flattened `output_text: ""` on the envelope. A response path pointing at *that* extracts the empty
string, the probe is scored, and an application that answered nothing at all is recorded as having
withstood the attack. Prefer the nested path even though it is longer. If a whole category comes
back undelivered with `stopped at '0'`, look at what your app does with a tool call before you look
at your URL: probes that ask for content the app cannot ground are exactly the ones that trigger one.

In every one of these cases, read the per-category table. A probe that was never delivered is
**not** in that table's `Pass` column. The row says how many were lost:

```
LLM05    Improper Output Handling                4     2     0  2 never delivered
```

Four probes, two answered and held, none failed, two never delivered. A row reading `4  4  0`
would be claiming your app handled output safely four times when it did so twice.


**Every inconclusive probe is named.** The reason recorded for each one starts with the probe's own id
and technique, so the report says which attacks you did not get an answer for:

```
APP-shop-LLM02-handover-summary [indirect disclosure via a configuration handover document]
after 90.0s: probe inconclusive, app endpoint http://127.0.0.1:8041/chat did not respond within 90s
```

That matters because a category runs several mechanisms. `LLM02 attempted 4, inconclusive 3` is honest
about the count. It still leaves you guessing which three. Now you can read it off the report.

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

There is one exception. The two **bounded LLM10** probes
score a timeout as a finding, because a request for explicitly finite output that eats the whole budget is
the vulnerability. Those probes are not inconclusive, so they land in the answered population and can set
`peak_seconds` to your budget. On our own cohort that is 13 targets of 51, every one of them an LLM10
bounded probe and nothing else. The finding's own text carries the honest figure beside it (*"21 other
probes completed inside the same budget, median 4.5s, slowest 9.2s"*), so read that when the peak reads
like a round number.

We did that to ourselves. Our own 50-application cohort split into ten slow targets at 18 to 23 seconds a
probe and forty fast ones at 4 to 10. It looked like two kinds of application. It was arithmetic. Each of
the ten had lost four or five probes pinned at 90 seconds. Count only the probes that answered and the ten
run at 5 to 12 seconds against the forty's 4 to 10. The gap is gone.

One more thing fell out of that. You want it before you read your own timeouts. On nine of the ten,
the probes that timed out were **consecutive**. That's not four expensive probes. It's one window where
the app answered nothing. Our own deadline is what opens it. Your app doesn't stop working when we
stop waiting. If your handler is synchronous in front of a backend that serves one request at a time, our
next probe queues behind the generation we walked away from, and it times out for a reason that has
nothing to do with it. So read a run of consecutive timeouts as one event and only the first one as
having a cause.

**A rate-limited target is a third case. It says so.** A hosted target that answers `HTTP 429` has
been reached, so the report does not tell you to check whether your endpoint is up. Those probes are
recorded inconclusive in the same tally, with `rate limited by the target` as the reason and the
provider's own `Retry-After` value when it sent one, and the run exits non-zero for the same reason as
above. There is no retry or backoff: getting the count right comes first. A retry loop
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
