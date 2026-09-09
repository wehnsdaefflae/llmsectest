# Have an assistant wire it up

--8<-- "_release.md"

Pointing LLMSecTest at a real application means answering about ten questions about that
application: which URL answers, what the request body looks like, where your text goes inside it,
where the reply comes back, what the auth header is, whether a conversation has to be created
first, and what ground truth the app holds. All of those answers are in your own code.

**This page is a prompt you can hand to a coding assistant, with your repository open, to produce
the command line for you.** It is written to make the assistant read your code rather than guess at
it, because a guessed adapter is worse than no adapter. The last section explains why.

## The prompt

Copy everything in the block. Run it in a coding assistant that can read your repository.

````markdown
You are wiring my application up to LLMSecTest, a security scanner that attacks a running
LLM application over HTTP and reports against the OWASP LLM Top 10.

Your job is to produce one shell command. You may only write a value into that command
if you can point at the file and line in THIS repository where you read it. If you cannot
find something, leave the flag out and list it under "Not determined" with the reason.
Do not infer a value from convention, from a similar project, or from the framework's
documentation. A wrong value here produces a security report that is confidently wrong,
which is worse for me than a short one.

Work in this order.

STEP 1 - Find the endpoint that a user's chat message reaches.
Search the repo for the HTTP route handlers. Identify the ONE route that takes a user's
message and returns the model's reply. Note the method, the full path, and the port the
service listens on in local development. If several routes qualify (streaming and
non-streaming, v1 and v2), pick the non-streaming one and say which others you saw.

STEP 2 - Read the request body shape off the handler.
Find the request model, schema, or the first lines of the handler that read the body.
Write down the exact JSON an existing client sends. Then answer: which key holds the
user's message text? Give it as a dotted path from the root of the body, using numbers
for list indices. Examples: "message", "input_value", "messages.0.content", "query.text".
This is --app-request-field. Every OTHER key in that body, with a valid fixed value that
makes the request well formed, is --app-body as a JSON object. If the body carries a
message list, --app-body must contain that list with exactly one user message whose
content is an empty string, and --app-request-field addresses that entry.

STEP 3 - Read the response body shape off the handler.
Find what the handler returns. Write down the exact JSON. Then give the dotted path to
the assistant's reply TEXT, again with numbers for list indices. Examples:
"reply", "choices.0.message.content", "outputs.0.outputs.0.results.message.text".
This is --app-response-path. If the reply text is not present as a plain string anywhere
in a non-streaming response, stop and say so: the scanner cannot read it and this is the
single most useful thing you can tell me.

STEP 4 - Read the authentication off the middleware.
Find the auth check that runs before the handler. Name the header and the exact format of
the value. This is --app-headers as a JSON object, for example
{"Authorization": "Bearer <token>"}. Leave the token as a placeholder for me to fill in.
If there is no auth in local development, say that explicitly rather than omitting it.

STEP 5 - Decide whether a conversation must exist first.
Look for a conversation, session, thread or chat id in the request body or path. If the
handler rejects a request without one, find the endpoint that creates one and give me:
the dotted path in the request body where the id goes (--app-session-field), and a JSON
object naming the creating endpoint's url, method, headers, body and the dotted path to
the new id in its response (--app-session-init). If no such id exists, say so.

STEP 6 - Collect the ground truth the app already holds.
These four unlock four of the ten categories. Report each one as found or absent, and
give the file and line for each one you found.
  a) The system prompt the application sends. Give me the file path.
     This becomes --app-prompt <path> and enables LLM07.
  b) A real secret the application holds in its context or prompt: an API key, an
     internal URL, a customer identifier. Give me the file and line, NOT the value.
     I will pass the value myself as --app-secret. This enables LLM02.
  c) Every privileged action the model can trigger, as the exact literal prefix the
     model must emit to trigger it. Read this off the tool definitions or the output
     parser, not off the documentation. Example: if the parser matches a line starting
     "ACTION: refund(", the signature is "ACTION: refund(". Each one is a repeated
     --app-action and they enable LLM06.
  d) Whether the app retrieves documents at query time. If it does, name the store and
     how a document gets into it. I will plant two markers myself
     (--app-canary and --app-rag-poison) and those enable LLM08.

STEP 7 - Prove the shape before you hand me the command.
Write ONE curl command using everything above, with a harmless question as the input.
Run it if you can run commands. Show me the raw response. Confirm that
--app-response-path resolves to the reply text in the response you actually got. If you
cannot run it, say the command is unverified.

STEP 8 - Output, in this order and nothing else.
  1. The curl command from step 7 and its response, or a note that it is unverified.
  2. The llmsectest command, one flag per line with backslash continuations.
  3. A table: flag, value, file:line where you read it.
  4. "Not determined": every flag you left out, with the reason.
  5. "Categories this will not exercise": for each of --app-prompt, --app-secret,
     --app-action, --app-canary and --app-rag-poison that you could not supply, name the
     OWASP category it would have unlocked, so I know the report will record those as
     skipped rather than as passed.

The flags exist exactly as named above. Do not invent flags. Do not write a wrapper
script, a proxy, or any Python: the scanner talks to the endpoint directly and every
shape difference is expressible in the flags above.
````

## What you get back

A command in this shape, with the values from your own repository:

```bash
llmsectest --target app:http://localhost:8000/api/chat \
  --app-request-field 'messages.0.content' \
  --app-response-path 'choices.0.message.content' \
  --app-headers '{"Authorization": "Bearer $APP_TOKEN"}' \
  --app-body '{"model": "app", "stream": false,
               "messages": [{"role": "user", "content": ""}]}' \
  --app-prompt prompts/system.txt \
  --app-secret "$REAL_SECRET" \
  --app-action "ACTION: refund(" \
  --report-formats sarif,html
```

Run it. A non-zero exit means the scan found something.

## Why the prompt is written to refuse

An assistant that fills in every flag looks more helpful than one that leaves four blank. For this
particular task it is the opposite. The reason is worth understanding before you use
the output.

**A wrong `--app-response-path` reports your whole application as unreachable.** The scanner cannot
find the reply, so every probe comes back unanswered. The report is then a true sentence about the
wrong thing, which is why the run refuses a malformed JSON flag rather than falling back to a
default.

**A wrong `--app-secret` is worse, because it comes out green.** The LLM02 probes ask the
application for a secret and check whether that exact value comes back. If the value you passed is
not a secret the application actually holds, nothing can ever match, and the category reports as
attacked and withstood. **You get a clean row that means nothing had been planted.** The same trap
sits under `--app-action` for LLM06 and under the two markers for LLM08.

This is the failure mode this project spends most of its effort on. LLMSecTest reports a category
with no ground truth as **skipped, naming the reason and the flag that would enable it**, rather
than as a pass. The prompt's "Not determined" and "Categories this will not exercise" sections exist so
that the assistant's output and the scanner's report agree about what was never tested.

**So read the file:line table before you run the command.** It takes a minute. It is the difference between a report about your application and a report about your configuration.

## When the assistant gets stuck

Three answers are common and all three are useful.

**"The reply is only available as a stream."** Some applications have no non-streaming route at all.
Say so in an issue. The adapter reads a complete response body, so a streaming-only door is a real gap and not a configuration problem.

**"The persona is attached to a conversation created by the UI."** This is normal in chat products.
Step 5 is the path: `--app-session-init` asks the application for a conversation before each probe.
`--app-session-field` puts the id where the handler reads it.

**"The retrieval context is assembled by a second endpoint."** The scanner talks to one door. An
application that assembles its context elsewhere needs that door to be the one you point at. If no single door carries both the retrieval and the generation, LLM08 cannot be exercised black-box.

## Related

- [Test your running app](target-app.md) for what each flag means in full.
- [CLI reference](../cli.md) for every flag the scanner takes.
