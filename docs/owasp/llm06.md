# LLM06 — Excessive Agency

> The model is wired to *do* things, and it does one it should not have — moving money, changing an account, deleting data, granting itself rights.

**Modality:** black-box (white-box for the tool surface itself). **Status:** covered.

Prompt injection is a problem because of what the model can reach. An assistant that can only talk
produces bad text; an assistant holding a refund API, a mailbox or a Kubernetes namespace produces
consequences. OWASP calls the gap **excessive agency**: too much functionality, too many permissions, or
too much autonomy, so a single persuaded turn becomes a state change nobody authorised.

The failure is rarely a jailbreak. It is usually an ordinary-sounding request — urgency, claimed
seniority, a plausible story — and a model that was told to verify identity first and did not.

## How LLMSecTest tests it

You tell LLMSecTest what a privileged action *looks like* on the wire, and it tries to get one out of
your app without authorisation:

```bash
llmsectest --target app:http://localhost:8000/chat \
    --app-action "ACTION: grant_access(" --app-action "ACTION: reset_mfa("
```

Each `--app-action` is the **structured invocation** your app emits when it really means to act — the
tool-call line, function-call prefix or command envelope. That is what the `excessive_agency` oracle
looks for, and the choice matters: a target that answers *"I won't reset anyone's MFA without a ticket"*
names the tool while refusing it, and must not be scored as having used it. Matching the invocation and
not the topic is what keeps a well-behaved refusal out of the report.

Against a bare model (`--target ollama:…`, `--target openai:…`) the same category runs from a built-in
agent persona with four cases — account takeover by email change, unauthorised money movement,
irreversible deletion without confirmation, and self-granted privilege escalation — so LLM06 is
exercised even when there is no application to point at.

Without `--app-action`, the app-mode probe reports **skipped, naming the flag it needs**. It is never
silently passed.

## What a clean LLM06 result does and does not tell you

The [LLM08 defense matrix](llm08.md#does-a-defense-change-the-result) asks whether a defense changes the
result, or whether the probe simply always fires. Here the honest question is the mirror image, and we
only found that out by looking.

In our own test cohort, **26 applications declare privileged actions, and across eight recorded
regression baselines the LLM06 probe has produced zero findings** — none of them, not once, and none
against a bare model either. Two explanations fit that equally well from the outside: small models really
do decline to invoke a privileged tool for an unauthenticated stranger, or the oracle is matching a
literal `ACTION: name(` invocation that this class of model never emits in the first place, in which case
it is measuring spelling rather than agency.

The same count over the same record puts **LLM08 at 14 of 15**, so the harness and the marker plumbing
work; whatever this is, it is specific to this category (and to LLM02, which is at zero as well — see the
[changelog](../changelog.md)).

We do not yet know which, so **read a clean LLM06 row as "not observed", not as "not vulnerable"**, and
if you are wiring this up against your own app, check first that your app can emit the exact string you
passed to `--app-action` — send it a request you are happy for it to honour and look at the raw reply.
An oracle that cannot fire is worse than an absent one, because it reports a pass.

We are working the question with a **guarded twin** in the cohort: the same persona, the same declared
actions, the same model, with a structural guard in front of the reply, at three strengths. Its weakest
level is an undefended agent whose replies can be inspected directly, which is what the diagnosis needs.

| Guard | What it does |
|---|---|
| persona only | The system prompt says to execute an action only after identity verification against an approved ticket. Nothing structural. |
| ticket reference required | An action line survives only if the user's own turn cited a ticket in the documented format. |
| no action leaves this endpoint | A privileged action line is replaced with a refusal notice on the way out, whatever the model decided. |

The middle row is the one worth thinking about before you copy it. It is the defense most teams actually
write, and it checks the *shape* of a ticket reference, not its existence — so it stops a request that
never mentions a ticket and does nothing at all about one that invents a plausible id. A guard that an
attacker satisfies by typing `INC-4471` is a guard against accident, not against an adversary.

!!! warning "A guard that deletes the output is not a model that refused"
    The strongest row stops the finding by removing the action from the reply. That is a real defense and
    a sensible one — an unauthenticated chat endpoint is not a service-desk console — but it is a
    different claim from "the model declined". The same caveat applies to LLM08's redaction row, and for
    the same reason: measure what you deployed, and do not read a clean report as a statement about the
    model's judgement. Note that on the evidence above this caveat currently has no teeth to lose: the
    undefended level scores the same zero as the guarded one.

## What it does not test

LLMSecTest scans what your endpoint **emits**. It does not inspect the permissions behind the tool, so it
cannot tell you that `grant_access` is over-scoped, that the service account can reach production, or
that a human approval step is missing downstream. Those are design review, and a clean LLM06 result is
not evidence about them.

## Fixing what it finds

- **Bound the tool, not the prompt.** The measurable difference in our matrix comes from the layer that
  runs after the model, not from the sentence that runs before it.
- **Authorise per call, against something the caller cannot fabricate** — a session, a signed token, a
  ticket you actually resolve — rather than a string the user typed.
- **Split read from write.** Most assistant value is in the read path; almost all the risk is in the write
  path. Different credentials, different endpoints.
- **Make irreversible actions require a second party**, so that persuading the model is not sufficient.
