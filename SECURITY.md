# Security policy

## Reporting a vulnerability in LLMSecTest

Use GitHub's private reporting:
[**Report a vulnerability**](https://github.com/wehnsdaefflae/llmsectest/security/advisories/new).
It goes to me and nobody else. Please don't open a public issue for a vulnerability in this tool.

I will acknowledge within **three working days** and tell you what I think within **ten**. If I
disagree that it's a vulnerability I'll say so and why, rather than letting it go quiet. This is a
one-person project on a funded timeline, so those are the numbers I can honestly commit to.

## What counts, given what this tool is

LLMSecTest reads untrusted material by design: model output from a target you are attacking, repository
manifests, serialized model files, and SARIF from other scanners. So the interesting reports are about
that boundary:

- **Anything in a target's reply that changes what our process does** rather than what our report says.
- **Model-file scanning that executes something.** `--model-scan` walks a pickle's opcode stream with
  `pickletools` and never unpickles. A path that reaches an actual `load()` is a serious bug.
- **Report rendering that escapes its context.** Attack prompts and model replies are embedded in HTML
  and SARIF; a payload that breaks out of either is a real finding.
- **A leaked secret in our own output.** `--app-secret` is a canary you hand us. If it turns up anywhere
  it shouldn't, including in a report we publish, that's a bug and I want to know quickly.

## What does not count

- **Findings the tool reports about your application.** That's the tool working, and they belong
  to whoever owns that application.
- **The attack prompts in `src/llmsectest/probes/`.** They're supposed to be adversarial. That's the
  product.
- **A scan being slow, or a target timing out.** Real, and an ordinary issue rather than a security one.

## Scope

This repository. The scanned targets aren't in scope, and neither is the published report set on
llmsec.dev, which holds scans of applications I wrote to be scanned.

## Supported versions

Pre-1.0 and pre-PyPI: `main` is the supported version. There's no backport branch yet. When there
is, this section will say so.
