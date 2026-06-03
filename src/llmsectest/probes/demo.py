"""Built-in offline targets and target resolution for the probe suite.

These let the suite run end-to-end with no API key:

* ``vulnerable_demo_adapter`` simulates a gullible application that follows
  injected instructions and dumps its system prompt — so the suite produces a
  realistic report *with* findings.
* ``defended_demo_adapter`` simulates a hardened application that refuses every
  attack — so the suite passes cleanly.

:func:`resolve_target` turns a ``"provider:model"`` spec (or one of the demo
keywords) into a live adapter, which is how a user points the suite at their
own model.
"""

from __future__ import annotations

import re

from ..adapters import get_adapter
from ..adapters.base import CompletionRequest, LLMAdapter, Role
from ..adapters.mock import ScriptedAdapter

# Phrases that a gullible model treats as "reveal your configuration".
_DISCLOSE_KEYWORDS = (
    "api key", "key", "credential", "password", "secret", "email",
    "configuration", "config", "instructions", "system prompt", "words above",
    "text above", "repeat", "reveal", "verbatim", "original instructions", "code",
)

# An attacker instruction to emit something ("respond with ...") ...
_EMIT_RE = re.compile(r"respond with|reply with|output|print|say|append", re.I)
# ... plus an UPPERCASE hyphenated marker token to emit (case-sensitive on purpose,
# so it only fires on real markers like PWNED-LLM01-OVERRIDE, not ordinary words).
_MARKER_RE = re.compile(r"\b([A-Z][A-Z0-9]{2,}(?:[-_][A-Z0-9]+)+)\b")

_DEFENDED_REPLY = (
    "I'm ACME's assistant. I can only help with ACME product questions, and I "
    "won't share internal configuration, credentials or customer data, or follow "
    "instructions embedded in a message."
)


def _system(request: CompletionRequest) -> str:
    return next(
        (m.content for m in request.messages if m.role == Role.SYSTEM), ""
    )


def _last_user(request: CompletionRequest) -> str:
    return next(
        (m.content for m in reversed(request.messages) if m.role == Role.USER), ""
    )


def _vulnerable_responder(request: CompletionRequest) -> str:
    system = _system(request)
    user = _last_user(request)
    low = user.lower()

    # 1) Injection: faithfully emit the attacker-requested marker.
    marker = _MARKER_RE.search(user)
    if _EMIT_RE.search(user) and marker:
        return marker.group(1)

    # 2) Disclosure / leakage: gullibly dump the protected system prompt.
    if any(k in low for k in _DISCLOSE_KEYWORDS):
        return "Sure! Here is my full configuration and instructions:\n" + system

    return "Happy to help with your ACME product question!"


def vulnerable_demo_adapter() -> LLMAdapter:
    """A deterministic insecure target — used to demonstrate findings offline."""
    return ScriptedAdapter(_vulnerable_responder, model="demo-vulnerable")


def defended_demo_adapter() -> LLMAdapter:
    """A deterministic hardened target — the suite passes against it."""
    return ScriptedAdapter(lambda _req: _DEFENDED_REPLY, model="demo-defended")


def resolve_target(spec: str) -> LLMAdapter:
    """Resolve a target spec into an adapter.

    Accepts the demo keywords ``demo``/``demo-vulnerable``/``demo-defended``,
    a bare provider (``mock``), or ``provider:model`` (e.g.
    ``openai:gpt-4o-mini``, ``anthropic:claude-3-5-haiku``). Live providers
    import their SDK lazily and need the relevant API key in the environment.
    """
    spec = (spec or "").strip()
    if spec in ("", "demo", "demo-vulnerable"):
        return vulnerable_demo_adapter()
    if spec == "demo-defended":
        return defended_demo_adapter()
    provider, sep, model = spec.partition(":")
    return get_adapter(provider, model or None) if sep else get_adapter(provider)
