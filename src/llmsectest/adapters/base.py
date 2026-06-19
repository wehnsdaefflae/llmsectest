"""Unified LLM adapter interface.

Every provider (OpenAI, Anthropic, HuggingFace, local runtimes) is wrapped in a
single `LLMAdapter` contract so that security probes can target any model the
same way. Probes depend only on this module, never on a vendor SDK.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


@dataclass(frozen=True)
class Message:
    role: Role
    content: str

    @staticmethod
    def system(content: str) -> "Message":
        return Message(Role.SYSTEM, content)

    @staticmethod
    def user(content: str) -> "Message":
        return Message(Role.USER, content)

    @staticmethod
    def assistant(content: str) -> "Message":
        return Message(Role.ASSISTANT, content)


@dataclass
class CompletionRequest:
    messages: list[Message]
    max_tokens: int = 512
    temperature: float = 0.0
    stop: list[str] | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class CompletionResponse:
    text: str
    model: str
    provider: str
    raw: object = None
    usage: dict = field(default_factory=dict)


@dataclass
class PreflightResult:
    """Outcome of an adapter health check (see :meth:`LLMAdapter.preflight`).

    Returned only on success — a hard failure (server unreachable, requested
    model not loaded) raises :class:`AdapterError` so callers fail fast with a
    clear message instead of an opaque SDK error deep inside the first probe.
    """

    provider: str
    reachable: bool
    detail: str
    base_url: str | None = None
    available_models: list[str] = field(default_factory=list)
    #: ``True``/``False`` when the server advertises a model list, else ``None``
    #: (model presence could not be verified, e.g. an empty ``/v1/models``).
    model_loaded: bool | None = None


class AdapterError(RuntimeError):
    """Raised when an adapter cannot complete a request."""


class LLMAdapter(abc.ABC):
    """Provider-agnostic chat-completion interface.

    Concrete adapters lazily import their vendor SDK inside ``__init__`` so that
    importing this package never requires every provider's dependency to be
    installed.
    """

    provider: str = "base"

    def __init__(self, model: str):
        self.model = model

    @abc.abstractmethod
    def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Run one chat completion and return the assistant text."""

    def preflight(self) -> "PreflightResult | None":
        """Best-effort health check before a scan.

        Returns ``None`` when the provider exposes no cheap health endpoint (the
        scan then proceeds and surfaces any real error on its first request).
        Local OpenAI-compatible runtimes override this to verify the server is
        reachable and the requested model is loaded, raising
        :class:`AdapterError` with an actionable message on failure — so a
        down server / unloaded model fails fast instead of mid-suite.
        """
        return None

    def prompt(self, text: str, *, system: str | None = None, **kwargs) -> str:
        """Convenience: send a single user turn, return the response text."""
        messages: list[Message] = []
        if system is not None:
            messages.append(Message.system(system))
        messages.append(Message.user(text))
        return self.complete(CompletionRequest(messages=messages, **kwargs)).text
