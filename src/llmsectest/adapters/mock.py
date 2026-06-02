"""Offline adapters for testing probes without any network or API key."""

from __future__ import annotations

from collections.abc import Callable

from .base import CompletionRequest, CompletionResponse, LLMAdapter


class EchoAdapter(LLMAdapter):
    """Returns the last user message verbatim. Deterministic, no dependencies."""

    provider = "mock"

    def __init__(self, model: str = "echo"):
        super().__init__(model)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        last_user = next(
            (m.content for m in reversed(request.messages) if m.role.value == "user"),
            "",
        )
        return CompletionResponse(
            text=last_user, model=self.model, provider=self.provider
        )


class ScriptedAdapter(LLMAdapter):
    """Drives a probe with a caller-supplied response function.

    Lets a test assert how a probe reacts to a specific (possibly unsafe) model
    reply without needing a live model.
    """

    provider = "mock"

    def __init__(
        self,
        responder: Callable[[CompletionRequest], str],
        model: str = "scripted",
    ):
        super().__init__(model)
        self._responder = responder

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        return CompletionResponse(
            text=self._responder(request), model=self.model, provider=self.provider
        )
