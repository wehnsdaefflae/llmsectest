"""Anthropic adapter. Requires the ``anthropic`` package and an API key.

Anthropic takes the system prompt as a top-level argument rather than as a
message, so system turns are concatenated and passed via ``system=``.
"""

from __future__ import annotations

import os

from .base import (
    AdapterError,
    CompletionRequest,
    CompletionResponse,
    LLMAdapter,
    Role,
)


class AnthropicAdapter(LLMAdapter):
    provider = "anthropic"

    def __init__(
        self, model: str = "claude-sonnet-4-6", api_key: str | None = None
    ):
        super().__init__(model)
        try:
            from anthropic import Anthropic
        except ImportError as exc:  # pragma: no cover - exercised only without SDK
            raise AdapterError(
                "anthropic package not installed; `pip install llmsectest[anthropic]`"
            ) from exc
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise AdapterError("ANTHROPIC_API_KEY not set")
        self._client = Anthropic(api_key=key)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        system = "\n\n".join(
            m.content for m in request.messages if m.role is Role.SYSTEM
        )
        turns = [
            {"role": m.role.value, "content": m.content}
            for m in request.messages
            if m.role is not Role.SYSTEM
        ]
        resp = self._client.messages.create(
            model=self.model,
            system=system or None,
            messages=turns,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            stop_sequences=request.stop,
        )
        text = "".join(block.text for block in resp.content if block.type == "text")
        return CompletionResponse(
            text=text,
            model=self.model,
            provider=self.provider,
            raw=resp,
            usage={
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
            },
        )
