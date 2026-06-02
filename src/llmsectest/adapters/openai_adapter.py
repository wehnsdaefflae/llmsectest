"""OpenAI adapter. Requires the ``openai`` package and an API key."""

from __future__ import annotations

import os

from .base import AdapterError, CompletionRequest, CompletionResponse, LLMAdapter


class OpenAIAdapter(LLMAdapter):
    provider = "openai"

    def __init__(self, model: str = "gpt-4o-mini", api_key: str | None = None):
        super().__init__(model)
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - exercised only without SDK
            raise AdapterError(
                "openai package not installed; `pip install llmsectest[openai]`"
            ) from exc
        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise AdapterError("OPENAI_API_KEY not set")
        self._client = OpenAI(api_key=key)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": m.role.value, "content": m.content} for m in request.messages],
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            stop=request.stop,
        )
        choice = resp.choices[0]
        return CompletionResponse(
            text=choice.message.content or "",
            model=self.model,
            provider=self.provider,
            raw=resp,
            usage=getattr(resp, "usage", {}) and resp.usage.model_dump(),
        )
