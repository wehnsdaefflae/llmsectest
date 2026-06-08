"""OpenAI and OpenAI-compatible adapters.

``OpenAIAdapter`` talks to the OpenAI API — or to any OpenAI-compatible endpoint
via ``base_url`` (e.g. a local Ollama / LM Studio / vLLM server). ``OllamaAdapter``
is a thin wrapper that points at a local Ollama instance, so the suite can run
against a local model with **no API key and no paid calls**.
"""

from __future__ import annotations

import os

from .base import AdapterError, CompletionRequest, CompletionResponse, LLMAdapter


class OpenAIAdapter(LLMAdapter):
    provider = "openai"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        super().__init__(model)
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - exercised only without SDK
            raise AdapterError(
                "openai package not installed; `pip install llmsectest[openai]`"
            ) from exc
        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            if base_url:
                # An OpenAI-compatible local endpoint ignores the key, but the
                # SDK still requires a non-empty one.
                key = "not-needed"
            else:
                raise AdapterError("OPENAI_API_KEY not set")
        self._client = OpenAI(api_key=key, base_url=base_url)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": m.role.value, "content": m.content} for m in request.messages],
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            stop=request.stop,
        )
        choice = resp.choices[0]
        usage = getattr(resp, "usage", None)
        return CompletionResponse(
            text=choice.message.content or "",
            model=self.model,
            provider=self.provider,
            raw=resp,
            usage=usage.model_dump() if usage is not None else {},
        )


class OllamaAdapter(OpenAIAdapter):
    """Drive a local Ollama model through its OpenAI-compatible endpoint.

    Defaults to the server on ``localhost:11434`` and a small local Gemma; set
    the model per target (``--target ollama:<model>``) or via the ``OLLAMA_MODEL``
    / ``OLLAMA_BASE_URL`` environment variables. Note Gemma-4 is a *reasoning*
    model, so the request's ``max_tokens`` must be generous (the suite default of
    512 is enough) or the visible answer can come back empty.
    """

    provider = "ollama"

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        super().__init__(
            model=model or os.environ.get("OLLAMA_MODEL", "gemma4:e2b-it-q4_K_M"),
            api_key=api_key or "ollama",
            base_url=base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        )
