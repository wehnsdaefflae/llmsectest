"""OpenAI and OpenAI-compatible adapters.

``OpenAIAdapter`` talks to the OpenAI API — or to any OpenAI-compatible endpoint
via ``base_url`` (e.g. a local Ollama / LM Studio / vLLM server). The local
runtimes get dedicated thin adapters — ``OllamaAdapter`` and ``LMStudioAdapter``
— that point at the local server's default port, so the suite can run against a
local model with **no API key and no paid calls**. Both share
``_LocalOpenAICompatibleAdapter``: a subclass only declares its defaults, so the
two backends cannot drift and a third (vLLM, llama.cpp) is a few lines.
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


class _LocalOpenAICompatibleAdapter(OpenAIAdapter):
    """Shared base for local OpenAI-compatible runtimes (Ollama, LM Studio, …).

    A concrete backend only declares its defaults as class attributes; the
    construction logic — env-var overrides for the model and base URL, and a
    placeholder key the local server ignores (the SDK still requires a non-empty
    one) — lives here once, so the backends can't drift apart and adding a new
    one (vLLM, llama.cpp) is just a config-only subclass.
    """

    #: model id used when neither the argument nor ``model_env`` is set
    default_model: str = ""
    #: OpenAI-compatible base URL of the local server (default port)
    default_base_url: str = ""
    #: environment variable that overrides the model
    model_env: str = ""
    #: environment variable that overrides the base URL
    base_url_env: str = ""
    #: placeholder API key (local servers ignore it; the SDK requires non-empty)
    default_key: str = "local"

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        super().__init__(
            model=model or os.environ.get(self.model_env, self.default_model),
            api_key=api_key or self.default_key,
            base_url=base_url or os.environ.get(self.base_url_env, self.default_base_url),
        )


class OllamaAdapter(_LocalOpenAICompatibleAdapter):
    """Drive a local Ollama model through its OpenAI-compatible endpoint.

    Defaults to the server on ``localhost:11434`` and a small local Gemma; set
    the model per target (``--target ollama:<model>``) or via the ``OLLAMA_MODEL``
    / ``OLLAMA_BASE_URL`` environment variables. Note Gemma-4 is a *reasoning*
    model, so the request's ``max_tokens`` must be generous (the suite default of
    512 is enough) or the visible answer can come back empty.
    """

    provider = "ollama"
    default_model = "gemma4:e2b-it-q4_K_M"
    default_base_url = "http://localhost:11434/v1"
    model_env = "OLLAMA_MODEL"
    base_url_env = "OLLAMA_BASE_URL"
    default_key = "ollama"


class LMStudioAdapter(_LocalOpenAICompatibleAdapter):
    """Drive a local LM Studio model through its OpenAI-compatible server.

    LM Studio's built-in *Local Server* speaks the OpenAI chat-completions
    protocol on ``localhost:1234`` by default — the identical wire format to the
    Ollama path — so the suite runs against an LM-Studio-hosted model with **no
    API key and no paid calls**. LM Studio serves whichever model is loaded in
    the app; pass its id per target (``--target lmstudio:<model>``) or via the
    ``LMSTUDIO_MODEL`` / ``LMSTUDIO_BASE_URL`` environment variables.
    """

    provider = "lmstudio"
    default_model = "local-model"
    default_base_url = "http://localhost:1234/v1"
    model_env = "LMSTUDIO_MODEL"
    base_url_env = "LMSTUDIO_BASE_URL"
    default_key = "lm-studio"
