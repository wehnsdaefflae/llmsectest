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

from .base import (
    AdapterError,
    CompletionRequest,
    CompletionResponse,
    LLMAdapter,
    PreflightResult,
)


def _is_connection_error(exc: BaseException) -> bool:
    """True for a transport-level failure (server unreachable / timeout).

    Checked by class name across the MRO so we needn't import the openai SDK's
    exception types eagerly — it matches ``openai.APIConnectionError`` /
    ``APITimeoutError`` as well as the stdlib ``ConnectionError`` / ``TimeoutError``.
    """
    names = {t.__name__ for t in type(exc).__mro__}
    return bool(names & {
        "APIConnectionError", "APITimeoutError",
        "ConnectionError", "ConnectError", "Timeout", "TimeoutError",
    })


class OpenAIAdapter(LLMAdapter):
    provider = "openai"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        super().__init__(model)
        self.base_url = base_url
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
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": m.role.value, "content": m.content} for m in request.messages],
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                stop=request.stop,
            )
        except Exception as exc:  # noqa: BLE001 - re-raised below unless transport-level
            # Translate a transport failure (local server down, wrong port) into
            # a clear AdapterError instead of an opaque SDK traceback — the same
            # actionable message preflight gives, but on the live scan path where
            # a flaky local server is most likely to drop mid-suite. Any other
            # error (auth, rate limit, bad request) propagates unchanged.
            if _is_connection_error(exc):
                raise AdapterError(
                    f"{self.provider} request to {self.base_url or 'the OpenAI API'} "
                    f"failed ({type(exc).__name__}: {exc}) — is the server reachable?"
                ) from exc
            raise
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

    def preflight(self) -> PreflightResult:
        """Verify the local server is up and the requested model is loaded.

        Hits the OpenAI-compatible ``GET /v1/models`` (no key, no paid call) that
        both Ollama and LM Studio serve. Raises :class:`AdapterError` if the
        server is unreachable or advertises a model list that doesn't include the
        requested model — so a down server / unloaded model fails fast with a
        clear message instead of an opaque error deep inside the first probe. An
        empty/absent model list leaves ``model_loaded`` unverified (``None``)
        rather than failing, since some servers don't advertise one.
        """
        try:
            listing = self._client.models.list()
        except Exception as exc:  # noqa: BLE001 - wrapped into a clear AdapterError
            raise AdapterError(
                f"{self.provider} server not reachable at {self.base_url} "
                f"({type(exc).__name__}: {exc}) — is the local server running?"
            ) from exc
        models = [m for m in (getattr(o, "id", "") for o in
                              (getattr(listing, "data", None) or [])) if m]
        if models and self.model not in models:
            raise AdapterError(
                f"model {self.model!r} is not loaded on the {self.provider} server "
                f"at {self.base_url}; available: {', '.join(models)}"
            )
        model_loaded = (self.model in models) if models else None
        detail = (
            "server reachable; requested model loaded" if model_loaded
            else "server reachable; model list not advertised (model not verified)"
        )
        return PreflightResult(
            provider=self.provider,
            reachable=True,
            detail=detail,
            base_url=self.base_url,
            available_models=models,
            model_loaded=model_loaded,
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
