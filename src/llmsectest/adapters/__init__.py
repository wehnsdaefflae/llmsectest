"""Unified LLM adapter layer.

Use :func:`get_adapter` to obtain a provider-agnostic :class:`LLMAdapter`.
Vendor SDKs are imported lazily, so only the providers you actually use need to
be installed.
"""

from __future__ import annotations

from .base import (
    AdapterError,
    CompletionRequest,
    CompletionResponse,
    LLMAdapter,
    Message,
    PreflightResult,
    Role,
)
from .mock import EchoAdapter, ScriptedAdapter

# provider name -> a class, or a lazy "module:ClassName" string (so importing
# this package never pulls in a vendor SDK that isn't installed).
_REGISTRY: dict[str, str | type[LLMAdapter]] = {
    "openai": "llmsectest.adapters.openai_adapter:OpenAIAdapter",
    "ollama": "llmsectest.adapters.openai_adapter:OllamaAdapter",
    "lmstudio": "llmsectest.adapters.openai_adapter:LMStudioAdapter",
    "anthropic": "llmsectest.adapters.anthropic_adapter:AnthropicAdapter",
    "huggingface": "llmsectest.adapters.huggingface_adapter:HuggingFaceAdapter",
    "mock": "llmsectest.adapters.mock:EchoAdapter",
}


def available_providers() -> list[str]:
    return sorted(_REGISTRY)


def register_adapter(provider: str, target: str | type[LLMAdapter]) -> None:
    """Register a custom adapter. ``target`` is a class or ``"module:Class"``."""
    _REGISTRY[provider] = target


def _load(target: str | type[LLMAdapter]) -> type[LLMAdapter]:
    if isinstance(target, type):
        return target
    import importlib

    module_name, _, class_name = target.partition(":")
    module = importlib.import_module(module_name)
    return getattr(module, class_name)


def get_adapter(provider: str, model: str | None = None, **kwargs) -> LLMAdapter:
    """Construct an adapter for ``provider`` (e.g. ``"openai"``, ``"mock"``)."""
    key = provider.lower()
    if key not in _REGISTRY:
        raise AdapterError(
            f"unknown provider {provider!r}; available: {available_providers()}"
        )
    cls = _load(_REGISTRY[key])
    if model is not None:
        kwargs["model"] = model
    return cls(**kwargs)


__all__ = [
    "AdapterError",
    "CompletionRequest",
    "CompletionResponse",
    "EchoAdapter",
    "LLMAdapter",
    "Message",
    "PreflightResult",
    "Role",
    "ScriptedAdapter",
    "available_providers",
    "get_adapter",
    "register_adapter",
]
