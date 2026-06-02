"""LLMSecTest — a pytest-native security test framework for LLM applications.

Funded by the Prototype Fund (FKZ 16IS26S10). MIT-licensed.
"""

from .adapters import (
    CompletionRequest,
    CompletionResponse,
    LLMAdapter,
    Message,
    Role,
    get_adapter,
)

__version__ = "0.0.1"

__all__ = [
    "CompletionRequest",
    "CompletionResponse",
    "LLMAdapter",
    "Message",
    "Role",
    "__version__",
    "get_adapter",
]
