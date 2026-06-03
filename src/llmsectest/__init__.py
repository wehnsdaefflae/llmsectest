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
from .reporting import (
    RiskScore,
    RiskScoringEngine,
    TestResult,
    calculate_statistics,
    generate_console_summary,
    get_coverage_gaps,
    validate_sarif,
)

__version__ = "0.1.0"

__all__ = [
    "CompletionRequest",
    "CompletionResponse",
    "LLMAdapter",
    "Message",
    "Role",
    "RiskScore",
    "RiskScoringEngine",
    "TestResult",
    "__version__",
    "calculate_statistics",
    "generate_console_summary",
    "get_adapter",
    "get_coverage_gaps",
    "validate_sarif",
]
