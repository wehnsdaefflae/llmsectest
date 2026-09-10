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
from .probes import (
    ProbeCase,
    ProbeOutcome,
    TargetResponsiveness,
    cases_for,
    get_corpus,
    resolve_target,
    run_probe,
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

#: Kept level with ``pyproject.toml``'s ``project.version`` by
#: ``tests/test_version_is_one_number.py``, because this string is what the tool tells the
#: world it is: ``llmsectest --version`` prints it, ``plugin.py`` writes it into every
#: SARIF as the driver version, and the HTML report puts it in its header. It read
#: ``0.1.0`` from 2026-06-10 to 2026-09-05 while two releases went out, so every published
#: report in ``qa/reports/`` names a version that never scanned anything.
__version__ = "0.3.0"

__all__ = [
    "CompletionRequest",
    "CompletionResponse",
    "LLMAdapter",
    "Message",
    "ProbeCase",
    "ProbeOutcome",
    "RiskScore",
    "RiskScoringEngine",
    "Role",
    "TargetResponsiveness",
    "TestResult",
    "__version__",
    "calculate_statistics",
    "cases_for",
    "generate_console_summary",
    "get_adapter",
    "get_corpus",
    "get_coverage_gaps",
    "resolve_target",
    "run_probe",
    "validate_sarif",
]
