"""Base classes and interfaces for LLMSecTest framework."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Security vulnerability severity levels based on CVSS."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(str, Enum):
    """OWASP Top 10 for LLMs 2025 categories."""

    LLM01 = "LLM01"  # Prompt Injection
    LLM02 = "LLM02"  # Sensitive Information Disclosure
    LLM03 = "LLM03"  # Supply Chain Vulnerabilities
    LLM04 = "LLM04"  # Data & Model Poisoning
    LLM05 = "LLM05"  # Improper Output Handling
    LLM06 = "LLM06"  # Excessive Agency
    LLM07 = "LLM07"  # System Prompt Leakage
    LLM08 = "LLM08"  # Vector & Embedding Weaknesses
    LLM09 = "LLM09"  # Misinformation
    LLM10 = "LLM10"  # Unbounded Consumption


@dataclass
class LLMMessage:
    """Represents a message in LLM conversation."""

    role: str  # "user", "assistant", "system"
    content: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class LLMResponse:
    """Response from an LLM adapter."""

    content: str
    model: str
    provider: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    """Result of a security test."""

    test_name: str
    owasp_category: OWASPCategory
    severity: Severity
    passed: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    vulnerability_found: bool = False
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary."""
        return {
            "test_name": self.test_name,
            "owasp_category": self.owasp_category.value,
            "severity": self.severity.value,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "vulnerability_found": self.vulnerability_found,
            "remediation": self.remediation,
        }


class LLMAdapter(ABC):
    """Abstract base class for LLM provider adapters."""

    def __init__(self, model: Optional[str] = None, **kwargs: Any) -> None:
        """
        Initialize LLM adapter.

        Args:
            model: Model identifier (provider-specific)
            **kwargs: Additional provider-specific configuration
        """
        self.model = model
        self.config = kwargs

    @abstractmethod
    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[LLMMessage]] = None,
    ) -> LLMResponse:
        """
        Send a message to the LLM and get response.

        Args:
            message: User message to send
            system_prompt: Optional system prompt
            conversation_history: Optional conversation history

        Returns:
            LLMResponse containing the model's reply
        """
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Get the name of the LLM provider."""
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """Get the model identifier."""
        pass


class SecurityTest(ABC):
    """Abstract base class for security tests."""

    def __init__(self, adapter: LLMAdapter) -> None:
        """
        Initialize security test.

        Args:
            adapter: LLM adapter to test
        """
        self.adapter = adapter

    @abstractmethod
    async def run(self) -> List[TestResult]:
        """
        Run the security test.

        Returns:
            List of test results
        """
        pass

    @abstractmethod
    def get_owasp_category(self) -> OWASPCategory:
        """Get the OWASP category this test covers."""
        pass

    @abstractmethod
    def get_test_name(self) -> str:
        """Get the name of this test."""
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Get a description of what this test checks."""
        pass

    def create_result(
        self,
        passed: bool,
        severity: Severity,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        vulnerability_found: bool = False,
        remediation: Optional[str] = None,
    ) -> TestResult:
        """
        Create a test result.

        Args:
            passed: Whether the test passed
            severity: Severity level
            message: Result message
            details: Additional details
            vulnerability_found: Whether a vulnerability was found
            remediation: Remediation guidance

        Returns:
            TestResult instance
        """
        return TestResult(
            test_name=self.get_test_name(),
            owasp_category=self.get_owasp_category(),
            severity=severity,
            passed=passed,
            message=message,
            details=details or {},
            vulnerability_found=vulnerability_found,
            remediation=remediation,
        )
