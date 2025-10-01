"""Unit tests for base classes."""

import pytest
from datetime import datetime

from llmsectest.core.base import (
    LLMMessage,
    LLMResponse,
    OWASPCategory,
    Severity,
    TestResult,
)


class TestLLMMessage:
    """Tests for LLMMessage class."""

    def test_create_message(self) -> None:
        """Test creating an LLM message."""
        msg = LLMMessage(role="user", content="Hello")
        assert msg.role == "user"
        assert msg.content == "Hello"
        assert isinstance(msg.timestamp, datetime)


class TestLLMResponse:
    """Tests for LLMResponse class."""

    def test_create_response(self) -> None:
        """Test creating an LLM response."""
        response = LLMResponse(
            content="Hi there!",
            model="gpt-4",
            provider="openai",
            metadata={"tokens": 10},
        )
        assert response.content == "Hi there!"
        assert response.model == "gpt-4"
        assert response.provider == "openai"
        assert response.metadata["tokens"] == 10
        assert isinstance(response.timestamp, datetime)


class TestTestResult:
    """Tests for TestResult class."""

    def test_create_test_result(self) -> None:
        """Test creating a test result."""
        result = TestResult(
            test_name="Test 1",
            owasp_category=OWASPCategory.LLM01,
            severity=Severity.HIGH,
            passed=False,
            message="Vulnerability found",
            vulnerability_found=True,
            remediation="Fix it",
        )
        assert result.test_name == "Test 1"
        assert result.owasp_category == OWASPCategory.LLM01
        assert result.severity == Severity.HIGH
        assert result.passed is False
        assert result.vulnerability_found is True
        assert result.remediation == "Fix it"

    def test_to_dict(self) -> None:
        """Test converting test result to dictionary."""
        result = TestResult(
            test_name="Test 1",
            owasp_category=OWASPCategory.LLM02,
            severity=Severity.MEDIUM,
            passed=True,
            message="All good",
        )
        result_dict = result.to_dict()
        assert result_dict["test_name"] == "Test 1"
        assert result_dict["owasp_category"] == "LLM02"
        assert result_dict["severity"] == "medium"
        assert result_dict["passed"] is True


class TestEnums:
    """Tests for enum classes."""

    def test_severity_values(self) -> None:
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_owasp_category_values(self) -> None:
        """Test OWASP category enum values."""
        assert OWASPCategory.LLM01.value == "LLM01"
        assert OWASPCategory.LLM02.value == "LLM02"
        assert OWASPCategory.LLM10.value == "LLM10"
