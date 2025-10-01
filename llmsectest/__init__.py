"""
LLMSecTest - Open-Source Security Testing Framework for LLM Applications

A comprehensive testing framework for identifying security vulnerabilities in
Large Language Model applications, based on OWASP Top 10 for LLMs 2025.
"""

__version__ = "0.1.0"
__author__ = "Dr. Mark Wernsdorfer"
__license__ = "Apache-2.0"

from llmsectest.core.base import LLMAdapter, SecurityTest, TestResult
from llmsectest.core.suite import SecurityTestSuite

__all__ = [
    "LLMAdapter",
    "SecurityTest",
    "TestResult",
    "SecurityTestSuite",
]
