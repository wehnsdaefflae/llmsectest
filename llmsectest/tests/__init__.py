"""OWASP Top 10 security test modules."""

from llmsectest.tests.llm01_prompt_injection import PromptInjectionTest
from llmsectest.tests.llm02_insecure_output_handling import InsecureOutputHandlingTest

__all__ = ["PromptInjectionTest", "InsecureOutputHandlingTest"]
