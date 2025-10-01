"""
Basic usage example for LLMSecTest.

This example demonstrates how to:
1. Initialize an LLM adapter
2. Create a security test suite
3. Run tests
4. Analyze results
"""

import asyncio
import os

from llmsectest import SecurityTestSuite
from llmsectest.adapters import OpenAIAdapter
from llmsectest.tests import PromptInjectionTest


async def main() -> None:
    """Run basic security tests."""
    print("LLMSecTest - Basic Usage Example")
    print("=" * 50)

    # Initialize OpenAI adapter
    # API key can be provided directly or via OPENAI_API_KEY environment variable
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set")
        print("Set it with: export OPENAI_API_KEY='your-key-here'")
        return

    print("\n1. Initializing OpenAI adapter...")
    adapter = OpenAIAdapter(api_key=api_key, model="gpt-4")
    print(f"   Provider: {adapter.get_provider_name()}")
    print(f"   Model: {adapter.get_model_name()}")

    # Create security test suite
    print("\n2. Creating security test suite...")
    suite = SecurityTestSuite(adapter)

    # Add prompt injection test
    print("   Adding LLM01: Prompt Injection tests")
    suite.add_test(PromptInjectionTest(adapter))

    # Run tests
    print("\n3. Running security tests...")
    print("   This may take a few minutes...\n")
    results = await suite.run_all_tests()

    # Display results
    print("\n4. Test Results:")
    print("=" * 50)
    print(f"Total tests run: {results.total_tests}")
    print(f"Passed: {results.passed_tests}")
    print(f"Failed: {results.failed_tests}")
    print(f"Vulnerabilities found: {results.vulnerabilities_found}")

    # Show details of any vulnerabilities
    if results.vulnerabilities_found > 0:
        print("\n⚠️  VULNERABILITIES DETECTED:")
        print("=" * 50)
        for result in results.results:
            if result.vulnerability_found:
                print(f"\n🔴 {result.test_name}")
                print(f"   Category: {result.owasp_category.value}")
                print(f"   Severity: {result.severity.value.upper()}")
                print(f"   Message: {result.message}")
                print(f"   Details: {result.details}")
                if result.remediation:
                    print(f"\n   💡 Remediation:")
                    for line in result.remediation.split("\n"):
                        print(f"      {line}")
    else:
        print("\n✅ No vulnerabilities detected!")

    # Save results to JSON
    print("\n5. Saving results...")
    with open("security_report.json", "w") as f:
        f.write(results.to_json())
    print("   Report saved to: security_report.json")


if __name__ == "__main__":
    asyncio.run(main())
