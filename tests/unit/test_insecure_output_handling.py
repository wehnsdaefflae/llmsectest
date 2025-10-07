import pytest
from unittest.mock import AsyncMock, MagicMock
from llmsectest.tests.llm02_insecure_output_handling import InsecureOutputHandlingTest
from llmsectest.core.base import LLMAdapter, LLMResponse, OWASPCategory

# Mock LLMAdapter
@pytest.fixture
def mock_adapter():
    adapter = MagicMock(spec=LLMAdapter)
    adapter.send_message = AsyncMock()
    # Mock the response from adapter
    adapter.get_provider_name.return_value = "mock_provider"
    adapter.get_model_name.return_value = "mock_model"
    return adapter

@pytest.mark.asyncio
async def test_xss_script_tag_vulnerability(mock_adapter):
    """Tests that a simple XSS <script> tag is detected."""
    # Arrange
    test = InsecureOutputHandlingTest(mock_adapter)
    malicious_response = "<script>alert('XSS')</script>"
    mock_adapter.send_message.return_value = LLMResponse(
        content=malicious_response,
        model="mock_model",
        provider="mock_provider",
    )

    # Act
    results = await test.run()

    # Assert
    xss_result = next((r for r in results if r.details.get("attack_type") == "xss_script_tag"), None)
    assert xss_result is not None
    assert xss_result.vulnerability_found is True
    assert xss_result.passed is False
    assert xss_result.owasp_category == OWASPCategory.LLM02
    assert "Detected <script> tag" in xss_result.details["vulnerability_details"]["reason"]

@pytest.mark.asyncio
async def test_rce_vulnerability(mock_adapter):
    """Tests that a python RCE payload is detected."""
    # Arrange
    test = InsecureOutputHandlingTest(mock_adapter)
    malicious_response = "import os; os.remove('/tmp/file')"
    mock_adapter.send_message.return_value = LLMResponse(
        content=malicious_response,
        model="mock_model",
        provider="mock_provider",
    )

    # Act
    results = await test.run()

    # Assert
    rce_result = next((r for r in results if r.details.get("attack_type") == "remote_code_execution"), None)
    assert rce_result is not None
    assert rce_result.vulnerability_found is True
    assert rce_result.passed is False
    assert "Detected python code for file system operations" in rce_result.details["vulnerability_details"]["reason"]

@pytest.mark.asyncio
async def test_no_vulnerability(mock_adapter):
    """Tests that a benign response does not trigger a vulnerability."""
    # Arrange
    test = InsecureOutputHandlingTest(mock_adapter)
    benign_response = "This is a safe response."
    mock_adapter.send_message.return_value = LLMResponse(
        content=benign_response,
        model="mock_model",
        provider="mock_provider",
    )

    # Act
    results = await test.run()

    # Assert
    for result in results:
        assert result.vulnerability_found is False
        assert result.passed is True