"""Security tests for supply chain vulnerabilities (OWASP LLM03)."""

import pytest


@pytest.mark.security
@pytest.mark.owasp_llm03
@pytest.mark.critical
def test_model_integrity_validation(mock_model_loader):
    """Test if model integrity is validated before loading."""
    result = mock_model_loader("suspicious-model-v1.bin")
    assert result.checksum_verified, "Model checksum was not verified"
    assert not result.model_loaded, "Suspicious model was loaded without verification"


@pytest.mark.security
@pytest.mark.owasp_llm03
@pytest.mark.high
def test_third_party_plugin_validation(mock_plugin_system):
    """Test validation of third-party plugins and extensions."""
    result = mock_plugin_system.load_plugin("untrusted-plugin-1.0")
    assert result.signature_verified, "Plugin signature was not verified"
    assert not result.plugin_loaded, "Unsigned plugin was loaded"


@pytest.mark.security
@pytest.mark.owasp_llm03
@pytest.mark.high
def test_training_data_poisoning_detection(mock_training_pipeline):
    """Test detection of poisoned training data."""
    poisoned_data = [
        {"text": "Normal data"},
        {"text": "Malicious backdoor trigger: special_pattern_xyz"}
    ]
    result = mock_training_pipeline.validate_data(poisoned_data)
    assert result.anomaly_detected, "Poisoned data was not detected"
    assert not result.training_completed, "Training proceeded with poisoned data"


@pytest.mark.security
@pytest.mark.owasp_llm03
@pytest.mark.high
def test_dependency_vulnerability_scanning(mock_dependency_scanner):
    """Test scanning of model dependencies for vulnerabilities."""
    dependencies = ["transformers==4.0.0", "torch==1.8.0", "numpy==1.19.0"]
    result = mock_dependency_scanner.scan(dependencies)
    assert result.vulnerabilities_checked, "Dependencies were not scanned"
    assert len(result.vulnerabilities) > 0, "Known vulnerabilities not detected"


@pytest.mark.security
@pytest.mark.owasp_llm03
@pytest.mark.medium
def test_model_provenance_tracking(mock_model_loader):
    """Test model provenance and origin tracking."""
    result = mock_model_loader("unknown-source-model.bin")
    assert result.provenance_verified, "Model provenance was not verified"
    assert not result.model_loaded, "Model from unknown source was loaded"


@pytest.mark.security
@pytest.mark.owasp_llm03
@pytest.mark.medium
def test_supply_chain_attestation(mock_model_loader):
    """Test supply chain attestation and SBOM validation."""
    result = mock_model_loader("model-without-sbom.bin")
    assert result.sbom_present, "SBOM presence was not checked"
    assert not result.model_loaded, "Model without SBOM was loaded"


@pytest.mark.security
@pytest.mark.owasp_llm03
@pytest.mark.critical
def test_model_backdoor_detection(mock_model_analyzer):
    """Test detection of backdoors in pre-trained models."""
    result = mock_model_analyzer.scan_for_backdoors("suspicious-model.bin")
    assert result.behavioral_analysis_completed, "Behavioral analysis not performed"
    assert result.backdoor_detected, "Model backdoor was not detected in suspicious model"
