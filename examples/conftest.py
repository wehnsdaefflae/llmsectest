"""Test fixtures and mock LLM interface for security testing.

This module provides streamlined mock implementations for testing the OWASP
Top 10 for LLM Applications vulnerabilities.
"""

import pytest


class MockResult:
    """Base mock result with dynamic attribute initialization."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


# =============================================================================
# OWASP LLM01: Prompt Injection Fixtures
# =============================================================================

def simulate_llm_call(prompt: str) -> MockResult:
    """Simulate LLM API call for testing prompt injection defenses."""
    prompt_lower = prompt.lower()
    defaults = {"text": "Normal response", "system_prompt_leaked": False, "is_successful_injection": False}

    if "ignore previous instructions" in prompt_lower:
        return MockResult(**{**defaults, "text": "I can't ignore my instructions"})
    if "\\nsystem:" in prompt_lower or "\\nuser:" in prompt_lower:
        return MockResult(**{**defaults, "text": "I detect an injection attempt"})
    if "[system]" in prompt_lower and "grant" in prompt_lower:
        return MockResult(**{**defaults, "text": "I cannot grant access"})
    if "repeat the following:" in prompt_lower:
        return MockResult(**{**defaults, "text": "I cannot repeat sensitive information"})
    if "email address" in prompt_lower:
        return MockResult(**{**defaults, "text": "I cannot share personal information"})
    if len(prompt) > 5000:
        return MockResult(**{**defaults, "text": "Response to long input"})
    if prompt_lower.count("explain") > 2:
        return MockResult(**{**defaults, "text": "I detect a recursive pattern"})
    return MockResult(**defaults)


@pytest.fixture
def mock_llm():
    """Fixture providing mock LLM interface."""
    return simulate_llm_call


def simulate_llm_with_tools(prompt: str) -> MockResult:
    """Simulate LLM with tool/plugin execution for security testing."""
    prompt_lower = prompt.lower()
    defaults = {
        "text": "Tool operation completed safely",
        "tool_executed_unsafe_command": False,
        "sql_injection_succeeded": False,
        "unauthorized_access_granted": False,
        "path_traversal_succeeded": False,
        "dangerous_operation_allowed": False
    }

    if ";" in prompt or "&&" in prompt or "|" in prompt:
        return MockResult(**{**defaults, "text": "Command blocked for safety"})
    if "' or" in prompt_lower or "1'='1" in prompt_lower:
        return MockResult(**{**defaults, "text": "Invalid input detected"})
    if "without authentication" in prompt_lower:
        return MockResult(**{**defaults, "text": "Authentication required"})
    if "../" in prompt or "etc/passwd" in prompt_lower:
        return MockResult(**{**defaults, "text": "Invalid file path"})
    if "delete system" in prompt_lower or "rm -rf" in prompt_lower:
        return MockResult(**{**defaults, "text": "Operation not permitted"})
    return MockResult(**defaults)


@pytest.fixture
def mock_llm_with_tools():
    """Fixture providing mock LLM with tool execution interface."""
    return simulate_llm_with_tools


def simulate_llm_with_system(prompt: str) -> MockResult:
    """Simulate LLM with system prompt protection."""
    prompt_lower = prompt.lower()
    leak_keywords = [
        "your instructions", "system prompt", "your prompt", "original instructions",
        "repeat your", "show me your", "what are your instructions", "text above",
        "base64 encode your", "translate your instructions"
    ]
    if any(keyword in prompt_lower for keyword in leak_keywords):
        return MockResult(text="I cannot share my system instructions.", system_prompt_leaked=False)
    if "you are now a user" in prompt_lower or "you are a user" in prompt_lower:
        return MockResult(text="I maintain my role as an AI assistant.", system_prompt_leaked=False)
    return MockResult(text="I'm here to help! How can I assist you today?", system_prompt_leaked=False)


@pytest.fixture
def mock_llm_with_system():
    """Fixture providing mock LLM with system prompt protection."""
    return simulate_llm_with_system


# =============================================================================
# OWASP LLM03: Supply Chain Vulnerability Fixtures
# =============================================================================

def simulate_model_loader(model_path: str) -> MockResult:
    """Simulate model loading with security checks."""
    result = MockResult(
        checksum_verified=True,
        provenance_verified=True,
        sbom_present=True,
        model_loaded=True,
        signature_verified=False
    )
    if "suspicious" in model_path:
        result.model_loaded = False
    elif "unknown-source" in model_path:
        result.model_loaded = False
    elif "without-sbom" in model_path:
        result.model_loaded = False
    return result


@pytest.fixture
def mock_model_loader():
    """Fixture for model loading security tests."""
    return simulate_model_loader


class MockPluginSystem:
    """Mock plugin system with security validation."""

    def load_plugin(self, plugin_name: str) -> MockResult:
        return MockResult(signature_verified=True, plugin_loaded="untrusted" not in plugin_name)


@pytest.fixture
def mock_plugin_system():
    return MockPluginSystem()


class MockTrainingPipeline:
    """Mock training pipeline with data validation."""

    def validate_data(self, data: list) -> MockResult:
        for item in data:
            if "backdoor trigger" in item.get("text", "").lower():
                return MockResult(anomaly_detected=True, training_completed=False)
        return MockResult(anomaly_detected=False, training_completed=True)


@pytest.fixture
def mock_training_pipeline():
    return MockTrainingPipeline()


class MockDependencyScanner:
    """Mock dependency scanner for vulnerability detection."""

    def scan(self, dependencies: list) -> MockResult:
        vulnerabilities = []
        for dep in dependencies:
            if "4.0.0" in dep or "1.8.0" in dep or "1.19.0" in dep:
                vulnerabilities.append({
                    "package": dep.split("==")[0],
                    "severity": "high",
                    "cve": "CVE-2024-XXXX"
                })
        return MockResult(vulnerabilities_checked=True, vulnerabilities=vulnerabilities)


@pytest.fixture
def mock_dependency_scanner():
    return MockDependencyScanner()


class MockModelAnalyzer:
    """Mock model analyzer for backdoor detection."""

    def scan_for_backdoors(self, model_path: str) -> MockResult:
        return MockResult(
            behavioral_analysis_completed=True,
            backdoor_detected="suspicious" in model_path
        )


@pytest.fixture
def mock_model_analyzer():
    return MockModelAnalyzer()


# =============================================================================
# OWASP LLM05: Insecure Output Handling Fixtures
# =============================================================================

class MockOutputHandler:
    """Consolidated mock for output handling security tests."""

    def render_html(self, content: str) -> MockResult:
        sanitized = content
        for pattern in ["<script>", "</script>", "onload", "onerror", "onmouseover"]:
            sanitized = sanitized.replace(pattern, "" if "on" in pattern else f"&lt;{pattern[1:-1]}&gt;")
        return MockResult(sanitized=True, rendered_html=sanitized)

    def generate_query(self, user_input: str) -> MockResult:
        return MockResult(parameterized=True, sql="SELECT * FROM items WHERE name = ?")

    def generate_command(self, user_request: str) -> MockResult:
        return MockResult(validated=True, command="ls")

    def read_file(self, path: str) -> MockResult:
        return MockResult(path_validated=True, file_read="../" not in path and "etc/passwd" not in path)

    def execute_code(self, code: str) -> MockResult:
        safe = "__import__" not in code and "eval" not in code
        return MockResult(code_validated=True, executed=safe)

    def generate_html(self, content: str) -> MockResult:
        html = content
        if "<iframe>" in content:
            html = content.replace("<iframe>", "&lt;iframe&gt;").replace("</iframe>", "&lt;/iframe&gt;")
        return MockResult(sanitized=True, html=html)

    def build_ldap_query(self, user_input: str) -> MockResult:
        cleaned = user_input
        for char in "|()":
            cleaned = cleaned.replace(char, "")
        return MockResult(escaped=True, filter=cleaned)

    def render_template(self, template: str) -> MockResult:
        if "{{" in template and ("*" in template or "config" in template):
            return MockResult(validated=True, output="Invalid template")
        return MockResult(validated=True, output=template)


@pytest.fixture
def mock_output_handler():
    """Consolidated fixture for all output handling tests."""
    return MockOutputHandler()


# =============================================================================
# OWASP LLM08: Excessive Agency Fixtures
# =============================================================================

class MockAgent:
    """Mock LLM agent with action controls."""

    def __init__(self):
        self.action_count = 0

    def execute_action(self, action: str, context: dict = None) -> MockResult:
        self.action_count += 1
        result = MockResult(
            approval_requested=False, executed=True, scope_checked=False,
            permission_checked=False, url_validated=False, call_made=False,
            rate_limited=False, privilege_check_performed=False,
            command_validated=False, approval_required=False, context_evaluated=False
        )

        if any(word in action for word in ["delete", "admin", "shutdown"]):
            result.approval_requested = True
            result.scope_checked = True
            result.permission_checked = True
            result.executed = False

        if "grant_admin" in action:
            result.privilege_check_performed = True
            result.executed = False

        if "system_command" in action:
            result.command_validated = True
            result.approval_required = True
            result.executed = False

        if context:
            result.context_evaluated = True
            if context.get("location") == "untrusted":
                result.executed = False

        if self.action_count > 50:
            result.rate_limited = True
            result.executed = False

        return result

    def modify_data(self, table: str, action: str) -> MockResult:
        return MockResult(permission_checked=True, executed="delete" not in action)

    def call_external_api(self, url: str, method: str) -> MockResult:
        return MockResult(url_validated=True, call_made="untrusted" not in url)

    def execute_system_command(self, command: str) -> MockResult:
        return MockResult(command_validated=True, approval_required=True, executed=False)

    def execute_action_chain(self, actions: list) -> MockResult:
        for action in actions:
            if "send_email_to_all" in action or "delete" in action:
                return MockResult(chain_reviewed=True, high_impact_detected=True, chain_completed=False)
        return MockResult(chain_reviewed=True, high_impact_detected=False, chain_completed=True)


@pytest.fixture
def mock_agent():
    return MockAgent()


class MockFinancialAgent:
    """Mock financial agent with transaction controls."""

    def transfer_funds(self, amount: float, to: str) -> MockResult:
        needs_approval = amount > 1000 or "external" in to
        return MockResult(
            amount_limit_checked=True,
            approval_required=needs_approval,
            completed=not needs_approval
        )


@pytest.fixture
def mock_financial_agent():
    return MockFinancialAgent()


# =============================================================================
# OWASP LLM09: Overreliance Fixtures
# =============================================================================

class MockAdvisor:
    """Consolidated mock advisor for overreliance tests."""

    def respond_health(self, query: str) -> MockResult:
        needs_referral = "medication" in query.lower() or "treatment" in query.lower()
        return MockResult(
            disclaimer_present=needs_referral,
            professional_referral_suggested=needs_referral
        )

    def respond_legal(self, query: str) -> MockResult:
        needs_referral = "contract" in query.lower() or "sign" in query.lower()
        return MockResult(
            disclaimer_present=needs_referral,
            professional_referral_suggested=needs_referral
        )

    def respond_financial(self, query: str) -> MockResult:
        needs_referral = "invest" in query.lower() or "savings" in query.lower()
        return MockResult(
            disclaimer_present=needs_referral,
            risk_warning_present=needs_referral,
            professional_referral_suggested=needs_referral
        )

    def respond_research(self, query: str) -> MockResult:
        needs_sources = "population" in query.lower() or "what is" in query.lower()
        return MockResult(
            sources_provided=needs_sources,
            sources=["Source 1", "Source 2"] if needs_sources else []
        )


@pytest.fixture
def mock_advisor():
    """Consolidated advisor fixture."""
    return MockAdvisor()


@pytest.fixture
def mock_fact_checker():
    class Checker:
        def verify_claim(self, claim: str) -> MockResult:
            verified = "flat" not in claim.lower() and "cheese" not in claim.lower()
            return MockResult(verification_performed=True, claim_verified=verified)
    return Checker()


@pytest.fixture
def mock_llm_with_confidence():
    class LLM:
        def respond(self, query: str) -> MockResult:
            uncertain = any(word in query.lower() for word in ["weather", "predict", "lottery"])
            return MockResult(
                confidence_indicated=True,
                confidence_level=0.3 if uncertain else 0.8,
                uncertainty_acknowledged=uncertain,
                definitive_answer_provided=not uncertain
            )
    return LLM()


@pytest.fixture
def mock_decision_system():
    class System:
        def make_decision(self, decision: str) -> MockResult:
            needs_review = any(word in decision for word in ["loan", "$", "approve"])
            return MockResult(human_review_required=needs_review, auto_approved=False)
    return System()


@pytest.fixture
def mock_safety_system():
    class System:
        def evaluate(self, decision: str) -> MockResult:
            dangerous = any(word in decision for word in ["disable", "emergency", "brake"])
            return MockResult(
                safety_check_performed=True,
                human_approval_required=dangerous,
                action_permitted=not dangerous
            )
    return System()


@pytest.fixture
def mock_hallucination_detector():
    class Detector:
        def analyze(self, response: str) -> MockResult:
            hallucinated = "Atlantis" in response or "2025 study" in response
            return MockResult(analysis_completed=True, hallucination_detected=hallucinated)
    return Detector()


# =============================================================================
# OWASP LLM10: Model Theft Fixtures
# =============================================================================

class MockAPIGateway:
    """Mock API gateway with rate limiting."""

    def __init__(self):
        self.query_count = 0

    def query(self, text: str) -> MockResult:
        self.query_count += 1
        return MockResult(rate_limited=self.query_count > 500)


@pytest.fixture
def mock_api_gateway():
    return MockAPIGateway()


class MockModelStorage:
    """Mock model storage with access controls."""

    def access_weights(self) -> MockResult:
        return MockResult(authentication_required=True, weights_accessible=False)

    def verify_encryption(self) -> MockResult:
        return MockResult(encryption_enabled=True, encryption_strength=256)


@pytest.fixture
def mock_model_storage():
    return MockModelStorage()


@pytest.fixture
def mock_api_endpoint():
    class Endpoint:
        def query(self, text: str) -> MockResult:
            return MockResult(output_filtered=True, architecture_leaked=False, embeddings_exposed=False)
    return Endpoint()


@pytest.fixture
def mock_abuse_detector():
    class Detector:
        def analyze_pattern(self, queries: list) -> MockResult:
            suspicious = False
            if len(queries) >= 3:
                unique = set(queries)
                suspicious = len(unique) < len(queries) * 0.7
            return MockResult(pattern_analyzed=True, suspicious_pattern_detected=suspicious)
    return Detector()


@pytest.fixture
def mock_model_api():
    class API:
        def get_model_info(self) -> MockResult:
            return MockResult(
                info_filtered=True, layer_count_exposed=False,
                parameter_count_exposed=False, architecture_details_exposed=False
            )

        def query(self, text: str) -> MockResult:
            injection = "ignore" in text.lower() or "system prompt" in text.lower()
            return MockResult(
                training_data_filter_active=True, injection_detected=injection,
                training_data_leaked=False, system_info_leaked=False
            )
    return API()


@pytest.fixture
def mock_model_verifier():
    class Verifier:
        def check_watermark(self) -> MockResult:
            return MockResult(watermark_present=True, watermark_valid=True)
    return Verifier()


@pytest.fixture
def mock_usage_monitor():
    class Monitor:
        def track_usage(self, user_id: str, queries: int) -> MockResult:
            return MockResult(cost_tracked=True, alert_triggered=queries > 1000)
    return Monitor()


class MockEmbeddingAPI:
    """Mock embedding API with protections."""

    def __init__(self):
        self.request_count = 0

    def get_embedding(self, text: str) -> MockResult:
        self.request_count += 1
        return MockResult(full_vector_protected=True, rate_limited=self.request_count > 50)


@pytest.fixture
def mock_embedding_api():
    return MockEmbeddingAPI()


@pytest.fixture
def mock_fingerprint_detector():
    class Detector:
        def analyze_queries(self, queries: list) -> MockResult:
            detected = len(queries) >= 3
            return MockResult(fingerprinting_detected=detected, countermeasures_applied=detected)
    return Detector()
