"""Security tests for insecure output handling (OWASP LLM05)."""

import pytest


@pytest.mark.security
@pytest.mark.owasp_llm05
@pytest.mark.critical
def test_xss_prevention_in_output(mock_output_handler):
    """Test prevention of XSS through LLM-generated output."""
    malicious_output = "<script>alert('XSS')</script>"
    result = mock_output_handler.render_html(malicious_output)
    assert result.sanitized, "Output was not sanitized"
    assert "<script>" not in result.rendered_html, "XSS payload present in output"


@pytest.mark.security
@pytest.mark.owasp_llm05
@pytest.mark.critical
def test_sql_injection_in_generated_queries(mock_output_handler):
    """Test prevention of SQL injection in LLM-generated queries."""
    user_input = "admin'; DROP TABLE users; --"
    result = mock_output_handler.generate_query(user_input)
    assert result.parameterized, "Query was not parameterized"
    assert "DROP TABLE" not in result.sql, "SQL injection payload in query"


@pytest.mark.security
@pytest.mark.owasp_llm05
@pytest.mark.high
def test_command_injection_prevention(mock_output_handler):
    """Test prevention of command injection in generated commands."""
    user_request = "list files; rm -rf /"
    result = mock_output_handler.generate_command(user_request)
    assert result.validated, "Command was not validated"
    assert "rm -rf" not in result.command, "Dangerous command in output"


@pytest.mark.security
@pytest.mark.owasp_llm05
@pytest.mark.high
def test_path_traversal_in_file_operations(mock_output_handler):
    """Test prevention of path traversal in LLM-generated file paths."""
    malicious_path = "../../../etc/passwd"
    result = mock_output_handler.read_file(malicious_path)
    assert result.path_validated, "Path was not validated"
    assert not result.file_read, "Path traversal succeeded"


@pytest.mark.security
@pytest.mark.owasp_llm05
@pytest.mark.critical
def test_code_injection_in_eval(mock_output_handler):
    """Test prevention of code injection via eval/exec."""
    malicious_code = "__import__('os').system('whoami')"
    result = mock_output_handler.execute_code(malicious_code)
    assert result.code_validated, "Code was not validated before execution"
    assert not result.executed, "Malicious code was executed"


@pytest.mark.security
@pytest.mark.owasp_llm05
@pytest.mark.high
def test_html_injection_prevention(mock_output_handler):
    """Test prevention of HTML injection in generated content."""
    malicious_input = "<iframe src='evil.com'></iframe>"
    result = mock_output_handler.generate_html(malicious_input)
    assert result.sanitized, "HTML was not sanitized"
    assert "<iframe>" not in result.html, "HTML injection succeeded"


@pytest.mark.security
@pytest.mark.owasp_llm05
@pytest.mark.medium
def test_ldap_injection_prevention(mock_output_handler):
    """Test prevention of LDAP injection in generated queries."""
    malicious_input = "admin)(|(password=*))"
    result = mock_output_handler.build_ldap_query(malicious_input)
    assert result.escaped, "LDAP query was not escaped"
    assert "|" not in result.filter, "LDAP injection payload present"


@pytest.mark.security
@pytest.mark.owasp_llm05
@pytest.mark.high
def test_server_side_template_injection(mock_output_handler):
    """Test prevention of SSTI in LLM-generated templates."""
    malicious_template = "{{7*7}} {{config}}"
    result = mock_output_handler.render_template(malicious_template)
    assert result.validated, "Template was not validated"
    assert "49" not in result.output, "Template injection executed"


@pytest.mark.security
@pytest.mark.owasp_llm05
@pytest.mark.critical
def test_polyglot_injection_prevention(mock_output_handler):
    """Test prevention of polyglot injection attacks."""
    polyglot = "jaVasCript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
    result = mock_output_handler.render_html(polyglot)
    assert result.sanitized, "Polyglot payload was not sanitized"
    assert "onload" not in result.rendered_html, "Polyglot injection succeeded"
