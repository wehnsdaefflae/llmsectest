"""OWASP Top 10 for LLM Applications metadata and mappings."""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class OWASPCategory:
    """OWASP LLM security category metadata."""

    id: str
    name: str
    description: str
    full_description: str
    help_text: str
    cwe_ids: List[str]
    references: List[str]
    tags: List[str]
    remediation_steps: List[str]
    compliance_frameworks: List[str]  # List of frameworks this category maps to


OWASP_LLM_CATEGORIES: Dict[str, OWASPCategory] = {
    "owasp_llm01": OWASPCategory(
        id="LLM01",
        name="Prompt Injection",
        description="Manipulating LLM via crafted inputs to override system instructions or cause unintended actions.",
        full_description=(
            "Prompt injection vulnerabilities occur when an attacker manipulates a large language model (LLM) "
            "through crafted inputs, causing the LLM to unknowingly execute the attacker's intentions. "
            "This can be done directly by 'jailbreaking' the system prompt or indirectly through manipulated "
            "external inputs, potentially leading to data exfiltration, social engineering, and other issues."
        ),
        help_text=(
            "To prevent prompt injection: (1) Enforce privilege control on LLM access to backend systems, "
            "(2) Add human approval for high-risk actions, (3) Segregate external content from user prompts, "
            "(4) Establish trust boundaries between LLM and external sources, (5) Implement input validation "
            "and sanitization, (6) Monitor and log LLM interactions for anomaly detection."
        ),
        cwe_ids=["CWE-77", "CWE-78", "CWE-94"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm01",
        ],
        tags=["injection", "prompt-manipulation", "jailbreak"],
        remediation_steps=[
            "Implement strict input validation and sanitization for all user-provided prompts",
            "Use prompt templates with clearly defined variable placeholders to separate instructions from data",
            "Apply privilege control and least-privilege principles to LLM backend system access",
            "Require human-in-the-loop approval for high-risk or sensitive operations",
            "Establish trust boundaries between system prompts, user inputs, and external data sources",
            "Deploy content filtering to detect and block common prompt injection patterns",
            "Implement comprehensive logging and monitoring to detect anomalous LLM behavior",
            "Use delimiter tokens or special formatting to clearly separate user content from instructions"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm02": OWASPCategory(
        id="LLM02",
        name="Sensitive Information Disclosure",
        description="LLM inadvertently reveals confidential data in responses, risking unauthorized access or privacy breaches.",
        full_description=(
            "Sensitive information disclosure occurs when LLMs inadvertently reveal confidential data, "
            "proprietary algorithms, or other sensitive details through their responses. This can result "
            "in unauthorized access to sensitive data, intellectual property, privacy violations, and other "
            "security breaches. The risk is compounded by the LLM's training data potentially containing "
            "sensitive information."
        ),
        help_text=(
            "To prevent sensitive information disclosure: (1) Integrate data sanitization and scrubbing "
            "techniques to prevent user data from entering training data, (2) Implement robust input validation "
            "and sanitization to identify and filter out potential malicious inputs, (3) Enrich the model's "
            "responses with contextual information to help users understand limitations, (4) Use techniques "
            "like federated learning or differential privacy for model training."
        ),
        cwe_ids=["CWE-200", "CWE-359", "CWE-522"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm02",
        ],
        tags=["data-leakage", "privacy", "confidentiality"],
        remediation_steps=[
            "Sanitize and scrub training data to remove PII, credentials, and sensitive information",
            "Implement output filtering to detect and redact sensitive data patterns in LLM responses",
            "Apply differential privacy techniques during model training to prevent data memorization",
            "Use access controls to restrict LLM access to sensitive data sources",
            "Configure rate limiting to prevent data extraction through repeated queries",
            "Implement context-aware response filtering based on user permissions and data classification",
            "Audit model outputs regularly for inadvertent sensitive information disclosure",
            "Use federated learning approaches to train on sensitive data without centralizing it"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm03": OWASPCategory(
        id="LLM03",
        name="Supply Chain Vulnerabilities",
        description="Vulnerabilities in third-party components, training data, or models can compromise system integrity.",
        full_description=(
            "LLM supply chain vulnerabilities focus on the risks associated with the lifecycle of LLM components, "
            "including training data, models, and deployment platforms. Attackers can tamper with training data, "
            "introduce backdoors into pre-trained models, exploit vulnerable components, or compromise the "
            "infrastructure where models are hosted. This can lead to biased outputs, security breaches, or "
            "complete system failures."
        ),
        help_text=(
            "To mitigate supply chain risks: (1) Carefully vet data sources and suppliers, maintaining "
            "attestations for data provenance, (2) Use only reputable models and plugins with verified "
            "signatures, (3) Implement model and code signing, (4) Maintain an up-to-date inventory of "
            "components (SBOM), (5) Employ anomaly detection and adversarial robustness tests on models, "
            "(6) Monitor for unauthorized access to data and model repositories."
        ),
        cwe_ids=["CWE-1329", "CWE-829", "CWE-494"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm03",
        ],
        tags=["supply-chain", "third-party", "dependencies"],
        remediation_steps=[
            "Maintain Software Bill of Materials (SBOM) for all LLM components and dependencies",
            "Verify signatures and checksums of pre-trained models before deployment",
            "Vet and audit all third-party data sources for integrity and provenance",
            "Use trusted model repositories with verified publishers only",
            "Implement continuous vulnerability scanning for dependencies and libraries",
            "Apply adversarial robustness testing to detect model backdoors and poisoning",
            "Establish secure model development pipeline with version control and access logs",
            "Monitor model behavior for anomalies that may indicate supply chain compromise"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm04": OWASPCategory(
        id="LLM04",
        name="Model Denial of Service",
        description="Attackers cause resource exhaustion leading to degraded service or high costs.",
        full_description=(
            "Model Denial of Service (DoS) occurs when an attacker interacts with an LLM in a way that "
            "consumes an exceptionally high amount of resources, leading to degraded service quality for "
            "all users and increased resource costs. The vulnerability is particularly concerning for "
            "LLMs due to their resource-intensive nature and the potential for variable input lengths "
            "that can trigger complex processing."
        ),
        help_text=(
            "To prevent Model DoS: (1) Implement input validation to limit input size and complexity, "
            "(2) Set rate limiting on API requests per user/IP, (3) Implement resource monitoring and "
            "(4) Set maximum processing time for queries, (5) Design systems to handle "
            "expected load with graceful degradation, (6) Monitor for unusual resource consumption patterns."
        ),
        cwe_ids=["CWE-400", "CWE-770", "CWE-920"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm04",
        ],
        tags=["denial-of-service", "resource-exhaustion", "availability"],
        remediation_steps=[
            "Enforce strict input size limits (tokens, characters) on all LLM queries",
            "Implement rate limiting per user, API key, and IP address",
            "Set maximum processing time timeouts for query execution",
            "Deploy resource quotas and throttling for API consumers",
            "Use load balancing and auto-scaling to handle traffic spikes gracefully",
            "Monitor resource usage patterns and alert on anomalies",
            "Implement CAPTCHA or proof-of-work for unauthenticated requests",
            "Queue and prioritize requests to prevent resource starvation"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm05": OWASPCategory(
        id="LLM05",
        name="Insecure Output Handling",
        description="Inadequate validation of LLM outputs leads to injection attacks in downstream systems.",
        full_description=(
            "Insecure output handling refers to insufficient validation, sanitization, and handling of "
            "outputs generated by large language models before they are passed to other components and "
            "systems. Since LLM-generated content can be controlled by prompt input, this behavior is "
            "similar to providing users indirect access to additional functionality. This can lead to "
            "XSS, CSRF, SSRF, privilege escalation, and remote code execution in downstream systems."
        ),
        help_text=(
            "To prevent insecure output handling: (1) Treat the model as any other user and apply proper "
            "input validation on responses from the model to backend functions, (2) Follow OWASP ASVS "
            "guidelines to ensure effective input validation and sanitization, (3) Encode model output "
            "back to users to mitigate XSS and other injection attacks, (4) Use parameterized queries "
            "or prepared statements when LLM output is used in database queries or system commands."
        ),
        cwe_ids=["CWE-79", "CWE-89", "CWE-74", "CWE-94"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm05",
        ],
        tags=["injection", "output-validation", "xss", "sql-injection"],
        remediation_steps=[
            "Validate and sanitize all LLM outputs before passing to downstream systems",
            "Encode LLM output for the target context (HTML, JavaScript, SQL, etc.)",
            "Use parameterized queries or prepared statements when using LLM output in databases",
            "Apply strict content security policies (CSP) to prevent XSS from LLM-generated content",
            "Implement allowlist-based validation for LLM outputs used in critical operations",
            "Treat LLM outputs as untrusted user input in all security contexts",
            "Use sandboxing or isolated execution environments for processing LLM outputs",
            "Deploy web application firewalls (WAF) to detect injection attempts in LLM outputs"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm06": OWASPCategory(
        id="LLM06",
        name="Insecure Plugin/Tool Use",
        description="LLM plugins/tools with inadequate access control enable unauthorized actions or data access.",
        full_description=(
            "LLM plugins and tools are extensions that enable LLMs to interact with external resources "
            "and systems. Insecure plugin design can allow attackers to craft malicious inputs that "
            "trigger unintended actions, bypass access controls, or exploit vulnerabilities in the "
            "plugin interface. This can lead to unauthorized data access, remote code execution, "
            "privilege escalation, and other security issues."
        ),
        help_text=(
            "To secure LLM plugins and tools: (1) Enforce strict parameterized input where possible, "
            "(2) Implement comprehensive input validation and sanitization, (3) Apply appropriate "
            "authentication and authorization to plugin access, (4) Implement manual user approval "
            "for high-risk actions, (5) Follow OWASP API Security Top 10 guidelines, (6) Minimize "
            "plugin functionality to only what is necessary, (7) Monitor and log plugin usage."
        ),
        cwe_ids=["CWE-285", "CWE-862", "CWE-863"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm06",
        ],
        tags=["plugin", "tool-use", "access-control", "authorization"],
        remediation_steps=[
            "Enforce parameterized input and strict type validation for all plugin parameters",
            "Implement comprehensive authentication and authorization for plugin access",
            "Apply principle of least privilege to plugin permissions and capabilities",
            "Require explicit user approval for high-risk plugin actions (file access, code execution)",
            "Validate and sanitize all plugin inputs and outputs rigorously",
            "Implement plugin sandboxing to isolate execution environments",
            "Audit and review third-party plugins for security vulnerabilities",
            "Monitor and log all plugin invocations for security analysis"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm07": OWASPCategory(
        id="LLM07",
        name="System Prompt Leakage",
        description="Attackers extract system prompts containing sensitive instructions or data.",
        full_description=(
            "System prompt leakage occurs when attackers extract the system prompts or instructions "
            "that guide an LLM's behavior. These prompts often contain sensitive information, business "
            "logic, security controls, or other confidential data. If exposed, attackers can bypass "
            "security measures, understand system limitations, or craft more effective attacks. The "
            "vulnerability is particularly concerning because system prompts form the security "
            "boundary for LLM applications."
        ),
        help_text=(
            "To prevent system prompt leakage: (1) Implement prompt injection defenses to prevent "
            "extraction attempts, (2) Avoid including sensitive information in system prompts when "
            "possible, (3) Monitor for common prompt extraction patterns, (4) Use prompt isolation "
            "techniques to separate system instructions from user inputs, (5) Implement output "
            "filtering to detect and block leaked system prompts, (6) Regularly test for prompt "
            "extraction vulnerabilities."
        ),
        cwe_ids=["CWE-200", "CWE-209", "CWE-497"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm07",
        ],
        tags=["information-disclosure", "prompt-leakage", "configuration"],
        remediation_steps=[
            "Avoid embedding sensitive data, credentials, or business logic directly in system prompts",
            "Implement output filtering to detect and prevent system prompt disclosure in responses",
            "Use prompt isolation techniques to clearly separate system and user content",
            "Monitor for common extraction patterns like 'repeat your instructions' or 'show system prompt'",
            "Apply defensive prompt engineering with explicit instructions against disclosure",
            "Regularly test for prompt extraction vulnerabilities using adversarial techniques",
            "Implement response screening to detect leaked prompt fragments",
            "Use dynamic prompt generation to vary non-sensitive instructions across sessions"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm08": OWASPCategory(
        id="LLM08",
        name="Excessive Agency",
        description="LLM-based systems granted excessive permissions or autonomy enable unintended harmful actions.",
        full_description=(
            "Excessive agency in LLM-based systems occurs when they are granted too much autonomy, "
            "permission, or functionality, enabling them to take actions beyond their intended scope. "
            "This can happen when LLMs have access to high-privilege APIs, lack proper authorization "
            "checks, or are not constrained in the types of actions they can perform. The risk is "
            "amplified because LLMs can be manipulated through prompt injection or may hallucinate "
            "and take incorrect actions autonomously."
        ),
        help_text=(
            "To prevent excessive agency: (1) Limit plugins/tools to minimum necessary functions, "
            "(2) Implement human-in-the-loop approval for high-risk actions, (3) Apply least privilege "
            "principles to LLM plugin access, (4) Track user authorization separately from LLM agency, "
            "(5) Implement comprehensive logging and monitoring of LLM actions, (6) Set boundaries on "
            "action chains and autonomous behavior, (7) Require explicit user consent for sensitive "
            "operations."
        ),
        cwe_ids=["CWE-250", "CWE-269", "CWE-732"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm08",
        ],
        tags=["authorization", "privilege-escalation", "autonomy"],
        remediation_steps=[
            "Apply least privilege principle - grant LLM minimum necessary permissions only",
            "Implement human-in-the-loop approval for destructive or sensitive operations",
            "Limit the scope and capabilities of available plugins/tools to essential functions only",
            "Track user authorization separately and validate before LLM-initiated actions",
            "Set explicit boundaries on action chains and autonomous decision-making depth",
            "Implement comprehensive audit logging for all LLM-initiated actions",
            "Require explicit user consent before performing state-changing operations",
            "Use role-based access control (RBAC) to restrict LLM capabilities per user context"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm09": OWASPCategory(
        id="LLM09",
        name="Overreliance",
        description="Users or systems overly depend on LLM outputs without verification, leading to misinformation or errors.",
        full_description=(
            "Overreliance on LLMs occurs when systems or users excessively depend on LLM-generated "
            "content without adequate oversight, verification, or understanding of the model's "
            "limitations. LLMs can hallucinate, generate plausible but incorrect information, produce "
            "biased content, or provide inconsistent outputs. When critical decisions are based solely "
            "on unverified LLM outputs, it can lead to misinformation, legal issues, security "
            "vulnerabilities, and reputational damage."
        ),
        help_text=(
            "To mitigate overreliance: (1) Regularly monitor and review LLM outputs with human "
            "oversight, (2) Implement cross-checking mechanisms and verification processes, "
            "(3) Use confidence scores and uncertainty indicators in LLM outputs, (4) Clearly "
            "communicate LLM limitations to users through disclaimers, (5) Provide source attribution "
            "and references for LLM-generated content, (6) Implement automated validation for "
            "fact-checkable claims, (7) Train users on LLM capabilities and limitations."
        ),
        cwe_ids=["CWE-1024", "CWE-693"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm09",
        ],
        tags=["hallucination", "misinformation", "verification"],
        remediation_steps=[
            "Implement mandatory human review for critical decisions based on LLM outputs",
            "Display confidence scores and uncertainty indicators alongside LLM responses",
            "Provide clear disclaimers about LLM limitations and potential for errors",
            "Implement cross-verification with authoritative sources for fact-checkable claims",
            "Include source citations and attribution for LLM-generated information",
            "Establish validation workflows for high-stakes outputs (legal, medical, financial)",
            "Train users on recognizing hallucinations and LLM capability boundaries",
            "Deploy automated fact-checking and consistency validation where applicable"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm10": OWASPCategory(
        id="LLM10",
        name="Model Theft",
        description="Unauthorized access to proprietary LLM models through extraction or replication.",
        full_description=(
            "Model theft involves the unauthorized access, copying, or exfiltration of proprietary "
            "LLM models. Attackers may exploit vulnerabilities in access controls, use API queries "
            "to recreate the model, or employ side-channel attacks to extract model architecture and "
            "weights. This can lead to economic loss, competitive disadvantage, exposure of sensitive "
            "training data, and unauthorized access to model capabilities. The impact is particularly "
            "severe for organizations that invest heavily in developing custom models."
        ),
        help_text=(
            "To prevent model theft: (1) Implement strong access controls and authentication for "
            "model repositories, (2) Use encryption for models at rest and in transit, (3) Apply "
            "rate limiting and monitoring to detect extraction attempts via API, (4) Implement "
            "watermarking techniques to track model provenance, (5) Use model obfuscation when "
            "deploying to edge devices, (6) Monitor for unusual query patterns indicating model "
            "extraction, (7) Implement DRM and usage restrictions, (8) Maintain audit logs of "
            "model access."
        ),
        cwe_ids=["CWE-284", "CWE-306", "CWE-311"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm10",
        ],
        tags=["theft", "extraction", "intellectual-property"],
        remediation_steps=[
            "Enforce strong authentication and authorization for all model access points",
            "Encrypt models at rest using industry-standard encryption (AES-256)",
            "Encrypt model transmissions using TLS 1.3 or equivalent",
            "Implement rate limiting and query throttling to prevent model extraction via API",
            "Deploy model watermarking to track unauthorized model distribution",
            "Monitor for suspicious query patterns that may indicate extraction attempts",
            "Use model obfuscation techniques when deploying to edge or untrusted environments",
            "Maintain comprehensive audit logs of all model access and usage"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
}


def get_owasp_category(marker: str) -> Optional[OWASPCategory]:
    """Get OWASP category metadata for a given marker.

    Args:
        marker: The marker name (e.g., 'owasp_llm01')

    Returns:
        OWASPCategory if found, None otherwise
    """
    return OWASP_LLM_CATEGORIES.get(marker)


def get_owasp_markers_from_test(markers: List[str]) -> List[str]:
    """Extract OWASP markers from test markers.

    Args:
        markers: List of all markers on a test

    Returns:
        List of OWASP LLM markers found
    """
    return [m for m in markers if m.startswith("owasp_llm")]


def get_cwe_tags(markers: List[str]) -> List[str]:
    """Get all CWE IDs associated with test markers.

    Args:
        markers: List of test markers

    Returns:
        List of CWE IDs
    """
    cwe_ids = []
    for marker in markers:
        category = get_owasp_category(marker)
        if category:
            cwe_ids.extend(category.cwe_ids)
    return cwe_ids


def get_security_tags(markers: List[str]) -> List[str]:
    """Get all security tags associated with test markers.

    Args:
        markers: List of test markers

    Returns:
        List of security tags
    """
    tags = []
    for marker in markers:
        category = get_owasp_category(marker)
        if category:
            tags.extend(category.tags)
    return tags
