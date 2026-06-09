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
    # Representative CVSS:4.0 base vector for this vulnerability class (worst-case
    # for the category). Scored by :mod:`llmsectest.reporting.cvss`.
    cvss_vector: str = ""


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
        name="Supply Chain",
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
        name="Data and Model Poisoning",
        description="Tampered training, fine-tuning or embedding data introduces backdoors, bias or degraded model behavior.",
        full_description=(
            "Data and model poisoning occurs when pre-training, fine-tuning or embedding data is "
            "manipulated to introduce vulnerabilities, backdoors or biases. Poisoning can degrade model "
            "performance, produce attacker-chosen outputs on a trigger phrase, emit toxic or biased "
            "content, or exfiltrate data. It can be introduced through unvetted external data sources, "
            "compromised fine-tuning pipelines, or malicious entries in a shared/federated dataset, and "
            "it compromises the integrity of every downstream prediction the model makes."
        ),
        help_text=(
            "To mitigate data and model poisoning: (1) Track data provenance and vet all training, "
            "fine-tuning and RAG data sources, (2) Sandbox and restrict the model's access to untrusted "
            "data sources, (3) Validate and sanitize training data; filter outliers and suspected "
            "poisoned samples, (4) Test models for backdoors/triggers and benchmark behavior against a "
            "trusted baseline, (5) Verify signatures and integrity of third-party models and datasets, "
            "(6) Maintain an ML-BOM and monitor deployed model behavior for drift or anomalies."
        ),
        cwe_ids=["CWE-349", "CWE-20", "CWE-707"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm04",
        ],
        tags=["data-poisoning", "model-poisoning", "backdoor", "training-data", "integrity"],
        remediation_steps=[
            "Track data provenance and vet every training, fine-tuning and RAG data source",
            "Validate, clean and filter training data to remove outliers and poisoned samples",
            "Sandbox the model and restrict its access to untrusted or unverified data sources",
            "Test models for backdoors and triggers; compare behavior against a trusted baseline",
            "Verify signatures and checksums of third-party models and datasets before use",
            "Maintain a machine-learning bill of materials (ML-BOM) for data and model lineage",
            "Use red-team and adversarial robustness testing during model evaluation",
            "Monitor deployed model outputs for drift, bias and anomalous behavior over time"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm05": OWASPCategory(
        id="LLM05",
        name="Improper Output Handling",
        description="Inadequate validation of LLM outputs leads to injection attacks in downstream systems.",
        full_description=(
            "Improper output handling refers to insufficient validation, sanitization, and handling of "
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
        name="Excessive Agency",
        description="LLM-based systems granted excessive permissions, functionality or autonomy take damaging unintended actions.",
        full_description=(
            "Excessive agency is the vulnerability that lets an LLM-based system perform damaging actions "
            "in response to unexpected, ambiguous or manipulated output. It stems from excessive "
            "functionality (tools the agent does not need), excessive permissions (tools that can do more "
            "than the task requires), or excessive autonomy (high-impact actions taken without human "
            "confirmation). Because an agent's actions can be steered by prompt injection or hallucination, "
            "an over-privileged tool turns a model mistake into account takeover, data destruction, "
            "fund movement or remote code execution."
        ),
        help_text=(
            "To prevent excessive agency: (1) Limit the tools/plugins an agent can call to the minimum "
            "necessary, (2) Limit each tool's functions and permissions to the minimum necessary, "
            "(3) Avoid open-ended tools (e.g. run a shell) in favour of narrowly-scoped ones, (4) Require "
            "human-in-the-loop approval for high-impact or state-changing actions, (5) Enforce authorization "
            "in downstream systems rather than trusting the LLM, (6) Track user authority separately and "
            "validate it before acting, (7) Log and monitor every agent-initiated action."
        ),
        cwe_ids=["CWE-250", "CWE-269", "CWE-732"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm06",
        ],
        tags=["excessive-agency", "tool-use", "authorization", "autonomy", "privilege-escalation"],
        remediation_steps=[
            "Grant the agent the minimum set of tools needed and remove unused functionality",
            "Scope each tool's permissions to least privilege (read-only where possible)",
            "Avoid high-blast-radius tools (raw shell, generic DB write) in favour of narrow operations",
            "Require explicit human approval before destructive or money-/account-changing actions",
            "Enforce authorization checks in the downstream system, never in the prompt alone",
            "Track the end user's authority independently and validate it before any action",
            "Require multi-party or step-up confirmation for irreversible operations",
            "Log and monitor all agent-initiated actions for anomaly detection and audit"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
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
        name="Vector and Embedding Weaknesses",
        description="Weaknesses in how embeddings and vector stores are generated, stored or retrieved enable data leakage or RAG poisoning.",
        full_description=(
            "Vector and embedding weaknesses arise in systems that use Retrieval-Augmented Generation "
            "(RAG) and other embedding-based methods. Flaws in how vectors and embeddings are generated, "
            "stored, retrieved or access-controlled can be exploited — intentionally or accidentally — to "
            "inject harmful content, retrieve another tenant's data, leak sensitive information embedded "
            "in the index, or invert embeddings back into their source text. Multi-tenant vector stores "
            "without strict partitioning, and federated knowledge bases, are especially exposed."
        ),
        help_text=(
            "To mitigate vector and embedding weaknesses: (1) Enforce per-tenant and per-user access "
            "controls and logical partitioning on the vector store, (2) Validate and sanitize documents "
            "before they are embedded and indexed, (3) Treat retrieved context as untrusted and guard "
            "against embedded instructions (indirect injection), (4) Classify and tag data so retrieval "
            "respects permissions, (5) Monitor retrieval for anomalous or cross-tenant access, (6) Limit "
            "what sensitive content is embedded, since embeddings can be inverted to recover source text."
        ),
        cwe_ids=["CWE-200", "CWE-285", "CWE-863"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm08",
        ],
        tags=["rag", "embeddings", "vector-store", "access-control", "data-leakage"],
        remediation_steps=[
            "Apply fine-grained, per-tenant access control and partitioning to the vector database",
            "Validate, sanitize and classify documents before embedding and indexing them",
            "Treat retrieved chunks as untrusted input and defend against indirect prompt injection",
            "Tag data with permissions and enforce them at retrieval time, not just at ingest",
            "Minimize embedding of secrets/PII, since embeddings can be inverted to recover text",
            "Monitor and log retrieval queries for cross-tenant or anomalous access patterns",
            "Detect and resolve conflicting or poisoned entries in federated knowledge bases",
            "Encrypt vector stores at rest and restrict administrative access to the index"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
    "owasp_llm09": OWASPCategory(
        id="LLM09",
        name="Misinformation",
        description="LLMs produce false but plausible content (hallucination), which overreliance lets propagate into decisions.",
        full_description=(
            "Misinformation occurs when an LLM produces false or misleading information that appears "
            "credible. Its main cause is hallucination — the model fills gaps with statistically "
            "plausible but incorrect content — compounded by bias, incomplete training data, and "
            "fabricated facts, citations or code packages. Overreliance, where users or systems trust "
            "unverified output without oversight, is the amplifier that lets misinformation reach "
            "decisions, leading to security breaches, reputational harm, legal liability, and (via "
            "hallucinated dependencies) supply-chain compromise."
        ),
        help_text=(
            "To mitigate misinformation: (1) Ground outputs with retrieval-augmented generation from "
            "trusted sources, (2) Cross-check and verify fact-checkable claims automatically, (3) Keep "
            "human oversight and review for high-stakes outputs, (4) Provide source attribution and "
            "citations, (5) Surface confidence/uncertainty and clear disclaimers of model limitations, "
            "(6) Validate generated code and package names against real registries before use, (7) Train "
            "users to recognize hallucinations and not over-rely on the model."
        ),
        cwe_ids=["CWE-345", "CWE-1025", "CWE-693"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm09",
        ],
        tags=["misinformation", "hallucination", "overreliance", "verification"],
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
        name="Unbounded Consumption",
        description="Unrestricted, expensive inference enables denial of service, denial of wallet and model extraction.",
        full_description=(
            "Unbounded consumption occurs when an LLM application allows excessive and uncontrolled "
            "inference, letting attackers degrade service, drive up costs (denial of wallet), or "
            "extract the model. Because each query is resource-intensive and input length is variable, "
            "unthrottled or oversized requests can exhaust compute, inflate API bills, and — through "
            "high-volume querying — enable functional model replication or distillation. It subsumes the "
            "older 'Model Denial of Service' and 'Model Theft' risks under one resource-control category."
        ),
        help_text=(
            "To prevent unbounded consumption: (1) Validate and cap input size and complexity, "
            "(2) Enforce rate limiting and quotas per user, API key and IP, (3) Set timeouts and "
            "ceilings on output length and on multi-step/agentic work, (4) Track and budget spend, "
            "alerting on denial-of-wallet patterns, (5) Throttle and monitor for high-volume querying "
            "that indicates model extraction, (6) Apply graceful degradation and queuing under load, "
            "(7) Restrict and log access to protect proprietary model weights."
        ),
        cwe_ids=["CWE-400", "CWE-770", "CWE-920"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://llmtop10.com/llm10",
        ],
        tags=["denial-of-service", "denial-of-wallet", "resource-exhaustion", "model-extraction", "availability"],
        remediation_steps=[
            "Enforce strict input size and complexity limits on all inference requests",
            "Apply rate limiting and quotas per user, API key and IP address",
            "Cap output length and bound multi-step or agentic execution to prevent runaway cost",
            "Set per-query timeouts and resource ceilings with graceful degradation under load",
            "Track spend and alert on denial-of-wallet (cost-spike) patterns",
            "Throttle and monitor high-volume querying that may indicate model extraction/distillation",
            "Restrict, encrypt and log access to model weights and deployment infrastructure",
            "Queue and prioritize requests to prevent resource starvation"
        ],
        compliance_frameworks=["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "NIST CSF 2.0", "SOC 2", "ISO/IEC 27001"],
    ),
}


# Representative CVSS:4.0 base vector per category — the worst-case for the
# vulnerability class, kept in one auditable block and attached to each category
# below. Scored by :mod:`llmsectest.reporting.cvss` (the baked scores there mirror
# these vectors and are asserted equal to the cvss library in the test suite).
_CVSS_VECTORS: Dict[str, str] = {
    "owasp_llm01": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N",
    "owasp_llm02": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
    "owasp_llm03": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "owasp_llm04": "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N",
    "owasp_llm05": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
    "owasp_llm06": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "owasp_llm07": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "owasp_llm08": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:L/SI:L/SA:N",
    "owasp_llm09": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
    "owasp_llm10": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L",
}

for _marker, _vector in _CVSS_VECTORS.items():
    OWASP_LLM_CATEGORIES[_marker].cvss_vector = _vector


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
