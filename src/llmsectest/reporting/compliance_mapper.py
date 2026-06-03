"""Compliance framework mapping for OWASP LLM vulnerabilities.

Maps OWASP Top 10 for LLM Applications to major security and AI governance frameworks
including NIST AI RMF, ISO/IEC 42001, EU AI Act, NIST CSF 2.0, SOC 2, and ISO 27001.
"""

from typing import Dict, List, Set, NamedTuple


class ComplianceMapping(NamedTuple):
    """Mapping of an OWASP category to a compliance framework control."""
    framework: str
    control_id: str
    control_name: str
    category: str
    description: str


def _m(fw: str, cid: str, name: str, cat: str, desc: str) -> ComplianceMapping:
    """Shorthand for creating compliance mappings."""
    return ComplianceMapping(fw, cid, name, cat, desc)


# Compliance framework mappings for each OWASP LLM category
# Format: (framework, control_id, control_name, category, description)
COMPLIANCE_MAPPINGS: Dict[str, List[ComplianceMapping]] = {
    "owasp_llm01": [  # Prompt Injection
        _m("NIST AI RMF", "GOVERN-1.2", "Risk Management", "Govern", "Risks and benefits of AI systems are identified, assessed, and managed"),
        _m("NIST AI RMF", "MAP-3.3", "AI System Capabilities", "Map", "Potential adverse impacts from AI systems are identified and assessed"),
        _m("NIST AI RMF", "MEASURE-2.3", "AI System Performance", "Measure", "AI system behavior and performance are monitored and evaluated"),
        _m("NIST AI RMF", "MANAGE-2.3", "Risk Treatment", "Manage", "Mechanisms are in place to manage risks from AI system inputs"),
        _m("ISO/IEC 42001", "6.2.1", "AI Risk Assessment", "Planning", "Organization shall assess risks associated with AI system operation"),
        _m("ISO/IEC 42001", "8.2", "AI System Input/Output Management", "Operation", "Controls for managing AI system inputs and preventing manipulation"),
        _m("EU AI Act", "Article 15", "Accuracy, Robustness and Cybersecurity", "High-Risk AI Requirements", "AI systems shall be resilient against harmful manipulation"),
        _m("NIST CSF 2.0", "PR.DS-5", "Data Integrity", "Protect", "Protections against data integrity threats implemented"),
        _m("SOC 2", "CC6.1", "Logical Access - Input Validation", "Common Criteria", "Entity implements controls over system inputs to prevent unauthorized manipulation"),
        _m("ISO/IEC 27001", "A.8.3", "Input Data Validation", "Annex A", "Input data validation controls to prevent injection attacks"),
    ],
    "owasp_llm02": [  # Sensitive Information Disclosure
        _m("NIST AI RMF", "GOVERN-5.1", "Privacy Management", "Govern", "Processes are established to manage AI system privacy risks"),
        _m("NIST AI RMF", "MAP-5.1", "Privacy Impact", "Map", "Potential privacy impacts from AI systems are identified"),
        _m("ISO/IEC 42001", "7.3", "Data Management for AI", "Support", "Controls for managing sensitive data in AI training and operations"),
        _m("EU AI Act", "Article 10", "Data and Data Governance", "High-Risk AI Requirements", "Training data shall be subject to appropriate data governance"),
        _m("NIST CSF 2.0", "PR.DS-1", "Data-at-Rest Protection", "Protect", "Data at rest is protected through appropriate mechanisms"),
        _m("NIST CSF 2.0", "PR.DS-2", "Data-in-Transit Protection", "Protect", "Data in transit is protected through appropriate mechanisms"),
        _m("SOC 2", "CC6.7", "Confidentiality", "Common Criteria", "Entity implements controls to prevent unauthorized disclosure of sensitive information"),
        _m("ISO/IEC 27001", "A.8.11", "Data Masking", "Annex A", "Data masking is used in accordance with access control policy"),
    ],
    "owasp_llm03": [  # Supply Chain Vulnerabilities
        _m("NIST AI RMF", "GOVERN-1.3", "Third-Party Risk", "Govern", "Processes to address AI risks associated with third parties"),
        _m("NIST AI RMF", "MAP-1.5", "Supply Chain Dependencies", "Map", "Dependencies and relationships with external parties are documented"),
        _m("ISO/IEC 42001", "8.4", "Supply Chain Management", "Operation", "Controls for managing AI system supply chain risks"),
        _m("EU AI Act", "Article 11", "Technical Documentation", "High-Risk AI Requirements", "Documentation of data sources and model provenance required"),
        _m("NIST CSF 2.0", "ID.SC-1", "Supply Chain Risk Management", "Identify", "Cyber supply chain risk management processes identified"),
        _m("NIST CSF 2.0", "ID.SC-2", "Supplier Assessment", "Identify", "Suppliers and third-party partners assessed using a risk-based approach"),
        _m("SOC 2", "CC9.2", "Vendor Management", "Common Criteria", "Entity implements controls over vendor and business partner risks"),
        _m("ISO/IEC 27001", "A.5.19", "Supplier Relationships", "Annex A", "Security in supplier relationships and supply chain managed"),
    ],
    "owasp_llm04": [  # Model Denial of Service
        _m("NIST AI RMF", "MANAGE-4.1", "Resource Management", "Manage", "AI system resource usage is monitored and managed"),
        _m("ISO/IEC 42001", "8.5", "AI System Performance Monitoring", "Operation", "Monitoring of AI system performance and resource utilization"),
        _m("NIST CSF 2.0", "PR.DS-4", "Availability", "Protect", "Adequate capacity to ensure availability is maintained"),
        _m("NIST CSF 2.0", "DE.CM-8", "Performance Monitoring", "Detect", "System performance is monitored to detect anomalies"),
        _m("SOC 2", "A1.2", "System Availability", "Availability", "Entity implements controls to meet system availability commitments"),
        _m("ISO/IEC 27001", "A.8.6", "Capacity Management", "Annex A", "Capacity management to ensure required system performance"),
    ],
    "owasp_llm05": [  # Insecure Output Handling
        _m("NIST AI RMF", "MANAGE-2.4", "Output Validation", "Manage", "AI system outputs are validated before use in downstream systems"),
        _m("ISO/IEC 42001", "8.2", "AI System Input/Output Management", "Operation", "Controls for managing and validating AI system outputs"),
        _m("EU AI Act", "Article 15", "Accuracy, Robustness and Cybersecurity", "High-Risk AI Requirements", "AI systems shall implement appropriate cybersecurity measures"),
        _m("NIST CSF 2.0", "PR.DS-5", "Data Integrity", "Protect", "Protections against data integrity threats implemented"),
        _m("SOC 2", "CC6.1", "Output Validation", "Common Criteria", "Entity implements controls over system outputs to prevent injection"),
        _m("ISO/IEC 27001", "A.8.3", "Output Data Validation", "Annex A", "Output data validation controls to prevent injection attacks"),
    ],
    "owasp_llm06": [  # Insecure Plugin/Tool Use
        _m("NIST AI RMF", "GOVERN-2.1", "Authorization & Access Control", "Govern", "Authorization and access control mechanisms for AI systems"),
        _m("NIST AI RMF", "MANAGE-3.1", "Integration Security", "Manage", "Security of AI system integrations and extensions managed"),
        _m("ISO/IEC 42001", "8.3", "AI System Integration Management", "Operation", "Controls for secure integration of AI system components"),
        _m("NIST CSF 2.0", "PR.AC-1", "Access Control", "Protect", "Identities and credentials are issued and managed"),
        _m("NIST CSF 2.0", "PR.AC-4", "Least Privilege", "Protect", "Access permissions follow least privilege principle"),
        _m("SOC 2", "CC6.2", "Authorization", "Common Criteria", "Entity implements controls to ensure proper authorization"),
        _m("ISO/IEC 27001", "A.5.15", "Access Control", "Annex A", "Access control policy to manage authorization"),
    ],
    "owasp_llm07": [  # System Prompt Leakage
        _m("NIST AI RMF", "GOVERN-5.1", "Privacy & Information Protection", "Govern", "Processes to manage privacy and information disclosure risks"),
        _m("NIST AI RMF", "MAP-5.2", "Configuration Protection", "Map", "Sensitive configuration and system details are protected"),
        _m("ISO/IEC 42001", "7.4", "Configuration Management", "Support", "AI system configuration information is protected"),
        _m("NIST CSF 2.0", "PR.DS-1", "Information Protection", "Protect", "Sensitive information is protected appropriately"),
        _m("SOC 2", "CC6.7", "Confidentiality", "Common Criteria", "Entity protects confidential information from unauthorized disclosure"),
        _m("ISO/IEC 27001", "A.5.12", "Classification of Information", "Annex A", "Information classification and protection requirements"),
    ],
    "owasp_llm08": [  # Excessive Agency
        _m("NIST AI RMF", "GOVERN-2.1", "Authorization Framework", "Govern", "Authorization mechanisms limit AI system capabilities appropriately"),
        _m("NIST AI RMF", "MANAGE-3.2", "Autonomy Boundaries", "Manage", "Boundaries on AI system autonomy and decision-making authority"),
        _m("ISO/IEC 42001", "8.6", "AI System Autonomy Management", "Operation", "Controls over AI system autonomous capabilities and permissions"),
        _m("EU AI Act", "Article 14", "Human Oversight", "High-Risk AI Requirements", "High-risk AI systems shall have appropriate human oversight measures"),
        _m("NIST CSF 2.0", "PR.AC-4", "Least Privilege", "Protect", "Access permissions follow principle of least privilege"),
        _m("SOC 2", "CC6.3", "Privilege Management", "Common Criteria", "Entity implements controls to manage privileged access appropriately"),
        _m("ISO/IEC 27001", "A.5.18", "Access Rights", "Annex A", "Access rights are provisioned following least privilege"),
    ],
    "owasp_llm09": [  # Overreliance
        _m("NIST AI RMF", "GOVERN-4.1", "Transparency & Explainability", "Govern", "AI system limitations and uncertainties are communicated to users"),
        _m("NIST AI RMF", "MEASURE-2.7", "Output Verification", "Measure", "AI system outputs are verified for accuracy and reliability"),
        _m("ISO/IEC 42001", "8.7", "AI System Output Verification", "Operation", "Verification and validation of AI system outputs"),
        _m("EU AI Act", "Article 13", "Transparency and User Information", "High-Risk AI Requirements", "Users must be informed of AI system capabilities and limitations"),
        _m("EU AI Act", "Article 14", "Human Oversight", "High-Risk AI Requirements", "Human oversight to prevent overreliance on AI systems"),
        _m("SOC 2", "CC2.2", "Communication with Users", "Common Criteria", "Entity communicates system limitations and responsibilities to users"),
        _m("ISO/IEC 27001", "A.5.1", "Information Security Policies", "Annex A", "Policies address appropriate use and limitations of systems"),
    ],
    "owasp_llm10": [  # Model Theft
        _m("NIST AI RMF", "GOVERN-1.4", "Intellectual Property Protection", "Govern", "AI system intellectual property is identified and protected"),
        _m("NIST AI RMF", "MAP-1.6", "Asset Management", "Map", "AI system assets including models are inventoried and protected"),
        _m("ISO/IEC 42001", "7.5", "AI Asset Protection", "Support", "AI system assets including models are protected from theft"),
        _m("EU AI Act", "Article 11", "Technical Documentation", "High-Risk AI Requirements", "Technical documentation includes model protection measures"),
        _m("NIST CSF 2.0", "PR.DS-1", "Data-at-Rest Protection", "Protect", "Sensitive assets including models are protected at rest"),
        _m("NIST CSF 2.0", "PR.AC-1", "Access Control", "Protect", "Access to sensitive assets is controlled and monitored"),
        _m("SOC 2", "CC6.6", "Logical Access - Monitoring", "Common Criteria", "Entity monitors access to sensitive assets for unauthorized activity"),
        _m("ISO/IEC 27001", "A.5.9", "Inventory of Information Assets", "Annex A", "Assets including AI models are inventoried and protected"),
    ],
}


def get_compliance_mappings(owasp_marker: str) -> List[ComplianceMapping]:
    """Get all compliance framework mappings for an OWASP category.

    Args:
        owasp_marker: OWASP marker name (e.g., 'owasp_llm01')

    Returns:
        List of compliance mappings for the category
    """
    return COMPLIANCE_MAPPINGS.get(owasp_marker, [])


def get_frameworks_covered(owasp_markers: List[str]) -> Set[str]:
    """Get unique set of compliance frameworks covered by test results.

    Args:
        owasp_markers: List of OWASP markers from test results

    Returns:
        Set of framework names covered
    """
    frameworks = set()
    for marker in owasp_markers:
        mappings = get_compliance_mappings(marker)
        for mapping in mappings:
            frameworks.add(mapping.framework)
    return frameworks


def get_compliance_summary(owasp_markers: List[str]) -> Dict[str, Dict[str, int]]:
    """Generate summary of compliance coverage across frameworks.

    Args:
        owasp_markers: List of OWASP markers from test results

    Returns:
        Dictionary mapping framework names to coverage statistics
    """
    summary = {}
    frameworks = get_frameworks_covered(owasp_markers)

    for framework in frameworks:
        coverage = []
        for marker in owasp_markers:
            mappings = get_compliance_mappings(marker)
            coverage.extend(m for m in mappings if m.framework == framework)

        unique_controls = set((m.control_id, m.control_name) for m in coverage)

        summary[framework] = {
            "total_controls": len(unique_controls),
            "categories_covered": len(set(m.category for m in coverage)),
            "owasp_mapped": len(set(owasp_markers)),
        }

    return summary
