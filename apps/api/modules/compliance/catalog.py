"""Static seed mapping of CWE ids -> compliance-framework controls.

This is the "mapping table" the blueprint (§3) calls for -- a curated,
extensible lookup, not a scanner. Keyed by lowercased CWE id (matching how
Nuclei reports classification.cwe-id, e.g. "cwe-693"). Extend as more finding
categories appear; unknown CWEs simply produce no mappings (better than a wrong
mapping).

Each entry is a list of (framework, control_id, description).
"""

# framework values: owasp | nist | iso27001 | pci_dss | cis
CWE_CONTROL_MAP: dict[str, list[tuple[str, str, str]]] = {
    "cwe-79": [  # Cross-site Scripting
        ("owasp", "A03:2021", "Injection"),
        ("nist", "SI-10", "Information Input Validation"),
        ("pci_dss", "6.5.7", "Cross-site scripting (XSS)"),
    ],
    "cwe-89": [  # SQL Injection
        ("owasp", "A03:2021", "Injection"),
        ("nist", "SI-10", "Information Input Validation"),
        ("pci_dss", "6.5.1", "Injection flaws, particularly SQL injection"),
    ],
    "cwe-200": [  # Exposure of Sensitive Information
        ("owasp", "A01:2021", "Broken Access Control"),
        ("nist", "AC-3", "Access Enforcement"),
        ("iso27001", "A.8.3", "Information access restriction"),
    ],
    "cwe-287": [  # Improper Authentication
        ("owasp", "A07:2021", "Identification and Authentication Failures"),
        ("nist", "IA-2", "Identification and Authentication"),
        ("pci_dss", "8.2", "User authentication management"),
    ],
    "cwe-352": [  # Cross-Site Request Forgery
        ("owasp", "A01:2021", "Broken Access Control"),
        ("nist", "SC-8", "Transmission Confidentiality and Integrity"),
    ],
    "cwe-693": [  # Protection Mechanism Failure (e.g. missing security headers)
        ("owasp", "A05:2021", "Security Misconfiguration"),
        ("nist", "SC-8", "Transmission Confidentiality and Integrity"),
        ("cis", "16.11", "Leverage vetted modules/services for application security components"),
    ],
    "cwe-1021": [  # Improper Restriction of Rendered UI Layers (clickjacking)
        ("owasp", "A05:2021", "Security Misconfiguration"),
        ("nist", "SC-18", "Mobile Code"),
    ],
    "cwe-522": [  # Insufficiently Protected Credentials
        ("owasp", "A07:2021", "Identification and Authentication Failures"),
        ("pci_dss", "8.2.1", "Strong cryptography for credentials"),
    ],
}


def controls_for_category(category: str | None) -> list[tuple[str, str, str]]:
    """Return (framework, control_id, description) tuples for a vuln's category.
    Accepts a CWE id in any case (e.g. 'CWE-693' or 'cwe-693'); returns [] when
    the category is missing or unmapped."""
    if not category:
        return []
    return CWE_CONTROL_MAP.get(category.strip().lower(), [])
