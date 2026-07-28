"""Static seed mapping of CWE ids -> compliance-framework controls.

This is the "mapping table" the blueprint (§3) calls for -- a curated,
extensible lookup, not a scanner. Keyed by lowercased CWE id (matching how
Nuclei reports classification.cwe-id, e.g. "cwe-693"). Extend as more finding
categories appear; unknown CWEs simply produce no mappings (better than a wrong
mapping).

Each entry is a list of (framework, control_id, description). Frameworks:
  owasp     -- OWASP Top 10:2021
  nist      -- NIST SP 800-53 Rev. 5
  iso27001  -- ISO/IEC 27001:2022 Annex A
  pci_dss   -- PCI DSS v4.0
  cis       -- CIS Controls v8

Human-readable framework names for display live in FRAMEWORK_NAMES below.
"""

FRAMEWORK_NAMES: dict[str, str] = {
    "owasp": "OWASP Top 10",
    "nist": "NIST 800-53",
    "iso27001": "ISO/IEC 27001",
    "pci_dss": "PCI DSS",
    "cis": "CIS Controls",
}

# Common ISO 27001:2022 / PCI DSS v4.0 controls reused across entries.
_ISO_SECURE_CODING = ("iso27001", "A.8.28", "Secure coding")
_ISO_CRYPTO = ("iso27001", "A.8.24", "Use of cryptography")
_ISO_AUTH = ("iso27001", "A.8.5", "Secure authentication")
_ISO_ACCESS = ("iso27001", "A.8.3", "Information access restriction")
_ISO_CONFIG = ("iso27001", "A.8.9", "Configuration management")
_ISO_TRANSFER = ("iso27001", "A.5.14", "Information transfer")
_PCI_SECURE_SOFTWARE = ("pci_dss", "6.2.4", "Software engineered to prevent common attacks")
_PCI_CRYPTO_TRANSIT = ("pci_dss", "4.2.1", "Strong cryptography for data in transit")

CWE_CONTROL_MAP: dict[str, list[tuple[str, str, str]]] = {
    "cwe-79": [  # Cross-site Scripting
        ("owasp", "A03:2021", "Injection"),
        ("nist", "SI-10", "Information Input Validation"),
        _ISO_SECURE_CODING,
        ("pci_dss", "6.5.7", "Cross-site scripting (XSS)"),
    ],
    "cwe-89": [  # SQL Injection
        ("owasp", "A03:2021", "Injection"),
        ("nist", "SI-10", "Information Input Validation"),
        _ISO_SECURE_CODING,
        ("pci_dss", "6.5.1", "Injection flaws, particularly SQL injection"),
    ],
    "cwe-94": [  # Code Injection
        ("owasp", "A03:2021", "Injection"),
        ("nist", "SI-10", "Information Input Validation"),
        _ISO_SECURE_CODING,
        _PCI_SECURE_SOFTWARE,
    ],
    "cwe-22": [  # Path Traversal
        ("owasp", "A01:2021", "Broken Access Control"),
        ("nist", "AC-3", "Access Enforcement"),
        _ISO_ACCESS,
        _PCI_SECURE_SOFTWARE,
    ],
    "cwe-200": [  # Exposure of Sensitive Information
        ("owasp", "A01:2021", "Broken Access Control"),
        ("nist", "AC-3", "Access Enforcement"),
        _ISO_ACCESS,
        ("pci_dss", "3.3.1", "Sensitive data protection and masking"),
    ],
    "cwe-287": [  # Improper Authentication
        ("owasp", "A07:2021", "Identification and Authentication Failures"),
        ("nist", "IA-2", "Identification and Authentication"),
        _ISO_AUTH,
        ("pci_dss", "8.2", "User authentication management"),
    ],
    "cwe-306": [  # Missing Authentication for Critical Function
        ("owasp", "A07:2021", "Identification and Authentication Failures"),
        ("nist", "IA-2", "Identification and Authentication"),
        _ISO_AUTH,
        ("pci_dss", "8.3", "Strong authentication for access"),
    ],
    "cwe-352": [  # Cross-Site Request Forgery
        ("owasp", "A01:2021", "Broken Access Control"),
        ("nist", "SC-8", "Transmission Confidentiality and Integrity"),
        _ISO_SECURE_CODING,
        ("pci_dss", "6.5.9", "Cross-site request forgery (CSRF)"),
    ],
    "cwe-611": [  # XML External Entity (XXE)
        ("owasp", "A05:2021", "Security Misconfiguration"),
        ("nist", "SI-10", "Information Input Validation"),
        _ISO_SECURE_CODING,
        _PCI_SECURE_SOFTWARE,
    ],
    "cwe-918": [  # Server-Side Request Forgery (SSRF)
        ("owasp", "A10:2021", "Server-Side Request Forgery (SSRF)"),
        ("nist", "SC-7", "Boundary Protection"),
        _ISO_SECURE_CODING,
        _PCI_SECURE_SOFTWARE,
    ],
    "cwe-693": [  # Protection Mechanism Failure (e.g. missing security headers)
        ("owasp", "A05:2021", "Security Misconfiguration"),
        ("nist", "SC-8", "Transmission Confidentiality and Integrity"),
        _ISO_CONFIG,
        ("cis", "16.11", "Leverage vetted modules/services for application security components"),
        ("pci_dss", "6.4.1", "Public-facing web application protections"),
    ],
    "cwe-16": [  # Configuration
        ("owasp", "A05:2021", "Security Misconfiguration"),
        ("nist", "CM-6", "Configuration Settings"),
        _ISO_CONFIG,
        ("pci_dss", "2.2", "Secure configuration standards for system components"),
    ],
    "cwe-1021": [  # Improper Restriction of Rendered UI Layers (clickjacking)
        ("owasp", "A05:2021", "Security Misconfiguration"),
        ("nist", "SC-18", "Mobile Code"),
        _ISO_CONFIG,
    ],
    "cwe-522": [  # Insufficiently Protected Credentials
        ("owasp", "A07:2021", "Identification and Authentication Failures"),
        ("nist", "IA-5", "Authenticator Management"),
        _ISO_CRYPTO,
        ("pci_dss", "8.2.1", "Strong cryptography for credentials"),
    ],
    "cwe-311": [  # Missing Encryption of Sensitive Data
        ("owasp", "A02:2021", "Cryptographic Failures"),
        ("nist", "SC-28", "Protection of Information at Rest"),
        _ISO_CRYPTO,
        ("pci_dss", "3.5.1", "Render stored account data unreadable"),
    ],
    "cwe-319": [  # Cleartext Transmission of Sensitive Information
        ("owasp", "A02:2021", "Cryptographic Failures"),
        ("nist", "SC-8", "Transmission Confidentiality and Integrity"),
        _ISO_TRANSFER,
        _PCI_CRYPTO_TRANSIT,
    ],
    "cwe-327": [  # Use of a Broken or Risky Cryptographic Algorithm
        ("owasp", "A02:2021", "Cryptographic Failures"),
        ("nist", "SC-13", "Cryptographic Protection"),
        _ISO_CRYPTO,
        _PCI_CRYPTO_TRANSIT,
    ],
    "cwe-548": [  # Information Exposure Through Directory Listing
        ("owasp", "A05:2021", "Security Misconfiguration"),
        ("nist", "CM-6", "Configuration Settings"),
        _ISO_CONFIG,
        ("pci_dss", "2.2", "Secure configuration standards for system components"),
    ],
    "cwe-538": [  # Insertion of Sensitive Information into Externally-Accessible File
        ("owasp", "A01:2021", "Broken Access Control"),
        ("nist", "AC-3", "Access Enforcement"),
        _ISO_ACCESS,
        ("pci_dss", "3.3.1", "Sensitive data protection and masking"),
    ],
}


def controls_for_category(category: str | None) -> list[tuple[str, str, str]]:
    """Return (framework, control_id, description) tuples for a vuln's category.
    Accepts a CWE id in any case (e.g. 'CWE-693' or 'cwe-693'); returns [] when
    the category is missing or unmapped."""
    if not category:
        return []
    return CWE_CONTROL_MAP.get(category.strip().lower(), [])


def framework_name(framework: str) -> str:
    """Human-readable name for a framework key (e.g. 'iso27001' -> 'ISO/IEC 27001')."""
    return FRAMEWORK_NAMES.get(framework, framework)
