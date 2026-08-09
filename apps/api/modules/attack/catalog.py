"""Static mapping of finding categories -> MITRE ATT&CK techniques + Cyber Kill
Chain phases.

This is the ATT&CK/kill-chain analogue of compliance/catalog.py: a curated,
extensible lookup, NOT a scanner. It is keyed by:
  * lowercased CWE id, as Nuclei reports classification.cwe-id (e.g. "cwe-89"), and
  * Nuclei tags (info.tags, e.g. "sqli", "default-login", "takeover").

An AI Correlator layer refines and narrates on top of this deterministic base;
this table guarantees a reproducible, citable mapping even with AI disabled.
Unknown keys map to nothing (better than a wrong mapping). Mapping a web weakness
to a single ATT&CK technique is inherently approximate -- extend/adjust freely;
the storage + API shape does not depend on the exact rows here.
"""


class KillChainPhase:
    """Lockheed Martin Cyber Kill Chain phases, in order."""

    RECON = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    C2 = "command_and_control"
    ACTIONS = "actions_on_objectives"


# Canonical order, used to sort a scan's kill-chain timeline.
KILL_CHAIN_ORDER: list[str] = [
    KillChainPhase.RECON,
    KillChainPhase.WEAPONIZATION,
    KillChainPhase.DELIVERY,
    KillChainPhase.EXPLOITATION,
    KillChainPhase.INSTALLATION,
    KillChainPhase.C2,
    KillChainPhase.ACTIONS,
]

KILL_CHAIN_PHASE_NAMES: dict[str, str] = {
    KillChainPhase.RECON: "Reconnaissance",
    KillChainPhase.WEAPONIZATION: "Weaponization",
    KillChainPhase.DELIVERY: "Delivery",
    KillChainPhase.EXPLOITATION: "Exploitation",
    KillChainPhase.INSTALLATION: "Installation",
    KillChainPhase.C2: "Command & Control",
    KillChainPhase.ACTIONS: "Actions on Objectives",
}

# MITRE ATT&CK Enterprise tactics referenced below (id -> display name).
TACTIC_NAMES: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0040": "Impact",
}

# A technique entry: (tactic_id, technique_id, technique_name, kill_chain_phase).
# Reusable constants keep the maps below terse and consistent.
_EXPLOIT_PUBLIC_APP = ("TA0001", "T1190", "Exploit Public-Facing Application", KillChainPhase.EXPLOITATION)
_CMD_SCRIPTING = ("TA0002", "T1059", "Command and Scripting Interpreter", KillChainPhase.EXPLOITATION)
_VALID_ACCOUNTS = ("TA0001", "T1078", "Valid Accounts", KillChainPhase.EXPLOITATION)
_DRIVE_BY = ("TA0001", "T1189", "Drive-by Compromise", KillChainPhase.DELIVERY)
_FILE_DISCOVERY = ("TA0007", "T1083", "File and Directory Discovery", KillChainPhase.EXPLOITATION)
_GATHER_HOST_INFO = ("TA0043", "T1592", "Gather Victim Host Information", KillChainPhase.RECON)
_ACTIVE_SCANNING = ("TA0043", "T1595", "Active Scanning", KillChainPhase.RECON)
_COMPROMISE_INFRA = ("TA0042", "T1584", "Compromise Infrastructure", KillChainPhase.WEAPONIZATION)
_EXPLOIT_REMOTE_SVC = ("TA0008", "T1210", "Exploitation of Remote Services", KillChainPhase.EXPLOITATION)
_NETWORK_SNIFFING = ("TA0006", "T1040", "Network Sniffing", KillChainPhase.EXPLOITATION)
_FORCED_AUTH = ("TA0006", "T1187", "Forced Authentication", KillChainPhase.EXPLOITATION)
_ENDPOINT_DOS = ("TA0040", "T1499", "Endpoint Denial of Service", KillChainPhase.ACTIONS)
_DEOBFUSCATE = ("TA0005", "T1140", "Deobfuscate/Decode Files or Information", KillChainPhase.EXPLOITATION)

# CWE id -> techniques (lowercased keys; matches Nuclei classification.cwe-id).
CWE_TECHNIQUE_MAP: dict[str, list[tuple[str, str, str, str]]] = {
    "cwe-89": [_EXPLOIT_PUBLIC_APP],                    # SQL injection
    "cwe-79": [_DRIVE_BY],                              # Cross-site scripting
    "cwe-78": [_EXPLOIT_PUBLIC_APP, _CMD_SCRIPTING],    # OS command injection
    "cwe-77": [_EXPLOIT_PUBLIC_APP, _CMD_SCRIPTING],    # Command injection
    "cwe-94": [_EXPLOIT_PUBLIC_APP, _CMD_SCRIPTING],    # Code injection
    "cwe-98": [_EXPLOIT_PUBLIC_APP],                    # PHP file inclusion (LFI/RFI)
    "cwe-22": [_FILE_DISCOVERY],                        # Path traversal
    "cwe-918": [_EXPLOIT_PUBLIC_APP],                   # SSRF
    "cwe-287": [_VALID_ACCOUNTS],                       # Improper authentication
    "cwe-306": [_VALID_ACCOUNTS],                       # Missing authentication
    "cwe-798": [_VALID_ACCOUNTS],                       # Hardcoded credentials
    "cwe-200": [_GATHER_HOST_INFO],                     # Information exposure
    "cwe-538": [_GATHER_HOST_INFO],                     # File/dir information exposure
    "cwe-1004": [_GATHER_HOST_INFO],                    # Sensitive cookie without HttpOnly
    "cwe-668": [_GATHER_HOST_INFO],                     # Exposure of resource to wrong sphere
    "cwe-693": [_ACTIVE_SCANNING],                      # Protection mechanism failure (missing headers)
    "cwe-16": [_ACTIVE_SCANNING],                       # Configuration
    "cwe-352": [_DRIVE_BY],                             # CSRF
    "cwe-1021": [_DRIVE_BY],                            # Clickjacking / UI redressing
    "cwe-601": [_DRIVE_BY],                             # Open redirect
    "cwe-434": [_EXPLOIT_PUBLIC_APP],                   # Unrestricted file upload
    "cwe-611": [_EXPLOIT_PUBLIC_APP],                   # XXE
    "cwe-502": [_EXPLOIT_PUBLIC_APP, _CMD_SCRIPTING],   # Insecure deserialization
    "cwe-284": [_EXPLOIT_PUBLIC_APP],                   # Improper access control
    "cwe-285": [_EXPLOIT_PUBLIC_APP],                   # Improper authorization
    "cwe-522": [_VALID_ACCOUNTS],                       # Insufficiently protected credentials
    "cwe-319": [_NETWORK_SNIFFING],                     # Cleartext transmission
    "cwe-327": [_NETWORK_SNIFFING],                     # Broken/risky crypto algorithm
    "cwe-326": [_NETWORK_SNIFFING],                     # Inadequate encryption strength
    "cwe-400": [_ENDPOINT_DOS],                         # Uncontrolled resource consumption (DoS)
}

# Nuclei tag -> techniques (info.tags). Complements CWE mapping; many templates
# carry a useful tag but no cwe-id.
TAG_TECHNIQUE_MAP: dict[str, list[tuple[str, str, str, str]]] = {
    "sqli": [_EXPLOIT_PUBLIC_APP],
    "xss": [_DRIVE_BY],
    "rce": [_EXPLOIT_PUBLIC_APP, _CMD_SCRIPTING],
    "ssti": [_EXPLOIT_PUBLIC_APP, _CMD_SCRIPTING],
    "lfi": [_FILE_DISCOVERY, _EXPLOIT_PUBLIC_APP],
    "ssrf": [_EXPLOIT_PUBLIC_APP],
    "injection": [_EXPLOIT_PUBLIC_APP],
    "auth-bypass": [_VALID_ACCOUNTS],
    "default-login": [_VALID_ACCOUNTS],
    "default-logins": [_VALID_ACCOUNTS],
    "exposure": [_GATHER_HOST_INFO],
    "exposures": [_GATHER_HOST_INFO],
    "disclosure": [_GATHER_HOST_INFO],
    "takeover": [_COMPROMISE_INFRA],
    "network": [_EXPLOIT_REMOTE_SVC],
    "misconfig": [_ACTIVE_SCANNING],
    "misconfiguration": [_ACTIVE_SCANNING],
    "cve": [_EXPLOIT_PUBLIC_APP],
    "csrf": [_DRIVE_BY],
    "redirect": [_DRIVE_BY],
    "open-redirect": [_DRIVE_BY],
    "clickjacking": [_DRIVE_BY],
    "xxe": [_EXPLOIT_PUBLIC_APP],
    "deserialization": [_EXPLOIT_PUBLIC_APP, _CMD_SCRIPTING],
    "fileupload": [_EXPLOIT_PUBLIC_APP],
    "file-upload": [_EXPLOIT_PUBLIC_APP],
    "idor": [_EXPLOIT_PUBLIC_APP],
    "crlf": [_EXPLOIT_PUBLIC_APP],
    "auth": [_VALID_ACCOUNTS],
    "jwt": [_VALID_ACCOUNTS],
    "token": [_VALID_ACCOUNTS],
    "creds": [_VALID_ACCOUNTS],
    "brute-force": [_FORCED_AUTH],
    "ssl": [_NETWORK_SNIFFING],
    "tls": [_NETWORK_SNIFFING],
    "crypto": [_NETWORK_SNIFFING],
    "backup": [_GATHER_HOST_INFO],
    "config": [_GATHER_HOST_INFO],
    "files": [_GATHER_HOST_INFO],
    "panel": [_GATHER_HOST_INFO],
    "debug": [_GATHER_HOST_INFO],
    "dos": [_ENDPOINT_DOS],
    "intrusive": [_ENDPOINT_DOS],
}


def _normalize_tags(tags) -> list[str]:
    """Nuclei reports info.tags as a list; be tolerant of a comma-separated
    string or None too."""
    if not tags:
        return []
    if isinstance(tags, str):
        tags = tags.split(",")
    return [str(t).strip().lower() for t in tags if str(t).strip()]


def techniques_for(category: str | None, tags=None) -> list[tuple[str, str, str, str]]:
    """De-duplicated technique tuples for a finding's CWE `category` and/or Nuclei
    `tags`. Each tuple is (tactic_id, technique_id, technique_name, kill_chain_phase).
    Unknown keys contribute nothing (same policy as compliance/catalog)."""
    out: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()

    def _add(entries: list[tuple[str, str, str, str]]) -> None:
        for entry in entries:
            technique_id = entry[1]
            if technique_id not in seen:
                seen.add(technique_id)
                out.append(entry)

    if category:
        _add(CWE_TECHNIQUE_MAP.get(category.strip().lower(), []))
    for tag in _normalize_tags(tags):
        _add(TAG_TECHNIQUE_MAP.get(tag, []))
    return out
