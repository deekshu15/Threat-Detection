"""
constants.py

Application-wide constants for the Threat Enrichment Lambda.
"""

# =========================
# Severity Levels
# =========================

LOW = "Low"
MEDIUM = "Medium"
HIGH = "High"
CRITICAL = "Critical"

# =========================
# Supported Sources
# =========================

WINDOWS = "windows"
LINUX = "linux"
IDS = "ids"
FIREWALL = "firewall"
CVE = "cve"

# =========================
# Asset Types
# =========================

AUTHENTICATION_SERVER = "Authentication Service"
WINDOWS_SERVER = "Windows Server"
LINUX_SERVER = "Linux Server"
NETWORK_GATEWAY = "Network Gateway"
NETWORK_SENSOR = "Network Sensor"
APPLICATION_SERVER = "Application Server"
UNKNOWN_ASSET = "Unknown Asset"

# =========================
# Asset Criticality
# =========================

LOW_CRITICALITY = "Low"
MEDIUM_CRITICALITY = "Medium"
HIGH_CRITICALITY = "High"
CRITICAL_CRITICALITY = "Critical"

# =========================
# Attack Categories
# =========================

CREDENTIAL_ATTACK = "Credential Attack"
EXECUTION = "Execution"
DISCOVERY = "Discovery"
PRIVILEGE_ESCALATION = "Privilege Escalation"
LATERAL_MOVEMENT = "Lateral Movement"
PERSISTENCE = "Persistence"
COMMAND_AND_CONTROL = "Command and Control"
DEFENSE_EVASION = "Defense Evasion"
IMPACT = "Impact"
RECONNAISSANCE = "Reconnaissance"
UNKNOWN_ATTACK = "Unknown"

# =========================
# Boolean Flags
# =========================

KNOWN_ATTACK = True
UNKNOWN_ATTACK_FLAG = False