"""
config.py

Configuration and mapping tables for Threat Enrichment.
"""

from aws.lambdas.threat_enrichment.constants import *

# ==========================================================
# Severity Score Mapping
# ==========================================================

SEVERITY_SCORES = {
    LOW: 25,
    MEDIUM: 50,
    HIGH: 75,
    CRITICAL: 100,
}

# ==========================================================
# Default Risk Weights
# ==========================================================

RISK_WEIGHTS = {
    LOW: 20,
    MEDIUM: 50,
    HIGH: 80,
    CRITICAL: 100,
}

# ==========================================================
# Asset Mapping
# ==========================================================

ASSET_MAPPING = {
    WINDOWS: {
        "asset_type": WINDOWS_SERVER,
        "criticality": HIGH_CRITICALITY,
    },

    LINUX: {
        "asset_type": LINUX_SERVER,
        "criticality": HIGH_CRITICALITY,
    },

    IDS: {
        "asset_type": NETWORK_SENSOR,
        "criticality": MEDIUM_CRITICALITY,
    },

    FIREWALL: {
        "asset_type": NETWORK_GATEWAY,
        "criticality": HIGH_CRITICALITY,
    },

    CVE: {
        "asset_type": APPLICATION_SERVER,
        "criticality": HIGH_CRITICALITY,
    },
}

# ==========================================================
# MITRE Technique Mapping
# ==========================================================

ATTACK_CATEGORY_MAPPING = {

    "T1110": CREDENTIAL_ATTACK,
    "T1059": EXECUTION,
    "T1087": DISCOVERY,
    "T1068": PRIVILEGE_ESCALATION,
    "T1021": LATERAL_MOVEMENT,
    "T1547": PERSISTENCE,
    "T1071": COMMAND_AND_CONTROL,
    "T1562": DEFENSE_EVASION,
    "T1486": IMPACT,
    "T1595": RECONNAISSANCE,
}

# ==========================================================
# Defaults
# ==========================================================

DEFAULT_ASSET_TYPE = UNKNOWN_ASSET
DEFAULT_CRITICALITY = MEDIUM_CRITICALITY
DEFAULT_ATTACK_CATEGORY = UNKNOWN_ATTACK
DEFAULT_RISK_WEIGHT = 50