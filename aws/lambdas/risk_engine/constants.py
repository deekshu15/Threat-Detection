"""
Risk Engine Constants

This module contains immutable constants used across the Risk Engine.
No business logic should be placed here.
"""

# ==========================================================
# Risk Thresholds
# ==========================================================

MIN_RISK_SCORE = 0.0
MAX_RISK_SCORE = 100.0

LOW_THRESHOLD = 0.0
MEDIUM_THRESHOLD = 40.0
HIGH_THRESHOLD = 70.0
CRITICAL_THRESHOLD = 90.0

RISK_LEVEL_LOW = "Low"
RISK_LEVEL_MEDIUM = "Medium"
RISK_LEVEL_HIGH = "High"
RISK_LEVEL_CRITICAL = "Critical"

# ==========================================================
# Risk Score Component Weights
# Must total 1.0
# ==========================================================

ML_PROBABILITY_WEIGHT = 0.40
CVSS_WEIGHT = 0.20
SEVERITY_WEIGHT = 0.15
IOC_WEIGHT = 0.15
MITRE_WEIGHT = 0.10

TOTAL_WEIGHT = (
    ML_PROBABILITY_WEIGHT
    + CVSS_WEIGHT
    + SEVERITY_WEIGHT
    + IOC_WEIGHT
    + MITRE_WEIGHT
)

# ==========================================================
# Severity Scores
# ==========================================================

SEVERITY_SCORES = {
    "Critical": 100,
    "High": 80,
    "Medium": 50,
    "Low": 20,
    "Informational": 10,
    "Unknown": 0,
    None: 0,
}

# ==========================================================
# IOC Scores
# ==========================================================

IOC_MATCH_SCORE = 100
IOC_NOT_FOUND_SCORE = 0

# ==========================================================
# Known Attack Scores
# ==========================================================

KNOWN_ATTACK_SCORE = 100
UNKNOWN_ATTACK_SCORE = 0

# ==========================================================
# MITRE ATT&CK Tactic Scores
# ==========================================================

MITRE_TACTIC_SCORES = {
    "Reconnaissance": 30,
    "Resource Development": 35,
    "Initial Access": 50,
    "Execution": 60,
    "Persistence": 70,
    "Privilege Escalation": 80,
    "Defense Evasion": 75,
    "Credential Access": 90,
    "Discovery": 45,
    "Lateral Movement": 85,
    "Collection": 70,
    "Command and Control": 95,
    "Exfiltration": 100,
    "Impact": 100,
}

DEFAULT_MITRE_SCORE = 25

# ==========================================================
# Confidence
# ==========================================================

MAX_CONFIDENCE = 1.0
MIN_CONFIDENCE = 0.0

MISSING_FIELD_PENALTY = 0.05
MISSING_CVE_PENALTY = 0.03
MISSING_IOC_PENALTY = 0.03

# ==========================================================
# Defaults
# ==========================================================

DEFAULT_MODEL_VERSION = "1.0.0"

DEFAULT_RISK_LEVEL = RISK_LEVEL_LOW

DEFAULT_REASON = "No significant indicators detected."

DEFAULT_EVENT_SOURCE = "Unknown"

DEFAULT_CVSS_SCORE = 0.0

DEFAULT_SEVERITY = "Unknown"

DEFAULT_PROBABILITY = 0.0