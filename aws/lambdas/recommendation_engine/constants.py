"""
Recommendation Engine Constants

Shared constants used throughout the
Recommendation Engine.
"""

# ==========================================================
# Engine Metadata
# ==========================================================

ENGINE_NAME = "Recommendation Engine"

ENGINE_VERSION = "1.0.0"

# ==========================================================
# Recommendation Priority
# ==========================================================

PRIORITY_CRITICAL = "Critical"

PRIORITY_HIGH = "High"

PRIORITY_MEDIUM = "Medium"

PRIORITY_LOW = "Low"

# ==========================================================
# Maximum Recommendations
# ==========================================================

MAX_RECOMMENDATIONS = 10

MAX_CONTAINMENT_ACTIONS = 10

MAX_RECOVERY_ACTIONS = 10

MAX_INVESTIGATION_STEPS = 15

# ==========================================================
# MITRE Severity Mapping
# ==========================================================

MITRE_PRIORITY = {

    "Impact": PRIORITY_CRITICAL,

    "Exfiltration": PRIORITY_CRITICAL,

    "Command and Control": PRIORITY_CRITICAL,

    "Credential Access": PRIORITY_HIGH,

    "Privilege Escalation": PRIORITY_HIGH,

    "Persistence": PRIORITY_HIGH,

    "Lateral Movement": PRIORITY_HIGH,

    "Defense Evasion": PRIORITY_HIGH,

    "Execution": PRIORITY_MEDIUM,

    "Discovery": PRIORITY_MEDIUM,

    "Collection": PRIORITY_MEDIUM,

    "Initial Access": PRIORITY_MEDIUM,

    "Reconnaissance": PRIORITY_LOW,

    "Resource Development": PRIORITY_LOW,
}

# ==========================================================
# Incident Severity Mapping
# ==========================================================

SEVERITY_CRITICAL = "Critical"

SEVERITY_HIGH = "High"

SEVERITY_MEDIUM = "Medium"

SEVERITY_LOW = "Low"

# ==========================================================
# Default Incident Summary
# ==========================================================

DEFAULT_SUMMARY = (
    "Multiple correlated security events detected."
)

DEFAULT_ROOT_CAUSE = (
    "Potential malicious activity identified."
)

DEFAULT_EXECUTIVE_SUMMARY = (
    "Immediate investigation is recommended."
)

# ==========================================================
# Recommendation Categories
# ==========================================================

CATEGORY_CONTAINMENT = "Containment"

CATEGORY_ERADICATION = "Eradication"

CATEGORY_RECOVERY = "Recovery"

CATEGORY_MONITORING = "Monitoring"

CATEGORY_INVESTIGATION = "Investigation"

CATEGORY_PREVENTION = "Prevention"

# ==========================================================
# Response Status
# ==========================================================

STATUS_SUCCESS = "Success"

STATUS_FAILED = "Failed"

# ==========================================================
# Confidence Thresholds
# ==========================================================

HIGH_CONFIDENCE = 0.85

MEDIUM_CONFIDENCE = 0.60

LOW_CONFIDENCE = 0.40

# ==========================================================
# Default Risk Thresholds
# ==========================================================

CRITICAL_SCORE = 90

HIGH_SCORE = 75

MEDIUM_SCORE = 50

LOW_SCORE = 25

# ==========================================================
# Recommendation Templates
# ==========================================================

ISOLATE_HOST = (
    "Immediately isolate affected host(s) from the network."
)

DISABLE_ACCOUNT = (
    "Temporarily disable compromised user accounts."
)

BLOCK_IP = (
    "Block malicious IP addresses at the firewall."
)

RESET_CREDENTIALS = (
    "Reset credentials for affected accounts."
)

TERMINATE_PROCESS = (
    "Terminate suspicious running processes."
)

REMOVE_PERSISTENCE = (
    "Remove persistence mechanisms from affected systems."
)

PATCH_SYSTEMS = (
    "Apply the latest security patches."
)

SCAN_ENDPOINTS = (
    "Run a full endpoint malware scan."
)

COLLECT_FORENSICS = (
    "Collect forensic artifacts for investigation."
)

ENABLE_MONITORING = (
    "Increase monitoring for related systems."
)

UPDATE_SIGNATURES = (
    "Update IDS/IPS detection signatures."
)

REVIEW_LOGS = (
    "Review authentication, endpoint, and network logs."
)

NOTIFY_SOC = (
    "Notify the Security Operations Center."
)

ESCALATE_IR = (
    "Escalate to the Incident Response team."
)

VERIFY_RECOVERY = (
    "Verify system integrity before restoring services."
)

# ==========================================================
# Supported Output Sections
# ==========================================================

SECTION_SUMMARY = "summary"

SECTION_ROOT_CAUSE = "root_cause"

SECTION_RECOMMENDATIONS = "recommendations"

SECTION_CONTAINMENT = "containment"

SECTION_RECOVERY = "recovery"

SECTION_INVESTIGATION = "investigation"

SECTION_EXECUTIVE = "executive_summary"

SECTION_METADATA = "metadata"