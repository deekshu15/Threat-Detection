"""
Feature Engineering Constants

Defines all constants used throughout the Feature
Engineering pipeline.

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

# =========================================================
# Pipeline
# =========================================================

PIPELINE_VERSION = "1.0"

# =========================================================
# Required Input Fields
# =========================================================

REQUIRED_COLUMNS = [

    "event_id",

    "timestamp",

    "src_ip",

    "dest_ip",

    "severity",

    "protocol",

    "event_category",

    "asset_criticality",

    "threat_score",

]

# =========================================================
# Severity Encoding
# =========================================================

SEVERITY_ENCODING = {

    "INFORMATIONAL": 0,

    "LOW": 1,

    "MEDIUM": 2,

    "HIGH": 3,

    "CRITICAL": 4,

    "UNKNOWN": 0,

}

# =========================================================
# Protocol Encoding
# =========================================================

PROTOCOL_ENCODING = {

    "TCP": 1,

    "UDP": 2,

    "ICMP": 3,

    "HTTP": 4,

    "HTTPS": 5,

    "DNS": 6,

    "SMTP": 7,

    "SSH": 8,

    "RDP": 9,

    "FTP": 10,

    "OTHER": 0,

}

# =========================================================
# Asset Encoding
# =========================================================

ASSET_ENCODING = {

    "LOW": 1,

    "MEDIUM": 2,

    "HIGH": 3,

    "CRITICAL": 4,

    "UNKNOWN": 0,

}

# =========================================================
# MITRE Tactic Encoding
# =========================================================

MITRE_TACTIC_ENCODING = {

    "Reconnaissance": 1,

    "Resource Development": 2,

    "Initial Access": 3,

    "Execution": 4,

    "Persistence": 5,

    "Privilege Escalation": 6,

    "Defense Evasion": 7,

    "Credential Access": 8,

    "Discovery": 9,

    "Lateral Movement": 10,

    "Collection": 11,

    "Command and Control": 12,

    "Exfiltration": 13,

    "Impact": 14,

}

# =========================================================
# Port Categories
# =========================================================

WELL_KNOWN_PORTS = {

    20: "FTP",

    21: "FTP",

    22: "SSH",

    23: "TELNET",

    25: "SMTP",

    53: "DNS",

    67: "DHCP",

    68: "DHCP",

    80: "HTTP",

    110: "POP3",

    123: "NTP",

    143: "IMAP",

    161: "SNMP",

    389: "LDAP",

    443: "HTTPS",

    445: "SMB",

    3306: "MYSQL",

    3389: "RDP",

    5432: "POSTGRES",

    6379: "REDIS",

    8080: "HTTP_ALT",

}

# =========================================================
# Business Hours
# =========================================================

BUSINESS_START = 9

BUSINESS_END = 18

# =========================================================
# Feature Columns
# =========================================================

FEATURE_COLUMNS = [

    # Temporal

    "hour",

    "minute",

    "day",

    "weekday",

    "month",

    "quarter",

    "is_weekend",

    "is_business_hours",

    # Network

    "protocol_encoded",

    "src_internal",

    "dest_internal",

    "same_subnet",

    "src_port",

    "dest_port",

    # Threat

    "severity_encoded",

    "cvss_normalized",

    "ioc_flag",

    "mitre_weight",

    "asset_score",

    "threat_score",

    # Behavioral

    "user_event_count",

    "host_event_count",

    "failed_login_count",

    "successful_login_count",

    "user_risk",

    "host_risk",

    # Statistical

    "rolling_event_count",

    "attack_frequency",

    "average_threat_score",

]

# =========================================================
# Output Column
# =========================================================

TARGET_COLUMN = "label"

# =========================================================
# Numerical Features
# =========================================================

NUMERIC_FEATURES = [

    feature

    for feature in FEATURE_COLUMNS

    if feature not in {

        "protocol_encoded",

        "severity_encoded",

    }

]

# =========================================================
# Categorical Features
# =========================================================

CATEGORICAL_FEATURES = [

    "protocol_encoded",

    "severity_encoded",

]