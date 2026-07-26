"""
Application constants for the AI-Assisted Threat Detection Dashboard.

This module contains values that rarely change during execution.
"""

# ============================================================
# Supported File Types
# ============================================================

SUPPORTED_FILE_TYPES = [
    ".csv",
    ".json",
    ".parquet"
]

# ============================================================
# Security Log Sources
# ============================================================

DATA_SOURCES = [
    "windows",
    "linux",
    "ids",
    "firewall",
    "cve",
    "threat_feeds",
    "incident_records"
]

# ============================================================
# Severity Levels
# ============================================================

SEVERITY_LEVELS = [
    "Low",
    "Medium",
    "High",
    "Critical"
]

# ============================================================
# Output Folder Names
# ============================================================

NORMALIZED_FOLDER = "normalized"

ENRICHED_FOLDER = "enriched"

MITRE_FOLDER = "mitre"

# ============================================================
# Default Output Format
# ============================================================

OUTPUT_FORMAT = "parquet"

# ============================================================
# Project Information
# ============================================================

PROJECT_NAME = "AI-Assisted Threat Detection Dashboard"

MODULE_NAME = "Security Data Aggregation & Threat Intelligence"

VERSION = "1.0.0"