"""
Incident Correlation Constants

This module contains immutable constants used by the
Incident Correlation Engine.
"""

# ==========================================================
# Correlation Window
# ==========================================================

DEFAULT_CORRELATION_WINDOW_MINUTES = 30

MAX_CORRELATION_WINDOW_MINUTES = 120

MIN_CORRELATION_WINDOW_MINUTES = 5

# ==========================================================
# Correlation Score
# ==========================================================

MIN_CORRELATION_SCORE = 0.0

MAX_CORRELATION_SCORE = 100.0

HIGH_CORRELATION_THRESHOLD = 80.0

MEDIUM_CORRELATION_THRESHOLD = 60.0

LOW_CORRELATION_THRESHOLD = 40.0

# ==========================================================
# Matching Weights
# Must total 1.0
# ==========================================================

SOURCE_IP_WEIGHT = 0.20

DESTINATION_IP_WEIGHT = 0.20

HOST_WEIGHT = 0.15

USER_WEIGHT = 0.10

MITRE_WEIGHT = 0.15

TIME_WEIGHT = 0.10

RISK_LEVEL_WEIGHT = 0.10

EVENT_CATEGORY_WEIGHT = 0.10

TOTAL_WEIGHT = (
    SOURCE_IP_WEIGHT
    + DESTINATION_IP_WEIGHT
    + HOST_WEIGHT
    + USER_WEIGHT
    + MITRE_WEIGHT
    + TIME_WEIGHT
    + RISK_LEVEL_WEIGHT
    + EVENT_CATEGORY_WEIGHT
)

# ==========================================================
# Incident Severity
# ==========================================================

SEVERITY_LOW = "Low"

SEVERITY_MEDIUM = "Medium"

SEVERITY_HIGH = "High"

SEVERITY_CRITICAL = "Critical"

# ==========================================================
# Risk Mapping
# ==========================================================

RISK_PRIORITY = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}

# ==========================================================
# Attack Chain
# ==========================================================

MAX_ATTACK_CHAIN_LENGTH = 50

DEFAULT_ATTACK_STAGE = "Unknown"

# ==========================================================
# Graph Limits
# ==========================================================

MAX_GRAPH_NODES = 5000

MAX_GRAPH_EDGES = 25000

# ==========================================================
# Default Incident Values
# ==========================================================

DEFAULT_INCIDENT_STATUS = "Open"

DEFAULT_INCIDENT_OWNER = "Unassigned"

DEFAULT_INCIDENT_PRIORITY = "P3"

DEFAULT_INCIDENT_TITLE = "Correlated Security Incident"

DEFAULT_DESCRIPTION = "Multiple related security events detected."

# ==========================================================
# Supported Entity Types
# ==========================================================

ENTITY_HOST = "host"

ENTITY_USER = "user"

ENTITY_SOURCE_IP = "source_ip"

ENTITY_DESTINATION_IP = "destination_ip"

ENTITY_PROCESS = "process"

ENTITY_FILE = "file"

ENTITY_DOMAIN = "domain"

ENTITY_URL = "url"

# ==========================================================
# Graph Edge Types
# ==========================================================

EDGE_COMMUNICATES = "communicates"

EDGE_LOGON = "logon"

EDGE_EXECUTION = "execution"

EDGE_NETWORK = "network"

EDGE_PROCESS = "process"

EDGE_FILE = "file"

# ==========================================================
# Time Formats
# ==========================================================

DEFAULT_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

# ==========================================================
# Incident Status
# ==========================================================

STATUS_OPEN = "Open"

STATUS_IN_PROGRESS = "In Progress"

STATUS_RESOLVED = "Resolved"

STATUS_CLOSED = "Closed"

# ==========================================================
# Model Metadata
# ==========================================================

ENGINE_NAME = "Incident Correlation Engine"

ENGINE_VERSION = "1.0.0"