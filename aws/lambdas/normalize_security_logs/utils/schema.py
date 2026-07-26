"""
Common event schema used across all security data sources.
"""

from dataclasses import dataclass, asdict, field
from typing import Optional, List


@dataclass
class SecurityEvent:
    """
    Standardized security event.
    """

    event_id: str
    timestamp: str
    source: str

    hostname: Optional[str] = None
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    raw_message: Optional[str] = None
    ingestion_time: Optional[str] = None

    def to_dict(self):
        """Convert dataclass to dictionary."""
        return asdict(self)


# ==============================================================
# Vulnerability Event Schema
# ==============================================================

@dataclass
class VulnerabilityEvent:
    """
    Standardized vulnerability event (NVD CVE).
    """

    event_id: str
    timestamp: str

    source: str = "cve"
    event_type: str = "vulnerability"

    severity: str = "UNKNOWN"
    cvss_score: float = 0.0

    cwe: str = ""

    vendor: str = ""
    product: str = ""

    description: str = ""

    references: List[str] = field(default_factory=list)

    def to_dict(self):
        """Convert dataclass to dictionary."""
        return asdict(self)