"""
Threat Enrichment Validator

Validates normalized security events before enrichment.

Responsibilities
----------------
- Validate required fields
- Normalize values
- Validate IP addresses
- Validate ports
- Validate timestamps
- Normalize severity
- Normalize protocol
- Normalize event category
- Normalize event action
- Validate MITRE fields
- Provide strongly typed event object

Author: NextCare AI / Threat Detection Platform
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class ValidationError(Exception):
    """Base validation exception."""


class MissingFieldError(ValidationError):
    """Raised when a required field is missing."""


class InvalidFieldError(ValidationError):
    """Raised when a field contains invalid data."""


# --------------------------------------------------------------------------
# Supported values
# --------------------------------------------------------------------------

VALID_PROTOCOLS = {
    "TCP",
    "UDP",
    "ICMP",
    "HTTP",
    "HTTPS",
    "DNS",
    "SSH",
    "FTP",
    "SMTP",
    "POP3",
    "IMAP",
    "RDP",
    "SMB",
    "TLS",
    "UNKNOWN"
}

VALID_SOURCE_TYPES = {
    "WINDOWS",
    "LINUX",
    "IDS",
    "IPS",
    "FIREWALL",
    "EDR",
    "EMAIL",
    "PROXY",
    "WEB",
    "CLOUD",
    "AWS",
    "AZURE",
    "GCP",
    "OTHER"
}

VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    "UNKNOWN"
}

VALID_EVENT_CATEGORIES = {
    "AUTHENTICATION",
    "NETWORK",
    "PROCESS",
    "FILE",
    "REGISTRY",
    "SYSTEM",
    "MALWARE",
    "PRIVILEGE_ESCALATION",
    "LATERAL_MOVEMENT",
    "PERSISTENCE",
    "DISCOVERY",
    "DEFENSE_EVASION",
    "COMMAND_AND_CONTROL",
    "EXFILTRATION",
    "IMPACT",
    "OTHER"
}

MITRE_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$")

# --------------------------------------------------------------------------
# Dataclass
# --------------------------------------------------------------------------


@dataclass(slots=True)
class ValidatedThreatEvent:
    """
    Canonical threat enrichment event.

    Every downstream module should consume this object
    instead of raw dictionaries.
    """

    event_id: str
    timestamp: datetime

    source_type: str
    source_name: str

    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None

    src_port: Optional[int] = None
    dest_port: Optional[int] = None

    protocol: str = "UNKNOWN"

    user: Optional[str] = None
    host: Optional[str] = None

    event_category: str = "OTHER"
    event_action: str = "UNKNOWN"

    severity: str = "UNKNOWN"

    label_raw: Optional[str] = None

    raw_log: str = ""

    enrichment_status: str = "PENDING"

    matched_ioc: bool = False

    mitre_technique_id: Optional[str] = None

    mitre_tactic: Optional[str] = None

    ingested_at: Optional[datetime] = None

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert validated event to dictionary.
        """

        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source_type": self.source_type,
            "source_name": self.source_name,
            "src_ip": self.src_ip,
            "dest_ip": self.dest_ip,
            "src_port": self.src_port,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "user": self.user,
            "host": self.host,
            "event_category": self.event_category,
            "event_action": self.event_action,
            "severity": self.severity,
            "label_raw": self.label_raw,
            "raw_log": self.raw_log,
            "enrichment_status": self.enrichment_status,
            "matched_ioc": self.matched_ioc,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_tactic": self.mitre_tactic,
            "ingested_at": (
                self.ingested_at.isoformat()
                if self.ingested_at
                else None
            ),
            "metadata": self.metadata,
        }


# --------------------------------------------------------------------------
# Validator
# --------------------------------------------------------------------------


class ThreatEnrichmentValidator:
    """
    Production-grade validator for Threat Enrichment.

    This class validates and normalizes all incoming events before
    they are passed into the enrichment pipeline.
    """

    REQUIRED_FIELDS = (
        "event_id",
        "timestamp",
        "source_type",
        "source_name",
        "event_category",
        "event_action",
        "raw_log",
    )

    def __init__(self) -> None:
        logger.info("ThreatEnrichmentValidator initialized")

    def validate(self, event: Dict[str, Any]) -> ValidatedThreatEvent:
        """
        Validate an incoming event dictionary and
        return a normalized ValidatedThreatEvent.
        """

        if not isinstance(event, dict):
            raise InvalidFieldError(
                "Incoming event must be a dictionary."
            )

        self._validate_required_fields(event)

        return ValidatedThreatEvent(
            event_id=self._validate_uuid(event["event_id"]),
            timestamp=self._validate_timestamp(event["timestamp"]),
            source_type=self._validate_source_type(
                event["source_type"]
            ),
            source_name=str(event["source_name"]).strip(),
                        src_ip=self._validate_ip(
                event.get("src_ip")
            ),

            dest_ip=self._validate_ip(
                event.get("dest_ip")
            ),

            src_port=self._validate_port(
                event.get("src_port")
            ),

            dest_port=self._validate_port(
                event.get("dest_port")
            ),

            protocol=self._validate_protocol(
                event.get("protocol")
            ),

            user=self._normalize_optional(
                event.get("user")
            ),

            host=self._normalize_optional(
                event.get("host")
            ),

            event_category=self._validate_event_category(
                event.get("event_category")
            ),

            event_action=self._normalize_string(
                event.get("event_action"),
                default="UNKNOWN",
            ),

            severity=self._validate_severity(
                event.get("severity")
            ),

            label_raw=self._normalize_optional(
                event.get("label_raw")
            ),

            raw_log=self._validate_raw_log(
                event.get("raw_log")
            ),

            enrichment_status=self._normalize_string(
                event.get(
                    "enrichment_status",
                    "PENDING",
                ),
                default="PENDING",
            ),

            matched_ioc=bool(
                event.get("matched_ioc", False)
            ),

            mitre_technique_id=self._validate_mitre(
                event.get("mitre_technique_id")
            ),

            mitre_tactic=self._normalize_optional(
                event.get("mitre_tactic")
            ),

            ingested_at=self._validate_optional_timestamp(
                event.get("ingested_at")
            ),

            metadata=event.get("metadata", {}),
        )

    # -----------------------------------------------------
    # Required fields
    # -----------------------------------------------------

    def _validate_required_fields(
        self,
        event: Dict[str, Any],
    ) -> None:

        for field in self.REQUIRED_FIELDS:

            if field not in event:

                raise MissingFieldError(
                    f"Missing required field '{field}'."
                )

            if event[field] is None:

                raise MissingFieldError(
                    f"Required field '{field}' is None."
                )

            if (
                isinstance(event[field], str)
                and not event[field].strip()
            ):

                raise MissingFieldError(
                    f"Required field '{field}' is empty."
                )

    # -----------------------------------------------------
    # UUID
    # -----------------------------------------------------

    def _validate_uuid(
        self,
        value: Any,
    ) -> str:

        try:

            UUID(str(value))

            return str(value)

        except Exception as exc:

            raise InvalidFieldError(
                f"Invalid UUID: {value}"
            ) from exc

    # -----------------------------------------------------
    # Timestamp
    # -----------------------------------------------------

    def _validate_timestamp(
        self,
        value: Any,
    ) -> datetime:

        if value is None:

            raise InvalidFieldError(
                "Timestamp cannot be None."
            )

        value = str(value).replace(
            "Z",
            "+00:00",
        )

        try:

            return datetime.fromisoformat(value)

        except Exception as exc:

            raise InvalidFieldError(
                f"Invalid timestamp '{value}'."
            ) from exc

    def _validate_optional_timestamp(
        self,
        value: Any,
    ) -> Optional[datetime]:

        if value in (
            None,
            "",
            "None",
            "nan",
        ):

            return None

        return self._validate_timestamp(value)

    # -----------------------------------------------------
    # IP Address
    # -----------------------------------------------------

    def _validate_ip(
        self,
        value: Any,
    ) -> Optional[str]:

        if value in (
            None,
            "",
            "None",
            "nan",
        ):

            return None

        try:

            ipaddress.ip_address(str(value))

            return str(value)

        except ValueError:

            logger.warning(
                "Invalid IP address: %s",
                value,
            )

            return None

    # -----------------------------------------------------
    # Port
    # -----------------------------------------------------

    def _validate_port(
        self,
        value: Any,
    ) -> Optional[int]:

        if value in (
            None,
            "",
            "None",
            "nan",
        ):

            return None

        try:

            port = int(float(value))

        except Exception:

            raise InvalidFieldError(
                f"Invalid port '{value}'."
            )

        if port < 0 or port > 65535:

            raise InvalidFieldError(
                f"Port '{port}' outside valid range."
            )

        return port

    # -----------------------------------------------------
    # Protocol
    # -----------------------------------------------------

    def _validate_protocol(
        self,
        value: Any,
    ) -> str:

        if value in (
            None,
            "",
            "None",
            "nan",
        ):

            return "UNKNOWN"

        protocol = (
            str(value)
            .strip()
            .upper()
        )

        if protocol not in VALID_PROTOCOLS:

            logger.debug(
                "Unknown protocol '%s'",
                protocol,
            )

            return "UNKNOWN"

        return protocol

    # -----------------------------------------------------
    # Severity
    # -----------------------------------------------------

    def _validate_severity(
        self,
        value: Any,
    ) -> str:

        if value in (
            None,
            "",
            "None",
            "nan",
        ):

            return "UNKNOWN"

        severity = (
            str(value)
            .strip()
            .upper()
        )

        if severity not in VALID_SEVERITIES:

            logger.warning(
                "Unknown severity '%s'",
                severity,
            )

            return "UNKNOWN"

        return severity
        # -----------------------------------------------------
    # Event Category
    # -----------------------------------------------------

    def _validate_event_category(
        self,
        value: Any,
    ) -> str:

        if value in (
            None,
            "",
            "None",
            "nan",
        ):

            return "OTHER"

        category = (
            str(value)
            .strip()
            .upper()
            .replace("-", "_")
            .replace(" ", "_")
        )

        if category not in VALID_EVENT_CATEGORIES:

            logger.warning(
                "Unknown event category '%s'",
                category,
            )

            return "OTHER"

        return category

    # -----------------------------------------------------
    # MITRE Technique
    # -----------------------------------------------------

    def _validate_mitre(
        self,
        value: Any,
    ) -> Optional[str]:

        if value in (
            None,
            "",
            "None",
            "nan",
        ):

            return None

        technique = (
            str(value)
            .strip()
            .upper()
        )

        if not MITRE_REGEX.match(technique):

            logger.warning(
                "Invalid MITRE Technique '%s'",
                technique,
            )

            return None

        return technique

    # -----------------------------------------------------
    # Raw Log
    # -----------------------------------------------------

    def _validate_raw_log(
        self,
        value: Any,
    ) -> str:

        if value is None:

            return ""

        return str(value).strip()

    # -----------------------------------------------------
    # String Helpers
    # -----------------------------------------------------

    def _normalize_string(
        self,
        value: Any,
        default: str = "",
    ) -> str:

        if value in (
            None,
            "",
            "None",
            "nan",
        ):

            return default

        return str(value).strip()

    def _normalize_optional(
        self,
        value: Any,
    ) -> Optional[str]:

        if value in (
            None,
            "",
            "None",
            "nan",
        ):

            return None

        value = str(value).strip()

        if not value:

            return None

        return value

    # -----------------------------------------------------
    # Batch Validation
    # -----------------------------------------------------

    def validate_events(
        self,
        events: List[Dict[str, Any]],
    ) -> List[ValidatedThreatEvent]:

        validated_events: List[
            ValidatedThreatEvent
        ] = []

        logger.info(
            "Validating %d events...",
            len(events),
        )

        for index, event in enumerate(events):

            try:

                validated_events.append(
                    self.validate(event)
                )

            except ValidationError as exc:

                logger.error(
                    "Validation failed for event %d: %s",
                    index,
                    exc,
                )

        logger.info(
            "Successfully validated %d/%d events.",
            len(validated_events),
            len(events),
        )

        return validated_events

    # -----------------------------------------------------
    # Statistics
    # -----------------------------------------------------

    def validation_summary(
        self,
        events: List[ValidatedThreatEvent],
    ) -> Dict[str, Any]:

        protocols = {}
        categories = {}
        severities = {}

        for event in events:

            protocols[event.protocol] = (
                protocols.get(
                    event.protocol,
                    0,
                )
                + 1
            )

            categories[event.event_category] = (
                categories.get(
                    event.event_category,
                    0,
                )
                + 1
            )

            severities[event.severity] = (
                severities.get(
                    event.severity,
                    0,
                )
                + 1
            )

        return {
            "total_events": len(events),
            "protocols": protocols,
            "categories": categories,
            "severities": severities,
        }


# ---------------------------------------------------------
# Public Convenience Functions
# ---------------------------------------------------------

_validator = ThreatEnrichmentValidator()


def validate_event(
    event: Dict[str, Any],
) -> ValidatedThreatEvent:
    """
    Validate a single event.

    Example
    -------
    validated = validate_event(event)
    """

    return _validator.validate(event)


def validate_events(
    events: List[Dict[str, Any]],
) -> List[ValidatedThreatEvent]:
    """
    Validate multiple events.

    Example
    -------
    validated = validate_events(events)
    """

    return _validator.validate_events(events)


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s - %(message)s",
    )

    sample_event = {

        "event_id": "340cc16b-4176-44f2-b367-56a53484a3d2",

        "timestamp": "2026-07-09T14:01:36Z",

        "source_type": "WINDOWS",

        "source_name": "Windows Security",

        "src_ip": "192.168.1.10",

        "dest_ip": "10.0.0.5",

        "src_port": 443,

        "dest_port": 3389,

        "protocol": "TCP",

        "user": "Administrator",

        "host": "SERVER-01",

        "event_category": "Authentication",

        "event_action": "Login Failed",

        "severity": "High",

        "raw_log": "Failed login detected",

        "mitre_technique_id": "T1110",
    }

    validated = validate_event(sample_event)

    print(validated)

    print()

    print(validated.to_dict())