"""
Feature Engineering Validator

Validates enriched security events before feature
generation.

Responsibilities
----------------
- Validate required fields
- Validate numeric ranges
- Validate threat enrichment
- Validate timestamp
- Validate encoded values
- Validate ML readiness

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

from .constants import REQUIRED_COLUMNS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# Exceptions
# ---------------------------------------------------------

class ValidationError(Exception):
    """Base validation exception."""


class MissingFieldError(ValidationError):
    """Required field missing."""


class InvalidFieldError(ValidationError):
    """Invalid field value."""


# ---------------------------------------------------------
# Validation Result
# ---------------------------------------------------------

@dataclass(slots=True)
class ValidatedFeatureEvent:

    event_id: str

    timestamp: datetime

    src_ip: str

    dest_ip: str

    protocol: str

    severity: str

    event_category: str

    asset_criticality: str

    threat_score: float

    cvss_score: Optional[float] = None

    matched_ioc: bool = False

    mitre_technique_id: Optional[str] = None

    mitre_tactic: Optional[str] = None

    user: Optional[str] = None

    host: Optional[str] = None

    src_port: Optional[int] = None

    dest_port: Optional[int] = None

    metadata: Optional[dict] = None


# ---------------------------------------------------------
# Validator
# ---------------------------------------------------------

class FeatureValidator:

    """
    Validate enriched events before feature generation.
    """

    def validate(
        self,
        event: Dict,
    ) -> ValidatedFeatureEvent:

        self._validate_required_fields(
            event
        )

        return ValidatedFeatureEvent(

            event_id=self._validate_string(
                event["event_id"],
                "event_id",
            ),

            timestamp=self._validate_timestamp(
                event["timestamp"]
            ),

            src_ip=self._validate_ip(
                event["src_ip"],
                "src_ip",
            ),

            dest_ip=self._validate_ip(
                event["dest_ip"],
                "dest_ip",
            ),

            protocol=self._validate_protocol(
                event.get(
                    "protocol",
                    "OTHER",
                )
            ),

            severity=self._validate_severity(
                event.get(
                    "severity",
                    "UNKNOWN",
                )
            ),

            event_category=self._validate_string(
                event.get(
                    "event_category",
                    "OTHER",
                ),
                "event_category",
            ),

            asset_criticality=self._validate_asset(
                event.get(
                    "asset_criticality",
                    "UNKNOWN",
                )
            ),

            threat_score=self._validate_score(
                event.get(
                    "threat_score",
                    0,
                ),
                "threat_score",
            ),

            cvss_score=self._validate_optional_cvss(
                event.get(
                    "cvss_score"
                )
            ),

            matched_ioc=bool(
                event.get(
                    "matched_ioc",
                    False,
                )
            ),

            mitre_technique_id=event.get(
                "mitre_technique_id"
            ),

            mitre_tactic=event.get(
                "mitre_tactic"
            ),

            user=event.get(
                "user"
            ),

            host=event.get(
                "host"
            ),

            src_port=self._validate_optional_port(
                event.get(
                    "src_port"
                )
            ),

            dest_port=self._validate_optional_port(
                event.get(
                    "dest_port"
                )
            ),

            metadata=event.get(
                "metadata",
                {},
            ),
        )
            # -----------------------------------------------------
    # Required Fields
    # -----------------------------------------------------

    def _validate_required_fields(
        self,
        event: Dict,
    ) -> None:

        missing = []

        for field in REQUIRED_COLUMNS:

            if field not in event:

                missing.append(field)

                continue

            value = event[field]

            if value is None:

                missing.append(field)

                continue

            if isinstance(value, str):

                if not value.strip():

                    missing.append(field)

        if missing:

            raise MissingFieldError(

                f"Missing required fields: {', '.join(missing)}"

            )

    # -----------------------------------------------------
    # String Validation
    # -----------------------------------------------------

    def _validate_string(
        self,
        value,
        field: str,
    ) -> str:

        if value is None:

            raise InvalidFieldError(

                f"{field} cannot be None"

            )

        value = str(value).strip()

        if not value:

            raise InvalidFieldError(

                f"{field} cannot be empty"

            )

        return value

    # -----------------------------------------------------
    # Timestamp
    # -----------------------------------------------------

    def _validate_timestamp(
        self,
        value,
    ) -> datetime:

        if isinstance(value, datetime):

            return value

        try:

            return datetime.fromisoformat(

                str(value).replace(
                    "Z",
                    "+00:00",
                )

            )

        except Exception:

            raise InvalidFieldError(

                "Invalid timestamp"

            )

    # -----------------------------------------------------
    # IP Validation
    # -----------------------------------------------------

    def _validate_ip(
        self,
        value,
        field: str,
    ) -> str:

        value = self._validate_string(
            value,
            field,
        )

        try:

            ipaddress.ip_address(
                value
            )

        except ValueError:

            raise InvalidFieldError(

                f"Invalid IP Address: {field}"

            )

        return value

    # -----------------------------------------------------
    # Protocol Validation
    # -----------------------------------------------------

    def _validate_protocol(
        self,
        protocol,
    ) -> str:

        if protocol is None:

            return "OTHER"

        protocol = (

            str(protocol)

            .upper()

            .strip()

        )

        return protocol if protocol else "OTHER"

    # -----------------------------------------------------
    # Severity
    # -----------------------------------------------------

    def _validate_severity(
        self,
        severity,
    ) -> str:

        if severity is None:

            return "UNKNOWN"

        severity = (

            str(severity)

            .upper()

            .strip()

        )

        valid = {

            "INFORMATIONAL",

            "LOW",

            "MEDIUM",

            "HIGH",

            "CRITICAL",

            "UNKNOWN",

        }

        if severity not in valid:

            return "UNKNOWN"

        return severity

    # -----------------------------------------------------
    # Asset Criticality
    # -----------------------------------------------------

    def _validate_asset(
        self,
        asset,
    ) -> str:

        if asset is None:

            return "UNKNOWN"

        asset = (

            str(asset)

            .upper()

            .strip()

        )

        valid = {

            "LOW",

            "MEDIUM",

            "HIGH",

            "CRITICAL",

            "UNKNOWN",

        }

        if asset not in valid:

            return "UNKNOWN"

        return asset
        # -----------------------------------------------------
    # Threat Score
    # -----------------------------------------------------

    def _validate_score(
        self,
        value,
        field: str,
    ) -> float:

        try:

            score = float(value)

        except (TypeError, ValueError):

            raise InvalidFieldError(

                f"{field} must be numeric"

            )

        if score < 0:

            raise InvalidFieldError(

                f"{field} cannot be negative"

            )

        if score > 100:

            score = 100.0

        return score

    # -----------------------------------------------------
    # Optional CVSS
    # -----------------------------------------------------

    def _validate_optional_cvss(
        self,
        value,
    ) -> Optional[float]:

        if value is None:

            return None

        try:

            score = float(value)

        except (TypeError, ValueError):

            logger.warning(

                "Invalid CVSS score ignored."

            )

            return None

        if score < 0:

            return 0.0

        if score > 10:

            return 10.0

        return score

    # -----------------------------------------------------
    # Optional Port
    # -----------------------------------------------------

    def _validate_optional_port(
        self,
        value,
    ) -> Optional[int]:

        if value is None:

            return None

        try:

            port = int(value)

        except (TypeError, ValueError):

            raise InvalidFieldError(

                "Port must be an integer"

            )

        if not 0 <= port <= 65535:

            raise InvalidFieldError(

                f"Invalid port: {port}"

            )

        return port

    # -----------------------------------------------------
    # Batch Validation
    # -----------------------------------------------------

    def validate_events(
        self,
        events: List[Dict],
    ) -> List[ValidatedFeatureEvent]:

        validated = []

        for index, event in enumerate(events):

            try:

                validated.append(

                    self.validate(event)

                )

            except ValidationError as exc:

                logger.warning(

                    "Validation failed for event %d: %s",

                    index,

                    exc,

                )

        return validated

    # -----------------------------------------------------
    # Statistics
    # -----------------------------------------------------

    def validation_summary(
        self,
        events: List[Dict],
    ) -> Dict:

        total = len(events)

        valid = 0

        invalid = 0

        for event in events:

            try:

                self.validate(event)

                valid += 1

            except ValidationError:

                invalid += 1

        return {

            "total_events": total,

            "valid_events": valid,

            "invalid_events": invalid,

            "success_rate": (

                round(

                    valid / total,

                    4,

                )

                if total

                else 0

            ),

        }


# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_validator = FeatureValidator()


def validate_event(
    event: Dict,
) -> ValidatedFeatureEvent:

    return _validator.validate(event)


def validate_events(
    events: List[Dict],
) -> List[ValidatedFeatureEvent]:

    return _validator.validate_events(events)


def validation_summary(
    events: List[Dict],
) -> Dict:

    return _validator.validation_summary(events)


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    sample_event = {

        "event_id": "EVT-1001",

        "timestamp": "2026-07-25T10:15:30",

        "src_ip": "192.168.1.10",

        "dest_ip": "10.0.0.15",

        "protocol": "TCP",

        "severity": "HIGH",

        "event_category": "Malware",

        "asset_criticality": "CRITICAL",

        "threat_score": 94.2,

        "cvss_score": 9.8,

        "matched_ioc": True,

        "mitre_technique_id": "T1486",

        "mitre_tactic": "Impact",

        "src_port": 443,

        "dest_port": 51515,

        "user": "admin",

        "host": "server-01",

    }

    validated = validate_event(

        sample_event

    )

    print(validated)