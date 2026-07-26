"""
Incident Correlation Validator

Validates and normalizes events received from the
Risk Engine before correlation begins.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Dict


# ==========================================================
# Validated Event
# ==========================================================

@dataclass
class ValidatedIncidentEvent:
    """
    Standard event passed into the Incident Correlation Engine.
    """

    event_id: str

    timestamp: datetime

    source_type: str

    source_name: str

    src_ip: str

    dest_ip: str

    src_port: int

    dest_port: int

    protocol: str

    host: str

    user: str

    event_category: str

    event_action: str

    severity: str

    prediction: str

    risk_score: float

    risk_level: str

    confidence: float

    matched_ioc: bool

    known_attack: bool

    mitre_tactic: str

    mitre_technique_id: str

    metadata: Dict[str, Any]


# ==========================================================
# Validator
# ==========================================================

class IncidentValidator:

    REQUIRED_FIELDS = [

        "event_id",

        "timestamp",

        "src_ip",

        "dest_ip",

        "host",

        "user",

        "event_category",

        "prediction",

        "risk_score",

        "risk_level",

        "confidence",

        "matched_ioc",

        "known_attack",

        "mitre_tactic",

        "mitre_technique_id",
    ]

    # ------------------------------------------------------

    @classmethod
    def validate(
        cls,
        event: Dict[str, Any],
    ) -> ValidatedIncidentEvent:

        cls._validate_required_fields(event)

        return ValidatedIncidentEvent(

            event_id=str(event["event_id"]),

            timestamp=cls._validate_timestamp(
                event["timestamp"]
            ),

            source_type=str(
                event.get("source_type", "")
            ),

            source_name=str(
                event.get("source_name", "")
            ),

            src_ip=cls._validate_ip(
                event["src_ip"]
            ),

            dest_ip=cls._validate_ip(
                event["dest_ip"]
            ),

            src_port=cls._validate_port(
                event.get("src_port", 0)
            ),

            dest_port=cls._validate_port(
                event.get("dest_port", 0)
            ),

            protocol=str(
                event.get("protocol", "")
            ),

            host=str(
                event["host"]
            ),

            user=str(
                event["user"]
            ),

            event_category=str(
                event["event_category"]
            ),

            event_action=str(
                event.get("event_action", "")
            ),

            severity=str(
                event.get("severity", "")
            ),

            prediction=str(
                event["prediction"]
            ),

            risk_score=cls._validate_score(
                event["risk_score"]
            ),

            risk_level=cls._validate_risk_level(
                event["risk_level"]
            ),

            confidence=cls._validate_confidence(
                event["confidence"]
            ),

            matched_ioc=bool(
                event["matched_ioc"]
            ),

            known_attack=bool(
                event["known_attack"]
            ),

            mitre_tactic=str(
                event["mitre_tactic"]
            ),

            mitre_technique_id=str(
                event["mitre_technique_id"]
            ),

            metadata=dict(
                event.get("metadata", {})
            ),
        )

    # ------------------------------------------------------

    @classmethod
    def _validate_required_fields(
        cls,
        event: Dict[str, Any],
    ) -> None:

        missing = [

            field

            for field in cls.REQUIRED_FIELDS

            if field not in event

        ]

        if missing:

            raise ValueError(
                f"Missing required fields: {', '.join(missing)}"
            )

    # ------------------------------------------------------

    @staticmethod
    def _validate_timestamp(
        value: Any,
    ) -> datetime:

        if isinstance(value, datetime):

            return value

        try:

            return datetime.fromisoformat(
                str(value).replace("Z", "")
            )

        except Exception:

            raise ValueError(
                "Invalid timestamp format."
            )

    # ------------------------------------------------------

    @staticmethod
    def _validate_ip(
        value: Any,
    ) -> str:

        try:

            return str(
                ip_address(str(value))
            )

        except Exception:

            raise ValueError(
                f"Invalid IP address: {value}"
            )

    # ------------------------------------------------------

    @staticmethod
    def _validate_port(
        value: Any,
    ) -> int:

        try:

            port = int(value)

        except Exception:

            raise ValueError(
                "Port must be numeric."
            )

        if port < 0 or port > 65535:

            raise ValueError(
                "Invalid port number."
            )

        return port

    # ------------------------------------------------------

    @staticmethod
    def _validate_score(
        value: Any,
    ) -> float:

        try:

            score = float(value)

        except Exception:

            raise ValueError(
                "Risk score must be numeric."
            )

        if score < 0:
            score = 0

        if score > 100:
            score = 100

        return score

    # ------------------------------------------------------

    @staticmethod
    def _validate_confidence(
        value: Any,
    ) -> float:

        try:

            confidence = float(value)

        except Exception:

            raise ValueError(
                "Confidence must be numeric."
            )

        if confidence < 0:
            confidence = 0.0

        if confidence > 1:
            confidence = 1.0

        return confidence

    # ------------------------------------------------------

    @staticmethod
    def _validate_risk_level(
        value: str,
    ) -> str:

        allowed = {

            "Low",

            "Medium",

            "High",

            "Critical",

        }

        if value not in allowed:

            raise ValueError(
                f"Invalid risk level: {value}"
            )

        return value


# ==========================================================
# Public Helper
# ==========================================================

def validate_event(
    event: Dict[str, Any],
) -> ValidatedIncidentEvent:
    """
    Validate and normalize an incoming event.
    """

    return IncidentValidator.validate(event)