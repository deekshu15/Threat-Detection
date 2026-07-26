"""
Risk Engine Validator

Validates and normalizes events received from the ML Engine before
they are processed by the Risk Engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from . import constants


# ==========================================================
# Validated Event
# ==========================================================

@dataclass
class ValidatedRiskEvent:
    """
    Normalized event passed to the Risk Engine.
    """

    event_id: str

    prediction: str
    probability: float

    severity: str
    severity_score: float

    risk_weight: float

    cvss_score: float

    matched_ioc: bool

    known_attack: bool

    mitre_tactic: str
    mitre_technique_id: str

    timestamp: str

    metadata: Dict[str, Any]


# ==========================================================
# Validator
# ==========================================================

class RiskEventValidator:

    REQUIRED_FIELDS = [
        "event_id",
        "prediction",
        "probability",
        "severity_score",
        "risk_weight",
        "cvss_score",
        "matched_ioc",
        "known_attack",
        "mitre_tactic",
        "mitre_technique_id",
        "timestamp",
    ]

    OPTIONAL_FIELDS = [
        "severity",
        "metadata",
    ]

    # ------------------------------------------------------

    @classmethod
    def validate(cls, event: Dict[str, Any]) -> ValidatedRiskEvent:

        cls._validate_required_fields(event)

        return ValidatedRiskEvent(

            event_id=str(event["event_id"]),

            prediction=str(event["prediction"]),

            probability=cls._validate_probability(
                event["probability"]
            ),

            severity=str(
                event.get(
                    "severity",
                    constants.DEFAULT_SEVERITY
                )
            ),

            severity_score=cls._validate_score(
                event["severity_score"],
                "severity_score"
            ),

            risk_weight=cls._validate_score(
                event["risk_weight"],
                "risk_weight"
            ),

            cvss_score=cls._validate_cvss(
                event["cvss_score"]
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

            timestamp=str(
                event["timestamp"]
            ),

            metadata=dict(
                event.get("metadata", {})
            ),
        )

    # ------------------------------------------------------

    @classmethod
    def _validate_required_fields(
        cls,
        event: Dict[str, Any]
    ):

        missing = []

        for field in cls.REQUIRED_FIELDS:

            if field not in event:

                missing.append(field)

        if missing:

            raise ValueError(
                f"Missing required fields: {', '.join(missing)}"
            )

    # ------------------------------------------------------

    @staticmethod
    def _validate_probability(value: Any) -> float:

        try:

            probability = float(value)

        except Exception:

            raise ValueError(
                "Probability must be numeric."
            )

        if probability < 0 or probability > 1:

            raise ValueError(
                "Probability must be between 0 and 1."
            )

        return probability

    # ------------------------------------------------------

    @staticmethod
    def _validate_score(
        value: Any,
        field: str
    ) -> float:

        try:

            score = float(value)

        except Exception:

            raise ValueError(
                f"{field} must be numeric."
            )

        if score < 0:

            score = 0

        if score > 100:

            score = 100

        return score

    # ------------------------------------------------------

    @staticmethod
    def _validate_cvss(value: Any) -> float:

        try:

            score = float(value)

        except Exception:

            return constants.DEFAULT_CVSS_SCORE

        if score < 0:

            score = 0

        if score > 10:

            score = 10

        return score


# ==========================================================
# Public Helper
# ==========================================================

def validate_event(
    event: Dict[str, Any]
) -> ValidatedRiskEvent:
    """
    Validate and normalize an incoming event.
    """

    return RiskEventValidator.validate(event)