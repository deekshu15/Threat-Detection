"""
Recommendation Engine Validator

Validates and normalizes SecurityIncident
objects received from the Incident
Correlation Engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


# ==========================================================
# Validated Incident
# ==========================================================

@dataclass
class ValidatedIncident:

    incident_id: str

    title: str

    description: str

    severity: str

    priority: str

    status: str

    owner: str

    confidence: float

    average_risk_score: float

    maximum_risk_score: float

    total_events: int

    affected_hosts: List[str]

    affected_users: List[str]

    mitre_tactics: List[str]

    mitre_techniques: List[str]

    event_ids: List[str]

    attack_chains: List[Dict]

    graph: Dict

    correlations: List[Dict]

    metadata: Dict[str, Any]


# ==========================================================
# Validator
# ==========================================================

class RecommendationValidator:

    REQUIRED_FIELDS = [

        "incident_id",

        "title",

        "description",

        "severity",

        "priority",

        "status",

        "confidence",

        "average_risk_score",

        "maximum_risk_score",

        "total_events",

        "affected_hosts",

        "affected_users",

        "mitre_tactics",

        "mitre_techniques",

        "event_ids",

        "attack_chains",

        "graph",

        "correlations",

    ]

    VALID_SEVERITIES = {

        "Low",

        "Medium",

        "High",

        "Critical",

    }

    VALID_PRIORITIES = {

        "P1",

        "P2",

        "P3",

        "P4",

    }

    # ------------------------------------------------------

    @classmethod
    def validate(

        cls,

        incident: Dict[str, Any],

    ) -> ValidatedIncident:

        cls._validate_required_fields(
            incident
        )

        return ValidatedIncident(

            incident_id=str(
                incident["incident_id"]
            ),

            title=str(
                incident["title"]
            ),

            description=str(
                incident["description"]
            ),

            severity=cls._validate_severity(
                incident["severity"]
            ),

            priority=cls._validate_priority(
                incident["priority"]
            ),

            status=str(
                incident["status"]
            ),

            owner=str(
                incident.get(
                    "owner",
                    "Unassigned",
                )
            ),

            confidence=cls._validate_confidence(
                incident["confidence"]
            ),

            average_risk_score=cls._validate_score(
                incident[
                    "average_risk_score"
                ]
            ),

            maximum_risk_score=cls._validate_score(
                incident[
                    "maximum_risk_score"
                ]
            ),

            total_events=cls._validate_event_count(
                incident["total_events"]
            ),

            affected_hosts=list(
                incident.get(
                    "affected_hosts",
                    [],
                )
            ),

            affected_users=list(
                incident.get(
                    "affected_users",
                    [],
                )
            ),

            mitre_tactics=list(
                incident.get(
                    "mitre_tactics",
                    [],
                )
            ),

            mitre_techniques=list(
                incident.get(
                    "mitre_techniques",
                    [],
                )
            ),

            event_ids=list(
                incident.get(
                    "event_ids",
                    [],
                )
            ),

            attack_chains=list(
                incident.get(
                    "attack_chains",
                    [],
                )
            ),

            graph=dict(
                incident.get(
                    "graph",
                    {},
                )
            ),

            correlations=list(
                incident.get(
                    "correlations",
                    [],
                )
            ),

            metadata=dict(
                incident.get(
                    "metadata",
                    {},
                )
            ),

        )

    # ------------------------------------------------------

    @classmethod
    def _validate_required_fields(

        cls,

        incident: Dict[str, Any],

    ) -> None:

        missing = [

            field

            for field in cls.REQUIRED_FIELDS

            if field not in incident

        ]

        if missing:

            raise ValueError(

                "Missing required fields: "

                + ", ".join(missing)

            )

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
            score = 0.0

        if score > 100:
            score = 100.0

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
    def _validate_event_count(
        value: Any,
    ) -> int:

        try:

            count = int(value)

        except Exception:

            raise ValueError(
                "Invalid event count."
            )

        if count < 0:

            raise ValueError(
                "Event count cannot be negative."
            )

        return count

    # ------------------------------------------------------

    @classmethod
    def _validate_severity(
        cls,
        value: str,
    ) -> str:

        if value not in cls.VALID_SEVERITIES:

            raise ValueError(
                f"Invalid severity: {value}"
            )

        return value

    # ------------------------------------------------------

    @classmethod
    def _validate_priority(
        cls,
        value: str,
    ) -> str:

        if value not in cls.VALID_PRIORITIES:

            raise ValueError(
                f"Invalid priority: {value}"
            )

        return value


# ==========================================================
# Public Helper
# ==========================================================

def validate_incident(
    incident: Dict[str, Any],
) -> ValidatedIncident:
    """
    Validate and normalize a SecurityIncident.
    """

    return RecommendationValidator.validate(
        incident
    )