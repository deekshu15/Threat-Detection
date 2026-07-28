"""
severity.py

Severity scoring module for the Threat Enrichment Lambda.

Responsibilities:
- Convert severity labels to numerical scores.
- Calculate default risk weights.
- Validate severity values.
"""

from typing import Dict

from aws.lambdas.threat_enrichment_old.config import (
    SEVERITY_SCORES,
    RISK_WEIGHTS,
    DEFAULT_RISK_WEIGHT,
)

from aws.lambdas.threat_enrichment_old.constants import (
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
)

class SeverityCalculator:
    """
    Utility class for severity-related calculations.
    """

    VALID_SEVERITIES = {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL,
    }

    @classmethod
    def is_valid(cls, severity: str) -> bool:
        """
        Check whether the provided severity level is valid.

        Args:
            severity: Severity label

        Returns:
            bool
        """
        if severity is None:
            return False

        return severity in cls.VALID_SEVERITIES

    @classmethod
    def get_score(cls, severity: str) -> int:
        """
        Convert severity label into numerical score.

        Low       -> 25
        Medium    -> 50
        High      -> 75
        Critical  -> 100

        Args:
            severity: Severity label

        Returns:
            Integer severity score
        """
        if not cls.is_valid(severity):
            return SEVERITY_SCORES.get(MEDIUM)

        return SEVERITY_SCORES[severity]

    @classmethod
    def get_risk_weight(cls, severity: str) -> int:
        """
        Return risk weight associated with severity.

        Args:
            severity: Severity label

        Returns:
            Integer risk weight
        """
        if not cls.is_valid(severity):
            return DEFAULT_RISK_WEIGHT

        return RISK_WEIGHTS[severity]

    @classmethod
    def enrich(cls, severity: str) -> Dict:
        """
        Generate severity intelligence.

        Args:
            severity: Severity label

        Returns:
            Dictionary containing severity intelligence.
        """
        return {
            "severity": severity,
            "severity_score": cls.get_score(severity),
            "risk_weight": cls.get_risk_weight(severity),
        }

    @classmethod
    def normalize(cls, severity: str) -> str:
        """
        Normalize invalid or missing severity values.

        Args:
            severity: Input severity

        Returns:
            Valid severity string
        """
        if not cls.is_valid(severity):
            return MEDIUM

        return severity


def calculate_severity(event: Dict) -> Dict:
    """
    Convenience function used by enrichment.py.

    Args:
        event: Normalized security event

    Returns:
        Severity enrichment dictionary.
    """
    severity = event.get("severity", MEDIUM)

    severity = SeverityCalculator.normalize(severity)

    return SeverityCalculator.enrich(severity)