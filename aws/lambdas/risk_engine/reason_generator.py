"""
Risk Engine Reason Generator

Generates human-readable explanations for the
calculated risk assessment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .score_calculator import RiskScoreResult
from .confidence import ConfidenceResult
from .risk_classifier import RiskClassification
from .validator import ValidatedRiskEvent


# ==========================================================
# Result Model
# ==========================================================

@dataclass
class ReasonResult:
    """
    Human readable explanation returned by
    the Risk Engine.
    """

    summary: str

    reasons: List[str] = field(default_factory=list)

    recommendations: List[str] = field(default_factory=list)


# ==========================================================
# Generator
# ==========================================================

class ReasonGenerator:

    @staticmethod
    def generate(
        event: ValidatedRiskEvent,
        score: RiskScoreResult,
        confidence: ConfidenceResult,
        classification: RiskClassification
    ) -> ReasonResult:

        reasons = []

        recommendations = []

        # --------------------------------------------------
        # ML
        # --------------------------------------------------

        reasons.append(
            f"ML model predicted '{event.prediction}' "
            f"with {event.probability:.1%} confidence."
        )

        # --------------------------------------------------
        # CVSS
        # --------------------------------------------------

        if event.cvss_score >= 9:

            reasons.append(
                f"Critical CVSS score detected ({event.cvss_score})."
            )

        elif event.cvss_score >= 7:

            reasons.append(
                f"High CVSS score detected ({event.cvss_score})."
            )

        # --------------------------------------------------
        # Severity
        # --------------------------------------------------

        if event.severity:

            reasons.append(
                f"Event severity is '{event.severity}'."
            )

        # --------------------------------------------------
        # IOC
        # --------------------------------------------------

        if event.matched_ioc:

            reasons.append(
                "Known Indicator of Compromise (IOC) matched."
            )

            recommendations.append(
                "Block the matched IOC immediately."
            )

        # --------------------------------------------------
        # Known Attack
        # --------------------------------------------------

        if event.known_attack:

            reasons.append(
                "Event matches a known attack pattern."
            )

        # --------------------------------------------------
        # MITRE
        # --------------------------------------------------

        if event.mitre_tactic:

            reasons.append(
                f"MITRE tactic detected: {event.mitre_tactic}."
            )

        if event.mitre_technique_id:

            reasons.append(
                f"MITRE technique: {event.mitre_technique_id}."
            )

        # --------------------------------------------------
        # Risk Level
        # --------------------------------------------------

        reasons.append(
            f"Final calculated risk score: {score.total_score:.2f}/100."
        )

        reasons.append(
            f"Final risk level: {classification.risk_level}."
        )

        reasons.append(
            f"Overall confidence: {confidence.confidence:.1%}."
        )

        # --------------------------------------------------
        # Recommendations
        # --------------------------------------------------

        if classification.is_critical:

            recommendations.extend([
                "Immediately isolate the affected endpoint.",
                "Notify the SOC team.",
                "Start forensic evidence collection.",
                "Block malicious IP addresses.",
                "Create a high-priority incident ticket."
            ])

        elif classification.is_high:

            recommendations.extend([
                "Investigate affected host.",
                "Review related authentication logs.",
                "Check lateral movement.",
                "Notify security analyst."
            ])

        elif classification.is_medium:

            recommendations.extend([
                "Review event history.",
                "Increase monitoring.",
                "Verify user activity."
            ])

        else:

            recommendations.extend([
                "Continue monitoring.",
                "No immediate response required."
            ])

        summary = (
            f"{classification.risk_level} Risk "
            f"({score.total_score:.2f}/100)"
        )

        return ReasonResult(
            summary=summary,
            reasons=reasons,
            recommendations=recommendations
        )


# ==========================================================
# Helper
# ==========================================================

def generate_reasons(
    event: ValidatedRiskEvent,
    score: RiskScoreResult,
    confidence: ConfidenceResult,
    classification: RiskClassification
) -> ReasonResult:

    return ReasonGenerator.generate(
        event,
        score,
        confidence,
        classification
    )