"""
Risk Engine Confidence Calculator

Calculates the confidence (0.0 - 1.0) of the
generated risk assessment.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import CONFIG
from .constants import (
    MAX_CONFIDENCE,
    MIN_CONFIDENCE,
)
from .score_calculator import RiskScoreResult
from .validator import ValidatedRiskEvent


# ==========================================================
# Confidence Result
# ==========================================================

@dataclass
class ConfidenceResult:
    """
    Confidence calculation result.
    """

    confidence: float

    probability_component: float

    enrichment_component: float

    data_quality_component: float


# ==========================================================
# Confidence Calculator
# ==========================================================

class ConfidenceCalculator:

    @staticmethod
    def calculate(
        event: ValidatedRiskEvent,
        score: RiskScoreResult
    ) -> ConfidenceResult:

        probability_component = event.probability

        enrichment_component = (
            ConfidenceCalculator._calculate_enrichment(event)
        )

        data_quality_component = (
            ConfidenceCalculator._calculate_data_quality(event)
        )

        confidence = (
            probability_component * 0.50
            + enrichment_component * 0.30
            + data_quality_component * 0.20
        )

        confidence = ConfidenceCalculator._normalize(confidence)

        return ConfidenceResult(
            confidence=round(confidence, 4),
            probability_component=round(probability_component, 4),
            enrichment_component=round(enrichment_component, 4),
            data_quality_component=round(data_quality_component, 4),
        )

    # ------------------------------------------------------

    @staticmethod
    def _calculate_enrichment(
        event: ValidatedRiskEvent
    ) -> float:

        score = 0.0

        if event.cvss_score > 0:
            score += 0.25

        if event.matched_ioc:
            score += 0.25

        if event.known_attack:
            score += 0.20

        if event.mitre_technique_id:
            score += 0.15

        if event.mitre_tactic:
            score += 0.15

        return min(score, 1.0)

    # ------------------------------------------------------

    @staticmethod
    def _calculate_data_quality(
        event: ValidatedRiskEvent
    ) -> float:

        total_fields = 11

        available = 0

        if event.event_id:
            available += 1

        if event.prediction:
            available += 1

        if event.probability is not None:
            available += 1

        if event.severity:
            available += 1

        if event.cvss_score is not None:
            available += 1

        if event.mitre_tactic:
            available += 1

        if event.mitre_technique_id:
            available += 1

        if event.timestamp:
            available += 1

        if event.severity_score >= 0:
            available += 1

        if event.risk_weight >= 0:
            available += 1

        if event.metadata is not None:
            available += 1

        return available / total_fields

    # ------------------------------------------------------

    @staticmethod
    def _normalize(value: float) -> float:

        if value < MIN_CONFIDENCE:
            return MIN_CONFIDENCE

        if value > MAX_CONFIDENCE:
            return MAX_CONFIDENCE

        return value