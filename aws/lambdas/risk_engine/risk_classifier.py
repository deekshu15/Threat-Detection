"""
Risk Engine Classifier

Converts a numerical risk score into a
human-readable risk level.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .config import CONFIG
from .constants import (
    RISK_LEVEL_LOW,
    RISK_LEVEL_MEDIUM,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_CRITICAL,
)
from .score_calculator import RiskScoreResult


# ==========================================================
# Classification Result
# ==========================================================

@dataclass
class RiskClassification:

    risk_level: str

    risk_score: float

    threshold_used: float

    is_critical: bool

    is_high: bool

    is_medium: bool

    is_low: bool


# ==========================================================
# Risk Classifier
# ==========================================================

class RiskClassifier:

    @staticmethod
    def classify(
        score: RiskScoreResult
    ) -> RiskClassification:

        risk_score = score.total_score

        # ------------------------------
        # Critical
        # ------------------------------

        if risk_score >= CONFIG.critical_threshold:

            return RiskClassification(
                risk_level=RISK_LEVEL_CRITICAL,
                risk_score=risk_score,
                threshold_used=CONFIG.critical_threshold,
                is_critical=True,
                is_high=False,
                is_medium=False,
                is_low=False,
            )

        # ------------------------------
        # High
        # ------------------------------

        if risk_score >= CONFIG.high_threshold:

            return RiskClassification(
                risk_level=RISK_LEVEL_HIGH,
                risk_score=risk_score,
                threshold_used=CONFIG.high_threshold,
                is_critical=False,
                is_high=True,
                is_medium=False,
                is_low=False,
            )

        # ------------------------------
        # Medium
        # ------------------------------

        if risk_score >= CONFIG.medium_threshold:

            return RiskClassification(
                risk_level=RISK_LEVEL_MEDIUM,
                risk_score=risk_score,
                threshold_used=CONFIG.medium_threshold,
                is_critical=False,
                is_high=False,
                is_medium=True,
                is_low=False,
            )

        # ------------------------------
        # Low
        # ------------------------------

        return RiskClassification(
            risk_level=RISK_LEVEL_LOW,
            risk_score=risk_score,
            threshold_used=CONFIG.low_threshold,
            is_critical=False,
            is_high=False,
            is_medium=False,
            is_low=True,
        )


# ==========================================================
# Utility Functions
# ==========================================================

def classify_risk(
    score: RiskScoreResult
) -> RiskClassification:
    """
    Convenience wrapper.
    """
    return RiskClassifier.classify(score)