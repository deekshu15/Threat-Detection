"""
Risk Score Calculator

Calculates the overall risk score (0-100)
using ML prediction and enrichment information.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import CONFIG
from .constants import (
    IOC_MATCH_SCORE,
    IOC_NOT_FOUND_SCORE,
    KNOWN_ATTACK_SCORE,
    UNKNOWN_ATTACK_SCORE,
    MITRE_TACTIC_SCORES,
    DEFAULT_MITRE_SCORE,
    MAX_RISK_SCORE,
    MIN_RISK_SCORE,
)
from .validator import ValidatedRiskEvent


# ==========================================================
# Risk Score Result
# ==========================================================

@dataclass
class RiskScoreResult:
    """
    Result returned by the score calculator.
    """

    ml_score: float

    cvss_score: float

    severity_score: float

    ioc_score: float

    mitre_score: float

    total_score: float


# ==========================================================
# Risk Score Calculator
# ==========================================================

class RiskScoreCalculator:

    @staticmethod
    def calculate(
        event: ValidatedRiskEvent
    ) -> RiskScoreResult:
        """
        Calculate overall risk score.
        """

        # ----------------------------
        # ML Prediction
        # ----------------------------

        ml_score = event.probability * 100

        # ----------------------------
        # CVSS
        # ----------------------------

        cvss_score = (event.cvss_score / 10.0) * 100

        # ----------------------------
        # Severity
        # ----------------------------

        severity_score = event.severity_score

        # ----------------------------
        # IOC
        # ----------------------------

        ioc_score = (
            IOC_MATCH_SCORE
            if event.matched_ioc
            else IOC_NOT_FOUND_SCORE
        )

        # ----------------------------
        # Known Attack Bonus
        # ----------------------------

        if event.known_attack:
            ioc_score = min(
                100,
                ioc_score + 20
            )

        # ----------------------------
        # MITRE
        # ----------------------------

        mitre_score = MITRE_TACTIC_SCORES.get(
            event.mitre_tactic,
            DEFAULT_MITRE_SCORE
        )

        # ----------------------------
        # Weighted Score
        # ----------------------------

        total = (

            ml_score
            * CONFIG.ml_probability_weight

            +

            cvss_score
            * CONFIG.cvss_weight

            +

            severity_score
            * CONFIG.severity_weight

            +

            ioc_score
            * CONFIG.ioc_weight

            +

            mitre_score
            * CONFIG.mitre_weight

        )

        total = RiskScoreCalculator._normalize(total)

        return RiskScoreResult(

            ml_score=round(ml_score, 2),

            cvss_score=round(cvss_score, 2),

            severity_score=round(severity_score, 2),

            ioc_score=round(ioc_score, 2),

            mitre_score=round(mitre_score, 2),

            total_score=round(total, 2),
        )

    # -----------------------------------------------------

    @staticmethod
    def _normalize(score: float) -> float:
        """
        Clamp score between 0 and 100.
        """

        if score < MIN_RISK_SCORE:
            return MIN_RISK_SCORE

        if score > MAX_RISK_SCORE:
            return MAX_RISK_SCORE

        return score