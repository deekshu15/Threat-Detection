"""
Risk Engine Lambda Entry Point

Pipeline:
Validated Event
        │
        ▼
Score Calculator
        │
        ▼
Confidence Calculator
        │
        ▼
Risk Classifier
        │
        ▼
Reason Generator
        │
        ▼
Return Result
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from .validator import validate_event
from .score_calculator import RiskScoreCalculator
from .confidence import ConfidenceCalculator
from .risk_classifier import RiskClassifier
from .reason_generator import ReasonGenerator


# ==========================================================
# Logger
# ==========================================================

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ==========================================================
# Risk Engine
# ==========================================================

class RiskEngine:

    @staticmethod
    def process(event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the complete Risk Engine pipeline.
        """

        # -----------------------------------------
        # Step 1: Validate Input
        # -----------------------------------------

        validated_event = validate_event(event)

        # -----------------------------------------
        # Step 2: Calculate Risk Score
        # -----------------------------------------

        score_result = RiskScoreCalculator.calculate(
            validated_event
        )

        # -----------------------------------------
        # Step 3: Calculate Confidence
        # -----------------------------------------

        confidence_result = (
            ConfidenceCalculator.calculate(
                validated_event,
                score_result,
            )
        )

        # -----------------------------------------
        # Step 4: Classify Risk
        # -----------------------------------------

        classification = (
            RiskClassifier.classify(
                score_result
            )
        )

        # -----------------------------------------
        # Step 5: Generate Explanation
        # -----------------------------------------

        reason_result = (
            ReasonGenerator.generate(
                validated_event,
                score_result,
                confidence_result,
                classification,
            )
        )

        # -----------------------------------------
        # Build Response
        # -----------------------------------------

        return {

            "event_id": validated_event.event_id,

            "prediction": validated_event.prediction,

            "risk_score": score_result.total_score,

            "risk_level": classification.risk_level,

            "confidence": confidence_result.confidence,

            "summary": reason_result.summary,

            "reasons": reason_result.reasons,

            "recommendations": reason_result.recommendations,

            "details": {

                "ml_score": score_result.ml_score,

                "cvss_score": score_result.cvss_score,

                "severity_score": score_result.severity_score,

                "ioc_score": score_result.ioc_score,

                "mitre_score": score_result.mitre_score,

                "probability": validated_event.probability,

                "threshold": classification.threshold_used,

                "confidence_breakdown": {

                    "probability_component":
                        confidence_result.probability_component,

                    "enrichment_component":
                        confidence_result.enrichment_component,

                    "data_quality_component":
                        confidence_result.data_quality_component,
                },
            },
        }


# ==========================================================
# AWS Lambda Handler
# ==========================================================

def lambda_handler(event, context):
    """
    AWS Lambda entry point.
    """

    logger.info("Risk Engine started.")

    try:

        result = RiskEngine.process(event)

        logger.info(
            "Risk Engine completed successfully."
        )

        return {

            "statusCode": 200,

            "body": json.dumps(result),
        }

    except Exception as exc:

        logger.exception("Risk Engine failed.")

        return {

            "statusCode": 500,

            "body": json.dumps({

                "error": str(exc),

                "status": "failed"

            }),
        }