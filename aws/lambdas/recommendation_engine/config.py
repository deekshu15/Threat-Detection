"""
Recommendation Engine Configuration

Loads runtime configuration for the
Recommendation Engine.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import constants


# ==========================================================
# Configuration Model
# ==========================================================

@dataclass(frozen=True)
class RecommendationConfig:
    """
    Runtime configuration.
    """

    # ------------------------------------------------------
    # Recommendation Limits
    # ------------------------------------------------------

    max_recommendations: int

    max_containment_actions: int

    max_recovery_actions: int

    max_investigation_steps: int

    # ------------------------------------------------------
    # Risk Thresholds
    # ------------------------------------------------------

    critical_score: float

    high_score: float

    medium_score: float

    low_score: float

    # ------------------------------------------------------
    # Confidence Thresholds
    # ------------------------------------------------------

    high_confidence: float

    medium_confidence: float

    low_confidence: float

    # ------------------------------------------------------
    # Feature Flags
    # ------------------------------------------------------

    enable_summary: bool

    enable_root_cause: bool

    enable_recommendations: bool

    enable_executive_summary: bool

    # ------------------------------------------------------
    # Logging
    # ------------------------------------------------------

    enable_logging: bool

    log_level: str


# ==========================================================
# Environment Helpers
# ==========================================================

def _get_bool(name: str, default: bool) -> bool:

    return os.getenv(
        name,
        str(default),
    ).lower() in (

        "true",

        "1",

        "yes",

        "on",

    )


def _get_int(name: str, default: int) -> int:

    try:

        return int(
            os.getenv(name, default)
        )

    except ValueError:

        return default


def _get_float(name: str, default: float) -> float:

    try:

        return float(
            os.getenv(name, default)
        )

    except ValueError:

        return default


# ==========================================================
# Load Configuration
# ==========================================================

def load_config() -> RecommendationConfig:

    config = RecommendationConfig(

        max_recommendations=_get_int(
            "MAX_RECOMMENDATIONS",
            constants.MAX_RECOMMENDATIONS,
        ),

        max_containment_actions=_get_int(
            "MAX_CONTAINMENT_ACTIONS",
            constants.MAX_CONTAINMENT_ACTIONS,
        ),

        max_recovery_actions=_get_int(
            "MAX_RECOVERY_ACTIONS",
            constants.MAX_RECOVERY_ACTIONS,
        ),

        max_investigation_steps=_get_int(
            "MAX_INVESTIGATION_STEPS",
            constants.MAX_INVESTIGATION_STEPS,
        ),

        critical_score=_get_float(
            "CRITICAL_SCORE",
            constants.CRITICAL_SCORE,
        ),

        high_score=_get_float(
            "HIGH_SCORE",
            constants.HIGH_SCORE,
        ),

        medium_score=_get_float(
            "MEDIUM_SCORE",
            constants.MEDIUM_SCORE,
        ),

        low_score=_get_float(
            "LOW_SCORE",
            constants.LOW_SCORE,
        ),

        high_confidence=_get_float(
            "HIGH_CONFIDENCE",
            constants.HIGH_CONFIDENCE,
        ),

        medium_confidence=_get_float(
            "MEDIUM_CONFIDENCE",
            constants.MEDIUM_CONFIDENCE,
        ),

        low_confidence=_get_float(
            "LOW_CONFIDENCE",
            constants.LOW_CONFIDENCE,
        ),

        enable_summary=_get_bool(
            "ENABLE_SUMMARY",
            True,
        ),

        enable_root_cause=_get_bool(
            "ENABLE_ROOT_CAUSE",
            True,
        ),

        enable_recommendations=_get_bool(
            "ENABLE_RECOMMENDATIONS",
            True,
        ),

        enable_executive_summary=_get_bool(
            "ENABLE_EXECUTIVE_SUMMARY",
            True,
        ),

        enable_logging=_get_bool(
            "ENABLE_LOGGING",
            True,
        ),

        log_level=os.getenv(
            "LOG_LEVEL",
            "INFO",
        ),
    )

    validate_config(config)

    return config


# ==========================================================
# Validation
# ==========================================================

def validate_config(
    config: RecommendationConfig,
) -> None:
    """
    Validate configuration values.
    """

    if not (
        config.low_score
        < config.medium_score
        < config.high_score
        < config.critical_score
    ):
        raise ValueError(
            "Risk thresholds are invalid."
        )

    if not (
        0.0
        <= config.low_confidence
        <= config.medium_confidence
        <= config.high_confidence
        <= 1.0
    ):
        raise ValueError(
            "Confidence thresholds are invalid."
        )

    if config.max_recommendations <= 0:
        raise ValueError(
            "max_recommendations must be greater than zero."
        )

    if config.max_containment_actions <= 0:
        raise ValueError(
            "max_containment_actions must be greater than zero."
        )

    if config.max_recovery_actions <= 0:
        raise ValueError(
            "max_recovery_actions must be greater than zero."
        )

    if config.max_investigation_steps <= 0:
        raise ValueError(
            "max_investigation_steps must be greater than zero."
        )


# ==========================================================
# Singleton
# ==========================================================

CONFIG = load_config()