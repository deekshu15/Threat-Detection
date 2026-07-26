"""
Risk Engine Configuration

Loads runtime configuration from environment variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import constants


# ==========================================================
# Configuration Dataclass
# ==========================================================

@dataclass(frozen=True)
class RiskEngineConfig:
    """
    Runtime configuration for the Risk Engine.
    """

    # -------------------------
    # Model
    # -------------------------
    model_name: str
    model_version: str
    model_path: str

    # -------------------------
    # Risk Weights
    # -------------------------
    ml_probability_weight: float
    cvss_weight: float
    severity_weight: float
    ioc_weight: float
    mitre_weight: float

    # -------------------------
    # Thresholds
    # -------------------------
    low_threshold: float
    medium_threshold: float
    high_threshold: float
    critical_threshold: float

    # -------------------------
    # Confidence
    # -------------------------
    missing_field_penalty: float
    missing_ioc_penalty: float
    missing_cve_penalty: float

    # -------------------------
    # Feature Flags
    # -------------------------
    enable_ml: bool
    enable_rule_engine: bool
    enable_reason_generation: bool

    # -------------------------
    # Logging
    # -------------------------
    enable_logging: bool
    log_level: str


# ==========================================================
# Configuration Loader
# ==========================================================

def _get_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _get_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


def load_config() -> RiskEngineConfig:
    """
    Load configuration from environment variables.
    """

    config = RiskEngineConfig(
        model_name=os.getenv(
            "RISK_ENGINE_MODEL_NAME",
            "RandomForestClassifier",
        ),

        model_version=os.getenv(
            "RISK_ENGINE_MODEL_VERSION",
            constants.DEFAULT_MODEL_VERSION,
        ),

        model_path=os.getenv(
            "RISK_ENGINE_MODEL_PATH",
            "models/risk_classifier.pkl",
        ),

        ml_probability_weight=_get_float(
            "ML_WEIGHT",
            constants.ML_PROBABILITY_WEIGHT,
        ),

        cvss_weight=_get_float(
            "CVSS_WEIGHT",
            constants.CVSS_WEIGHT,
        ),

        severity_weight=_get_float(
            "SEVERITY_WEIGHT",
            constants.SEVERITY_WEIGHT,
        ),

        ioc_weight=_get_float(
            "IOC_WEIGHT",
            constants.IOC_WEIGHT,
        ),

        mitre_weight=_get_float(
            "MITRE_WEIGHT",
            constants.MITRE_WEIGHT,
        ),

        low_threshold=constants.LOW_THRESHOLD,

        medium_threshold=constants.MEDIUM_THRESHOLD,

        high_threshold=constants.HIGH_THRESHOLD,

        critical_threshold=constants.CRITICAL_THRESHOLD,

        missing_field_penalty=constants.MISSING_FIELD_PENALTY,

        missing_ioc_penalty=constants.MISSING_IOC_PENALTY,

        missing_cve_penalty=constants.MISSING_CVE_PENALTY,

        enable_ml=_get_bool(
            "ENABLE_ML",
            True,
        ),

        enable_rule_engine=_get_bool(
            "ENABLE_RULE_ENGINE",
            True,
        ),

        enable_reason_generation=_get_bool(
            "ENABLE_REASON_GENERATION",
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

def validate_config(config: RiskEngineConfig) -> None:
    """
    Validate runtime configuration.
    Raises ValueError if invalid.
    """

    total = (
        config.ml_probability_weight
        + config.cvss_weight
        + config.severity_weight
        + config.ioc_weight
        + config.mitre_weight
    )

    if abs(total - 1.0) > 1e-6:
        raise ValueError(
            f"Risk weights must total 1.0. Current total={total}"
        )

    if not (
        config.low_threshold
        < config.medium_threshold
        < config.high_threshold
        < config.critical_threshold
    ):
        raise ValueError(
            "Risk thresholds are invalid."
        )


# ==========================================================
# Singleton Configuration
# ==========================================================

CONFIG = load_config()