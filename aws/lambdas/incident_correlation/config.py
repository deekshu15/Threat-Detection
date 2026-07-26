"""
Incident Correlation Configuration

Loads runtime configuration for the Incident
Correlation Engine.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import constants


# ==========================================================
# Configuration Model
# ==========================================================

@dataclass(frozen=True)
class IncidentCorrelationConfig:
    """
    Runtime configuration.
    """

    # ------------------------------------------------------
    # Correlation Window
    # ------------------------------------------------------

    correlation_window_minutes: int

    # ------------------------------------------------------
    # Correlation Thresholds
    # ------------------------------------------------------

    low_threshold: float

    medium_threshold: float

    high_threshold: float

    # ------------------------------------------------------
    # Matching Weights
    # ------------------------------------------------------

    source_ip_weight: float

    destination_ip_weight: float

    host_weight: float

    user_weight: float

    mitre_weight: float

    time_weight: float

    risk_level_weight: float

    event_category_weight: float

    # ------------------------------------------------------
    # Graph Limits
    # ------------------------------------------------------

    max_graph_nodes: int

    max_graph_edges: int

    # ------------------------------------------------------
    # Attack Chain
    # ------------------------------------------------------

    max_attack_chain_length: int

    # ------------------------------------------------------
    # Feature Flags
    # ------------------------------------------------------

    enable_graph: bool

    enable_attack_chain: bool

    enable_incident_merging: bool

    # ------------------------------------------------------
    # Logging
    # ------------------------------------------------------

    enable_logging: bool

    log_level: str


# ==========================================================
# Helpers
# ==========================================================

def _get_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).lower() in (
        "true",
        "1",
        "yes",
        "on",
    )


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


# ==========================================================
# Load Configuration
# ==========================================================

def load_config() -> IncidentCorrelationConfig:

    config = IncidentCorrelationConfig(

        correlation_window_minutes=_get_int(
            "CORRELATION_WINDOW_MINUTES",
            constants.DEFAULT_CORRELATION_WINDOW_MINUTES,
        ),

        low_threshold=constants.LOW_CORRELATION_THRESHOLD,

        medium_threshold=constants.MEDIUM_CORRELATION_THRESHOLD,

        high_threshold=constants.HIGH_CORRELATION_THRESHOLD,

        source_ip_weight=_get_float(
            "SOURCE_IP_WEIGHT",
            constants.SOURCE_IP_WEIGHT,
        ),

        destination_ip_weight=_get_float(
            "DESTINATION_IP_WEIGHT",
            constants.DESTINATION_IP_WEIGHT,
        ),

        host_weight=_get_float(
            "HOST_WEIGHT",
            constants.HOST_WEIGHT,
        ),

        user_weight=_get_float(
            "USER_WEIGHT",
            constants.USER_WEIGHT,
        ),

        mitre_weight=_get_float(
            "MITRE_WEIGHT",
            constants.MITRE_WEIGHT,
        ),

        time_weight=_get_float(
            "TIME_WEIGHT",
            constants.TIME_WEIGHT,
        ),

        risk_level_weight=_get_float(
            "RISK_LEVEL_WEIGHT",
            constants.RISK_LEVEL_WEIGHT,
        ),

        event_category_weight=_get_float(
            "EVENT_CATEGORY_WEIGHT",
            constants.EVENT_CATEGORY_WEIGHT,
        ),

        max_graph_nodes=_get_int(
            "MAX_GRAPH_NODES",
            constants.MAX_GRAPH_NODES,
        ),

        max_graph_edges=_get_int(
            "MAX_GRAPH_EDGES",
            constants.MAX_GRAPH_EDGES,
        ),

        max_attack_chain_length=_get_int(
            "MAX_ATTACK_CHAIN_LENGTH",
            constants.MAX_ATTACK_CHAIN_LENGTH,
        ),

        enable_graph=_get_bool(
            "ENABLE_GRAPH",
            True,
        ),

        enable_attack_chain=_get_bool(
            "ENABLE_ATTACK_CHAIN",
            True,
        ),

        enable_incident_merging=_get_bool(
            "ENABLE_INCIDENT_MERGING",
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
    config: IncidentCorrelationConfig,
) -> None:
    """
    Validate configuration.
    """

    if not (
        constants.MIN_CORRELATION_WINDOW_MINUTES
        <= config.correlation_window_minutes
        <= constants.MAX_CORRELATION_WINDOW_MINUTES
    ):
        raise ValueError(
            "Invalid correlation window."
        )

    total = (
        config.source_ip_weight
        + config.destination_ip_weight
        + config.host_weight
        + config.user_weight
        + config.mitre_weight
        + config.time_weight
        + config.risk_level_weight
        + config.event_category_weight
    )

    if abs(total - 1.0) > 1e-6:
        raise ValueError(
            f"Correlation weights must total 1.0. Current total={total}"
        )

    if not (
        config.low_threshold
        < config.medium_threshold
        < config.high_threshold
    ):
        raise ValueError(
            "Correlation thresholds are invalid."
        )

    if config.max_graph_nodes <= 0:
        raise ValueError(
            "max_graph_nodes must be positive."
        )

    if config.max_graph_edges <= 0:
        raise ValueError(
            "max_graph_edges must be positive."
        )

    if config.max_attack_chain_length <= 0:
        raise ValueError(
            "max_attack_chain_length must be positive."
        )


# ==========================================================
# Singleton
# ==========================================================

CONFIG = load_config()