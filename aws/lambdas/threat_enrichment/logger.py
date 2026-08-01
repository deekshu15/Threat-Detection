"""
Enterprise Logging Configuration

Centralized logging for the Threat Enrichment pipeline.

Features:
- Console logging
- Rotating file logging
- Thread-safe
- Configurable log level
- Structured formatting
- Singleton logger creation
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict

from .config import LOG_DIR, LOG_FILE, LOG_LEVEL



# =============================================================================
# Create Log Directory
# =============================================================================

LOG_DIR.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Log Format
# =============================================================================

LOG_FORMAT = (
    "%(asctime)s | "
    "%(levelname)-8s | "
    "%(name)s | "
    "%(filename)s:%(lineno)d | "
    "%(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# =============================================================================
# Logger Cache
# =============================================================================

_LOGGER_CACHE: Dict[str, logging.Logger] = {}


# =============================================================================
# Logger Factory
# =============================================================================

def get_logger(name: str) -> logging.Logger:
    """
    Returns a configured logger instance.

    The logger is created only once and reused
    throughout the application.
    """

    if name in _LOGGER_CACHE:
        return _LOGGER_CACHE[name]

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(LOG_LEVEL)

    formatter = logging.Formatter(
        LOG_FORMAT,
        datefmt=DATE_FORMAT,
    )

    # -------------------------------------------------------------------------
    # Console Handler
    # -------------------------------------------------------------------------

    console_handler = logging.StreamHandler()

    console_handler.setLevel(LOG_LEVEL)

    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)

    # -------------------------------------------------------------------------
    # Rotating File Handler
    # -------------------------------------------------------------------------

    file_handler = RotatingFileHandler(
        filename=LOG_FILE,
        maxBytes=10 * 1024 * 1024,     # 10 MB
        backupCount=10,
        encoding="utf-8",
    )

    file_handler.setLevel(LOG_LEVEL)

    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    logger.propagate = False

    _LOGGER_CACHE[name] = logger

    return logger


# =============================================================================
# Module Loggers
# =============================================================================

pipeline_logger = get_logger("ThreatPipeline")

validator_logger = get_logger("Validator")

ioc_logger = get_logger("IOCMatcher")

cve_logger = get_logger("CVELookup")

mitre_logger = get_logger("MITREMapper")

asset_logger = get_logger("AssetContext")

severity_logger = get_logger("SeverityEngine")

behavior_logger = get_logger("BehaviorAnalyzer")

threat_score_logger = get_logger("ThreatScore")

risk_logger = get_logger("RiskEngine")

lambda_logger = get_logger("Lambda")


# =============================================================================
# Startup Log
# =============================================================================

pipeline_logger.info(
    "Threat Enrichment logging initialized successfully."
)