"""
Centralized logging configuration.

This module provides a reusable logger for all Lambda functions.
"""

import logging
from config import Config


def get_logger(name: str) -> logging.Logger:
    """
    Create and return a configured logger.

    Args:
        name (str): Name of the logger (usually __name__).

    Returns:
        logging.Logger: Configured logger instance.
    """

    logger = logging.getLogger(name)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO))

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.propagate = False

    return logger