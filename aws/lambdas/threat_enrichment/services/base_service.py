"""
Base Service

Provides common functionality shared by all enrichment services.

Author: AI-Assisted Threat Detection Dashboard
Python 3.11+
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from ..logger import get_logger


class BaseService(ABC):
    """
    Base class for every enrichment service.
    """

    service_name = "BaseService"

    def __init__(self) -> None:

        self.logger = get_logger(self.service_name)

        self.initialized_at = datetime.now(UTC)

    # ============================================================
    # Lifecycle
    # ============================================================

    def initialize(self) -> None:

        self.logger.info(
            "%s initialized",
            self.service_name,
        )

    def shutdown(self) -> None:

        self.logger.info(
            "%s shutdown",
            self.service_name,
        )

    # ============================================================
    # Health
    # ============================================================

    def health(self) -> dict[str, Any]:

        return {

            "service": self.service_name,

            "status": "healthy",

            "initialized_at":
                self.initialized_at.isoformat(),
        }

    # ============================================================
    # Statistics
    # ============================================================

    def stats(self) -> dict[str, Any]:

        return {}

    # ============================================================
    # Abstract
    # ============================================================

    @abstractmethod
    def process(self, *args, **kwargs):

        """
        Execute service logic.
        """