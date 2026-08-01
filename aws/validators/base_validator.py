"""
Base Validator

Abstract base class for all validators in the Threat Enrichment
pipeline.

Every validator should inherit from BaseValidator.

Responsibilities
----------------
• Validate input payloads
• Normalize raw events
• Convert to ThreatEvent
• Standardize logging
• Standardize exception handling

Author: AI-Assisted Threat Detection Dashboard
Python: 3.11+
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from ..lambdas.threat_enrichment.exceptions import (
    InvalidFieldError,
    MissingFieldError,
    ValidationError as ThreatValidationError,
)
from ..lambdas.threat_enrichment.logger import validator_logger
from ..models.asset import AssetModel
from ..models.event import (
    EventCategory,
    EventSource,
    EventStatus,
    ThreatEvent,
)
from ..models.network import NetworkModel
from ..models.user import UserModel


class BaseValidator(ABC):
    """
    Base class for all event validators.
    """

    validator_name: str = "BaseValidator"

    def __init__(self) -> None:
        self.logger = validator_logger

    # ======================================================================
    # Abstract Interface
    # ======================================================================

    @abstractmethod
    def validate(self, raw_event: dict[str, Any]) -> ThreatEvent:
        """
        Validate and convert a raw event into ThreatEvent.
        """
        raise NotImplementedError

    # ======================================================================
    # Common Helpers
    # ======================================================================

    def require_field(
        self,
        data: dict[str, Any],
        field: str,
    ) -> Any:
        """
        Ensure a required field exists.
        """

        if field not in data:
            raise MissingFieldError(field)

        value = data[field]

        if value is None:
            raise MissingFieldError(field)

        return value

    def optional_field(
        self,
        data: dict[str, Any],
        field: str,
        default: Any = None,
    ) -> Any:
        """
        Return optional field.
        """

        return data.get(field, default)

    def require_string(
        self,
        data: dict[str, Any],
        field: str,
    ) -> str:
        """
        Ensure a string exists.
        """

        value = self.require_field(data, field)

        if not isinstance(value, str):
            raise InvalidFieldError(field)

        return value.strip()

    def require_int(
        self,
        data: dict[str, Any],
        field: str,
    ) -> int:
        value = self.require_field(data, field)

        try:
            return int(value)
        except Exception as exc:
            raise InvalidFieldError(field) from exc

    def require_float(
        self,
        data: dict[str, Any],
        field: str,
    ) -> float:
        value = self.require_field(data, field)

        try:
            return float(value)
        except Exception as exc:
            raise InvalidFieldError(field) from exc

    def require_bool(
        self,
        data: dict[str, Any],
        field: str,
    ) -> bool:
        value = self.require_field(data, field)

        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            return value.lower() in (
                "true",
                "1",
                "yes",
                "y",
            )

        return bool(value)

    # ======================================================================
    # Timestamp
    # ======================================================================

    def parse_timestamp(
        self,
        value: Any,
    ) -> datetime:
        """
        Parse supported timestamp formats.
        """

        if isinstance(value, datetime):
            return value

        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value)

        if isinstance(value, str):
            try:
                return datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
            except Exception:
                pass

        raise ThreatValidationError(
            "Invalid timestamp."
        )

    # ======================================================================
    # Threat Event Builder
    # ======================================================================

    def build_event(
        self,
        *,
        event_name: str,
        event_type: str,
        event_source: EventSource,
        category: EventCategory,
        network: NetworkModel,
        asset: AssetModel | None = None,
        user: UserModel | None = None,
        timestamp: datetime,
        raw_event: dict[str, Any],
    ) -> ThreatEvent:
        """
        Construct the canonical ThreatEvent.
        """

        return ThreatEvent(
            event_id=uuid4(),
            event_name=event_name,
            event_type=event_type,
            event_source=event_source,
            category=category,
            status=EventStatus.NEW,
            timestamp=timestamp,
            network=network,
            asset=asset or AssetModel(),
            user=user or UserModel(),
            raw_event=raw_event,
        )

    # ======================================================================
    # Logging
    # ======================================================================

    def log_validation_start(
        self,
        event_name: str,
    ) -> None:

        self.logger.info(
            "[%s] Validation started: %s",
            self.validator_name,
            event_name,
        )

    def log_validation_success(
        self,
        event: ThreatEvent,
    ) -> None:

        self.logger.info(
            "[%s] Validation successful: %s",
            self.validator_name,
            event.event_id,
        )

    def log_validation_error(
        self,
        exc: Exception,
    ) -> None:

        self.logger.exception(
            "[%s] Validation failed: %s",
            self.validator_name,
            exc,
        )

    # ======================================================================
    # Wrapper
    # ======================================================================

    def run(
        self,
        raw_event: dict[str, Any],
    ) -> ThreatEvent:
        """
        Execute validation with standardized logging and
        exception handling.
        """

        try:
            event = self.validate(raw_event)

            self.log_validation_success(event)

            return event

        except (
            ThreatValidationError,
            MissingFieldError,
            InvalidFieldError,
            ValidationError,
        ):
            raise

        except Exception as exc:
            self.log_validation_error(exc)
            raise