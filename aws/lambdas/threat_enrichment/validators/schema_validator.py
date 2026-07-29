"""
Schema Validator

Performs generic schema validation before source-specific
validation occurs.

Responsibilities
----------------
• Ensure payload is a dictionary
• Verify required fields exist
• Validate field types
• Validate timestamp format
• Validate UUIDs
• Detect empty payloads

Author: AI-Assisted Threat Detection Dashboard
Python 3.11+
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from ..exceptions import (
    InvalidFieldError,
    MissingFieldError,
    ValidationError,
)
from .base_validator import BaseValidator


class SchemaValidator(BaseValidator):
    """
    Generic schema validator.
    """

    validator_name = "SchemaValidator"

    # ------------------------------------------------------------------
    # Required fields
    # ------------------------------------------------------------------

    REQUIRED_FIELDS = (
        "event_name",
        "event_type",
        "event_source",
        "timestamp",
    )

    # ------------------------------------------------------------------
    # Validation Entry
    # ------------------------------------------------------------------

    def validate(
        self,
        raw_event: dict[str, Any],
    ):
        """
        Validate the raw event schema.

        This validator only validates the payload structure.
        It does not create a ThreatEvent.
        """

        self.log_validation_start("Schema Validation")

        self.validate_payload(raw_event)

        self.validate_required_fields(raw_event)

        self.validate_timestamp(raw_event)

        self.validate_optional_fields(raw_event)

        return raw_event

    # ------------------------------------------------------------------
    # Payload
    # ------------------------------------------------------------------

    def validate_payload(
        self,
        payload: Any,
    ) -> None:

        if payload is None:
            raise ValidationError("Payload is None.")

        if not isinstance(payload, dict):
            raise ValidationError(
                "Payload must be a dictionary."
            )

        if len(payload) == 0:
            raise ValidationError(
                "Payload is empty."
            )

    # ------------------------------------------------------------------
    # Required Fields
    # ------------------------------------------------------------------

    def validate_required_fields(
        self,
        payload: dict[str, Any],
    ) -> None:

        for field in self.REQUIRED_FIELDS:

            if field not in payload:
                raise MissingFieldError(field)

            if payload[field] is None:
                raise MissingFieldError(field)

            if (
                isinstance(payload[field], str)
                and payload[field].strip() == ""
            ):
                raise MissingFieldError(field)

    # ------------------------------------------------------------------
    # Timestamp
    # ------------------------------------------------------------------

    def validate_timestamp(
        self,
        payload: dict[str, Any],
    ) -> None:

        self.parse_timestamp(
            payload["timestamp"]
        )

    # ------------------------------------------------------------------
    # UUID
    # ------------------------------------------------------------------

    def validate_uuid(
        self,
        value: str,
        field_name: str,
    ) -> None:

        try:
            UUID(str(value))

        except Exception as exc:
            raise InvalidFieldError(
                field_name
            ) from exc

    # ------------------------------------------------------------------
    # Optional Fields
    # ------------------------------------------------------------------

    def validate_optional_fields(
        self,
        payload: dict[str, Any],
    ) -> None:

        if "event_id" in payload:

            self.validate_uuid(
                payload["event_id"],
                "event_id",
            )

        if "correlation_id" in payload:

            self.validate_uuid(
                payload["correlation_id"],
                "correlation_id",
            )

        if "received_timestamp" in payload:

            self.parse_timestamp(
                payload["received_timestamp"]
            )

        if "ingestion_timestamp" in payload:

            self.parse_timestamp(
                payload["ingestion_timestamp"]
            )

    # ------------------------------------------------------------------
    # Generic Type Validators
    # ------------------------------------------------------------------

    @staticmethod
    def ensure_string(
        value: Any,
        field: str,
    ) -> None:

        if not isinstance(value, str):
            raise InvalidFieldError(field)

    @staticmethod
    def ensure_integer(
        value: Any,
        field: str,
    ) -> None:

        if not isinstance(value, int):
            raise InvalidFieldError(field)

    @staticmethod
    def ensure_float(
        value: Any,
        field: str,
    ) -> None:

        if not isinstance(
            value,
            (int, float),
        ):
            raise InvalidFieldError(field)

    @staticmethod
    def ensure_boolean(
        value: Any,
        field: str,
    ) -> None:

        if not isinstance(value, bool):
            raise InvalidFieldError(field)

    @staticmethod
    def ensure_list(
        value: Any,
        field: str,
    ) -> None:

        if not isinstance(value, list):
            raise InvalidFieldError(field)

    @staticmethod
    def ensure_dictionary(
        value: Any,
        field: str,
    ) -> None:

        if not isinstance(value, dict):
            raise InvalidFieldError(field)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def is_iso_datetime(
        value: str,
    ) -> bool:

        try:
            datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
            return True

        except Exception:
            return False