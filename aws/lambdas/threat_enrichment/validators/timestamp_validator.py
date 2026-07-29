"""
Timestamp Validator

Provides reusable timestamp validation and normalization utilities.

Responsibilities
----------------
• Parse ISO-8601 timestamps
• Parse Unix timestamps (seconds/milliseconds)
• Normalize timestamps to UTC
• Validate timestamps are reasonable
• Calculate event age

Author: AI-Assisted Threat Detection Dashboard
Python: 3.11+
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from ..exceptions import (
    InvalidTimestampError,
)
from .base_validator import BaseValidator


class TimestampValidator(BaseValidator):
    """
    Timestamp validation utilities.
    """

    validator_name = "TimestampValidator"

    MAX_FUTURE_MINUTES = 5
    MAX_PAST_DAYS = 3650

    def validate(self, raw_event: dict[str, Any]):
        raise NotImplementedError(
            "Use parse_timestamp() or validate_timestamp()."
        )

    # ==============================================================
    # Parsing
    # ==============================================================

    def parse_timestamp(
        self,
        value: Any,
    ) -> datetime:
        """
        Parse supported timestamp formats.
        """

        if value is None:
            raise InvalidTimestampError("Timestamp is None")

        # datetime object
        if isinstance(value, datetime):

            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)

            return value.astimezone(UTC)

        # Unix timestamp
        if isinstance(value, (int, float)):

            timestamp = float(value)

            # milliseconds
            if timestamp > 1_000_000_000_000:
                timestamp /= 1000

            return datetime.fromtimestamp(
                timestamp,
                tz=UTC,
            )

        # ISO string
        if isinstance(value, str):

            value = value.strip()

            try:
                return datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                ).astimezone(UTC)

            except Exception:
                pass

            # numeric string
            try:
                return self.parse_timestamp(
                    float(value)
                )

            except Exception:
                pass

        raise InvalidTimestampError(
            f"Unsupported timestamp: {value}"
        )

    # ==============================================================
    # Validation
    # ==============================================================

    def validate_timestamp(
        self,
        value: Any,
    ) -> datetime:
        """
        Parse and validate timestamp.
        """

        timestamp = self.parse_timestamp(value)

        self.validate_future(timestamp)

        self.validate_age(timestamp)

        return timestamp

    def validate_future(
        self,
        timestamp: datetime,
    ) -> None:

        now = datetime.now(UTC)

        if timestamp > (
            now + timedelta(minutes=self.MAX_FUTURE_MINUTES)
        ):
            raise InvalidTimestampError(
                "Timestamp is in the future."
            )

    def validate_age(
        self,
        timestamp: datetime,
    ) -> None:

        now = datetime.now(UTC)

        if timestamp < (
            now - timedelta(days=self.MAX_PAST_DAYS)
        ):
            raise InvalidTimestampError(
                "Timestamp is too old."
            )

    # ==============================================================
    # Utilities
    # ==============================================================

    def event_age(
        self,
        timestamp: datetime,
    ) -> timedelta:
        """
        Return event age.
        """

        return datetime.now(UTC) - timestamp

    def event_age_seconds(
        self,
        timestamp: datetime,
    ) -> int:
        return int(
            self.event_age(timestamp).total_seconds()
        )

    def event_age_minutes(
        self,
        timestamp: datetime,
    ) -> float:
        return (
            self.event_age(timestamp)
            .total_seconds()
            / 60
        )

    def event_age_hours(
        self,
        timestamp: datetime,
    ) -> float:
        return (
            self.event_age(timestamp)
            .total_seconds()
            / 3600
        )

    def event_age_days(
        self,
        timestamp: datetime,
    ) -> float:
        return (
            self.event_age(timestamp)
            .total_seconds()
            / 86400
        )

    # ==============================================================
    # Formatting
    # ==============================================================

    @staticmethod
    def isoformat(
        timestamp: datetime,
    ) -> str:
        """
        UTC ISO-8601 format.
        """

        return (
            timestamp
            .astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

    @staticmethod
    def unix_seconds(
        timestamp: datetime,
    ) -> int:
        return int(timestamp.timestamp())

    @staticmethod
    def unix_milliseconds(
        timestamp: datetime,
    ) -> int:
        return int(
            timestamp.timestamp() * 1000
        )

    # ==============================================================
    # Comparison
    # ==============================================================

    @staticmethod
    def is_same_day(
        ts1: datetime,
        ts2: datetime,
    ) -> bool:

        return ts1.date() == ts2.date()

    @staticmethod
    def difference(
        ts1: datetime,
        ts2: datetime,
    ) -> timedelta:

        return abs(ts1 - ts2)

    @staticmethod
    def within_seconds(
        ts1: datetime,
        ts2: datetime,
        seconds: int,
    ) -> bool:

        return abs(
            (ts1 - ts2).total_seconds()
        ) <= seconds

    @staticmethod
    def within_minutes(
        ts1: datetime,
        ts2: datetime,
        minutes: int,
    ) -> bool:

        return TimestampValidator.within_seconds(
            ts1,
            ts2,
            minutes * 60,
        )

    @staticmethod
    def within_hours(
        ts1: datetime,
        ts2: datetime,
        hours: int,
    ) -> bool:

        return TimestampValidator.within_seconds(
            ts1,
            ts2,
            hours * 3600,
        )