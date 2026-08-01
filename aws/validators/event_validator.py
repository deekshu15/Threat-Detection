"""
Event Validator

Main orchestrator for the Threat Enrichment validation pipeline.

Validation Pipeline
-------------------

Raw Event
    │
    ▼
SchemaValidator
    │
    ▼
TimestampValidator
    │
    ▼
NetworkValidator
    │
    ▼
Source Specific Validator
    │
    ▼
ThreatEvent

Author: AI-Assisted Threat Detection Dashboard
Python 3.11+
"""

from __future__ import annotations

from typing import Any

from ..lambdas.threat_enrichment.exceptions import ValidationError
from ..lambdas.threat_enrichment.logger import validator_logger
from ..models.event import (
    EventCategory,
    EventSource,
    ThreatEvent,
)
from .base_validator import BaseValidator
from .network_validator import NetworkValidator
from .schema_validator import SchemaValidator
from .timestamp_validator import TimestampValidator


class EventValidator(BaseValidator):
    """
    Main validation orchestrator.
    """

    validator_name = "EventValidator"

    def __init__(self) -> None:

        super().__init__()

        self.schema_validator = SchemaValidator()

        self.timestamp_validator = TimestampValidator()

        self.network_validator = NetworkValidator()

    # ==============================================================
    # Main Entry
    # ==============================================================

    def validate(
        self,
        raw_event: dict[str, Any],
    ) -> ThreatEvent:

        self.log_validation_start("Threat Event")

        # Step 1
        self.schema_validator.validate(raw_event)

        # Step 2
        timestamp = self.timestamp_validator.validate_timestamp(
            raw_event["timestamp"]
        )

        # Step 3
        network = self.network_validator.build_network(
            raw_event
        )

        # Step 4
        event = self.build_event(
            event_name=raw_event["event_name"],
            event_type=raw_event["event_type"],
            event_source=self.parse_source(
                raw_event["event_source"]
            ),
            category=self.parse_category(
                raw_event.get(
                    "category",
                    "OTHER",
                )
            ),
            network=network,
            timestamp=timestamp,
            raw_event=raw_event,
        )

        # Step 5
        self.apply_optional_fields(
            event,
            raw_event,
        )

        return event

    # ==============================================================
    # Enum Parsing
    # ==============================================================

    @staticmethod
    def parse_source(
        source: str,
    ) -> EventSource:

        try:
            return EventSource(
                source.upper()
            )

        except Exception as exc:
            raise ValidationError(
                f"Unsupported source: {source}"
            ) from exc

    @staticmethod
    def parse_category(
        category: str,
    ) -> EventCategory:

        try:
            return EventCategory(
                category.upper()
            )

        except Exception:
            return EventCategory.OTHER

    # ==============================================================
    # Optional Fields
    # ==============================================================

    def apply_optional_fields(
        self,
        event: ThreatEvent,
        raw: dict[str, Any],
    ) -> None:

        event.collector = raw.get(
            "collector"
        )

        event.sensor = raw.get(
            "sensor"
        )

        event.tenant = raw.get(
            "tenant"
        )

        event.organization = raw.get(
            "organization"
        )

        event.environment = raw.get(
            "environment",
            event.environment,
        )

        event.region = raw.get(
            "region"
        )

        event.availability_zone = raw.get(
            "availability_zone"
        )

        event.tags.extend(
            raw.get(
                "tags",
                [],
            )
        )

        event.labels.update(
            raw.get(
                "labels",
                {},
            )
        )

        event.raw_event = raw

    # ==============================================================
    # Convenience
    # ==============================================================

    def validate_many(
        self,
        events: list[dict[str, Any]],
    ) -> list[ThreatEvent]:

        validated = []

        for event in events:

            validated.append(
                self.validate(event)
            )

        return validated

    # ==============================================================
    # Statistics
    # ==============================================================

    @staticmethod
    def summary(
        events: list[ThreatEvent],
    ) -> dict[str, Any]:

        return {
            "events": len(events),
            "high_risk": sum(
                e.is_high_risk
                for e in events
            ),
            "critical": sum(
                e.is_critical
                for e in events
            ),
            "ioc_matches": sum(
                e.ioc_count
                for e in events
            ),
            "cves": sum(
                e.cve_count
                for e in events
            ),
        }

    # ==============================================================
    # Health Check
    # ==============================================================

    @staticmethod
    def health() -> dict[str, str]:

        return {
            "validator": "EventValidator",
            "status": "healthy",
        }