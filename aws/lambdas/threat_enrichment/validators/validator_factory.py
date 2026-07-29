"""
Validator Factory

Creates the correct validator instance for incoming events.

This module isolates validator selection from the pipeline.

Author: AI-Assisted Threat Detection Dashboard
Python 3.11+
"""

from __future__ import annotations

from typing import Any

from ..exceptions import ValidationError

from ..models.event import EventSource

from .base_validator import BaseValidator
from .windows_validator import WindowsValidator
from .linux_validator import LinuxValidator
from .firewall_validator import FirewallValidator
from .cloudtrail_validator import CloudTrailValidator
from .azure_validator import AzureValidator
from .gcp_validator import GCPValidator


class ValidatorFactory:
    """
    Factory responsible for returning validators.
    """

    _validators: dict[EventSource, type[BaseValidator]] = {

        EventSource.WINDOWS:
            WindowsValidator,

        EventSource.LINUX:
            LinuxValidator,

        EventSource.FIREWALL:
            FirewallValidator,

        EventSource.CLOUDTRAIL:
            CloudTrailValidator,

        EventSource.AZURE:
            AzureValidator,

        EventSource.GCP:
            GCPValidator,
    }

    # ===========================================================
    # Registration
    # ===========================================================

    @classmethod
    def register(
        cls,
        source: EventSource,
        validator: type[BaseValidator],
    ) -> None:

        cls._validators[source] = validator

    # ===========================================================
    # Remove
    # ===========================================================

    @classmethod
    def unregister(
        cls,
        source: EventSource,
    ) -> None:

        cls._validators.pop(
            source,
            None,
        )

    # ===========================================================
    # Get Validator
    # ===========================================================

    @classmethod
    def get_validator(
        cls,
        source: EventSource,
    ) -> BaseValidator:

        validator = cls._validators.get(source)

        if validator is None:
            raise ValidationError(
                f"No validator registered for '{source}'"
            )

        return validator()

    # ===========================================================
    # Validate Event
    # ===========================================================

    @classmethod
    def validate(
        cls,
        source: EventSource,
        raw_event: dict[str, Any],
    ):

        validator = cls.get_validator(source)

        return validator.validate(raw_event)

    # ===========================================================
    # Information
    # ===========================================================

    @classmethod
    def supported_sources(cls):

        return sorted(
            source.value
            for source in cls._validators
        )

    @classmethod
    def validator_names(cls):

        return {
            source.value:
            validator.__name__
            for source, validator in cls._validators.items()
        }

    @classmethod
    def exists(
        cls,
        source: EventSource,
    ) -> bool:

        return source in cls._validators

    @classmethod
    def count(cls) -> int:

        return len(cls._validators)

    @classmethod
    def clear(cls):

        cls._validators.clear()

    @classmethod
    def reset(cls):

        cls._validators = {

            EventSource.WINDOWS:
                WindowsValidator,

            EventSource.LINUX:
                LinuxValidator,

            EventSource.FIREWALL:
                FirewallValidator,

            EventSource.CLOUDTRAIL:
                CloudTrailValidator,

            EventSource.AZURE:
                AzureValidator,

            EventSource.GCP:
                GCPValidator,
        }