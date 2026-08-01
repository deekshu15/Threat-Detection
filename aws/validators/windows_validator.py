"""
Windows Event Validator

Validates Windows Event Logs and converts them into the
canonical ThreatEvent model.

Supported Events
----------------
• Logon
• Logoff
• Failed Logon
• Process Creation
• Service Creation
• PowerShell
• Registry Modification
• File Access
• Scheduled Task
• Security Events
• Sysmon Events

Author: AI-Assisted Threat Detection Dashboard
Python 3.11+
"""

from __future__ import annotations

from typing import Any

from ..models.asset import AssetModel
from ..models.event import (
    EventCategory,
    EventSource,
    ThreatEvent,
)
from ..models.network import NetworkModel
from ..models.user import UserModel
from .event_validator import EventValidator


class WindowsValidator(EventValidator):
    """
    Windows Event Validator.
    """

    validator_name = "WindowsValidator"

    # ==============================================================
    # Main Validation
    # ==============================================================

    def validate(
        self,
        raw_event: dict[str, Any],
    ) -> ThreatEvent:

        # Generic validation
        event = super().validate(raw_event)

        # Override source
        event.event_source = EventSource.WINDOWS

        # Windows specific enrichment
        event.asset = self.build_asset(raw_event)

        event.user = self.build_user(raw_event)

        event.category = self.detect_category(raw_event)

        self.extract_windows_metadata(
            event,
            raw_event,
        )

        return event

    # ==============================================================
    # Asset
    # ==============================================================

    def build_asset(
        self,
        data: dict[str, Any],
    ) -> AssetModel:

        return AssetModel(
            hostname=data.get("computer_name"),
            operating_system="Windows",
            asset_name=data.get(
                "computer_name",
                "Unknown",
            ),
            owner=data.get("owner"),
            department=data.get("department"),
            environment=data.get(
                "environment",
                "PRODUCTION",
            ),
        )

    # ==============================================================
    # User
    # ==============================================================

    def build_user(
        self,
        data: dict[str, Any],
    ) -> UserModel:

        return UserModel(
            username=data.get("username"),
            email=data.get("email"),
            role=data.get("role"),
            department=data.get("department"),
            failed_logins=int(
                data.get(
                    "failed_logins",
                    0,
                )
            ),
        )

    # ==============================================================
    # Category Detection
    # ==============================================================

    def detect_category(
        self,
        data: dict[str, Any],
    ) -> EventCategory:

        event_id = int(
            data.get(
                "event_id",
                0,
            )
        )

        if event_id in (
            4624,
            4625,
            4634,
            4648,
        ):
            return EventCategory.AUTHENTICATION

        if event_id in (
            4688,
            4689,
        ):
            return EventCategory.ENDPOINT

        if event_id in (
            4697,
            7045,
        ):
            return EventCategory.PRIVILEGE_ESCALATION

        if event_id in (
            4656,
            4663,
        ):
            return EventCategory.FILE

        if event_id in (
            5156,
            5158,
        ):
            return EventCategory.NETWORK

        return EventCategory.OTHER

    # ==============================================================
    # Metadata
    # ==============================================================

    def extract_windows_metadata(
        self,
        event: ThreatEvent,
        data: dict[str, Any],
    ) -> None:

        event.update_metadata(
            "event_id",
            data.get("event_id"),
        )

        event.update_metadata(
            "channel",
            data.get("channel"),
        )

        event.update_metadata(
            "provider",
            data.get("provider"),
        )

        event.update_metadata(
            "process_name",
            data.get("process_name"),
        )

        event.update_metadata(
            "command_line",
            data.get("command_line"),
        )

        event.update_metadata(
            "logon_type",
            data.get("logon_type"),
        )

        event.update_metadata(
            "integrity_level",
            data.get(
                "integrity_level"
            ),
        )

        event.update_metadata(
            "session_id",
            data.get("session_id"),
        )

    # ==============================================================
    # Helpers
    # ==============================================================

    @staticmethod
    def is_failed_login(
        event_id: int,
    ) -> bool:

        return event_id == 4625

    @staticmethod
    def is_successful_login(
        event_id: int,
    ) -> bool:

        return event_id == 4624

    @staticmethod
    def is_process_creation(
        event_id: int,
    ) -> bool:

        return event_id == 4688

    @staticmethod
    def is_service_creation(
        event_id: int,
    ) -> bool:

        return event_id in (
            4697,
            7045,
        )