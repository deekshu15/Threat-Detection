"""
Firewall Validator

Validates firewall logs and converts them into the
canonical ThreatEvent model.

Supported Vendors
-----------------
• Cisco ASA
• Palo Alto
• Fortinet
• Check Point
• Sophos
• SonicWall
• pfSense
• Generic Syslog Firewall

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
from ..models.user import UserModel
from .event_validator import EventValidator


class FirewallValidator(EventValidator):

    validator_name = "FirewallValidator"

    # ===============================================================
    # Main Validation
    # ===============================================================

    def validate(
        self,
        raw_event: dict[str, Any],
    ) -> ThreatEvent:

        event = super().validate(raw_event)

        event.event_source = EventSource.FIREWALL

        event.category = self.detect_category(raw_event)

        event.asset = self.build_asset(raw_event)

        event.user = self.build_user(raw_event)

        self.extract_firewall_metadata(
            event,
            raw_event,
        )

        return event

    # ===============================================================
    # Asset
    # ===============================================================

    def build_asset(
        self,
        data: dict[str, Any],
    ) -> AssetModel:

        return AssetModel(
            hostname=data.get("firewall_name"),
            asset_name=data.get(
                "firewall_name",
                "Firewall",
            ),
            asset_type="Firewall",
            owner=data.get("owner"),
            department=data.get("department"),
            environment=data.get(
                "environment",
                "PRODUCTION",
            ),
        )

    # ===============================================================
    # User
    # ===============================================================

    def build_user(
        self,
        data: dict[str, Any],
    ) -> UserModel:

        return UserModel(
            username=data.get("username"),
            department=data.get("department"),
        )

    # ===============================================================
    # Category Detection
    # ===============================================================

    def detect_category(
        self,
        data: dict[str, Any],
    ) -> EventCategory:

        action = str(
            data.get(
                "action",
                "",
            )
        ).upper()

        if action in (
            "ALLOW",
            "ACCEPT",
            "PERMIT",
        ):
            return EventCategory.NETWORK

        if action in (
            "DENY",
            "DROP",
            "BLOCK",
        ):
            return EventCategory.NETWORK

        if action == "VPN":
            return EventCategory.AUTHENTICATION

        if action == "IPS":
            return EventCategory.INTRUSION

        return EventCategory.OTHER

    # ===============================================================
    # Metadata
    # ===============================================================

    def extract_firewall_metadata(
        self,
        event: ThreatEvent,
        data: dict[str, Any],
    ) -> None:

        metadata = {
            "vendor": data.get("vendor"),
            "model": data.get("model"),
            "firmware": data.get("firmware"),
            "policy": data.get("policy"),
            "rule": data.get("rule"),
            "action": data.get("action"),
            "zone_in": data.get("zone_in"),
            "zone_out": data.get("zone_out"),
            "interface_in": data.get("interface_in"),
            "interface_out": data.get("interface_out"),
            "nat_source": data.get("nat_source"),
            "nat_destination": data.get("nat_destination"),
            "session_id": data.get("session_id"),
            "application": data.get("application"),
            "country": data.get("country"),
        }

        for key, value in metadata.items():
            if value is not None:
                event.update_metadata(
                    key,
                    value,
                )

    # ===============================================================
    # Firewall Helpers
    # ===============================================================

    @staticmethod
    def is_allowed(action: str) -> bool:

        return action.upper() in (
            "ALLOW",
            "ACCEPT",
            "PERMIT",
        )

    @staticmethod
    def is_blocked(action: str) -> bool:

        return action.upper() in (
            "DENY",
            "DROP",
            "BLOCK",
        )

    @staticmethod
    def is_vpn(action: str) -> bool:

        return action.upper() == "VPN"

    @staticmethod
    def is_ips(action: str) -> bool:

        return action.upper() == "IPS"