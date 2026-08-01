"""
Azure Validator

Validates Azure Activity Logs, Microsoft Entra ID (Azure AD),
Defender for Cloud, Key Vault, Storage and VM events.

Supported Services
------------------
• Azure Activity Logs
• Microsoft Entra ID
• Defender for Cloud
• Key Vault
• Storage Accounts
• Virtual Machines
• Network Security Groups
• Azure Firewall
• Azure Monitor

Author: AI-Assisted Threat Detection Dashboard
Python 3.11+
"""

from __future__ import annotations

from typing import Any

from ..models.asset import AssetModel
from ..models.event import (
    CloudProvider,
    EventCategory,
    EventSource,
    ThreatEvent,
)
from ..models.user import UserModel
from .event_validator import EventValidator


class AzureValidator(EventValidator):

    validator_name = "AzureValidator"

    # ==========================================================
    # Main Validation
    # ==========================================================

    def validate(
        self,
        raw_event: dict[str, Any],
    ) -> ThreatEvent:

        event = super().validate(raw_event)

        event.event_source = EventSource.AZURE
        event.cloud_provider = CloudProvider.AZURE

        event.asset = self.build_asset(raw_event)
        event.user = self.build_user(raw_event)

        event.category = self.detect_category(raw_event)

        self.extract_metadata(
            event,
            raw_event,
        )

        return event

    # ==========================================================
    # Asset
    # ==========================================================

    def build_asset(
        self,
        data: dict[str, Any],
    ) -> AssetModel:

        resource = data.get(
            "resourceName",
            "Azure Resource",
        )

        return AssetModel(
            hostname=resource,
            asset_name=resource,
            asset_type="Cloud Resource",
            owner=data.get("subscriptionId"),
            environment=data.get(
                "environment",
                "PRODUCTION",
            ),
        )

    # ==========================================================
    # User
    # ==========================================================

    def build_user(
        self,
        data: dict[str, Any],
    ) -> UserModel:

        identity = data.get(
            "identity",
            {},
        )

        return UserModel(
            username=identity.get("user"),
            email=identity.get("email"),
            role=identity.get("role"),
            department=identity.get("department"),
        )

    # ==========================================================
    # Category Detection
    # ==========================================================

    def detect_category(
        self,
        data: dict[str, Any],
    ) -> EventCategory:

        category = str(
            data.get(
                "category",
                "",
            )
        ).lower()

        operation = str(
            data.get(
                "operationName",
                "",
            )
        ).lower()

        if "signin" in operation:
            return EventCategory.AUTHENTICATION

        if "identity" in category:
            return EventCategory.AUTHENTICATION

        if "security" in category:
            return EventCategory.CLOUD

        if "network" in category:
            return EventCategory.NETWORK

        if "storage" in category:
            return EventCategory.CLOUD

        if "compute" in category:
            return EventCategory.CLOUD

        return EventCategory.CLOUD

    # ==========================================================
    # Metadata
    # ==========================================================

    def extract_metadata(
        self,
        event: ThreatEvent,
        data: dict[str, Any],
    ) -> None:

        metadata = {

            "subscription_id":
                data.get("subscriptionId"),

            "tenant_id":
                data.get("tenantId"),

            "resource_group":
                data.get("resourceGroup"),

            "resource_id":
                data.get("resourceId"),

            "resource_type":
                data.get("resourceType"),

            "resource_name":
                data.get("resourceName"),

            "operation_name":
                data.get("operationName"),

            "operation_status":
                data.get("status"),

            "caller":
                data.get("caller"),

            "level":
                data.get("level"),

            "location":
                data.get("location"),

            "correlation_id":
                data.get("correlationId"),

            "event_category":
                data.get("category"),
        }

        for key, value in metadata.items():
            if value is not None:
                event.update_metadata(
                    key,
                    value,
                )

    # ==========================================================
    # Helpers
    # ==========================================================

    @staticmethod
    def is_success(
        data: dict[str, Any],
    ) -> bool:

        return str(
            data.get(
                "status",
                "",
            )
        ).lower() == "succeeded"

    @staticmethod
    def is_failure(
        data: dict[str, Any],
    ) -> bool:

        return str(
            data.get(
                "status",
                "",
            )
        ).lower() == "failed"

    @staticmethod
    def has_identity(
        data: dict[str, Any],
    ) -> bool:

        return "identity" in data

    @staticmethod
    def resource_type(
        data: dict[str, Any],
    ) -> str:

        return str(
            data.get(
                "resourceType",
                "",
            )
        )