"""
Google Cloud Platform Validator

Validates Google Cloud Audit Logs and converts them into the
canonical ThreatEvent model.

Supported Services
------------------
• Cloud Audit Logs
• IAM
• Compute Engine
• Cloud Storage
• Cloud Functions
• Cloud Run
• GKE
• VPC
• Cloud SQL
• Secret Manager
• Cloud Logging

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


class GCPValidator(EventValidator):
    """
    Google Cloud Platform Validator.
    """

    validator_name = "GCPValidator"

    # ==========================================================
    # Main Validation
    # ==========================================================

    def validate(
        self,
        raw_event: dict[str, Any],
    ) -> ThreatEvent:

        event = super().validate(raw_event)

        event.event_source = EventSource.GCP
        event.cloud_provider = CloudProvider.GCP

        event.asset = self.build_asset(raw_event)
        event.user = self.build_user(raw_event)

        event.category = self.detect_category(raw_event)

        self.extract_gcp_metadata(
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
            "GCP Resource",
        )

        return AssetModel(
            hostname=resource,
            asset_name=resource,
            asset_type="Cloud Resource",
            owner=data.get("projectId"),
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

        principal = data.get(
            "authenticationInfo",
            {},
        )

        return UserModel(
            username=principal.get(
                "principalEmail"
            ),
            email=principal.get(
                "principalEmail"
            ),
            role=data.get("role"),
            department=data.get("department"),
        )

    # ==========================================================
    # Category Detection
    # ==========================================================

    def detect_category(
        self,
        data: dict[str, Any],
    ) -> EventCategory:

        service = str(
            data.get(
                "serviceName",
                "",
            )
        ).lower()

        method = str(
            data.get(
                "methodName",
                "",
            )
        ).lower()

        if "login" in method:
            return EventCategory.AUTHENTICATION

        if service.startswith("iam"):
            return EventCategory.AUTHENTICATION

        if service.startswith("compute"):
            return EventCategory.CLOUD

        if service.startswith("storage"):
            return EventCategory.CLOUD

        if service.startswith("container"):
            return EventCategory.CLOUD

        if service.startswith("secretmanager"):
            return EventCategory.CLOUD

        if service.startswith("sql"):
            return EventCategory.CLOUD

        return EventCategory.CLOUD

    # ==========================================================
    # Metadata
    # ==========================================================

    def extract_gcp_metadata(
        self,
        event: ThreatEvent,
        data: dict[str, Any],
    ) -> None:

        auth = data.get(
            "authenticationInfo",
            {}
        )

        resource = data.get(
            "resource",
            {}
        )

        metadata = {

            "project_id":
                data.get("projectId"),

            "service_name":
                data.get("serviceName"),

            "method_name":
                data.get("methodName"),

            "resource_name":
                data.get("resourceName"),

            "resource_type":
                resource.get("type"),

            "principal_email":
                auth.get("principalEmail"),

            "caller_ip":
                data.get("callerIp"),

            "severity":
                data.get("severity"),

            "location":
                data.get("location"),

            "status":
                data.get("status"),

            "authorization":
                data.get("authorizationInfo"),

            "request_metadata":
                data.get("requestMetadata"),

            "insert_id":
                data.get("insertId"),

            "log_name":
                data.get("logName"),
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

        status = data.get("status")

        return (
            status is None
            or status == {}
        )

    @staticmethod
    def has_authentication(
        data: dict[str, Any],
    ) -> bool:

        return (
            "authenticationInfo"
            in data
        )

    @staticmethod
    def service_name(
        data: dict[str, Any],
    ) -> str:

        return str(
            data.get(
                "serviceName",
                "",
            )
        )

    @staticmethod
    def project_id(
        data: dict[str, Any],
    ) -> str:

        return str(
            data.get(
                "projectId",
                "",
            )
        )