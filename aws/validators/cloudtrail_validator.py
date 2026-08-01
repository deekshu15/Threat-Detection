"""
AWS CloudTrail Validator

Validates AWS CloudTrail events and converts them into the
canonical ThreatEvent model.

Supported Services
------------------
• IAM
• STS
• EC2
• S3
• Lambda
• CloudWatch
• CloudTrail
• VPC
• KMS
• Secrets Manager
• ECR
• ECS
• EKS

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


class CloudTrailValidator(EventValidator):

    validator_name = "CloudTrailValidator"

    # ============================================================
    # Main Validation
    # ============================================================

    def validate(
        self,
        raw_event: dict[str, Any],
    ) -> ThreatEvent:

        event = super().validate(raw_event)

        event.event_source = EventSource.CLOUDTRAIL
        event.cloud_provider = CloudProvider.AWS

        event.asset = self.build_asset(raw_event)
        event.user = self.build_user(raw_event)

        event.category = self.detect_category(raw_event)

        self.extract_cloudtrail_metadata(
            event,
            raw_event,
        )

        return event

    # ============================================================
    # Asset
    # ============================================================

    def build_asset(
        self,
        data: dict[str, Any],
    ) -> AssetModel:

        resource = data.get(
            "resource_name",
            "AWS Resource",
        )

        return AssetModel(
            hostname=resource,
            asset_name=resource,
            asset_type="Cloud Resource",
            owner=data.get("account_id"),
            environment=data.get(
                "environment",
                "PRODUCTION",
            ),
        )

    # ============================================================
    # User
    # ============================================================

    def build_user(
        self,
        data: dict[str, Any],
    ) -> UserModel:

        identity = data.get(
            "userIdentity",
            {},
        )

        return UserModel(
            username=identity.get("userName"),
            email=identity.get("arn"),
            role=identity.get("type"),
        )

    # ============================================================
    # Category Detection
    # ============================================================

    def detect_category(
        self,
        data: dict[str, Any],
    ) -> EventCategory:

        service = str(
            data.get(
                "eventSource",
                "",
            )
        ).lower()

        event_name = str(
            data.get(
                "eventName",
                "",
            )
        ).lower()

        if "signin" in event_name:
            return EventCategory.AUTHENTICATION

        if service.startswith("iam"):
            return EventCategory.AUTHENTICATION

        if service.startswith("sts"):
            return EventCategory.AUTHENTICATION

        if service.startswith("ec2"):
            return EventCategory.CLOUD

        if service.startswith("s3"):
            return EventCategory.CLOUD

        if service.startswith("lambda"):
            return EventCategory.CLOUD

        if service.startswith("kms"):
            return EventCategory.CLOUD

        return EventCategory.CLOUD

    # ============================================================
    # Metadata
    # ============================================================

    def extract_cloudtrail_metadata(
        self,
        event: ThreatEvent,
        data: dict[str, Any],
    ) -> None:

        identity = data.get(
            "userIdentity",
            {}
        )

        metadata = {

            "aws_region":
                data.get("awsRegion"),

            "account_id":
                identity.get("accountId"),

            "principal_id":
                identity.get("principalId"),

            "arn":
                identity.get("arn"),

            "event_name":
                data.get("eventName"),

            "event_source":
                data.get("eventSource"),

            "event_version":
                data.get("eventVersion"),

            "event_type":
                data.get("eventType"),

            "management_event":
                data.get("managementEvent"),

            "read_only":
                data.get("readOnly"),

            "recipient_account":
                data.get("recipientAccountId"),

            "request_id":
                data.get("requestID"),

            "source_ip":
                data.get("sourceIPAddress"),

            "user_agent":
                data.get("userAgent"),

            "error_code":
                data.get("errorCode"),

            "error_message":
                data.get("errorMessage"),
        }

        for key, value in metadata.items():
            if value is not None:
                event.update_metadata(
                    key,
                    value,
                )

    # ============================================================
    # Helpers
    # ============================================================

    @staticmethod
    def is_management_event(
        data: dict[str, Any],
    ) -> bool:

        return bool(
            data.get(
                "managementEvent",
                False,
            )
        )

    @staticmethod
    def is_read_only(
        data: dict[str, Any],
    ) -> bool:

        return bool(
            data.get(
                "readOnly",
                False,
            )
        )

    @staticmethod
    def has_error(
        data: dict[str, Any],
    ) -> bool:

        return (
            data.get("errorCode")
            is not None
        )

    @staticmethod
    def service_name(
        data: dict[str, Any],
    ) -> str:

        return str(
            data.get(
                "eventSource",
                "",
            )
        ).split(".")[0]