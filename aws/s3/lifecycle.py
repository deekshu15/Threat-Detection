"""
lifecycle.py

Enterprise S3 Lifecycle Management

Responsibilities
----------------
• Lifecycle rule creation
• Rule updates
• Rule deletion
• Object expiration
• Storage class transitions
• Version cleanup
• Lifecycle diagnostics
"""

from __future__ import annotations

import logging

from typing import Any

from botocore.exceptions import ClientError

from aws.utils.aws_utils import get_client

from .buckets import (
    BucketNames,
)

logger = logging.getLogger(__name__)


###########################################################################
# Client
###########################################################################


def s3():

    return get_client(
        "s3",
    )


###########################################################################
# Lifecycle Service
###########################################################################


class LifecycleService:
    """
    High-level lifecycle management for project buckets.
    """

    def __init__(
        self,
    ):

        self.client = s3()

        self.default_buckets = [
            BucketNames.THREAT_LOGS.value,
            BucketNames.NORMALIZED_LOGS.value,
            BucketNames.IOC_DATA.value,
            BucketNames.CVE_DATA.value,
            BucketNames.MITRE_DATA.value,
            BucketNames.FEATURE_STORE.value,
            BucketNames.ML_MODELS.value,
            BucketNames.REPORTS.value,
            BucketNames.BACKUPS.value,
            BucketNames.QUICKSIGHT_DATA.value,
        ]

    #######################################################################
    # Get Lifecycle Configuration
    #######################################################################

    def get_configuration(
        self,
        bucket: str,
    ) -> dict[str, Any]:

        try:

            return self.client.get_bucket_lifecycle_configuration(
                Bucket=bucket,
            )

        except ClientError:

            return {
                "Rules": [],
            }

    #######################################################################
    # Put Lifecycle Configuration
    #######################################################################

    def put_configuration(
        self,
        bucket: str,
        rules: list[dict[str, Any]],
    ) -> bool:

        # Validate every lifecycle rule first
        for rule in rules:

            self.validate_rule(rule)

        # Send only valid rules to AWS
        self.client.put_bucket_lifecycle_configuration(
            Bucket=bucket,
            LifecycleConfiguration={
                "Rules": rules,
            },
        )

        logger.info(
            "Lifecycle configuration updated for %s",
            bucket,
        )

        return True

    #######################################################################
    # Delete Lifecycle Configuration
    #######################################################################

    def delete_configuration(
        self,
        bucket: str,
    ) -> bool:

        self.client.delete_bucket_lifecycle(
            Bucket=bucket,
        )

        logger.info(
            "Lifecycle configuration removed from %s",
            bucket,
        )

        return True

    #######################################################################
    # List Rules
    #######################################################################

    def list_rules(
        self,
        bucket: str,
    ) -> list[dict[str, Any]]:

        configuration = self.get_configuration(
            bucket,
        )

        return configuration.get(
            "Rules",
            [],
        )

    #######################################################################
    # Rule Exists
    #######################################################################

    def rule_exists(
        self,
        bucket: str,
        rule_id: str,
    ) -> bool:

        rules = self.list_rules(
            bucket,
        )

        return any(
            rule.get(
                "ID",
            )
            == rule_id
            for rule in rules
        )

    #######################################################################
    # Get Rule
    #######################################################################

    def get_rule(
        self,
        bucket: str,
        rule_id: str,
    ) -> dict[str, Any] | None:

        for rule in self.list_rules(
            bucket,
        ):

            if (
                rule.get(
                    "ID",
                )
                == rule_id
            ):

                return rule

        return None

    #######################################################################
    # Delete Rule
    #######################################################################

    def delete_rule(
        self,
        bucket: str,
        rule_id: str,
    ) -> bool:

        rules = [
            rule
            for rule in self.list_rules(
                bucket,
            )
            if rule.get(
                "ID",
            )
            != rule_id
        ]

        self.put_configuration(
            bucket,
            rules,
        )

        return True

    #######################################################################
    # Expiration Rule
    #######################################################################

    def expiration_rule(
        self,
        rule_id: str,
        days: int,
        prefix: str = "",
        enabled: bool = True,
    ) -> dict[str, Any]:

        return {
            "ID": rule_id,
            "Status": "Enabled" if enabled else "Disabled",
            "Filter": {
                "Prefix": prefix,
            },
            "Expiration": {
                "Days": days,
            },
        }

    #######################################################################
    # Prefix Expiration Rule
    #######################################################################

    def prefix_expiration_rule(
        self,
        rule_id: str,
        prefix: str,
        days: int,
        enabled: bool = True,
    ) -> dict[str, Any]:

        return self.expiration_rule(
            rule_id=rule_id,
            days=days,
            prefix=prefix,
            enabled=enabled,
        )

    #######################################################################
    # Tag Expiration Rule
    #######################################################################

    def tag_expiration_rule(
        self,
        rule_id: str,
        tag_key: str,
        tag_value: str,
        days: int,
        enabled: bool = True,
    ) -> dict[str, Any]:

        return {
            "ID": rule_id,
            "Status": "Enabled" if enabled else "Disabled",
            "Filter": {
                "Tag": {
                    "Key": tag_key,
                    "Value": tag_value,
                }
            },
            "Expiration": {
                "Days": days,
            },
        }

    #######################################################################
    # Add Rule
    #######################################################################

    def add_rule(
        self,
        bucket: str,
        rule: dict[str, Any],
    ) -> bool:

        rules = self.list_rules(
            bucket,
        )

        rules.append(
            rule,
        )

        self.put_configuration(
            bucket,
            rules,
        )

        return True

    #######################################################################
    # Replace Rule
    #######################################################################

    def replace_rule(
        self,
        bucket: str,
        rule_id: str,
        new_rule: dict[str, Any],
    ) -> bool:

        rules = []

        for rule in self.list_rules(
            bucket,
        ):

            if (
                rule.get(
                    "ID",
                )
                == rule_id
            ):

                rules.append(
                    new_rule,
                )

            else:

                rules.append(
                    rule,
                )

        self.put_configuration(
            bucket,
            rules,
        )

        return True

    #######################################################################
    # Enable Rule
    #######################################################################

    def enable_rule(
        self,
        bucket: str,
        rule_id: str,
    ) -> bool:

        rule = self.get_rule(
            bucket,
            rule_id,
        )

        if rule is None:

            return False

        rule["Status"] = "Enabled"

        return self.replace_rule(
            bucket,
            rule_id,
            rule,
        )

    #######################################################################
    # Disable Rule
    #######################################################################

    def disable_rule(
        self,
        bucket: str,
        rule_id: str,
    ) -> bool:

        rule = self.get_rule(
            bucket,
            rule_id,
        )

        if rule is None:

            return False

        rule["Status"] = "Disabled"

        return self.replace_rule(
            bucket,
            rule_id,
            rule,
        )

    #######################################################################
    # Rule Validation
    #######################################################################

    def validate_rule(
        self,
        rule: dict[str, Any],
    ) -> bool:

        required = [
            "ID",
            "Status",
            "Filter",
        ]

        for field in required:

            if field not in rule:

                raise ValueError(f"Missing lifecycle field: {field}")

        return True

    #######################################################################
    # Rule Builder
    #######################################################################

    def build_rule(
        self,
        rule_id: str,
        days: int,
        prefix: str = "",
        enabled: bool = True,
    ) -> dict[str, Any]:

        return self.expiration_rule(
            rule_id=rule_id,
            days=days,
            prefix=prefix,
            enabled=enabled,
        )

    #######################################################################
    # Transition Rule
    #######################################################################

    def transition_rule(
        self,
        rule_id: str,
        transition_days: int,
        storage_class: str,
        prefix: str = "",
        enabled: bool = True,
    ) -> dict[str, Any]:

        return {
            "ID": rule_id,
            "Status": "Enabled" if enabled else "Disabled",
            "Filter": {
                "Prefix": prefix,
            },
            "Transitions": [
                {
                    "Days": transition_days,
                    "StorageClass": storage_class,
                }
            ],
        }

    #######################################################################
    # Standard IA Transition
    #######################################################################

    def standard_ia_rule(
        self,
        rule_id: str,
        days: int,
        prefix: str = "",
    ) -> dict[str, Any]:

        return self.transition_rule(
            rule_id=rule_id,
            transition_days=days,
            storage_class="STANDARD_IA",
            prefix=prefix,
        )

    #######################################################################
    # Intelligent Tiering
    #######################################################################

    def intelligent_tiering_rule(
        self,
        rule_id: str,
        days: int,
        prefix: str = "",
    ) -> dict[str, Any]:

        return self.transition_rule(
            rule_id=rule_id,
            transition_days=days,
            storage_class="INTELLIGENT_TIERING",
            prefix=prefix,
        )

    #######################################################################
    # Glacier Instant Retrieval
    #######################################################################

    def glacier_ir_rule(
        self,
        rule_id: str,
        days: int,
        prefix: str = "",
    ) -> dict[str, Any]:

        return self.transition_rule(
            rule_id=rule_id,
            transition_days=days,
            storage_class="GLACIER_IR",
            prefix=prefix,
        )

    #######################################################################
    # Glacier Flexible Retrieval
    #######################################################################

    def glacier_flexible_rule(
        self,
        rule_id: str,
        days: int,
        prefix: str = "",
    ) -> dict[str, Any]:

        return self.transition_rule(
            rule_id=rule_id,
            transition_days=days,
            storage_class="GLACIER",
            prefix=prefix,
        )

    #######################################################################
    # Deep Archive
    #######################################################################

    def deep_archive_rule(
        self,
        rule_id: str,
        days: int,
        prefix: str = "",
    ) -> dict[str, Any]:

        return self.transition_rule(
            rule_id=rule_id,
            transition_days=days,
            storage_class="DEEP_ARCHIVE",
            prefix=prefix,
        )

    #######################################################################
    # Non-current Version Transition
    #######################################################################

    def noncurrent_transition_rule(
        self,
        rule_id: str,
        noncurrent_days: int,
        storage_class: str,
        enabled: bool = True,
    ) -> dict[str, Any]:

        return {
            "ID": rule_id,
            "Status": "Enabled" if enabled else "Disabled",
            "Filter": {},
            "NoncurrentVersionTransitions": [
                {
                    "NoncurrentDays": noncurrent_days,
                    "StorageClass": storage_class,
                }
            ],
        }

    #######################################################################
    # Expiration + Transition Rule
    #######################################################################

    def expiration_transition_rule(
        self,
        rule_id: str,
        transition_days: int,
        expiration_days: int,
        storage_class: str,
        prefix: str = "",
    ) -> dict[str, Any]:

        return {
            "ID": rule_id,
            "Status": "Enabled",
            "Filter": {
                "Prefix": prefix,
            },
            "Transitions": [
                {
                    "Days": transition_days,
                    "StorageClass": storage_class,
                }
            ],
            "Expiration": {
                "Days": expiration_days,
            },
        }

    #######################################################################
    # Rule Template
    #######################################################################

    def default_archive_rule(
        self,
    ) -> dict[str, Any]:

        return self.expiration_transition_rule(
            rule_id="default-archive",
            transition_days=30,
            expiration_days=365,
            storage_class="GLACIER",
        )

    #######################################################################
    # Non-current Version Expiration
    #######################################################################

    def noncurrent_expiration_rule(
        self,
        rule_id: str,
        noncurrent_days: int,
        enabled: bool = True,
    ) -> dict[str, Any]:

        return {
            "ID": rule_id,
            "Status": "Enabled" if enabled else "Disabled",
            "Filter": {},
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": noncurrent_days,
            },
        }

    #######################################################################
    # Abort Incomplete Multipart Upload
    #######################################################################

    def abort_incomplete_upload_rule(
        self,
        rule_id: str,
        days_after_initiation: int = 7,
        enabled: bool = True,
    ) -> dict[str, Any]:

        return {
            "ID": rule_id,
            "Status": "Enabled" if enabled else "Disabled",
            "Filter": {},
            "AbortIncompleteMultipartUpload": {
                "DaysAfterInitiation": days_after_initiation,
            },
        }

    #######################################################################
    # Cleanup Rule
    #######################################################################

    def cleanup_rule(
        self,
        rule_id: str,
        expiration_days: int,
        multipart_days: int = 7,
    ) -> dict[str, Any]:

        return {
            "ID": rule_id,
            "Status": "Enabled",
            "Filter": {},
            "Expiration": {
                "Days": expiration_days,
            },
            "AbortIncompleteMultipartUpload": {
                "DaysAfterInitiation": multipart_days,
            },
        }

    #######################################################################
    # Complete Archive Rule
    #######################################################################

    def complete_archive_rule(
        self,
        rule_id: str,
        transition_days: int,
        expiration_days: int,
        storage_class: str = "GLACIER",
    ) -> dict[str, Any]:

        return {
            "ID": rule_id,
            "Status": "Enabled",
            "Filter": {},
            "Transitions": [
                {
                    "Days": transition_days,
                    "StorageClass": storage_class,
                }
            ],
            "Expiration": {
                "Days": expiration_days,
            },
            "AbortIncompleteMultipartUpload": {
                "DaysAfterInitiation": 7,
            },
        }

    #######################################################################
    # Apply Default Rule
    #######################################################################

    def apply_default_rule(
        self,
        bucket: str,
    ) -> bool:

        rule = self.default_archive_rule()

        return self.add_rule(
            bucket,
            rule,
        )

    #######################################################################
    # Apply Default Rule To All Buckets
    #######################################################################

    def apply_default_rules(
        self,
    ) -> dict[str, bool]:

        results = {}

        for bucket in self.default_buckets:

            try:

                self.apply_default_rule(
                    bucket,
                )

                results[bucket] = True

            except Exception:

                logger.exception(
                    "Failed applying lifecycle to %s",
                    bucket,
                )

                results[bucket] = False

        return results

    #######################################################################
    # Validate Bucket Rules
    #######################################################################

    def validate_bucket(
        self,
        bucket: str,
    ) -> bool:

        try:

            configuration = self.get_configuration(
                bucket,
            )

            return "Rules" in configuration

        except Exception:

            return False

    #######################################################################
    # Validate All Buckets
    #######################################################################

    def validate_all(
        self,
    ) -> dict[str, bool]:

        results = {}

        for bucket in self.default_buckets:

            results[bucket] = self.validate_bucket(
                bucket,
            )

        return results

    #######################################################################
    # Lifecycle Summary
    #######################################################################

    def summary(
        self,
    ) -> dict[str, Any]:

        validation = self.validate_all()

        return {
            "managed_buckets": len(
                self.default_buckets,
            ),
            "valid": sum(
                validation.values(),
            ),
            "invalid": len(
                validation,
            )
            - sum(
                validation.values(),
            ),
        }

    #######################################################################
    # Lifecycle Health
    #######################################################################

    def health(
        self,
    ) -> dict[str, Any]:

        validation = self.validate_all()

        healthy = all(validation.values())

        return {
            "healthy": healthy,
            "buckets": validation,
        }

    #######################################################################
    # Lifecycle Metrics
    #######################################################################

    def metrics(
        self,
    ) -> dict[str, Any]:

        validation = self.validate_all()

        managed = len(
            self.default_buckets,
        )

        valid = sum(
            validation.values(),
        )

        invalid = managed - valid

        return {
            "managed_buckets": managed,
            "valid": valid,
            "invalid": invalid,
        }

    #######################################################################
    # Lifecycle Inventory
    #######################################################################

    def inventory(
        self,
    ) -> dict[str, list[dict[str, Any]]]:

        inventory = {}

        for bucket in self.default_buckets:

            inventory[bucket] = self.list_rules(
                bucket,
            )

        return inventory

    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return {
            "summary": self.summary(),
            "health": self.health(),
            "metrics": self.metrics(),
            "inventory": self.inventory(),
        }


###########################################################################
# Lifecycle Manager
###########################################################################


class LifecycleManager:
    """
    High-level manager for lifecycle operations.
    """

    def __init__(
        self,
    ):

        self.service = LifecycleService()

    def lifecycle(
        self,
    ) -> LifecycleService:

        return self.service

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return self.service.diagnostics()

    def summary(
        self,
    ) -> dict[str, Any]:

        return self.service.summary()

    def health(
        self,
    ) -> dict[str, Any]:

        return self.service.health()


###########################################################################
# Global Instances
###########################################################################

LIFECYCLE = LifecycleService()

LIFECYCLE_MANAGER = LifecycleManager()


###########################################################################
# Convenience Functions
###########################################################################


def lifecycle() -> LifecycleService:

    return LIFECYCLE


def diagnostics() -> dict[str, Any]:

    return LIFECYCLE.diagnostics()


def summary() -> dict[str, Any]:

    return LIFECYCLE.summary()


def health() -> dict[str, Any]:

    return LIFECYCLE.health()


###########################################################################
# Self Test
###########################################################################


def self_test() -> dict[str, Any]:

    service = LifecycleService()

    return {
        "module": "lifecycle",
        "status": "ready",
        "summary": service.summary(),
        "diagnostics": service.diagnostics(),
    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [
    "LifecycleService",
    "LifecycleManager",
    "LIFECYCLE",
    "LIFECYCLE_MANAGER",
    "lifecycle",
    "diagnostics",
    "summary",
    "health",
    "self_test",
]


###########################################################################
# Main
###########################################################################

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )

    print("=" * 80)

    print("S3 Lifecycle Service")

    print("=" * 80)

    print()

    print("Summary")

    print(
        summary(),
    )

    print()

    print("Health")

    print(
        health(),
    )

    print()

    print("Diagnostics")

    print(
        diagnostics(),
    )

    print()

    print("Self Test")

    print(
        self_test(),
    )

    print()

    print("Lifecycle Service Ready")
