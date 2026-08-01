"""
buckets.py

Enterprise S3 Bucket Management

Responsibilities
----------------
- Bucket definitions
- Bucket creation
- Bucket validation
- Bucket discovery
- Versioning
- Server-side encryption
- Public access blocking
- Bucket tagging
- Bucket diagnostics
"""

from __future__ import annotations

import logging
import os

from dataclasses import dataclass
from enum import Enum
from typing import Any

from botocore.exceptions import ClientError

from aws.utils.aws_utils import (
    get_client,
    AWSUtilityError,
)

logger = logging.getLogger(__name__)


###########################################################################
# Configuration
###########################################################################

DEFAULT_REGION = os.getenv(
    "AWS_REGION",
    os.getenv(
        "AWS_DEFAULT_REGION",
        "us-east-1",
    ),
)

PROJECT_NAME = "AI-Assisted-Threat-Detection"

PROJECT_TAGS = {
    "Project": PROJECT_NAME,
    "ManagedBy": "CloudFormation",
    "Environment": "Development",
}


###########################################################################
# Bucket Names
###########################################################################


class BucketNames(str, Enum):

    THREAT_LOGS = "threat-logs"

    NORMALIZED_LOGS = "normalized-logs"

    IOC_DATA = "ioc-data"

    CVE_DATA = "cve-data"

    MITRE_DATA = "mitre-data"

    FEATURE_STORE = "feature-store"

    ML_MODELS = "ml-models"

    REPORTS = "reports"

    BACKUPS = "backups"

    QUICKSIGHT_DATA = "quicksight-data"


###########################################################################
# Bucket Definition
###########################################################################


@dataclass(slots=True)
class BucketDefinition:

    name: str

    versioning: bool = True

    encryption: bool = True

    public_access: bool = False

    lifecycle: bool = True

    tags: dict[str, str] | None = None


###########################################################################
# Registry
###########################################################################

BUCKETS = [
    BucketDefinition(
        name=BucketNames.THREAT_LOGS.value,
        tags={
            **PROJECT_TAGS,
            "Purpose": "Threat Logs",
        },
    ),
    BucketDefinition(
        name=BucketNames.NORMALIZED_LOGS.value,
        tags={
            **PROJECT_TAGS,
            "Purpose": "Normalized Logs",
        },
    ),
    BucketDefinition(
        name=BucketNames.IOC_DATA.value,
        tags={
            **PROJECT_TAGS,
            "Purpose": "IOC Data",
        },
    ),
    BucketDefinition(
        name=BucketNames.CVE_DATA.value,
        tags={
            **PROJECT_TAGS,
            "Purpose": "CVE Database",
        },
    ),
    BucketDefinition(
        name=BucketNames.MITRE_DATA.value,
        tags={
            **PROJECT_TAGS,
            "Purpose": "MITRE ATT&CK",
        },
    ),
    BucketDefinition(
        name=BucketNames.FEATURE_STORE.value,
        tags={
            **PROJECT_TAGS,
            "Purpose": "Feature Store",
        },
    ),
    BucketDefinition(
        name=BucketNames.ML_MODELS.value,
        tags={
            **PROJECT_TAGS,
            "Purpose": "ML Models",
        },
    ),
    BucketDefinition(
        name=BucketNames.REPORTS.value,
        tags={
            **PROJECT_TAGS,
            "Purpose": "Reports",
        },
    ),
    BucketDefinition(
        name=BucketNames.BACKUPS.value,
        tags={
            **PROJECT_TAGS,
            "Purpose": "Backups",
        },
    ),
    BucketDefinition(
        name=BucketNames.QUICKSIGHT_DATA.value,
        tags={
            **PROJECT_TAGS,
            "Purpose": "QuickSight",
        },
    ),
]


###########################################################################
# Client
###########################################################################


def s3():

    return get_client("s3")


###########################################################################
# Bucket Lookup
###########################################################################


def get_bucket_definition(
    bucket_name: str,
) -> BucketDefinition:

    for bucket in BUCKETS:

        if bucket.name == bucket_name:

            return bucket

    raise ValueError(f"Unknown bucket '{bucket_name}'.")


def bucket_names() -> list[str]:

    return [bucket.name for bucket in BUCKETS]


###########################################################################
# Validation
###########################################################################


def validate_bucket_name(
    bucket_name: str,
) -> bool:

    if not bucket_name:

        raise ValueError("Bucket name cannot be empty.")

    if len(bucket_name) < 3:

        raise ValueError("Bucket name must contain at least 3 characters.")

    if len(bucket_name) > 63:

        raise ValueError("Bucket name exceeds AWS limit.")

    if bucket_name.startswith("-"):

        raise ValueError("Bucket name cannot start with '-'.")

    if bucket_name.endswith("-"):

        raise ValueError("Bucket name cannot end with '-'.")

    return True


###########################################################################
# Discovery
###########################################################################


def list_buckets() -> list[str]:

    client = s3()

    try:

        response = client.list_buckets()

        return [
            bucket["Name"]
            for bucket in response.get(
                "Buckets",
                [],
            )
        ]

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="ListBuckets",
        ) from exc


def bucket_exists(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.head_bucket(
            Bucket=bucket_name,
        )

        return True

    except ClientError:

        return False


###########################################################################
# Bucket Information
###########################################################################


def bucket_region(
    bucket_name: str,
) -> str | None:

    client = s3()

    try:

        response = client.get_bucket_location(
            Bucket=bucket_name,
        )

        location = response.get("LocationConstraint")

        if location is None:

            return "us-east-1"

        return location

    except Exception:

        return None


###########################################################################
# Bucket Creation
###########################################################################


def create_bucket(
    bucket_name: str,
    region: str | None = None,
) -> bool:

    validate_bucket_name(
        bucket_name,
    )

    if bucket_exists(
        bucket_name,
    ):

        logger.info(
            "Bucket '%s' already exists.",
            bucket_name,
        )

        return False

    client = s3()

    region = region or DEFAULT_REGION

    try:

        if region == "us-east-1":

            client.create_bucket(
                Bucket=bucket_name,
            )

        else:

            client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    "LocationConstraint": region,
                },
            )

        logger.info(
            "Bucket '%s' created.",
            bucket_name,
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="CreateBucket",
        ) from exc


###########################################################################
# Delete Bucket
###########################################################################


def delete_bucket(
    bucket_name: str,
) -> bool:

    client = s3()

    if not bucket_exists(
        bucket_name,
    ):

        return False

    try:

        client.delete_bucket(
            Bucket=bucket_name,
        )

        logger.info(
            "Deleted bucket '%s'.",
            bucket_name,
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="DeleteBucket",
        ) from exc


###########################################################################
# Wait Until Bucket Exists
###########################################################################


def wait_until_bucket_exists(
    bucket_name: str,
) -> None:

    waiter = s3().get_waiter(
        "bucket_exists",
    )

    waiter.wait(
        Bucket=bucket_name,
    )


###########################################################################
# Wait Until Bucket Deleted
###########################################################################


def wait_until_bucket_deleted(
    bucket_name: str,
) -> None:

    waiter = s3().get_waiter(
        "bucket_not_exists",
    )

    waiter.wait(
        Bucket=bucket_name,
    )


###########################################################################
# Versioning
###########################################################################


def enable_versioning(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={
                "Status": "Enabled",
            },
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketVersioning",
        ) from exc


def suspend_versioning(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={
                "Status": "Suspended",
            },
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="SuspendBucketVersioning",
        ) from exc


def versioning_status(
    bucket_name: str,
) -> str:

    client = s3()

    response = client.get_bucket_versioning(
        Bucket=bucket_name,
    )

    return response.get(
        "Status",
        "Disabled",
    )


###########################################################################
# Encryption
###########################################################################


def enable_default_encryption(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketEncryption",
        ) from exc


def encryption_enabled(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.get_bucket_encryption(
            Bucket=bucket_name,
        )

        return True

    except ClientError:

        return False


###########################################################################
# Public Access Block
###########################################################################


def block_public_access(
    bucket_name: str,
) -> bool:

    client = s3()

    configuration = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    try:

        client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=configuration,
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutPublicAccessBlock",
        ) from exc


def public_access_configuration(
    bucket_name: str,
) -> dict[str, Any]:

    client = s3()

    response = client.get_public_access_block(
        Bucket=bucket_name,
    )

    return response.get(
        "PublicAccessBlockConfiguration",
        {},
    )


###########################################################################
# Bucket Tags
###########################################################################


def put_bucket_tags(
    bucket_name: str,
    tags: dict[str, str],
) -> bool:

    client = s3()

    tag_set = [
        {
            "Key": key,
            "Value": value,
        }
        for key, value in tags.items()
    ]

    try:

        client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={
                "TagSet": tag_set,
            },
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketTagging",
        ) from exc


def get_bucket_tags(
    bucket_name: str,
) -> dict[str, str]:

    client = s3()

    try:

        response = client.get_bucket_tagging(
            Bucket=bucket_name,
        )

        return {
            item["Key"]: item["Value"]
            for item in response.get(
                "TagSet",
                [],
            )
        }

    except ClientError:

        return {}


###########################################################################
# Bucket Policy
###########################################################################


def put_bucket_policy(
    bucket_name: str,
    policy: str,
) -> bool:

    client = s3()

    try:

        client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=policy,
        )

        logger.info(
            "Bucket policy applied to '%s'.",
            bucket_name,
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketPolicy",
        ) from exc


def get_bucket_policy(
    bucket_name: str,
) -> str | None:

    client = s3()

    try:

        response = client.get_bucket_policy(
            Bucket=bucket_name,
        )

        return response.get("Policy")

    except ClientError:

        return None


def delete_bucket_policy(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.delete_bucket_policy(
            Bucket=bucket_name,
        )

        return True

    except ClientError:

        return False


###########################################################################
# Bucket CORS
###########################################################################


def put_bucket_cors(
    bucket_name: str,
    rules: list[dict[str, Any]],
) -> bool:

    client = s3()

    try:

        client.put_bucket_cors(
            Bucket=bucket_name,
            CORSConfiguration={
                "CORSRules": rules,
            },
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketCors",
        ) from exc


def get_bucket_cors(
    bucket_name: str,
) -> list[dict[str, Any]]:

    client = s3()

    try:

        response = client.get_bucket_cors(
            Bucket=bucket_name,
        )

        return response.get(
            "CORSRules",
            [],
        )

    except ClientError:

        return []


def delete_bucket_cors(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.delete_bucket_cors(
            Bucket=bucket_name,
        )

        return True

    except ClientError:

        return False


###########################################################################
# Bucket Logging
###########################################################################


def enable_bucket_logging(
    bucket_name: str,
    target_bucket: str,
    prefix: str = "logs/",
) -> bool:

    client = s3()

    try:

        client.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": target_bucket,
                    "TargetPrefix": prefix,
                }
            },
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketLogging",
        ) from exc


def disable_bucket_logging(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus={},
        )

        return True

    except ClientError:

        return False


def bucket_logging_status(
    bucket_name: str,
) -> dict[str, Any]:

    client = s3()

    try:

        response = client.get_bucket_logging(
            Bucket=bucket_name,
        )

        return response.get(
            "LoggingEnabled",
            {},
        )

    except ClientError:

        return {}


###########################################################################
# Ownership Controls
###########################################################################


def enable_bucket_owner_enforced(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.put_bucket_ownership_controls(
            Bucket=bucket_name,
            OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketOwnershipControls",
        ) from exc


def get_bucket_ownership(
    bucket_name: str,
) -> dict[str, Any]:

    client = s3()

    try:

        response = client.get_bucket_ownership_controls(
            Bucket=bucket_name,
        )

        return response.get(
            "OwnershipControls",
            {},
        )

    except ClientError:

        return {}


###########################################################################
# Bucket Inventory
###########################################################################


def put_bucket_inventory(
    bucket_name: str,
    inventory_bucket: str,
    inventory_id: str = "default",
    prefix: str = "inventory/",
) -> bool:

    client = s3()

    try:

        client.put_bucket_inventory_configuration(
            Bucket=bucket_name,
            Id=inventory_id,
            InventoryConfiguration={
                "Destination": {
                    "S3BucketDestination": {
                        "Bucket": f"arn:aws:s3:::{inventory_bucket}",
                        "Format": "CSV",
                        "Prefix": prefix,
                    }
                },
                "IsEnabled": True,
                "IncludedObjectVersions": "Current",
                "Schedule": {"Frequency": "Daily"},
                "OptionalFields": [
                    "Size",
                    "LastModifiedDate",
                    "StorageClass",
                    "ETag",
                ],
                "Id": inventory_id,
            },
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketInventoryConfiguration",
        ) from exc


def get_bucket_inventory(
    bucket_name: str,
    inventory_id: str = "default",
) -> dict[str, Any]:

    client = s3()

    try:

        response = client.get_bucket_inventory_configuration(
            Bucket=bucket_name,
            Id=inventory_id,
        )

        return response.get(
            "InventoryConfiguration",
            {},
        )

    except ClientError:

        return {}


###########################################################################
# Transfer Acceleration
###########################################################################


def enable_transfer_acceleration(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.put_bucket_accelerate_configuration(
            Bucket=bucket_name,
            AccelerateConfiguration={
                "Status": "Enabled",
            },
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketAccelerateConfiguration",
        ) from exc


def disable_transfer_acceleration(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.put_bucket_accelerate_configuration(
            Bucket=bucket_name,
            AccelerateConfiguration={
                "Status": "Suspended",
            },
        )

        return True

    except ClientError:

        return False


def acceleration_status(
    bucket_name: str,
) -> str:

    client = s3()

    try:

        response = client.get_bucket_accelerate_configuration(
            Bucket=bucket_name,
        )

        return response.get(
            "Status",
            "Suspended",
        )

    except ClientError:

        return "Unknown"


###########################################################################
# Request Payment
###########################################################################


def requester_pays(
    bucket_name: str,
) -> bool:

    client = s3()

    try:

        client.put_bucket_request_payment(
            Bucket=bucket_name,
            RequestPaymentConfiguration={
                "Payer": "Requester",
            },
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketRequestPayment",
        ) from exc


def bucket_payment_configuration(
    bucket_name: str,
) -> str:

    client = s3()

    try:

        response = client.get_bucket_request_payment(
            Bucket=bucket_name,
        )

        return response.get(
            "Payer",
            "BucketOwner",
        )

    except ClientError:

        return "BucketOwner"


###########################################################################
# Website Hosting
###########################################################################


def enable_static_website(
    bucket_name: str,
    index_document: str = "index.html",
    error_document: str = "error.html",
) -> bool:

    client = s3()

    try:

        client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {
                    "Suffix": index_document,
                },
                "ErrorDocument": {
                    "Key": error_document,
                },
            },
        )

        return True

    except Exception as exc:

        raise AWSUtilityError(
            str(exc),
            service="s3",
            operation="PutBucketWebsite",
        ) from exc


def website_configuration(
    bucket_name: str,
) -> dict[str, Any]:

    client = s3()

    try:

        response = client.get_bucket_website(
            Bucket=bucket_name,
        )

        return response

    except ClientError:

        return {}


###########################################################################
# Bucket Summary
###########################################################################


def bucket_summary(
    bucket_name: str,
) -> dict[str, Any]:

    return {
        "name": bucket_name,
        "exists": bucket_exists(
            bucket_name,
        ),
        "region": bucket_region(
            bucket_name,
        ),
        "versioning": versioning_status(
            bucket_name,
        ),
        "encryption": encryption_enabled(
            bucket_name,
        ),
        "tags": get_bucket_tags(
            bucket_name,
        ),
        "public_access": public_access_configuration(
            bucket_name,
        ),
        "logging": bucket_logging_status(
            bucket_name,
        ),
        "ownership": get_bucket_ownership(
            bucket_name,
        ),
        "acceleration": acceleration_status(
            bucket_name,
        ),
        "payment": bucket_payment_configuration(
            bucket_name,
        ),
    }


###########################################################################
# Create All Project Buckets
###########################################################################


def configure_bucket(
    bucket: BucketDefinition,
) -> dict[str, Any]:

    result = {
        "bucket": bucket.name,
        "created": False,
        "versioning": False,
        "encryption": False,
        "public_access_block": False,
        "tags": False,
    }

    if not bucket_exists(
        bucket.name,
    ):

        create_bucket(
            bucket.name,
        )

        wait_until_bucket_exists(
            bucket.name,
        )

        result["created"] = True

    if bucket.versioning:

        enable_versioning(
            bucket.name,
        )

        result["versioning"] = True

    if bucket.encryption:

        enable_default_encryption(
            bucket.name,
        )

        result["encryption"] = True

    if not bucket.public_access:

        block_public_access(
            bucket.name,
        )

        result["public_access_block"] = True

    if bucket.tags:

        put_bucket_tags(
            bucket.name,
            bucket.tags,
        )

        result["tags"] = True

    logger.info(
        "Configured bucket '%s'.",
        bucket.name,
    )

    return result


###########################################################################
# Create All Buckets
###########################################################################


def create_all_buckets() -> dict[str, Any]:

    created = []

    existing = []

    configuration = []

    for bucket in BUCKETS:

        if bucket_exists(
            bucket.name,
        ):

            existing.append(
                bucket.name,
            )

        else:

            created.append(
                bucket.name,
            )

        configuration.append(
            configure_bucket(
                bucket,
            )
        )

    return {
        "created": created,
        "existing": existing,
        "configuration": configuration,
    }


###########################################################################
# Delete All Buckets
###########################################################################


def delete_all_buckets() -> dict[str, Any]:

    deleted = []

    skipped = []

    for bucket in BUCKETS:

        if bucket_exists(
            bucket.name,
        ):

            delete_bucket(
                bucket.name,
            )

            deleted.append(
                bucket.name,
            )

        else:

            skipped.append(
                bucket.name,
            )

    return {
        "deleted": deleted,
        "skipped": skipped,
    }


###########################################################################
# Bucket Validation
###########################################################################


def validate_bucket(
    bucket_name: str,
) -> dict[str, Any]:

    return {
        "bucket": bucket_name,
        "exists": bucket_exists(
            bucket_name,
        ),
        "versioning": versioning_status(
            bucket_name,
        ),
        "encrypted": encryption_enabled(
            bucket_name,
        ),
        "public_access": public_access_configuration(
            bucket_name,
        ),
        "tags": get_bucket_tags(
            bucket_name,
        ),
    }


###########################################################################
# Validate All Buckets
###########################################################################


def validate_all_buckets() -> list[dict[str, Any]]:

    return [
        validate_bucket(
            bucket.name,
        )
        for bucket in BUCKETS
    ]


###########################################################################
# Bucket Health
###########################################################################


def bucket_health(
    bucket_name: str,
) -> dict[str, Any]:

    healthy = True

    issues = []

    if not bucket_exists(
        bucket_name,
    ):

        healthy = False

        issues.append("Bucket does not exist.")

    if (
        versioning_status(
            bucket_name,
        )
        != "Enabled"
    ):

        healthy = False

        issues.append("Versioning disabled.")

    if not encryption_enabled(
        bucket_name,
    ):

        healthy = False

        issues.append("Encryption disabled.")

    configuration = public_access_configuration(
        bucket_name,
    )

    if not configuration:

        healthy = False

        issues.append("Public access block missing.")

    return {
        "bucket": bucket_name,
        "healthy": healthy,
        "issues": issues,
    }


###########################################################################
# Health Report
###########################################################################


def health_report() -> list[dict[str, Any]]:

    return [
        bucket_health(
            bucket.name,
        )
        for bucket in BUCKETS
    ]


###########################################################################
# Statistics
###########################################################################


def bucket_statistics() -> dict[str, Any]:

    existing = list_buckets()

    configured = bucket_names()

    missing = [bucket for bucket in configured if bucket not in existing]

    return {
        "configured": len(configured),
        "existing": len(existing),
        "missing": len(missing),
        "missing_buckets": missing,
    }


###########################################################################
# Inventory Report
###########################################################################


def inventory_report() -> list[dict[str, Any]]:

    report = []

    for bucket in BUCKETS:

        report.append(
            bucket_summary(
                bucket.name,
            )
        )

    return report


###########################################################################
# Configuration Report
###########################################################################


def configuration_report() -> list[dict[str, Any]]:

    report = []

    for bucket in BUCKETS:

        report.append(
            {
                "name": bucket.name,
                "versioning": bucket.versioning,
                "encryption": bucket.encryption,
                "public_access": bucket.public_access,
                "lifecycle": bucket.lifecycle,
                "tags": bucket.tags,
            }
        )

    return report


###########################################################################
# Diagnostics
###########################################################################


def diagnostics() -> dict[str, Any]:

    return {
        "statistics": bucket_statistics(),
        "health": health_report(),
        "inventory": inventory_report(),
    }


###########################################################################
# Bucket Manager
###########################################################################


class BucketManager:
    """
    High-level manager for all project buckets.
    """

    def __init__(
        self,
    ):

        self.client = s3()

    def create_all(
        self,
    ):

        return create_all_buckets()

    def delete_all(
        self,
    ):

        return delete_all_buckets()

    def validate(
        self,
    ):

        return validate_all_buckets()

    def diagnostics(
        self,
    ):

        return diagnostics()

    def inventory(
        self,
    ):

        return inventory_report()

    def statistics(
        self,
    ):

        return bucket_statistics()


###########################################################################
# Global Manager
###########################################################################

BUCKET_MANAGER = BucketManager()


###########################################################################
# Self Test
###########################################################################


def self_test() -> dict[str, Any]:

    configured = bucket_names()

    existing = list_buckets()

    health = health_report()

    passed = True

    for item in health:

        if not item["healthy"]:

            passed = False

            break

    return {
        "passed": passed,
        "configured": configured,
        "existing": existing,
        "statistics": bucket_statistics(),
        "health": health,
    }


###########################################################################
# Main
###########################################################################

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )

    print("=" * 80)

    print("S3 Bucket Management")

    print("=" * 80)

    print()

    print("Registered Buckets")

    for bucket in bucket_names():

        print(f" • {bucket}")

    print()

    print("Statistics")

    print(bucket_statistics())

    print()

    print("Diagnostics")

    print(diagnostics())

    print()

    print("Self Test")

    print(self_test())

    print()

    print("Bucket Manager Ready")


__all__ = [
    "BucketNames",
    "BucketDefinition",
    "BucketManager",
    "BUCKET_MANAGER",
]
