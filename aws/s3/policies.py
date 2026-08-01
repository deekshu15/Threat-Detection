"""
policies.py

Enterprise S3 Bucket Policy Management

Responsibilities
----------------
• Bucket policy creation
• Bucket policy updates
• Bucket policy deletion
• IAM access policies
• Public/private policies
• Policy validation
• Policy diagnostics
"""

from __future__ import annotations

import json
import logging

from typing import Any

from botocore.exceptions import ClientError

from aws.utils.aws_utils import get_client

from .buckets import BucketNames

logger = logging.getLogger(__name__)


###########################################################################
# Client
###########################################################################


def s3():

    return get_client(
        "s3",
    )


###########################################################################
# Policy Service
###########################################################################


class PolicyService:
    """
    High-level S3 Bucket Policy Management.
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
    # Get Bucket Policy
    #######################################################################

    def get_policy(
        self,
        bucket: str,
    ) -> dict[str, Any] | None:

        try:

            response = self.client.get_bucket_policy(
                Bucket=bucket,
            )

            return json.loads(response["Policy"])

        except ClientError:

            return None

    #######################################################################
    # Put Bucket Policy
    #######################################################################

    def put_policy(
        self,
        bucket: str,
        policy: dict[str, Any],
    ) -> bool:

        self.client.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps(
                policy,
            ),
        )

        logger.info(
            "Policy applied to %s",
            bucket,
        )

        return True

    #######################################################################
    # Delete Bucket Policy
    #######################################################################

    def delete_policy(
        self,
        bucket: str,
    ) -> bool:

        self.client.delete_bucket_policy(
            Bucket=bucket,
        )

        logger.info(
            "Policy removed from %s",
            bucket,
        )

        return True

    #######################################################################
    # Policy Exists
    #######################################################################

    def policy_exists(
        self,
        bucket: str,
    ) -> bool:

        return (
            self.get_policy(
                bucket,
            )
            is not None
        )

    #######################################################################
    # Validate Policy
    #######################################################################

    def validate_policy(
        self,
        policy: dict[str, Any],
    ) -> bool:

        required = [
            "Version",
            "Statement",
        ]

        for field in required:

            if field not in policy:

                raise ValueError(f"Missing policy field: {field}")

        return True

    #######################################################################
    # Empty Policy
    #######################################################################

    def empty_policy(
        self,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [],
        }

    #######################################################################
    # Add Statement
    #######################################################################

    def add_statement(
        self,
        policy: dict[str, Any],
        statement: dict[str, Any],
    ) -> dict[str, Any]:

        policy.setdefault(
            "Statement",
            [],
        ).append(
            statement,
        )

        return policy

    #######################################################################
    # Remove Statement
    #######################################################################

    def remove_statement(
        self,
        policy: dict[str, Any],
        sid: str,
    ) -> dict[str, Any]:

        policy["Statement"] = [
            statement
            for statement in policy.get(
                "Statement",
                [],
            )
            if statement.get(
                "Sid",
            )
            != sid
        ]

        return policy

    #######################################################################
    # Public Read Policy
    #######################################################################

    def public_read_policy(
        self,
        bucket: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicRead",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": [
                        "s3:GetObject",
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                }
            ],
        }

    #######################################################################
    # Private Bucket Policy
    #######################################################################

    def private_bucket_policy(
        self,
        bucket: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyPublicAccess",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                    "Condition": {
                        "Bool": {
                            "aws:SecureTransport": "false",
                        }
                    },
                }
            ],
        }

    #######################################################################
    # HTTPS Only Policy
    #######################################################################

    def https_only_policy(
        self,
        bucket: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "HttpsOnly",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                    "Condition": {
                        "Bool": {
                            "aws:SecureTransport": "false",
                        }
                    },
                }
            ],
        }

    #######################################################################
    # Read Only Policy
    #######################################################################

    def read_only_policy(
        self,
        bucket: str,
        principal: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadOnly",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": principal,
                    },
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket",
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                }
            ],
        }

    #######################################################################
    # Read Write Policy
    #######################################################################

    def read_write_policy(
        self,
        bucket: str,
        principal: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadWrite",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": principal,
                    },
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:ListBucket",
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                }
            ],
        }

    #######################################################################
    # IAM Role Access Policy
    #######################################################################

    def iam_role_policy(
        self,
        bucket: str,
        role_arn: str,
    ) -> dict[str, Any]:

        return self.read_write_policy(
            bucket,
            role_arn,
        )

    #######################################################################
    # Cross Account Policy
    #######################################################################

    def cross_account_policy(
        self,
        bucket: str,
        account_id: str,
    ) -> dict[str, Any]:

        principal = f"arn:aws:iam::{account_id}:root"

        return self.read_only_policy(
            bucket,
            principal,
        )

    #######################################################################
    # Policy Builder
    #######################################################################

    def build_policy(
        self,
        statements: list[dict[str, Any]],
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": statements,
        }

    #######################################################################
    # IP Restriction Policy
    #######################################################################

    def ip_restriction_policy(
        self,
        bucket: str,
        allowed_ip: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowSpecificIP",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": allowed_ip,
                        }
                    },
                }
            ],
        }

    #######################################################################
    # VPC Endpoint Policy
    #######################################################################

    def vpc_endpoint_policy(
        self,
        bucket: str,
        vpce_id: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VpcEndpointOnly",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                    "Condition": {
                        "StringNotEquals": {
                            "aws:SourceVpce": vpce_id,
                        }
                    },
                }
            ],
        }

    #######################################################################
    # AWS Organization Policy
    #######################################################################

    def organization_policy(
        self,
        bucket: str,
        organization_id: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "OrganizationAccess",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalOrgID": organization_id,
                        }
                    },
                }
            ],
        }

    #######################################################################
    # MFA Enforcement Policy
    #######################################################################

    def mfa_policy(
        self,
        bucket: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireMFA",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                    "Condition": {
                        "BoolIfExists": {
                            "aws:MultiFactorAuthPresent": "false",
                        }
                    },
                }
            ],
        }

    #######################################################################
    # Encryption Enforcement Policy
    #######################################################################

    def encryption_policy(
        self,
        bucket: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireEncryption",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": [
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": "AES256",
                        }
                    },
                }
            ],
        }

    #######################################################################
    # Object Tag Policy
    #######################################################################

    def object_tag_policy(
        self,
        bucket: str,
        tag_key: str,
        tag_value: str,
    ) -> dict[str, Any]:

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireObjectTag",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": [
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                    "Condition": {
                        "StringEquals": {
                            f"s3:RequestObjectTag/{tag_key}": tag_value,
                        }
                    },
                }
            ],
        }

    #######################################################################
    # Secure Default Policy
    #######################################################################

    def secure_default_policy(
        self,
        bucket: str,
    ) -> dict[str, Any]:

        statements = []

        statements.extend(
            self.https_only_policy(
                bucket,
            )["Statement"]
        )

        statements.extend(
            self.encryption_policy(
                bucket,
            )["Statement"]
        )

        return self.build_policy(
            statements,
        )

    #######################################################################
    # Policy Merge
    #######################################################################

    def merge_policies(
        self,
        *policies: dict[str, Any],
    ) -> dict[str, Any]:

        statements = []

        for policy in policies:

            statements.extend(
                policy.get(
                    "Statement",
                    [],
                )
            )

        return self.build_policy(
            statements,
        )

    #######################################################################
    # Apply Policy
    #######################################################################

    def apply_policy(
        self,
        bucket: str,
        policy: dict[str, Any],
    ) -> bool:

        self.validate_policy(
            policy,
        )

        return self.put_policy(
            bucket,
            policy,
        )

    #######################################################################
    # Apply Policy To All Buckets
    #######################################################################

    def apply_to_all(
        self,
        policy: dict[str, Any],
    ) -> dict[str, bool]:

        results = {}

        for bucket in self.default_buckets:

            try:

                self.apply_policy(
                    bucket,
                    policy,
                )

                results[bucket] = True

            except Exception:

                logger.exception(
                    "Failed applying policy to %s",
                    bucket,
                )

                results[bucket] = False

        return results

    #######################################################################
    # Remove Policy From All Buckets
    #######################################################################

    def remove_from_all(
        self,
    ) -> dict[str, bool]:

        results = {}

        for bucket in self.default_buckets:

            try:

                self.delete_policy(
                    bucket,
                )

                results[bucket] = True

            except Exception:

                logger.exception(
                    "Failed removing policy from %s",
                    bucket,
                )

                results[bucket] = False

        return results

    #######################################################################
    # Validate Bucket Policy
    #######################################################################

    def validate_bucket(
        self,
        bucket: str,
    ) -> bool:

        policy = self.get_policy(
            bucket,
        )

        if policy is None:

            return False

        try:

            self.validate_policy(
                policy,
            )

            return True

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
    # Policy Inventory
    #######################################################################

    def inventory(
        self,
    ) -> dict[str, dict[str, Any] | None]:

        inventory = {}

        for bucket in self.default_buckets:

            inventory[bucket] = self.get_policy(
                bucket,
            )

        return inventory

    #######################################################################
    # Policy Summary
    #######################################################################

    def summary(
        self,
    ) -> dict[str, Any]:

        validation = self.validate_all()

        total = len(
            validation,
        )

        valid = sum(
            validation.values(),
        )

        return {
            "managed_buckets": total,
            "valid_policies": valid,
            "invalid_policies": total - valid,
        }

    #######################################################################
    # Policy Metrics
    #######################################################################

    def metrics(
        self,
    ) -> dict[str, Any]:

        validation = self.validate_all()

        return {
            "total": len(
                validation,
            ),
            "configured": sum(
                validation.values(),
            ),
            "missing": len(
                validation,
            )
            - sum(
                validation.values(),
            ),
        }

    #######################################################################
    # Policy Health
    #######################################################################

    def health(
        self,
    ) -> dict[str, Any]:

        validation = self.validate_all()

        return {
            "healthy": all(
                validation.values(),
            ),
            "buckets": validation,
        }

    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return {
            "summary": self.summary(),
            "metrics": self.metrics(),
            "health": self.health(),
            "inventory": self.inventory(),
        }


###########################################################################
# Policy Manager
###########################################################################


class PolicyManager:
    """
    High-level manager for bucket policy operations.
    """

    def __init__(
        self,
    ):

        self.service = PolicyService()

    def policy(
        self,
    ) -> PolicyService:

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

POLICY = PolicyService()

POLICY_MANAGER = PolicyManager()


###########################################################################
# Convenience Functions
###########################################################################


def policy() -> PolicyService:

    return POLICY


def diagnostics() -> dict[str, Any]:

    return POLICY.diagnostics()


def summary() -> dict[str, Any]:

    return POLICY.summary()


def health() -> dict[str, Any]:

    return POLICY.health()


###########################################################################
# Self Test
###########################################################################


def self_test() -> dict[str, Any]:

    service = PolicyService()

    return {
        "module": "policies",
        "status": "ready",
        "summary": service.summary(),
        "diagnostics": service.diagnostics(),
    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [
    "PolicyService",
    "PolicyManager",
    "POLICY",
    "POLICY_MANAGER",
    "policy",
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

    print("S3 Policy Service")

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

    print("S3 Policy Service Ready")
