"""
policies.py

Enterprise IAM Policy Management

Responsibilities
----------------
• Create IAM policies
• Delete IAM policies
• Manage policy versions
• Attach/detach policies
• Policy validation
• Diagnostics
"""

from __future__ import annotations

import json
import logging

from typing import Any

from botocore.exceptions import ClientError

from aws.utils.aws_utils import get_client

logger = logging.getLogger(__name__)


###########################################################################
# Client
###########################################################################

def iam():

    return get_client(

        "iam",

    )


###########################################################################
# Policy Service
###########################################################################

class PolicyService:

    """
    High-level IAM Policy Management.
    """

    def __init__(

        self,

    ):

        self.client = iam()


    #######################################################################
    # Create Policy
    #######################################################################

    def create_policy(

        self,

        policy_name: str,

        policy_document: dict[str, Any],

        description: str = "",

        path: str = "/",

    ) -> dict[str, Any]:

        response = self.client.create_policy(

            PolicyName=policy_name,

            PolicyDocument=json.dumps(

                policy_document,

            ),

            Description=description,

            Path=path,

        )

        logger.info(

            "Created IAM policy %s",

            policy_name,

        )

        return response["Policy"]


    #######################################################################
    # Delete Policy
    #######################################################################

    def delete_policy(

        self,

        policy_arn: str,

    ) -> bool:

        self.client.delete_policy(

            PolicyArn=policy_arn,

        )

        logger.info(

            "Deleted IAM policy %s",

            policy_arn,

        )

        return True


    #######################################################################
    # Get Policy
    #######################################################################

    def get_policy(

        self,

        policy_arn: str,

    ) -> dict[str, Any] | None:

        try:

            response = self.client.get_policy(

                PolicyArn=policy_arn,

            )

            return response["Policy"]

        except ClientError:

            return None


    #######################################################################
    # Policy Exists
    #######################################################################

    def policy_exists(

        self,

        policy_arn: str,

    ) -> bool:

        return self.get_policy(

            policy_arn,

        ) is not None


    #######################################################################
    # List Policies
    #######################################################################

    def list_policies(

        self,

        scope: str = "Local",

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_policies",

        )

        policies = []

        for page in paginator.paginate(

            Scope=scope,

        ):

            policies.extend(

                page.get(

                    "Policies",

                    [],

                )

            )

        return policies


    #######################################################################
    # List Policy ARNs
    #######################################################################

    def list_policy_arns(

        self,

        scope: str = "Local",

    ) -> list[str]:

        return [

            policy["Arn"]

            for policy in self.list_policies(

                scope,

            )

        ]


    #######################################################################
    # Get Default Policy Version
    #######################################################################

    def get_default_version(

        self,

        policy_arn: str,

    ) -> str | None:

        policy = self.get_policy(

            policy_arn,

        )

        if policy is None:

            return None

        return policy.get(

            "DefaultVersionId",

        )


    #######################################################################
    # Get Policy Version
    #######################################################################

    def get_policy_version(

        self,

        policy_arn: str,

        version_id: str,

    ) -> dict[str, Any] | None:

        try:

            response = self.client.get_policy_version(

                PolicyArn=policy_arn,

                VersionId=version_id,

            )

            return response["PolicyVersion"]

        except ClientError:

            return None


    #######################################################################
    # Validate Policy
    #######################################################################

    def validate_policy(

        self,

        policy_document: dict[str, Any],

    ) -> bool:

        required = [

            "Version",

            "Statement",

        ]

        for field in required:

            if field not in policy_document:

                raise ValueError(

                    f"Missing required policy field: {field}"

                )

        return True

    #######################################################################
    # Create Policy Version
    #######################################################################

    def create_policy_version(

        self,

        policy_arn: str,

        policy_document: dict[str, Any],

        set_as_default: bool = False,

    ) -> dict[str, Any]:

        self.validate_policy(

            policy_document,

        )

        response = self.client.create_policy_version(

            PolicyArn=policy_arn,

            PolicyDocument=json.dumps(

                policy_document,

            ),

            SetAsDefault=set_as_default,

        )

        logger.info(

            "Created policy version for %s",

            policy_arn,

        )

        return response["PolicyVersion"]


    #######################################################################
    # Set Default Policy Version
    #######################################################################

    def set_default_version(

        self,

        policy_arn: str,

        version_id: str,

    ) -> bool:

        self.client.set_default_policy_version(

            PolicyArn=policy_arn,

            VersionId=version_id,

        )

        logger.info(

            "Set %s as default version for %s",

            version_id,

            policy_arn,

        )

        return True


    #######################################################################
    # Delete Policy Version
    #######################################################################

    def delete_policy_version(

        self,

        policy_arn: str,

        version_id: str,

    ) -> bool:

        self.client.delete_policy_version(

            PolicyArn=policy_arn,

            VersionId=version_id,

        )

        logger.info(

            "Deleted policy version %s",

            version_id,

        )

        return True


    #######################################################################
    # List Policy Versions
    #######################################################################

    def list_policy_versions(

        self,

        policy_arn: str,

    ) -> list[dict[str, Any]]:

        response = self.client.list_policy_versions(

            PolicyArn=policy_arn,

        )

        return response.get(

            "Versions",

            [],

        )


    #######################################################################
    # Attach Policy To Role
    #######################################################################

    def attach_to_role(

        self,

        policy_arn: str,

        role_name: str,

    ) -> bool:

        self.client.attach_role_policy(

            RoleName=role_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Attached %s to role %s",

            policy_arn,

            role_name,

        )

        return True


    #######################################################################
    # Detach Policy From Role
    #######################################################################

    def detach_from_role(

        self,

        policy_arn: str,

        role_name: str,

    ) -> bool:

        self.client.detach_role_policy(

            RoleName=role_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Detached %s from role %s",

            policy_arn,

            role_name,

        )

        return True


    #######################################################################
    # Attach Policy To User
    #######################################################################

    def attach_to_user(

        self,

        policy_arn: str,

        user_name: str,

    ) -> bool:

        self.client.attach_user_policy(

            UserName=user_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Attached %s to user %s",

            policy_arn,

            user_name,

        )

        return True


    #######################################################################
    # Detach Policy From User
    #######################################################################

    def detach_from_user(

        self,

        policy_arn: str,

        user_name: str,

    ) -> bool:

        self.client.detach_user_policy(

            UserName=user_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Detached %s from user %s",

            policy_arn,

            user_name,

        )

        return True


    #######################################################################
    # Attach Policy To Group
    #######################################################################

    def attach_to_group(

        self,

        policy_arn: str,

        group_name: str,

    ) -> bool:

        self.client.attach_group_policy(

            GroupName=group_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Attached %s to group %s",

            policy_arn,

            group_name,

        )

        return True


    #######################################################################
    # Detach Policy From Group
    #######################################################################

    def detach_from_group(

        self,

        policy_arn: str,

        group_name: str,

    ) -> bool:

        self.client.detach_group_policy(

            GroupName=group_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Detached %s from group %s",

            policy_arn,

            group_name,

        )

        return True
    
    #######################################################################
    # Search Policies
    #######################################################################

    def search_policies(

        self,

        keyword: str,

        scope: str = "Local",

    ) -> list[dict[str, Any]]:

        keyword = keyword.lower()

        return [

            policy

            for policy in self.list_policies(

                scope,

            )

            if keyword

            in policy.get(

                "PolicyName",

                "",

            ).lower()

        ]


    #######################################################################
    # Filter Policies By Path
    #######################################################################

    def filter_by_path(

        self,

        path: str,

        scope: str = "Local",

    ) -> list[dict[str, Any]]:

        return [

            policy

            for policy in self.list_policies(

                scope,

            )

            if policy.get(

                "Path",

            )

            == path

        ]


    #######################################################################
    # Export Policy
    #######################################################################

    def export_policy(

        self,

        policy_arn: str,

    ) -> dict[str, Any]:

        policy = self.get_policy(

            policy_arn,

        )

        if policy is None:

            return {}

        version = self.get_policy_version(

            policy_arn,

            policy["DefaultVersionId"],

        )

        return {

            "Policy": policy,

            "DefaultVersion": version,

            "Versions": self.list_policy_versions(

                policy_arn,

            ),

        }


    #######################################################################
    # Import Policy
    #######################################################################

    def import_policy(

        self,

        configuration: dict[str, Any],

    ) -> dict[str, Any]:

        policy = configuration["Policy"]

        version = configuration["DefaultVersion"]

        document = version["Document"]

        return self.create_policy(

            policy_name=policy["PolicyName"],

            policy_document=document,

            description=policy.get(

                "Description",

                "",

            ),

            path=policy.get(

                "Path",

                "/",

            ),

        )


    #######################################################################
    # Clone Policy
    #######################################################################

    def clone_policy(

        self,

        source_policy_arn: str,

        new_policy_name: str,

        description: str | None = None,

    ) -> dict[str, Any]:

        exported = self.export_policy(

            source_policy_arn,

        )

        if not exported:

            raise ValueError(

                "Source policy not found."

            )

        document = exported[

            "DefaultVersion"

        ][

            "Document"

        ]

        return self.create_policy(

            policy_name=new_policy_name,

            policy_document=document,

            description=description

            or exported["Policy"].get(

                "Description",

                "",

            ),

        )


    #######################################################################
    # Policy Summary
    #######################################################################

    def summary(

        self,

        policy_arn: str,

    ) -> dict[str, Any]:

        policy = self.get_policy(

            policy_arn,

        )

        if policy is None:

            return {}

        return {

            "PolicyName":

            policy.get(

                "PolicyName",

            ),

            "Arn":

            policy.get(

                "Arn",

            ),

            "Path":

            policy.get(

                "Path",

            ),

            "Description":

            policy.get(

                "Description",

            ),

            "DefaultVersion":

            policy.get(

                "DefaultVersionId",

            ),

            "AttachmentCount":

            policy.get(

                "AttachmentCount",

            ),

            "CreateDate":

            policy.get(

                "CreateDate",

            ),

            "UpdateDate":

            policy.get(

                "UpdateDate",

            ),

        }


    #######################################################################
    # Bulk Attach To Roles
    #######################################################################

    def bulk_attach_roles(

        self,

        policy_arn: str,

        roles: list[str],

    ) -> dict[str, bool]:

        results = {}

        for role in roles:

            try:

                self.attach_to_role(

                    policy_arn,

                    role,

                )

                results[role] = True

            except Exception:

                logger.exception(

                    "Failed attaching to %s",

                    role,

                )

                results[role] = False

        return results


    #######################################################################
    # Bulk Detach From Roles
    #######################################################################

    def bulk_detach_roles(

        self,

        policy_arn: str,

        roles: list[str],

    ) -> dict[str, bool]:

        results = {}

        for role in roles:

            try:

                self.detach_from_role(

                    policy_arn,

                    role,

                )

                results[role] = True

            except Exception:

                logger.exception(

                    "Failed detaching from %s",

                    role,

                )

                results[role] = False

        return results


    #######################################################################
    # Health
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        policies = self.list_policies()

        return {

            "healthy": True,

            "policy_count": len(

                policies,

            ),

            "policies": [

                policy["PolicyName"]

                for policy in policies

            ],

        }
        
    #######################################################################
    # Inventory
    #######################################################################

    def inventory(

        self,

    ) -> list[dict[str, Any]]:

        return [

            self.summary(

                policy["Arn"],

            )

            for policy in self.list_policies()

        ]


    #######################################################################
    # Metrics
    #######################################################################

    def metrics(

        self,

    ) -> dict[str, Any]:

        policies = self.list_policies()

        attached = sum(

            policy.get(

                "AttachmentCount",

                0,

            )

            for policy in policies

        )

        versions = sum(

            len(

                self.list_policy_versions(

                    policy["Arn"],

                )

            )

            for policy in policies

        )

        return {

            "total_policies":

            len(

                policies,

            ),

            "total_attachments":

            attached,

            "total_versions":

            versions,

        }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

    ) -> dict[str, Any]:

        return {

            "health":

            self.health(),

            "metrics":

            self.metrics(),

            "inventory":

            self.inventory(),

        }


    #######################################################################
    # Validate All Policies
    #######################################################################

    def validate_all(

        self,

    ) -> dict[str, bool]:

        results = {}

        for policy in self.list_policies():

            arn = policy["Arn"]

            try:

                version = self.get_policy_version(

                    arn,

                    policy["DefaultVersionId"],

                )

                self.validate_policy(

                    version["Document"],

                )

                results[arn] = True

            except Exception:

                logger.exception(

                    "Validation failed for %s",

                    arn,

                )

                results[arn] = False

        return results


    #######################################################################
    # Bulk Attach To Users
    #######################################################################

    def bulk_attach_users(

        self,

        policy_arn: str,

        users: list[str],

    ) -> dict[str, bool]:

        results = {}

        for user in users:

            try:

                self.attach_to_user(

                    policy_arn,

                    user,

                )

                results[user] = True

            except Exception:

                logger.exception(

                    "Failed attaching to user %s",

                    user,

                )

                results[user] = False

        return results


    #######################################################################
    # Bulk Attach To Groups
    #######################################################################

    def bulk_attach_groups(

        self,

        policy_arn: str,

        groups: list[str],

    ) -> dict[str, bool]:

        results = {}

        for group in groups:

            try:

                self.attach_to_group(

                    policy_arn,

                    group,

                )

                results[group] = True

            except Exception:

                logger.exception(

                    "Failed attaching to group %s",

                    group,

                )

                results[group] = False

        return results


    #######################################################################
    # Bulk Detach From Users
    #######################################################################

    def bulk_detach_users(

        self,

        policy_arn: str,

        users: list[str],

    ) -> dict[str, bool]:

        results = {}

        for user in users:

            try:

                self.detach_from_user(

                    policy_arn,

                    user,

                )

                results[user] = True

            except Exception:

                logger.exception(

                    "Failed detaching from user %s",

                    user,

                )

                results[user] = False

        return results


    #######################################################################
    # Bulk Detach From Groups
    #######################################################################

    def bulk_detach_groups(

        self,

        policy_arn: str,

        groups: list[str],

    ) -> dict[str, bool]:

        results = {}

        for group in groups:

            try:

                self.detach_from_group(

                    policy_arn,

                    group,

                )

                results[group] = True

            except Exception:

                logger.exception(

                    "Failed detaching from group %s",

                    group,

                )

                results[group] = False

        return results


    #######################################################################
    # Delete Non-default Policy Versions
    #######################################################################

    def cleanup_versions(

        self,

        policy_arn: str,

    ) -> int:

        deleted = 0

        default = self.get_default_version(

            policy_arn,

        )

        for version in self.list_policy_versions(

            policy_arn,

        ):

            if version["VersionId"] != default:

                self.delete_policy_version(

                    policy_arn,

                    version["VersionId"],

                )

                deleted += 1

        return deleted
    
    #######################################################################
    # Policy Report
    #######################################################################

    def report(

        self,

    ) -> dict[str, Any]:

        return {

            "summary":

            {

                "total":

                len(

                    self.list_policies(),

                ),

            },

            "health":

            self.health(),

            "metrics":

            self.metrics(),

            "validation":

            self.validate_all(),

        }


###########################################################################
# Policy Manager
###########################################################################

class PolicyManager:

    """
    High-level IAM Policy Manager.
    """

    def __init__(

        self,

    ):

        self.service = PolicyService()


    def policies(

        self,

    ) -> PolicyService:

        return self.service


    def health(

        self,

    ) -> dict[str, Any]:

        return self.service.health()


    def metrics(

        self,

    ) -> dict[str, Any]:

        return self.service.metrics()


    def diagnostics(

        self,

    ) -> dict[str, Any]:

        return self.service.diagnostics()


    def report(

        self,

    ) -> dict[str, Any]:

        return self.service.report()


###########################################################################
# Global Instances
###########################################################################

POLICY_SERVICE = PolicyService()

POLICY_MANAGER = PolicyManager()


###########################################################################
# Convenience Functions
###########################################################################

def policies(

) -> PolicyService:

    return POLICY_SERVICE


def health(

) -> dict[str, Any]:

    return POLICY_SERVICE.health()


def metrics(

) -> dict[str, Any]:

    return POLICY_SERVICE.metrics()


def diagnostics(

) -> dict[str, Any]:

    return POLICY_SERVICE.diagnostics()


def report(

) -> dict[str, Any]:

    return POLICY_SERVICE.report()


###########################################################################
# Self Test
###########################################################################

def self_test(

) -> dict[str, Any]:

    return {

        "module":

        "iam.policies",

        "status":

        "ready",

        "health":

        health(),

        "metrics":

        metrics(),

        "report":

        report(),

    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [

    "PolicyService",

    "PolicyManager",

    "POLICY_SERVICE",

    "POLICY_MANAGER",

    "policies",

    "health",

    "metrics",

    "diagnostics",

    "report",

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

    print("IAM Policy Service")

    print("=" * 80)

    print()

    print("Health")

    print(

        health(),

    )

    print()

    print("Metrics")

    print(

        metrics(),

    )

    print()

    print("Diagnostics")

    print(

        diagnostics(),

    )

    print()

    print("Report")

    print(

        report(),

    )

    print()

    print("Self Test")

    print(

        self_test(),

    )

    print()

    print("IAM Policy Service Ready")