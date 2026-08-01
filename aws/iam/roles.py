"""
roles.py

Enterprise IAM Role Management

Responsibilities
----------------
• Create IAM roles
• Delete IAM roles
• Update trust policies
• Attach managed policies
• Detach managed policies
• List roles
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
# IAM Role Service
###########################################################################

class RoleService:

    """
    High-level IAM Role Management.
    """

    def __init__(

        self,

    ):

        self.client = iam()


    #######################################################################
    # Create Role
    #######################################################################

    def create_role(

        self,

        role_name: str,

        trust_policy: dict[str, Any],

        description: str = "",

        path: str = "/",

        max_session_duration: int = 3600,

    ) -> dict[str, Any]:

        response = self.client.create_role(

            RoleName=role_name,

            AssumeRolePolicyDocument=json.dumps(

                trust_policy,

            ),

            Description=description,

            Path=path,

            MaxSessionDuration=max_session_duration,

        )

        logger.info(

            "Created IAM role %s",

            role_name,

        )

        return response["Role"]


    #######################################################################
    # Delete Role
    #######################################################################

    def delete_role(

        self,

        role_name: str,

    ) -> bool:

        self.client.delete_role(

            RoleName=role_name,

        )

        logger.info(

            "Deleted IAM role %s",

            role_name,

        )

        return True


    #######################################################################
    # Get Role
    #######################################################################

    def get_role(

        self,

        role_name: str,

    ) -> dict[str, Any] | None:

        try:

            response = self.client.get_role(

                RoleName=role_name,

            )

            return response["Role"]

        except ClientError:

            return None


    #######################################################################
    # Role Exists
    #######################################################################

    def role_exists(

        self,

        role_name: str,

    ) -> bool:

        return self.get_role(

            role_name,

        ) is not None


    #######################################################################
    # List Roles
    #######################################################################

    def list_roles(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_roles",

        )

        roles = []

        for page in paginator.paginate():

            roles.extend(

                page.get(

                    "Roles",

                    [],

                )

            )

        return roles


    #######################################################################
    # List Role Names
    #######################################################################

    def list_role_names(

        self,

    ) -> list[str]:

        return [

            role["RoleName"]

            for role in self.list_roles()

        ]


    #######################################################################
    # Update Trust Policy
    #######################################################################

    def update_trust_policy(

        self,

        role_name: str,

        trust_policy: dict[str, Any],

    ) -> bool:

        self.client.update_assume_role_policy(

            RoleName=role_name,

            PolicyDocument=json.dumps(

                trust_policy,

            ),

        )

        logger.info(

            "Updated trust policy for %s",

            role_name,

        )

        return True


    #######################################################################
    # Get Trust Policy
    #######################################################################

    def get_trust_policy(

        self,

        role_name: str,

    ) -> dict[str, Any] | None:

        role = self.get_role(

            role_name,

        )

        if role is None:

            return None

        return role.get(

            "AssumeRolePolicyDocument",

        )
        
    #######################################################################
    # Attach Managed Policy
    #######################################################################

    def attach_policy(

        self,

        role_name: str,

        policy_arn: str,

    ) -> bool:

        self.client.attach_role_policy(

            RoleName=role_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Attached policy %s to role %s",

            policy_arn,

            role_name,

        )

        return True


    #######################################################################
    # Detach Managed Policy
    #######################################################################

    def detach_policy(

        self,

        role_name: str,

        policy_arn: str,

    ) -> bool:

        self.client.detach_role_policy(

            RoleName=role_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Detached policy %s from role %s",

            policy_arn,

            role_name,

        )

        return True


    #######################################################################
    # List Attached Policies
    #######################################################################

    def list_attached_policies(

        self,

        role_name: str,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_attached_role_policies",

        )

        policies = []

        for page in paginator.paginate(

            RoleName=role_name,

        ):

            policies.extend(

                page.get(

                    "AttachedPolicies",

                    [],

                )

            )

        return policies


    #######################################################################
    # List Attached Policy ARNs
    #######################################################################

    def list_policy_arns(

        self,

        role_name: str,

    ) -> list[str]:

        return [

            policy["PolicyArn"]

            for policy in self.list_attached_policies(

                role_name,

            )

        ]


    #######################################################################
    # Put Inline Policy
    #######################################################################

    def put_inline_policy(

        self,

        role_name: str,

        policy_name: str,

        policy_document: dict[str, Any],

    ) -> bool:

        self.client.put_role_policy(

            RoleName=role_name,

            PolicyName=policy_name,

            PolicyDocument=json.dumps(

                policy_document,

            ),

        )

        logger.info(

            "Created inline policy %s for %s",

            policy_name,

            role_name,

        )

        return True


    #######################################################################
    # Delete Inline Policy
    #######################################################################

    def delete_inline_policy(

        self,

        role_name: str,

        policy_name: str,

    ) -> bool:

        self.client.delete_role_policy(

            RoleName=role_name,

            PolicyName=policy_name,

        )

        logger.info(

            "Deleted inline policy %s",

            policy_name,

        )

        return True


    #######################################################################
    # List Inline Policies
    #######################################################################

    def list_inline_policies(

        self,

        role_name: str,

    ) -> list[str]:

        response = self.client.list_role_policies(

            RoleName=role_name,

        )

        return response.get(

            "PolicyNames",

            [],

        )


    #######################################################################
    # Get Inline Policy
    #######################################################################

    def get_inline_policy(

        self,

        role_name: str,

        policy_name: str,

    ) -> dict[str, Any] | None:

        try:

            response = self.client.get_role_policy(

                RoleName=role_name,

                PolicyName=policy_name,

            )

            return response

        except ClientError:

            return None


    #######################################################################
    # Update Role Description
    #######################################################################

    def update_description(

        self,

        role_name: str,

        description: str,

    ) -> bool:

        self.client.update_role_description(

            RoleName=role_name,

            Description=description,

        )

        logger.info(

            "Updated description for %s",

            role_name,

        )

        return True
    
    #######################################################################
    # Update Maximum Session Duration
    #######################################################################

    def update_session_duration(

        self,

        role_name: str,

        duration: int,

    ) -> bool:

        self.client.update_role(

            RoleName=role_name,

            MaxSessionDuration=duration,

        )

        logger.info(

            "Updated session duration for %s",

            role_name,

        )

        return True


    #######################################################################
    # Tag Role
    #######################################################################

    def tag_role(

        self,

        role_name: str,

        tags: dict[str, str],

    ) -> bool:

        self.client.tag_role(

            RoleName=role_name,

            Tags=[

                {

                    "Key": key,

                    "Value": value,

                }

                for key, value in tags.items()

            ],

        )

        logger.info(

            "Tagged role %s",

            role_name,

        )

        return True


    #######################################################################
    # Remove Tags
    #######################################################################

    def untag_role(

        self,

        role_name: str,

        tag_keys: list[str],

    ) -> bool:

        self.client.untag_role(

            RoleName=role_name,

            TagKeys=tag_keys,

        )

        logger.info(

            "Removed tags from %s",

            role_name,

        )

        return True


    #######################################################################
    # List Tags
    #######################################################################

    def list_tags(

        self,

        role_name: str,

    ) -> list[dict[str, Any]]:

        response = self.client.list_role_tags(

            RoleName=role_name,

        )

        return response.get(

            "Tags",

            [],

        )


    #######################################################################
    # Get Role ARN
    #######################################################################

    def role_arn(

        self,

        role_name: str,

    ) -> str | None:

        role = self.get_role(

            role_name,

        )

        if role is None:

            return None

        return role.get(

            "Arn",

        )


    #######################################################################
    # Get Creation Date
    #######################################################################

    def creation_date(

        self,

        role_name: str,

    ) -> Any:

        role = self.get_role(

            role_name,

        )

        if role is None:

            return None

        return role.get(

            "CreateDate",

        )


    #######################################################################
    # Get Last Used Information
    #######################################################################

    def last_used(

        self,

        role_name: str,

    ) -> dict[str, Any]:

        role = self.get_role(

            role_name,

        )

        if role is None:

            return {}

        return role.get(

            "RoleLastUsed",

            {},

        )


    #######################################################################
    # Validate Role Name
    #######################################################################

    def validate_role_name(

        self,

        role_name: str,

    ) -> bool:

        if not role_name:

            raise ValueError(

                "Role name cannot be empty."

            )

        if len(

            role_name,

        ) > 64:

            raise ValueError(

                "Role name exceeds AWS limit (64 characters)."

            )

        return True


    #######################################################################
    # Role Summary
    #######################################################################

    def summary(

        self,

        role_name: str,

    ) -> dict[str, Any]:

        role = self.get_role(

            role_name,

        )

        if role is None:

            return {}

        return {

            "RoleName":

            role.get(

                "RoleName",

            ),

            "Arn":

            role.get(

                "Arn",

            ),

            "CreateDate":

            role.get(

                "CreateDate",

            ),

            "Description":

            role.get(

                "Description",

            ),

            "MaxSessionDuration":

            role.get(

                "MaxSessionDuration",

            ),

            "AttachedPolicies":

            len(

                self.list_attached_policies(

                    role_name,

                )

            ),

            "InlinePolicies":

            len(

                self.list_inline_policies(

                    role_name,

                )

            ),

            "Tags":

            len(

                self.list_tags(

                    role_name,

                )

            ),

        }
        
    #######################################################################
    # Clone Role
    #######################################################################

    def clone_role(

        self,

        source_role: str,

        target_role: str,

        description: str | None = None,

    ) -> dict[str, Any]:

        source = self.get_role(

            source_role,

        )

        if source is None:

            raise ValueError(

                f"Role '{source_role}' does not exist."

            )

        trust_policy = source.get(

            "AssumeRolePolicyDocument",

        )

        new_role = self.create_role(

            role_name=target_role,

            trust_policy=trust_policy,

            description=description

            or source.get(

                "Description",

                "",

            ),

            path=source.get(

                "Path",

                "/",

            ),

            max_session_duration=source.get(

                "MaxSessionDuration",

                3600,

            ),

        )

        for policy in self.list_attached_policies(

            source_role,

        ):

            self.attach_policy(

                target_role,

                policy["PolicyArn"],

            )

        return new_role


    #######################################################################
    # Export Role
    #######################################################################

    def export_role(

        self,

        role_name: str,

    ) -> dict[str, Any]:

        role = self.get_role(

            role_name,

        )

        if role is None:

            return {}

        return {

            "Role": role,

            "TrustPolicy": self.get_trust_policy(

                role_name,

            ),

            "AttachedPolicies": self.list_attached_policies(

                role_name,

            ),

            "InlinePolicies": self.list_inline_policies(

                role_name,

            ),

            "Tags": self.list_tags(

                role_name,

            ),

        }


    #######################################################################
    # Import Role
    #######################################################################

    def import_role(

        self,

        configuration: dict[str, Any],

    ) -> dict[str, Any]:

        role = configuration["Role"]

        created = self.create_role(

            role_name=role["RoleName"],

            trust_policy=configuration["TrustPolicy"],

            description=role.get(

                "Description",

                "",

            ),

            path=role.get(

                "Path",

                "/",

            ),

            max_session_duration=role.get(

                "MaxSessionDuration",

                3600,

            ),

        )

        for policy in configuration.get(

            "AttachedPolicies",

            [],

        ):

            self.attach_policy(

                role["RoleName"],

                policy["PolicyArn"],

            )

        return created


    #######################################################################
    # Search Roles
    #######################################################################

    def search_roles(

        self,

        keyword: str,

    ) -> list[dict[str, Any]]:

        keyword = keyword.lower()

        return [

            role

            for role in self.list_roles()

            if keyword

            in role.get(

                "RoleName",

                "",

            ).lower()

        ]


    #######################################################################
    # Filter By Path
    #######################################################################

    def filter_by_path(

        self,

        path: str,

    ) -> list[dict[str, Any]]:

        return [

            role

            for role in self.list_roles()

            if role.get(

                "Path",

            )

            == path

        ]


    #######################################################################
    # Bulk Attach Policy
    #######################################################################

    def bulk_attach_policy(

        self,

        roles: list[str],

        policy_arn: str,

    ) -> dict[str, bool]:

        results = {}

        for role in roles:

            try:

                self.attach_policy(

                    role,

                    policy_arn,

                )

                results[role] = True

            except Exception:

                logger.exception(

                    "Failed attaching policy to %s",

                    role,

                )

                results[role] = False

        return results


    #######################################################################
    # Bulk Detach Policy
    #######################################################################

    def bulk_detach_policy(

        self,

        roles: list[str],

        policy_arn: str,

    ) -> dict[str, bool]:

        results = {}

        for role in roles:

            try:

                self.detach_policy(

                    role,

                    policy_arn,

                )

                results[role] = True

            except Exception:

                logger.exception(

                    "Failed detaching policy from %s",

                    role,

                )

                results[role] = False

        return results


    #######################################################################
    # Health Check
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        roles = self.list_roles()

        return {

            "healthy": True,

            "role_count": len(

                roles,

            ),

            "roles": [

                role["RoleName"]

                for role in roles

            ],

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

            "inventory":

            self.inventory(),

            "metrics":

            self.metrics(),

        }


    #######################################################################
    # Metrics
    #######################################################################

    def metrics(

        self,

    ) -> dict[str, Any]:

        roles = self.list_roles()

        return {

            "total_roles":

            len(

                roles,

            ),

            "roles_with_tags":

            sum(

                1

                for role in roles

                if role.get(

                    "Tags",

                )

            ),

            "service_roles":

            sum(

                1

                for role in roles

                if role.get(

                    "Path",

                    "",

                ).startswith(

                    "/service-role/"

                )

            ),

        }


    #######################################################################
    # Inventory
    #######################################################################

    def inventory(

        self,

    ) -> list[dict[str, Any]]:

        return [

            self.summary(

                role["RoleName"],

            )

            for role in self.list_roles()

        ]


###########################################################################
# Role Manager
###########################################################################

class RoleManager:

    """
    High-level IAM Role Manager.
    """

    def __init__(

        self,

    ):

        self.service = RoleService()


    def roles(

        self,

    ) -> RoleService:

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


###########################################################################
# Global Instances
###########################################################################

ROLE_SERVICE = RoleService()

ROLE_MANAGER = RoleManager()


###########################################################################
# Convenience Functions
###########################################################################

def roles(

) -> RoleService:

    return ROLE_SERVICE


def diagnostics(

) -> dict[str, Any]:

    return ROLE_SERVICE.diagnostics()


def metrics(

) -> dict[str, Any]:

    return ROLE_SERVICE.metrics()


def health(

) -> dict[str, Any]:

    return ROLE_SERVICE.health()


###########################################################################
# Self Test
###########################################################################

def self_test(

) -> dict[str, Any]:

    return {

        "module":

        "iam.roles",

        "status":

        "ready",

        "health":

        health(),

        "metrics":

        metrics(),

    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [

    "RoleService",

    "RoleManager",

    "ROLE_SERVICE",

    "ROLE_MANAGER",

    "roles",

    "diagnostics",

    "metrics",

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

    print("IAM Role Service")

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

    print("Self Test")

    print(

        self_test(),

    )

    print()

    print("IAM Role Service Ready")