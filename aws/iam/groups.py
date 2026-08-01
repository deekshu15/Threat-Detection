"""
groups.py

Enterprise IAM Group Management

Responsibilities
----------------
• Create IAM groups
• Delete IAM groups
• Update IAM groups
• Manage group membership
• Attach/detach policies
• Diagnostics
"""

from __future__ import annotations

import logging

import json

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
# Group Service
###########################################################################

class GroupService:

    """
    High-level IAM Group Management.
    """

    def __init__(

        self,

    ):

        self.client = iam()


    #######################################################################
    # Create Group
    #######################################################################

    def create_group(

        self,

        group_name: str,

        path: str = "/",

    ) -> dict[str, Any]:

        response = self.client.create_group(

            GroupName=group_name,

            Path=path,

        )

        logger.info(

            "Created IAM group %s",

            group_name,

        )

        return response["Group"]


    #######################################################################
    # Delete Group
    #######################################################################

    def delete_group(

        self,

        group_name: str,

    ) -> bool:

        self.client.delete_group(

            GroupName=group_name,

        )

        logger.info(

            "Deleted IAM group %s",

            group_name,

        )

        return True


    #######################################################################
    # Get Group
    #######################################################################

    def get_group(

        self,

        group_name: str,

    ) -> dict[str, Any] | None:

        try:

            response = self.client.get_group(

                GroupName=group_name,

            )

            return {

                "Group":

                response["Group"],

                "Users":

                response.get(

                    "Users",

                    [],

                ),

            }

        except ClientError:

            return None


    #######################################################################
    # Group Exists
    #######################################################################

    def group_exists(

        self,

        group_name: str,

    ) -> bool:

        return self.get_group(

            group_name,

        ) is not None


    #######################################################################
    # List Groups
    #######################################################################

    def list_groups(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_groups",

        )

        groups = []

        for page in paginator.paginate():

            groups.extend(

                page.get(

                    "Groups",

                    [],

                )

            )

        return groups


    #######################################################################
    # List Group Names
    #######################################################################

    def list_group_names(

        self,

    ) -> list[str]:

        return [

            group["GroupName"]

            for group in self.list_groups()

        ]


    #######################################################################
    # Update Group
    #######################################################################

    def update_group(

        self,

        group_name: str,

        new_group_name: str | None = None,

        new_path: str | None = None,

    ) -> bool:

        request = {

            "GroupName":

            group_name,

        }

        if new_group_name:

            request["NewGroupName"] = new_group_name

        if new_path:

            request["NewPath"] = new_path

        self.client.update_group(

            **request,

        )

        logger.info(

            "Updated IAM group %s",

            group_name,

        )

        return True


    #######################################################################
    # Validate Group Name
    #######################################################################

    def validate_group_name(

        self,

        group_name: str,

    ) -> bool:

        if not group_name:

            raise ValueError(

                "Group name cannot be empty."

            )

        if len(

            group_name,

        ) > 128:

            raise ValueError(

                "Group name exceeds AWS limit."

            )

        return True


    #######################################################################
    # Group Summary
    #######################################################################

    def summary(

        self,

        group_name: str,

    ) -> dict[str, Any]:

        group = self.get_group(

            group_name,

        )

        if group is None:

            return {}

        info = group["Group"]

        return {

            "GroupName":

            info.get(

                "GroupName",

            ),

            "Arn":

            info.get(

                "Arn",

            ),

            "Path":

            info.get(

                "Path",

            ),

            "GroupId":

            info.get(

                "GroupId",

            ),

            "CreateDate":

            info.get(

                "CreateDate",

            ),

            "Users":

            len(

                group["Users"],

            ),

        }
        
    #######################################################################
    # Add User To Group
    #######################################################################

    def add_user(

        self,

        group_name: str,

        user_name: str,

    ) -> bool:

        self.client.add_user_to_group(

            GroupName=group_name,

            UserName=user_name,

        )

        logger.info(

            "Added %s to group %s",

            user_name,

            group_name,

        )

        return True


    #######################################################################
    # Remove User From Group
    #######################################################################

    def remove_user(

        self,

        group_name: str,

        user_name: str,

    ) -> bool:

        self.client.remove_user_from_group(

            GroupName=group_name,

            UserName=user_name,

        )

        logger.info(

            "Removed %s from group %s",

            user_name,

            group_name,

        )

        return True


    #######################################################################
    # List Users In Group
    #######################################################################

    def list_users(

        self,

        group_name: str,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "get_group",

        )

        users = []

        for page in paginator.paginate(

            GroupName=group_name,

        ):

            users.extend(

                page.get(

                    "Users",

                    [],

                )

            )

        return users


    #######################################################################
    # Attach Managed Policy
    #######################################################################

    def attach_policy(

        self,

        group_name: str,

        policy_arn: str,

    ) -> bool:

        self.client.attach_group_policy(

            GroupName=group_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Attached policy %s to group %s",

            policy_arn,

            group_name,

        )

        return True


    #######################################################################
    # Detach Managed Policy
    #######################################################################

    def detach_policy(

        self,

        group_name: str,

        policy_arn: str,

    ) -> bool:

        self.client.detach_group_policy(

            GroupName=group_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Detached policy %s from group %s",

            policy_arn,

            group_name,

        )

        return True


    #######################################################################
    # List Attached Policies
    #######################################################################

    def list_attached_policies(

        self,

        group_name: str,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_attached_group_policies",

        )

        policies = []

        for page in paginator.paginate(

            GroupName=group_name,

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

        group_name: str,

    ) -> list[str]:

        return [

            policy["PolicyArn"]

            for policy in self.list_attached_policies(

                group_name,

            )

        ]


    #######################################################################
    # Put Inline Policy
    #######################################################################

    def put_inline_policy(

        self,

        group_name: str,

        policy_name: str,

        policy_document: dict[str, Any],

    ) -> bool:

        self.client.put_group_policy(

            GroupName=group_name,

            PolicyName=policy_name,

            PolicyDocument=json.dumps(

                policy_document,

            ),

        )

        logger.info(

            "Created inline policy %s for %s",

            policy_name,

            group_name,

        )

        return True


    #######################################################################
    # Delete Inline Policy
    #######################################################################

    def delete_inline_policy(

        self,

        group_name: str,

        policy_name: str,

    ) -> bool:

        self.client.delete_group_policy(

            GroupName=group_name,

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

        group_name: str,

    ) -> list[str]:

        response = self.client.list_group_policies(

            GroupName=group_name,

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

        group_name: str,

        policy_name: str,

    ) -> dict[str, Any] | None:

        try:

            response = self.client.get_group_policy(

                GroupName=group_name,

                PolicyName=policy_name,

            )

            return response

        except ClientError:

            return None


    #######################################################################
    # Search Groups
    #######################################################################

    def search_groups(

        self,

        keyword: str,

    ) -> list[dict[str, Any]]:

        keyword = keyword.lower()

        return [

            group

            for group in self.list_groups()

            if keyword

            in group.get(

                "GroupName",

                "",

            ).lower()

        ]


    #######################################################################
    # Filter Groups By Path
    #######################################################################

    def filter_by_path(

        self,

        path: str,

    ) -> list[dict[str, Any]]:

        return [

            group

            for group in self.list_groups()

            if group.get(

                "Path",

            )

            == path

        ]


    #######################################################################
    # Group Inventory
    #######################################################################

    def inventory(

        self,

    ) -> list[dict[str, Any]]:

        return [

            self.summary(

                group["GroupName"],

            )

            for group in self.list_groups()

        ]


    #######################################################################
    # Group Metrics
    #######################################################################

    def metrics(

        self,

    ) -> dict[str, Any]:

        groups = self.list_groups()

        total_users = sum(

            len(

                self.list_users(

                    group["GroupName"],

                )

            )

            for group in groups

        )

        total_policies = sum(

            len(

                self.list_attached_policies(

                    group["GroupName"],

                )

            )

            for group in groups

        )

        return {

            "total_groups":

            len(

                groups,

            ),

            "total_users":

            total_users,

            "attached_policies":

            total_policies,

        }


    #######################################################################
    # Group Health
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        groups = self.list_groups()

        return {

            "healthy":

            True,

            "group_count":

            len(

                groups,

            ),

            "groups":

            [

                group["GroupName"]

                for group in groups

            ],

        }


    #######################################################################
    # Bulk Add Users
    #######################################################################

    def bulk_add_users(

        self,

        group_name: str,

        users: list[str],

    ) -> dict[str, bool]:

        results = {}

        for user in users:

            try:

                self.add_user(

                    group_name,

                    user,

                )

                results[user] = True

            except Exception:

                logger.exception(

                    "Failed adding %s",

                    user,

                )

                results[user] = False

        return results


    #######################################################################
    # Bulk Remove Users
    #######################################################################

    def bulk_remove_users(

        self,

        group_name: str,

        users: list[str],

    ) -> dict[str, bool]:

        results = {}

        for user in users:

            try:

                self.remove_user(

                    group_name,

                    user,

                )

                results[user] = True

            except Exception:

                logger.exception(

                    "Failed removing %s",

                    user,

                )

                results[user] = False

        return results


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
        
###########################################################################
# Group Manager
###########################################################################

class GroupManager:

    """
    High-level IAM Group Manager.
    """

    def __init__(

        self,

    ):

        self.service = GroupService()


    def groups(

        self,

    ) -> GroupService:

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

GROUP_SERVICE = GroupService()

GROUP_MANAGER = GroupManager()


###########################################################################
# Convenience Functions
###########################################################################

def groups(

) -> GroupService:

    return GROUP_SERVICE


def health(

) -> dict[str, Any]:

    return GROUP_SERVICE.health()


def metrics(

) -> dict[str, Any]:

    return GROUP_SERVICE.metrics()


def diagnostics(

) -> dict[str, Any]:

    return GROUP_SERVICE.diagnostics()


###########################################################################
# Self Test
###########################################################################

def self_test(

) -> dict[str, Any]:

    return {

        "module":

        "iam.groups",

        "status":

        "ready",

        "health":

        health(),

        "metrics":

        metrics(),

        "diagnostics":

        diagnostics(),

    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [

    "GroupService",

    "GroupManager",

    "GROUP_SERVICE",

    "GROUP_MANAGER",

    "groups",

    "health",

    "metrics",

    "diagnostics",

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

    print("IAM Group Service")

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

    print("IAM Group Service Ready")