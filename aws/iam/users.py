"""
users.py

Enterprise IAM User Management

Responsibilities
----------------
• Create IAM users
• Delete IAM users
• Update IAM users
• Login profiles
• Access keys
• MFA helpers
• Group membership
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
# User Service
###########################################################################

class UserService:

    """
    High-level IAM User Management.
    """

    def __init__(

        self,

    ):

        self.client = iam()


    #######################################################################
    # Create User
    #######################################################################

    def create_user(

        self,

        user_name: str,

        path: str = "/",

        tags: dict[str, str] | None = None,

    ) -> dict[str, Any]:

        request = {

            "UserName": user_name,

            "Path": path,

        }

        if tags:

            request["Tags"] = [

                {

                    "Key": key,

                    "Value": value,

                }

                for key, value in tags.items()

            ]

        response = self.client.create_user(

            **request,

        )

        logger.info(

            "Created IAM user %s",

            user_name,

        )

        return response["User"]


    #######################################################################
    # Delete User
    #######################################################################

    def delete_user(

        self,

        user_name: str,

    ) -> bool:

        self.client.delete_user(

            UserName=user_name,

        )

        logger.info(

            "Deleted IAM user %s",

            user_name,

        )

        return True


    #######################################################################
    # Get User
    #######################################################################

    def get_user(

        self,

        user_name: str,

    ) -> dict[str, Any] | None:

        try:

            response = self.client.get_user(

                UserName=user_name,

            )

            return response["User"]

        except ClientError:

            return None


    #######################################################################
    # User Exists
    #######################################################################

    def user_exists(

        self,

        user_name: str,

    ) -> bool:

        return self.get_user(

            user_name,

        ) is not None


    #######################################################################
    # List Users
    #######################################################################

    def list_users(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_users",

        )

        users = []

        for page in paginator.paginate():

            users.extend(

                page.get(

                    "Users",

                    [],

                )

            )

        return users


    #######################################################################
    # List User Names
    #######################################################################

    def list_user_names(

        self,

    ) -> list[str]:

        return [

            user["UserName"]

            for user in self.list_users()

        ]


    #######################################################################
    # Update User
    #######################################################################

    def update_user(

        self,

        user_name: str,

        new_user_name: str | None = None,

        new_path: str | None = None,

    ) -> bool:

        request = {

            "UserName": user_name,

        }

        if new_user_name:

            request["NewUserName"] = new_user_name

        if new_path:

            request["NewPath"] = new_path

        self.client.update_user(

            **request,

        )

        logger.info(

            "Updated IAM user %s",

            user_name,

        )

        return True


    #######################################################################
    # Validate User Name
    #######################################################################

    def validate_user_name(

        self,

        user_name: str,

    ) -> bool:

        if not user_name:

            raise ValueError(

                "User name cannot be empty."

            )

        if len(

            user_name,

        ) > 64:

            raise ValueError(

                "User name exceeds AWS limit (64 characters)."

            )

        return True


    #######################################################################
    # User Summary
    #######################################################################

    def summary(

        self,

        user_name: str,

    ) -> dict[str, Any]:

        user = self.get_user(

            user_name,

        )

        if user is None:

            return {}

        return {

            "UserName":

            user.get(

                "UserName",

            ),

            "Arn":

            user.get(

                "Arn",

            ),

            "Path":

            user.get(

                "Path",

            ),

            "UserId":

            user.get(

                "UserId",

            ),

            "CreateDate":

            user.get(

                "CreateDate",

            ),

        }
        
    #######################################################################
    # Create Login Profile
    #######################################################################

    def create_login_profile(

        self,

        user_name: str,

        password: str,

        password_reset_required: bool = True,

    ) -> dict[str, Any]:

        response = self.client.create_login_profile(

            UserName=user_name,

            Password=password,

            PasswordResetRequired=password_reset_required,

        )

        logger.info(

            "Created login profile for %s",

            user_name,

        )

        return response["LoginProfile"]


    #######################################################################
    # Update Login Profile
    #######################################################################

    def update_login_profile(

        self,

        user_name: str,

        password: str,

        password_reset_required: bool = True,

    ) -> bool:

        self.client.update_login_profile(

            UserName=user_name,

            Password=password,

            PasswordResetRequired=password_reset_required,

        )

        logger.info(

            "Updated login profile for %s",

            user_name,

        )

        return True


    #######################################################################
    # Delete Login Profile
    #######################################################################

    def delete_login_profile(

        self,

        user_name: str,

    ) -> bool:

        self.client.delete_login_profile(

            UserName=user_name,

        )

        logger.info(

            "Deleted login profile for %s",

            user_name,

        )

        return True


    #######################################################################
    # Get Login Profile
    #######################################################################

    def get_login_profile(

        self,

        user_name: str,

    ) -> dict[str, Any] | None:

        try:

            response = self.client.get_login_profile(

                UserName=user_name,

            )

            return response["LoginProfile"]

        except ClientError:

            return None


    #######################################################################
    # Create Access Key
    #######################################################################

    def create_access_key(

        self,

        user_name: str,

    ) -> dict[str, Any]:

        response = self.client.create_access_key(

            UserName=user_name,

        )

        logger.info(

            "Created access key for %s",

            user_name,

        )

        return response["AccessKey"]


    #######################################################################
    # List Access Keys
    #######################################################################

    def list_access_keys(

        self,

        user_name: str,

    ) -> list[dict[str, Any]]:

        response = self.client.list_access_keys(

            UserName=user_name,

        )

        return response.get(

            "AccessKeyMetadata",

            [],

        )


    #######################################################################
    # Delete Access Key
    #######################################################################

    def delete_access_key(

        self,

        user_name: str,

        access_key_id: str,

    ) -> bool:

        self.client.delete_access_key(

            UserName=user_name,

            AccessKeyId=access_key_id,

        )

        logger.info(

            "Deleted access key %s",

            access_key_id,

        )

        return True


    #######################################################################
    # Update Access Key Status
    #######################################################################

    def update_access_key_status(

        self,

        user_name: str,

        access_key_id: str,

        status: str,

    ) -> bool:

        self.client.update_access_key(

            UserName=user_name,

            AccessKeyId=access_key_id,

            Status=status,

        )

        logger.info(

            "Updated access key %s to %s",

            access_key_id,

            status,

        )

        return True


    #######################################################################
    # Disable Access Key
    #######################################################################

    def disable_access_key(

        self,

        user_name: str,

        access_key_id: str,

    ) -> bool:

        return self.update_access_key_status(

            user_name,

            access_key_id,

            "Inactive",

        )


    #######################################################################
    # Enable Access Key
    #######################################################################

    def enable_access_key(

        self,

        user_name: str,

        access_key_id: str,

    ) -> bool:

        return self.update_access_key_status(

            user_name,

            access_key_id,

            "Active",

        )
        
    #######################################################################
    # Rotate Access Key
    #######################################################################

    def rotate_access_key(

        self,

        user_name: str,

        old_access_key_id: str,

    ) -> dict[str, Any]:

        new_key = self.create_access_key(

            user_name,

        )

        self.delete_access_key(

            user_name,

            old_access_key_id,

        )

        logger.info(

            "Rotated access key for %s",

            user_name,

        )

        return new_key


    #######################################################################
    # Tag User
    #######################################################################

    def tag_user(

        self,

        user_name: str,

        tags: dict[str, str],

    ) -> bool:

        self.client.tag_user(

            UserName=user_name,

            Tags=[

                {

                    "Key": key,

                    "Value": value,

                }

                for key, value in tags.items()

            ],

        )

        logger.info(

            "Tagged user %s",

            user_name,

        )

        return True


    #######################################################################
    # Remove User Tags
    #######################################################################

    def untag_user(

        self,

        user_name: str,

        tag_keys: list[str],

    ) -> bool:

        self.client.untag_user(

            UserName=user_name,

            TagKeys=tag_keys,

        )

        logger.info(

            "Removed tags from %s",

            user_name,

        )

        return True


    #######################################################################
    # List User Tags
    #######################################################################

    def list_tags(

        self,

        user_name: str,

    ) -> list[dict[str, Any]]:

        response = self.client.list_user_tags(

            UserName=user_name,

        )

        return response.get(

            "Tags",

            [],

        )


    #######################################################################
    # Add User To Group
    #######################################################################

    def add_to_group(

        self,

        user_name: str,

        group_name: str,

    ) -> bool:

        self.client.add_user_to_group(

            UserName=user_name,

            GroupName=group_name,

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

    def remove_from_group(

        self,

        user_name: str,

        group_name: str,

    ) -> bool:

        self.client.remove_user_from_group(

            UserName=user_name,

            GroupName=group_name,

        )

        logger.info(

            "Removed %s from group %s",

            user_name,

            group_name,

        )

        return True


    #######################################################################
    # List Groups For User
    #######################################################################

    def list_groups(

        self,

        user_name: str,

    ) -> list[dict[str, Any]]:

        response = self.client.list_groups_for_user(

            UserName=user_name,

        )

        return response.get(

            "Groups",

            [],

        )


    #######################################################################
    # List Attached User Policies
    #######################################################################

    def list_attached_policies(

        self,

        user_name: str,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_attached_user_policies",

        )

        policies = []

        for page in paginator.paginate(

            UserName=user_name,

        ):

            policies.extend(

                page.get(

                    "AttachedPolicies",

                    [],

                )

            )

        return policies


    #######################################################################
    # List Inline User Policies
    #######################################################################

    def list_inline_policies(

        self,

        user_name: str,

    ) -> list[str]:

        response = self.client.list_user_policies(

            UserName=user_name,

        )

        return response.get(

            "PolicyNames",

            [],

        )


    #######################################################################
    # Get User ARN
    #######################################################################

    def user_arn(

        self,

        user_name: str,

    ) -> str | None:

        user = self.get_user(

            user_name,

        )

        if user is None:

            return None

        return user.get(

            "Arn",

        )
        
    #######################################################################
    # Attach Managed Policy
    #######################################################################

    def attach_policy(

        self,

        user_name: str,

        policy_arn: str,

    ) -> bool:

        self.client.attach_user_policy(

            UserName=user_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Attached policy %s to user %s",

            policy_arn,

            user_name,

        )

        return True


    #######################################################################
    # Detach Managed Policy
    #######################################################################

    def detach_policy(

        self,

        user_name: str,

        policy_arn: str,

    ) -> bool:

        self.client.detach_user_policy(

            UserName=user_name,

            PolicyArn=policy_arn,

        )

        logger.info(

            "Detached policy %s from user %s",

            policy_arn,

            user_name,

        )

        return True


    #######################################################################
    # Put Inline Policy
    #######################################################################

    def put_inline_policy(

        self,

        user_name: str,

        policy_name: str,

        policy_document: dict[str, Any],

    ) -> bool:

        self.client.put_user_policy(

            UserName=user_name,

            PolicyName=policy_name,

            PolicyDocument=json.dumps(

                policy_document,

            ),

        )

        logger.info(

            "Created inline policy %s for %s",

            policy_name,

            user_name,

        )

        return True


    #######################################################################
    # Delete Inline Policy
    #######################################################################

    def delete_inline_policy(

        self,

        user_name: str,

        policy_name: str,

    ) -> bool:

        self.client.delete_user_policy(

            UserName=user_name,

            PolicyName=policy_name,

        )

        logger.info(

            "Deleted inline policy %s",

            policy_name,

        )

        return True


    #######################################################################
    # Get Inline Policy
    #######################################################################

    def get_inline_policy(

        self,

        user_name: str,

        policy_name: str,

    ) -> dict[str, Any] | None:

        try:

            response = self.client.get_user_policy(

                UserName=user_name,

                PolicyName=policy_name,

            )

            return response

        except ClientError:

            return None


    #######################################################################
    # List MFA Devices
    #######################################################################

    def list_mfa_devices(

        self,

        user_name: str,

    ) -> list[dict[str, Any]]:

        response = self.client.list_mfa_devices(

            UserName=user_name,

        )

        return response.get(

            "MFADevices",

            [],

        )


    #######################################################################
    # Password Last Used
    #######################################################################

    def password_last_used(

        self,

        user_name: str,

    ) -> Any:

        user = self.get_user(

            user_name,

        )

        if user is None:

            return None

        return user.get(

            "PasswordLastUsed",

        )


    #######################################################################
    # Search Users
    #######################################################################

    def search_users(

        self,

        keyword: str,

    ) -> list[dict[str, Any]]:

        keyword = keyword.lower()

        return [

            user

            for user in self.list_users()

            if keyword

            in user.get(

                "UserName",

                "",

            ).lower()

        ]


    #######################################################################
    # Filter Users By Path
    #######################################################################

    def filter_by_path(

        self,

        path: str,

    ) -> list[dict[str, Any]]:

        return [

            user

            for user in self.list_users()

            if user.get(

                "Path",

            )

            == path

        ]


    #######################################################################
    # User Health
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        users = self.list_users()

        return {

            "healthy":

            True,

            "user_count":

            len(

                users,

            ),

            "users":

            [

                user["UserName"]

                for user in users

            ],

        }
        
    #######################################################################
    # User Inventory
    #######################################################################

    def inventory(

        self,

    ) -> list[dict[str, Any]]:

        return [

            self.summary(

                user["UserName"],

            )

            for user in self.list_users()

        ]


    #######################################################################
    # User Metrics
    #######################################################################

    def metrics(

        self,

    ) -> dict[str, Any]:

        users = self.list_users()

        total_users = len(

            users,

        )

        users_with_password = 0

        users_with_access_keys = 0

        users_with_mfa = 0

        for user in users:

            name = user["UserName"]

            if self.get_login_profile(

                name,

            ):

                users_with_password += 1

            if self.list_access_keys(

                name,

            ):

                users_with_access_keys += 1

            if self.list_mfa_devices(

                name,

            ):

                users_with_mfa += 1

        return {

            "total_users":

            total_users,

            "console_users":

            users_with_password,

            "programmatic_users":

            users_with_access_keys,

            "mfa_enabled":

            users_with_mfa,

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
    # Bulk Delete Users
    #######################################################################

    def bulk_delete(

        self,

        users: list[str],

    ) -> dict[str, bool]:

        results = {}

        for user in users:

            try:

                self.delete_user(

                    user,

                )

                results[user] = True

            except Exception:

                logger.exception(

                    "Failed deleting %s",

                    user,

                )

                results[user] = False

        return results


    #######################################################################
    # Bulk Tag Users
    #######################################################################

    def bulk_tag(

        self,

        users: list[str],

        tags: dict[str, str],

    ) -> dict[str, bool]:

        results = {}

        for user in users:

            try:

                self.tag_user(

                    user,

                    tags,

                )

                results[user] = True

            except Exception:

                logger.exception(

                    "Failed tagging %s",

                    user,

                )

                results[user] = False

        return results


###########################################################################
# User Manager
###########################################################################

class UserManager:

    """
    High-level IAM User Manager.
    """

    def __init__(

        self,

    ):

        self.service = UserService()


    def users(

        self,

    ) -> UserService:

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

USER_SERVICE = UserService()

USER_MANAGER = UserManager()


###########################################################################
# Convenience Functions
###########################################################################

def users(

) -> UserService:

    return USER_SERVICE


def health(

) -> dict[str, Any]:

    return USER_SERVICE.health()


def metrics(

) -> dict[str, Any]:

    return USER_SERVICE.metrics()


def diagnostics(

) -> dict[str, Any]:

    return USER_SERVICE.diagnostics()


###########################################################################
# Self Test
###########################################################################

def self_test(

) -> dict[str, Any]:

    return {

        "module":

        "iam.users",

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

    "UserService",

    "UserManager",

    "USER_SERVICE",

    "USER_MANAGER",

    "users",

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

    print("IAM User Service")

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

    print("IAM User Service Ready")