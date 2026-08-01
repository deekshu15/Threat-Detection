"""
users.py

Enterprise Amazon QuickSight User Management
"""

from __future__ import annotations

import logging

from typing import Any

from botocore.exceptions import ClientError

from aws.utils.aws_utils import get_client

logger = logging.getLogger(__name__)


###########################################################################
# Client
###########################################################################

def quicksight():

    return get_client(

        "quicksight",

    )


###########################################################################
# User Service
###########################################################################

class UserService:

    """
    Enterprise QuickSight User Management.
    """

    def __init__(

        self,

        aws_account_id: str,

        namespace: str = "default",

    ):

        self.client = quicksight()

        self.account_id = aws_account_id

        self.namespace = namespace


    #######################################################################
    # List Users
    #######################################################################

    def list(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_users",

        )

        users = []

        for page in paginator.paginate(

            AwsAccountId=self.account_id,

            Namespace=self.namespace,

        ):

            users.extend(

                page.get(

                    "UserList",

                    [],

                )

            )

        return users


    #######################################################################
    # Describe User
    #######################################################################

    def describe(

        self,

        user_name: str,

    ) -> dict[str, Any]:

        response = self.client.describe_user(

            AwsAccountId=self.account_id,

            Namespace=self.namespace,

            UserName=user_name,

        )

        return response["User"]


    #######################################################################
    # Register User
    #######################################################################

    def register(

        self,

        identity_type: str,

        email: str,

        user_role: str,

        iam_arn: str,

        session_name: str,

    ) -> dict[str, Any]:

        logger.info(

            "Registering QuickSight user %s",

            email,

        )

        return self.client.register_user(

            AwsAccountId=self.account_id,

            Namespace=self.namespace,

            IdentityType=identity_type,

            Email=email,

            UserRole=user_role,

            IamArn=iam_arn,

            SessionName=session_name,

        )


    #######################################################################
    # Delete User
    #######################################################################

    def delete(

        self,

        user_name: str,

    ) -> dict[str, Any]:

        logger.info(

            "Deleting user %s",

            user_name,

        )

        return self.client.delete_user(

            AwsAccountId=self.account_id,

            Namespace=self.namespace,

            UserName=user_name,

        )


    #######################################################################
    # User Exists
    #######################################################################

    def exists(

        self,

        user_name: str,

    ) -> bool:

        try:

            self.describe(

                user_name,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # List Groups
    #######################################################################

    def groups(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_groups",

        )

        groups = []

        for page in paginator.paginate(

            AwsAccountId=self.account_id,

            Namespace=self.namespace,

        ):

            groups.extend(

                page.get(

                    "GroupList",

                    [],

                )

            )

        return groups
    
    #######################################################################
    # Group Memberships
    #######################################################################

    def group_memberships(

        self,

        group_name: str,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_group_memberships",

        )

        members = []

        for page in paginator.paginate(

            AwsAccountId=self.account_id,

            Namespace=self.namespace,

            GroupName=group_name,

        ):

            members.extend(

                page.get(

                    "GroupMemberList",

                    [],

                )

            )

        return members


    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

    ) -> dict[str, Any]:

        users = self.list()

        groups = self.groups()

        return {

            "user_count": len(

                users,

            ),

            "group_count": len(

                groups,

            ),

            "users": [

                user.get(

                    "UserName",

                )

                for user in users

            ],

            "groups": [

                group.get(

                    "GroupName",

                )

                for group in groups

            ],

        }


    #######################################################################
    # Health Check
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        try:

            self.list()

            return {

                "healthy": True,

                "service": "QuickSight Users",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "QuickSight Users",

                "error": str(

                    exc,

                ),

            }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

    ) -> dict[str, Any]:

        try:

            return {

                "healthy": True,

                **self.summary(),

            }

        except Exception as exc:

            return {

                "healthy": False,

                "user_count": 0,

                "group_count": 0,

                "users": [],

                "groups": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_user_service(

    aws_account_id: str,

    namespace: str = "default",

) -> UserService:

    """
    Create a UserService instance.
    """

    return UserService(

        aws_account_id=aws_account_id,

        namespace=namespace,

    )