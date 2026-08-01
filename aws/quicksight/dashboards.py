"""
dashboards.py

Enterprise Amazon QuickSight Dashboard Management
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
# Dashboard Service
###########################################################################

class DashboardService:

    """
    Enterprise QuickSight Dashboard Management.
    """

    def __init__(

        self,

        aws_account_id: str,

    ):

        self.client = quicksight()

        self.account_id = aws_account_id


    #######################################################################
    # List Dashboards
    #######################################################################

    def list(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_dashboards",

        )

        dashboards = []

        for page in paginator.paginate(

            AwsAccountId=self.account_id,

        ):

            dashboards.extend(

                page.get(

                    "DashboardSummaryList",

                    [],

                )

            )

        return dashboards


    #######################################################################
    # Describe Dashboard
    #######################################################################

    def describe(

        self,

        dashboard_id: str,

    ) -> dict[str, Any]:

        response = self.client.describe_dashboard(

            AwsAccountId=self.account_id,

            DashboardId=dashboard_id,

        )

        return response["Dashboard"]


    #######################################################################
    # Dashboard Exists
    #######################################################################

    def exists(

        self,

        dashboard_id: str,

    ) -> bool:

        try:

            self.describe(

                dashboard_id,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Delete Dashboard
    #######################################################################

    def delete(

        self,

        dashboard_id: str,

    ) -> dict[str, Any]:

        logger.info(

            "Deleting dashboard %s",

            dashboard_id,

        )

        return self.client.delete_dashboard(

            AwsAccountId=self.account_id,

            DashboardId=dashboard_id,
        )


    #######################################################################
    # Dashboard Permissions
    #######################################################################

    def permissions(

        self,

        dashboard_id: str,

    ) -> list[dict[str, Any]]:

        response = self.client.describe_dashboard_permissions(

            AwsAccountId=self.account_id,

            DashboardId=dashboard_id,

        )

        return response.get(

            "Permissions",

            [],

        )
        
    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

    ) -> dict[str, Any]:

        dashboards = self.list()

        return {

            "dashboard_count": len(

                dashboards,

            ),

            "dashboards": [

                dashboard.get(

                    "Name",

                )

                for dashboard in dashboards

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

                "service": "QuickSight Dashboards",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "QuickSight Dashboards",

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

                "dashboard_count": 0,

                "dashboards": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_dashboard_service(

    aws_account_id: str,

) -> DashboardService:

    """
    Create a DashboardService instance.
    """

    return DashboardService(

        aws_account_id,

    )