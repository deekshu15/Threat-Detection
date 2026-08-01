"""
analyses.py

Enterprise Amazon QuickSight Analysis Management
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
# Analysis Service
###########################################################################

class AnalysisService:

    """
    Enterprise QuickSight Analysis Management.
    """

    def __init__(

        self,

        aws_account_id: str,

    ):

        self.client = quicksight()

        self.account_id = aws_account_id


    #######################################################################
    # List Analyses
    #######################################################################

    def list(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_analyses",

        )

        analyses = []

        for page in paginator.paginate(

            AwsAccountId=self.account_id,

        ):

            analyses.extend(

                page.get(

                    "AnalysisSummaryList",

                    [],

                )

            )

        return analyses


    #######################################################################
    # Describe Analysis
    #######################################################################

    def describe(

        self,

        analysis_id: str,

    ) -> dict[str, Any]:

        response = self.client.describe_analysis(

            AwsAccountId=self.account_id,

            AnalysisId=analysis_id,

        )

        return response["Analysis"]


    #######################################################################
    # Analysis Exists
    #######################################################################

    def exists(

        self,

        analysis_id: str,

    ) -> bool:

        try:

            self.describe(

                analysis_id,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Delete Analysis
    #######################################################################

    def delete(

        self,

        analysis_id: str,

    ) -> dict[str, Any]:

        logger.info(

            "Deleting analysis %s",

            analysis_id,

        )

        return self.client.delete_analysis(

            AwsAccountId=self.account_id,

            AnalysisId=analysis_id,

        )


    #######################################################################
    # Analysis Permissions
    #######################################################################

    def permissions(

        self,

        analysis_id: str,

    ) -> list[dict[str, Any]]:

        response = self.client.describe_analysis_permissions(

            AwsAccountId=self.account_id,

            AnalysisId=analysis_id,

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

        analyses = self.list()

        return {

            "analysis_count": len(

                analyses,

            ),

            "analyses": [

                analysis.get(

                    "Name",

                )

                for analysis in analyses

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

                "service": "QuickSight Analyses",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "QuickSight Analyses",

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

                "analysis_count": 0,

                "analyses": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_analysis_service(

    aws_account_id: str,

) -> AnalysisService:

    """
    Create an AnalysisService instance.
    """

    return AnalysisService(

        aws_account_id,

    )