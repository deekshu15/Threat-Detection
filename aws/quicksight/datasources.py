"""
datasources.py

Enterprise Amazon QuickSight Data Source Management
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
# Data Source Service
###########################################################################

class DataSourceService:

    """
    Enterprise QuickSight Data Source Management.
    """

    def __init__(

        self,

        aws_account_id: str,

    ):

        self.client = quicksight()

        self.account_id = aws_account_id


    #######################################################################
    # List Data Sources
    #######################################################################

    def list(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_data_sources",

        )

        results = []

        for page in paginator.paginate(

            AwsAccountId=self.account_id,

        ):

            results.extend(

                page.get(

                    "DataSources",

                    [],

                )

            )

        return results


    #######################################################################
    # Describe
    #######################################################################

    def describe(

        self,

        data_source_id: str,

    ) -> dict[str, Any]:

        response = self.client.describe_data_source(

            AwsAccountId=self.account_id,

            DataSourceId=data_source_id,

        )

        return response["DataSource"]


    #######################################################################
    # Exists
    #######################################################################

    def exists(

        self,

        data_source_id: str,

    ) -> bool:

        try:

            self.describe(

                data_source_id,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Delete
    #######################################################################

    def delete(

        self,

        data_source_id: str,

    ) -> dict[str, Any]:

        logger.info(

            "Deleting data source %s",

            data_source_id,

        )

        return self.client.delete_data_source(

            AwsAccountId=self.account_id,

            DataSourceId=data_source_id,

        )
        
    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

    ) -> dict[str, Any]:

        sources = self.list()

        return {

            "data_source_count": len(

                sources,

            ),

            "data_sources": [

                source.get(

                    "Name",

                )

                for source in sources

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

                "service": "QuickSight Data Sources",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "QuickSight Data Sources",

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

                "data_source_count": 0,

                "data_sources": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_datasource_service(

    aws_account_id: str,

) -> DataSourceService:

    """
    Create a DataSourceService instance.
    """

    return DataSourceService(

        aws_account_id,

    )