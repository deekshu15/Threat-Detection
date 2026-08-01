"""
datasets.py

Enterprise Amazon QuickSight Dataset Management
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
# Dataset Service
###########################################################################

class DatasetService:

    """
    Enterprise QuickSight Dataset Management.
    """

    def __init__(

        self,

        aws_account_id: str,

    ):

        self.client = quicksight()

        self.account_id = aws_account_id


    #######################################################################
    # List Datasets
    #######################################################################

    def list(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_data_sets",

        )

        datasets = []

        for page in paginator.paginate(

            AwsAccountId=self.account_id,

        ):

            datasets.extend(

                page.get(

                    "DataSetSummaries",

                    [],

                )

            )

        return datasets


    #######################################################################
    # Describe Dataset
    #######################################################################

    def describe(

        self,

        dataset_id: str,

    ) -> dict[str, Any]:

        response = self.client.describe_data_set(

            AwsAccountId=self.account_id,

            DataSetId=dataset_id,

        )

        return response["DataSet"]


    #######################################################################
    # Dataset Exists
    #######################################################################

    def exists(

        self,

        dataset_id: str,

    ) -> bool:

        try:

            self.describe(

                dataset_id,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Delete Dataset
    #######################################################################

    def delete(

        self,

        dataset_id: str,

    ) -> dict[str, Any]:

        logger.info(

            "Deleting dataset %s",

            dataset_id,

        )

        return self.client.delete_data_set(

            AwsAccountId=self.account_id,

            DataSetId=dataset_id,

        )


    #######################################################################
    # Import Mode
    #######################################################################

    def import_mode(

        self,

        dataset_id: str,

    ) -> str:

        dataset = self.describe(

            dataset_id,

        )

        return dataset.get(

            "ImportMode",

            "UNKNOWN",

        )
        
    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

    ) -> dict[str, Any]:

        datasets = self.list()

        return {

            "dataset_count": len(

                datasets,

            ),

            "datasets": [

                dataset.get(

                    "Name",

                )

                for dataset in datasets

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

                "service": "QuickSight Datasets",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "QuickSight Datasets",

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

                "dataset_count": 0,

                "datasets": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_dataset_service(

    aws_account_id: str,

) -> DatasetService:

    """
    Create a DatasetService instance.
    """

    return DatasetService(

        aws_account_id,

    )