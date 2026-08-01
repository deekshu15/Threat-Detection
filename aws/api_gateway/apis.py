"""
apis.py

Enterprise Amazon API Gateway REST API Management
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

def api_gateway():

    """
    Return API Gateway client.
    """

    return get_client(

        "apigateway",

    )


###########################################################################
# REST API Service
###########################################################################

class RestApiService:

    """
    Enterprise REST API Management.
    """

    def __init__(

        self,

    ):

        self.client = api_gateway()


    #######################################################################
    # Create API
    #######################################################################

    def create(

        self,

        name: str,

        description: str = "",

        endpoint_type: str = "REGIONAL",

    ) -> dict[str, Any]:

        logger.info(

            "Creating REST API %s",

            name,

        )

        return self.client.create_rest_api(

            name=name,

            description=description,

            endpointConfiguration={

                "types": [

                    endpoint_type,

                ]

            },

        )


    #######################################################################
    # List APIs
    #######################################################################

    def list(

        self,

    ) -> list[dict[str, Any]]:

        apis = []

        paginator = self.client.get_paginator(

            "get_rest_apis",

        )

        for page in paginator.paginate():

            apis.extend(

                page.get(

                    "items",

                    [],

                )

            )

        return apis


    #######################################################################
    # Get API
    #######################################################################

    def describe(

        self,

        api_id: str,

    ) -> dict[str, Any]:

        return self.client.get_rest_api(

            restApiId=api_id,

        )


    #######################################################################
    # API Exists
    #######################################################################

    def exists(

        self,

        api_id: str,

    ) -> bool:

        try:

            self.describe(

                api_id,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Delete API
    #######################################################################

    def delete(

        self,

        api_id: str,

    ) -> None:

        logger.info(

            "Deleting REST API %s",

            api_id,

        )

        self.client.delete_rest_api(

            restApiId=api_id,

        )
        
    #######################################################################
    # Import OpenAPI Specification
    #######################################################################

    def import_openapi(

        self,

        body: str,

        mode: str = "merge",

    ) -> dict[str, Any]:

        logger.info(

            "Importing OpenAPI specification",

        )

        return self.client.import_rest_api(

            body=body,

            failOnWarnings=False,

            parameters={

                "mode": mode,

            },

        )


    #######################################################################
    # Export API
    #######################################################################

    def export(

        self,

        api_id: str,

        stage_name: str,

        export_type: str = "oas30",

    ) -> bytes:

        response = self.client.get_export(

            restApiId=api_id,

            stageName=stage_name,

            exportType=export_type,

            accepts="application/yaml",

        )

        return response["body"].read()


    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

    ) -> dict[str, Any]:

        apis = self.list()

        return {

            "api_count": len(

                apis,

            ),

            "apis": [

                api.get(

                    "name",

                )

                for api in apis

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

                "service": "API Gateway",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "API Gateway",

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

                "api_count": 0,

                "apis": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_rest_api_service(

    ) -> RestApiService:

    """
    Create a RestApiService instance.
    """

    return RestApiService()