"""
deployments.py

Enterprise Amazon API Gateway Deployment & Stage Management
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
# Deployment Service
###########################################################################

class DeploymentService:

    """
    Enterprise API Gateway Deployment Management.
    """

    def __init__(

        self,

    ):

        self.client = api_gateway()


    #######################################################################
    # Create Deployment
    #######################################################################

    def create(

        self,

        api_id: str,

        stage_name: str,

        description: str = "",

    ) -> dict[str, Any]:

        logger.info(

            "Creating deployment for %s",

            stage_name,

        )

        return self.client.create_deployment(

            restApiId=api_id,

            stageName=stage_name,

            description=description,

        )


    #######################################################################
    # List Deployments
    #######################################################################

    def list(

        self,

        api_id: str,

    ) -> list[dict[str, Any]]:

        response = self.client.get_deployments(

            restApiId=api_id,

        )

        return response.get(

            "items",

            [],

        )


    #######################################################################
    # Describe Deployment
    #######################################################################

    def describe(

        self,

        api_id: str,

        deployment_id: str,

    ) -> dict[str, Any]:

        return self.client.get_deployment(

            restApiId=api_id,

            deploymentId=deployment_id,

        )


    #######################################################################
    # Deployment Exists
    #######################################################################

    def exists(

        self,

        api_id: str,

        deployment_id: str,

    ) -> bool:

        try:

            self.describe(

                api_id,

                deployment_id,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Delete Deployment
    #######################################################################

    def delete(

        self,

        api_id: str,

        deployment_id: str,

    ) -> None:

        logger.info(

            "Deleting deployment %s",

            deployment_id,

        )

        self.client.delete_deployment(

            restApiId=api_id,

            deploymentId=deployment_id,

        )


    #######################################################################
    # Get Stage
    #######################################################################

    def stage(

        self,

        api_id: str,

        stage_name: str,

    ) -> dict[str, Any]:

        return self.client.get_stage(

            restApiId=api_id,

            stageName=stage_name,

        )
        
    #######################################################################
    # Update Stage Variables
    #######################################################################

    def update_stage_variables(

        self,

        api_id: str,

        stage_name: str,

        variables: dict[str, str],

    ) -> dict[str, Any]:

        patch_operations = [

            {

                "op": "replace",

                "path": f"/variables/{key}",

                "value": value,

            }

            for key, value in variables.items()

        ]

        return self.client.update_stage(

            restApiId=api_id,

            stageName=stage_name,

            patchOperations=patch_operations,

        )


    #######################################################################
    # Update Stage Settings
    #######################################################################

    def update_stage_settings(

        self,

        api_id: str,

        stage_name: str,

        logging_level: str = "INFO",

        metrics_enabled: bool = True,

        tracing_enabled: bool = True,

    ) -> dict[str, Any]:

        return self.client.update_stage(

            restApiId=api_id,

            stageName=stage_name,

            patchOperations=[

                {

                    "op": "replace",

                    "path": "/*/*/logging/loglevel",

                    "value": logging_level,

                },

                {

                    "op": "replace",

                    "path": "/*/*/metrics/enabled",

                    "value": str(metrics_enabled).lower(),

                },

                {

                    "op": "replace",

                    "path": "/tracingEnabled",

                    "value": str(tracing_enabled).lower(),

                },

            ],

        )


    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

        api_id: str,

    ) -> dict[str, Any]:

        deployments = self.list(

            api_id,

        )

        return {

            "deployment_count": len(

                deployments,

            ),

            "deployments": [

                deployment.get(

                    "id",

                )

                for deployment in deployments

            ],

        }


    #######################################################################
    # Health Check
    #######################################################################

    def health(

        self,

        api_id: str,

    ) -> dict[str, Any]:

        try:

            self.list(

                api_id,

            )

            return {

                "healthy": True,

                "service": "API Gateway Deployments",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "API Gateway Deployments",

                "error": str(

                    exc,

                ),

            }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

        api_id: str,

    ) -> dict[str, Any]:

        try:

            return {

                "healthy": True,

                **self.summary(

                    api_id,

                ),

            }

        except Exception as exc:

            return {

                "healthy": False,

                "deployment_count": 0,

                "deployments": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_deployment_service(

) -> DeploymentService:

    """
    Create a DeploymentService instance.
    """

    return DeploymentService()