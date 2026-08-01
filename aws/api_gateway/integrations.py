"""
integrations.py

Enterprise Amazon API Gateway Integration Management
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
# Integration Service
###########################################################################

class IntegrationService:

    """
    Enterprise API Gateway Integration Management.
    """

    def __init__(

        self,

    ):

        self.client = api_gateway()


    #######################################################################
    # Lambda Integration
    #######################################################################

    def lambda_integration(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

        lambda_uri: str,

    ) -> dict[str, Any]:

        logger.info(

            "Creating Lambda integration",

        )

        return self.client.put_integration(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

            type="AWS_PROXY",

            integrationHttpMethod="POST",

            uri=lambda_uri,

        )


    #######################################################################
    # HTTP Integration
    #######################################################################

    def http_integration(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

        endpoint: str,

    ) -> dict[str, Any]:

        return self.client.put_integration(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

            type="HTTP",

            integrationHttpMethod=http_method,

            uri=endpoint,

        )


    #######################################################################
    # Mock Integration
    #######################################################################

    def mock_integration(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

    ) -> dict[str, Any]:

        return self.client.put_integration(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

            type="MOCK",

        )


    #######################################################################
    # AWS Service Integration
    #######################################################################

    def aws_integration(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

        service_uri: str,

        integration_http_method: str = "POST",

    ) -> dict[str, Any]:

        return self.client.put_integration(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

            type="AWS",

            integrationHttpMethod=integration_http_method,

            uri=service_uri,

        )


    #######################################################################
    # Describe Integration
    #######################################################################

    def describe(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

    ) -> dict[str, Any]:

        return self.client.get_integration(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

        )
        
    #######################################################################
    # VPC Link Integration
    #######################################################################

    def vpc_link_integration(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

        endpoint: str,

        vpc_link_id: str,

        integration_http_method: str = "POST",

    ) -> dict[str, Any]:

        return self.client.put_integration(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

            type="HTTP_PROXY",

            integrationHttpMethod=integration_http_method,

            uri=endpoint,

            connectionType="VPC_LINK",

            connectionId=vpc_link_id,

        )


    #######################################################################
    # Integration Exists
    #######################################################################

    def exists(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

    ) -> bool:

        try:

            self.describe(

                api_id,

                resource_id,

                http_method,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Delete Integration
    #######################################################################

    def delete(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

    ) -> None:

        logger.info(

            "Deleting integration",

        )

        self.client.delete_integration(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

        )


    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

    ) -> dict[str, Any]:

        integration = self.describe(

            api_id,

            resource_id,

            http_method,

        )

        return {

            "type": integration.get(

                "type",

            ),

            "uri": integration.get(

                "uri",

            ),

            "connection_type": integration.get(

                "connectionType",

            ),

            "timeout":

            integration.get(

                "timeoutInMillis",

            ),

        }


    #######################################################################
    # Health Check
    #######################################################################

    def health(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

    ) -> dict[str, Any]:

        try:

            self.describe(

                api_id,

                resource_id,

                http_method,

            )

            return {

                "healthy": True,

                "service": "API Gateway Integrations",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "API Gateway Integrations",

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

        resource_id: str,

        http_method: str,

    ) -> dict[str, Any]:

        try:

            return {

                "healthy": True,

                **self.summary(

                    api_id,

                    resource_id,

                    http_method,

                ),

            }

        except Exception as exc:

            return {

                "healthy": False,

                "type": None,

                "uri": None,

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_integration_service(

) -> IntegrationService:

    """
    Create an IntegrationService instance.
    """

    return IntegrationService()