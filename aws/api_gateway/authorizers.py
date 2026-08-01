"""
authorizers.py

Enterprise Amazon API Gateway Authorizer Management
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
# Authorizer Service
###########################################################################

class AuthorizerService:

    """
    Enterprise API Gateway Authorizer Management.
    """

    def __init__(

        self,

    ):

        self.client = api_gateway()


    #######################################################################
    # Create Lambda Authorizer
    #######################################################################

    def create_lambda(

        self,

        api_id: str,

        name: str,

        authorizer_uri: str,

        identity_source: str = "method.request.header.Authorization",

    ) -> dict[str, Any]:

        logger.info(

            "Creating Lambda authorizer %s",

            name,

        )

        return self.client.create_authorizer(

            restApiId=api_id,

            name=name,

            type="TOKEN",

            authorizerUri=authorizer_uri,

            identitySource=identity_source,

        )


    #######################################################################
    # Create Cognito Authorizer
    #######################################################################

    def create_cognito(

        self,

        api_id: str,

        name: str,

        provider_arns: list[str],

        identity_source: str = "method.request.header.Authorization",

    ) -> dict[str, Any]:

        logger.info(

            "Creating Cognito authorizer %s",

            name,

        )

        return self.client.create_authorizer(

            restApiId=api_id,

            name=name,

            type="COGNITO_USER_POOLS",

            providerARNs=provider_arns,

            identitySource=identity_source,

        )


    #######################################################################
    # List Authorizers
    #######################################################################

    def list(

        self,

        api_id: str,

    ) -> list[dict[str, Any]]:

        response = self.client.get_authorizers(

            restApiId=api_id,

        )

        return response.get(

            "items",

            [],

        )


    #######################################################################
    # Describe Authorizer
    #######################################################################

    def describe(

        self,

        api_id: str,

        authorizer_id: str,

    ) -> dict[str, Any]:

        return self.client.get_authorizer(

            restApiId=api_id,

            authorizerId=authorizer_id,

        )


    #######################################################################
    # Authorizer Exists
    #######################################################################

    def exists(

        self,

        api_id: str,

        authorizer_id: str,

    ) -> bool:

        try:

            self.describe(

                api_id,

                authorizer_id,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Delete Authorizer
    #######################################################################

    def delete(

        self,

        api_id: str,

        authorizer_id: str,

    ) -> None:

        logger.info(

            "Deleting authorizer %s",

            authorizer_id,

        )

        self.client.delete_authorizer(

            restApiId=api_id,

            authorizerId=authorizer_id,

        )

    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

        api_id: str,

    ) -> dict[str, Any]:

        authorizers = self.list(

            api_id,

        )

        return {

            "authorizer_count": len(

                authorizers,

            ),

            "authorizers": [

                authorizer.get(

                    "name",

                )

                for authorizer in authorizers

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

                "service": "API Gateway Authorizers",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "API Gateway Authorizers",

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

                "authorizer_count": 0,

                "authorizers": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_authorizer_service(

) -> AuthorizerService:

    """
    Create an AuthorizerService instance.
    """

    return AuthorizerService()