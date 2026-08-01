"""
methods.py

Enterprise Amazon API Gateway Method Management
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
# Method Service
###########################################################################

class MethodService:

    """
    Enterprise API Gateway Method Management.
    """

    def __init__(

        self,

    ):

        self.client = api_gateway()


    #######################################################################
    # Create Method
    #######################################################################

    def create(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

        authorization_type: str = "NONE",

        api_key_required: bool = False,

        request_parameters: dict[str, bool] | None = None,

    ) -> dict[str, Any]:

        logger.info(

            "Creating %s method",

            http_method,

        )

        return self.client.put_method(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

            authorizationType=authorization_type,

            apiKeyRequired=api_key_required,

            requestParameters=request_parameters or {},

        )


    #######################################################################
    # Describe Method
    #######################################################################

    def describe(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

    ) -> dict[str, Any]:

        return self.client.get_method(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

        )


    #######################################################################
    # Method Exists
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
    # Delete Method
    #######################################################################

    def delete(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

    ) -> None:

        logger.info(

            "Deleting %s method",

            http_method,

        )

        self.client.delete_method(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

        )


    #######################################################################
    # Method Response
    #######################################################################

    def put_method_response(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

        status_code: str,

        response_models: dict[str, str] | None = None,

        response_parameters: dict[str, bool] | None = None,

    ) -> dict[str, Any]:

        return self.client.put_method_response(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

            statusCode=status_code,

            responseModels=response_models or {},

            responseParameters=response_parameters or {},

        )
        
    #######################################################################
    # Put Integration Response
    #######################################################################

    def put_integration_response(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

        status_code: str,

        selection_pattern: str = "",

        response_templates: dict[str, str] | None = None,

    ) -> dict[str, Any]:

        return self.client.put_integration_response(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

            statusCode=status_code,

            selectionPattern=selection_pattern,

            responseTemplates=response_templates or {},

        )


    #######################################################################
    # Update Request Validator
    #######################################################################

    def update_request_validator(

        self,

        api_id: str,

        resource_id: str,

        http_method: str,

        request_validator_id: str,

    ) -> dict[str, Any]:

        return self.client.update_method(

            restApiId=api_id,

            resourceId=resource_id,

            httpMethod=http_method,

            patchOperations=[

                {

                    "op": "replace",

                    "path": "/requestValidatorId",

                    "value": request_validator_id,

                }

            ],

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

        method = self.describe(

            api_id,

            resource_id,

            http_method,

        )

        return {

            "http_method":

            method.get(

                "httpMethod",

            ),

            "authorization":

            method.get(

                "authorizationType",

            ),

            "api_key_required":

            method.get(

                "apiKeyRequired",

            ),

            "request_parameters":

            len(

                method.get(

                    "requestParameters",

                    {},

                )

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

                "service": "API Gateway Methods",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "API Gateway Methods",

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

                "http_method": http_method,

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_method_service(

) -> MethodService:

    """
    Create a MethodService instance.
    """

    return MethodService()