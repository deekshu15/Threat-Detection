"""
resources.py

Enterprise Amazon API Gateway Resource Management
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
# Resource Service
###########################################################################

class ResourceService:

    """
    Enterprise API Gateway Resource Management.
    """

    def __init__(

        self,

    ):

        self.client = api_gateway()


    #######################################################################
    # List Resources
    #######################################################################

    def list(

        self,

        api_id: str,

    ) -> list[dict[str, Any]]:

        resources = []

        paginator = self.client.get_paginator(

            "get_resources",

        )

        for page in paginator.paginate(

            restApiId=api_id,

        ):

            resources.extend(

                page.get(

                    "items",

                    [],

                )

            )

        return resources


    #######################################################################
    # Describe Resource
    #######################################################################

    def describe(

        self,

        api_id: str,

        resource_id: str,

    ) -> dict[str, Any]:

        return self.client.get_resource(

            restApiId=api_id,

            resourceId=resource_id,

        )


    #######################################################################
    # Find Resource by Path
    #######################################################################

    def find_by_path(

        self,

        api_id: str,

        path: str,

    ) -> dict[str, Any] | None:

        for resource in self.list(

            api_id,

        ):

            if (

                resource.get(

                    "path",

                )

                == path

            ):

                return resource

        return None


    #######################################################################
    # Create Resource
    #######################################################################

    def create(

        self,

        api_id: str,

        parent_id: str,

        path_part: str,

    ) -> dict[str, Any]:

        logger.info(

            "Creating resource %s",

            path_part,

        )

        return self.client.create_resource(

            restApiId=api_id,

            parentId=parent_id,

            pathPart=path_part,

        )


    #######################################################################
    # Delete Resource
    #######################################################################

    def delete(

        self,

        api_id: str,

        resource_id: str,

    ) -> None:

        logger.info(

            "Deleting resource %s",

            resource_id,

        )

        self.client.delete_resource(

            restApiId=api_id,

            resourceId=resource_id,

        )
        
    #######################################################################
    # Resource Exists
    #######################################################################

    def exists(

        self,

        api_id: str,

        resource_id: str,

    ) -> bool:

        try:

            self.describe(

                api_id,

                resource_id,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Root Resource
    #######################################################################

    def root_resource(

        self,

        api_id: str,

    ) -> dict[str, Any] | None:

        for resource in self.list(

            api_id,

        ):

            if (

                resource.get(

                    "path",

                )

                == "/"

            ):

                return resource

        return None


    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

        api_id: str,

    ) -> dict[str, Any]:

        resources = self.list(

            api_id,

        )

        return {

            "resource_count": len(

                resources,

            ),

            "resources": [

                resource.get(

                    "path",

                )

                for resource in resources

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

                "service": "API Gateway Resources",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "API Gateway Resources",

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

                "resource_count": 0,

                "resources": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_resource_service(

) -> ResourceService:

    """
    Create a ResourceService instance.
    """

    return ResourceService()