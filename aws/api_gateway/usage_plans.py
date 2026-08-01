"""
usage_plans.py

Enterprise Amazon API Gateway Usage Plan Management
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
# Usage Plan Service
###########################################################################

class UsagePlanService:

    """
    Enterprise API Gateway Usage Plan Management.
    """

    def __init__(

        self,

    ):

        self.client = api_gateway()


    #######################################################################
    # Create Usage Plan
    #######################################################################

    def create(

        self,

        name: str,

        description: str = "",

        throttle_rate: int = 100,

        throttle_burst: int = 200,

        quota_limit: int = 100000,

        quota_period: str = "MONTH",

    ) -> dict[str, Any]:

        logger.info(

            "Creating usage plan %s",

            name,

        )

        return self.client.create_usage_plan(

            name=name,

            description=description,

            throttle={

                "rateLimit": throttle_rate,

                "burstLimit": throttle_burst,

            },

            quota={

                "limit": quota_limit,

                "period": quota_period,

            },

        )


    #######################################################################
    # List Usage Plans
    #######################################################################

    def list(

        self,

    ) -> list[dict[str, Any]]:

        response = self.client.get_usage_plans()

        return response.get(

            "items",

            [],

        )


    #######################################################################
    # Describe Usage Plan
    #######################################################################

    def describe(

        self,

        usage_plan_id: str,

    ) -> dict[str, Any]:

        return self.client.get_usage_plan(

            usagePlanId=usage_plan_id,

        )


    #######################################################################
    # Usage Plan Exists
    #######################################################################

    def exists(

        self,

        usage_plan_id: str,

    ) -> bool:

        try:

            self.describe(

                usage_plan_id,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Delete Usage Plan
    #######################################################################

    def delete(

        self,

        usage_plan_id: str,

    ) -> None:

        logger.info(

            "Deleting usage plan %s",

            usage_plan_id,

        )

        self.client.delete_usage_plan(

            usagePlanId=usage_plan_id,

        )


    #######################################################################
    # Create API Key
    #######################################################################

    def create_api_key(

        self,

        name: str,

        enabled: bool = True,

    ) -> dict[str, Any]:

        logger.info(

            "Creating API key %s",

            name,

        )

        return self.client.create_api_key(

            name=name,

            enabled=enabled,

        )
        
    #######################################################################
    # Associate API Key
    #######################################################################

    def attach_api_key(

        self,

        usage_plan_id: str,

        api_key_id: str,

    ) -> dict[str, Any]:

        logger.info(

            "Associating API key %s",

            api_key_id,

        )

        return self.client.create_usage_plan_key(

            usagePlanId=usage_plan_id,

            keyId=api_key_id,

            keyType="API_KEY",

        )


    #######################################################################
    # List API Keys
    #######################################################################

    def api_keys(

        self,

    ) -> list[dict[str, Any]]:

        response = self.client.get_api_keys(

            includeValues=False,

        )

        return response.get(

            "items",

            [],

        )


    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

    ) -> dict[str, Any]:

        usage_plans = self.list()

        api_keys = self.api_keys()

        return {

            "usage_plan_count": len(

                usage_plans,

            ),

            "api_key_count": len(

                api_keys,

            ),

            "usage_plans": [

                plan.get(

                    "name",

                )

                for plan in usage_plans

            ],

            "api_keys": [

                key.get(

                    "name",

                )

                for key in api_keys

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

                "service": "API Gateway Usage Plans",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "API Gateway Usage Plans",

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

                "usage_plan_count": 0,

                "api_key_count": 0,

                "usage_plans": [],

                "api_keys": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_usage_plan_service(

) -> UsagePlanService:

    """
    Create a UsagePlanService instance.
    """

    return UsagePlanService()