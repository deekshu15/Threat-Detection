"""
manager.py

Enterprise Amazon API Gateway Manager

Unified interface for all API Gateway services.
"""

from __future__ import annotations

from typing import Any

from .apis import create_rest_api_service
from .resources import create_resource_service
from .methods import create_method_service
from .integrations import create_integration_service
from .deployments import create_deployment_service
from .authorizers import create_authorizer_service
from .usage_plans import create_usage_plan_service
from .domains import create_domain_service


###########################################################################
# API Gateway Manager
###########################################################################

class ApiGatewayManager:

    """
    Enterprise API Gateway Manager.
    """

    def __init__(

        self,

    ):

        self.apis = create_rest_api_service()

        self.resources = create_resource_service()

        self.methods = create_method_service()

        self.integrations = create_integration_service()

        self.deployments = create_deployment_service()

        self.authorizers = create_authorizer_service()

        self.usage_plans = create_usage_plan_service()

        self.domains = create_domain_service()


    #######################################################################
    # REST APIs
    #######################################################################

    def rest_apis(

        self,

    ) -> list[dict[str, Any]]:

        return self.apis.list()


    #######################################################################
    # Usage Plans
    #######################################################################

    def usage_plans_list(

        self,

    ) -> list[dict[str, Any]]:

        return self.usage_plans.list()


    #######################################################################
    # Domains
    #######################################################################

    def domains_list(

        self,

    ) -> list[dict[str, Any]]:

        return self.domains.list()
    
    #######################################################################
    # Health
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        diagnostics = self.diagnostics()

        return {

            "healthy":

            diagnostics["apis"]["healthy"]

            and diagnostics["usage_plans"]["healthy"]

            and diagnostics["domains"]["healthy"],

            "service": "Amazon API Gateway",

        }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

    ) -> dict[str, Any]:

        try:

            return {

                "apis":

                self.apis.diagnostics(),

                "usage_plans":

                self.usage_plans.diagnostics(),

                "domains":

                self.domains.diagnostics(),

            }

        except Exception as exc:

            return {

                "healthy": False,

                "apis": {},

                "usage_plans": {},

                "domains": {},

                "error": str(

                    exc,

                ),

            }


    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

    ) -> dict[str, Any]:

        diagnostics = self.diagnostics()

        return {

            "service": "Amazon API Gateway",

            "healthy": self.health()["healthy"],

            "rest_apis":

            diagnostics.get(

                "apis",

                {},

            ).get(

                "api_count",

                0,

            ),

            "usage_plans":

            diagnostics.get(

                "usage_plans",

                {},

            ).get(

                "usage_plan_count",

                0,

            ),

            "api_keys":

            diagnostics.get(

                "usage_plans",

                {},

            ).get(

                "api_key_count",

                0,

            ),

            "domains":

            diagnostics.get(

                "domains",

                {},

            ).get(

                "domain_count",

                0,

            ),

        }


###########################################################################
# Factory
###########################################################################

def create_api_gateway_manager(

) -> ApiGatewayManager:

    """
    Create an ApiGatewayManager instance.
    """

    return ApiGatewayManager()