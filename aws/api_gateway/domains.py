"""
domains.py

Enterprise Amazon API Gateway Custom Domain Management
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
# Domain Service
###########################################################################

class DomainService:

    """
    Enterprise API Gateway Custom Domain Management.
    """

    def __init__(

        self,

    ):

        self.client = api_gateway()


    #######################################################################
    # Create Custom Domain
    #######################################################################

    def create(

        self,

        domain_name: str,

        certificate_arn: str,

        endpoint_type: str = "REGIONAL",

        security_policy: str = "TLS_1_2",

    ) -> dict[str, Any]:

        logger.info(

            "Creating custom domain %s",

            domain_name,

        )

        return self.client.create_domain_name(

            domainName=domain_name,

            regionalCertificateArn=certificate_arn,

            endpointConfiguration={

                "types": [

                    endpoint_type,

                ]

            },

            securityPolicy=security_policy,

        )


    #######################################################################
    # List Domains
    #######################################################################

    def list(

        self,

    ) -> list[dict[str, Any]]:

        response = self.client.get_domain_names()

        return response.get(

            "items",

            [],

        )


    #######################################################################
    # Describe Domain
    #######################################################################

    def describe(

        self,

        domain_name: str,

    ) -> dict[str, Any]:

        return self.client.get_domain_name(

            domainName=domain_name,

        )


    #######################################################################
    # Domain Exists
    #######################################################################

    def exists(

        self,

        domain_name: str,

    ) -> bool:

        try:

            self.describe(

                domain_name,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Delete Domain
    #######################################################################

    def delete(

        self,

        domain_name: str,

    ) -> None:

        logger.info(

            "Deleting custom domain %s",

            domain_name,

        )

        self.client.delete_domain_name(

            domainName=domain_name,

        )


    #######################################################################
    # Create Base Path Mapping
    #######################################################################

    def create_base_path_mapping(

        self,

        domain_name: str,

        api_id: str,

        stage: str,

        base_path: str = "(none)",

    ) -> dict[str, Any]:

        return self.client.create_base_path_mapping(

            domainName=domain_name,

            restApiId=api_id,

            stage=stage,

            basePath=base_path,

        )
        
    #######################################################################
    # Delete Base Path Mapping
    #######################################################################

    def delete_base_path_mapping(

        self,

        domain_name: str,

        base_path: str = "(none)",

    ) -> None:

        logger.info(

            "Deleting base path mapping %s",

            base_path,

        )

        self.client.delete_base_path_mapping(

            domainName=domain_name,

            basePath=base_path,

        )


    #######################################################################
    # List Base Path Mappings
    #######################################################################

    def base_path_mappings(

        self,

        domain_name: str,

    ) -> list[dict[str, Any]]:

        response = self.client.get_base_path_mappings(

            domainName=domain_name,

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

        domains = self.list()

        return {

            "domain_count": len(

                domains,

            ),

            "domains": [

                domain.get(

                    "domainName",

                )

                for domain in domains

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

                "service": "API Gateway Domains",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "API Gateway Domains",

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

                "domain_count": 0,

                "domains": [],

                "error": str(

                    exc,

                ),

            }


###########################################################################
# Factory
###########################################################################

def create_domain_service(

) -> DomainService:

    """
    Create a DomainService instance.
    """

    return DomainService()