"""
manager.py

Enterprise Amazon QuickSight Manager

Unified interface for all QuickSight services.
"""

from __future__ import annotations

from typing import Any

from .datasources import create_datasource_service
from .datasets import create_dataset_service
from .dashboards import create_dashboard_service
from .analyses import create_analysis_service
from .users import create_user_service


###########################################################################
# Manager
###########################################################################

class QuickSightManager:

    """
    Enterprise QuickSight Manager.
    """

    def __init__(

        self,

        aws_account_id: str,

        namespace: str = "default",

    ):

        self.account_id = aws_account_id

        self.namespace = namespace

        self.datasources = create_datasource_service(

            aws_account_id,

        )

        self.datasets = create_dataset_service(

            aws_account_id,

        )

        self.dashboards = create_dashboard_service(

            aws_account_id,

        )

        self.analyses = create_analysis_service(

            aws_account_id,

        )

        self.users = create_user_service(

            aws_account_id,

            namespace,

        )


    #######################################################################
    # Data Sources
    #######################################################################

    def data_sources(

        self,

    ) -> list[dict[str, Any]]:

        return self.datasources.list()


    #######################################################################
    # Datasets
    #######################################################################

    def datasets_list(

        self,

    ) -> list[dict[str, Any]]:

        return self.datasets.list()


    #######################################################################
    # Dashboards
    #######################################################################

    def dashboards_list(

        self,

    ) -> list[dict[str, Any]]:

        return self.dashboards.list()


    #######################################################################
    # Analyses
    #######################################################################

    def analyses_list(

        self,

    ) -> list[dict[str, Any]]:

        return self.analyses.list()


    #######################################################################
    # Users
    #######################################################################

    def users_list(

        self,

    ) -> list[dict[str, Any]]:

        return self.users.list()
    
    #######################################################################
    # Health
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        diagnostics = self.diagnostics()

        return {

            "healthy":

            diagnostics["datasources"]["healthy"]

            and diagnostics["datasets"]["healthy"]

            and diagnostics["dashboards"]["healthy"]

            and diagnostics["analyses"]["healthy"]

            and diagnostics["users"]["healthy"],

            "service": "Amazon QuickSight",

        }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

    ) -> dict[str, Any]:

        return {

            "datasources":

            self.datasources.diagnostics(),

            "datasets":

            self.datasets.diagnostics(),

            "dashboards":

            self.dashboards.diagnostics(),

            "analyses":

            self.analyses.diagnostics(),

            "users":

            self.users.diagnostics(),

        }


    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

    ) -> dict[str, Any]:

        diagnostics = self.diagnostics()

        return {

            "service": "Amazon QuickSight",

            "healthy": self.health()["healthy"],

            "data_sources":

            diagnostics["datasources"].get(

                "data_source_count",

                0,

            ),

            "datasets":

            diagnostics["datasets"].get(

                "dataset_count",

                0,

            ),

            "dashboards":

            diagnostics["dashboards"].get(

                "dashboard_count",

                0,

            ),

            "analyses":

            diagnostics["analyses"].get(

                "analysis_count",

                0,

            ),

            "users":

            diagnostics["users"].get(

                "user_count",

                0,

            ),

            "groups":

            diagnostics["users"].get(

                "group_count",

                0,

            ),

        }


###########################################################################
# Factory
###########################################################################

def create_quicksight_manager(

    aws_account_id: str,

    namespace: str = "default",

) -> QuickSightManager:

    """
    Create a QuickSightManager instance.
    """

    return QuickSightManager(

        aws_account_id=aws_account_id,

        namespace=namespace,

    )