"""
AWS QuickSight Package

Enterprise Amazon QuickSight Services
"""

from .datasources import (
    DataSourceService,
    create_datasource_service,
)

from .datasets import (
    DatasetService,
    create_dataset_service,
)

from .dashboards import (
    DashboardService,
    create_dashboard_service,
)

from .analyses import (
    AnalysisService,
    create_analysis_service,
)

from .users import (
    UserService,
    create_user_service,
)

from .manager import (
    QuickSightManager,
    create_quicksight_manager,
)

__version__ = "1.0.0"

__all__ = [

    "DataSourceService",
    "create_datasource_service",

    "DatasetService",
    "create_dataset_service",

    "DashboardService",
    "create_dashboard_service",

    "AnalysisService",
    "create_analysis_service",

    "UserService",
    "create_user_service",

    "QuickSightManager",
    "create_quicksight_manager",

]