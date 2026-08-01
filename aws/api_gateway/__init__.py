"""
AWS API Gateway Package

Enterprise Amazon API Gateway Services
"""

from .apis import (
    RestApiService,
    create_rest_api_service,
)

from .resources import (
    ResourceService,
    create_resource_service,
)

from .methods import (
    MethodService,
    create_method_service,
)

from .integrations import (
    IntegrationService,
    create_integration_service,
)

from .deployments import (
    DeploymentService,
    create_deployment_service,
)

from .authorizers import (
    AuthorizerService,
    create_authorizer_service,
)

from .usage_plans import (
    UsagePlanService,
    create_usage_plan_service,
)

from .domains import (
    DomainService,
    create_domain_service,
)

from .manager import (
    ApiGatewayManager,
    create_api_gateway_manager,
)

__version__ = "1.0.0"

__all__ = [

    "RestApiService",
    "create_rest_api_service",

    "ResourceService",
    "create_resource_service",

    "MethodService",
    "create_method_service",

    "IntegrationService",
    "create_integration_service",

    "DeploymentService",
    "create_deployment_service",

    "AuthorizerService",
    "create_authorizer_service",

    "UsagePlanService",
    "create_usage_plan_service",

    "DomainService",
    "create_domain_service",

    "ApiGatewayManager",
    "create_api_gateway_manager",

]