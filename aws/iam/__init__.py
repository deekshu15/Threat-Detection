"""
AWS IAM Package

Enterprise Identity and Access Management

Modules
-------
roles.py
policies.py
users.py
groups.py
permissions.py
manager.py
"""

from .roles import (
    RoleService,
    RoleManager,
    ROLE_SERVICE,
    ROLE_MANAGER,
)

from .policies import (
    PolicyService,
    PolicyManager,
    POLICY_SERVICE,
    POLICY_MANAGER,
)

from .users import (
    UserService,
    UserManager,
    USER_SERVICE,
    USER_MANAGER,
)

from .groups import (
    GroupService,
    GroupManager,
    GROUP_SERVICE,
    GROUP_MANAGER,
)

from .permissions import (
    PermissionService,
    PermissionManager,
    PERMISSION_SERVICE,
    PERMISSION_MANAGER,
)

from .manager import (
    IAMManager,
    IAM,
)

__version__ = "1.0.0"

__author__ = "AI-Assisted Threat Detection Dashboard"

__all__ = [

    # Roles
    "RoleService",
    "RoleManager",
    "ROLE_SERVICE",
    "ROLE_MANAGER",

    # Policies
    "PolicyService",
    "PolicyManager",
    "POLICY_SERVICE",
    "POLICY_MANAGER",

    # Users
    "UserService",
    "UserManager",
    "USER_SERVICE",
    "USER_MANAGER",

    # Groups
    "GroupService",
    "GroupManager",
    "GROUP_SERVICE",
    "GROUP_MANAGER",

    # Permissions
    "PermissionService",
    "PermissionManager",
    "PERMISSION_SERVICE",
    "PERMISSION_MANAGER",

    # Central Manager
    "IAMManager",
    "IAM",

]