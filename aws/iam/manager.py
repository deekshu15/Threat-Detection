"""
manager.py

Enterprise IAM Manager

Central management interface for the IAM package.

Responsibilities
----------------
• Roles
• Policies
• Users
• Groups
• Permission Analysis
• Diagnostics
• Inventory
• Health
"""

from __future__ import annotations

import logging

from typing import Any

from .roles import RoleService
from .policies import PolicyService
from .users import UserService
from .groups import GroupService
from .permissions import PermissionService

logger = logging.getLogger(__name__)


###########################################################################
# IAM Manager
###########################################################################

class IAMManager:

    """
    Central IAM management interface.
    """

    def __init__(

        self,

    ):

        self.roles = RoleService()

        self.policies = PolicyService()

        self.users = UserService()

        self.groups = GroupService()

        self.permissions = PermissionService()


    #######################################################################
    # Health
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        return {

            "roles":

            self.roles.health(),

            "policies":

            self.policies.health(),

            "users":

            self.users.health(),

            "groups":

            self.groups.health(),

        }


    #######################################################################
    # Metrics
    #######################################################################

    def metrics(

        self,

    ) -> dict[str, Any]:

        return {

            "roles":

            self.roles.metrics(),

            "policies":

            self.policies.metrics(),

            "users":

            self.users.metrics(),

            "groups":

            self.groups.metrics(),

        }


    #######################################################################
    # Inventory
    #######################################################################

    def inventory(

        self,

    ) -> dict[str, Any]:

        return {

            "roles":

            self.roles.inventory(),

            "policies":

            self.policies.inventory(),

            "users":

            self.users.inventory(),

            "groups":

            self.groups.inventory(),

        }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

        policy_documents: list[dict[str, Any]] | None = None,

    ) -> dict[str, Any]:

        if policy_documents is None:

            policy_documents = []

        return {

            "roles":

            self.roles.diagnostics(),

            "policies":

            self.policies.diagnostics(),

            "users":

            self.users.diagnostics(),

            "groups":

            self.groups.diagnostics(),

            "permissions":

            self.permissions.diagnostics(

                policy_documents,

            ),

        }


    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

    ) -> dict[str, Any]:

        inventory = self.inventory()

        return {

            "roles":

            len(

                inventory["roles"],

            ),

            "policies":

            len(

                inventory["policies"],

            ),

            "users":

            len(

                inventory["users"],

            ),

            "groups":

            len(

                inventory["groups"],

            ),

        }
        
###########################################################################
# Global Manager
###########################################################################

IAM = IAMManager()


###########################################################################
# Convenience Functions
###########################################################################

def roles() -> RoleService:

    return IAM.roles


def policies() -> PolicyService:

    return IAM.policies


def users() -> UserService:

    return IAM.users


def groups() -> GroupService:

    return IAM.groups


def permissions() -> PermissionService:

    return IAM.permissions


def health() -> dict[str, Any]:

    return IAM.health()


def metrics() -> dict[str, Any]:

    return IAM.metrics()


def inventory() -> dict[str, Any]:

    return IAM.inventory()


def diagnostics(

    policy_documents: list[dict[str, Any]] | None = None,

) -> dict[str, Any]:

    return IAM.diagnostics(

        policy_documents,

    )


def summary() -> dict[str, Any]:

    return IAM.summary()


###########################################################################
# Self Test
###########################################################################

def self_test() -> dict[str, Any]:

    return {

        "module": "iam.manager",

        "status": "ready",

        "summary": summary(),

        "health": health(),

    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [

    "IAMManager",

    "IAM",

    "roles",

    "policies",

    "users",

    "groups",

    "permissions",

    "health",

    "metrics",

    "inventory",

    "diagnostics",

    "summary",

    "self_test",

]


###########################################################################
# Main
###########################################################################

if __name__ == "__main__":

    logging.basicConfig(

        level=logging.INFO,

        format="%(levelname)s %(message)s",

    )

    print("=" * 80)

    print("Enterprise IAM Manager")

    print("=" * 80)

    print()

    print("Summary")

    print(

        summary(),

    )

    print()

    print("Health")

    print(

        health(),

    )

    print()

    print("Metrics")

    print(

        metrics(),

    )

    print()

    print("Inventory")

    print(

        inventory(),

    )

    print()

    print("Self Test")

    print(

        self_test(),

    )

    print()

    print("Enterprise IAM Manager Ready")