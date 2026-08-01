"""
manager.py

Enterprise SNS Manager

Central management interface for the SNS package.

Responsibilities
----------------
• Topics
• Publishing
• Subscriptions
• Policies
• Health
• Metrics
• Inventory
• Diagnostics
"""

from __future__ import annotations

import logging

from typing import Any

from .topics import TopicService
from .publish import PublisherService
from .subscriptions import SubscriptionService
from .policies import PolicyService

logger = logging.getLogger(__name__)


###########################################################################
# SNS Manager
###########################################################################

class SNSManager:

    """
    Central SNS management interface.
    """

    def __init__(

        self,

    ):

        self.topics = TopicService()

        self.publisher = PublisherService()

        self.subscriptions = SubscriptionService()

        self.policies = PolicyService()


    #######################################################################
    # Health
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        return {

            "topics":

            self.topics.health(),

            "publisher":

            self.publisher.health(),

            "subscriptions":

            self.subscriptions.health(),

        }


    #######################################################################
    # Metrics
    #######################################################################

    def metrics(

        self,

    ) -> dict[str, Any]:

        return {

            "topics":

            self.topics.metrics(),

            "subscriptions":

            self.subscriptions.metrics(),

        }


    #######################################################################
    # Inventory
    #######################################################################

    def inventory(

        self,

    ) -> dict[str, Any]:

        return {

            "topics":

            self.topics.inventory(),

            "subscriptions":

            self.subscriptions.inventory(),

        }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

        topic_arns: list[str] | None = None,

        account_id: str | None = None,

    ) -> dict[str, Any]:

        if topic_arns is None:

            topic_arns = []

        return {

            "topics":

            self.topics.diagnostics(),

            "publisher":

            self.publisher.diagnostics(),

            "subscriptions":

            self.subscriptions.diagnostics(),

            "policies":

            self.policies.diagnostics(

                topic_arns,

                account_id,

            ),

        }


    #######################################################################
    # Report
    #######################################################################

    def report(

        self,

        topic_arns: list[str] | None = None,

        account_id: str | None = None,

    ) -> dict[str, Any]:

        if topic_arns is None:

            topic_arns = []

        return {

            "topics":

            self.topics.report(),

            "subscriptions":

            self.subscriptions.report(),

            "policies":

            self.policies.report(

                topic_arns,

                account_id,

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

            "topics":

            len(

                inventory["topics"],

            ),

            "subscriptions":

            len(

                inventory["subscriptions"],

            ),

        }
        
###########################################################################
# Global Manager
###########################################################################

SNS = SNSManager()


###########################################################################
# Convenience Functions
###########################################################################

def topics() -> TopicService:

    return SNS.topics


def publisher() -> PublisherService:

    return SNS.publisher


def subscriptions() -> SubscriptionService:

    return SNS.subscriptions


def policies() -> PolicyService:

    return SNS.policies


def health() -> dict[str, Any]:

    return SNS.health()


def metrics() -> dict[str, Any]:

    return SNS.metrics()


def inventory() -> dict[str, Any]:

    return SNS.inventory()


def diagnostics(

    topic_arns: list[str] | None = None,

    account_id: str | None = None,

) -> dict[str, Any]:

    return SNS.diagnostics(

        topic_arns,

        account_id,

    )


def report(

    topic_arns: list[str] | None = None,

    account_id: str | None = None,

) -> dict[str, Any]:

    return SNS.report(

        topic_arns,

        account_id,

    )


def summary() -> dict[str, Any]:

    return SNS.summary()


###########################################################################
# Self Test
###########################################################################

def self_test() -> dict[str, Any]:

    return {

        "module": "sns.manager",

        "status": "ready",

        "summary": summary(),

        "health": health(),

    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [

    "SNSManager",

    "SNS",

    "topics",

    "publisher",

    "subscriptions",

    "policies",

    "health",

    "metrics",

    "inventory",

    "diagnostics",

    "report",

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

    print("Enterprise SNS Manager")

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

    print("Enterprise SNS Manager Ready")