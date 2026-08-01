"""
subscriptions.py

Enterprise SNS Subscription Management

Responsibilities
----------------
• Subscribe endpoints
• Unsubscribe
• Confirm subscriptions
• Filter policies
• Raw message delivery
• Redrive policies
• Diagnostics
"""

from __future__ import annotations

import json
import logging

from typing import Any

from botocore.exceptions import ClientError

from aws.utils.aws_utils import get_client

logger = logging.getLogger(__name__)


###########################################################################
# Client
###########################################################################

def sns():

    return get_client(

        "sns",

    )


###########################################################################
# Subscription Service
###########################################################################

class SubscriptionService:

    """
    High-level SNS Subscription Management.
    """

    def __init__(

        self,

    ):

        self.client = sns()


    #######################################################################
    # Subscribe
    #######################################################################

    def subscribe(

        self,

        topic_arn: str,

        protocol: str,

        endpoint: str,

        return_subscription_arn: bool = True,

    ) -> dict[str, Any]:

        response = self.client.subscribe(

            TopicArn=topic_arn,

            Protocol=protocol,

            Endpoint=endpoint,

            ReturnSubscriptionArn=return_subscription_arn,

        )

        logger.info(

            "Subscribed %s to %s",

            endpoint,

            topic_arn,

        )

        return response


    #######################################################################
    # Unsubscribe
    #######################################################################

    def unsubscribe(

        self,

        subscription_arn: str,

    ) -> bool:

        self.client.unsubscribe(

            SubscriptionArn=subscription_arn,

        )

        logger.info(

            "Removed subscription %s",

            subscription_arn,

        )

        return True


    #######################################################################
    # Confirm Subscription
    #######################################################################

    def confirm_subscription(

        self,

        topic_arn: str,

        token: str,

    ) -> dict[str, Any]:

        response = self.client.confirm_subscription(

            TopicArn=topic_arn,

            Token=token,

        )

        return response


    #######################################################################
    # Get Subscription Attributes
    #######################################################################

    def get_attributes(

        self,

        subscription_arn: str,

    ) -> dict[str, Any]:

        response = self.client.get_subscription_attributes(

            SubscriptionArn=subscription_arn,

        )

        return response.get(

            "Attributes",

            {},

        )


    #######################################################################
    # Subscription Exists
    #######################################################################

    def subscription_exists(

        self,

        subscription_arn: str,

    ) -> bool:

        try:

            self.client.get_subscription_attributes(

                SubscriptionArn=subscription_arn,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # List Subscriptions
    #######################################################################

    def list_subscriptions(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_subscriptions",

        )

        subscriptions = []

        for page in paginator.paginate():

            subscriptions.extend(

                page.get(

                    "Subscriptions",

                    [],

                )

            )

        return subscriptions


    #######################################################################
    # List Topic Subscriptions
    #######################################################################

    def list_topic_subscriptions(

        self,

        topic_arn: str,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_subscriptions_by_topic",

        )

        subscriptions = []

        for page in paginator.paginate(

            TopicArn=topic_arn,

        ):

            subscriptions.extend(

                page.get(

                    "Subscriptions",

                    [],

                )

            )

        return subscriptions


    #######################################################################
    # Summary
    #######################################################################

    def summary(

        self,

        subscription_arn: str,

    ) -> dict[str, Any]:

        attributes = self.get_attributes(

            subscription_arn,

        )

        return {

            "SubscriptionArn":

            subscription_arn,

            "TopicArn":

            attributes.get(

                "TopicArn",

            ),

            "Protocol":

            attributes.get(

                "Protocol",

            ),

            "Endpoint":

            attributes.get(

                "Endpoint",

            ),

            "Owner":

            attributes.get(

                "Owner",

            ),

        }
        
    #######################################################################
    # Set Subscription Attribute
    #######################################################################

    def set_attribute(

        self,

        subscription_arn: str,

        attribute_name: str,

        attribute_value: str,

    ) -> bool:

        self.client.set_subscription_attributes(

            SubscriptionArn=subscription_arn,

            AttributeName=attribute_name,

            AttributeValue=attribute_value,

        )

        logger.info(

            "Updated subscription attribute %s",

            attribute_name,

        )

        return True


    #######################################################################
    # Set Filter Policy
    #######################################################################

    def set_filter_policy(

        self,

        subscription_arn: str,

        filter_policy: dict[str, Any],

    ) -> bool:

        return self.set_attribute(

            subscription_arn,

            "FilterPolicy",

            json.dumps(

                filter_policy,

            ),

        )


    #######################################################################
    # Get Filter Policy
    #######################################################################

    def get_filter_policy(

        self,

        subscription_arn: str,

    ) -> dict[str, Any]:

        attributes = self.get_attributes(

            subscription_arn,

        )

        policy = attributes.get(

            "FilterPolicy",

        )

        if not policy:

            return {}

        return json.loads(

            policy,

        )


    #######################################################################
    # Enable Raw Message Delivery
    #######################################################################

    def enable_raw_delivery(

        self,

        subscription_arn: str,

    ) -> bool:

        return self.set_attribute(

            subscription_arn,

            "RawMessageDelivery",

            "true",

        )


    #######################################################################
    # Disable Raw Message Delivery
    #######################################################################

    def disable_raw_delivery(

        self,

        subscription_arn: str,

    ) -> bool:

        return self.set_attribute(

            subscription_arn,

            "RawMessageDelivery",

            "false",

        )


    #######################################################################
    # Set Redrive Policy
    #######################################################################

    def set_redrive_policy(

        self,

        subscription_arn: str,

        dead_letter_queue_arn: str,

    ) -> bool:

        policy = {

            "deadLetterTargetArn":

            dead_letter_queue_arn,

        }

        return self.set_attribute(

            subscription_arn,

            "RedrivePolicy",

            json.dumps(

                policy,

            ),

        )


    #######################################################################
    # Set Delivery Policy
    #######################################################################

    def set_delivery_policy(

        self,

        subscription_arn: str,

        delivery_policy: dict[str, Any],

    ) -> bool:

        return self.set_attribute(

            subscription_arn,

            "DeliveryPolicy",

            json.dumps(

                delivery_policy,

            ),

        )


    #######################################################################
    # Search Subscriptions
    #######################################################################

    def search_subscriptions(

        self,

        keyword: str,

    ) -> list[dict[str, Any]]:

        keyword = keyword.lower()

        return [

            subscription

            for subscription

            in self.list_subscriptions()

            if (

                keyword

                in subscription.get(

                    "Endpoint",

                    "",

                ).lower()

                or

                keyword

                in subscription.get(

                    "Protocol",

                    "",

                ).lower()

                or

                keyword

                in subscription.get(

                    "TopicArn",

                    "",

                ).lower()

            )

        ]


    #######################################################################
    # Inventory
    #######################################################################

    def inventory(

        self,

    ) -> list[dict[str, Any]]:

        return [

            self.summary(

                subscription["SubscriptionArn"],

            )

            for subscription

            in self.list_subscriptions()

            if subscription.get(

                "SubscriptionArn",

            )

            != "PendingConfirmation"

        ]


    #######################################################################
    # Health
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        subscriptions = self.list_subscriptions()

        return {

            "healthy":

            True,

            "subscription_count":

            len(

                subscriptions,

            ),

            "confirmed":

            sum(

                1

                for subscription

                in subscriptions

                if subscription.get(

                    "SubscriptionArn",

                )

                != "PendingConfirmation"

            ),

        }
        
    #######################################################################
    # Metrics
    #######################################################################

    def metrics(

        self,

    ) -> dict[str, Any]:

        subscriptions = self.list_subscriptions()

        protocols: dict[str, int] = {}

        confirmed = 0

        pending = 0

        for subscription in subscriptions:

            protocol = subscription.get(

                "Protocol",

                "unknown",

            )

            protocols[protocol] = (

                protocols.get(

                    protocol,

                    0,

                )

                + 1

            )

            if (

                subscription.get(

                    "SubscriptionArn",

                )

                == "PendingConfirmation"

            ):

                pending += 1

            else:

                confirmed += 1

        return {

            "total_subscriptions":

            len(

                subscriptions,

            ),

            "confirmed":

            confirmed,

            "pending":

            pending,

            "protocols":

            protocols,

        }


    #######################################################################
    # Bulk Subscribe
    #######################################################################

    def bulk_subscribe(

        self,

        topic_arn: str,

        protocol: str,

        endpoints: list[str],

    ) -> dict[str, bool]:

        results = {}

        for endpoint in endpoints:

            try:

                self.subscribe(

                    topic_arn,

                    protocol,

                    endpoint,

                )

                results[endpoint] = True

            except Exception:

                logger.exception(

                    "Failed subscribing %s",

                    endpoint,

                )

                results[endpoint] = False

        return results


    #######################################################################
    # Bulk Unsubscribe
    #######################################################################

    def bulk_unsubscribe(

        self,

        subscription_arns: list[str],

    ) -> dict[str, bool]:

        results = {}

        for arn in subscription_arns:

            try:

                self.unsubscribe(

                    arn,

                )

                results[arn] = True

            except Exception:

                logger.exception(

                    "Failed unsubscribing %s",

                    arn,

                )

                results[arn] = False

        return results


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

    ) -> dict[str, Any]:

        return {

            "health":

            self.health(),

            "metrics":

            self.metrics(),

            "inventory":

            self.inventory(),

        }


    #######################################################################
    # Report
    #######################################################################

    def report(

        self,

    ) -> dict[str, Any]:

        return {

            "summary":

            {

                "total":

                self.metrics()[

                    "total_subscriptions"

                ],

                "confirmed":

                self.metrics()[

                    "confirmed"

                ],

            },

            "health":

            self.health(),

            "metrics":

            self.metrics(),

            "inventory":

            self.inventory(),

        }


###########################################################################
# Subscription Manager
###########################################################################

class SubscriptionManager:

    """
    High-level SNS Subscription Manager.
    """

    def __init__(

        self,

    ):

        self.service = SubscriptionService()


    def subscriptions(

        self,

    ) -> SubscriptionService:

        return self.service


    def health(

        self,

    ) -> dict[str, Any]:

        return self.service.health()


    def metrics(

        self,

    ) -> dict[str, Any]:

        return self.service.metrics()


    def diagnostics(

        self,

    ) -> dict[str, Any]:

        return self.service.diagnostics()


    def report(

        self,

    ) -> dict[str, Any]:

        return self.service.report()


###########################################################################
# Global Instances
###########################################################################

SUBSCRIPTION_SERVICE = SubscriptionService()

SUBSCRIPTION_MANAGER = SubscriptionManager()


###########################################################################
# Convenience Functions
###########################################################################

def subscriptions(

) -> SubscriptionService:

    return SUBSCRIPTION_SERVICE


def health(

) -> dict[str, Any]:

    return SUBSCRIPTION_SERVICE.health()


def metrics(

) -> dict[str, Any]:

    return SUBSCRIPTION_SERVICE.metrics()


def diagnostics(

) -> dict[str, Any]:

    return SUBSCRIPTION_SERVICE.diagnostics()


def report(

) -> dict[str, Any]:

    return SUBSCRIPTION_SERVICE.report()


###########################################################################
# Self Test
###########################################################################

def self_test(

) -> dict[str, Any]:

    return {

        "module":

        "sns.subscriptions",

        "status":

        "ready",

        "health":

        health(),

        "metrics":

        metrics(),

    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [

    "SubscriptionService",

    "SubscriptionManager",

    "SUBSCRIPTION_SERVICE",

    "SUBSCRIPTION_MANAGER",

    "subscriptions",

    "health",

    "metrics",

    "diagnostics",

    "report",

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

    print("SNS Subscription Service")

    print("=" * 80)

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

    print("Diagnostics")

    print(

        diagnostics(),

    )

    print()

    print("Report")

    print(

        report(),

    )

    print()

    print("Self Test")

    print(

        self_test(),

    )

    print()

    print("SNS Subscription Service Ready")