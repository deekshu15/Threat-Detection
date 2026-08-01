"""
topics.py

Enterprise SNS Topic Management

Responsibilities
----------------
• Create SNS topics
• Delete SNS topics
• List SNS topics
• Topic attributes
• Topic tags
• Diagnostics
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

def sns():

    return get_client(

        "sns",

    )


###########################################################################
# SNS Topic Service
###########################################################################

class TopicService:

    """
    High-level SNS Topic Management.
    """

    def __init__(

        self,

    ):

        self.client = sns()


    #######################################################################
    # Create Topic
    #######################################################################

    def create_topic(

        self,

        name: str,

        attributes: dict[str, str] | None = None,

        tags: dict[str, str] | None = None,

    ) -> dict[str, Any]:

        request = {

            "Name": name,

        }

        if attributes:

            request["Attributes"] = attributes

        if tags:

            request["Tags"] = [

                {

                    "Key": key,

                    "Value": value,

                }

                for key, value in tags.items()

            ]

        response = self.client.create_topic(

            **request,

        )

        logger.info(

            "Created SNS topic %s",

            name,

        )

        return response


    #######################################################################
    # Delete Topic
    #######################################################################

    def delete_topic(

        self,

        topic_arn: str,

    ) -> bool:

        self.client.delete_topic(

            TopicArn=topic_arn,

        )

        logger.info(

            "Deleted SNS topic %s",

            topic_arn,

        )

        return True


    #######################################################################
    # Topic Exists
    #######################################################################

    def topic_exists(

        self,

        topic_arn: str,

    ) -> bool:

        try:

            self.client.get_topic_attributes(

                TopicArn=topic_arn,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Get Topic Attributes
    #######################################################################

    def get_attributes(

        self,

        topic_arn: str,

    ) -> dict[str, Any]:

        response = self.client.get_topic_attributes(

            TopicArn=topic_arn,

        )

        return response.get(

            "Attributes",

            {},

        )


    #######################################################################
    # List Topics
    #######################################################################

    def list_topics(

        self,

    ) -> list[dict[str, Any]]:

        paginator = self.client.get_paginator(

            "list_topics",

        )

        topics = []

        for page in paginator.paginate():

            topics.extend(

                page.get(

                    "Topics",

                    [],

                )

            )

        return topics


    #######################################################################
    # List Topic ARNs
    #######################################################################

    def list_topic_arns(

        self,

    ) -> list[str]:

        return [

            topic["TopicArn"]

            for topic in self.list_topics()

        ]


    #######################################################################
    # Validate Topic Name
    #######################################################################

    def validate_name(

        self,

        name: str,

    ) -> bool:

        if not name:

            raise ValueError(

                "Topic name cannot be empty."

            )

        if len(

            name,

        ) > 256:

            raise ValueError(

                "Topic name exceeds AWS limit."

            )

        return True


    #######################################################################
    # Topic Summary
    #######################################################################

    def summary(

        self,

        topic_arn: str,

    ) -> dict[str, Any]:

        attributes = self.get_attributes(

            topic_arn,

        )

        return {

            "TopicArn":

            topic_arn,

            "DisplayName":

            attributes.get(

                "DisplayName",

            ),

            "Owner":

            attributes.get(

                "Owner",

            ),

            "SubscriptionsConfirmed":

            attributes.get(

                "SubscriptionsConfirmed",

            ),

            "SubscriptionsPending":

            attributes.get(

                "SubscriptionsPending",

            ),

        }
        
    #######################################################################
    # Set Topic Attribute
    #######################################################################

    def set_attribute(

        self,

        topic_arn: str,

        attribute_name: str,

        attribute_value: str,

    ) -> bool:

        self.client.set_topic_attributes(

            TopicArn=topic_arn,

            AttributeName=attribute_name,

            AttributeValue=attribute_value,

        )

        logger.info(

            "Updated %s for topic %s",

            attribute_name,

            topic_arn,

        )

        return True


    #######################################################################
    # Set Display Name
    #######################################################################

    def set_display_name(

        self,

        topic_arn: str,

        display_name: str,

    ) -> bool:

        return self.set_attribute(

            topic_arn,

            "DisplayName",

            display_name,

        )


    #######################################################################
    # Set Delivery Policy
    #######################################################################

    def set_delivery_policy(

        self,

        topic_arn: str,

        delivery_policy: str,

    ) -> bool:

        return self.set_attribute(

            topic_arn,

            "DeliveryPolicy",

            delivery_policy,

        )


    #######################################################################
    # Set Access Policy
    #######################################################################

    def set_access_policy(

        self,

        topic_arn: str,

        policy: str,

    ) -> bool:

        return self.set_attribute(

            topic_arn,

            "Policy",

            policy,

        )


    #######################################################################
    # Enable KMS Encryption
    #######################################################################

    def enable_kms(

        self,

        topic_arn: str,

        kms_key_id: str,

    ) -> bool:

        return self.set_attribute(

            topic_arn,

            "KmsMasterKeyId",

            kms_key_id,

        )


    #######################################################################
    # Disable KMS Encryption
    #######################################################################

    def disable_kms(

        self,

        topic_arn: str,

    ) -> bool:

        return self.set_attribute(

            topic_arn,

            "KmsMasterKeyId",

            "",

        )


    #######################################################################
    # Tag Topic
    #######################################################################

    def tag_topic(

        self,

        topic_arn: str,

        tags: dict[str, str],

    ) -> bool:

        self.client.tag_resource(

            ResourceArn=topic_arn,

            Tags=[

                {

                    "Key": key,

                    "Value": value,

                }

                for key, value in tags.items()

            ],

        )

        logger.info(

            "Tagged topic %s",

            topic_arn,

        )

        return True


    #######################################################################
    # Remove Topic Tags
    #######################################################################

    def untag_topic(

        self,

        topic_arn: str,

        tag_keys: list[str],

    ) -> bool:

        self.client.untag_resource(

            ResourceArn=topic_arn,

            TagKeys=tag_keys,

        )

        logger.info(

            "Removed tags from topic %s",

            topic_arn,

        )

        return True


    #######################################################################
    # List Topic Tags
    #######################################################################

    def list_tags(

        self,

        topic_arn: str,

    ) -> list[dict[str, Any]]:

        response = self.client.list_tags_for_resource(

            ResourceArn=topic_arn,

        )

        return response.get(

            "Tags",

            [],

        )


    #######################################################################
    # Search Topics
    #######################################################################

    def search_topics(

        self,

        keyword: str,

    ) -> list[str]:

        keyword = keyword.lower()

        return [

            arn

            for arn in self.list_topic_arns()

            if keyword in arn.lower()

        ]
        
    #######################################################################
    # Topic Inventory
    #######################################################################

    def inventory(

        self,

    ) -> list[dict[str, Any]]:

        return [

            self.summary(

                topic["TopicArn"],

            )

            for topic in self.list_topics()

        ]


    #######################################################################
    # Topic Metrics
    #######################################################################

    def metrics(

        self,

    ) -> dict[str, Any]:

        topics = self.list_topics()

        encrypted = 0

        tagged = 0

        for topic in topics:

            arn = topic["TopicArn"]

            attributes = self.get_attributes(

                arn,

            )

            if attributes.get(

                "KmsMasterKeyId",

            ):

                encrypted += 1

            if self.list_tags(

                arn,

            ):

                tagged += 1

        return {

            "total_topics":

            len(

                topics,

            ),

            "encrypted_topics":

            encrypted,

            "tagged_topics":

            tagged,

        }


    #######################################################################
    # Topic Health
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        topics = self.list_topics()

        return {

            "healthy":

            True,

            "topic_count":

            len(

                topics,

            ),

            "topics":

            [

                topic["TopicArn"]

                for topic in topics

            ],

        }


    #######################################################################
    # Bulk Tag Topics
    #######################################################################

    def bulk_tag(

        self,

        topic_arns: list[str],

        tags: dict[str, str],

    ) -> dict[str, bool]:

        results = {}

        for arn in topic_arns:

            try:

                self.tag_topic(

                    arn,

                    tags,

                )

                results[arn] = True

            except Exception:

                logger.exception(

                    "Failed tagging topic %s",

                    arn,

                )

                results[arn] = False

        return results


    #######################################################################
    # Bulk Delete Topics
    #######################################################################

    def bulk_delete(

        self,

        topic_arns: list[str],

    ) -> dict[str, bool]:

        results = {}

        for arn in topic_arns:

            try:

                self.delete_topic(

                    arn,

                )

                results[arn] = True

            except Exception:

                logger.exception(

                    "Failed deleting topic %s",

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

                "total_topics":

                len(

                    self.list_topics(),

                ),

            },

            "health":

            self.health(),

            "metrics":

            self.metrics(),

            "inventory":

            self.inventory(),

        }


###########################################################################
# Topic Manager
###########################################################################

class TopicManager:

    """
    High-level SNS Topic Manager.
    """

    def __init__(

        self,

    ):

        self.service = TopicService()


    def topics(

        self,

    ) -> TopicService:

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

TOPIC_SERVICE = TopicService()

TOPIC_MANAGER = TopicManager()


###########################################################################
# Convenience Functions
###########################################################################

def topics(

) -> TopicService:

    return TOPIC_SERVICE


def health(

) -> dict[str, Any]:

    return TOPIC_SERVICE.health()


def metrics(

) -> dict[str, Any]:

    return TOPIC_SERVICE.metrics()


def diagnostics(

) -> dict[str, Any]:

    return TOPIC_SERVICE.diagnostics()


def report(

) -> dict[str, Any]:

    return TOPIC_SERVICE.report()


###########################################################################
# Self Test
###########################################################################

def self_test(

) -> dict[str, Any]:

    return {

        "module":

        "sns.topics",

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

    "TopicService",

    "TopicManager",

    "TOPIC_SERVICE",

    "TOPIC_MANAGER",

    "topics",

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

    print("SNS Topic Service")

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

    print("SNS Topic Service Ready")