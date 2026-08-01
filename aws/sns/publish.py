"""
publish.py

Enterprise SNS Publishing

Responsibilities
----------------
• Publish messages
• FIFO publishing
• Batch publishing
• Message attributes
• SMS publishing
• Mobile push
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
# Publisher Service
###########################################################################

class PublisherService:

    """
    High-level SNS Publisher.
    """

    def __init__(

        self,

    ):

        self.client = sns()


    #######################################################################
    # Publish Message
    #######################################################################

    def publish(

        self,

        topic_arn: str,

        message: str,

        subject: str | None = None,

        message_attributes: dict[str, Any] | None = None,

    ) -> dict[str, Any]:

        request = {

            "TopicArn": topic_arn,

            "Message": message,

        }

        if subject:

            request["Subject"] = subject

        if message_attributes:

            request["MessageAttributes"] = {

                key: {

                    "DataType": "String",

                    "StringValue": str(value),

                }

                for key, value in message_attributes.items()

            }

        response = self.client.publish(

            **request,

        )

        logger.info(

            "Published message to %s",

            topic_arn,

        )

        return response


    #######################################################################
    # Publish JSON Message
    #######################################################################

    def publish_json(

        self,

        topic_arn: str,

        payload: dict[str, Any],

        subject: str | None = None,

    ) -> dict[str, Any]:

        return self.publish(

            topic_arn=topic_arn,

            message=json.dumps(

                payload,

                default=str,

            ),

            subject=subject,

        )


    #######################################################################
    # Publish FIFO Message
    #######################################################################

    def publish_fifo(

        self,

        topic_arn: str,

        message: str,

        group_id: str,

        deduplication_id: str,

    ) -> dict[str, Any]:

        response = self.client.publish(

            TopicArn=topic_arn,

            Message=message,

            MessageGroupId=group_id,

            MessageDeduplicationId=deduplication_id,

        )

        logger.info(

            "Published FIFO message to %s",

            topic_arn,

        )

        return response


    #######################################################################
    # Publish SMS
    #######################################################################

    def publish_sms(

        self,

        phone_number: str,

        message: str,

    ) -> dict[str, Any]:

        response = self.client.publish(

            PhoneNumber=phone_number,

            Message=message,

        )

        logger.info(

            "Published SMS to %s",

            phone_number,

        )

        return response


    #######################################################################
    # Publish Mobile Push
    #######################################################################

    def publish_mobile(

        self,

        target_arn: str,

        message: str,

    ) -> dict[str, Any]:

        response = self.client.publish(

            TargetArn=target_arn,

            Message=message,

        )

        logger.info(

            "Published mobile notification",

        )

        return response


    #######################################################################
    # Publish To Endpoint
    #######################################################################

    def publish_endpoint(

        self,

        endpoint_arn: str,

        message: str,

    ) -> dict[str, Any]:

        response = self.client.publish(

            TargetArn=endpoint_arn,

            Message=message,

        )

        logger.info(

            "Published endpoint message",

        )

        return response


    #######################################################################
    # Publish Structured Message
    #######################################################################

    def publish_structured(

        self,

        topic_arn: str,

        default: str,

        email: str | None = None,

        sms: str | None = None,

    ) -> dict[str, Any]:

        payload = {

            "default": default,

        }

        if email:

            payload["email"] = email

        if sms:

            payload["sms"] = sms

        response = self.client.publish(

            TopicArn=topic_arn,

            Message=json.dumps(

                payload,

            ),

            MessageStructure="json",

        )

        return response


    #######################################################################
    # Validate Message
    #######################################################################

    def validate_message(

        self,

        message: str,

    ) -> bool:

        if not message:

            raise ValueError(

                "Message cannot be empty."

            )

        return True
    
    #######################################################################
    # Publish Batch
    #######################################################################

    def publish_batch(

        self,

        topic_arn: str,

        messages: list[str],

        subject: str | None = None,

    ) -> list[dict[str, Any]]:

        responses = []

        for message in messages:

            responses.append(

                self.publish(

                    topic_arn=topic_arn,

                    message=message,

                    subject=subject,

                )

            )

        logger.info(

            "Published %d messages",

            len(messages),

        )

        return responses


    #######################################################################
    # Retry Publish
    #######################################################################

    def publish_retry(

        self,

        topic_arn: str,

        message: str,

        retries: int = 3,

        subject: str | None = None,

    ) -> dict[str, Any]:

        last_error = None

        for _ in range(retries):

            try:

                return self.publish(

                    topic_arn,

                    message,

                    subject,

                )

            except ClientError as exc:

                last_error = exc

                logger.warning(

                    "Retrying SNS publish",

                )

        raise last_error


    #######################################################################
    # Publish Multiple JSON Documents
    #######################################################################

    def publish_json_batch(

        self,

        topic_arn: str,

        payloads: list[dict[str, Any]],

    ) -> list[dict[str, Any]]:

        results = []

        for payload in payloads:

            results.append(

                self.publish_json(

                    topic_arn,

                    payload,

                )

            )

        return results


    #######################################################################
    # Publish Metrics
    #######################################################################

    def metrics(

        self,

        responses: list[dict[str, Any]],

    ) -> dict[str, Any]:

        successful = sum(

            1

            for response in responses

            if "MessageId" in response

        )

        failed = len(

            responses,

        ) - successful

        return {

            "published":

            successful,

            "failed":

            failed,

            "total":

            len(

                responses,

            ),

        }


    #######################################################################
    # Publish History
    #######################################################################

    def history(

        self,

        responses: list[dict[str, Any]],

    ) -> list[str]:

        return [

            response.get(

                "MessageId",

                "",

            )

            for response in responses

        ]


    #######################################################################
    # Health
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        return {

            "healthy": True,

            "service": "SNS Publisher",

        }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

    ) -> dict[str, Any]:

        return {

            "health":

            self.health(),

        }


    #######################################################################
    # Report
    #######################################################################

    def report(

        self,

        responses: list[dict[str, Any]],

    ) -> dict[str, Any]:

        return {

            "metrics":

            self.metrics(

                responses,

            ),

            "message_ids":

            self.history(

                responses,

            ),

            "health":

            self.health(),

        }


    #######################################################################
    # Search Message IDs
    #######################################################################

    def search_message_ids(

        self,

        responses: list[dict[str, Any]],

        keyword: str,

    ) -> list[str]:

        keyword = keyword.lower()

        return [

            response.get(

                "MessageId",

                "",

            )

            for response in responses

            if keyword

            in response.get(

                "MessageId",

                "",

            ).lower()

        ]
        
###########################################################################
# Publisher Manager
###########################################################################

class PublisherManager:

    """
    High-level SNS Publisher Manager.
    """

    def __init__(

        self,

    ):

        self.service = PublisherService()


    def publisher(

        self,

    ) -> PublisherService:

        return self.service


    def health(

        self,

    ) -> dict[str, Any]:

        return self.service.health()


    def diagnostics(

        self,

    ) -> dict[str, Any]:

        return self.service.diagnostics()


    def report(

        self,

        responses: list[dict[str, Any]],

    ) -> dict[str, Any]:

        return self.service.report(

            responses,

        )


###########################################################################
# Global Instances
###########################################################################

PUBLISHER_SERVICE = PublisherService()

PUBLISHER_MANAGER = PublisherManager()


###########################################################################
# Convenience Functions
###########################################################################

def publisher(

) -> PublisherService:

    return PUBLISHER_SERVICE


def publish(

    topic_arn: str,

    message: str,

    subject: str | None = None,

    message_attributes: dict[str, Any] | None = None,

) -> dict[str, Any]:

    return PUBLISHER_SERVICE.publish(

        topic_arn,

        message,

        subject,

        message_attributes,

    )


def publish_json(

    topic_arn: str,

    payload: dict[str, Any],

    subject: str | None = None,

) -> dict[str, Any]:

    return PUBLISHER_SERVICE.publish_json(

        topic_arn,

        payload,

        subject,

    )


def publish_batch(

    topic_arn: str,

    messages: list[str],

    subject: str | None = None,

) -> list[dict[str, Any]]:

    return PUBLISHER_SERVICE.publish_batch(

        topic_arn,

        messages,

        subject,

    )


def health(

) -> dict[str, Any]:

    return PUBLISHER_SERVICE.health()


def diagnostics(

) -> dict[str, Any]:

    return PUBLISHER_SERVICE.diagnostics()


def report(

    responses: list[dict[str, Any]],

) -> dict[str, Any]:

    return PUBLISHER_SERVICE.report(

        responses,

    )


###########################################################################
# Self Test
###########################################################################

def self_test(

) -> dict[str, Any]:

    return {

        "module":

        "sns.publish",

        "status":

        "ready",

        "health":

        health(),

    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [

    "PublisherService",

    "PublisherManager",

    "PUBLISHER_SERVICE",

    "PUBLISHER_MANAGER",

    "publisher",

    "publish",

    "publish_json",

    "publish_batch",

    "health",

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

    print("SNS Publisher Service")

    print("=" * 80)

    print()

    print("Health")

    print(

        health(),

    )

    print()

    print("Diagnostics")

    print(

        diagnostics(),

    )

    print()

    print("Self Test")

    print(

        self_test(),

    )

    print()

    print("SNS Publisher Service Ready")