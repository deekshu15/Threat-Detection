"""
streams.py

Enterprise AWS Kinesis Stream Management

Responsibilities
----------------
• Create streams
• Delete streams
• Describe streams
• List streams
• Wait for ACTIVE state
• Update shard count
• Enable monitoring
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

def kinesis():

    """
    Return Kinesis client.
    """

    return get_client("kinesis")


###########################################################################
# Stream Service
###########################################################################

class StreamService:

    """
    High-level Kinesis Stream Management.
    """

    def __init__(

        self,

    ):

        self.client = kinesis()


    #######################################################################
    # Create Stream
    #######################################################################

    def create_stream(

        self,

        stream_name: str,

        shard_count: int = 1,

    ) -> bool:

        self.client.create_stream(

            StreamName=stream_name,

            ShardCount=shard_count,

        )

        logger.info(

            "Created stream %s",

            stream_name,

        )

        return True


    #######################################################################
    # Delete Stream
    #######################################################################

    def delete_stream(

        self,

        stream_name: str,

        enforce_consumer_deletion: bool = True,

    ) -> bool:

        self.client.delete_stream(

            StreamName=stream_name,

            EnforceConsumerDeletion=enforce_consumer_deletion,

        )

        logger.info(

            "Deleted stream %s",

            stream_name,

        )

        return True


    #######################################################################
    # Stream Exists
    #######################################################################

    def stream_exists(

        self,

        stream_name: str,

    ) -> bool:

        try:

            self.describe_stream(

                stream_name,

            )

            return True

        except ClientError:

            return False


    #######################################################################
    # Describe Stream
    #######################################################################

    def describe_stream(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        response = self.client.describe_stream_summary(

            StreamName=stream_name,

        )

        return response["StreamDescriptionSummary"]


    #######################################################################
    # List Streams
    #######################################################################

    def list_streams(

        self,

    ) -> list[str]:

        streams = []

        paginator = self.client.get_paginator(

            "list_streams",

        )

        for page in paginator.paginate():

            streams.extend(

                page.get(

                    "StreamNames",

                    [],

                )

            )

        return streams
    
    #######################################################################
    # Wait Until Active
    #######################################################################

    def wait_until_active(

        self,

        stream_name: str,

        max_attempts: int = 30,

    ) -> bool:

        import time

        for _ in range(max_attempts):

            summary = self.describe_stream(

                stream_name,

            )

            if (

                summary.get(

                    "StreamStatus",

                )

                == "ACTIVE"

            ):

                return True

            time.sleep(2)

        return False


    #######################################################################
    # Wait Until Deleted
    #######################################################################

    def wait_until_deleted(

        self,

        stream_name: str,

        max_attempts: int = 30,

    ) -> bool:

        import time

        for _ in range(max_attempts):

            if not self.stream_exists(

                stream_name,

            ):

                return True

            time.sleep(2)

        return False


    #######################################################################
    # Update Shard Count
    #######################################################################

    def update_shard_count(

        self,

        stream_name: str,

        target_shards: int,

        scaling_type: str = "UNIFORM_SCALING",

    ) -> dict[str, Any]:

        response = self.client.update_shard_count(

            StreamName=stream_name,

            TargetShardCount=target_shards,

            ScalingType=scaling_type,

        )

        logger.info(

            "Updated shard count for %s",

            stream_name,

        )

        return response


    #######################################################################
    # Enable Enhanced Monitoring
    #######################################################################

    def enable_monitoring(

        self,

        stream_name: str,

        metrics: list[str],

    ) -> dict[str, Any]:

        return self.client.enable_enhanced_monitoring(

            StreamName=stream_name,

            ShardLevelMetrics=metrics,

        )


    #######################################################################
    # Disable Enhanced Monitoring
    #######################################################################

    def disable_monitoring(

        self,

        stream_name: str,

        metrics: list[str],

    ) -> dict[str, Any]:

        return self.client.disable_enhanced_monitoring(

            StreamName=stream_name,

            ShardLevelMetrics=metrics,

        )


    #######################################################################
    # Stream Summary
    #######################################################################

    def summary(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        summary = self.describe_stream(

            stream_name,

        )

        return {

            "Name":

            summary.get(

                "StreamName",

            ),

            "Status":

            summary.get(

                "StreamStatus",

            ),

            "Mode":

            summary.get(

                "StreamModeDetails",

                {},

            ).get(

                "StreamMode",

            ),

            "OpenShards":

            summary.get(

                "OpenShardCount",

            ),

            "RetentionHours":

            summary.get(

                "RetentionPeriodHours",

            ),

            "ARN":

            summary.get(

                "StreamARN",

            ),

        }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

    ) -> dict[str, Any]:

        streams = self.list_streams()

        return {

            "stream_count": len(streams),

            "streams": streams,

        }


###########################################################################
# Singleton
###########################################################################

STREAM_SERVICE = StreamService()